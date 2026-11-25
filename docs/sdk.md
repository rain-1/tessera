# Tessera SDK and `tessera` CLI

`tessera-sdk` (Rust crate) and `tessera` (CLI binary from `tessera-cli`) are
the agent side of the Tessera capability protocol (spec §3.1, §5.1, §9.2,
WP6). They run **inside** an untrusted sandbox and are **untrusted** themselves.
They can only *ask* the broker. Every decision (who the caller is, whether a
scope is a subset, whether budget is left, whether a human approved) is made
by the broker and the authority core.

## 1. Connecting

The launcher gives every sandbox exactly one pre-connected broker channel:

| Item | Value |
|---|---|
| Descriptor | fd `3`, one end of an `AF_UNIX`/`SOCK_SEQPACKET` socketpair |
| Environment | `TESSERA_BROKER_FD=3` |
| Framing | one versioned `tessera-protocol` payload per datagram |
| Label | `TESSERA_AGENT_ID=<label>`. **Informational only.** The SDK never reads it and never sends it. |

```rust
use tessera_sdk::Client;
let client = Client::from_env()?;            // claims TESSERA_BROKER_FD, once per process
// or Client::from_fd(owned_fd) / Client::from_stream(unix_stream)
```

* `from_env` takes ownership of the descriptor. A second call in the same
  process fails rather than creating a second owner. Create one `Client` and
  share it: all methods take `&self`, and the client is `Send + Sync`.
* `from_fd` detects the socket type. `SOCK_SEQPACKET` is the primary transport.
  `SOCK_STREAM` with `u32` big-endian length-prefixed frames is supported as a
  secondary transport, for tests and tools.
* The SDK rejects any ancillary data (passed descriptors) from the peer and
  closes any descriptors that arrive.

### The one `unsafe` line

The workspace denies `unsafe_code`. Turning the number in `TESSERA_BROKER_FD`
into an `OwnedFd` needs `OwnedFd::from_raw_fd`, which is `unsafe`. That one call
lives in `crates/sdk/src/env_fd.rs` under `#[allow(unsafe_code)]`, with a
SAFETY comment. It is the **only** `unsafe` in the repository
(`crates/sdk/tests/unsafe_inventory.rs` enforces this) and is listed as
trusted assumption A14 in `docs/proof-register.md`. We re-checked the safe
alternatives during hardening; none works inside a sandbox:

* `pidfd_getfd` is denied by the launcher's seccomp filter (ADR-0004).
* `/proc/self/fd/N` cannot be opened for sockets.
* "Safe" crates for inherited descriptors contain the same `unsafe` call.
* Passing the channel on stdin (whose `BorrowedFd` std hands out safely)
  would take stdio away from the workload.

These checks keep the call sound:

* a process-wide once-only claim;
* fds 0–2 refused;
* a `/proc/self/fd/N` → `socket:[…]` check when `/proc` is readable;
* an `SO_TYPE` check after the claim. On failure the descriptor is released
  without being closed.

## 2. API overview

| Method | Wire request | Returns |
|---|---|---|
| `request_grant(terms, untrusted_description)` | `RequestGrant` (→ `GrantPending`, then final) | `CapId` (after operator approval) |
| `request_grant_with_progress(id, terms, desc, on_pending)` | same | same; calls `on_pending(time left)` when queued |
| `consume(cap, WireOperation)` | `Consume` | `Consumed::{Executed, Prior}` |
| `read_file(cap, max_bytes)` | `Consume(FileReadSnapshot)` | `FileSnapshot` |
| `replace_file(cap, bytes)` | `Consume(FileReplaceContent)` | bytes written |
| `https_request(cap, HttpsRequest)` | `Consume(Https)` | `HttpsResponse` |
| `delegate(cap, recipient, child_terms)` | `Delegate` (atomic, §5.1) | child `CapId` |
| `attenuate(cap, reduced_terms)` | `Attenuate` | `()` |
| `transfer(cap, recipient)` | `Transfer` | `()` |
| `drop(cap)` | `Drop` | `()` |
| `inspect(cap)` | `Inspect` | `CapabilityView` |
| `list_capabilities()` | `ListCapabilities` (paged, 64 per page) | every `CapabilityView` you own |
| `spawn(profile)` | `Spawn` (operator-configured agent profiles, quotas) | new `AgentId` |
| `revoke(cap)` | `Revoke` (a cap you own, or a descendant of one) | `()` |
| `call_raw(Request, timeout)` | any | raw `Response` |

Each mutating method has a `*_with_id(request_id, …)` twin. `Terms` bundles
scope, budget, depth and expiry:

```rust
use tessera_sdk::{Terms, wire::{WireScope, WireMethodSet}};
let scope = WireScope::Https { endpoint_id: 7, methods: WireMethodSet { get: true, ..Default::default() }, max_body_bytes: 0 };
let root  = client.request_grant(Terms::new(scope, 100).depth(2), Some("research swarm"))?;
let child = client.delegate(root, worker, Terms::new(scope, 30).depth(1))?;
```

Expiry is always *relative* (`WireExpiry::WithinMillis`). The broker's
monotonic clock is the only time source, and it clamps the expiry to the
parent's expiry.

`untrusted_description` (at most 512 bytes) is free text for the operator,
carried since protocol v2. The approval UI prints it in a separate block
labelled UNTRUSTED, with control, bidi and invisible characters escaped and
long text truncated, below the broker's normalized rendering (§8.1). It is
not part of what the operator's key signs, and the audit log records only its
length and SHA-256.

### Errors

`tessera_sdk::Error`:

| Variant | Meaning |
|---|---|
| `Broker(BrokerError { code, detail, request_id })` | Typed denial; `code` is the protocol `ErrorCode` |
| `Timeout { request_id }` | No answer before the deadline. **Outcome uncertain.** For `request_grant`: not even the `GrantPending` acknowledgement arrived (broker not answering). |
| `ApprovalPending { request_id }` | `request_grant` was acknowledged (`GrantPending`) but the operator had not decided by `approval_timeout`. The broker is alive and the request is still queued; repeat with the same id to keep waiting. Outcome uncertain. |
| `PriorReservation { … }` | A convenience consume method found an earlier reservation for this id. No new effect happened. |
| `Closed`, `Io`, `Poisoned` | Channel failure. `Poisoned` happens only on stream transports, after a partial write or a bad frame header. |
| `FrameTooLarge { outbound, len, max }` | Message too large. If `outbound`, nothing was sent. If inbound, a seqpacket channel stays usable. |
| `Protocol(_)` | The broker sent something that does not follow the protocol: undecodable payload, wrong version, unknown correlation id, wrong response kind, or a mismatched request id echo. |
| `InvalidArgument`, `Config` | Local problems; nothing was sent. |

`error.code()`, `error.request_id()` and `error.outcome_uncertain()` are the
helpers to branch on. Denials are deliberately coarse. "Does not exist" and
"not yours" are both `UnknownCapability`.

### Timeouts

| Setting | Default |
|---|---|
| `ClientConfig::call_timeout` | 30 s; also the limit for the first answer (`GrantPending`) to `request_grant` |
| `ClientConfig::approval_timeout` | 15 min, total wait of `request_grant` for the human's decision |

The broker answers `RequestGrant` first with `GrantPending { expires_in_millis }`
(queued for the operator), then with the final `GrantIssued` or error on the
same correlation id. So a short `call_timeout` detects a hung broker while
`approval_timeout` bounds the wait for a human. Repeating a pending
`RequestGrant` with the same id is a status query: another `GrantPending`,
the same approval, one prompt, one mint.

The broker also limits each principal: a token bucket (default 100 requests/s,
burst 200) and at most 64 requests in flight (a pending grant request counts
until it is decided). Over either limit the answer is `RateLimited`; nothing
was done and nothing was bound to the id, so retrying with the same id later
is safe.

Calls on one `Client` are serialized. One request is in flight at a time, so
an approval wait blocks other calls on the same client.

After a timeout, the late response is recognized by its correlation id and
discarded, so the channel stays usable.

## 3. Idempotency and retry (read this)

> **Retrying with the same request id never performs a second effect.
> Retrying with a new request id is a new request.**

* Plain methods generate a fresh random 128-bit request id from the kernel
  CSPRNG.
* `*_with_id` methods send the id you give them.
* The broker scopes request ids to the authenticated principal and epoch, and
  binds each id to the canonical request content (§9.2). The same id with
  different content is answered with `RequestIdConflict`.
* For `Consume`, a repeated id returns `PriorReservation { reservation_id,
  status }`, where `status` is one of `Reserved`, `Dispatched`, `Completed` or
  `Unknown`. **No new dispatch takes place** (§5.2). `consume_with_id` returns
  this as `Consumed::Prior`. `read_file`/`replace_file`/`https_request` return
  `Error::PriorReservation`, because they cannot produce the original result.
  The bytes of an earlier read are not resent.
* "Once" means one *attempt*. If the adapter failed after dispatch, the budget
  stays spent. `EffectUnknown` and `Unknown` mean that nobody knows whether
  the effect happened. Nothing retries automatically.

Pattern:

```rust
match client.https_request(cap, req.clone()) {
    Err(e) if e.outcome_uncertain() => {
        let id = e.request_id().expect("consume carries an id");
        // Same id: learns the status, cannot cause a second request.
        let status = client.consume_with_id(id, cap, Client::https_operation(req)?)?;
    }
    other => { /* … */ }
}
```

The CLI prints the request id for every mutating command and accepts
`--request-id HEX`. After a timeout it tells you the exact id to retry with.

## 4. The `tessera` CLI

```text
tessera [--json] [--timeout DUR] [--approval-timeout DUR] [--socket PATH] <command> …
  request   SCOPE TERMS [--description TEXT]
  read      --cap CAP [--max-bytes N] [--out FILE]
  replace   --cap CAP (--from FILE | --stdin)
  http      --cap CAP [--method M] [--path P] [-H 'N: v']… [--data T | --data-file F] [--out F]
  delegate  --cap CAP --to AGENT SCOPE TERMS
  attenuate --cap CAP SCOPE TERMS
  transfer  --cap CAP --to AGENT
  drop | inspect | revoke  --cap CAP
  list      (every capability you own, e.g. ones delegated to you)
  spawn     --profile N
SCOPE: --file OBJ [--rights read,replace] | --https EP [--methods get,post] [--max-body N]
TERMS: --budget N|unlimited [--depth N|unlimited] [--expiry inherit|90s|5m|2h|1500ms]
```

* `request` prints the request id, then `queued: waiting for operator
  approval … expires in Ns` when the broker acknowledges, then blocks.
* `--socket PATH` connects to a stream socket instead of `TESSERA_BROKER_FD`
  (tests and tools).
* `read` and `http` write the raw body to stdout, or to `--out`. With `--json`
  the body is included as `body_utf8`, or as `body_hex` when it is not valid
  UTF-8.
* Ids are 32 hex digits. Agents are written `<epoch-hex>:<serial>`.
* Exit codes:

  | Code | Meaning |
  |---|---|
  | 0 | Success |
  | 1 | Broker denial |
  | 2 | Usage error |
  | 3 | Outcome uncertain (retry with `--request-id`) |
  | 4 | Other failure |

## 5. Compatibility mode vs native mode (§3.1)

**Compatibility mode** (`capsandbox run -- <harness>`): an unmodified harness
runs in the baseline sandbox. It has no ambient credentials and no direct
network beyond approved model routing. It cannot perform a protected
operation unless something calls the broker. The `tessera` CLI is that
"something" for shells and tool-calling harnesses. A harness tool definition
can simply shell out to `tessera read --cap … --max-bytes …`. The harness's own
permission settings are extra restrictions only: no harness setting can widen
what the broker allows.

**Native mode**: a capability-aware agent links `tessera-sdk`. It requests,
splits (`delegate`), transfers and spawns explicitly. Each subagent is a
separate sandbox created with `spawn`, with its own channel and identity. A
thread or a prompt inside one process is **not** a separate principal.

`crates/sdk/examples/swarm_demo.rs` is the minimal native harness for the
§12.2 research swarm:

1. A gets 100 HTTPS requests at depth 2, delegates 30 to B and 20 to C, and
   keeps 50.
2. B gives 10 to D at depth 0.
3. D uses 3, leaving 97 in total.

The test `crates/sdk/tests/swarm.rs` drives the same functions against a mock
ledger with four channels. It checks conservation, that a copied id gives no
authority, that depth 0 blocks further delegation, and that revoking B stops D
but not C.

```text
swarm_demo coordinator --endpoint 7 --worker-profile 2      # in A's sandbox
swarm_demo worker --cap <hex> --sub-profile 3 --give 10     # in B's sandbox
swarm_demo worker --cap <hex> --use 3 --path /search        # in D's sandbox
```

**Handoff:** protocol v1 gives a recipient no way to learn which capabilities
it was given (see §7). The coordinator prints `HANDOFF <agent> <cap>` lines,
and whatever starts the workers passes the id as `--cap`.

## 6. Security notes

* **The SDK is untrusted.** A compromised agent can bypass it, patch it, or
  write raw frames. Every check that matters is in the broker. SDK-side
  checks (field bounds, frame size, response validation) exist for robustness
  and clear errors, not for security.
* **No identity claims.** The protocol has no field for the caller's identity.
  The broker identifies the caller by the channel the launcher bound to the
  sandbox (ADR-0004). `recipient` fields *name* another principal and never
  authenticate anyone. The tests check that the caller's own id, even after it
  has been learned through `inspect`, never appears in a sent message, and
  that the `TESSERA_AGENT_ID` label is never sent.
* **Capability ids are references, not secrets.** Logging them or passing them
  to another agent is harmless. Using a capability requires that the
  authenticated caller *owns* it in the broker's ledger. To give authority to
  another agent, use `delegate` or `transfer`; copying the id does not do it.
* **Descriptions are untrusted.** Nothing the agent writes is shown to the
  operator as fact. The approval UI renders the broker's normalized fields.
* **Content is not logged.** `Debug` output of snapshots, HTTP requests and
  responses shows lengths only.
* **Forks share identity.** Every process in a sandbox (including subprocesses
  that inherit fd 3) is the same principal. Use `spawn` for a separate one.

## 7. Protocol gaps found while writing the SDK

Status after protocol v2 and broker hardening (ADR-0024). Items 1–5 are
resolved; 6 and 7 were resolved by ADR-0022.

1. **Description field.** *Resolved:* `RequestGrant.untrusted_description`
   (≤ 512 bytes), shown escaped under an UNTRUSTED label, not signed, audited
   by length and digest only.
2. **Idempotent replay for non-consume requests.** *Resolved:* a repeated id
   returns the original success (`GrantIssued` with the same cap, `Delegated`
   with the same child, `Spawned` with the same agent, `Dropped`, `Revoked`,
   `Transferred`, `Attenuated`). A repeat while a grant is pending attaches to
   it; a repeat while a spawn is launching attaches to the launch. Final
   denials of grant requests (denied, timed out, invalid) and failed spawns
   are remembered for the epoch, so a repeat gets the same denial and never a
   second prompt or launch. Transient refusals (`RateLimited`, `Unavailable`)
   are not remembered.
3. **"Pending" response.** *Resolved:* interim `GrantPending { request_id,
   expires_in_millis }`; see Timeouts.
4. **Recipients cannot discover received capabilities.** *Resolved:*
   `ListCapabilities { after }` lists the caller's own capabilities (64 per
   page, ascending id; `list_capabilities()` pages through them). `Spawn`
   still passes no parameters to the child; the child lists what it was
   delegated.
5. **No self-identity query.** *Unchanged by design:* an id is not a
   credential; the owner field of `Inspect`/`ListCapabilities` shows it, and
   a parent learns each child's id from `Spawn`.
6. **Datagram size versus socket buffers.** Resolved by ADR-0022 (1 MiB
   buffers, 96 KiB inline content).
7. **Correlation ids.** Resolved by ADR-0022.
