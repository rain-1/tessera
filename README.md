<p align="center"><img src="docs/brand/tessera-lockup.svg" alt="Tessera" width="420"></p>

# Tessera

A capability platform for running untrusted autonomous agents. Authority is an explicit,
countable, delegable and revocable resource, minted only by a human with a hardware key,
and enforced outside the agent harness so that a compromised agent cannot relax it.

> Status: early implementation of [`docs/specification.md`](docs/specification.md)
> (v0.1). Nothing here is verified or security-certified yet. There has been no
> independent review. See the [status table](#status-and-limitations).

## What it is

An agent (an LLM harness, a shell, any subprocess tree) runs in a Linux
sandbox with **no ambient authority**: no host files, no network and no
credentials. To read a file or call an HTTPS API, it asks the Tessera
broker for a **capability**. A capability is an entry in a ledger, bound
to that agent, with:

* a **scope**: one registered file with `read`/`replace` rights, or one
  registered HTTPS endpoint with methods and a body limit;
* a **budget**: a number of operation attempts, or unlimited. A failed
  attempt still counts;
* a **delegation depth** and an **expiry**.

A new root capability exists only after the operator approves the exact,
broker-normalized request with a FIDO2 key. Agents can split, delegate,
attenuate, transfer or drop capabilities they own, but never widen them.
Revocation is recursive. Conservation holds across every operation:
**N = U + L + D** (minted = used + live + discarded). The broker performs
every effect through a trusted adapter, at most once per reservation,
after a durable journal commit. A broker restart is fail-closed: it starts
a new epoch, every grant dies, and sandboxes are killed.

### The mark

A *tessera hospitalis* was a Roman token of trust, broken and shared between parties.
The logo is a 2×2 mosaic tile (root authority) with one piece moved out (a delegated,
attenuated child). The dashed outline shows the piece is still accounted for, so
the conservation invariant **N = U + L + D** holds.

## Architecture

```text
operator + FIDO2 key
   │  tessera-admin: shows the normalized request,
   │  re-checks its digest, gets the assertion
   ▼
admin socket (0600; peer uid must equal broker uid)
   │
┌────────────────────────────────────────────────────────┐
│ tesserad (broker)                                      │
│                                                        │
│ single writer: validate -> journal append + fsync      │
│                -> capability-core step -> release      │
│ approval session: canonical GrantRequest, FIDO2 verify │
│ adapters: file slots, HTTPS endpoints (at most once)   │
└────────────────────────────────────────────────────────┘
   │ launcher: bwrap + seccomp        ▲ SOCK_SEQPACKET per
   │ + Landlock + cgroup v2           │ sandbox on fd 3
   ▼                                  │ (identity = channel)
┌────────────────────────────────────────────────────────┐
│ sandbox (untrusted)                                    │
│ tessera-sandbox-init -> agent workload                 │
│ `tessera` CLI / SDK; no host files, network or creds   │
└────────────────────────────────────────────────────────┘
```

| Crate | Role | Trust |
|---|---|---|
| [`capability-core`](crates/capability-core) | pure ledger: scopes, budgets, transitions, `check_invariant` | trusted; Verus target |
| [`journal`](crates/journal) | append-only hash-chained WAL, recovery | trusted |
| [`approval`](crates/approval) | canonical grant request, enrollment, FIDO2 assertion verification | trusted |
| [`protocol`](crates/protocol) | bounded, canonical wire schema and framing | parses untrusted input |
| [`broker`](crates/broker) | `tesserad`, `tessera-admin`: reactor, admin endpoint, dispatch | trusted |
| [`launcher`](crates/launcher) | bubblewrap + seccomp + Landlock + cgroup sandbox, probe | trusted |
| [`adapters/file`](adapters/file), [`adapters/https`](adapters/https) | the only code that touches protected resources | trusted |
| [`sdk`](crates/sdk), [`cli`](crates/cli) | `tessera` client used inside sandboxes | untrusted |

## Quickstart

Requirements: Linux ≥ 6.12, bubblewrap, unprivileged user namespaces, a
delegated cgroup v2 subtree (a normal systemd login session has one), and
Rust (installed from `rust-toolchain.toml`). The details are in
[docs/install.md](docs/install.md).

```sh
cargo run -p tessera-launcher --bin tessera-launch-probe   # can this host launch sandboxes?
make test                                                  # or: cargo test --workspace --locked
scripts/demo.sh                                            # full walkthrough, below
```

`scripts/demo.sh` starts a real `tesserad` with a throwaway configuration
and enrolls a **software** approval key (development only). It registers a
file and launches a sandboxed agent that asks for a one-use read
capability. It approves the request with `tessera-admin`, shows that the
first read succeeds and the second is denied (`InsufficientBudget`), then
shows the capability tree, the accounts and the audit log. It finishes by
revoking, running an emergency stop and restarting the daemon on the same
journal (the epoch increases and old grants are dead).

To run it yourself, see [docs/operations.md](docs/operations.md). In short:

```sh
tesserad --config tesserad.json &
tessera-admin enroll --key operator.key        # or --fido2 /dev/hidrawN (feature fido2-cli)
tessera-admin register-file notes.txt          # -> id 1
tessera-admin create-principal agent           # launches the sandbox
#   inside: tessera --json request --file 1 --rights read --budget 1 --depth 0
tessera-admin pending
tessera-admin approve 1 --key operator.key
#   inside: tessera --json read --cap <cap_id>
tessera-admin revoke <cap_id>
```

## Status and limitations

| Area | State | Evidence |
|---|---|---|
| Authority core (scopes, budgets, split/delegate/attenuate/transfer/revoke, expiry, epochs) | implemented, **tested** | unit, property and reference-model tests; fuzz target `core_step`; [proof register](docs/proof-register.md) |
| Verus proofs of the core | in progress on a separate branch, **not merged**; nothing is machine-proved here | CI `verus` job runs once `proofs/run_verus.sh` exists |
| Commit/dispatch/revoke/crash protocol | **model-checked** (bounded) | `models/dispatch_model.py` and TLC on `models/Dispatch.tla` (both pass) |
| Journal (WAL, hash chain, torn-tail handling) | implemented, tested | fault-injection tests; fuzz target `journal_recover` |
| Broker (`tesserad`), admin CLI, approval flow | implemented, tested with the **software** authenticator | broker, crash and swarm tests; `scripts/demo.sh` |
| FIDO2 hardware tokens | written (`fido2-cli` feature), **untested against hardware** | |
| Sandbox launcher | implemented, tested on Debian 13 / Linux 6.12 | launcher sandbox tests, `tests/adversarial/` corpus |
| File adapter | implemented, tested | |
| HTTPS adapter | implemented, tested against a local TLS server | |
| BPF LSM direct enforcement (WP7) | research only; not used | `docs/bpf-lsm*` |
| Fuzzing | 8 cargo-fuzz targets; 60 s baseline per target, no findings | [release.md](docs/release.md#fuzzing) |
| Supply chain | cargo-deny policy, SBOMs, reproducible builds verified locally | [release.md](docs/release.md) |
| Release signing, independent review | **not done** | ADR-0021 |

Known limitations (more in [operations.md §8](docs/operations.md#8-known-residual-risks-operator-view)
and [threat-model.md §8](docs/threat-model.md)):

* The software authenticator proves no physical presence and is for
  development only.
* Revocation is prospective. Effects reserved before a revoke can still
  happen, and data that was read cannot be un-read.
* Remote effects are at-most-once, not exactly-once. An effect interrupted
  by a crash is reported as `unknown` and never retried.
* The audit log is not tamper-evident. The journal is tamper-evident only
  against an off-host checkpoint. Root on the host is out of scope.
* There is no information-flow control. A principal that can read secrets
  and reach the network can leak them.

## Documentation

* [Specification](docs/specification.md) · [Threat model](docs/threat-model.md) ·
  [ADRs](docs/adr/README.md) · [Traceability](docs/traceability.md) ·
  [Proof register](docs/proof-register.md)
* [Install](docs/install.md) · [Operations](docs/operations.md) ·
  [Release engineering](docs/release.md) · [SDK and CLI](docs/sdk.md) ·
  [Protected effects](docs/protected-effects.md) ·
  [Kernel feature report](docs/kernel-feature-report.md)
* [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)

## License

Apache-2.0.
