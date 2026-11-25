# ADR-0022: Broker implementation (WP3)

- Status: Accepted. Implemented in `crates/broker`; tested, not proved.
- Spec: §5.2, §8.1, §9, §11, §15, WP3. Refines ADR-0001, ADR-0002,
  ADR-0003, ADR-0004, ADR-0012, ADR-0014 and ADR-0017.

## Context
WP3 needs a broker that turns authenticated IPC into core transitions,
makes every transition durable before releasing anything, dispatches
adapter effects at most once, runs the approval flow, and fails closed
across restarts. The merged crates use different integer widths for the
same quantities, and the launcher's channel properties differ from what
ADR-0004 assumed.

## Decision

### Structure
- One writer thread owns `State`, `Journal`, request bindings, the
  approval session and the channel table. Reader threads (one per agent
  channel), admin connection threads and dispatch workers only post inbox
  messages. Commit path: `validate_command` (pure), append
  `Entry::Command { tick, command, binding }` and `fdatasync`, then `step`
  (a mismatch halts the broker), then release. Nothing is pipelined
  (ADR-0001).
- Journal payloads are a tagged postcard `Entry` (`TSBK` v1): `Genesis`
  (installation id), `Command`, `Dispatched`, `FileRegistered`,
  `EndpointRegistered`, `Enrolled`. The journal crate's `RecoveryEvent`
  helpers are not used: the core's own reservation ledger plus the
  `Dispatched` marker carry the same information in one format.
- Startup replays every `Command` through `step` (the same loop as
  `State::replay`, so that effects can re-derive binding results), maps each
  journal `EpochBump` record to `AdminCommand::BumpEpoch` at tick 0, checks
  the invariant, then appends a new `EpochBump` and applies `BumpEpoch`
  (ADR-0003). The journal's epoch and the ledger's epoch are kept equal
  (checked; a mismatch refuses to start). The operator's emergency stop does
  the same in place.
- Trusted time is milliseconds of `CLOCK_MONOTONIC` measured from the start
  of the epoch. A new epoch restarts the clock at 0, which the core permits
  only on `BumpEpoch`.

### Dispatch (resolves README item 6)
Consume → durable reservation → durable `Dispatched` marker → hand the job
to a worker → adapter → `RecordOutcome` journaled → response. Recovery
therefore distinguishes `abandoned-not-dispatched` (no marker) from
`unknown-dispatched-before-restart` (marker, no outcome). Both are never
re-dispatched. The cost is one extra fsync per consume. The agent sees
`Failed` (definite failure, new `WireReservationStatus::Failed` appended to
the wire enum) or `EffectUnknown`; neither refunds.

### Request ids (ADR-0012, docs/sdk.md §7.2)
Every mutating agent request binds `(principal, request id)` to the SHA-256
of its canonical bytes (`canonical_request_bytes`), journaled in the same
record as the command. A repeat with the same digest returns the original
success response (same reservation and status, same child id, same granted
capability id); a different digest is `RequestIdConflict`. A repeated
`RequestGrant` while approval is pending attaches its correlation id to the
pending request: one prompt, one mint, every waiter gets the same answer.
Denied or timed-out grant requests are not bound (nothing was created).

### Identity (amends ADR-0004)
The launcher creates the socketpair inside the broker process, so
`SO_PEERCRED` on the host end names the broker/launcher, not the sandbox.
It is recorded in the audit log and is **not** a cross-check. Identity is
only the channel: the broker allocates the AgentId (`CreatePrincipal`,
journaled), then asks the spawner to launch, then binds the returned host
end to that AgentId; the reader thread stamps every request with it. When a
channel closes for any reason the principal is terminated (journaled):
identity cannot be re-established. Ancillary data, an oversized datagram,
or an undecodable frame without a parsable correlation id close the channel
(and so terminate the principal). Undecodable frames with a correlation id
get a typed error under that id.

### Datagram size (docs/sdk.md §7.6)
The broker sizes both directions of each channel it owns to 1 MiB
(`SO_SNDBUFFORCE` if permitted, else `SO_SNDBUF`, capped by `wmem_max`).
Independently, inline content is capped at `MAX_INLINE_CONTENT` = 96 KiB
(file snapshot, file replacement, HTTPS request/response body), so every
message fits the default `wmem_default` (~208 KiB). File slots and
endpoints are clamped to this at registration. The file adapter denies
oversized reads rather than truncating, so a read never silently truncates.
The agent request frame bound is 128 KiB.

### Approval (ADR-0017)
`RequestGrant` builds the canonical approval `GrantRequest` (installation,
current epoch, enrolled operator, recipient = authenticated caller, scope
of a *registered* object/endpoint, budget in operation units, depth, finite
grant expiry, fresh random nonce, request expiry) and queues it behind the
`ApprovalSession` (one outstanding touch, rate-limited, bounded queue). The
operator lists, narrows (`check_narrowing_of`, broker re-checks), denies or
approves on the admin socket; `tessera-admin approve` recomputes the digest
of the request it displays and compares it to the challenge before
touching. The verified approval is converted to the core's
`VerifiedApproval` and `Mint` (nonce redemption + root) is one journal
record.

### Admin endpoint
Unix stream socket, mode 0600, in a directory owned by the broker uid and
not group/world-writable; every connection's peer uid must equal the
broker's euid; ancillary data closes the connection. Requests: status,
enroll, register file/endpoint, create/terminate principal, baseline,
pending/narrow/challenge/approve/deny, revoke, inspect/lineage/tree,
accounts, reservations, audit, emergency stop, checkpoint. Endpoint secrets
come only from the daemon configuration and are never journaled.

### Revocation (amends ADR-0014)
Agents may revoke a capability they own or any descendant of one they
currently own (the core's rule). The operator may revoke anything. There is
still no designated-revoker role.

### Id widths
The core's widths are authoritative. Core → wire/approval/adapter widens;
the reverse is a checked narrowing and denies on overflow (`convert.rs`):
agent epoch u128 → u64, approval object/endpoint ids u128 → u64, approval
rights bits the core does not implement (APPEND, METADATA, OPTIONS) refuse
the mint instead of being dropped.

### Audit
JSON lines (flushed, not fsynced; the journal is authoritative) plus an
in-memory ring: sequence, epoch, tick, journal seq, principal, kind,
request id and digest, capability/root/parent/child/reservation ids, scope
summary, budget before/after, outcome, effect status, content-free detail
(sizes and SHA-256 digests). Denials are audited; contents and secrets are
never recorded.

## Consequences / known gaps
- Agent `Spawn` is denied (`InvalidProfile`); principals are created by the
  operator only. Spawn idempotency is therefore trivially satisfied.
- `RequestGrant` has no untrusted-description field and no "pending"
  response (docs/sdk.md §7.1, §7.3); not added, to keep wire v1 stable.
- One fsync per transition plus one for the dispatch marker; no group
  commit.
- Bindings of denied/timed-out grant requests are not durable; a repeat
  creates a fresh approval request.
- Audit log is best-effort (not fsynced) and not hash-chained itself.
- Spawned sandboxes from an earlier epoch are killed with the broker
  process (`--die-with-parent`); an explicit cgroup sweep on startup is not
  implemented.
- `fido2-cli` path in `tessera-admin` is untested against hardware.
- Per-principal request rate limits are not implemented beyond bounded
  queues.
