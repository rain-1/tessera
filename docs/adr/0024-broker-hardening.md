# ADR-0024: Broker hardening: protocol v2, agent spawn, audit chain, admission control

- Status: Accepted. Implemented in `crates/protocol`, `crates/broker`,
  `crates/sdk`, `crates/cli`, `crates/launcher`; tested, not proved.
- Spec: §8.1, §9.1, §9.2, §11, §15. Amends ADR-0022 (closes most of its
  known gaps), ADR-0005 (seccomp list, stop semantics) and ADR-0012
  (request-id bindings of denials).

## Context
ADR-0022 left these gaps: no untrusted description and no "pending" signal
on `RequestGrant`; agent `Spawn` denied; recipients could not discover
delegated capabilities; denied/timed-out grant ids not bound; no
per-principal rate limit; audit log neither chained nor synced; no startup
sweep of sandboxes from earlier epochs; the revoke-vs-consume race tested
only serially.

## Decision

### Protocol v2
`PROTOCOL_VERSION = 2`. A version-1 payload is refused before body parsing
(`UnsupportedVersion`); every peer is in this repository, so no
negotiation. The codec is unchanged: strict, canonical, bounded.
- `RequestGrant.untrusted_description: Option<BoundedString<512>>` (last
  field). Part of the canonical request bytes, so it is bound to the request
  id. Not part of the signed `GrantRequest`. Rendered by
  `tessera_approval::render_request` in a block labelled UNTRUSTED with
  control/bidi/invisible characters escaped and truncated; `tessera-admin
  approve` shows it the same way. Audited as length and SHA-256 only.
- `Request::ListCapabilities { after: Option<CapId> }` → `Response::
  Capabilities { caps: BoundedVec<WireCapabilityView, 64>, more }`: the
  caller's own capabilities (any status), ascending id. Read-only, no request
  id. Owner-only, as §9.2 requires for inspection.
- `Response::GrantPending { request_id, expires_in_millis }`: interim answer
  sent when a grant request is queued, before the final answer on the same
  correlation id. A repeat of a pending request id (same content) is a status
  query: another `GrantPending`, attached to the same approval. The SDK uses
  `call_timeout` for the first answer and `approval_timeout` for the total;
  silence is `Timeout`, an unanswered pending request is `ApprovalPending`.

### Agent spawn (§9.2)
- Only profiles in `BrokerConfig::spawn_profiles` (daemon config
  `agent_spawn_profiles`: `LaunchProfileId` → trusted launcher profile name +
  baseline grants). Anything else: `InvalidProfile`.
- Orchestration domain: an operator-created principal roots a domain at
  depth 0; a spawned child joins its parent's domain at depth + 1. Quotas
  (per epoch, terminated principals count): `max_children_per_agent` (8),
  `max_spawn_depth` (2; a principal at that depth may not spawn:
  `PermissionDenied`), `max_domain_agents` (16). Quota hits: `RateLimited`.
- Authority: the child receives exactly the profile's baseline grants
  (`InstallBaseline`, recorded as baseline roots, R2) and nothing from the
  parent. The parent learns the child's AgentId from `Spawned` and may
  delegate to it.
- Idempotency: `CreatePrincipal` is journaled with the `Spawn` request's
  binding in one record (`BindingResult::Spawned`). A repeat while the launch
  is in progress attaches to it; after it, the same child is returned; a
  failed launch is bound as a denial (in memory). Never a second sandbox.
- Termination cascades down the spawn tree: terminating a principal (by the
  operator, channel loss or emergency stop) terminates every principal it
  spawned and stops their sandboxes. A domain never outlives its creator.
- The domain tree is in memory only: every restart ends the epoch and
  terminates every principal, so there is nothing to recover.

### Request-id bindings of denials (amends ADR-0012/0022)
Final denials of `RequestGrant` (operator denial, approval timeout,
validation denials) and failed spawns bind `(principal, id)` to
`BindingResult::Denied(code)` in memory for the rest of the epoch. Not
journaled: nothing was created, and a restart ends every principal that could
repeat the id. Transient refusals (`RateLimited`, `Unavailable`, `Internal`)
and conflicts are not bound, so a retry with the same id is a fresh attempt.
At most `max_denied_bindings_per_agent` (1024) per principal; when full, new
grant/spawn requests from that principal are refused with `RateLimited`
(unbound), so the answer for any bound id never changes.

### Admission control
Per channel, in the reader thread before anything reaches the single writer:
a token bucket (`agent_rate_per_sec` 100, `agent_rate_burst` 200) and an
in-flight bound (`max_in_flight_per_agent` 64: forwarded requests without a
final answer; a pending grant counts until decided, a consume until its
outcome is journaled). Over either: `RateLimited` under the request's
correlation id, not forwarded, not bound. One principal cannot fill the
shared writer inbox.

### Audit log
JSON lines, each with `prev` = hex SHA-256 of the previous line's bytes
(genesis: 64 zeros). `AuditSync`: `every-event` (default), `every:N`,
`never` (`audit_fsync` in the daemon config). A write or sync failure stops
the broker (`StopReason::AuditFailure`, fail closed). On open the existing
file is verified: a torn final line is truncated (and that is audited);
anything else refuses to start. `AdminRequest::AuditCheckpoint` /
`tessera-admin audit checkpoint` prints `SEQ:HASH` of the last event for
off-host retention; `tessera-admin audit verify --file F [--checkpoint
SEQ:HASH]` verifies offline. This detects corruption and rewriting relative
to a retained checkpoint, not a rewrite of all history plus every checkpoint
(§11).

### Startup cgroup sweep and termination (§11)
`tesserad` uses a cgroup group private to the broker (`launcher.cgroup_group`,
default `tesserad`). Before serving, `Launcher::sweep_stale_cgroups` kills
(`cgroup.kill`) and removes every leaf in that group not created by the
current process, including nested cgroups; if any cannot be removed within
5 s, `tesserad` refuses to start. Without a cgroup leaf (operator opt-out),
`SandboxHandle::stop` now pins the PID-namespace init with a pidfd, kills it
and waits for it to exit, so `stop()` returns only after every process of the
sandbox is gone (previously `--die-with-parent` made this asynchronous).

### Launcher details
- Linux AIO (`io_setup`, `io_destroy`, `io_submit`, `io_cancel`,
  `io_getevents`, `io_pgetevents`) is denied by seccomp, like io_uring.
- Landlock rules for single-file read-only binds use file-level rights only;
  directory rights on a file made the ruleset "partial" and a Required launch
  fail.

### Daemon configuration
Unknown keys are errors at every level (`deny_unknown_fields`). The journal's
`TruncateUnverifiableFinalRecord` tail policy is available only as the
explicit flag `tesserad --truncate-unverifiable-final-record` (warned).

## Evidence
- `crates/broker/tests/hardening.rs`: `revoke_vs_consume_race_matches_a_serial_order`
  (24 rounds, operator and owner revokes, pipelined consumer; the journal
  order is the linearization witness: no consume record and no dispatch
  marker after the revoke record, adapter runs = journaled reservations,
  answers per request id are journaled successes followed only by `Revoked`),
  pending/description/denial-binding tests, discovery and pagination,
  spawn (idempotency, attach-while-launching, quotas, baseline-only, cascade),
  admission control, audit chain through the broker.
- `crates/broker/tests/sandbox_e2e.rs` (real bwrap/seccomp/Landlock/cgroup):
  agent-spawned third sandbox, discovery by listing, owner revoke, admin
  socket and the other sandbox's process/channel unreachable from inside,
  cascade termination including cgroup removal. The test used to skip
  silently under newer cargo layouts; it now fails if a binary is missing.
- `crates/launcher/tests/sweep.rs` (real cgroups), `audit` unit tests,
  protocol codec tests, SDK wire tests, CLI tests, config tests.

## Consequences / remaining gaps
- No group commit; one fsync per transition, one per dispatch marker, and by
  default one per audit event.
- Denial bindings and the domain tree are lost on restart by design (the
  epoch ends).
- `Spawn` passes no parameters to the child; the child discovers delegated
  capabilities by listing.
- Rate limits are per principal, not per domain; a domain of N principals
  gets N budgets (bounded by `max_domain_agents`).
- The audit hash chain is not anchored externally by the broker itself; the
  operator must retain checkpoints off-host.
- The in-sandbox isolation probes in `sandbox_e2e` check the admin socket
  path and the other sandbox's PID visibility/channel path; abstract-socket
  and network isolation are covered by the launcher's adversarial corpus.
- `fido2-cli` remains untested against hardware.
