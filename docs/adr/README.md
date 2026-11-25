# Architecture decision records

Format: context, decision, consequences, status. Status values:

- **Accepted**: decided.
- **Accepted (design)**: decided, not implemented.
- **Proposed**: the direction is chosen but depends on evaluation.
- **Deferred**: postponed to a later phase.
- **Open**: no decision yet.

Nothing here is implemented or verified unless the ADR says so.

| ADR | Topic | Spec source | Status |
|---|---|---|---|
| [0001](0001-single-writer-ledger.md) | Single-writer ledger | §16 Concurrency, T9 | Accepted (design) |
| [0002](0002-persistence-wal.md) | Append-only hash-chained WAL + fsync | §11, open Q persistence | Accepted (design) |
| [0003](0003-restart-epoch-fail-closed.md) | Restart: epoch bump, fail closed | §16 Restart, §11 | Accepted (design), model-checked |
| [0004](0004-peer-authentication.md) | Socketpair per sandbox + SO_PEERCRED | open Q peer auth | Accepted (design) |
| [0005](0005-launcher.md) | bwrap + seccomp + optional Landlock + cgroup v2 | open Q launcher | Accepted (design) |
| [0006](0006-fido2-verification.md) | RustCrypto verification, libfido2 transport | §8, changes WP4 wording | Accepted (design) |
| [0007](0007-https-client.md) | HTTPS client: no redirects/retries, own DNS | §9.4 | Accepted (design) |
| [0008](0008-verification-strategy.md) | Verus target; tests/proptest/model meanwhile | §16 Verification | Accepted; amended 2026-11-25: Verus pinned, mirrored core verified (`proofs/`) |
| [0009](0009-project-name-and-brand.md) | Name and mark: Tessera | — | Accepted |
| [0010](0010-product-boundary.md) | External platform, not a harness | §16 Product boundary | Accepted |
| [0011](0011-scope-language.md) | Small typed exact-resource scopes | §16 Scope | Accepted |
| [0012](0012-budget-semantics.md) | At-most-once attempt, no refunds, dedup | §16 Budget | Accepted (design), model-checked |
| [0013](0013-delegation.md) | Single owner, split/transfer, bounded depth | §16 Delegation | Accepted |
| [0014](0014-revocation.md) | Recursive prospective revocation; operator, or agent within its own subtree | §16 Revocation | Accepted, implemented (amended by 0022) |
| [0015](0015-attenuation.md) | Non-retroactive attenuation | §16 Attenuation | Accepted |
| [0016](0016-enforcement-split.md) | Brokered finite enforcement; BPF LSM deferred | §16 Finite/Direct enforcement, open Q BPF toolchain | Accepted / Deferred (refined by 0023) |
| [0017](0017-human-approval-and-ui.md) | FIDO2 UP/UV, isolated approval UI | §16 Human approval, open Q UI deployment | Proposed |
| [0018](0018-target-host-and-isolation.md) | Pinned kernel/distro | §16 Isolation, open Q kernel | Proposed |
| [0019](0019-file-object-identity.md) | Logical file slots | open Q file slot identity | Proposed |
| [0020](0020-model-api-credentials.md) | Model API proxy and credentials | open Q model API | Proposed |
| [0021](0021-independent-review.md) | Independent review | open Q review resources | Open |
| [0022](0022-broker.md) | Broker: single writer, journal entries, dispatch marker, request-id binding, channel identity, admin endpoint | §5.2, §9, §11, WP3 | Accepted, implemented (tested) |
| [0023](0023-bpf-lsm-direct-grants.md) | BPF LSM direct grants: not in MVP; read-only subtree class, libbpf-rs, lease-gated generation protocol | §10.2, §10.3, WP7 | Accepted (no direct grants in MVP); P6 design Proposed, modelled, not kernel-tested |

## Specification inconsistencies and gaps found in WP0

These need a spec revision (v0.2). Until then, the ADR listed for each one
governs.

1. **FIDO2 verification library.** §8.1 and WP4 say to use libfido2 for
   verification. ADR-0006 verifies in pure Rust and uses libfido2 only for
   transport. This also changes the §2.1 trust base: the "authenticator
   library" is trusted for transport only.
2. **Number of primitives.** §5 says "seven authority primitives", but §5.1
   and §9.2 make DELEGATE an eighth public transaction (ADR-0013).
3. **Where Revoke is accepted.** §9.2 lists `Revoke` in the agent protocol
   ("admin or designated revoker") and also requires a separate admin
   endpoint. There is no designated-revoker design. The operator revokes
   anything; an agent may revoke only within its own subtree (ADR-0014 as
   amended by ADR-0022).
4. **Request id reused with different content.** §5.2 says a repeated
   request id returns the earlier status. §9.2 binds ids to canonical
   content. The spec does not say what happens when the same id arrives with
   different content. ADR-0012 denies it (`RequestIdConflict`).
5. **Baseline grants across restart.** §11 invalidates "all live session
   grants". It does not say whether operator baseline policy (R2, §8.2)
   survives. ADR-0003 re-applies the baseline from admin configuration as a
   separate recorded event.
6. **"Unknown" versus "never dispatched".** §5.2 and §11 say unresolved
   reservations are "abandoned or reported as unknown". Without a durable
   dispatch-started marker, recovery cannot tell "never sent" from "sent,
   outcome lost". The MVP reports both as `unknown`. A pre-dispatch marker
   would add an fsync per operation.
7. **Uniqueness of IDs across epochs.** §4.3 makes IDs unique "within an
   authority epoch". Audit lineage across restarts needs globally unique
   IDs. ADR-0003 includes the epoch in capability ids and AgentIds.
8. **Optional Landlock versus R10.** §10.1 calls Landlock defence in depth.
   R10 forbids a silent downgrade. ADR-0005 makes each profile declare
   Landlock as `required` or `optional`, and records whether it was applied.
9. **Workspace layout drift.** §7 lists `approval-ui/`, `authenticator/`,
   `capability-proofs/`, `enforcement/ebpf/` and `tests/adversarial/`. The
   repository has `crates/approval` (which covers the UI and the
   authenticator) and does not yet have proofs, ebpf or adversarial
   directories. `capsandbox run` (§3.1) becomes `tessera run` (ADR-0009).
10. **§12.2 wording.** "Revoking B" means revoking B's capability (the
    30-unit child), not the principal B. Principal termination follows §4.4
    and §9.1, which conflict slightly: §4.4 says parent-owner termination
    does not revoke delegated children, while §9.1 says termination
    "invalidates the subject's remaining grants". These are consistent only
    if "remaining grants" means grants the terminated subject owns, not its
    delegated descendants. This needs explicit wording.
11. **Dedup test bound (from the model).** A request-id dedup test at budget
    1 cannot detect a missing dedup check, because the budget check hides
    it. The §15 and WP3 tests must use budget ≥ 2.
12. **`SO_PEERCRED` is not a cross-check (WP3).** ADR-0004 planned a
    `SO_PEERCRED`/cgroup cross-check of each channel. The launcher creates
    the socketpair in the broker process, so the credentials name the broker
    itself. Identity is the channel alone (ADR-0022).
13. **Datagram size (WP3).** `MAX_CONTENT_BYTES` (8 MiB) cannot be carried
    in one `SOCK_SEQPACKET` datagram under default socket buffers. The
    broker caps inline content at 96 KiB and denies larger reads rather than
    truncating (ADR-0022). The spec should state a content bound or a
    streaming design.
