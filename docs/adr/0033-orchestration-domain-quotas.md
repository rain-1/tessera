# ADR-0033: Admission limits per orchestration domain

- Status: Accepted. Implemented in `crates/broker` (`reactor.rs`,
  `ledger_quota.rs`, `config.rs`); tested.
- Spec: §9.2 (agent-initiated spawn), §9.4, §11. Amends ADR-0024
  (admission control), ADR-0032 (dispatch fairness) and ADR-0031
  (compaction also on emergency stop). Re-review 2026-11-26, item N1 and
  the informational item (`docs/security-review-2026-11-25.md`).

## Context

An *orchestration domain* is an operator-created principal together with
every principal spawned under it (`OrchNode::domain`). Spawning is bounded
(8 children per principal, depth 2, 16 principals per domain), but the
approval pending cap, the approval rate window, the dispatch cap and the
ledger record quotas were per principal. Spawning children multiplied a
domain's share: a tree of 9 principals held 17 of the 18 approval slots,
so other domains got "approval queue full", and the operator saw 9 times
the prompt rate.

## Decision

Every shared broker resource that agents compete for is accounted per
domain. The domain, not the principal, is the unit the operator created.

- **Approval slots.** The queue plus the active request form
  `slots = approval_queue + 1`. A domain may hold at most
  `min(max_pending_approvals_per_domain, ceil(slots / live domains))`,
  where a live domain is one whose root principal is active. Once a domain
  has one request pending, it may not take a slot still needed for the
  first request of every other live domain that has none pending
  (reservation). With the defaults (16 + 1 slots, 2 per domain) up to 8
  domains always find room. With more live domains the fair share shrinks
  to `ceil(slots / domains)`, and slots freed by approval, denial or
  timeout go first to domains with nothing pending. A guarantee for more
  domains than slots would need eviction, which we do not do.
- **Round-robin and rate window.** Activation walks domains in order
  (oldest request first within a domain). `approval_max_per_window` counts
  the prompts of a whole domain. The window ends only when the domain's
  root is terminated, which terminates every member.
- **Dispatch.** `max_dispatch_per_domain` (default 2 of 4 workers) bounds
  the jobs of a domain on the workers. Deferred jobs are released
  round-robin across domains, then across the principals of a domain. Each
  job records its domain, so the slot is returned correctly even after an
  emergency stop cleared the domain map.
- **Ledger records.** `LedgerQuotas` gains `derived_per_domain` (2 048)
  and `reservations_per_domain` (16 384), checked alongside the
  per-principal and per-root quotas. One domain can use about 2% of either
  global cap (`Limits::max_capabilities` = 100 000,
  `Limits::max_reservations` = 1 000 000) per epoch, so a spawn tree
  cannot exhaust them. Operator-created domains are the only unbounded
  factor, and they are operator actions.
- **Emergency stop compacts.** After the epoch bump, `CompactEpoch` is
  journaled and then applied, as at startup. Compaction is deferred until
  no job of the ended epoch is still on a worker: such a job may still
  journal a file-replacement intent or an outcome for its reservation,
  which must stay in the ledger until then.

All limits are configurable in `tesserad`'s `limits` section
(`approval_queue`, `max_pending_approvals_per_domain`,
`approval_max_per_window`, `max_dispatch_per_domain`,
`ledger_quotas.{derived,reservations}_per_domain`).

## Consequences

- An agent gains no admission capacity by spawning. A multi-agent
  orchestration shares one budget of prompts, approval slots, workers and
  records. Operators running large trees raise the per-domain limits
  explicitly.
- The capability core is unchanged: these are broker admission policies
  outside the verified ledger (the Verus mirror and the differential test
  are unaffected).
- Tests: `crates/broker/tests/rereview_regressions.rs`.
