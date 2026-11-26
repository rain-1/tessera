# ADR-0031: Ledger compaction at the epoch boundary

- Status: Accepted. Implemented in `crates/capability-core`
  (`AdminCommand::CompactEpoch`) and `crates/broker` (`Reactor::open`).
  Machine-checked on the Verus mirror since 2026-11-26 (see Verification).
  The production code is tied to the mirror by the differential test
  (proof register A13).
- Spec: §4.4, §6.1, §11. Closes security review 2026-11-25 finding 3 together
  with the per-principal and per-root admission limits of ADR-0024. Amends
  proof-register semantic decisions 9 and 13 ("records are never
  garbage-collected").

## Context
The ledger's global bounds (`max_capabilities`, `max_principals`,
`max_roots`, `max_reservations`) counted every record ever created. A
principal could fill them by self-delegation; because every record survived
restart, the installation stayed unable to serve anyone after a restart
(review finding 3, proof of concept `exhaust`). ADR-0024's per-principal and
per-root quotas bound what one principal can create in an epoch, but not the
accumulation across epochs.

Every record of an earlier epoch is permanently dead: its owner is a
terminated principal of a stale epoch, and `BumpEpoch` abandoned every
unresolved reservation. A capability's owner is always a principal of the
epoch its root was issued in (MINT/baseline recipients, DELEGATE and TRANSFER
recipients must be active, and every derivation needs a live parent), so no
current record refers to an earlier-epoch one.

## Decision

### Core: `AdminCommand::CompactEpoch`
A new operator command, appended last to `AdminCommand` so journaled
commands keep their encoding. It removes exactly:
- principals of earlier epochs;
- roots issued in an earlier epoch, with every capability, pool and
  reservation of their lineage;
- the `(principal, request id)` index entries of those reservations.

It keeps every spent nonce (T7), the epoch, the sequence and every id
counter (ids are never reused). Root ids grow with epochs, so the pruned
roots are exactly the ids below `State::retired_roots_below`; the invariant
allows a spent nonce to name a root below that floor and nothing else.

Accounting for pruned pools: none of their members was live, so their
`N = U + L + D` identity had `L = 0`. Their totals are added to
`State::retired` (`pools`, `initial`, `consumed`, `discarded`), where
`discarded` includes the balances stranded in the pruned records.
`check_invariant` requires `retired.initial = retired.consumed +
retired.discarded`, so the global conservation identity is

    Σ_pools N + retired.N = Σ_pools U + retired.U + Σ_pools D_explicit
                            + Σ stranded + retired.D

The effect `EpochCompacted` reports the counts and the pruned pools'
totals.

### Broker
At every start, after replay and the fail-closed `BumpEpoch`, the broker
(1) reports unresolved reservations of the previous epoch in the audit log
as before, (2) keeps display-only admin views of every earlier-epoch
capability and reservation ("archive"), (3) journals and applies
`CompactEpoch` (journal first, like every transition), re-runs
`check_invariant`, and (4) audits `epoch-compaction` with the counts, the
pruned pools' N/U/D and the cumulative retired totals.

The archive serves the operator's post-crash reconciliation (`tessera-admin
tree`, `reservations --uncertain`, `status`): pruned capabilities show with
their final status (`StaleEpoch`, ...), pruned reservations with
`abandoned-not-dispatched` / `unknown-dispatched-before-restart`. It lives in
memory only, authorizes nothing, is not counted against any ledger bound and
is replaced at the next start; its size is bounded by the previous epoch's
ledger bounds. Replay re-applies every journaled compaction, so the ledger
never holds more than the epochs since the last start.

Emergency stop bumps the epoch in-process but does not compact: dispatches
already handed to workers may still record outcomes against their
(abandoned) reservations. The next start compacts.

### Not done: journal file compaction
The journal file is not rewritten. History (and therefore audit lineage and
the operator's retained journal checkpoints) stays intact, replay time grows
with total history, and disk use grows by at most one epoch's records
(bounded by ADR-0024's per-principal, per-root and spawn quotas) per epoch.
A snapshot record plus file rotation needs a journal format change
(`crates/journal`) and a story for external checkpoints; it is left for a
later ADR.

## Evidence
- `crates/capability-core/tests/model.rs`
  `core_refines_reference_model_with_compaction{,_tight_limits}`: the
  reference model specifies compaction as "forget everything owned in an
  earlier epoch" (by *owner* epoch, whereas the core prunes by *root*
  epoch); compaction at random points (not only after a bump) agrees on
  every accept/deny, every surviving record, `check_invariant` and the
  global conservation identity including `retired`.
- `tests/rules.rs`: `compaction_frees_capacity_filled_by_a_previous_epoch`
  (capacity freed, nonces stay spent, ids not reused, pruned id unknown),
  `compaction_keeps_the_current_epoch` (current records, liveness and request
  ids untouched; idempotent), `compacted_snapshot_is_checked`.
- `crates/broker/tests/review_regressions.rs`
  `finding3_record_exhaustion_does_not_survive_restart` (the PoC: global
  bound filled, victim refused; after restart a fresh principal is served,
  twice, and each epoch bump in the journal is followed by `CompactEpoch`).
- `crates/broker/src/entry.rs` `command_variant_tags_are_stable`.
- Crash tests (`crates/broker/tests/crash.rs`) run unchanged against the
  archived views.

## Verification

The Verus mirror (`proofs/src/ledger.rs`) keeps every record in its
dense-vector slot. A record that compaction removes becomes a tombstone
(`pruned`), which every lookup treats exactly like a missing key, so ids
stay indices and are never reused. `compact` mirrors `plan_compact_epoch`
and its commit. Verus proves (see `proofs/README.md`, "Compaction"):

- `inv` is preserved by COMPACT. This includes T1 per-pool conservation
  and the retired-pool sums. `lemma_retired_balanced` proves
  `retired.initial = retired.consumed + retired.discarded`, with stranded
  balances counted in D. `lemma_global_conservation` proves the global
  identity above.
- COMPACT prunes exactly the principals and roots of earlier epochs and
  every capability, pool and reservation of those roots. It keeps every
  spent nonce, the epoch and every id counter.
- Liveness is unchanged for every id at every time: no live capability is
  pruned, and none is resurrected. Pruned records never change again
  (`frozen`).
- No present record refers to a pruned one (`lemma_no_dangling_*`). The
  pruned roots are exactly the ids below `retired_roots_below`. Every
  spent nonce names the root that redeemed it, and that root is present
  iff its id is at or above the floor. Spent nonces stay pairwise
  distinct, so a pruned approval cannot be redeemed again.

The differential test (`proofs/tests/differential.rs`) generates
`CompactEpoch` at random points and right after `BumpEpoch`. It compares
the mirror with the production core after every step, including the
tombstones (which must be absent in the core), `retired`,
`retired_roots_below` and the request-id index. A soak of 20,000 cases
per configuration passed on 2026-11-26. The production `state.rs`/
`step.rs` themselves are not verified; that link is assumption A13.

## Consequences
> Amended 2026-11-26: the first point below is superseded by the
> Verification section above. The mirror now represents pruned ids as
> tombstones, and `CompactEpoch` is mirrored, proved and differentially
> tested.

- The Verus mirror (`proofs/`) represents identifiers as dense vector
  indices and cannot express pruned (sparse) ids. `CompactEpoch` is
  therefore outside the mirrored command set: the differential test never
  generates it, and states after a compaction are covered by the production
  model test and `check_invariant`, not by the proof (proof register A13).
- `AdminRequest::Revoke` of an archived capability now answers
  `UnknownCapability`; it was a no-op on a dead record before.
- Agent-facing answers for pruned ids are `UnknownCapability`, the same as
  for any unknown or foreign id (finding 8).
