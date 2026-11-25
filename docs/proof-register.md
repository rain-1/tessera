# Proof register — authority core (`tessera-capability-core`)

Status as of 2026-11-25: **nothing in this repository is machine-proved.**
Verus is not installed in the development environment and no verifier has
been run. All evidence below is dynamic: unit tests, property-based tests
against a reference model, and an executable invariant checker. The code is
structured for a later Verus port (small pure functions, a plan/commit split,
`// requires:` / `// ensures:` comments on every transition), but comments
are not proofs.

This register follows spec §6.2: every theorem target lists its current
evidence, status and the trusted assumptions it depends on. Do not describe
the core, or the system, as verified on the basis of this document.

## Status vocabulary

| Status | Meaning |
|---|---|
| **tested-only** | Covered by deterministic unit tests and/or property tests; no proof. |
| **proof pending** | A Verus proof is planned for this crate; obligations are written down but not discharged. |
| **out of core scope** | The obligation is mostly discharged outside this crate (broker, journal, adapters, kernel). The core provides only a building block. |

## Evidence inventory

| Artifact | What it checks |
|---|---|
| `src/invariant.rs` `check_invariant` | Executable statement of the ledger invariant (intended Verus `spec fn inv`). Run after **every** step in all tests, and on every snapshot deserialization. |
| `tests/rules.rs` (29 tests) | One or more tests per core-level rule of spec §15, §5, §12.1 and the §12.2 swarm example. Every command goes through a harness that asserts invariant preservation and that denials leave the state unchanged. |
| `tests/scope.rs` (6 unit + 3 proptests, 2,000 cases each) | Every rights/method bit, body-size boundary, mismatched resource kinds, undefined-bit rejection; subset soundness, reflexivity/transitivity, and exact agreement of `is_subset` with denotational inclusion over a finite universe. |
| `tests/model.rs` (2 proptests, 512 cases each by default, up to 80 commands per case; plus a generator coverage check) | Random command sequences, including clock regression, epoch bumps, stale/forged callers and request-id repeats, executed against both the core and an independent naive reference model. After each step: accept/deny agreement, `check_invariant`, no mutation on denial/duplicate, per-capability field and liveness agreement, an independently maintained global conservation identity, and liveness monotonicity. One run uses tight limits to exercise capacity/lineage denials. Soak: `PROPTEST_CASES=20000 cargo test --release -p tessera-capability-core --test model` passed. |
| doctest in `src/lib.rs` | End-to-end mint / consume / deny example of the public API. |

## Theorems (spec §6.1)

| ID | Target | Core evidence | Status | Depends on |
|---|---|---|---|---|
| T1 | Every reachable finite allocation preserves accounting; no overspend. | Stored identity `initial = consumed + discarded + Σ balances` per pool and the derived `N = U + L + D` at the clock, both in `check_invariant`; `U` cross-checked against the reservation ledger. Tests: `budget_one_thousand_attempts_yield_one_reservation`, `repeated_splits_conserve_budget`, `unlimited_root_allocates_conserved_finite_children`, `maximal_budgets_do_not_overflow`, `swarm_example_12_2`; the model test checks an independently maintained global identity. | tested-only; proof pending | A1 |
| T2 | Child scope contained in parent at delegation and in root scope; lifetime bounded by ancestry. | `is_subset` soundness (scope proptests); per-edge checks on immutable creation snapshots (`origin`) plus "current within origin" in `check_invariant`; root capability equals root record terms. Tests: `broader_delegation_is_denied_and_authority_unchanged`, `attenuate_only_decreases_and_accounts_discard`. Transitivity of `is_subset` / `Expiry::within` gives the root bound. | tested-only; proof pending | A1 |
| T3 | Every authorized use has an authenticated live owner and a valid root authorization (or baseline). | CONSUME requires `owner == caller`, active current-epoch caller and `State::live`; every capability's root record exists and is `Approved{nonce}` or `Baseline` (`check_invariant`). Tests: `copied_capability_id_by_other_principal_denied`, `baseline_grants_are_recorded_separately`. | tested-only (core part); out of core scope (authentication) | A2 |
| T4 | No split/transfer/delegate from depth zero; finite depth decreases. | `Depth::can_delegate`, `Depth::admits_child` (strict), `Depth::decrement`; per-edge depth check on origin snapshots. Tests: `non_delegatable_split_transfer_delegate_denied`, `delegate_consumes_one_generation_split_then_transfer_two`, swarm test. | tested-only; proof pending | A1 |
| T5 | After revocation, later authorizations through the subtree fail. | `State::live` walks all ancestors (bounded by `max_lineage_length`) and fails on any `Revoked`; statuses are never reset; liveness monotonicity is asserted in the model test. Tests: `revoke_zero_balance_ancestor_kills_descendants`, `revoke_is_prospective_and_scoped_to_subtree`, swarm test. | tested-only; proof pending (core); the serial-order revoke/consume race is out of core scope (T9) | A5 |
| T6 | Expired, terminated or stale-epoch identities cannot authorize. | `require_active` (epoch + status) on every agent command and recipient; `State::live` checks expiry, owner status and owner epoch. Tests: `expiry_boundary`, `termination_stops_owner_but_not_delegated_children`, `epoch_bump_invalidates_everything_and_preserves_nonces`, `clock_regression_denied`. | tested-only (core part); out of core scope (trusted time, identity mapping) | A2, A4 |
| T7 | Each approval nonce redeemed at most once; exact request binding preserved. | MINT inserts the nonce in the same commit that creates the root; `spent_nonces` ↔ approved roots is a bijection in `check_invariant` and survives `BumpEpoch`; the root's terms equal `request.terms` exactly. Tests: `nonce_reuse_and_binding`, `mint_rejects_wrong_epoch_expired_request_and_bad_terms`, epoch test. | tested-only (ledger part); proof pending; the crypto binding is out of core scope | A3, A9 |
| T8 | Denial, invalid input and arithmetic overflow cannot increase authority. | `plan` (pure, total, all checked arithmetic) / `commit` (infallible, no arithmetic) split; no `unsafe` (`#![forbid(unsafe_code)]`); snapshot deserialization re-checks the invariant. Every test asserts the state is unchanged after a denial. Tests: `exhausted_counters_deny_without_mutation`, `capacity_and_lineage_bounds_deny`, `corrupt_snapshot_is_rejected`, model tests. | tested-only; proof pending | A1 |
| T9 | Concurrent requests refine a serial trace; no double spend. | `step` takes `&mut State`, so Rust aliasing rules allow only one writer at a time. A serial 1,000-attempt test shows at most one reservation. | out of core scope (broker single-writer queue and model checking) | A5 |
| T10 | Crash recovery never resurrects spent authority or re-dispatches uncertain reservations. | `BumpEpoch` invalidates every live grant, abandons `Reserved` reservations, keeps nonces; `State::replay` rebuilds from a log of successful commands and fails closed on any denial; `Reservation` is not `Clone`/`Deserialize`. Tests: `replay_rebuilds_identical_state`, epoch test. | out of core scope (journal protocol, fault injection) | A6 |
| T11 | Every claimed protected effect has a matching authorized reservation. | CONSUME returns a single `Reservation` bound to `(owner, request_id, capability, root, operation)`; repeated request ids return the earlier status and never a second reservation (`repeated_request_id_returns_previous_status_without_new_reservation`). | out of core scope (per-adapter refinement, Linux mediation) | A7, A8 |

## Trusted assumptions

| ID | Assumption | Discharged by |
|---|---|---|
| A1 | The Rust compiler, `core`/`std` (`BTreeMap`, `BTreeSet`, checked integer operations) and `serde` behave as documented. After a Verus port, also the Verus toolchain and any `external_body` specs for `BTreeMap`. | Toolchain trust (spec §2.1) |
| A2 | The broker builds `AuthenticatedCommand::Agent { caller, .. }` only from kernel-observed peer identity, and `AuthenticatedCommand::Operator` only for the separate operator endpoint. Commands deserialized from the journal are trusted; commands deserialized from workload IPC must never be passed to `step`. | Broker (WP3) |
| A3 | `VerifiedApproval::new` is called only by the approval service, after verifying the FIDO2 assertion (credential, RP id, client-data hash binding nonce and exact request, UP/UV flags). The core cannot enforce this across crates; its constructor is public. | Approval service (WP4) |
| A4 | `now` comes from a trusted monotonic clock and does not decrease within an epoch. The core denies regressions instead of trusting them, but cannot detect a clock that runs fast or slow. | Broker |
| A5 | All calls to `step` for one ledger are serialized, and their effects are released in commit order. | Broker single-writer queue (WP3) |
| A6 | The broker durably journals each successful command, with its `now`, before releasing the effect. After a crash it replays the journal and immediately issues `BumpEpoch`. | Journal (WP3) |
| A7 | An adapter performs at most one dispatch per `Reservation`, of exactly `reservation.operation()`, and never re-dispatches after a crash. | Adapters (WP5/WP6) |
| A8 | `ObjectId` / `EndpointId` name stable, registered resources, interpreted the same way by every adapter. | Adapter registry |
| A9 | Approval nonces are fresh and unpredictable (32 bytes from a CSPRNG). | Approval service |

No `assume`, `external_body` or `unsafe` exists in the core today, because no
proofs exist yet. When the Verus port begins, each such escape hatch must be
added to this table.

## Semantic decisions (spec ambiguities resolved)

1. **Accounting.** Balances live in *pools* (finite allocation boundaries):
   finite roots, finite allocations carved from unlimited capabilities, and
   unlimited capabilities attenuated to finite. DROP and budget-reducing
   ATTENUATE move units to D in the same transaction. REVOKE, expiry, owner
   termination and epoch change leave the balance in its record. D is then
   *computed* as the explicit part plus "stranded" balances of non-live
   records (spec §6.1 option (b)). Because liveness is monotone, no unit is
   counted twice or ever becomes usable again.
2. **Ancestor expiry vs. non-retroactive attenuation.** §4.4 says an expired
   ancestor invalidates its descendants, while §5 says ATTENUATE does not
   affect existing children. Resolution: ancestors are checked against their
   *creation-time* expiry (`origin`). Because every child's expiry is at most
   its parent's expiry at creation, this check is implied by the child's own
   expiry and is kept only as a defensive measure. Later attenuating a
   parent's expiry does not shorten its children.
3. **Depth.** SPLIT and DELEGATE both require the child's depth to be strictly
   lower than a finite parent depth (one generation). TRANSFER decrements
   depth by one. Split followed by transfer therefore costs two generations.
   ATTENUATE may lower depth to zero. Depth zero means use and attenuate
   only.
4. **Parent-owner termination** does not revoke capabilities already
   delegated to other principals. Capabilities owned by the terminated
   principal stop authorizing.
5. **DROP** sets status `Dropped`, so the capability stops authorizing even
   when its budget is unlimited, and discards any finite balance.
   Descendants are unaffected. The dropped capability's owner may still
   revoke its descendants.
6. **Who may revoke.** The operator may revoke any capability. An agent may
   revoke a capability it currently owns or one descended from a capability
   it currently owns (that capability need not be live). Revoking an
   already-revoked capability is denied (`AlreadyRevoked`).
7. **Request-id idempotency** is implemented for CONSUME only, keyed by
   `(authenticated AgentId, RequestId)` and therefore scoped to the epoch. A
   repeat with identical content returns `AlreadyReserved` with no state
   change, not even the clock. A repeat with different content is denied
   (`RequestIdConflict`). For other commands the broker handles idempotency.
8. **Time.** `step` takes trusted `now` and denies `now < clock`. Each
   successful transition records `clock = now`. `AdvanceClock` only records
   time. `BumpEpoch` is the single exception allowed to move the clock
   backwards (a fresh monotonic source after restart); this is safe because
   no earlier-epoch capability can be live again.
9. **Epoch bump** terminates every principal, abandons `Reserved`
   reservations, keeps all records, spent nonces and history, and does not
   reset id counters. Ids are never recycled, even across epochs.
10. **Issuance validity.** New grants (roots and children) must have a
    non-empty scope, an expiry not already elapsed, and a nonzero budget.
    ATTENUATE may reduce a budget to zero.
11. **Unlimited budgets.** An unlimited parent may issue finite children
    (each becomes a new pool) or unlimited children. A finite parent may
    issue only finite children. An unlimited capability attenuated to
    finite becomes the anchor of a new pool; its existing children keep
    their own terms.
12. **Approval request binding.** The core checks `request.epoch == epoch`
    and `now < request.request_expires`, then mints exactly `request.terms`
    to `request.recipient`. A denied mint does not spend the nonce.
13. **Bounds.** Limits on capability records, principals, roots,
    reservations and lineage length are enforced as denials. Records are
    never garbage-collected (see gaps).

## Known gaps and future work

- No Verus proofs. Next step: pin a Verus release, add `spec fn inv(s)`
  mirroring `check_invariant`, and prove `plan`/`commit` preservation one
  transition at a time, starting with T1, T4 and T8. `BTreeMap` needs a
  ghost `Map` view.
- Records are never compacted, so a long-lived installation eventually hits
  `max_capabilities` or `max_reservations`. Possible remedy: compaction at
  epoch bump, which would need its own invariant argument (nonces must be
  kept).
- `check_invariant` is O(n · lineage) and is not run on the hot path.
- Agent revocation authority is a core policy choice (decision 6) that the
  spec leaves to the implementation ("explicitly authorized revoker"). It
  should be confirmed in an ADR.
- Weighted costs, shared budgets and cascading attenuation are not
  implemented (spec §16 research extensions).
