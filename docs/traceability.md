# Traceability matrix (spec §15)

Status as of 2026-11-25 (WP0, broker rows updated in WP3 and in broker
hardening (ADR-0024), core proof rows updated in WP-verus). The production code is not proved. A
function-by-function mirror of the authority core is machine-checked with
Verus 0.2026.11.02.8bf68ee (`proofs/`). "tested" means CI tests exist in the named crate. Status
values:

- **planned**: an artifact is assigned but does not exist yet.
- **model-checked**: the *protocol* property holds in
  `models/dispatch_model.py` at the bounds in `models/README.md`. This says
  nothing about the Rust code.
- **drafted**: the model was written but not machine-checked
  (`models/Dispatch.tla`).
- **tested**: covered by `cargo test` in the named crate (WP3 broker rows).
- **machine-checked (Verus, mirrored model)**: discharged by Verus 0.2026.11.02.8bf68ee on `proofs/src`, a mirror of
  `crates/capability-core`. The mirror is tied to the production crate by
  the differential test `proofs/tests/differential.rs`, which is not a proof
  (proof register A13).
- **proved**: not used yet (would mean the production code itself is
  verified).

Module names are the planned layout for the crates, which are owned by the
implementation work packages. The reviewer sign-off column stays empty until
independent review is resourced (ADR-0021). Proof-register entries live in
`docs/proof-register.md`, which another work package maintains.

## Requirements

| ID | Requirement (short) | Planned crate / module | Proof / model artifact | Test (planned) | Status |
|---|---|---|---|---|---|
| R1 | Workload cannot weaken its confinement | `crates/launcher` (`profile`, `seccomp`, `bwrap`, `cgroup`) | — (Linux mediation evidence, kernel feature report) | `tests/adversarial/escape_syscalls`, `harness_escape_toggle` (PE-20, PE-21) | planned |
| R2 | Fresh human authorization for each new root; baseline recorded separately | `crates/approval` (`payload`, `verify`), `crates/broker` (`reactor::on_request_grant`, `mint`), `crates/capability-core` (`step::mint`) | T7. Model: `NoResurrection` (nonce mints ≤ 1) | `crates/approval` tamper/replay/wrong-key/no-UP tests; broker `approval_flow_mutated_reused_and_narrowed`, `repeated_grant_request_attaches_and_returns_the_same_capability`, `crash_*_mint_*` (software authenticator), `grant_pending_signal_description_and_consistent_repeats` (UNTRUSTED description escaped and unsigned; repeated/denied/timed-out ids answered consistently, no second prompt; ADR-0024), approval `padded_description_cannot_forge_screen_lines`, `every_invisible_or_format_character_is_escaped` (ADR-0032, review finding 5), `review_regressions::finding4_*`/`finding7_*`/`finding9_*` (per-principal queue, expired queued grants answered, rate window outside the session), `agent_spawn_*` (child gets profile baseline only); real YubiKey WP4 test | model-checked (nonce protocol); broker flow tested (software authenticator); hardware planned |
| R3 | Capability binds subject, scope, budget, delegation, lifetime, provenance | `crates/capability-core` (`types`, `Capability`) | Verus type invariants (ADR-0008) | unit tests on construction and validation | planned |
| R4 | Budgets conserved; no automatic refund | `crates/capability-core` (`ledger`, `step`), `crates/broker` (`reactor::on_consume`, `on_dispatched`) | T1 (Verus). Model: `NoOverspend` (variant `refund-on-failure` caught) | proptest conservation; broker `thousand_concurrent_attempts_on_budget_one_dispatch_exactly_once`, `swarm_example_12_2_through_the_broker` (N=U+L+D), crash tests (no refund) | machine-checked (Verus, mirrored model) (core conservation, T1); model-checked (protocol); tested (broker) |
| R5 | Delegation obeys attenuation and depth | `crates/capability-core` (`scope::is_subset`, `step::delegate`) | T2, T4: `proofs/src/{scope,ledger}.rs` | `delegate_broader_denied`, `depth_zero_denied`, `proofs/tests/differential.rs` | machine-checked (Verus, mirrored model) |
| R6 | Revocation stops later authorizations through the subtree | `crates/capability-core` (`live`, `step::revoke`), `crates/broker` (admin `Revoke`, agent `Revoke` within own subtree, ADR-0022) | T5. Model: `RevokeLinearization` | `revoke_ancestor_zero_balance`; broker `end_to_end_two_principals_read_delegate_revoke`, `agent_may_revoke_its_own_delegated_child_only`, swarm test, `sandbox_e2e` (incl. owner revoke of a grant delegated to an agent-spawned sandbox); `revoke_vs_consume_race_matches_a_serial_order` (concurrent, journal order as witness) | model-checked (ordering); tested (broker, concurrent) |
| R7 | Caller identity established externally | `crates/launcher` (`channel`), `crates/broker` (`conn`, channel bound at spawn; `spawner` per-principal workspace, ADR-0032) | ADR-0004 as amended by ADR-0022 (identity = channel; `SO_PEERCRED` not a cross-check); T3 refinement | broker `copied_capability_id_from_another_principal_is_denied`, `malformed_oversized_and_fd_passing_frames` (SCM_RIGHTS closes channel), `workspace_isolation_e2e` (two real sandboxes from one profile cannot exchange fd 3 or a file; corpus probes `tests/adversarial/cross_principal/`; review finding 1), `review_regressions::finding8_*` (constant answer for foreign and unknown ids), `sandbox_e2e` (real launcher channels; admin socket and the other sandbox's process/channel unreachable from inside; agent-spawned child bound to its own channel), `recipients_discover_their_capabilities` (listing is owner-only) | tested |
| R8 | Decisions auditable incl. root grant and delegation path | `crates/journal` (`record`, `chain`), `crates/broker` (`audit`, admin `Lineage`/`Tree`/`Audit`, `tessera-admin lineage`) | ADR-0002 (journal hash chain); ADR-0024 (audit hash chain, fsync policy, external checkpoint) | journal chain-verification tests; broker e2e/swarm tests check root id on every effect and no content in audit; `audit::tests::*` (tamper, deletion, consistent rewrite vs checkpoint, torn tail), `broker_audit_log_is_chained_verifiable_and_content_free`; `tessera-admin audit verify` | tested (broker); lineage display manual |
| R9 | Restart/crash restores no consumed grant, permits no replay | `crates/journal` (`recover`), `crates/broker` (`reactor::open`, epoch bump, `Dispatched` marker) | T10. Model: `NoResurrection`, `RestartInvalidatesGrants`, `NoReplayAfterCrash` (variants `no-epoch-bump`, `replay-after-crash`, `volatile-nonces` caught) | `crates/broker/tests/crash.rs` (kill before/after consume commit, after marker, after dispatch, after outcome, around mint; fsync failure; torn tail), `file_backed_journal_restart_resurrects_nothing`; startup `CompactEpoch` keeps nonces and frees capacity (ADR-0031: `review_regressions::finding3_record_exhaustion_does_not_survive_restart`, core `compaction_*`, model `core_refines_reference_model_with_compaction*`); startup sweep of earlier-epoch sandbox cgroups, fail closed (`crates/launcher/tests/sweep.rs`, ADR-0024) | model-checked (protocol); tested (fault injection, in-memory storage; sweep on real cgroups) |
| R10 | Unsupported enforcement fails closed | `crates/launcher` (`probe`) | ADR-0005, ADR-0018 | `missing_seccomp_refuses`, `landlock_required_missing_refuses` (PE-23) | planned |
| R11 | Small deterministic core with executable proofs | `crates/capability-core` | `proofs/` (Verus 0.2026.11.02.8bf68ee, ADR-0008 amendment) | proptest vs reference model; differential test vs the verified mirror | machine-checked (Verus, mirrored model); production crate not directly verified |
| R12 | Existing harnesses run unmodified where possible | `crates/launcher` (`ModelRoute` compat profile), `crates/model-proxy`, `crates/broker` (`model_route`), `crates/cli` (`run`), `crates/sdk` | ADR-0030 | `crates/model-proxy/tests/compat_sandbox.rs`; `examples/compat/run-claude.sh` (unmodified Claude Code against a local fake upstream, `docs/compat.md`) | compat mode implemented (P5); Codex path covered by the shim test only |

## Theorems

| ID | Target | Planned crate / module | Proof / model artifact | Test (planned) | Status |
|---|---|---|---|---|---|
| T1 | Accounting preserved; no overspend | `crates/capability-core` (`ledger`, `check_invariant`) | `proofs/src/ledger.rs` `inv`/`pool_ok`, `lemma_no_overspend`. Model `NoOverspend` for one root with one delegation, budget 1–2 | proptest command sequences; §15 split-repeatedly test; differential test | machine-checked (Verus, mirrored model) (stored per-pool identity); model-checked (protocol, tiny bounds); derived `N = U + L + D` tested only |
| T2 | Child scope ⊆ parent ⊆ root; lifetime bounded | `crates/capability-core` (`scope`, `expiry`) | `lemma_subset_sound`/`_trans`, `edge_ok` in `inv`, `lemma_lineage_attenuated` | `delegate_broader_denied`, scope negative tests (WP1 gate) | machine-checked (Verus, mirrored model) |
| T3 | Every authorized use has an authenticated live owner and valid root | `crates/capability-core` (`live`, `permits`), `crates/broker` (`conn`) | `State::step` ensures (CONSUME ⇒ active caller owns a live capability whose scope permits the operation) + ADR-0022 channel-identity argument | broker `copied_capability_id_from_another_principal_is_denied`, `sandbox_e2e` | machine-checked (Verus, mirrored model) (core part); tested (broker) |
| T4 | No delegation from depth 0; finite depth decreases | `crates/capability-core` (`step::delegate/split/transfer`) | `State::step` ensures, `edge_ok` (`admits_child`), `lemma_admits_child_strict` | `depth_zero_denied`, non-delegatable split/transfer tests | machine-checked (Verus, mirrored model) |
| T5 | After revoke, later authorizations through the subtree fail | `crates/capability-core` (`live`), `crates/broker` (writer order) | `State::live` (`chain_ok`), `records_monotone` + model `RevokeLinearization` | broker revoke tests; `revoke_vs_consume_race_matches_a_serial_order` (24 rounds, operator and owner revokes; no consume record or dispatch marker after the revoke record) | machine-checked (Verus, mirrored model) (core part); model-checked (ordering); tested (concurrent) |
| T6 | Expired / terminated / stale-epoch identities cannot authorize | `crates/capability-core` (`live`, time input), `crates/broker` (`epoch`) | `State::live` ensures (expiry, owner active in current epoch); model `RestartInvalidatesGrants` (stale epoch only) | clock/lifecycle tests; PID/cgroup reuse test | machine-checked (Verus, mirrored model) (core liveness predicate); model-checked (epoch part); rest planned |
| T7 | Each approval nonce redeemed at most once; exact binding | `crates/approval` (`payload`, `verify`), `crates/broker` (`Mint` + nonce in one journal record), `crates/journal` | `nonces_ok`, `lemma_roots_distinct_nonces`, MINT ensures; model `NoResurrection`; crypto assumptions (RustCrypto, ADR-0006) | approval tamper tests; broker mutated-digest and reused-assertion tests, `crash_after_mint_commit_resurrects_no_grant` | machine-checked (Verus, mirrored model) (ledger part); model-checked (redemption); tested |
| T8 | Denial, invalid input and overflow cannot increase authority | `crates/capability-core` (`step` totality, checked arithmetic), `crates/protocol` (bounded decode) | `post` (Err ⇒ unchanged) for every command; Verus overflow/bounds checks on all transitions | fuzzing of `crates/protocol`; overflow unit tests; differential test | machine-checked (Verus, mirrored model) (core); protocol decode planned |
| T9 | Concurrent requests refine a serial trace; no double spend | `crates/broker` (`reactor`, single-writer queue, ADR-0001) | Model: all invariants hold under arbitrary interleavings; variant `stale-validation` caught. TLA+ draft | `thousand_concurrent_attempts_on_budget_one_dispatch_exactly_once` (1,000 attempts, 20 threads, one dispatch); `revoke_vs_consume_race_matches_a_serial_order` (no dispatch marker after the revoke, also for jobs waiting on the per-principal dispatch cap, ADR-0032); per-principal admission control `per_principal_rate_limit_and_in_flight_bound` (ADR-0024); dispatch fairness `review_regressions::slow_principal_cannot_hold_every_dispatch_worker`; Loom later | model-checked (protocol); drafted (TLA+); tested (broker) |
| T10 | Crash recovery never resurrects spent authority or re-dispatches | `crates/journal` (`recover`), `crates/broker` (`reactor::open`, `Dispatched` marker) | Model `NoReplayAfterCrash`, `AtMostOneDispatchPerReservation`, `DispatchAfterDurableCommit`, `NoResurrection`; up to 2 crashes | `crates/broker/tests/crash.rs` fault-injection matrix | model-checked (protocol); tested (broker) |
| T11 | Every claimed protected effect has a matching reservation or direct-policy witness | `adapters/file`, `adapters/https`, `crates/launcher` | `docs/protected-effects.md` (inventory); model `DispatchAfterDurableCommit` (dispatch ⇒ durable reservation) | `tests/adversarial/*` per PE row | inventory done; model-checked (adapter ordering); mediation planned |

## Model invariant → spec map

| Model invariant | R / T |
|---|---|
| NoOverspend | R4, T1 |
| AtMostOneDispatchPerReservation | §5.2, T10 |
| RevokeLinearization | R6, T5 |
| NoReplayAfterCrash | R9, T10 |
| DispatchAfterDurableCommit | §11, T11 |
| NoResurrection | R2, R9, T7 |
| RestartInvalidatesGrants | R9, T6 (epoch part) |
| RequestIdDedup | §5.2, §9.2 |
