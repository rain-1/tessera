# Traceability matrix (spec §15)

Status as of 2026-11-25 (WP0, broker rows updated in WP3). **Nothing is
proved.** "tested" means CI tests exist in the named crate. Status values:

- **planned**: an artifact is assigned but does not exist yet.
- **model-checked**: the *protocol* property holds in
  `models/dispatch_model.py` at the bounds in `models/README.md`. This says
  nothing about the Rust code.
- **drafted**: the model was written but not machine-checked
  (`models/Dispatch.tla`).
- **tested**: covered by `cargo test` in the named crate (WP3 broker rows).
- **proved**: not used yet.

Module names are the planned layout for the crates, which are owned by the
implementation work packages. The reviewer sign-off column stays empty until
independent review is resourced (ADR-0021). Proof-register entries live in
`docs/proof-register.md`, which another work package maintains.

## Requirements

| ID | Requirement (short) | Planned crate / module | Proof / model artifact | Test (planned) | Status |
|---|---|---|---|---|---|
| R1 | Workload cannot weaken its confinement | `crates/launcher` (`profile`, `seccomp`, `bwrap`, `cgroup`) | — (Linux mediation evidence, kernel feature report) | `tests/adversarial/escape_syscalls`, `harness_escape_toggle` (PE-20, PE-21) | planned |
| R2 | Fresh human authorization for each new root; baseline recorded separately | `crates/approval` (`payload`, `verify`), `crates/broker` (`reactor::on_request_grant`, `mint`), `crates/capability-core` (`step::mint`) | T7. Model: `NoResurrection` (nonce mints ≤ 1) | `crates/approval` tamper/replay/wrong-key/no-UP tests; broker `approval_flow_mutated_reused_and_narrowed`, `repeated_grant_request_attaches_and_returns_the_same_capability`, `crash_*_mint_*` (software authenticator); real YubiKey WP4 test | model-checked (nonce protocol); broker flow tested (software authenticator); hardware planned |
| R3 | Capability binds subject, scope, budget, delegation, lifetime, provenance | `crates/capability-core` (`types`, `Capability`) | Verus type invariants (ADR-0008) | unit tests on construction and validation | planned |
| R4 | Budgets conserved; no automatic refund | `crates/capability-core` (`ledger`, `step`), `crates/broker` (`reactor::on_consume`, `on_dispatched`) | T1 (Verus). Model: `NoOverspend` (variant `refund-on-failure` caught) | proptest conservation; broker `thousand_concurrent_attempts_on_budget_one_dispatch_exactly_once`, `swarm_example_12_2_through_the_broker` (N=U+L+D), crash tests (no refund) | model-checked (protocol); tested (broker) |
| R5 | Delegation obeys attenuation and depth | `crates/capability-core` (`scope::is_subset`, `step::delegate`) | T2, T4 (Verus) | `delegate_broader_denied`, `depth_zero_denied` | planned |
| R6 | Revocation stops later authorizations through the subtree | `crates/capability-core` (`live`, `step::revoke`), `crates/broker` (admin `Revoke`, agent `Revoke` within own subtree, ADR-0022) | T5. Model: `RevokeLinearization` | `revoke_ancestor_zero_balance`; broker `end_to_end_two_principals_read_delegate_revoke`, `agent_may_revoke_its_own_delegated_child_only`, swarm test, `sandbox_e2e`; race test revoke vs consume (planned) | model-checked (ordering); tested (broker, serial) |
| R7 | Caller identity established externally | `crates/launcher` (`channel`), `crates/broker` (`conn`, channel bound at spawn) | ADR-0004 as amended by ADR-0022 (identity = channel; `SO_PEERCRED` not a cross-check); T3 refinement | broker `copied_capability_id_from_another_principal_is_denied`, `malformed_oversized_and_fd_passing_frames` (SCM_RIGHTS closes channel), `sandbox_e2e` (real launcher channels) | tested |
| R8 | Decisions auditable incl. root grant and delegation path | `crates/journal` (`record`, `chain`), `crates/broker` (`audit`, admin `Lineage`/`Tree`/`Audit`, `tessera-admin lineage`) | ADR-0002 (hash chain) | journal chain-verification tests; broker e2e/swarm tests check root id on every effect and no content in audit | tested (broker); lineage display manual |
| R9 | Restart/crash restores no consumed grant, permits no replay | `crates/journal` (`recover`), `crates/broker` (`reactor::open`, epoch bump, `Dispatched` marker) | T10. Model: `NoResurrection`, `RestartInvalidatesGrants`, `NoReplayAfterCrash` (variants `no-epoch-bump`, `replay-after-crash`, `volatile-nonces` caught) | `crates/broker/tests/crash.rs` (kill before/after consume commit, after marker, after dispatch, after outcome, around mint; fsync failure; torn tail), `file_backed_journal_restart_resurrects_nothing` | model-checked (protocol); tested (fault injection, in-memory storage) |
| R10 | Unsupported enforcement fails closed | `crates/launcher` (`probe`) | ADR-0005, ADR-0018 | `missing_seccomp_refuses`, `landlock_required_missing_refuses` (PE-23) | planned |
| R11 | Small deterministic core with executable proofs | `crates/capability-core` | Verus (not installed, ADR-0008) | proptest vs reference model | planned (proof blocked on toolchain) |
| R12 | Existing harnesses run unmodified where possible | `crates/launcher` (harness profile), `crates/cli` (`run`), `crates/sdk` | — | WP6 harness compatibility demo | planned (P5) |

## Theorems

| ID | Target | Planned crate / module | Proof / model artifact | Test (planned) | Status |
|---|---|---|---|---|---|
| T1 | Accounting preserved; no overspend | `crates/capability-core` (`ledger`, `check_invariant`) | Verus induction (planned). Model `NoOverspend` for one root with one delegation, budget 1–2 | proptest command sequences; §15 split-repeatedly test | model-checked (protocol, tiny bounds); proof planned |
| T2 | Child scope ⊆ parent ⊆ root; lifetime bounded | `crates/capability-core` (`scope`, `expiry`) | Verus scope lemmas | `delegate_broader_denied`, scope negative tests (WP1 gate) | planned |
| T3 | Every authorized use has an authenticated live owner and valid root | `crates/capability-core` (`live`, `permits`), `crates/broker` (`conn`) | Verus state invariant + ADR-0022 channel-identity argument | broker `copied_capability_id_from_another_principal_is_denied`, `sandbox_e2e` | tested (broker); proof planned |
| T4 | No delegation from depth 0; finite depth decreases | `crates/capability-core` (`step::delegate/split/transfer`) | Verus transition proofs | `depth_zero_denied`, non-delegatable split/transfer tests | planned |
| T5 | After revoke, later authorizations through the subtree fail | `crates/capability-core` (`live`), `crates/broker` (writer order) | Verus + model `RevokeLinearization` | broker revoke tests (serial); revoke-vs-consume race integration trace (planned) | model-checked (ordering); tested (serial) |
| T6 | Expired / terminated / stale-epoch identities cannot authorize | `crates/capability-core` (`live`, time input), `crates/broker` (`epoch`) | Model `RestartInvalidatesGrants` (stale epoch only; expiry and termination **not modelled**) | clock/lifecycle tests; PID/cgroup reuse test | model-checked (epoch part); rest planned |
| T7 | Each approval nonce redeemed at most once; exact binding | `crates/approval` (`payload`, `verify`), `crates/broker` (`Mint` + nonce in one journal record), `crates/journal` | Model `NoResurrection`; crypto assumptions (RustCrypto, ADR-0006) | approval tamper tests; broker mutated-digest and reused-assertion tests, `crash_after_mint_commit_resurrects_no_grant` | model-checked (redemption); tested |
| T8 | Denial, invalid input and overflow cannot increase authority | `crates/capability-core` (`step` totality, checked arithmetic), `crates/protocol` (bounded decode) | Verus total-transition proof | fuzzing of `crates/protocol`; overflow unit tests | planned |
| T9 | Concurrent requests refine a serial trace; no double spend | `crates/broker` (`reactor`, single-writer queue, ADR-0001) | Model: all invariants hold under arbitrary interleavings; variant `stale-validation` caught. TLA+ draft | `thousand_concurrent_attempts_on_budget_one_dispatch_exactly_once` (1,000 attempts, 20 threads, one dispatch); Loom later | model-checked (protocol); drafted (TLA+); tested (broker) |
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
