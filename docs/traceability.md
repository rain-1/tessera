# Traceability matrix (spec §15)

Status as of 2026-11-25 (WP0). The crates exist only as skeletons. **No
requirement is implemented, tested or proved.** Status values:

- **planned**: an artifact is assigned but does not exist yet.
- **model-checked**: the *protocol* property holds in
  `models/dispatch_model.py` at the bounds in `models/README.md`. This says
  nothing about the Rust code.
- **drafted**: the model was written but not machine-checked
  (`models/Dispatch.tla`).
- **tested / proved**: not used yet. These need CI output.

Module names are the planned layout for the crates, which are owned by the
implementation work packages. The reviewer sign-off column stays empty until
independent review is resourced (ADR-0021). Proof-register entries live in
`docs/proof-register.md`, which another work package maintains.

## Requirements

| ID | Requirement (short) | Planned crate / module | Proof / model artifact | Test (planned) | Status |
|---|---|---|---|---|---|
| R1 | Workload cannot weaken its confinement | `crates/launcher` (`profile`, `seccomp`, `bwrap`, `cgroup`) | — (Linux mediation evidence, kernel feature report) | `tests/adversarial/escape_syscalls`, `harness_escape_toggle` (PE-20, PE-21) | planned |
| R2 | Fresh human authorization for each new root; baseline recorded separately | `crates/approval` (`payload`, `verify`), `crates/broker` (`mint`), `crates/capability-core` (`step::mint`) | T7. Model: `NoResurrection` (nonce mints ≤ 1) | `crates/approval` tamper/replay/wrong-key/no-UP tests; real YubiKey WP4 test | model-checked (nonce protocol); rest planned |
| R3 | Capability binds subject, scope, budget, delegation, lifetime, provenance | `crates/capability-core` (`types`, `Capability`) | Verus type invariants (ADR-0008) | unit tests on construction and validation | planned |
| R4 | Budgets conserved; no automatic refund | `crates/capability-core` (`ledger`, `step`), `crates/broker` (`dispatch`) | T1 (Verus). Model: `NoOverspend` (variant `refund-on-failure` caught) | proptest conservation; `thousand_concurrent_one_budget`; `failed_read_not_refunded` | model-checked (protocol); core planned |
| R5 | Delegation obeys attenuation and depth | `crates/capability-core` (`scope::is_subset`, `step::delegate`) | T2, T4 (Verus) | `delegate_broader_denied`, `depth_zero_denied` | planned |
| R6 | Revocation stops later authorizations through the subtree | `crates/capability-core` (`live`, `step::revoke`), `crates/broker` (admin endpoint) | T5. Model: `RevokeLinearization` | `revoke_ancestor_zero_balance`; race test revoke vs consume | model-checked (ordering); core planned |
| R7 | Caller identity established externally | `crates/launcher` (`channel`), `crates/broker` (`auth`) | ADR-0004; T3 refinement | `copied_cap_id`, `channel_theft`, `peercred_mismatch_kills`, `ancillary_rejected` | planned |
| R8 | Decisions auditable incl. root grant and delegation path | `crates/journal` (`record`, `chain`), `crates/cli` (lineage view) | ADR-0002 (hash chain) | journal chain-verification tests; lineage display test | planned |
| R9 | Restart/crash restores no consumed grant, permits no replay | `crates/journal` (`recover`), `crates/broker` (`epoch`) | T10. Model: `NoResurrection`, `RestartInvalidatesGrants`, `NoReplayAfterCrash` (variants `no-epoch-bump`, `replay-after-crash`, `volatile-nonces` caught) | fault injection before/after write/fsync/dispatch/response; torn-tail test | model-checked (protocol); implementation planned |
| R10 | Unsupported enforcement fails closed | `crates/launcher` (`probe`) | ADR-0005, ADR-0018 | `missing_seccomp_refuses`, `landlock_required_missing_refuses` (PE-23) | planned |
| R11 | Small deterministic core with executable proofs | `crates/capability-core` | Verus (not installed, ADR-0008) | proptest vs reference model | planned (proof blocked on toolchain) |
| R12 | Existing harnesses run unmodified where possible | `crates/launcher` (harness profile), `crates/cli` (`run`), `crates/sdk` | — | WP6 harness compatibility demo | planned (P5) |

## Theorems

| ID | Target | Planned crate / module | Proof / model artifact | Test (planned) | Status |
|---|---|---|---|---|---|
| T1 | Accounting preserved; no overspend | `crates/capability-core` (`ledger`, `check_invariant`) | Verus induction (planned). Model `NoOverspend` for one root with one delegation, budget 1–2 | proptest command sequences; §15 split-repeatedly test | model-checked (protocol, tiny bounds); proof planned |
| T2 | Child scope ⊆ parent ⊆ root; lifetime bounded | `crates/capability-core` (`scope`, `expiry`) | Verus scope lemmas | `delegate_broader_denied`, scope negative tests (WP1 gate) | planned |
| T3 | Every authorized use has an authenticated live owner and valid root | `crates/capability-core` (`live`, `permits`), `crates/broker` (`auth`) | Verus state invariant + ADR-0004 refinement argument | `copied_cap_id` | planned |
| T4 | No delegation from depth 0; finite depth decreases | `crates/capability-core` (`step::delegate/split/transfer`) | Verus transition proofs | `depth_zero_denied`, non-delegatable split/transfer tests | planned |
| T5 | After revoke, later authorizations through the subtree fail | `crates/capability-core` (`live`), `crates/broker` (writer order) | Verus + model `RevokeLinearization` | revoke-vs-consume race integration trace | model-checked (ordering); planned |
| T6 | Expired / terminated / stale-epoch identities cannot authorize | `crates/capability-core` (`live`, time input), `crates/broker` (`epoch`) | Model `RestartInvalidatesGrants` (stale epoch only; expiry and termination **not modelled**) | clock/lifecycle tests; PID/cgroup reuse test | model-checked (epoch part); rest planned |
| T7 | Each approval nonce redeemed at most once; exact binding | `crates/approval` (`payload`, `verify`), `crates/journal` | Model `NoResurrection`; crypto assumptions (RustCrypto, ADR-0006) | tamper-each-field, replay, stale-epoch tests | model-checked (redemption); binding planned |
| T8 | Denial, invalid input and overflow cannot increase authority | `crates/capability-core` (`step` totality, checked arithmetic), `crates/protocol` (bounded decode) | Verus total-transition proof | fuzzing of `crates/protocol`; overflow unit tests | planned |
| T9 | Concurrent requests refine a serial trace; no double spend | `crates/broker` (`writer`, single-writer queue, ADR-0001) | Model: all invariants hold under arbitrary interleavings; variant `stale-validation` caught. TLA+ draft | `thousand_concurrent_one_budget`; Loom later | model-checked (protocol); drafted (TLA+); implementation planned |
| T10 | Crash recovery never resurrects spent authority or re-dispatches | `crates/journal` (`recover`), `crates/broker` (`epoch`, `dispatch`) | Model `NoReplayAfterCrash`, `AtMostOneDispatchPerReservation`, `DispatchAfterDurableCommit`, `NoResurrection`; up to 2 crashes | fault injection matrix (WP3) | model-checked (protocol); implementation planned |
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
