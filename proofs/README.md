# Verus proofs: mirrored authority core

This directory holds a Verus-verified **mirror** of the security-critical
logic of `crates/capability-core`. It does not verify the production crate
itself. The mirror is executable Rust with the same types and algorithms.
A differential test runs it against the production crate after every
command, so drift between the two is detected (see
[Drift prevention](#drift-prevention)).

`proofs/` is **not** a member of the root Cargo workspace. It has its own
empty `[workspace]` table, and `cargo build` at the repository root does
not touch it.

## Running

```sh
proofs/run_verus.sh                                       # verify (downloads + checks the pinned release on first use)
cargo test --release --manifest-path proofs/Cargo.toml    # differential test vs. the production core
PROPTEST_CASES=20000 cargo test --release --manifest-path proofs/Cargo.toml   # soak
```

`run_verus.sh` downloads the pinned binary release, checks its SHA-256,
unpacks it under `${XDG_DATA_HOME:-~/.local/share}/tessera/verus-<ver>`,
installs the Rust toolchain that Verus requires through `rustup` (no root
needed), and runs `verus proofs/src/lib.rs --crate-type=lib`.

| Item | Value |
|---|---|
| Verus release | `0.2026.11.02.8bf68ee` (published 2026-11-02, commit `8bf68ee741df833ea5d0fe6a2255126fdea87e47`) |
| Asset | `verus-0.2026.11.02.8bf68ee-x86-linux.zip` |
| SHA-256 | `f3a0119292df8855e4435da8130bee1873b0e6a60c306accf81a08ea687bba3c` |
| Rust toolchain required by Verus | `1.99.1-x86_64-unknown-linux-gnu` (installed by the script) |
| Solver | Z3 as bundled in the release zip |
| Erasure build (`cargo test`) | `vstd = "=0.0.0-2026-11-01-0251"` from crates.io, on the workspace's stable toolchain |

## Verifier output (recorded 2026-11-25)

```
$ proofs/run_verus.sh
verification results:: 132 verified, 0 errors
```

The run takes about 10 s wall-clock on the development machine. It prints
no warnings or trigger notes.

```
$ cargo test --release --manifest-path proofs/Cargo.toml
test result: ok. 5 passed; 0 failed      (tests/differential.rs, 512 cases x 2 configurations by default)
$ PROPTEST_CASES=20000 cargo test --release --manifest-path proofs/Cargo.toml
test result: ok. 5 passed; 0 failed
```

Sanity checks done while developing (all reverted):

| Injected change | Detected by |
|---|---|
| CONSUME does not increment the pool's `consumed` counter | Verus (conservation assertion fails) |
| DERIVE skips the `is_subset` check | Verus (precondition of the T2 edge argument fails) |
| DERIVE denies `q == b` (off-by-one) | differential test |
| Ancestor walk uses current expiry instead of creation-time expiry | differential test (`attenuated_ancestor_expiry_agrees`) |

## What is proved

All of the following are discharged by Verus with **no `assume`, `admit`,
`external_body`, `external`, `assume_specification` or
`#[verifier::truncate]`** in `proofs/src`:

```sh
grep -rnwE 'assume|admit|external_body|external|assume_specification|truncate' proofs/src   # no matches
```

Verus also checks every executable function in `proofs/src` for absence
of arithmetic overflow and out-of-bounds indexing.

### Quantities and scopes (`quantity.rs`, `scope.rs`)

| Lemma / spec | Statement |
|---|---|
| `Budget::within`, `Depth::within`, `Expiry::within` | exec = spec. Each is reflexive and transitive (`lemma_*_within_refl/trans`). |
| `lemma_unlimited_within_only_unlimited` | Only an unlimited bound admits an unlimited budget. |
| `Depth::decrement` | `None` iff `Finite(0)`. The result is within the input. |
| `Depth::admits_child` | `result ⇒ can_delegate()` (T4). `lemma_admits_child_strict`: finite parents admit only strictly smaller finite children. `lemma_admits_child_weaken`: admitting against current depth implies admitting against creation depth. |
| `lemma_expiry_within_expired`, `lemma_expiry_monotone` | An expired bound expires everything within it. Expiry is monotone in time. |
| `FileRights` / `MethodSet` | `from_bits` rejects exactly the undefined bits. `contains_all`/`has` exec = spec. Bit lemmas are proved `by (bit_vector)`. `lemma_file_rights_complete`: the bitset subset is complete for single rights. |
| `lemma_subset_sound` | **`is_subset(c, p) ∧ permits(c, o) ⇒ permits(p, o)`** |
| `lemma_subset_refl`, `lemma_subset_trans`, `lemma_subset_same_kind`, `lemma_subset_sound_chain` | Reflexivity, transitivity, mismatched kinds never comparable, soundness through a chain. |

### Ledger (`ledger.rs`)

`State::step` has precondition `inv()` and the postcondition `post(old,
new, r)` plus command-specific clauses:

| Theorem | Where | Statement |
|---|---|---|
| **T1** conservation | `inv` → `pool_ok` | For every pool `p`: `initial = consumed + discarded + Σ_{caps in p} balance`. Preserved by CREATE/TERMINATE principal, ADVANCE clock (expiry is time passing), BUMP epoch, MINT, INSTALL baseline, CONSUME, SPLIT, DELEGATE, ATTENUATE (finite→finite, unlimited→finite, unlimited→unlimited), TRANSFER, REVOKE (admin and agent), DROP and RECORD outcome. |
| T1 no overspend | `lemma_no_overspend` | `consumed + discarded ≤ initial`, and every single balance is `≤ initial`. |
| T1 pool membership | `inv` → `cap_ok` | `budget` is finite iff the record has a pool, and that pool exists. Dropped records hold 0 units. |
| **T2** attenuation | `inv` → `cap_ok`, `edge_ok` | For every edge parent→child, on immutable creation snapshots: child scope ⊆ parent scope, child expiry within parent expiry, `parent.depth.admits_child(child.depth)`, unlimited child ⇒ unlimited parent. For every record, current terms are within creation terms. The parent index is below the child index (acyclic). |
| T2 lineage | `lemma_lineage_attenuated`, `lemma_use_within_ancestor` | For every ancestor `k` steps up (in particular the root), creation scope and expiry are contained. Any operation permitted by a capability's current scope is permitted by every ancestor's creation scope. |
| **T4** depth | `step` ensures, `edge_ok` | SPLIT, DELEGATE and TRANSFER succeed only if the source depth ≠ `Finite(0)`. TRANSFER sets depth to `decrement(old)`. Every edge strictly decreases finite depth. |
| **T8** denial | `post` | `r is Err ⇒ new == old`. A repeated request (`AlreadyReserved`) also leaves the state unchanged. Every check precedes the first write in every transition. No transition can overflow or index out of bounds. |
| **T7** nonce | `inv` → `nonces_ok`, `nonces_extend`, `step` ensures, `lemma_roots_distinct_nonces` | Spent nonces are pairwise distinct and append-only. Every approved root has a spent-nonce entry naming it. MINT succeeds only if the nonce was not spent, and records it. Distinct approved roots carry distinct nonces, so each nonce is redeemed at most once over any trace. The minted capability's creation terms and owner equal the approved request exactly. |
| T3/T5/T6 (core part) | `live`, `step` ensures | `live(id, now) is Ok ⇒ live_spec`: the record exists, is `Live`, is not expired, its owner is an active principal of the current epoch, and every ancestor (walk bounded by `max_lineage_length`) exists, is not revoked and was not expired at its creation terms. A successful CONSUME implies that the caller is active, owns the capability, the capability is live, and its scope permits the reserved operation. |
| T5 permanence | `post` → `records_monotone` | Existing records never change parent, root or creation terms. `Revoked` is never reset. |

## Correspondence with the production core

The model mirrors the core function by function. Each mirror keeps the
core's check order, so denials agree exactly. The differential test
checks this.

| Core (`crates/capability-core/src`) | Mirror (`proofs/src`) | Difference |
|---|---|---|
| `budget.rs` `Budget`, `Depth`, `Tick`, `Expiry` and all their methods | `quantity.rs` | `Tick(pub u64)` instead of a private field. |
| `scope.rs` `FileRight(s)`, `HttpMethod`, `MethodSet`, `Scope`, `Operation`, `permits`, `is_subset`, `is_well_formed`, `from_bits` | `scope.rs` | `HttpMethod::bit` uses literals instead of `1 << k`. `union`/`with`/`only` (constructors only) are not mirrored. |
| `ids.rs` | `ledger.rs` type aliases, `AgentId`, `Nonce` | Raw integers instead of newtypes. `Nonce([u8; 32])` becomes `Nonce { hi, lo }` (big-endian halves, a bijection). |
| `command.rs` `AgentCommand`, `AdminCommand`, `AuthenticatedCommand`, `GrantRequest`, `VerifiedApproval`, `Denial`, `Resource`, `Effect` | `ledger.rs` | `Effect::Reserved` carries only the reservation id. The full record is `reservations[id]`. |
| `state.rs` `State` (`BTreeMap`s) | `ledger.rs` `State` (`Vec`s) | Identifiers come from monotone counters and are never removed, so each map is a dense vector and `next_*` is its length. Principals are indexed by serial, with the epoch stored in the record. `requests` is replaced by a linear search over `reservations` (`find_request`). `spent_nonces` keeps insertion order. |
| `State::principal`, `is_active`, `live`, `is_nonce_spent` | `principal`, `require_active`/`active_spec`, `live`, `is_nonce_spent` | none |
| `step.rs` `step`, `plan`, `plan_admin`, `plan_agent` | `State::step`, `admin`, `agent` | The `plan`/`commit` split becomes "checks, then writes" inside each function. T8 is proved instead of being argued from the structure. |
| `require_active`, `owned_live`, `require_issuable`, `require_capacity`, `derive_budget`, `discard_into` | same names | The overflow checks `bump_u128(next_capability/next_root)` are omitted. They cannot be reached in the core or the model, because capacity checks bound the counts by a `u64`. `bump_u64` checks are kept. |
| `plan_create_principal`, `plan_terminate`, `plan_bump_epoch`, `plan_mint`, `plan_new_root`, `plan_admin_revoke`, `plan_record_outcome` | arms of `admin`, `new_root` | none |
| `plan_consume`, `plan_derive`, `plan_attenuate`, `plan_transfer`, `plan_agent_revoke`, `plan_drop` | `consume`, `derive`, `attenuate`, `transfer`, `may_revoke` + `commit_revoke`, `drop_cap` | none |
| `commit` (each `Change` arm) | the write section of each function above | none |

**Not mirrored:** `invariant.rs` (`check_invariant`) and the parts of
the invariant listed in the next section, `State::accounts_at` (the
computed L/D split), `State::lineage`, `State::replay`, serde
(de)serialization, and `seq_map.rs`.

## What is not proved (tested-only)

- **The production crate itself.** The theorems hold for the mirror. For
  the production crate they rest on the differential test, which is
  evidence, not proof (trusted assumption A13 in
  `docs/proof-register.md`).
- The derived identity `N = U + L + D` at a given clock
  (`accounts_at`). Only the stored identity is proved. The split of Σ
  balances into live and stranded units is not.
- The parts of `check_invariant` not in `inv`: principal epoch
  consistency, id freshness, limit bounds, root-record ↔ capability
  linkage (`r.capability`, `c.root`, `generation`), pool `anchor`/`root`
  fields, and the reservation ↔ `consumed` cross-check.
- Liveness completeness. Only `Ok ⇒ live_spec` is proved, not the
  converse. Liveness monotonicity over time is only partly proved:
  `records_monotone` covers revocation, and expiry monotonicity is a
  lemma, but principal termination and epoch monotonicity are not in
  `post`.
- Everything out of core scope: T9–T11, authentication (A2), the
  approval crypto (A3, A9) and the journal (A6).

## Drift prevention

1. `proofs/tests/differential.rs` compiles `proofs/src` with ghost code
   erased. It feeds the model and `tessera-capability-core` the same random
   command sequences (the generator in
   `crates/capability-core/tests/common/sym.rs`, shared with the core's own
   model test), under default and tight limits. After every step it
   compares:
   - the result: the exact `Denial`, including the `NotLive` and
     `Resource` detail, or the exact `Effect`;
   - every field of every principal, capability, root, pool, reservation
     and spent nonce;
   - `live()` with its exact reason, for every capability.

   A property test also compares every pure quantity and scope function
   on arbitrary inputs. Deterministic scenarios cover `u64::MAX` budgets,
   nonces that differ only in the second half, depth exhaustion and
   semantic decision 2 (ancestor expiry uses creation terms).
2. Any behavioural change to `crates/capability-core/src/{budget,scope,
   ids,command,state,step}.rs` must be mirrored here. Then
   `run_verus.sh` and the differential test must both pass again. Review
   rule: a pull request that touches those files without touching
   `proofs/` must explain why the change has no behavioural effect.
