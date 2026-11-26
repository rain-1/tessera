# Verus proofs: mirrored authority core

This directory holds a Verus-verified **mirror** of the security-critical
logic of `crates/capability-core`. The mirror is executable Rust with the
same types and algorithms, and covers every transition of `step`,
including `CompactEpoch` (ADR-0031). A differential test runs it against
the production crate after every command, so drift between the two is
detected (see [Drift prevention](#drift-prevention)).

In addition, `run_verus.sh` runs Verus on the **production crate itself**
for its pure leaf functions in `budget.rs`, `scope.rs` and `ids.rs` (see
[Production leaf functions](#production-leaf-functions-verified-directly)).
The production ledger (`state.rs`, `step.rs`, `invariant.rs`) is **not**
verified directly. Its theorems hold for the mirror and carry over through
the differential test only.

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
needed), and then runs two stages:

1. `verus proofs/src/lib.rs --crate-type=lib` (the mirror);
2. `verus crates/capability-core/src/lib.rs --crate-type=lib --edition=2024
   --no-cheating` with `serde` passed as `--extern`. That `serde` rlib is
   built by the Verus toolchain into `proofs/target/verus-deps`. This is
   the production crate's source, compiled by Verus with
   `cfg(verus_keep_ghost)`.

Both stages must report 0 errors.

| Item | Value |
|---|---|
| Verus release | `0.2026.11.02.8bf68ee` (published 2026-11-02, commit `8bf68ee741df833ea5d0fe6a2255126fdea87e47`) |
| Asset | `verus-0.2026.11.02.8bf68ee-x86-linux.zip` |
| SHA-256 | `f3a0119292df8855e4435da8130bee1873b0e6a60c306accf81a08ea687bba3c` |
| Rust toolchain required by Verus | `1.99.1-x86_64-unknown-linux-gnu` (installed by the script) |
| Solver | Z3 as bundled in the release zip |
| Erasure build (`cargo test`) | `vstd = "=0.0.0-2026-11-01-0251"` from crates.io, on the workspace's stable toolchain |

## Verifier output (recorded 2026-11-26)

```
$ proofs/run_verus.sh
== mirror (proofs/src)
verification results:: 173 verified, 0 errors
== production (crates/capability-core)
verification results:: 63 verified, 0 errors
```

That is 236 verified items in total. The run takes about 7 s wall-clock on
the development machine. It prints no warnings or trigger notes.

```
$ cargo test --release --manifest-path proofs/Cargo.toml
test result: ok. 8 passed; 0 failed      (tests/differential.rs, 512 cases x 4 configurations by default)
$ PROPTEST_CASES=20000 cargo test --release --manifest-path proofs/Cargo.toml
test result: ok. 8 passed; 0 failed      (each compaction configuration: 20,000 cases, ~1.29 M compared steps)
```

Sanity checks done while developing (all reverted):

| Injected change | Detected by |
|---|---|
| CONSUME does not increment the pool's `consumed` counter | Verus (conservation assertion fails) |
| DERIVE skips the `is_subset` check | Verus (precondition of the T2 edge argument fails) |
| DERIVE denies `q == b` (off-by-one) | differential test |
| Ancestor walk uses current expiry instead of creation-time expiry | differential test (`attenuated_ancestor_expiry_agrees`) |
| COMPACT omits the stranded balances from `retired.discarded` | Verus (`retired_ok`) |
| COMPACT sets `retired_roots_below` one too high | Verus (`root_ok`: pruned ⇔ id below the floor) |
| COMPACT also prunes current-epoch principals (spec and code changed together) | Verus (owner presence in `cap_ok`) |
| Production `Depth::admits_child` uses `c <= p` | Verus, production stage (postcondition of `admits_child`) |

## What is proved

All of the following are discharged by Verus with **no `assume`, `admit`,
`external_body`, `external`, `assume_specification` or
`#[verifier::truncate]`** in `proofs/src` or in the production spec files.
The production stage runs with `--no-cheating`, which rejects them:

```sh
grep -rnwE 'assume|admit|external_body|external|assume_specification|truncate' \
  proofs/src crates/capability-core/src/*_verus.rs                                # no matches
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
| Counters and tombstones | `post` → `frozen` | Id counters (vector lengths), the epoch and `retired_roots_below` never decrease. A pruned record never changes again and is never un-pruned. |

### Compaction (`CompactEpoch`, ADR-0031)

Pruned records stay in their slot as tombstones (`pruned == true`). Every
lookup treats a tombstone as a missing key. The specification
`compact_principals`/`compact_roots`/`compact_caps`/`compact_pools`/
`compact_reservations` states exactly what is pruned in epoch `e`:
non-pruned principals with `epoch < e`, non-pruned roots with
`epoch < e`, and every non-pruned capability, pool and reservation whose
root is one of those roots.

| Theorem | Where | Statement |
|---|---|---|
| Exact pruning | `step` ensures → `compacted` | A successful COMPACT turns exactly the records above into tombstones and changes nothing else. |
| Spent nonces kept, counters unchanged | `compacted` | `spent_nonces`, the epoch, the limits and every vector length (the id counters) are unchanged. |
| No live capability pruned, none resurrected | `compacted`, `frozen` | For every id and every time, `live_spec` after equals `live_spec` before. Tombstones are permanent, and `live_spec` requires a non-pruned record and non-pruned ancestors. |
| Invariant preserved | `lemma_compact` | `inv` holds after COMPACT. This covers T1/T2/T7 and the clauses below. |
| Structure | `inv` → `cap_ok`, `pool_ref_ok`, `root_ok`, `res_ok`, `roots_sorted` | Parent, pool, reservation and root-capability links stay within one root. A record is pruned iff its root is. Owners and recipients are principals of the root's epoch. Root epochs grow with ids and never exceed the current epoch. |
| No dangling references | `lemma_no_dangling_{cap,pool,root,reservation}` | A present capability's root, parent, pool and owner are present. A present pool's root and anchor are present. A present root's capability and recipient are present. A present reservation's capability, root and pool are present. |
| Retired-pool accounting | `inv` → `retired_ok`, `lemma_retired_balanced` | `retired.{pools,initial,consumed}` are the sums over pruned pools. `retired.discarded` is the pruned pools' discarded total plus the balances stranded in pruned capability records. Hence `retired.initial = retired.consumed + retired.discarded`. The effect's `pools/initial/consumed/discarded` are exactly the increments. |
| Global conservation | `lemma_global_conservation` | `Σ_present N + retired.N = Σ_present U + retired.U + Σ_present D_explicit + Σ_present balances + retired.D`. The proof exchanges the order of summation over pools and records (`lemma_psum_bal_csum`). |
| T7 across the boundary | `inv` → `root_ok`, `nonces_ok`; `lemma_spent_nonce_boundary` | The pruned roots are exactly the ids `< retired_roots_below` (`≤ roots.len()`). Every spent nonce names a root that redeemed it with exactly that nonce. That root is present iff its id is `>= retired_roots_below`. Spent nonces stay pairwise distinct, and MINT still requires an unspent nonce, so a pruned approval can never be redeemed again. |

### Production leaf functions (verified directly)

`crates/capability-core/src/{budget,scope,ids}.rs` carry
`#[cfg_attr(verus_keep_ghost, verus_verify)]` /
`#[cfg_attr(verus_keep_ghost, verus_spec(r => ensures ...))]`
annotations. Only Verus sets `verus_keep_ghost`, so a normal `cargo`
build sees no attributes and compiles the same tokens as before. The
workspace `Cargo.toml` declares the cfg for `check-cfg`. Spec twins and
lemmas are in `budget_verus.rs` and `scope_verus.rs`, which are
`include!`d into the same modules only under the cfg (this keeps private
fields such as `Tick(u64)` visible to the specs). vstd is not a cargo
dependency: Verus uses its bundled vstd.

| Item (production code) | Verified postcondition |
|---|---|
| `Budget::within`, `is_finite`; `Depth::within`, `can_delegate`, `decrement`, `admits_child`; `Expiry::is_expired_at`, `within` | exec = spec. `admits_child ⇒ can_delegate`. |
| `Tick::{ZERO, from_raw, to_raw}`; `from_raw`/`to_raw` of the 9 id types | Round-trip with the raw value. |
| `FileRights`/`MethodSet` `from_bits`, `contains_all`, `has`, `is_empty`; `FileRight::bit`, `HttpMethod::bit`; `READ`, `REPLACE` | `from_bits` accepts exactly the defined bits. The others are exec = spec on the bit representation. |
| `Scope::is_well_formed`, `permits`, `is_subset` | exec = spec. |
| Lemmas on the production definitions | `lemma_subset_sound` (**`is_subset(c, p) ∧ permits(c, o) ⇒ permits(p, o)`**), `lemma_subset_refl`/`trans`, Budget/Depth `within` transitivity, `lemma_admits_child_weaken`, expiry monotonicity. |

Compiled by Verus but not verified, and with no assumed specs:
`FileRights`/`MethodSet` `empty`, `bits`, `union`, `with`, `only` (Verus
still checks their arithmetic for overflow), all derived impls (`Debug`,
`Clone`, `PartialEq`, `Hash`, `Ord`, `Serialize`, `Deserialize`), the
`TryFrom`/`From<u8>` impls, and every function in `command.rs`,
`state.rs`, `step.rs`, `invariant.rs` and `seq_map.rs`.

The production spec twins (`*_verus.rs`) and the mirror's specs
(`proofs/src/{quantity,scope}.rs`) are separate texts with the same
definitions. Their equality is checked by review and by the differential
test's pure-function comparison, not by Verus. For a `const fn`, Verus
verifies a copy of the body that its attribute macro generates from the
same source tokens. The mutation of `admits_child` in the sanity-check
table above shows that a change to the production body is detected.

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
| `state.rs` `State` (`BTreeMap`s) | `ledger.rs` `State` (`Vec`s) | Identifiers come from monotone counters and are never reused, so each map is a dense vector and `next_*` is its length. A key that `CompactEpoch` removed is a tombstone (`pruned`), and every lookup treats it as absent. `map.len()` is mirrored by `n_principals`/`n_capabilities`/`n_roots`/`n_reservations`. Principals are indexed by serial, with the epoch stored in the record. `requests` is replaced by a linear search over non-pruned `reservations` (`find_request`). `spent_nonces` keeps insertion order. `retired_roots_below` and `retired` are the same fields. |
| `State::principal`, `is_active`, `live`, `is_nonce_spent` | `principal`, `require_active`/`active_spec`, `live`, `is_nonce_spent` | none |
| `step.rs` `step`, `plan`, `plan_admin`, `plan_agent` | `State::step`, `admin`, `agent` | The `plan`/`commit` split becomes "checks, then writes" inside each function. T8 is proved instead of being argued from the structure. |
| `require_active`, `owned_live`, `require_issuable`, `require_capacity`, `derive_budget`, `discard_into` | same names | The overflow checks `bump_u128(next_capability/next_root)` are omitted. In the model the counters are vector lengths `≤ usize::MAX < u128::MAX`, so the checks cannot fail. In the core the counters advance only after a capacity check (one per new record), so they cannot reach `u128::MAX` either. `bump_u64` checks are kept. |
| `plan_create_principal`, `plan_terminate`, `plan_bump_epoch`, `plan_mint`, `plan_new_root`, `plan_admin_revoke`, `plan_record_outcome` | arms of `admin`, `new_root` | `BumpEpoch` skips tombstones (the core iterates only over present records). |
| `plan_compact_epoch` + the `CompactEpoch` commit | `compact`, `sweep_*`, `first_current_root` | Sets `pruned` instead of removing. Computes the same totals. Each sum is checked (`ArithmeticOverflow`), but in a different grouping (pool and stranded discards are summed separately and then added). The sums are of non-negative terms, so the set of overflowing inputs is the same. That equivalence is argued here, not proved. |
| `plan_consume`, `plan_derive`, `plan_attenuate`, `plan_transfer`, `plan_agent_revoke`, `plan_drop` | `consume`, `derive`, `attenuate`, `transfer`, `may_revoke` + `commit_revoke`, `drop_cap` | none |
| `commit` (each `Change` arm) | the write section of each function above | none |

**Not mirrored:** `invariant.rs` (`check_invariant`) and the parts of
the invariant listed in the next section, `State::accounts_at` (the
computed L/D split), `State::lineage`, `State::replay`, serde
(de)serialization, and `seq_map.rs`.

## What is not proved (tested-only)

- **The production ledger.** The ledger theorems (T1–T8, compaction)
  hold for the mirror. For the production `state.rs`/`step.rs` they rest
  on the differential test, which is evidence, not proof (trusted
  assumption A13 in `docs/proof-register.md`). Only the leaf functions
  listed above are verified on the production source.
- The `n_*` record counters (capacity checks) are not linked to the
  number of non-pruned records in `inv`. Their agreement with the core's
  map lengths is tested by the differential test. The effect's record
  counts (`principals`, `capabilities`, `roots`, `reservations` of
  `EpochCompacted`) are tested the same way. Its `pools`, `initial`,
  `consumed` and `discarded` are proved.
- The derived identity `N = U + L + D` at a given clock
  (`accounts_at`). Only the stored identity is proved. The split of Σ
  balances into live and stranded units is not.
- The parts of `check_invariant` not in `inv`: "old-epoch principals are
  terminated", limit bounds, `generation` and "root capability ⇔
  `parent is None`" (the `c.root`/`r.capability` links and the pool
  `root`/`anchor` links are now in `inv`), `anchor.pool == Some(p)`, and
  the reservation ↔ `consumed` cross-check. Id freshness holds by
  construction in the model (ids are indices).
- Liveness completeness. Only `Ok ⇒ live_spec` is proved, not the
  converse. Liveness monotonicity over time is only partly proved:
  `records_monotone` covers revocation, `frozen` covers tombstones and
  epoch monotonicity, and expiry monotonicity is a lemma. Principal
  termination is not in `post`.
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
     `Resource` detail, or the exact `Effect` (including `EpochCompacted`);
   - every field of every principal, capability, root, pool, reservation
     and spent nonce, and that each model tombstone is absent from the
     core;
   - `live()` with its exact reason, for every capability id ever
     allocated;
   - the record counts, `retired_roots_below`, `retired`, the request-id
     index for every `(owner, request id)` ever used, and
     `is_nonce_spent` over the generator's whole nonce space.

   Two of the four runs add `CompactEpoch` at random points and as the
   pair `BumpEpoch` then `CompactEpoch`, as the broker issues them at start.
   `compaction_generator_coverage` checks that those runs reach pruning
   compactions with stranded balances, successful operations afterwards,
   and the post-compaction denials.

   A property test also compares every pure quantity and scope function
   on arbitrary inputs. Deterministic scenarios cover `u64::MAX` budgets,
   nonces that differ only in the second half, depth exhaustion and
   semantic decision 2 (ancestor expiry uses creation terms).
2. Any behavioural change to `crates/capability-core/src/{budget,scope,
   ids,command,state,step}.rs` must be mirrored here. Then
   `run_verus.sh` (both stages) and the differential test must both pass
   again. For `budget.rs`, `scope.rs` and `ids.rs` the production stage
   also fails directly when an annotated function no longer meets its
   spec. Review
   rule: a pull request that touches those files without touching
   `proofs/` must explain why the change has no behavioural effect.
