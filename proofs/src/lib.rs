//! Verus-verified mirror of the security-critical logic of
//! `tessera-capability-core` (crates/capability-core/src).
//!
//! * `quantity` mirrors `budget.rs` (Budget, Depth, Tick, Expiry).
//! * `scope` mirrors `scope.rs` (FileRights, MethodSet, Scope, Operation,
//!   `permits`, `is_subset`).
//! * `ledger` mirrors `state.rs` + `step.rs` (the whole `step` transition
//!   function including `CompactEpoch`, `live`, the pool accounting) over
//!   a dense-vector representation of the core's `BTreeMap`s, with
//!   tombstones for records removed by compaction.
//!
//! The same file is (a) verified by `proofs/run_verus.sh` and (b) compiled
//! by plain `cargo` with ghost code erased, so that
//! `proofs/tests/differential.rs` can run it side by side with the
//! production core. See `proofs/README.md`.
#![allow(unused_imports, unused_braces, dead_code, clippy::all)]

pub mod ledger;
pub mod quantity;
pub mod scope;
