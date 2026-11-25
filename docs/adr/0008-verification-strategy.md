# ADR-0008: Verification: Verus is the target. Until it is installed, the evidence is tests, proptest and model checking

- Status: Accepted. Amended 2026-11-25 (see below): Verus is pinned and
  installed without root. A mirror of the core is verified. The production
  crate itself is not.
- Spec: §6.2, §16 "Verification", R11, WP1–WP2

## Context
The spec makes Verus the primary verifier for the authority core. The
toolchain is not available yet, but the core is being written now.

## Decision
- Write `crates/capability-core` in a Verus-compatible subset: no trait
  objects in the core, explicit loops with bounded iteration, checked
  arithmetic, no `unsafe`, pure `step`. Keep spec functions (ghost
  ledger, `permits`, `is_subset` laws) as plain Rust under
  `#[cfg(test)]` or doc comments, ready to move into `verus!` blocks.
- Meanwhile, evidence comes from:
  - unit tests for every rights bit, boundary and mismatch
  - `proptest` command-sequence tests against a simple reference model,
    with the `check_invariant` conservation check after every step
  - an explicit-state model check of the external protocol
    (`models/dispatch_model.py`)
  - a TLA+ draft (`models/Dispatch.tla`) to run under TLC once tools are in
    CI
- Every unverified obligation is listed as *unverified* in the proof
  register (written by another work package). Nothing is called "verified"
  without checker output.
- Kani, Loom and fuzzing supplement this later. They do not replace the
  proofs.

## Consequences
- The P1 gate (T1–T8 proofs) is **not met** until Verus runs. The
  traceability matrix says "planned" or "tested", never "proved".
- Verus may need refactoring away from patterns that the stable Rust
  version accepts.

## Amendment (2026-11-25): Verus pinned; mirrored core verified

- Verus release `0.2026.11.02.8bf68ee` (x86_64 Linux binary, SHA-256
  `f3a0119292df8855e4435da8130bee1873b0e6a60c306accf81a08ea687bba3c`) is
  pinned in `proofs/run_verus.sh`. The script downloads and checks the
  release, installs the Rust toolchain Verus needs (1.99.1) through rustup,
  and runs the verifier. No root is required.
- `proofs/` (not a workspace member) contains a function-by-function
  mirror of `budget.rs`, `scope.rs`, `ids.rs`, `command.rs`, the `state.rs`
  queries and all of `step.rs`, written in Verus. Result: `132 verified, 0
  errors`, with no `assume`, `admit` or `external_body` in our code. T1,
  T2, T4, T7 (ledger) and T8, and the core parts of T3, T5 and T6, are
  machine-checked **on the mirror**.
- Correspondence with the production crate is enforced by a differential
  test (`proofs/tests/differential.rs`). It compiles the mirror with ghost
  code erased and requires identical results and identical observable
  state after every command. This is evidence, not proof. The proof
  register lists it as trusted assumption A13.
- The P1 gate (T1–T8) is therefore **met for the mirrored model only**.
  The production crate is not yet directly verified. Next step: port
  `step.rs` into `verus!` in place, using vstd's `BTreeMap` specs, and
  reuse the mirror's invariant and lemmas.
