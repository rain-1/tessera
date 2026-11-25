# ADR-0008: Verification: Verus is the target. Until it is installed, the evidence is tests, proptest and model checking

- Status: Accepted. **Verus is not installed in the current environment. No
  proof has been checked.**
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
