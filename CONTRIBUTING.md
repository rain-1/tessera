# Contributing to Tessera

Tessera is security software for running untrusted agents. Changes are
judged first by whether they keep the security argument intact. Features
come second.

## Ground rules

* **Read first:** [`docs/specification.md`](docs/specification.md),
  [`docs/threat-model.md`](docs/threat-model.md) and the ADRs in
  [`docs/adr/`](docs/adr/). A change to a security-critical assumption
  needs an ADR, or an amendment to an existing one.
* **Fail closed.** If a mandatory control is missing, refuse. Never fall
  back silently to a weaker profile (R10).
* **No `unsafe`.** The workspace sets `unsafe_code = "deny"`. The only
  exception is documented in [`docs/sdk.md`](docs/sdk.md).
* **Untrusted input is bounded before it is parsed.** Wire, approval,
  journal and snapshot decoders are strict and canonical. If you change
  one, extend its fuzz target.
* **Be honest about status.** Say "tested", "model-checked" or "proved"
  only when that is literally true. Keep
  [`docs/traceability.md`](docs/traceability.md) accurate.

## Workflow

```sh
make help          # every target
make lint          # cargo fmt --check + clippy -D warnings
make test          # cargo test --workspace --locked
make models        # Python model checker   (make tlc for TLC; needs java)
make deny          # cargo-deny policy
make fuzz-smoke    # 30 s per fuzz target (nightly + cargo-fuzz)
make adversarial   # hostile-shell corpus in a real sandbox
make demo          # tesserad + sandbox + approval walkthrough
```

Sandbox tests need user namespaces, bubblewrap and a delegated cgroup v2
subtree ([`docs/install.md`](docs/install.md)). When those are missing,
the tests print a loud `SKIPPED` banner and pass. **A skipped sandbox test
is not a pass.** CI's `sandbox` job fails on any such banner.

### Tooling (user-level)

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz cargo-deny cargo-audit cargo-cyclonedx --locked
```

## Fuzzing

The targets are in `fuzz/fuzz_targets/` (see the table in
[`docs/release.md`](docs/release.md#fuzzing)). To run one for longer:

```sh
cd fuzz
cargo +nightly fuzz run core_step corpus/core_step seeds/core_step -- -max_total_time=600
```

Every new decoder of untrusted bytes needs a fuzz target. Every new core
transition needs to be reachable from `core_step`. If you find a crash,
commit the reproducer under `fuzz/artifacts-found/<target>/` and add a
regression test in the owning crate.

## Dependencies

Each new dependency is a supply-chain decision. Prefer crates that are
already in the graph. `cargo deny check` must pass, and the license must be
on the allow-list in `deny.toml`. After changing `Cargo.lock`, run
`scripts/sbom.sh` and commit `docs/sbom/`.

## Commits and reviews

* Keep commits focused, and write messages in the imperative mood.
* Changes to `crates/capability-core`, `crates/approval`,
  `crates/journal`, `crates/broker`, `crates/launcher` or the adapters are
  security-critical. They need a reviewer other than the author, and the
  PR has to say which invariants or theorems (T1–T11) the change touches.
* Report vulnerabilities privately; see [`SECURITY.md`](SECURITY.md).

By contributing, you agree to license your work under Apache-2.0.
