# Release engineering (WP8)

This covers reproducible builds, the supply-chain policy, SBOMs and the
release checklist. Status: the process below is in place and was checked
on 2026-11-25. Release signing and an independent review (ADR-0021) are
**not** done yet.

## 1. Reproducible builds

### Inputs that are pinned

| Input | How |
|---|---|
| Dependency graph | committed `Cargo.lock`; every build uses `--locked` |
| Toolchain | `TESSERA_TOOLCHAIN` in `scripts/release-build.sh` (default `1.100.0`). `rust-toolchain.toml` currently says `stable` for development; a release must name an exact version |
| Timestamp | `SOURCE_DATE_EPOCH` = commit time of `HEAD` (`git log -1 --format=%ct`) |
| Build paths | `RUSTFLAGS=--remap-path-prefix` for the checkout, `$CARGO_HOME` and `$RUSTUP_HOME`; `CFLAGS=-ffile-prefix-map` for C code compiled by build scripts (`ring`) |
| Target | `x86_64-unknown-linux-gnu` (glibc host linker; record the distro/linker version with the release) |
| Locale/TZ | `LC_ALL=C TZ=UTC` |

### Build

```sh
scripts/release-build.sh dist/        # or: make release
cat dist/SHA256SUMS
```

The output is `tesserad`, `tessera-admin`, `tessera`,
`tessera-sandbox-init`, `tessera-launch-run`, `tessera-launch-probe` and
`SHA256SUMS`.

### Verify

```sh
scripts/repro-check.sh                # or: make repro
```

This builds `HEAD` twice from two separate `git archive` checkouts at
different paths, each with its own target directory, and compares
`SHA256SUMS`.

**Result (2026-11-25, rustc 1.100.0, Debian 13 x86_64).** `make repro`
printed `REPRODUCIBLE`. All six binaries were bit-identical across two
`git archive` checkouts at different paths with separate target
directories (for example, `tesserad`
`30cfe392…8e7d7` at commit `452d21e`). Without the
`CFLAGS` prefix map, the binaries were still identical on one machine but
embedded `$CARGO_HOME` paths from ring's C sources. That is why the C flags
are part of the recipe. Cross-machine reproduction (a different distro or
linker) has not been tested.

## 2. Supply chain

### Policy: `deny.toml` (`cargo deny check`, `make deny`)

* **Advisories:** RustSec. Vulnerable, unmaintained, unsound or yanked
  crates fail the check. Each exception needs a written justification.
* **Licenses:** only permissive licenses compatible with Apache-2.0
  (Apache-2.0, MIT, BSD-3-Clause, ISC, Unicode-3.0, CDLA-Permissive-2.0).
* **Bans:** OpenSSL / native-tls are banned (rustls is the only TLS stack).
  Duplicate versions produce a warning.
* **Sources:** crates.io only, with no git dependencies.

### Findings (2026-11-25)

| Check | Result |
|---|---|
| `cargo deny check` | advisories ok, bans ok, licenses ok, sources ok, with 1 ignored advisory and warnings below |
| `cargo audit` | 1 vulnerability: **RUSTSEC-2026-0387** (`crypto-bigint 0.5.5`: secret-dependent timing in arithmetic meant to be constant-time). Reached via `p256 0.13 → elliptic-curve 0.13`. No 0.5.x fix exists. |
| Duplicates (warn) | `sha2` 0.10 + 0.11 (journal uses 0.11, everything else 0.10), so `digest`, `block-buffer`, `crypto-common`, `const-oid`, `cpufeatures` are duplicated too, as is `syn` 2 + 3 |
| Wildcards (warn) | workspace crates have path dependencies without `publish = false`. Set `publish = false` in each crate manifest, then make this `deny` |

**Resolved:** `p256` was upgraded to 0.14, which removes `crypto-bigint`
0.5 from the tree; the ignore entries were deleted. Original rationale, kept
for the record: A production broker only **verifies** ES256
signatures, and those inputs are public. Secret-key arithmetic runs only in
the development software authenticator (`crates/broker/src/softkey.rs`),
which must not be used in production. **Action:** upgrade to the `p256` /
`elliptic-curve` 0.14 series, which uses `crypto-bigint` ≥ 0.7.6, and
remove the ignore entry.

### SBOM

CycloneDX 1.5 JSON, one file per workspace crate, in
[`docs/sbom/`](sbom/), generated with `cargo-cyclonedx`:

```sh
cargo install cargo-cyclonedx --locked
scripts/sbom.sh                       # or: make sbom
```

The script sets `SOURCE_DATE_EPOCH` from the last commit that touched
`Cargo.lock` and rewrites
absolute checkout paths to `path+file://./`, so the output does not depend
on the machine. CI regenerates the SBOMs and fails if `docs/sbom/` differs
from what is committed. Regenerate the SBOMs whenever `Cargo.lock` changes.

## 3. Security gates (CI)

`.github/workflows/ci.yml` runs these jobs:

| Job | Runs |
|---|---|
| `lint` | `cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings` |
| `test` | `cargo test --workspace --locked` (sandbox tests may SKIP loudly) |
| `sandbox` | launcher + broker sandbox tests, `tests/adversarial/run.sh`, `scripts/demo.sh` inside a `Delegate=yes` transient unit. **Fails on any SKIPPED banner** |
| `models` | `models/dispatch_model.py`, TLC via `models/run_tlc.sh` |
| `verus` | `proofs/run_verus.sh` if it exists on the ref |
| `supply-chain` | cargo-deny, cargo-audit, SBOM drift |
| `fuzz-smoke` | every cargo-fuzz target for 30 s (600 s on the weekly schedule) |
| `reproducible` | `scripts/repro-check.sh` (push and schedule only) |

Actions are pinned by commit SHA, with the release tag in a comment.

### Fuzzing

The targets are in `fuzz/fuzz_targets/` (cargo-fuzz, nightly, libFuzzer +
ASan). Structured seeds are in `fuzz/seeds/` (regenerate them with
`make fuzz-seeds`).

| Target | Input | Oracle |
|---|---|---|
| `protocol_decode_client` / `_server` | wire payload | no panic; accepted ⇒ re-encodes byte-identically; smaller limit never accepts more |
| `frame_reader` | byte stream, 4 frame limits | no panic; no frame above the limit; `recv_message` loop |
| `approval_grant_request` | canonical grant request | accepted ⇒ `encode(decode(b)) == b`, fields re-validate, same digest; rendering never panics |
| `approval_enrollment` | enrollment record | accepted ⇒ round-trips exactly |
| `journal_recover` | raw journal file (in-memory storage) | open under both tail policies, replay, `recover`, append + epoch bump, reopen: earlier checkpoint still verifies, no records lost |
| `core_state_decode` | postcard / JSON `State` snapshot | accepted ⇒ `check_invariant` holds and postcard round-trips |
| `core_step` | small `Limits` + stream of `(AuthenticatedCommand, Δtick)` | after each successful `step` `check_invariant` holds; a denial leaves the state byte-identical; the final state round-trips |

Baseline run, 2026-11-25: 60 s per target, seeded, one process each. **No
crashes, no invariant violations, no timeouts, no OOMs.**

| Target | Executions | Coverage (edges) |
|---|---|---|
| protocol_decode_client | 4.37 M | 2454 |
| protocol_decode_server | 4.08 M | 3084 |
| frame_reader | 2.64 M | 1428 |
| approval_grant_request | 1.57 M | 730 |
| approval_enrollment | 2.45 M | 408 |
| journal_recover | 1.00 M | 478 |
| core_state_decode | 1.39 M | 5227 |
| core_step | 0.28 M | 2064 |

When a target crashes, commit the reproducer under
`fuzz/artifacts-found/<target>/` with a minimal regression test in the
owning crate.

## 4. Release checklist

1. CI is green on the release commit, with **no SKIPPED sandbox tests**.
2. `cargo deny check` and `cargo audit` pass. Every ignore has been
   re-justified.
3. `scripts/sbom.sh` produces no diff.
4. `scripts/repro-check.sh` prints REPRODUCIBLE. Publish `SHA256SUMS`
   along with the toolchain, target and `SOURCE_DATE_EPOCH`.
5. Sign `SHA256SUMS` (not implemented yet; planned: a detached signature
   with a hardware-held key).
6. Update `docs/traceability.md` and `docs/proof-register.md` to match what
   was actually verified or tested. Release scope is limited to tested
   profiles (WP8 gate).
7. Independent review sign-off (ADR-0021). None has happened yet.
