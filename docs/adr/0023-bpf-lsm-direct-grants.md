# ADR-0023: BPF LSM direct grants: not in the MVP; read-only subtree class, libbpf-rs, lease-gated generation protocol for P6

- Status: **Accepted** for the MVP decision (no direct grants; broker-only
  stays the supported profile). **Proposed** for the P6 design (class,
  toolchain, protocol), which has been evaluated without root and is not
  implemented against a kernel.
- Spec: §3, §10.2, §10.3, §16 "Direct enforcement", WP7 (P6). Refines
  ADR-0016, which deferred the toolchain choice to WP7.
- Evidence: `docs/bpf-lsm.md`, `enforcement/ebpf/`,
  `models/bpf_generation_model.py`.

## Context

WP7 asks whether BPF LSM direct grants can be supported, and with which
toolchain.

What is available on the development host:
- Debian 13, kernel 6.12.118, with `bpf` in the active LSM list.
- `CONFIG_BPF_LSM=y` and BTF.
- No `bpftool`, no libbpf headers and no root. Unprivileged `bpf(2)` is
  refused (`unprivileged_bpf_disabled=2`).

So the evaluation could check the following:
- hook availability and prototypes, in the running kernel's BTF;
- kernel call sites, in `v6.12.118` source;
- the generation protocol, as a model and as a pure Rust state machine;
- that the BPF C program compiles.

It could **not** check verifier acceptance, attachment, runtime
enforcement, fail-closed behaviour in a kernel, or overhead.

## Decision

1. **No direct grants in the MVP.**
   - Every protected effect stays brokered or baseline-denied, as in
     ADR-0016 and `docs/protected-effects.md`.
   - The launcher must not require BPF LSM.
   - The broker-only profile is the only supported profile until the WP7
     gate (`docs/bpf-lsm.md` §8) is met on a pinned kernel.
2. **First candidate class (P6):** unlimited-use **read-only** access to a
   registered directory subtree, for one sandbox, for the length of a lease.
   - **Object identity** is the `mnt_id_unique` of a per-sandbox,
     per-subtree read-only bind mount.
   - **Subject identity** is the sandbox's cgroup v2 id paired with a
     manager launch id.
   - Grantable subtrees live on a dedicated filesystem.
   - Outbound connect was rejected for the first iteration. It needs a
     routed network namespace, which makes BPF the only egress control.
     It also has more uncovered paths and is an unbounded exfiltration
     channel (`docs/bpf-lsm.md` §2.1).
3. **Toolchain (P6): libbpf-rs, with the BPF program in C using CO-RE.**
   Aya was the alternative.
   - The policy reads internal kernel structures (`struct mount`, `struct
     file`) whose layouts vary between builds. clang emits CO-RE relocations
     for C, and libbpf applies them against the running kernel's BTF at
     load. That is the reference path used by kernel selftests and BPF LSM
     documentation. Aya's support for writing the kernel side in Rust with
     CO-RE field relocation was judged less mature (assumed from Aya's
     documentation; not re-verified here).
   - The kernel side builds today with the installed clang 19 and no extra
     packages (`enforcement/ebpf/bpf/build.sh`). The program declares its
     own minimal CO-RE types, so it needs neither `vmlinux.h` nor `bpftool`.
     Aya would need a nightly toolchain plus `bpf-linker`, and neither is
     set up.
   - Reviewers of kernel-side code read C. The program is about 400 lines
     with no loops.
   - Cost: libbpf is C behind FFI. The future loader crate is the one place
     that FFI is allowed (WP8: isolate FFI and unsafe code). The workspace
     keeps `unsafe_code = "deny"`, and the manager's protocol crate stays
     dependency-free.
   - Revisit if Aya's CO-RE support for LSM programs matures, or if the
     libbpf FFI surface proves hard to audit.
4. **Generation protocol** (`docs/bpf-lsm.md` §6):
   - The broker owns the desired generation and the manager owns the
     installed generation, read back from the kernel maps.
   - A transition runs: reconcile → check → stage (inert at the current
     generation) → freeze barrier (when removing) → single-word activation
     → thaw → remove retired entries → verify → report.
   - Revocations are acknowledged only after removal and verification.
   - Every subject has a kernel-checked lease on `CLOCK_BOOTTIME`. Only a
     live manager with a live broker connection renews it, so a dead
     manager or broker fails closed within one lease period.
   - A restarted manager expires leases first, then wipes the grants.
   - Grants that allow `mmap` are reported as non-strict revocations and
     must be labelled non-revocable for their lease.
5. **No finite counters in BPF.** A direct grant is unlimited-use within
   its lease. Finite budgets stay in the broker ledger (spec §10.3;
   `docs/bpf-lsm.md` §7).

## Rationale for "not in the MVP"

- **Nothing kernel-side is tested.** The program has not been
  verifier-checked or attached, and no adversarial workload has run against
  it. Spec §10.2 requires coverage validated on the target kernel before a
  direct class is advertised.
- **Required integration is missing:**
  - the launcher start gate (register before the workload runs);
  - per-subtree bind mounts and the dedicated-filesystem check;
  - a libbpf-rs loader with pinning and a watchdog that checks the link is
    still attached;
  - the ledger representation of lease-bounded direct capabilities.
- **There are residuals:**
  - `O_PATH` and name-existence probing;
  - metadata after revocation (`lseek` `SEEK_DATA`/`SEEK_HOLE`, `fstatfs`,
    `cachestat`);
  - `flock` availability;
  - host-created hardlinks.
  None of these exist in the broker-only profile, where the subtree is not
  mounted at all.
- **Detaching the program fails open** for every subtree mounted into a
  sandbox, not only for the granted ones. The broker-only profile has no
  such mode.
- **Overhead is unmeasured.** A global `BPF_LSM_MAC` program on
  `file_permission` runs on every host read.
- **The brokered alternative already delivers the protected-effect
  semantics** (PE-01, PE-03). Direct grants are a performance and
  compatibility feature, not a security requirement, and P6 is optional
  (spec §11 phase note).

## Consequences

- `enforcement/ebpf/` is kept as a research skeleton:
  - the probe;
  - the C program (compiles; not loaded);
  - `tessera-bpf-manager`, a workspace member with no dependencies whose
    protocol state machine and fake kernel have 17 tests.
  None of it is wired into the launcher or the broker.
- `models/bpf_generation_model.py` holds the update protocol: six
  invariants, with six bug variants each caught.
- Resuming P6 requires:
  - a root-capable test VM on the pinned kernel;
  - the §8 gate items in `docs/bpf-lsm.md`;
  - a decision between `BPF_LSM_MAC` and `BPF_LSM_CGROUP` after measuring
    overhead.
- `docs/protected-effects.md` is unchanged: PE-03 remains "kernel baseline
  (denied)".
