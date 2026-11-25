# ADR-0018: Isolation profile and target host: a pinned Linux kernel and distro

- Status: Proposed. Waiting for the kernel feature report (separate work
  package). The exact kernel and distro are **not yet frozen**.
- Spec: §10, §16 "Isolation", WP0. Open question "exact kernel version and
  distro".

## Decision
The candidate is the current development host: Debian 13 with kernel 6.12
(amd64, cgroup v2 unified, Landlock ABI 6 expected for 6.12; confirmed only by the feature probe). The kernel feature
report is the authority on what is available. Each profile records:

- kernel build
- enabled LSMs
- seccomp and the user-namespace sysctls
- cgroup controllers
- the Landlock ABI
- BTF/BPF LSM availability, which is informational only for the MVP

Launch is refused when a mandatory feature is missing (R10). A disposable VM
is used for hostile tests. A VM boundary for high-risk research is
recommended but not part of the proof.

## Consequences
- The kernel stays in the TCB.
- Supporting more kernels means more profiles, each with its own probe
  evidence.
