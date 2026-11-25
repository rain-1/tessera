# ADR-0005: Launcher: bubblewrap, seccomp, optional Landlock, cgroup v2

- Status: Accepted (design). Not implemented. Depends on the kernel feature
  report (written by another work package).
- Spec: §10.1, R1, R10, WP5. Resolves the open question "launcher
  integration strategy".

## Context
A trusted launcher must build the isolation domain and activate every
restriction *before* the workload's first instruction runs. Reusing mature
tools keeps the trusted code small.

## Decision
`crates/launcher` runs a pinned `bwrap` binary from a trusted path.
Arguments are built from a typed launch profile. No shell string is ever
built.

- Namespaces: `--unshare-user --unshare-pid --unshare-ipc --unshare-net
  --unshare-uts --unshare-cgroup-try`. Use `--die-with-parent`,
  `--new-session` and `--cap-drop ALL`. no_new_privs is always on in bwrap.
- Mounts: a read-only minimal runtime (`--ro-bind` of a curated tree), a
  per-sandbox writable workspace (`--bind`), a size-limited tmpfs `/tmp`,
  `--proc /proc` (scoped to the PID namespace) and a minimal `--dev`
  (null, zero, full, random, urandom, tty only). No home directory, no
  `/run`, no sockets.
- seccomp: the launcher generates a BPF filter (allow-list, default
  `EPERM`/`KILL_PROCESS`) and passes it with `--seccomp FD`. The filter
  checks the architecture first. It denies io_uring, Linux AIO
  (io_setup/io_submit/io_getevents/io_pgetevents/io_cancel/io_destroy), ptrace, process_vm_*,
  bpf, perf_event_open, userfaultfd, keyctl/add_key, mount/umount/pivot_root,
  unshare/setns/clone with namespace flags, kexec, init/finit_module,
  open_by_handle_at, name_to_handle_at, and the 32-bit/x32 syscall ABIs.
- Landlock (optional, defence in depth): when the profile declares
  `landlock = required` and the ABI is missing, launch is refused (R10). When
  the profile declares `landlock = optional`, the feature report and the
  audit record show whether it was applied. Absence is never silent. The
  security claims in `protected-effects.md` do **not** depend on Landlock.
- cgroup v2: the broker's delegated subtree has one child cgroup per
  sandbox. It sets `pids.max`, `memory.max`, `memory.swap.max=0` and
  `cpu.max`. Cleanup uses `cgroup.kill`. The cgroup subtree is not delegated
  to the workload, so the workload cannot migrate itself.
- Startup probes: the user-namespace sysctl, seccomp, the cgroup v2
  controllers and the Landlock ABI. Launch is refused when a mandatory
  probe fails.

## Consequences
- bwrap and libseccomp-style filter generation are in the trusted base. The
  bwrap version is pinned.
- Unprivileged user namespaces must be enabled on the host. Hardened distros
  that disable them need the setuid bwrap variant. That is a separate
  profile and needs review.
- No direct network: the network namespace has only `lo`. The model API
  connectivity for the P5 harness profile goes through a trusted proxy
  (ADR-0020).
