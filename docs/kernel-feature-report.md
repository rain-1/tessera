# Kernel feature report — launcher host baseline

Recorded on 2026-11-25 with `tessera-launch-probe` (crate `tessera-launcher` 0.1.0)
on the WP5 development host. Regenerate with:

```sh
cargo run -p tessera-launcher --bin tessera-launch-probe   # exit 0 = launch allowed, 2 = refused (R10)
```

## Summary

| Control | Status on this host | Mandatory? | Mechanism |
|---|---|---|---|
| bubblewrap | 0.12.0 (min 0.8.0 for `--disable-userns`) | yes | `/usr/bin/bwrap`, never looked up in `$PATH` |
| Unprivileged user namespaces | enabled (`unprivileged_userns_clone=1`), smoke sandbox OK | yes | probe starts a real bwrap sandbox with every namespace |
| seccomp-BPF | available, `errno`/`kill_process` actions present | yes | 3 filters via `--add-seccomp-fd` |
| Landlock | ABI 6 (fs + TCP + signal/abstract-socket scoping) | yes by default (`LandlockRequirement::Required`, pinned to ABI ≥ 6) | applied by `tessera-sandbox-init` inside the sandbox |
| cgroup v2 delegation | delegated at `user@1000.service` (cpu memory pids, `cgroup.kill`) | yes by default; explicit operator opt-out | per-sandbox leaf under `tessera.launcher/` |
| BPF LSM | `bpf` in active LSM list, BTF present | no (informational; WP7) | not used by the launcher |

Launch is **allowed** on this host under the default (strict) policy.

## Raw probe output

```json
{
  "launch_allowed": true,
  "missing_mandatory": [],
  "policy": {
    "cgroup": {
      "mode": "required"
    },
    "landlock": "required",
    "min_bwrap_version": [
      0,
      8,
      0
    ],
    "required_landlock_abi": 6
  },
  "report": {
    "arch": "x86_64",
    "bpf_lsm": {
      "active": true,
      "btf_vmlinux": true,
      "note": "informational: BPF LSM policies are WP7 and not yet mandatory; attaching requires privileges the launcher does not hold"
    },
    "bwrap": {
      "error": null,
      "found": true,
      "path": "/usr/bin/bwrap",
      "version": "bubblewrap 0.12.0",
      "version_ok": true
    },
    "cgroup": {
      "cgroup_kill": true,
      "delegation_root": "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service",
      "enabled_controllers": [
        "cpu",
        "memory",
        "pids"
      ],
      "own_cgroup": "/user.slice/user-1000.slice/user@1000.service/app.slice/<terminal scope>",
      "reason": null,
      "usable": true,
      "v2_mounted": true
    },
    "kernel_release": "6.12.118+deb13-amd64",
    "kernel_version": "#1 SMP PREEMPT_DYNAMIC Debian 6.12.118-1 (2026-11-20)",
    "landlock": {
      "abi": 6,
      "in_lsm_list": true,
      "status": "available"
    },
    "lsms": [
      "lockdown",
      "capability",
      "landlock",
      "yama",
      "apparmor",
      "tomoyo",
      "bpf",
      "ipe",
      "ima",
      "evm"
    ],
    "seccomp": {
      "actions_avail": [
        "kill_process",
        "kill_thread",
        "trap",
        "errno",
        "user_notif",
        "trace",
        "log",
        "allow"
      ],
      "available": true,
      "denied_syscalls": 54,
      "error": null,
      "filter_compiles": true,
      "filter_count": 3
    },
    "user_namespaces": {
      "apparmor_restrict_unprivileged_userns": null,
      "max_user_namespaces": 123810,
      "sandbox_smoke_test": true,
      "smoke_test_error": null,
      "unprivileged_userns_clone": "1"
    },
    "yama_ptrace_scope": "0"
  },
  "tessera_launcher_version": "0.1.0"
}
```

(`own_cgroup` abbreviated; it is the launching terminal's systemd scope.)

## What the launcher enforces (and how it is verified)

Each sandbox is started as `/bin/sh -c 'echo 0 > <leaf>/cgroup.procs && exec bwrap …'`,
so every sandbox process is born inside its cgroup leaf. bubblewrap then sets up:

* `--unshare-user --unshare-ipc --unshare-pid --unshare-net --unshare-uts --unshare-cgroup`
  (explicit, not the `-try` variants), `--disable-userns`, `--die-with-parent`,
  `--new-session`, `--cap-drop ALL`, `--clearenv` + explicit `--setenv`, hostname `tessera`.
* Filesystem: tmpfs root remounted read-only; `/usr` read-only plus the host's `/bin`,
  `/sbin`, `/lib*` symlinks; `/etc` contains only `ld.so.*`, `alternatives`, `localtime`
  and synthetic `passwd`/`group`/`hosts`/`nsswitch.conf` (sealed memfds via
  `--ro-bind-data`); sandbox-only `/proc`; bwrap's minimal `/dev` (null, zero, full,
  random, urandom, tty, pts, shm); private tmpfs `/tmp` and `/dev/shm`; the workspace
  bound at `/workspace` (rw or ro); optional extra read-only binds. No `/home`, `/root`,
  `/run`, `/sys`, `/var`. Workspaces/binds that are, or contain, `/`, `$HOME`,
  `$XDG_RUNTIME_DIR`, `/etc`, `/usr`, `/home`, `/run`, … or that lie under `/run`,
  `/proc`, `/sys`, `/dev` are rejected.
* seccomp (installed by bwrap just before the init shim runs, so it covers the shim
  and the workload): `EPERM` for io_uring_*, ptrace, bpf, perf_event_open, keyctl,
  add_key, request_key, mount, umount2, pivot_root, chroot, the new mount API
  (open_tree, move_mount, fsopen, fsconfig, fsmount, fspick, mount_setattr), setns,
  unshare, userfaultfd, kexec_*, (f)init_module, delete_module, open_by_handle_at,
  name_to_handle_at, process_vm_readv/writev, process_madvise, pidfd_getfd, kcmp,
  fanotify_init, swapon/off, reboot, syslog, acct, clock/time setters, quotactl(_fd),
  vhangup, iopl, ioperm, uselib, _sysctl, lookup_dcookie, nfsservctl; `clone` with any
  `CLONE_NEW*` flag; `ioctl(TIOCSTI|TIOCLINUX)`; `socket`/`socketpair` outside
  AF_UNIX/AF_INET/AF_INET6/AF_NETLINK (blocks AF_VSOCK, AF_PACKET, AF_ALG, …).
  `clone3` → `ENOSYS` (libc falls back to the inspectable `clone`). Architecture check:
  foreign audit arch (e.g. i386 `int 0x80`) kills the process; x32 syscall numbers
  (`__X32_SYSCALL_BIT`) → `ENOSYS`.
* `tessera-sandbox-init` (bound read-only at `/.tessera/init`) closes every fd except
  0, 1, 2 and the broker channel, applies Landlock (read/exec on runtime paths, full
  access on `/workspace`, `/tmp`, `/dev/shm`, read/write/ioctl on `/dev`; all TCP
  bind/connect denied; signal and abstract-unix-socket scoping), verifies
  `Seccomp: 2`, `NoNewPrivs: 1`, `CapEff: 0`, and reports a status line over a
  dedicated pipe. `Launcher::spawn` returns only after that confirmation (and
  checks the reported fd set is exactly `0,1,2,3`); otherwise it kills the tree.
* cgroup leaf: `memory.max` (default 2 GiB) with `memory.oom.group=1`,
  `memory.swap.max=0`, `pids.max` (default 512), optional `cpu.max`.
  `SandboxHandle::stop()` writes `cgroup.kill`, SIGKILLs bwrap via pidfd, reaps it and
  removes the leaf.

### Broker channel

A fresh `socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC)` per sandbox. The sandbox
end is mapped to **fd 3** for bwrap (via `command-fds`, i.e. `dup2` in the forked child,
so concurrent launches cannot leak each other's channels) and survives into the
workload, which is told `TESSERA_BROKER_FD=3` (plus `TESSERA_AGENT_ID=<label>`). The
host end is `SandboxHandle::broker_channel()` / `take_broker_channel()`. `SO_PEERCRED`
on the host end reports the *launcher* (the socketpair creator), so the broker must
bind identity to the channel object itself, not to peer credentials.

## Evidence

* `cargo test -p tessera-launcher`: 9 unit + 18 integration tests, all launching real
  sandboxes on this host (canary in `$HOME` and in an unbound temp dir unreadable;
  TCP to 1.1.1.1:53 / 8.8.8.8:443 / IPv6 / metadata IP fail, DNS fails, host unix and
  abstract sockets unreachable, loopback TCP bind denied by Landlock; ≤ 10 PIDs
  visible, host PID unsignalable, `/proc/1/{environ,fd}` unreadable; 38 syscall
  cases + 8 clone namespace flags + 5 socket families + TIOCSTI denied, fork/threads
  still work; inherited fds 7/8/9 from a hostile parent closed; credential variables
  in the launcher's environment absent; writes outside workspace fail; read-only
  workspace; broker round trip with message boundaries and EOF on exit; distinct
  channels per sandbox; `pids.max` enforced; process tree (incl. a `setsid`
  daemon) killed by `stop()` both with cgroup and in the opt-out PID-namespace path;
  R10 refusals for missing bwrap, missing init shim, missing cgroup delegation).
* `tests/adversarial/run.sh`: 7 probes (env, escape, fds, fs_read, fs_write, net,
  pids; 164 blocked attempts) — **ALL PROBES CONTAINED** on this host.

## Not enforced / residual limitations on this host

* **BPF LSM**: active in the kernel, but the launcher runs unprivileged and does not
  attach BPF programs (WP7). Not a mandatory control.
* **Seccomp is a denylist**, not an allowlist; newly added kernel syscalls are allowed
  until reviewed. `bpf`, `mount`, `kexec_*`, module and `open_by_handle_at` denials
  cannot be distinguished from the kernel's own capability checks by the probe
  (they return `EPERM` either way); all other cases are discriminating.
* **Landlock** denies `ls /` (no rule on `/` itself); the root is a read-only tmpfs.
  UDP is not restricted by Landlock ABI 6 — the empty network namespace is the
  control there.
* **The broker-channel peer identity** is the channel itself (`SO_PEERCRED` shows the
  launcher). Membership via cgroup path is recorded in the launch record.
* **`--die-with-parent`** ties the sandbox to the *thread* that called `spawn()`.
* bwrap's PID-1 command line (visible in the sandbox's `/proc/1/cmdline`) shows host
  paths of the workspace and init shim.
* Without delegation (operator opt-out `CgroupRequirement::AllowMissing{operator_reason}`)
  there are no CPU/memory/PID limits; tree kill relies on PID-namespace teardown.
  Every such launch prints a warning and stores the reason in `LaunchRecord`.
