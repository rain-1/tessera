# BPF LSM direct grants: evaluation (WP7 / P6)

Status: **research, not shipped.** ADR-0023 records the decision: direct
grants are not part of the MVP; the broker-only profile remains the
supported profile. This document is the evidence behind that decision and
the starting point if direct grants are pursued later.

Nothing in this document has been run against a kernel with a BPF program
loaded. The development host has no root, so no BPF program was loaded,
verified or attached, and no runtime behaviour was observed. Every claim is
labelled with how it was established:

| Label | Meaning |
|---|---|
| **probe** | Observed on the host by `enforcement/ebpf/probe/bpf_lsm_probe.py` (unprivileged) |
| **src** | Read in kernel source at tag `v6.12.118` (file:line given), see §1.2 |
| **btf** | Present with this prototype or field in the running kernel's `/sys/kernel/btf/vmlinux` |
| **model** | Checked by `models/bpf_generation_model.py` or the Rust tests in `enforcement/ebpf/manager` |
| **assumed** | Believed from documentation or general knowledge; not verified here |
| **untested** | Requires root to test; not done |

## 1. Host and kernel

### 1.1 Feature probe (2026-11-25)

Regenerate with `python3 -I enforcement/ebpf/probe/bpf_lsm_probe.py`
(`--strict` exits 2 if a prerequisite is missing). Raw output:
`enforcement/ebpf/probe/results-6.12.118+deb13-amd64.json`.

| Item | Result | How |
|---|---|---|
| Kernel | `6.12.118+deb13-amd64`, Debian 6.12.118-1 (2026-11-20), x86_64 | probe |
| Active LSMs | `lockdown,capability,landlock,yama,apparmor,tomoyo,bpf,ipe,ima,evm`; no `lsm=` on the command line | probe |
| `CONFIG_BPF_LSM` | `y` | probe (`/boot/config-6.12.118+deb13-amd64`, world-readable) |
| `CONFIG_DEBUG_INFO_BTF` / `_MODULES` | `y` / `y` | probe |
| `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT`, `CONFIG_CGROUP_BPF` | `y`, `y`, `y`; `CONFIG_BPF_JIT_ALWAYS_ON` not set | probe |
| `CONFIG_SECURITY_PATH`, `CONFIG_SECURITY_NETWORK` | `y`, `y` (path_* and socket_* hooks exist) | probe |
| `CONFIG_LSM` (default order) | `landlock,lockdown,yama,loadpin,safesetid,integrity,apparmor,selinux,smack,tomoyo,bpf,ipe` | probe |
| `/sys/kernel/btf/vmlinux` | present, 113,961 types | probe |
| Lockdown | `integrity` (Secure Boot). `bpf_probe_write_user` is unavailable; `bpf_probe_read_kernel` is not (it is gated by `LOCKDOWN_BPF_READ_KERNEL`, a confidentiality-level reason: `include/linux/security.h:140-147`, `kernel/trace/bpf_trace.c:1467-1484`) | probe + src |
| `kernel.unprivileged_bpf_disabled` | `2` (disabled; an admin may re-enable); `CONFIG_BPF_UNPRIV_DEFAULT_OFF=y` | probe |
| `bpf(BPF_MAP_CREATE)` as uid 1000 | refused, `EPERM` | probe |
| bpffs | mounted at `/sys/fs/bpf`, mode 0700 (not listable as uid 1000) | probe |
| `bpftool` | **not installed** | probe |
| `clang` | 19.1.7 with `bpf`/`bpfel`/`bpfeb` targets | probe |
| `libbpf` | `libbpf1` 1.5.0 runtime only; **no `libbpf-dev` headers** | `dpkg -l` |
| LSM attach targets `bpf_lsm_<hook>` for all 14 hooks used or considered (§4) | present, parameter names match `lsm_hook_defs.h` | btf |
| CO-RE fields read by the program (12, e.g. `struct mount.mnt_id_unique` at +304, `file.f_path` at +64) | present | btf |

What is **not** known for this host: whether the verifier accepts the
program, whether attachment succeeds, the order in which the BPF LSM runs
relative to other LSMs at runtime (the static order is in the table), and
overhead. All need root.

### 1.2 Source used

- `include/linux/lsm_hook_defs.h`: the Debian package
  `linux-headers-6.12.118+deb13-common` (matching the running kernel) and the
  upstream stable tag `v6.12.118` from git.kernel.org are **byte-identical**.
- `.c` call sites: upstream stable `v6.12.118` (git.kernel.org
  `stable/linux.git`). Debian's patch set on top of that tag was **not
  reviewed**. Debian patches rarely touch these paths, but that is an
  assumption.
- Line numbers below refer to `v6.12.118`.

### 1.3 BPF LSM semantics relevant here (src)

- Every LSM hook in `lsm_hook_defs.h` is a BPF attach target, apart from a
  small disabled set. None of the hooks used here is in that set
  (`kernel/bpf/bpf_lsm.c:38-57`).
- An `int` hook program may return only 0 or `-errno`
  (`bpf_lsm_get_retval_range`, `kernel/bpf/bpf_lsm.c:426-447`). A BPF program
  therefore can only add a denial. It cannot grant what another LSM denied.
- `call_int_hook` stops at the first LSM that returns a non-default value
  (`security/security.c:994-1011`). A denial by Landlock, AppArmor, Yama and
  so on is final, which preserves prior denials (spec §10.2). Several BPF
  programs on one hook are chained, and the program sees the previous
  return value as its last argument. Our program returns it unchanged when
  it is non-zero.
- `bpf_get_current_cgroup_id`, `bpf_get_current_ancestor_cgroup_id` and
  `bpf_ktime_get_boot_ns` are available to LSM programs loaded with
  `CAP_BPF` (`kernel/bpf/helpers.c:1954,2030-2033`; LSM programs fall back
  to `tracing_prog_func_proto`, `kernel/bpf/bpf_lsm.c:281-282`).
- `BPF_LSM_MAC` programs are global: they run for every task, so the
  program must recognise managed subjects itself. `BPF_LSM_CGROUP`
  (per-cgroup attachment) exists but uses different helper sets and return
  conventions. It was not evaluated (assumed; see §9).

## 2. Candidate class chosen

**Unlimited-use read-only access to a registered directory subtree**, for
the lifetime of a lease, by exactly one sandbox.

How it fits the existing design:

- Today PE-01 (read a registered file) is brokered. Each read costs one unit
  and returns bytes, never a descriptor. PE-03 (direct open, read or mmap
  of a registered file) is denied by the baseline: the object is not in the
  sandbox's mount namespace.
- A direct grant would turn PE-03 into "allowed while a valid grant is
  installed" for one subtree. That suits read-heavy tools (grep, compilers,
  indexers), for which per-read brokering is impractical, on data the
  operator already approved for unlimited reading.

### 2.1 Why not outbound connect to a registered address:port

The other suggested class was rejected for the first iteration. The reasons:

1. **It inverts the network baseline.** Today PE-07 holds because the
   sandbox's network namespace contains only `lo`. A direct connect grant
   needs a routed interface (veth, NAT) in that namespace. From then on,
   every non-granted protocol and destination is denied **only** by the BPF
   program, so a detached program or a missed hook fails open for all
   egress. The read-subtree class fails open only for the subtrees that the
   operator chose to mount into that sandbox (§5.4).
2. **There are more paths to cover.** The paths are `connect`
   (`security_socket_connect`, `net/socket.c:2050`, in `__sys_connect_file`,
   which io_uring also uses), unconnected UDP `sendto`/`sendmsg`
   (`security_socket_sendmsg`, `net/socket.c:724`), TCP Fast Open
   (`sendto(MSG_FASTOPEN)` connects inside the protocol without
   `socket_connect`; assumed to be covered by `socket_sendmsg` only), DNS,
   IPv4-mapped IPv6 addresses, `AF_UNSPEC` disconnect and reconnect,
   already-connected sockets passed by `SCM_RIGHTS`, ICMP and ping
   sockets, and the address rewriting of `cgroup/connect4` programs.
3. **The disclosure is unbounded.** An unlimited-use connect to an external
   host is an unbounded exfiltration channel (spec §10.1). It needs a
   stronger approval story than read-only local data.
4. **There is an existing alternative.** `cgroup/connect4/6` and
   `cgroup_skb` programs are the conventional mechanism for this class and
   would need their own evaluation.

The attach targets `bpf_lsm_socket_connect` and `bpf_lsm_socket_sendmsg`
exist on this kernel (btf). No further work was done on this class.

## 3. Identities

### 3.1 Subject: cgroup id plus launch id

- The launcher already places every sandbox process in a per-sandbox cgroup
  v2 leaf before `exec bwrap` (kernel-feature-report). The BPF program reads
  `bpf_get_current_cgroup_id()`.
- The workload cannot leave the leaf. It has no cgroupfs mount, a private
  cgroup namespace and no capabilities (assumed from the launcher design;
  tested by the launcher for visibility, not for migration).
- **Reuse (src):** on 64-bit, `kernfs_node.id` is
  `(id_highbits << 32) | idr_alloc_cyclic(...)`, and `id_highbits` is
  incremented when the cyclic allocator wraps
  (`fs/kernfs/dir.c:630-640,984`). Cgroup ids therefore do not repeat within
  a boot unless 2^64 ids are allocated. The manager still pairs the id with
  a manager-assigned **launch id** stored in the subject entry. Adoption
  after a manager restart requires the same (cgroup id, launch id) pair
  (`Manager::adopt`), and a mismatch is refused.
- Cleanup: on sandbox stop the manager expires the lease, deletes the
  grants, the governed mounts and the subject (`Manager::unregister`). The
  launcher must call this **before** it removes the cgroup directory.

### 3.2 Object: the bind mount's `mnt_id_unique`

Each grantable subtree is bind-mounted read-only (`nosuid,nodev,noexec`)
into the sandbox at launch, **one mount per subtree**. The object identity
is that bind mount's 64-bit `mnt_id_unique`:

- `struct mount.mnt_id_unique` is "mount ID unique until reboot"
  (`fs/mount.h:81`). It comes from a 64-bit counter that only increases
  (`fs/namespace.c:254`). It is never reused.
- The manager reads it with `statx(STATX_MNT_ID_UNIQUE)`
  (`fs/stat.c:258`, v6.8 and later) on `/proc/<sandbox-pid>/root/<mountpoint>`,
  **before** registering it.
- In BPF it is reached as `container_of(file->f_path.mnt, struct mount, mnt)->mnt_id_unique`.
  The program uses a CO-RE-relocated offset and `bpf_probe_read_kernel`.
- Why a mount and not an inode or a path walk:
  - Path resolution cannot leave a vfsmount through `..` above its root:
    `..` crosses to the parent mount, so the access is then judged under
    *that* mount's id.
  - `linkat` and `renameat` across mounts fail with `EXDEV`
    (`fs/namei.c:4866,5154`), so a workload cannot alias a file out of, or
    into, the granted mount.
  - Magic-link reopen (`/proc/self/fd/N`, `proc_pid_get_link` →
    `nd_jump_link`, `fs/proc/base.c:1813`) keeps the original
    `struct path`, mount included.
  - Raw inode numbers are not identities (spec §10.2), and walking dentry
    parents in BPF is bounded, racy against rename, and expensive.
- Each sandbox gets its own bind mount, so one sandbox's grant can never be
  used through another sandbox's mount. Even with a grant entry for itself,
  any task whose cgroup is not the mount's registered owner is denied.

### 3.3 Dentry-only hooks: governed filesystem

`inode_getxattr`, `inode_listxattr` and `inode_readlink` receive only a
dentry, with no vfsmount (src: `lsm_hook_defs.h`; btf). For these hooks the
program decides by superblock: a managed subject is denied on any
**governed device**. This requires every grantable subtree to live on a
**dedicated filesystem**, one that nothing else the sandbox uses is mounted
from, and one where `st_dev == sb->s_dev` (for example ext4 or xfs; not
btrfs subvolumes, assumed). The manager checks this against
`/proc/<pid>/mountinfo` before registration (not implemented).

## 4. Hook matrix for the chosen class

Program: `enforcement/ebpf/bpf/tessera_direct_read.bpf.c`. "Governed" means
the access goes through a registered bind mount. Every row denies unless
all of these hold:
- the current cgroup owns the mount;
- the owner's lease is unexpired;
- a grant for (cgroup, mount) is valid at the owner's active generation.

The hook prototypes in the table were confirmed in btf. Each call site was
confirmed in src at `v6.12.118`.

| # | Access path | Kernel call site → hook (src) | Program action | Status |
|---|---|---|---|---|
| 1 | `open`, `openat`, `openat2`, `creat` | `do_dentry_open` → `security_file_open` (`fs/open.c:939`) | Allow read-only opens with a grant; deny `FMODE_WRITE` and `FMODE_EXEC` | src, compiled, untested |
| 2 | `O_PATH` open | `do_dentry_open` **returns before `security_file_open`** for `O_PATH` (`fs/open.c:913-917`) | Not mediated at open. An `O_PATH` fd gives no content: `fdget` rejects `FMODE_PATH` files for read, mmap and cachestat (`fs/file.c:1135`). Content needs a reopen through `/proc/self/fd`, which is row 1. `fstat` on it is row 10 | src; **residual: name/inode existence** |
| 3 | `execve`/`execveat` of a file in the subtree | `do_open_execat` opens with `__FMODE_EXEC` via `do_filp_open` (`fs/exec.c:889,902`) → row 1 | Denied (`FMODE_EXEC`). The mount is also `noexec` | src |
| 4 | `read`, `pread64`, `readv`, `preadv(2)` | `vfs_read`/`vfs_readv`/`vfs_iter_read` → `rw_verify_area` → `security_file_permission` (`fs/read_write.c:470,560,919,1020`) | Re-checked on **every call**: `MAY_READ` with a currently valid grant; anything else denied | src, compiled, untested |
| 5 | `sendfile` | `do_sendfile` → `rw_verify_area(READ, in)` (`fs/read_write.c:1343`) | As row 4 | src |
| 6 | `splice` from the file | `vfs_splice_read` → `rw_verify_area` (`fs/splice.c:1012`); `do_splice` (`fs/splice.c:1375`) | As row 4. Bytes already in a pipe stay there | src |
| 7 | `copy_file_range`, reflink/dedupe ioctls | `vfs_copy_file_range` → `rw_verify_area` both ends (`fs/read_write.c:1594-1598`); `remap_verify_area` → `security_file_permission` (`fs/remap_range.c:114`) | Read side as row 4. Cross-filesystem copies to the workspace use the read path | src |
| 8 | `getdents64` (directory listing) | `iterate_dir` → `security_file_permission(MAY_READ)` (`fs/readdir.c:93`) | As row 4 | src |
| 9 | Kernel-internal reads (`kernel_read`, e.g. by interpreters or binfmt) | `kernel_read` → `rw_verify_area` (`fs/read_write.c:542`) | As row 4 (subject = current task) | src |
| 10 | `stat`, `fstat`, `statx`, `newfstatat`, including on `O_PATH` fds | `vfs_getattr` → `security_inode_getattr(path)` (`fs/stat.c:208`) | Requires a grant. Bypass `vfs_getattr_nosec` is used only by file-handle code (`fs/stat.c:124-136`), which seccomp denies | src, compiled, untested |
| 11 | `mmap` of a file | `vm_mmap_pgoff` → `security_mmap_file` (`mm/util.c:584`), which also covers ELF loading via `vm_mmap`; `remap_file_pages` (`mm/mmap.c:1727`) | **Denied by default.** Allowed read-only (no `PROT_WRITE`/`PROT_EXEC`) only if the grant carries `ALLOW_MMAP`, which marks it **non-revocable for its lease** | src, compiled, untested |
| 12 | `mprotect` on an existing file mapping | `do_mprotect_pkey` → `security_file_mprotect` (`mm/mprotect.c:824`) | Denied for governed files unless `ALLOW_MMAP`, and never `PROT_WRITE`/`PROT_EXEC` | src, compiled, untested |
| 13 | Receive an fd via `SCM_RIGHTS` | `scm_recv_one_fd` → `receive_fd` → `security_file_receive` (`include/net/scm.h:228`, `fs/file.c:1295`) | Requires the receiver to own the mount and hold a grant. Another sandbox's fds are useless anyway, because they reference *its* mount | src, compiled, untested |
| 14 | `pidfd_getfd` | `pidfd_getfd` → `receive_fd` (`kernel/pid.c:723`) | As row 13. Seccomp also denies `pidfd_getfd` | src |
| 15 | fds inherited across `fork`/`exec`, `dup`, `dup3`, `fcntl(F_DUPFD)` | No hook | Not mediated at acquisition. Every later read goes through row 4, so a revoked grant makes inherited fds useless for `read`-family calls. Sandbox start closes inherited fds (launcher) | src (absence), by design |
| 16 | `ioctl` | `ioctl` syscall → `security_file_ioctl` before `do_vfs_ioctl` (`fs/ioctl.c:900,956`) | Denied on governed files (`FIONREAD`, `FS_IOC_*`, `FICLONE` source…) | src, compiled, untested |
| 17 | `inotify_add_watch` | `inotify_find_inode` → `security_path_notify` (`fs/notify/inotify/inotify_user.c:386`); fanotify (`fs/notify/fanotify/fanotify_user.c:1839`) is also denied by seccomp | Denied on governed mounts | src, compiled, untested |
| 18 | `getxattr`/`lgetxattr`/`fgetxattr`, `listxattr` | `vfs_getxattr` → `security_inode_getxattr` (`fs/xattr.c:438`); `security_inode_listxattr` (`fs/xattr.c:488`) | Dentry only: denied for managed subjects on governed devices (§3.3) | src, compiled, untested |
| 19 | `readlink`/`readlinkat` | `do_readlinkat` → `security_inode_readlink` (`fs/stat.c:552`); `vfs_get_link` (`fs/namei.c:5360`) | Dentry only: as row 18. Following symlinks during a path walk is not denied: an absolute target resolves under the sandbox root and therefore lands on another mount | src, compiled, untested |
| 20 | `io_uring` read/openat | `__io_read` → `rw_verify_area` (`io_uring/rw.c:855`); opens go through `do_filp_open` | Would be rows 1 and 4. All `io_uring_*` syscalls are denied by seccomp (PE-20) | src, seccomp |
| 21 | Linux AIO `io_submit` with `IOCB_CMD_PREAD` | `aio_read` → `rw_verify_area` (`fs/aio.c:1611`) | As row 4. **Note:** `io_setup`/`io_submit` are *not* in the launcher's seccomp deny list. They are mediated by row 4 regardless | src |
| 22 | Write paths: `write`, `truncate`, `fallocate`, `unlink`, `rename`, `link`, `mkdir`, `chmod`, `setxattr`, `utimes` | Read-only bind mount (`EROFS`) and Landlock read-only rules; `security_file_permission(MAY_WRITE)` and `file_open(FMODE_WRITE)` are also denied by the program | Baseline controls. The program adds denials on rows 1 and 4 only. The `path_*` mutation hooks are **not** attached | mount + Landlock (baseline, tested by launcher for its own mounts); assumed for this mount |
| 23 | `flock`/`fcntl` locks | `security_file_lock` (`fs/locks.c:2023,2168,2377`), `security_file_fcntl` (`fs/fcntl.c:589`) | **Not attached.** A shared lock on a read-only fd can block a broker writer that takes an exclusive lock | src; **residual (availability)** |
| 24 | `lseek(SEEK_DATA/SEEK_HOLE)`, `fstatfs`, `cachestat`, `fadvise`, `readahead` on an fd opened under a valid grant | `ksys_lseek` has no hook (`fs/read_write.c`); `statfs_by_dentry` → `security_sb_statfs` (`fs/statfs.c:63`) is not attached; `cachestat` uses `fdget` with no LSM hook | Not mediated. After revocation they reveal metadata (holes, size, page-cache residency, filesystem statistics) but no content | src; **residual (metadata side channels)** |
| 25 | Path traversal and existence probing (`access`, `faccessat2`, `open` returning `ENOENT` vs `EACCES`) | `inode_permission` → `security_inode_permission` (`fs/namei.c:548`), which receives the inode and no mount | Not attached (no mount identity; hot path). Names inside a mounted, non-granted subtree can be probed | src; **residual (name existence)** |
| 26 | Pages mapped before revocation (`ALLOW_MMAP` grants only) | Page faults have no LSM hook | Cannot be revoked. Hence `ALLOW_MMAP` ⇒ non-revocable; strict revocation means killing the sandbox | src (absence) |
| 27 | Data already read: copies in the workspace, in pipes, in memory, or sent to the model | — | Not revocable by any mechanism; unchanged from brokered reads | inherent |
| 28 | Another sandbox's mount, or the broker's own host path to the same files | A different `mnt_id_unique` | The mount is not in `governed_mounts`, so the program does not act; access is decided by baseline confinement (that mount is not visible in the sandbox) | src (mount identity), by design |
| 29 | Hardlinks, bind mounts or overlays that a **host** actor creates inside the subtree | — | Inside the granted mount they are part of the grant. The operator/broker must keep `st_nlink == 1` and avoid foreign mounts in grantable subtrees (ADR-0019 already requires a broker-owned root) | **residual (trusted host configuration)** |

### 4.1 Coverage caveats

- **Per-call re-check is what makes revocation work.** Rows 4–9 re-check on
  every read-family syscall. After revocation an existing fd still exists
  but every `read`/`getdents`/`sendfile` on it fails. This depends on
  `rw_verify_area` being on every content-returning path. That was verified
  for the call sites listed above, **not** for every filesystem's private
  ioctl or every in-kernel consumer. A full audit would trace all callers of
  `->read_iter`, `->splice_read` and `->iterate_shared` (not done).
- **Revocation is not instantaneous for syscalls already past the hook.**
  The protocol uses a freeze barrier (§6) so that acknowledgement waits for
  them.
- `O_PATH` (row 2), the metadata side channels (row 24) and name existence
  (row 25) are accepted residuals. None of them returns file content.
- Rows 18 and 19 rely on the dedicated-filesystem rule (§3.3).
- The BPF LSM can be detached by root. Root is in the TCB (threat model
  R-3), but see §5.4 for what fails open.

## 5. Program and map design

Source: `enforcement/ebpf/bpf/tessera_direct_read.{h,bpf.c}`. It is
self-contained: there is no `vmlinux.h` because `bpftool` is not installed,
and there are no libbpf headers because `libbpf-dev` is not installed.
Kernel structs are declared minimally with `preserve_access_index`, so
libbpf would relocate each field against the running kernel's BTF at load
time. Compile check: `enforcement/ebpf/bpf/build.sh` (clang 19, `-Wall
-Werror`). It builds an object with 12 `lsm/*` program sections plus `.BTF`
and `.BTF.ext`.

### 5.1 Maps (hash maps, fixed capacity)

| Map | Key → value | Capacity |
|---|---|---|
| `subjects` | cgroup id → `{active_gen, lease_expiry_ns, launch_id}` | 1024 |
| `governed_mounts` | `mnt_id_unique` → `{owner_cgroup_id}` | 8192 |
| `governed_devs` | `s_dev` → `u8` | 16 |
| `grants` | `(cgroup id, mnt_id_unique)` → `{gen_from, gen_until, flags}` | 8192 |

- A grant is valid iff `gen_from <= active_gen < gen_until`.
- The manager refuses a transition that would exceed capacity *before*
  staging (`Error::Capacity`).
- Hash maps are used because a hash-map update replaces the whole element,
  so a concurrent reader sees either the old or the new value (assumed from
  the htab implementation; **verify** before relying on it). An array-map
  update copies in place and can tear multi-word values.

### 5.2 Decision procedure (`decide()`)

1. Look up the mount's `mnt_id_unique` in `governed_mounts`. If it is
   absent, return 0: no opinion, other LSMs and the baseline decide. This is
   what keeps the program from affecting `/usr`, the workspace or the host.
2. Otherwise the access is **governed: default deny.** Deny unless:
   - the current cgroup id equals the mount's owner;
   - `subjects[cg]` exists;
   - `bpf_ktime_get_boot_ns() < lease_expiry_ns`;
   - `grants[(cg, mnt)]` exists and is valid at `active_gen`.
3. Per-hook restrictions follow the matrix: read only, no exec, no ioctl,
   no inotify, and mmap only with `ALLOW_MMAP`.

There are no counters, no per-access state and no loops.

### 5.3 Protection of BPF objects

- Maps and links are pinned under `/sys/fs/bpf/tessera/`. bpffs is mode
  0700, owned by root, and never mounted into a sandbox.
- Workloads have no capabilities, and seccomp denies `bpf(2)` (PE-20).
- The manager runs as a separate privileged service. The broker stays
  unprivileged and talks to it over a socket.
- Attachment uses `bpf_link`s pinned in bpffs. A link pinned in bpffs keeps
  the program attached after the manager exits (assumed from libbpf/bpffs
  semantics; **untested**).

### 5.4 What fails open, and how far

- If the program is **detached**, the governed bind mounts become ordinary
  read-only mounts. The sandbox can then read every subtree *mounted into
  it*, which is everything it **could** be granted, not just what it **was**
  granted. Everything else (other files, network, other sandboxes) is still
  denied by the baseline.
- Mitigations:
  - mount only subtrees the operator registered as grantable for that
    sandbox at launch;
  - the manager verifies the pinned link is attached on every lease renewal
    (`BPF_OBJ_GET_INFO_BY_FD`) and kills managed cgroups (`cgroup.kill`) when
    it is not;
  - the launcher refuses to mount grantable subtrees unless the manager has
    acknowledged registration (default-deny entries in place) **before**
    the workload is released from its start gate.
- None of these mitigations is implemented. The start gate does not exist
  yet: today `tessera-sandbox-init` execs the workload straight after its
  status report.

## 6. Policy generation protocol (spec §10.3)

Implemented as a pure state machine in
`enforcement/ebpf/manager/src/manager.rs` and modelled in
`models/bpf_generation_model.py`.

### 6.1 Roles

- **Broker (authority).** For each sandbox the ledger holds direct grants as
  unlimited-use capabilities with a lease and a scope (mount). Each change
  produces a new **desired generation** D, which is strictly increasing,
  and its complete grant set. The broker tells the agent that a grant is
  usable only after the manager reports `Installed(g ≥ D)`. A revocation is
  acknowledged to the revoker only when the report lists it in
  `revocations_acked`.
- **Manager (installer).** It owns the **installed generation**, which is
  `subjects[cg].active_gen` in the kernel map. Memory is never trusted over
  the maps.

### 6.2 Transition G → D

0. **Reconcile** from the kernel. Read `active_gen` = G and the grant
   entries. Delete leftovers of an aborted transition: entries with
   `gen_from > G` and entries with `gen_until <= G`. Re-open aborted
   removals (`gen_until` back to ∞). This changes no authority at G.
1. **Check:** D > G; every mount is registered to this subject; no in-place
   flag change (changing `ALLOW_MMAP` takes a revoke followed by a grant);
   map capacity is sufficient.
2. **Stage:** write additions as `[D, ∞)` and removals as `[gen_from, D)`.
   Both are inert at G. A crash here leaves G's authority unchanged.
3. **Barrier,** only if something is removed. Write `cgroup.freeze`, then
   wait for `frozen 1`. The cgroup v2 freezer stops tasks at the return to
   user mode, so no task is inside a hook that already read the old entry
   (cgroup freezer semantics assumed; **untested**).
4. **Activate:** one hash-map update sets `active_gen = D`, leaving the
   lease unchanged.
5. **Thaw.**
6. **Remove** retired entries.
7. **Verify** by reading back: `active_gen == D`, the set valid at D equals
   the desired set, and no retired entries remain. Only now report
   `Installed(D)` and acknowledge revocations. If verification fails, the
   manager sets the lease to 0 (fail closed) and reports an error.

A freeze timeout aborts the transition before activation and thaws. The
next transition's reconcile step removes the leftovers.

### 6.3 Lease and failure

- Every subject entry has `lease_expiry_ns` on `CLOCK_BOOTTIME`, the same
  clock as `bpf_ktime_get_boot_ns`, which also counts suspend time.
- The program denies every governed access once the lease has expired.
- The manager renews leases only while it is idle, alive and connected to a
  live broker.
- So: the **manager dies** → nobody renews → all direct grants become inert
  within one lease period, even though pinned maps and links survive
  ("do not assume a dead broker automatically removes pinned policy").
- The **broker dies or disconnects** → the manager stops renewing → the same
  outcome. A broker restart bumps the epoch (ADR-0003), which invalidates
  all grants, including direct ones, so they must be re-issued.
- The **manager restarts** → it expires every lease first, then deletes
  every grant and thaws (`Manager::start`). Orphaned subjects must be
  re-adopted with the same (cgroup id, launch id) and receive a fresh
  generation D > G before anything is usable again.
- The lease period bounds how long direct use outlives a failure. Choosing
  it trades renewal traffic against that exposure (for example 5 s; not
  measured).

### 6.4 Revocation semantics

| Grant kind | After `revocations_acked` contains it |
|---|---|
| default (no mmap) | Every open, read-family call, `getdents`, `stat`, `mmap` or fd receipt entering the kernel afterwards is denied. Calls in flight at the barrier completed before activation. Existing fds remain, but are useless for content. Metadata residuals (row 24) remain |
| `ALLOW_MMAP` | The same, except that pages already mapped stay readable. It is reported as `revoked_with_residual_mappings`, **not** as acknowledged. The ledger must label such grants non-revocable for their lease (spec §10.2), or the broker must kill the sandbox to revoke strictly |

### 6.5 Results

**Rust** (`cargo test -p tessera-bpf-manager`): 17 tests pass, with no root
needed. They cover:
- default deny;
- usable only at activation and never partially visible;
- foreign cgroup denied;
- stale generation rejected with zero writes;
- revocation acknowledged only after removal, with the activation under the
  barrier;
- an mmap grant reported as non-strict;
- an in-place flag change rejected;
- capacity refused before staging;
- lease expiry, with renewal requiring the broker;
- manager death failing closed through the lease;
- restart wiping state and requiring a fresh generation and a matching
  launch id;
- reconcile of an aborted transition;
- **crash before each of the kernel operations of a 4-generation
  scenario**, with the safety property checked after every intermediate
  map write;
- fault injection showing that verification catches the "no reconcile"
  bug.

The fake kernel cannot represent in-flight hooks, so the barrier is checked
only by the model.

**Model** (`python3 -I models/bpf_generation_model.py`): see
`models/README.md`.
- The correct protocol satisfies all six invariants, exhaustively, in
  33,806 states (1 crash, 1 freeze abort, 1 broker failure) and 103,244
  states (2 crashes, 2 aborts).
- Each of the six bug variants produces a counterexample:

| Bug variant | Invariant violated |
|---|---|
| `ack-before-removal` | AckAfterRemoval |
| `no-barrier` | NoUseAfterRevocationAck: a check passes at G, the revocation is acked at D, then the access completes |
| `activate-before-stage` | KernelWithinActiveGeneration and NoUseAfterRevocationAck |
| `no-reconcile` | KernelWithinActiveGeneration: a staged add from an aborted generation becomes valid at a later generation that does not grant it |
| `no-lease` | ManagerFailureFailsClosed |
| `restart-trusts-maps` | RestartFailsClosed |

## 7. Why finite budgets stay in the broker

- A direct grant is **unlimited-use within a lease**. An allowed `open` is
  not "one read", and an allowed `read` is not "one unit of disclosure".
  Bytes, calls and duplicated fds have no meaningful mapping to the
  ledger's units (spec §10.2).
- Kernel counters would be a second source of truth. Keeping them
  consistent with the ledger across crashes would need the journal's
  durability (fsync before effect, ADR-0002) inside the kernel, which BPF
  maps do not provide. The spec forbids independent counters in both places
  (§10.3).
- Per-CPU or atomic counters in BPF can be made exact. Their state is still
  lost or stale on manager restart, and "refund on failure" cannot be
  avoided at the hook level. A hook allowing an `open` does not know whether
  the open succeeded, because a later LSM or the filesystem may still fail
  it.
- So: the ledger holds the direct grant as an **unlimited, lease-bounded
  capability** (it is minted with approval like any other). The kernel
  holds only "valid at generation g, until lease t". Finite operations
  (PE-01, PE-02, PE-06) remain brokered.

## 8. What remains before direct grants could ship (WP7 gate)

The gate in spec WP7 is "supported resource class has documented hook
coverage, tested fail-closed behaviour, measured overhead and stated
residual limitations". Against that gate:

| Gate item | State |
|---|---|
| Documented hook coverage | This document. Call sites verified in source; Debian patches and full caller audit of `->read_iter`/`->splice_read`/`->iterate_shared` not done |
| Program accepted by the verifier on the pinned kernel | **Not done (root)** |
| Kernel backend (libbpf-rs loader, pinning, `cgroup.freeze`, link-attached watchdog) | **Not written** |
| Launcher start gate, per-subtree bind mounts, dedicated-filesystem check, Landlock outer bound | **Not written** |
| Adversarial tests: every row of §4 as a hostile workload, run before and after revocation; detach the link; kill the manager; manager restart; freeze timeout | **Not done (root)** |
| Fail-closed behaviour tested on a kernel | **Not done**; modelled and tested against a fake kernel only |
| Overhead measured (global `BPF_LSM_MAC` on `file_permission` runs for every read on the host) | **Not done**. `BPF_LSM_CGROUP` should be evaluated to limit the cost to managed cgroups |
| Ledger representation of direct grants (lease, non-revocable label, desired generation) | **Not designed** in `capability-core` |
| Residual limitations stated | §4 rows 2, 23–27, 29; §5.4 |

## 9. Open questions

- `BPF_LSM_CGROUP` versus global `BPF_LSM_MAC`. Per-cgroup attachment would
  confine the cost to sandboxes, but its program type has different helpers
  and return conventions (`kernel/bpf/bpf_lsm.c:228-233`). Not evaluated.
- Whether the bpf_link for an LSM program, pinned in bpffs, stays attached
  across manager exit on this kernel (expected yes; untested).
- htab update atomicity for multi-field values as seen by a concurrent BPF
  reader (§5.1). The design needs only `active_gen` (8 bytes) and whole
  grant replacement.
- Whether `cgroup.freeze` reliably reaches `frozen 1` while tasks sit in
  long uninterruptible I/O on the governed filesystem. The freeze timeout
  aborts the transition and does not acknowledge.
- Whether to attach `file_lock` (row 23) and `sb_statfs` (row 24) to close
  the availability and metadata residuals.
