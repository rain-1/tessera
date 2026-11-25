//! Seccomp-BPF policy for sandboxed workloads (spec §10.1).
//!
//! The policy is a *denylist* of interfaces that are unaudited or give
//! kernel-level control (io_uring, ptrace, BPF, perf, keyrings, mount API,
//! namespace manipulation, userfaultfd, module/kexec loading, handle-based
//! opens, cross-process memory access, ...). Three programs are produced and
//! all installed by bubblewrap (`--add-seccomp-fd`) immediately before the
//! sandbox init shim is executed:
//!
//! 1. the main deny filter (`EPERM`), including argument filters for
//!    `clone(CLONE_NEW*)`, terminal-injection ioctls and non-allowlisted
//!    socket address families. Built with `seccompiler`, which prefixes an
//!    architecture check that kills the process on a foreign ABI (e.g. i386
//!    `int 0x80` on x86_64);
//! 2. `clone3` -> `ENOSYS` (its flags live in memory and cannot be inspected;
//!    libc falls back to `clone`, which filter 1 inspects);
//! 3. on x86_64 only, an x32-ABI guard returning `ENOSYS` for any syscall
//!    number with `__X32_SYSCALL_BIT` set, so the denylist cannot be bypassed
//!    through x32 aliases.

use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch, sock_filter,
};

use crate::LaunchError;

/// Syscalls denied unconditionally with `EPERM`.
pub fn denied_syscalls() -> Vec<(&'static str, i64)> {
    let mut v: Vec<(&'static str, i64)> = vec![
        ("io_uring_setup", libc::SYS_io_uring_setup),
        ("io_uring_enter", libc::SYS_io_uring_enter),
        ("io_uring_register", libc::SYS_io_uring_register),
        ("ptrace", libc::SYS_ptrace),
        ("bpf", libc::SYS_bpf),
        ("perf_event_open", libc::SYS_perf_event_open),
        ("keyctl", libc::SYS_keyctl),
        ("add_key", libc::SYS_add_key),
        ("request_key", libc::SYS_request_key),
        ("mount", libc::SYS_mount),
        ("umount2", libc::SYS_umount2),
        ("pivot_root", libc::SYS_pivot_root),
        ("chroot", libc::SYS_chroot),
        ("move_mount", libc::SYS_move_mount),
        ("open_tree", libc::SYS_open_tree),
        ("fsopen", libc::SYS_fsopen),
        ("fsconfig", libc::SYS_fsconfig),
        ("fsmount", libc::SYS_fsmount),
        ("fspick", libc::SYS_fspick),
        ("mount_setattr", libc::SYS_mount_setattr),
        ("setns", libc::SYS_setns),
        ("unshare", libc::SYS_unshare),
        ("userfaultfd", libc::SYS_userfaultfd),
        ("kexec_load", libc::SYS_kexec_load),
        ("kexec_file_load", libc::SYS_kexec_file_load),
        ("init_module", libc::SYS_init_module),
        ("finit_module", libc::SYS_finit_module),
        ("delete_module", libc::SYS_delete_module),
        ("open_by_handle_at", libc::SYS_open_by_handle_at),
        ("name_to_handle_at", libc::SYS_name_to_handle_at),
        ("process_vm_readv", libc::SYS_process_vm_readv),
        ("process_vm_writev", libc::SYS_process_vm_writev),
        ("process_madvise", libc::SYS_process_madvise),
        ("pidfd_getfd", libc::SYS_pidfd_getfd),
        ("kcmp", libc::SYS_kcmp),
        ("fanotify_init", libc::SYS_fanotify_init),
        ("swapon", libc::SYS_swapon),
        ("swapoff", libc::SYS_swapoff),
        ("reboot", libc::SYS_reboot),
        ("syslog", libc::SYS_syslog),
        ("acct", libc::SYS_acct),
        ("settimeofday", libc::SYS_settimeofday),
        ("clock_settime", libc::SYS_clock_settime),
        ("clock_adjtime", libc::SYS_clock_adjtime),
        ("adjtimex", libc::SYS_adjtimex),
        ("quotactl", libc::SYS_quotactl),
        ("quotactl_fd", libc::SYS_quotactl_fd),
        ("vhangup", libc::SYS_vhangup),
    ];
    #[cfg(target_arch = "x86_64")]
    v.extend([
        ("iopl", libc::SYS_iopl),
        ("ioperm", libc::SYS_ioperm),
        ("uselib", libc::SYS_uselib),
        ("_sysctl", libc::SYS__sysctl),
        ("lookup_dcookie", libc::SYS_lookup_dcookie),
        ("nfsservctl", libc::SYS_nfsservctl),
    ]);
    v
}

/// Namespace-creating `clone` flags rejected with `EPERM`.
pub const DENIED_CLONE_FLAGS: &[(&str, u64)] = &[
    ("CLONE_NEWNS", libc::CLONE_NEWNS as u64),
    ("CLONE_NEWCGROUP", libc::CLONE_NEWCGROUP as u64),
    ("CLONE_NEWUTS", libc::CLONE_NEWUTS as u64),
    ("CLONE_NEWIPC", libc::CLONE_NEWIPC as u64),
    ("CLONE_NEWUSER", libc::CLONE_NEWUSER as u64),
    ("CLONE_NEWPID", libc::CLONE_NEWPID as u64),
    ("CLONE_NEWNET", libc::CLONE_NEWNET as u64),
    ("CLONE_NEWTIME", libc::CLONE_NEWTIME as u64),
];

/// Terminal ioctls that inject input or control the console.
pub const DENIED_IOCTLS: &[(&str, u64)] =
    &[("TIOCSTI", libc::TIOCSTI), ("TIOCLINUX", libc::TIOCLINUX)];

/// Socket address families the workload may create. Everything else
/// (AF_VSOCK, AF_PACKET, AF_BLUETOOTH, AF_ALG, ...) gets `EPERM`; some of those
/// are not network-namespace aware.
pub const ALLOWED_SOCKET_FAMILIES: &[(&str, u64)] = &[
    ("AF_UNIX", libc::AF_UNIX as u64),
    ("AF_INET", libc::AF_INET as u64),
    ("AF_INET6", libc::AF_INET6 as u64),
    ("AF_NETLINK", libc::AF_NETLINK as u64),
];

fn target_arch() -> Result<TargetArch, LaunchError> {
    TargetArch::try_from(std::env::consts::ARCH)
        .map_err(|e| LaunchError::Seccomp(format!("unsupported architecture: {e}")))
}

fn cond(
    arg: u8,
    len: SeccompCmpArgLen,
    op: SeccompCmpOp,
    val: u64,
) -> Result<SeccompCondition, LaunchError> {
    SeccompCondition::new(arg, len, op, val).map_err(|e| LaunchError::Seccomp(e.to_string()))
}

fn rule(conds: Vec<SeccompCondition>) -> Result<SeccompRule, LaunchError> {
    SeccompRule::new(conds).map_err(|e| LaunchError::Seccomp(e.to_string()))
}

fn compile(filter: SeccompFilter) -> Result<BpfProgram, LaunchError> {
    BpfProgram::try_from(filter).map_err(|e| LaunchError::Seccomp(e.to_string()))
}

/// Builds the main deny filter.
pub fn main_filter() -> Result<BpfProgram, LaunchError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for (_, nr) in denied_syscalls() {
        rules.insert(nr, Vec::new());
    }
    let clone_rules = DENIED_CLONE_FLAGS
        .iter()
        .map(|&(_, f)| {
            rule(vec![cond(
                0,
                SeccompCmpArgLen::Qword,
                SeccompCmpOp::MaskedEq(f),
                f,
            )?])
        })
        .collect::<Result<Vec<_>, _>>()?;
    rules.insert(libc::SYS_clone, clone_rules);
    let ioctl_rules = DENIED_IOCTLS
        .iter()
        .map(|&(_, req)| {
            rule(vec![cond(
                1,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                req,
            )?])
        })
        .collect::<Result<Vec<_>, _>>()?;
    rules.insert(libc::SYS_ioctl, ioctl_rules);
    let socket_not_allowed = ALLOWED_SOCKET_FAMILIES
        .iter()
        .map(|&(_, af)| cond(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, af))
        .collect::<Result<Vec<_>, _>>()?;
    rules.insert(libc::SYS_socket, vec![rule(socket_not_allowed.clone())?]);
    rules.insert(libc::SYS_socketpair, vec![rule(socket_not_allowed)?]);

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        target_arch()?,
    )
    .map_err(|e| LaunchError::Seccomp(e.to_string()))?;
    compile(filter)
}

/// `clone3` -> ENOSYS so libc falls back to the inspectable `clone`.
pub fn clone3_filter() -> Result<BpfProgram, LaunchError> {
    let mut rules = BTreeMap::new();
    rules.insert(libc::SYS_clone3, Vec::new());
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        target_arch()?,
    )
    .map_err(|e| LaunchError::Seccomp(e.to_string()))?;
    compile(filter)
}

/// x86_64: deny every x32-ABI syscall number (`nr >= 0x4000_0000`).
#[cfg(target_arch = "x86_64")]
pub fn x32_guard_filter() -> Option<BpfProgram> {
    const AUDIT_ARCH_X86_64: u32 = 62 | 0x8000_0000 | 0x4000_0000;
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;
    let ins = |code: u16, jt: u8, jf: u8, k: u32| sock_filter { code, jt, jf, k };
    let ld_abs = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let jeq = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    let jge = (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16;
    let ret = (libc::BPF_RET | libc::BPF_K) as u16;
    Some(vec![
        ins(ld_abs, 0, 0, 4), // seccomp_data.arch
        ins(jeq, 0, 4, AUDIT_ARCH_X86_64),
        ins(ld_abs, 0, 0, 0), // seccomp_data.nr
        ins(jge, 0, 1, X32_SYSCALL_BIT),
        ins(ret, 0, 0, libc::SECCOMP_RET_ERRNO | (libc::ENOSYS as u32)),
        ins(ret, 0, 0, libc::SECCOMP_RET_ALLOW),
        ins(ret, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
    ])
}

#[cfg(not(target_arch = "x86_64"))]
pub fn x32_guard_filter() -> Option<BpfProgram> {
    None
}

/// All programs, in installation order.
pub fn all_filters() -> Result<Vec<BpfProgram>, LaunchError> {
    let mut v = vec![main_filter()?, clone3_filter()?];
    if let Some(x) = x32_guard_filter() {
        v.push(x);
    }
    Ok(v)
}

/// Serialises a program as the raw `struct sock_filter[]` bytes bubblewrap
/// expects on its `--add-seccomp-fd` descriptor.
pub fn to_bytes(prog: &BpfProgram) -> Vec<u8> {
    let mut out = Vec::with_capacity(prog.len() * 8);
    for i in prog {
        out.extend_from_slice(&i.code.to_ne_bytes());
        out.push(i.jt);
        out.push(i.jf);
        out.extend_from_slice(&i.k.to_ne_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_compile() {
        let filters = all_filters().unwrap();
        assert!(filters.len() >= 2);
        for f in &filters {
            assert!(!f.is_empty() && f.len() < 4096);
            assert_eq!(to_bytes(f).len(), f.len() * 8);
        }
    }

    #[test]
    fn mandatory_syscalls_present() {
        let names: Vec<_> = denied_syscalls().into_iter().map(|(n, _)| n).collect();
        for must in [
            "io_uring_setup",
            "io_uring_enter",
            "io_uring_register",
            "ptrace",
            "bpf",
            "perf_event_open",
            "keyctl",
            "add_key",
            "request_key",
            "mount",
            "umount2",
            "pivot_root",
            "move_mount",
            "fsopen",
            "setns",
            "unshare",
            "userfaultfd",
            "kexec_load",
            "kexec_file_load",
            "init_module",
            "finit_module",
            "open_by_handle_at",
            "process_vm_readv",
            "process_vm_writev",
        ] {
            assert!(names.contains(&must), "{must} missing from denylist");
        }
    }
}
