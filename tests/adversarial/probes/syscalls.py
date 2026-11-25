"""Seccomp policy probe (x86_64). Each dangerous syscall is invoked with
arguments chosen so that an *unfiltered* kernel would return something other
than the expected errno (success, EFAULT, EBADF, ...) wherever possible; the
`disc` column marks such discriminating cases. Exit 1 on any breach."""
import ctypes, errno, os, platform, socket, sys, threading

if platform.machine() != "x86_64":
    print("SKIP: syscall numbers in this probe are x86_64-only")
    sys.exit(0)

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
breaches = 0

def breach(m):
    global breaches
    breaches += 1
    print("BREACH:", m)

def sc(nr, *args):
    ctypes.set_errno(0)
    r = libc.syscall(ctypes.c_long(nr), *[ctypes.c_long(a) for a in args])
    return r, ctypes.get_errno()

PID = os.getpid()
EPERM, ENOSYS = errno.EPERM, errno.ENOSYS
# name, nr, args, expected errno, discriminating (unfiltered result differs)
CASES = [
    ("ptrace(TRACEME)", 101, (0, 0, 0, 0), EPERM, True),
    ("io_uring_setup", 425, (1, 0), EPERM, True),
    ("io_uring_enter", 426, (-1, 0, 0, 0, 0, 0), EPERM, True),
    ("io_uring_register", 427, (-1, 0, 0, 0), EPERM, True),
    # Linux AIO (unfiltered: EFAULT / EINVAL).
    ("io_setup", 206, (1, 0), EPERM, True),
    ("io_destroy", 207, (0,), EPERM, True),
    ("io_getevents", 208, (0, 0, 0, 0, 0), EPERM, True),
    ("io_submit", 209, (0, 0, 0), EPERM, True),
    ("io_cancel", 210, (0, 0, 0), EPERM, True),
    ("io_pgetevents", 333, (0, 0, 0, 0, 0, 0), EPERM, True),
    ("bpf", 321, (0, 0, 0), EPERM, False),
    ("perf_event_open", 298, (0, 0, -1, -1, 0), EPERM, True),
    ("keyctl(GET_KEYRING_ID)", 250, (0, -3, 0), EPERM, True),
    ("add_key", 248, (0, 0, 0, 0, 0), EPERM, True),
    ("request_key", 249, (0, 0, 0, 0), EPERM, True),
    ("mount", 165, (0, 0, 0, 0, 0), EPERM, False),
    ("umount2", 166, (0, 0), EPERM, True),
    ("pivot_root", 155, (0, 0), EPERM, True),
    ("chroot", 161, (0,), EPERM, True),
    ("open_tree", 428, (-1, 0, 0), EPERM, True),
    ("move_mount", 429, (-1, 0, -1, 0, 0), EPERM, True),
    ("fsopen", 430, (0, 0), EPERM, True),
    ("fsconfig", 431, (-1, 0, 0, 0, 0), EPERM, True),
    ("fsmount", 432, (-1, 0, 0), EPERM, True),
    ("fspick", 433, (-1, 0, 0), EPERM, True),
    ("mount_setattr", 442, (-1, 0, 0, 0, 0), EPERM, True),
    ("setns", 308, (-1, 0), EPERM, True),
    ("unshare(0)", 272, (0,), EPERM, True),
    ("userfaultfd(USER_MODE_ONLY)", 323, (1,), EPERM, True),
    ("kexec_load", 246, (0, 0, 0, 0), EPERM, False),
    ("kexec_file_load", 320, (-1, -1, 0, 0, 0), EPERM, False),
    ("init_module", 175, (0, 0, 0), EPERM, False),
    ("finit_module", 313, (-1, 0, 0), EPERM, False),
    ("delete_module", 176, (0, 0), EPERM, False),
    ("open_by_handle_at", 304, (-1, 0, 0), EPERM, False),
    ("name_to_handle_at", 303, (-1, 0, 0, 0, 0), EPERM, True),
    ("process_vm_readv(self)", 310, (PID, 0, 0, 0, 0, 0), EPERM, True),
    ("process_vm_writev(self)", 311, (PID, 0, 0, 0, 0, 0), EPERM, True),
    ("pidfd_getfd", 438, (-1, 0, 0), EPERM, True),
    ("kcmp(self)", 312, (PID, PID, 0, 0, 0), EPERM, True),
    ("process_madvise", 440, (-1, 0, 0, 0, 0), EPERM, True),
    ("syslog", 103, (3, 0, 0), EPERM, False),
    # Newer syscalls (unfiltered on older kernels: ENOSYS; here EPERM).
    ("open_tree_attr", 467, (-1, 0, 0, 0, 0), EPERM, True),
    ("file_getattr", 468, (-1, 0, 0, 0, 0), EPERM, True),
    ("file_setattr", 469, (-1, 0, 0, 0, 0), EPERM, True),
    ("listns", 470, (0, 0, 0, 0), EPERM, True),
    # modify_ldt(read, NULL, 0): unfiltered returns 0.
    ("modify_ldt", 154, (0, 0, 0), EPERM, True),
    # Future syscalls beyond the reviewed table: ENOSYS by default.
    ("future syscall 471", 471, (), ENOSYS, False),
    ("future syscall 1000", 1000, (), ENOSYS, False),
    ("clone3", 435, (0, 0), ENOSYS, True),
    ("x32 getpid", 0x40000000 | 39, (), ENOSYS, False),
]
CLONE_NS = {
    "CLONE_NEWNS": 0x00020000, "CLONE_NEWCGROUP": 0x02000000, "CLONE_NEWUTS": 0x04000000,
    "CLONE_NEWIPC": 0x08000000, "CLONE_NEWUSER": 0x10000000, "CLONE_NEWPID": 0x20000000,
    "CLONE_NEWNET": 0x40000000, "CLONE_NEWTIME": 0x00000080,
}

for name, nr, args, want, disc in CASES:
    r, e = sc(nr, *args)
    if r == -1 and e == want:
        print(f"ok: {name:32} -> {errno.errorcode[e]}{' (discriminating)' if disc else ''}")
    else:
        breach(f"{name} returned {r} errno={errno.errorcode.get(e, e)} (wanted {errno.errorcode[want]})")
        if r > 2 and name.startswith(("userfaultfd", "io_uring")):
            os.close(r)

SIGCHLD = 17
for flag, value in CLONE_NS.items():
    r, e = sc(56, value | SIGCHLD, 0, 0, 0, 0)
    if r == 0:
        os._exit(0)  # child of an unexpectedly successful clone
    if r > 0:
        os.waitpid(r, 0)
        breach(f"clone({flag}) succeeded")
    elif e == EPERM:
        print(f"ok: clone({flag:15}) -> EPERM")
    else:
        breach(f"clone({flag}) errno={errno.errorcode.get(e, e)}")

for fam_name, fam in [("AF_VSOCK", 40), ("AF_PACKET", 17), ("AF_ALG", 38), ("AF_BLUETOOTH", 31), ("AF_KEY", 15)]:
    try:
        socket.socket(fam, socket.SOCK_RAW if fam in (17, 15) else socket.SOCK_STREAM if fam != 38 else socket.SOCK_SEQPACKET).close()
        breach(f"socket({fam_name}) allowed")
    except OSError as ex:
        if ex.errno == EPERM:
            print(f"ok: socket({fam_name}) -> EPERM")
        else:
            breach(f"socket({fam_name}) failed with {ex} (wanted EPERM from seccomp)")

import fcntl, termios
try:
    fcntl.ioctl(1, termios.TIOCSTI, b"x")
    breach("TIOCSTI allowed")
except OSError as ex:
    (print("ok: ioctl(TIOCSTI) -> EPERM") if ex.errno == EPERM else breach(f"TIOCSTI {ex}"))

# Sanity: ordinary process and thread creation still work (clone without
# namespace flags; clone3 -> ENOSYS falls back to clone).
pid = os.fork()
if pid == 0:
    os._exit(7)
_, status = os.waitpid(pid, 0)
t = threading.Thread(target=lambda: None); t.start(); t.join()
if os.WEXITSTATUS(status) == 7:
    print("ok: fork and threads work")
else:
    breach("fork sanity failed")
sys.exit(1 if breaches else 0)
