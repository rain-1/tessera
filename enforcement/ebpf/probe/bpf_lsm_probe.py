#!/usr/bin/env python3
"""Unprivileged BPF LSM feature probe for WP7 (docs/bpf-lsm.md).

Python 3 standard library only. Needs no privileges and changes nothing:

    python3 -I enforcement/ebpf/probe/bpf_lsm_probe.py            # JSON report
    python3 -I enforcement/ebpf/probe/bpf_lsm_probe.py --strict   # exit 2 if a prerequisite is missing

What it checks:
  * kernel release, active LSM list (/sys/kernel/security/lsm), lockdown mode;
  * CONFIG_BPF_LSM, CONFIG_DEBUG_INFO_BTF, CONFIG_BPF_SYSCALL, CONFIG_SECURITY_PATH,
    CONFIG_SECURITY_NETWORK, CONFIG_CGROUP_BPF, CONFIG_LSM from /boot/config-$(uname -r);
  * kernel.unprivileged_bpf_disabled, bpffs mount, bpftool presence;
  * whether bpf(2) is refused to this (unprivileged) process (a BPF_MAP_CREATE
    that is expected to fail; nothing is created if it fails);
  * the running kernel's BTF (/sys/kernel/btf/vmlinux): every LSM attach target the
    policy program uses (bpf_lsm_<hook> FUNC + prototype) and every struct field the
    program reads through CO-RE (offset in this build).

It cannot check: that the verifier accepts the program, that attachment works,
or runtime behaviour. Those need CAP_BPF + CAP_PERFMON + CAP_MAC_ADMIN (in
practice root) and are marked "not tested" in docs/bpf-lsm.md.
"""

import ctypes
import json
import os
import platform
import shutil
import struct
import sys

# LSM hooks the policy program attaches to, with the parameter names expected
# from include/linux/lsm_hook_defs.h (v6.12).
HOOKS = {
    "file_open": ["file"],
    "file_permission": ["file", "mask"],
    "mmap_file": ["file", "reqprot", "prot", "flags"],
    "file_mprotect": ["vma", "reqprot", "prot"],
    "file_receive": ["file"],
    "file_ioctl": ["file", "cmd", "arg"],
    "file_ioctl_compat": ["file", "cmd", "arg"],
    "inode_getattr": ["path"],
    "path_notify": ["path", "mask", "obj_type"],
    "inode_getxattr": ["dentry", "name"],
    "inode_listxattr": ["dentry"],
    "inode_readlink": ["dentry"],
    # Not used by the read-subtree program, recorded for the rejected
    # network class (docs/bpf-lsm.md section 3).
    "socket_connect": ["sock", "address", "addrlen"],
    "socket_sendmsg": ["sock", "msg", "size"],
}

# (struct, member) pairs read via CO-RE in bpf/tessera_direct_read.bpf.c.
FIELDS = [
    ("file", "f_path"),
    ("file", "f_inode"),
    ("file", "f_mode"),
    ("path", "mnt"),
    ("path", "dentry"),
    ("mount", "mnt"),
    ("mount", "mnt_id_unique"),
    ("vfsmount", "mnt_sb"),
    ("dentry", "d_sb"),
    ("inode", "i_sb"),
    ("super_block", "s_dev"),
    ("vm_area_struct", "vm_file"),
]

CONFIG_KEYS = [
    "CONFIG_BPF_SYSCALL", "CONFIG_BPF_LSM", "CONFIG_DEBUG_INFO_BTF",
    "CONFIG_BPF_JIT", "CONFIG_BPF_JIT_ALWAYS_ON", "CONFIG_BPF_UNPRIV_DEFAULT_OFF",
    "CONFIG_CGROUP_BPF", "CONFIG_SECURITY", "CONFIG_SECURITY_PATH",
    "CONFIG_SECURITY_NETWORK", "CONFIG_SECURITY_LANDLOCK", "CONFIG_IO_URING",
    "CONFIG_LSM",
]

BTF_KIND = {1: "INT", 2: "PTR", 3: "ARRAY", 4: "STRUCT", 5: "UNION", 6: "ENUM",
            7: "FWD", 8: "TYPEDEF", 9: "VOLATILE", 10: "CONST", 11: "RESTRICT",
            12: "FUNC", 13: "FUNC_PROTO", 14: "VAR", 15: "DATASEC", 16: "FLOAT",
            17: "DECL_TAG", 18: "TYPE_TAG", 19: "ENUM64"}


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError as e:
        return {"error": f"{type(e).__name__}: {e.strerror}"}


class Btf:
    """Minimal BTF reader (types + strings), enough to look up FUNCs and members."""

    def __init__(self, data):
        magic, ver, _flags, hdr_len, type_off, type_len, str_off, str_len = \
            struct.unpack_from("<HBBIIIII", data, 0)
        if magic != 0xEB9F:
            raise ValueError("bad BTF magic")
        self.version = ver
        base = hdr_len
        self.strs = data[base + str_off: base + str_off + str_len]
        tdata = data[base + type_off: base + type_off + type_len]
        self.types = [None]  # type id 0 is void
        off = 0
        while off < len(tdata):
            name_off, info, size_type = struct.unpack_from("<III", tdata, off)
            off += 12
            kind = (info >> 24) & 0x1F
            vlen = info & 0xFFFF
            kflag = info >> 31
            t = {"name": self.s(name_off), "kind": BTF_KIND.get(kind, kind),
                 "st": size_type}
            if kind == 1 or kind == 14 or kind == 17:
                off += 4
            elif kind == 3:
                off += 12
            elif kind in (4, 5):
                mem = []
                for _ in range(vlen):
                    mn, mt, mo = struct.unpack_from("<III", tdata, off)
                    off += 12
                    bit = (mo & 0xFFFFFF) if kflag else mo
                    mem.append((self.s(mn), mt, bit))
                t["members"] = mem
            elif kind == 6:
                off += 8 * vlen
            elif kind == 13:
                ps = []
                for _ in range(vlen):
                    pn, pt = struct.unpack_from("<II", tdata, off)
                    off += 8
                    ps.append((self.s(pn), pt))
                t["params"] = ps
            elif kind in (15, 19):
                off += 12 * vlen
            self.types.append(t)
        self.by_name = {}
        for i, t in enumerate(self.types[1:], 1):
            self.by_name.setdefault((t["kind"], t["name"]), i)

    def s(self, off):
        end = self.strs.index(b"\0", off)
        return self.strs[off:end].decode()

    def type_str(self, tid, depth=0):
        if tid == 0:
            return "void"
        t = self.types[tid]
        k = t["kind"]
        if k == "PTR":
            return self.type_str(t["st"], depth + 1) + " *"
        if k in ("CONST", "VOLATILE", "TYPEDEF", "RESTRICT", "TYPE_TAG") and depth < 8:
            if k == "TYPEDEF":
                return t["name"]
            return self.type_str(t["st"], depth + 1)
        if k in ("STRUCT", "UNION"):
            return f"{k.lower()} {t['name']}"
        return t["name"] or k

    def func_proto(self, name):
        tid = self.by_name.get(("FUNC", name))
        if tid is None:
            return None
        proto = self.types[self.types[tid]["st"]]
        return {"ret": self.type_str(proto["st"]),
                "params": [(n, self.type_str(pt)) for n, pt in proto["params"]]}

    def member(self, sname, mname):
        tid = self.by_name.get(("STRUCT", sname))
        if tid is None:
            return None
        for n, mt, bit in self.types[tid]["members"]:
            if n == mname:
                return {"type": self.type_str(mt), "byte_offset": bit // 8}
        return {"missing_member": True}


def probe_bpf_syscall():
    """Try BPF_MAP_CREATE (array, 1 x 4-byte). Expected to fail unprivileged."""
    nr = {"x86_64": 321, "aarch64": 280}.get(platform.machine())
    if nr is None:
        return {"tested": False, "reason": "unknown syscall number for arch"}
    libc = ctypes.CDLL(None, use_errno=True)
    attr = ctypes.create_string_buffer(struct.pack("<IIIII", 2, 4, 4, 1, 0) + b"\0" * 108)
    fd = libc.syscall(ctypes.c_long(nr), ctypes.c_int(0), attr, ctypes.c_uint(len(attr)))
    if fd >= 0:
        os.close(fd)
        return {"tested": True, "unprivileged_map_create": "succeeded (unexpected)"}
    err = ctypes.get_errno()
    return {"tested": True, "unprivileged_map_create": "refused",
            "errno": os.strerror(err)}


def main(argv):
    strict = "--strict" in argv
    rel = platform.release()
    rep = {"kernel_release": rel, "kernel_version": read("/proc/version"),
           "arch": platform.machine(), "euid": os.geteuid()}
    lsm = read("/sys/kernel/security/lsm")
    rep["active_lsms"] = lsm.split(",") if isinstance(lsm, str) else lsm
    rep["lockdown"] = read("/sys/kernel/security/lockdown")
    rep["kernel_cmdline_lsm"] = [a for a in read("/proc/cmdline").split()
                                 if a.startswith(("lsm=", "security="))] \
        if isinstance(read("/proc/cmdline"), str) else None
    cfg = {}
    cpath = f"/boot/config-{rel}"
    try:
        with open(cpath, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                for k in CONFIG_KEYS:
                    if line.startswith(k + "="):
                        cfg[k] = line.split("=", 1)[1].strip('"')
                    elif line == f"# {k} is not set":
                        cfg[k] = "n"
        rep["config_source"] = cpath
    except OSError as e:
        rep["config_source"] = f"unreadable: {e.strerror}"
    rep["config"] = cfg
    rep["sysctl"] = {
        "kernel.unprivileged_bpf_disabled": read("/proc/sys/kernel/unprivileged_bpf_disabled"),
        "net.core.bpf_jit_enable": read("/proc/sys/net/core/bpf_jit_enable"),
        "net.core.bpf_jit_harden": read("/proc/sys/net/core/bpf_jit_harden"),
    }
    bpffs = [l for l in read("/proc/mounts").splitlines() if " bpf " in l] \
        if isinstance(read("/proc/mounts"), str) else []
    rep["bpffs_mounts"] = bpffs
    rep["bpftool"] = shutil.which("bpftool") or next(
        (p for p in ("/usr/sbin/bpftool", "/sbin/bpftool") if os.path.exists(p)), None)
    rep["clang"] = shutil.which("clang")
    rep["bpf_syscall"] = probe_bpf_syscall()

    btf_path = "/sys/kernel/btf/vmlinux"
    hooks, fields = {}, {}
    try:
        with open(btf_path, "rb") as f:
            btf = Btf(f.read())
        rep["btf_vmlinux"] = {"present": True, "types": len(btf.types) - 1}
        for h, want in HOOKS.items():
            p = btf.func_proto(f"bpf_lsm_{h}")
            if p is None:
                hooks[h] = {"attach_target": False}
                continue
            names = [n for n, _ in p["params"]]
            hooks[h] = {"attach_target": True, "ret": p["ret"],
                        "params": [f"{t} {n}" for n, t in p["params"]],
                        "params_match_6_12": names == want}
        for s, m in FIELDS:
            r = btf.member(s, m)
            fields[f"{s}.{m}"] = r if r is not None else {"missing_struct": True}
    except (OSError, ValueError) as e:
        rep["btf_vmlinux"] = {"present": False, "error": str(e)}
    rep["lsm_attach_targets"] = hooks
    rep["core_fields"] = fields

    missing = []
    if "bpf" not in (rep["active_lsms"] or []):
        missing.append("bpf not in active LSM list")
    if cfg.get("CONFIG_BPF_LSM") != "y":
        missing.append("CONFIG_BPF_LSM != y (or config unreadable)")
    if not rep["btf_vmlinux"].get("present"):
        missing.append("no /sys/kernel/btf/vmlinux")
    for h in ("file_open", "file_permission", "mmap_file", "file_receive",
              "inode_getattr"):
        if not hooks.get(h, {}).get("attach_target"):
            missing.append(f"no attach target bpf_lsm_{h}")
    for k, v in fields.items():
        if "byte_offset" not in v:
            missing.append(f"CO-RE field {k} missing")
    rep["prerequisites_missing"] = missing
    rep["not_tested_here"] = [
        "verifier acceptance of the policy program",
        "attach (needs CAP_BPF+CAP_PERFMON+CAP_MAC_ADMIN)",
        "runtime enforcement and overhead",
    ]
    json.dump(rep, sys.stdout, indent=2, sort_keys=True)
    print()
    return 2 if (strict and missing) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
