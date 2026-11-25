// SPDX-License-Identifier: GPL-2.0-only
/*
 * Tessera BPF LSM policy: direct read-only grants on registered subtrees.
 *
 * STATUS: research skeleton (WP7). Compiles with `clang -target bpf`
 * (see enforcement/ebpf/bpf/build.sh). NOT loaded, NOT verifier-checked,
 * NOT tested: the development host has no root. Do not ship.
 *
 * Model (docs/bpf-lsm.md):
 *   * A grantable subtree lives on a dedicated filesystem ("governed dev")
 *     and is bind-mounted read-only into exactly one sandbox. The manager
 *     records that bind mount's mnt_id_unique in `governed_mounts` before
 *     the workload starts.
 *   * Every access through a governed mount is DENIED unless the current
 *     task's cgroup is the mount's owner, the owner's lease has not expired,
 *     and a grant for (cgroup, mount) is valid at the owner's active
 *     generation. Unknown mounts and unmanaged objects get 0 ("no opinion"):
 *     this program only ever adds denials, never overrides another LSM.
 *   * Writes, exec, ioctl, inotify, xattr and readlink are always denied on
 *     governed objects. mmap is denied unless the grant is explicitly
 *     non-revocable (TESSERA_GRANT_ALLOW_MMAP).
 *   * No counters. Finite budgets stay in the broker (spec section 10.3).
 *
 * Self-contained on purpose: no vmlinux.h and no libbpf headers (neither
 * bpftool nor libbpf-dev is installed on the host). Kernel types are
 * declared minimally with preserve_access_index, so libbpf CO-RE relocates
 * every field access against the running kernel's BTF at load time.
 * Fields used are checked against this kernel's BTF by probe/bpf_lsm_probe.py.
 */

typedef unsigned char __u8;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef int __s32;
typedef __u32 dev_t;
typedef __u32 fmode_t;

#include "tessera_direct_read.h"

#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#define EACCES 13
#define EPERM 1

/* include/linux/fs.h (v6.12) */
#define FMODE_READ 0x1u
#define FMODE_WRITE 0x2u
#define FMODE_EXEC 0x20u
#define MAY_READ 0x4
/* include/uapi/asm-generic/mman-common.h */
#define PROT_WRITE 0x2ul
#define PROT_EXEC 0x4ul

enum { BPF_MAP_TYPE_HASH = 1 };
enum { BPF_FIELD_BYTE_OFFSET = 0 }; /* clang __builtin_preserve_field_info kind */
enum { BPF_F_NO_PREALLOC = 1 };

/* Helper IDs from include/uapi/linux/bpf.h (stable ABI). */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *src) = (void *)113;
static __u64 (*bpf_ktime_get_boot_ns)(void) = (void *)125;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)80;

/* Minimal CO-RE views of kernel types (only the fields we read). */
struct super_block {
	dev_t s_dev;
} __attribute__((preserve_access_index));

struct inode {
	struct super_block *i_sb;
} __attribute__((preserve_access_index));

struct dentry {
	struct super_block *d_sb;
} __attribute__((preserve_access_index));

struct vfsmount {
	struct super_block *mnt_sb;
} __attribute__((preserve_access_index));

struct mount {
	struct vfsmount mnt;
	__u64 mnt_id_unique; /* fs/mount.h, v6.8+: "mount ID unique until reboot" */
} __attribute__((preserve_access_index));

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
} __attribute__((preserve_access_index));

struct file {
	struct path f_path;
	struct inode *f_inode;
	fmode_t f_mode;
} __attribute__((preserve_access_index));

struct vm_area_struct {
	struct file *vm_file;
} __attribute__((preserve_access_index));

/* Maps. Pinned by the manager under /sys/fs/bpf/tessera/ (bpffs mode 0700,
 * root-owned; never mounted in a sandbox; bpf(2) denied by seccomp). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, TESSERA_MAX_SUBJECTS);
	__type(key, __u64);
	__type(value, struct tessera_subject);
} subjects SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, TESSERA_MAX_GOVERNED_MOUNTS);
	__type(key, __u64);
	__type(value, struct tessera_governed_mount);
} governed_mounts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, TESSERA_MAX_GOVERNED_DEVS);
	__type(key, __u32);
	__type(value, __u8);
} governed_devs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, TESSERA_MAX_GRANTS);
	__type(key, struct tessera_grant_key);
	__type(value, struct tessera_grant);
} grants SEC(".maps");

enum verdict_kind { GOV_NONE = 0, GOV_DENY = 1, GOV_GRANTED = 2 };

struct verdict {
	enum verdict_kind kind;
	__u32 grant_flags;
};

static __always_inline __u64 mnt_id_of(struct vfsmount *vmnt)
{
	/* container_of(vmnt, struct mount, mnt): the offset is CO-RE relocated.
	 * Pointer arithmetic on a BTF pointer is not allowed for direct loads, so
	 * read through bpf_probe_read_kernel (allowed under lockdown=integrity;
	 * only lockdown=confidentiality removes it, see kernel/trace/bpf_trace.c). */
	__u64 id = 0;
	struct mount *m = (struct mount *)((char *)vmnt -
		__builtin_preserve_field_info(((struct mount *)0)->mnt,
					      BPF_FIELD_BYTE_OFFSET));
	if (bpf_probe_read_kernel(&id, sizeof(id), &m->mnt_id_unique))
		return 0;
	return id;
}

/* Decide for an access through vfsmount `vmnt`. */
static __always_inline struct verdict decide(struct vfsmount *vmnt)
{
	struct verdict v = { GOV_NONE, 0 };
	__u64 mnt_id, cg, gen, now;
	struct tessera_governed_mount *gm;
	struct tessera_subject *s;
	struct tessera_grant *g;
	struct tessera_grant_key k;

	if (!vmnt)
		return v;
	mnt_id = mnt_id_of(vmnt);
	if (!mnt_id)
		return v; /* unreadable: not a governed mount we registered */
	gm = bpf_map_lookup_elem(&governed_mounts, &mnt_id);
	if (!gm)
		return v;

	v.kind = GOV_DENY; /* governed from here on: default deny */
	cg = bpf_get_current_cgroup_id();
	if (gm->owner_cgroup_id != cg)
		return v;
	s = bpf_map_lookup_elem(&subjects, &cg);
	if (!s)
		return v;
	now = bpf_ktime_get_boot_ns();
	if (now >= s->lease_expiry_ns)
		return v; /* manager/broker stopped renewing: fail closed */
	gen = *(volatile __u64 *)&s->active_gen;
	k.cgroup_id = cg;
	k.mnt_id = mnt_id;
	g = bpf_map_lookup_elem(&grants, &k);
	if (!g)
		return v;
	if (!(g->gen_from <= gen && gen < g->gen_until))
		return v; /* staged-but-inactive, or retired */
	v.kind = GOV_GRANTED;
	v.grant_flags = g->flags;
	return v;
}

static __always_inline int governed_dev(struct super_block *sb)
{
	dev_t dev;

	if (!sb)
		return 0;
	dev = sb->s_dev;
	return bpf_map_lookup_elem(&governed_devs, &dev) != 0;
}

/* LSM program context: ctx[0..n-1] are the hook arguments, ctx[n] is the
 * return value of the previous BPF LSM program on this hook. A non-zero
 * previous value is always preserved. */

SEC("lsm/file_open")
int tessera_file_open(__u64 *ctx)
{
	struct file *file = (struct file *)ctx[0];
	int prev = (int)ctx[1];
	struct verdict v;

	if (prev)
		return prev;
	v = decide(file->f_path.mnt);
	if (v.kind == GOV_NONE)
		return 0;
	if (v.kind != GOV_GRANTED)
		return -EACCES;
	if (file->f_mode & (FMODE_WRITE | FMODE_EXEC))
		return -EACCES;
	return 0;
}

SEC("lsm/file_permission")
int tessera_file_permission(__u64 *ctx)
{
	struct file *file = (struct file *)ctx[0];
	int mask = (int)ctx[1];
	int prev = (int)ctx[2];
	struct verdict v;

	if (prev)
		return prev;
	/* Re-checked on every read/readv/pread/splice/sendfile/copy_file_range/
	 * getdents (rw_verify_area, iterate_dir): this is what makes revocation
	 * apply to descriptors opened before the revocation. */
	v = decide(file->f_path.mnt);
	if (v.kind == GOV_NONE)
		return 0;
	if (v.kind != GOV_GRANTED || mask != MAY_READ)
		return -EACCES;
	return 0;
}

SEC("lsm/file_receive")
int tessera_file_receive(__u64 *ctx)
{
	struct file *file = (struct file *)ctx[0];
	int prev = (int)ctx[1];
	struct verdict v;

	if (prev)
		return prev;
	v = decide(file->f_path.mnt);
	if (v.kind == GOV_NONE)
		return 0;
	if (v.kind != GOV_GRANTED || (file->f_mode & FMODE_WRITE))
		return -EACCES;
	return 0;
}

SEC("lsm/mmap_file")
int tessera_mmap_file(__u64 *ctx)
{
	struct file *file = (struct file *)ctx[0];
	unsigned long prot = (unsigned long)ctx[2];
	int prev = (int)ctx[4];
	struct verdict v;

	if (prev)
		return prev;
	if (!file)
		return 0; /* anonymous mapping */
	v = decide(file->f_path.mnt);
	if (v.kind == GOV_NONE)
		return 0;
	if (v.kind != GOV_GRANTED || !(v.grant_flags & TESSERA_GRANT_ALLOW_MMAP))
		return -EACCES;
	if (prot & (PROT_WRITE | PROT_EXEC))
		return -EACCES;
	return 0;
}

SEC("lsm/file_mprotect")
int tessera_file_mprotect(__u64 *ctx)
{
	struct vm_area_struct *vma = (struct vm_area_struct *)ctx[0];
	unsigned long prot = (unsigned long)ctx[2];
	int prev = (int)ctx[3];
	struct file *file;
	struct verdict v;

	if (prev)
		return prev;
	file = vma->vm_file;
	if (!file)
		return 0;
	v = decide(file->f_path.mnt);
	if (v.kind == GOV_NONE)
		return 0;
	if (v.kind != GOV_GRANTED || (prot & (PROT_WRITE | PROT_EXEC)))
		return -EACCES;
	return 0;
}

static __always_inline int deny_if_governed_file(struct file *file)
{
	return decide(file->f_path.mnt).kind == GOV_NONE ? 0 : -EACCES;
}

SEC("lsm/file_ioctl")
int tessera_file_ioctl(__u64 *ctx)
{
	int prev = (int)ctx[3];

	if (prev)
		return prev;
	return deny_if_governed_file((struct file *)ctx[0]);
}

SEC("lsm/file_ioctl_compat")
int tessera_file_ioctl_compat(__u64 *ctx)
{
	int prev = (int)ctx[3];

	if (prev)
		return prev;
	return deny_if_governed_file((struct file *)ctx[0]);
}

SEC("lsm/inode_getattr")
int tessera_inode_getattr(__u64 *ctx)
{
	struct path *path = (struct path *)ctx[0];
	int prev = (int)ctx[1];
	struct verdict v;

	if (prev)
		return prev;
	v = decide(path->mnt);
	if (v.kind == GOV_NONE || v.kind == GOV_GRANTED)
		return 0;
	return -EACCES;
}

SEC("lsm/path_notify")
int tessera_path_notify(__u64 *ctx)
{
	struct path *path = (struct path *)ctx[0];
	int prev = (int)ctx[3];

	if (prev)
		return prev;
	return decide(path->mnt).kind == GOV_NONE ? 0 : -EACCES;
}

/* Hooks that only see a dentry: no vfsmount, so decide by superblock. A
 * managed subject may not read xattrs or symlink bodies on a governed
 * filesystem at all. (Requires the dedicated-filesystem rule.) */
static __always_inline int deny_dentry_on_governed_dev(struct dentry *d)
{
	__u64 cg;

	if (!governed_dev(d->d_sb))
		return 0;
	cg = bpf_get_current_cgroup_id();
	if (!bpf_map_lookup_elem(&subjects, &cg))
		return 0;
	return -EACCES;
}

SEC("lsm/inode_getxattr")
int tessera_inode_getxattr(__u64 *ctx)
{
	int prev = (int)ctx[2];

	if (prev)
		return prev;
	return deny_dentry_on_governed_dev((struct dentry *)ctx[0]);
}

SEC("lsm/inode_listxattr")
int tessera_inode_listxattr(__u64 *ctx)
{
	int prev = (int)ctx[1];

	if (prev)
		return prev;
	return deny_dentry_on_governed_dev((struct dentry *)ctx[0]);
}

SEC("lsm/inode_readlink")
int tessera_inode_readlink(__u64 *ctx)
{
	int prev = (int)ctx[1];

	if (prev)
		return prev;
	return deny_dentry_on_governed_dev((struct dentry *)ctx[0]);
}

char LICENSE[] SEC("license") = "GPL";
