/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Map layouts shared by the BPF policy program (tessera_direct_read.bpf.c)
 * and the manager (manager/src/maps.rs mirrors these with #[repr(C)]).
 *
 * Direct capability class: unlimited-use READ-ONLY access to a registered
 * directory subtree, exposed to one sandbox as its own bind mount.
 * See docs/bpf-lsm.md and docs/adr/0023-bpf-lsm-direct-grants.md.
 *
 * STATUS: written and compiled with clang -target bpf; NOT loaded, NOT
 * verifier-checked, NOT tested on a kernel (no root on the development host).
 */
#ifndef TESSERA_DIRECT_READ_H
#define TESSERA_DIRECT_READ_H

#define TESSERA_GEN_OPEN_END 0xffffffffffffffffULL

/* Grant flags. */
#define TESSERA_GRANT_ALLOW_MMAP 0x1u /* read-only mmap allowed: grant is NON-REVOCABLE
                                       * for its lease (existing mappings survive). */

/* Capacity limits. The manager refuses a transition that would exceed them
 * before staging anything (no partial installs because a map is full). */
#define TESSERA_MAX_SUBJECTS 1024
#define TESSERA_MAX_GRANTS 8192
#define TESSERA_MAX_GOVERNED_MOUNTS 8192
#define TESSERA_MAX_GOVERNED_DEVS 16

/* subjects: key = cgroup v2 id (u64) of the sandbox leaf. Presence = managed. */
struct tessera_subject {
	__u64 active_gen;      /* installed-and-activated policy generation */
	__u64 lease_expiry_ns; /* CLOCK_BOOTTIME ns; grants are inert at or after it */
	__u64 launch_id;       /* manager-side launch generation (not used by BPF) */
};

/* governed_mounts: key = mnt_id_unique (u64) of a bind mount inside a sandbox's
 * mount namespace. Every access through such a mount needs a grant. */
struct tessera_governed_mount {
	__u64 owner_cgroup_id; /* the only subject that may ever use this mount */
};

/* grants: key = (owner cgroup id, mnt_id_unique). */
struct tessera_grant_key {
	__u64 cgroup_id;
	__u64 mnt_id;
};

/* Valid iff gen_from <= subject.active_gen < gen_until. */
struct tessera_grant {
	__u64 gen_from;
	__u64 gen_until;
	__u32 flags;
	__u32 _pad;
};

#endif
