//! Rust mirrors of the BPF map layouts in `../bpf/tessera_direct_read.h`.
//!
//! These are the values the manager would write through libbpf-rs. Layout
//! equality with the C header is asserted by size/offset tests below; the
//! kernel side is not loaded anywhere (see docs/bpf-lsm.md).

/// `gen_until` for a grant that has not been scheduled for removal.
pub const GEN_OPEN_END: u64 = u64::MAX;
/// Grant flag: read-only `mmap` allowed. Such a grant is non-revocable for
/// its lease, because existing mappings survive map updates.
pub const GRANT_ALLOW_MMAP: u32 = 0x1;

pub const MAX_SUBJECTS: usize = 1024;
pub const MAX_GRANTS: usize = 8192;
pub const MAX_GOVERNED_MOUNTS: usize = 8192;

/// cgroup v2 id of a sandbox leaf (`bpf_get_current_cgroup_id()`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CgroupId(pub u64);

/// `mnt_id_unique` of a bind mount inside one sandbox (statx `STATX_MNT_ID_UNIQUE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MountId(pub u64);

/// `struct tessera_subject`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Subject {
    pub active_gen: u64,
    pub lease_expiry_ns: u64,
    pub launch_id: u64,
}

/// `struct tessera_governed_mount`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GovernedMount {
    pub owner_cgroup_id: u64,
}

/// `struct tessera_grant_key`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrantKey {
    pub cgroup_id: u64,
    pub mnt_id: u64,
}

/// `struct tessera_grant`. Valid iff `gen_from <= active_gen < gen_until`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    pub gen_from: u64,
    pub gen_until: u64,
    pub flags: u32,
    pub _pad: u32,
}

impl Grant {
    pub fn valid_at(&self, generation: u64) -> bool {
        self.gen_from <= generation && generation < self.gen_until
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    #[test]
    fn layouts_match_c_header() {
        assert_eq!(size_of::<Subject>(), 24);
        assert_eq!(offset_of!(Subject, lease_expiry_ns), 8);
        assert_eq!(size_of::<GovernedMount>(), 8);
        assert_eq!(size_of::<GrantKey>(), 16);
        assert_eq!(offset_of!(GrantKey, mnt_id), 8);
        assert_eq!(size_of::<Grant>(), 24);
        assert_eq!(offset_of!(Grant, flags), 16);
    }

    #[test]
    fn validity_window() {
        let g = Grant {
            gen_from: 3,
            gen_until: 5,
            flags: 0,
            _pad: 0,
        };
        assert!(!g.valid_at(2));
        assert!(g.valid_at(3));
        assert!(g.valid_at(4));
        assert!(!g.valid_at(5));
    }
}
