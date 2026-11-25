//! The seam between the manager and the kernel, plus an in-memory fake.
//!
//! A real backend would implement [`KernelPolicy`] with libbpf-rs on pinned
//! maps under `/sys/fs/bpf/tessera/` and with `cgroup.freeze` for the
//! barrier. That backend does not exist (no root on the development host).
//!
//! [`FakeKernel`] keeps the maps in memory, survives a simulated manager
//! crash (as pinned maps do), and evaluates accesses with
//! [`FakeKernel::read_allowed`], a line-by-line mirror of `decide()` in
//! `bpf/tessera_direct_read.bpf.c`. Tests use it to check the protocol at
//! every intermediate kernel state.

use crate::maps::{CgroupId, GovernedMount, Grant, GrantKey, MountId, Subject};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelError {
    /// The manager process died; nothing more it does reaches the kernel.
    ManagerCrashed,
    /// A map is full (`-E2BIG`/`-ENOMEM` from `bpf_map_update_elem`).
    MapFull(&'static str),
    /// `cgroup.freeze` did not reach `frozen 1` in time.
    FreezeTimeout,
    Other(String),
}

/// Operations the manager needs. Each call is one syscall-sized step; there
/// is no transaction across calls, which is the point of the protocol.
pub trait KernelPolicy {
    fn now_boot_ns(&self) -> u64;
    fn put_subject(&mut self, cg: CgroupId, s: Subject) -> Result<(), KernelError>;
    fn get_subject(&self, cg: CgroupId) -> Result<Option<Subject>, KernelError>;
    fn delete_subject(&mut self, cg: CgroupId) -> Result<(), KernelError>;
    fn list_subjects(&self) -> Result<Vec<CgroupId>, KernelError>;
    fn put_governed_mount(&mut self, m: MountId, g: GovernedMount) -> Result<(), KernelError>;
    fn delete_governed_mount(&mut self, m: MountId) -> Result<(), KernelError>;
    fn put_grant(&mut self, k: GrantKey, g: Grant) -> Result<(), KernelError>;
    fn delete_grant(&mut self, k: GrantKey) -> Result<(), KernelError>;
    fn list_grants(&self, cg: CgroupId) -> Result<Vec<(GrantKey, Grant)>, KernelError>;
    /// Write `1` to `cgroup.freeze` and wait for `frozen 1` in `cgroup.events`.
    fn freeze(&mut self, cg: CgroupId) -> Result<(), KernelError>;
    fn thaw(&mut self, cg: CgroupId) -> Result<(), KernelError>;
}

/// In-memory kernel. State persists across a simulated manager crash.
#[derive(Debug, Clone, Default)]
pub struct FakeKernel {
    pub now: u64,
    pub subjects: BTreeMap<CgroupId, Subject>,
    pub governed: BTreeMap<MountId, GovernedMount>,
    pub grants: BTreeMap<GrantKey, Grant>,
    pub frozen: BTreeSet<CgroupId>,
    pub max_grants: usize,
    /// Number of mutating ops performed so far.
    pub ops: usize,
    /// If set, the manager "crashes" when it attempts op number `crash_at`.
    pub crash_at: Option<usize>,
    pub crashed: bool,
    /// If set, `freeze` times out (tasks stuck in uninterruptible sleep).
    pub fail_freeze: bool,
    /// After every successful mutating op: what each subject could read at
    /// that instant (only if it could run, i.e. was not frozen). Tests check
    /// invariants over every intermediate kernel state with this.
    pub history: Vec<Snapshot>,
}

/// Kernel-observable authority at one instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub op: usize,
    /// For each runnable subject: (active generation, mounts it can read now).
    pub readable: BTreeMap<CgroupId, (u64, BTreeSet<MountId>)>,
}

impl FakeKernel {
    pub fn new() -> Self {
        FakeKernel {
            max_grants: crate::maps::MAX_GRANTS,
            ..Default::default()
        }
    }

    /// Restart the manager: kernel state is kept, crash injection cleared.
    pub fn restart_manager(&mut self) {
        self.crashed = false;
        self.crash_at = None;
    }

    fn step(&mut self) -> Result<(), KernelError> {
        if self.crashed {
            return Err(KernelError::ManagerCrashed);
        }
        if self.crash_at == Some(self.ops) {
            self.crashed = true;
            return Err(KernelError::ManagerCrashed);
        }
        self.ops += 1;
        Ok(())
    }

    fn observe(&mut self) {
        let snap = self.snapshot();
        self.history.push(snap);
    }

    pub fn snapshot(&self) -> Snapshot {
        let mut readable = BTreeMap::new();
        for (cg, s) in &self.subjects {
            if !self.can_run(*cg) {
                continue;
            }
            let ms = self
                .governed
                .keys()
                .filter(|m| self.read_allowed(*cg, **m) == Some(true))
                .copied()
                .collect();
            readable.insert(*cg, (s.active_gen, ms));
        }
        Snapshot {
            op: self.ops,
            readable,
        }
    }

    /// Mirror of `decide()` + `tessera_file_open` (read-only open) in the BPF
    /// program, for a task in cgroup `cg` opening through mount `m`.
    /// `None` = mount not governed (the program has no opinion).
    pub fn read_allowed(&self, cg: CgroupId, m: MountId) -> Option<bool> {
        let gm = self.governed.get(&m)?;
        if gm.owner_cgroup_id != cg.0 {
            return Some(false);
        }
        let Some(s) = self.subjects.get(&cg) else {
            return Some(false);
        };
        if self.now >= s.lease_expiry_ns {
            return Some(false);
        }
        let key = GrantKey {
            cgroup_id: cg.0,
            mnt_id: m.0,
        };
        let Some(g) = self.grants.get(&key) else {
            return Some(false);
        };
        Some(g.valid_at(s.active_gen))
    }

    /// Frozen tasks make no syscalls, so they cannot hit a hook.
    pub fn can_run(&self, cg: CgroupId) -> bool {
        !self.frozen.contains(&cg)
    }
}

impl KernelPolicy for FakeKernel {
    fn now_boot_ns(&self) -> u64 {
        self.now
    }
    fn put_subject(&mut self, cg: CgroupId, s: Subject) -> Result<(), KernelError> {
        self.step()?;
        if !self.subjects.contains_key(&cg) && self.subjects.len() >= crate::maps::MAX_SUBJECTS {
            return Err(KernelError::MapFull("subjects"));
        }
        self.subjects.insert(cg, s);
        self.observe();
        Ok(())
    }
    fn get_subject(&self, cg: CgroupId) -> Result<Option<Subject>, KernelError> {
        if self.crashed {
            return Err(KernelError::ManagerCrashed);
        }
        Ok(self.subjects.get(&cg).copied())
    }
    fn delete_subject(&mut self, cg: CgroupId) -> Result<(), KernelError> {
        self.step()?;
        self.subjects.remove(&cg);
        self.observe();
        Ok(())
    }
    fn list_subjects(&self) -> Result<Vec<CgroupId>, KernelError> {
        if self.crashed {
            return Err(KernelError::ManagerCrashed);
        }
        Ok(self.subjects.keys().copied().collect())
    }
    fn put_governed_mount(&mut self, m: MountId, g: GovernedMount) -> Result<(), KernelError> {
        self.step()?;
        self.governed.insert(m, g);
        self.observe();
        Ok(())
    }
    fn delete_governed_mount(&mut self, m: MountId) -> Result<(), KernelError> {
        self.step()?;
        self.governed.remove(&m);
        self.observe();
        Ok(())
    }
    fn put_grant(&mut self, k: GrantKey, g: Grant) -> Result<(), KernelError> {
        self.step()?;
        if !self.grants.contains_key(&k) && self.grants.len() >= self.max_grants {
            return Err(KernelError::MapFull("grants"));
        }
        self.grants.insert(k, g);
        self.observe();
        Ok(())
    }
    fn delete_grant(&mut self, k: GrantKey) -> Result<(), KernelError> {
        self.step()?;
        self.grants.remove(&k);
        self.observe();
        Ok(())
    }
    fn list_grants(&self, cg: CgroupId) -> Result<Vec<(GrantKey, Grant)>, KernelError> {
        if self.crashed {
            return Err(KernelError::ManagerCrashed);
        }
        Ok(self
            .grants
            .iter()
            .filter(|(k, _)| k.cgroup_id == cg.0)
            .map(|(k, g)| (*k, *g))
            .collect())
    }
    fn freeze(&mut self, cg: CgroupId) -> Result<(), KernelError> {
        self.step()?;
        if self.fail_freeze {
            return Err(KernelError::FreezeTimeout);
        }
        self.frozen.insert(cg);
        self.observe();
        Ok(())
    }
    fn thaw(&mut self, cg: CgroupId) -> Result<(), KernelError> {
        self.step()?;
        self.frozen.remove(&cg);
        self.observe();
        Ok(())
    }
}
