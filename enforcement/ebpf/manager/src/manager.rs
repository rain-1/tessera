//! The policy generation protocol (spec §10.3, docs/bpf-lsm.md §6).
//!
//! The broker owns the *desired* generation per sandbox (from the ledger).
//! The manager owns the *installed* generation (what the kernel enforces).
//! One transition G -> D (D > G) is:
//!
//! 0. **Reconcile** from kernel truth: read `active_gen` and the grant
//!    entries; delete leftovers of an aborted transition (staged entries with
//!    `gen_from > G`, retired entries with `gen_until <= G`) and re-open
//!    aborted removals. Memory is never trusted over the maps.
//! 1. **Check** before staging: D > G, every mount registered to this
//!    subject, no in-place flag change, map capacity suffices. A failed check
//!    leaves the authority of generation G untouched.
//! 2. **Stage** additions as `[D, MAX)` and removals as `[gen_from, D)`.
//!    Staged entries are inert at G, so a crash here changes nothing.
//! 3. **Barrier** (only if something is removed): freeze the cgroup, so no
//!    task is inside a hook that already looked up the old entry.
//! 4. **Activate**: one map update sets `active_gen = D`.
//! 5. Thaw.
//! 6. **Remove** retired entries.
//! 7. **Verify** by reading back. Only now report `Installed(D)`; only now
//!    are revocations acknowledged. A failed verification expires the lease.
//!
//! Fail closed: every subject has a lease in the kernel map that the BPF
//! program checks on every access. Only a live manager with a live broker
//! connection renews it. A dead manager, or one restarted, leaves (or sets)
//! an expired lease, so no grant is usable until the broker re-issues a
//! fresh generation.
//!
//! No counters exist on either side: direct grants are unlimited-use within
//! their lease; finite budgets stay in the broker.

use crate::kernel::{KernelError, KernelPolicy};
use crate::maps::{
    CgroupId, GEN_OPEN_END, GRANT_ALLOW_MMAP, GovernedMount, Grant, GrantKey, MountId, Subject,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantSpec {
    /// Read-only `mmap` allowed. Makes the grant non-revocable for its lease.
    pub allow_mmap: bool,
}

impl GrantSpec {
    fn flags(self) -> u32 {
        if self.allow_mmap { GRANT_ALLOW_MMAP } else { 0 }
    }
    fn from_flags(f: u32) -> Self {
        GrantSpec {
            allow_mmap: f & GRANT_ALLOW_MMAP != 0,
        }
    }
}

/// The broker's desired direct-grant state for one sandbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Desired {
    pub generation: u64,
    pub grants: BTreeMap<MountId, GrantSpec>,
}

/// What the manager tells the broker after a verified transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Installed {
    pub cgroup: CgroupId,
    pub generation: u64,
    pub active: BTreeSet<MountId>,
    /// Removed and verified absent, enforced on every later read syscall.
    pub revocations_acked: BTreeSet<MountId>,
    /// Removed, but the grant allowed mmap: mappings made before the
    /// revocation survive. Not a strict revocation (spec §10.2); the broker
    /// must kill the sandbox if it needs one.
    pub revoked_with_residual_mappings: BTreeSet<MountId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    UnknownSubject(CgroupId),
    LaunchMismatch {
        cgroup: CgroupId,
        kernel: u64,
        claimed: u64,
    },
    StaleGeneration {
        desired: u64,
        installed: u64,
    },
    MountNotRegistered(MountId),
    FlagChange(MountId),
    Capacity {
        needed: usize,
        max: usize,
    },
    VerifyFailed(String),
    Kernel(KernelError),
}

impl From<KernelError> for Error {
    fn from(e: KernelError) -> Self {
        Error::Kernel(e)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub lease_ns: u64,
    pub grant_capacity: usize,
}

#[derive(Clone, Debug)]
struct Record {
    launch_id: u64,
    mounts: BTreeSet<MountId>,
}

/// Fault-injection switches for the tests in this crate (each breaks one
/// protocol rule; the tests show the checks catch it).
#[derive(Clone, Copy, Debug, Default)]
pub struct Faults {
    pub skip_reconcile: bool,
    pub skip_freeze: bool,
}

pub struct Manager {
    cfg: Config,
    subjects: BTreeMap<CgroupId, Record>,
    pub broker_connected: bool,
    pub faults: Faults,
}

impl Manager {
    /// Start (or restart) the manager. Anything already in the pinned maps
    /// is distrusted: leases are expired first, then grants are deleted and
    /// cgroups thawed. Returns the orphaned subjects; each must be adopted
    /// (same cgroup and launch id) or stopped by the launcher.
    pub fn start<K: KernelPolicy>(k: &mut K, cfg: Config) -> Result<(Self, Vec<CgroupId>), Error> {
        let orphans = k.list_subjects()?;
        for cg in &orphans {
            if let Some(mut s) = k.get_subject(*cg)? {
                s.lease_expiry_ns = 0;
                k.put_subject(*cg, s)?;
            }
        }
        for cg in &orphans {
            for (key, _) in k.list_grants(*cg)? {
                k.delete_grant(key)?;
            }
            k.thaw(*cg)?;
        }
        let m = Manager {
            cfg,
            subjects: BTreeMap::new(),
            broker_connected: false,
            faults: Faults::default(),
        };
        Ok((m, orphans))
    }

    /// Register a sandbox before its workload starts (the launcher holds the
    /// workload at a gate until this returns). `mounts` are the
    /// `mnt_id_unique` of the grantable bind mounts in its mount namespace.
    pub fn register<K: KernelPolicy>(
        &mut self,
        k: &mut K,
        cg: CgroupId,
        launch_id: u64,
        mounts: &BTreeSet<MountId>,
    ) -> Result<(), Error> {
        for m in mounts {
            k.put_governed_mount(
                *m,
                GovernedMount {
                    owner_cgroup_id: cg.0,
                },
            )?;
        }
        let now = k.now_boot_ns();
        k.put_subject(
            cg,
            Subject {
                active_gen: 0,
                lease_expiry_ns: now + self.cfg.lease_ns,
                launch_id,
            },
        )?;
        self.subjects.insert(
            cg,
            Record {
                launch_id,
                mounts: mounts.clone(),
            },
        );
        Ok(())
    }

    /// Re-adopt a subject found at start-up. Identity is (cgroup id, launch
    /// id); a mismatch means the cgroup is not the sandbox we think it is.
    pub fn adopt<K: KernelPolicy>(
        &mut self,
        k: &mut K,
        cg: CgroupId,
        launch_id: u64,
        mounts: &BTreeSet<MountId>,
    ) -> Result<(), Error> {
        let s = k.get_subject(cg)?.ok_or(Error::UnknownSubject(cg))?;
        if s.launch_id != launch_id {
            return Err(Error::LaunchMismatch {
                cgroup: cg,
                kernel: s.launch_id,
                claimed: launch_id,
            });
        }
        self.subjects.insert(
            cg,
            Record {
                launch_id,
                mounts: mounts.clone(),
            },
        );
        Ok(())
    }

    /// Renew leases. Without a broker connection nothing is renewed, so the
    /// kernel fails closed when the lease runs out.
    pub fn renew_leases<K: KernelPolicy>(&mut self, k: &mut K) -> Result<(), Error> {
        if !self.broker_connected {
            return Ok(());
        }
        let now = k.now_boot_ns();
        for cg in self.subjects.keys() {
            if let Some(mut s) = k.get_subject(*cg)? {
                s.lease_expiry_ns = now + self.cfg.lease_ns;
                k.put_subject(*cg, s)?;
            }
        }
        Ok(())
    }

    /// Remove every trace of a stopped sandbox (lease first).
    pub fn unregister<K: KernelPolicy>(&mut self, k: &mut K, cg: CgroupId) -> Result<(), Error> {
        let rec = self.subjects.remove(&cg).ok_or(Error::UnknownSubject(cg))?;
        if let Some(mut s) = k.get_subject(cg)? {
            s.lease_expiry_ns = 0;
            k.put_subject(cg, s)?;
        }
        for (key, _) in k.list_grants(cg)? {
            k.delete_grant(key)?;
        }
        for m in &rec.mounts {
            k.delete_governed_mount(*m)?;
        }
        k.delete_subject(cg)?;
        Ok(())
    }

    /// Install `desired` for `cg` (steps 0-7 in the module docs).
    pub fn apply<K: KernelPolicy>(
        &mut self,
        k: &mut K,
        cg: CgroupId,
        desired: &Desired,
    ) -> Result<Installed, Error> {
        let rec = self
            .subjects
            .get(&cg)
            .ok_or(Error::UnknownSubject(cg))?
            .clone();
        let subj = k.get_subject(cg)?.ok_or(Error::UnknownSubject(cg))?;
        if subj.launch_id != rec.launch_id {
            return Err(Error::LaunchMismatch {
                cgroup: cg,
                kernel: subj.launch_id,
                claimed: rec.launch_id,
            });
        }
        let g = subj.active_gen;
        let d = desired.generation;

        // 1. Checks that need no kernel state beyond `active_gen`.
        if d <= g {
            return Err(Error::StaleGeneration {
                desired: d,
                installed: g,
            });
        }
        for m in desired.grants.keys() {
            if !rec.mounts.contains(m) {
                return Err(Error::MountNotRegistered(*m));
            }
        }

        // 0. Reconcile with kernel truth.
        let mut installed: BTreeMap<MountId, (Grant, GrantSpec)> = BTreeMap::new();
        for (key, gr) in k.list_grants(cg)? {
            let m = MountId(key.mnt_id);
            if self.faults.skip_reconcile {
                if gr.valid_at(g) {
                    installed.insert(m, (gr, GrantSpec::from_flags(gr.flags)));
                }
                continue;
            }
            if gr.gen_from > g || gr.gen_until <= g {
                k.delete_grant(key)?; // inert leftover of an aborted transition
            } else {
                let mut gr = gr;
                if gr.gen_until != GEN_OPEN_END {
                    gr.gen_until = GEN_OPEN_END; // aborted removal: still installed
                    k.put_grant(key, gr)?;
                }
                installed.insert(m, (gr, GrantSpec::from_flags(gr.flags)));
            }
        }

        let adds: Vec<(MountId, GrantSpec)> = desired
            .grants
            .iter()
            .filter(|(m, _)| !installed.contains_key(m))
            .map(|(m, s)| (*m, *s))
            .collect();
        let removes: Vec<(MountId, Grant, GrantSpec)> = installed
            .iter()
            .filter(|(m, _)| !desired.grants.contains_key(m))
            .map(|(m, (gr, s))| (*m, *gr, *s))
            .collect();
        for (m, spec) in &desired.grants {
            if let Some((_, cur)) = installed.get(m) {
                if cur != spec {
                    return Err(Error::FlagChange(*m));
                }
            }
        }
        let mut total_now = 0;
        for other in self.subjects.keys() {
            total_now += k.list_grants(*other)?.len();
        }
        let needed = total_now + adds.len();
        if needed > self.cfg.grant_capacity {
            return Err(Error::Capacity {
                needed,
                max: self.cfg.grant_capacity,
            });
        }

        // 2. Stage.
        for (m, spec) in &adds {
            let key = GrantKey {
                cgroup_id: cg.0,
                mnt_id: m.0,
            };
            k.put_grant(
                key,
                Grant {
                    gen_from: d,
                    gen_until: GEN_OPEN_END,
                    flags: spec.flags(),
                    _pad: 0,
                },
            )?;
        }
        for (m, gr, _) in &removes {
            let key = GrantKey {
                cgroup_id: cg.0,
                mnt_id: m.0,
            };
            k.put_grant(
                key,
                Grant {
                    gen_until: d,
                    ..*gr
                },
            )?;
        }

        // 3. Barrier.
        let barrier = !removes.is_empty() && !self.faults.skip_freeze;
        if barrier {
            if let Err(e) = k.freeze(cg) {
                let _ = k.thaw(cg);
                return Err(e.into());
            }
        }

        // 4. Activate (single map update; lease unchanged).
        let cur = k.get_subject(cg)?.ok_or(Error::UnknownSubject(cg))?;
        k.put_subject(
            cg,
            Subject {
                active_gen: d,
                ..cur
            },
        )?;

        // 5. Thaw.
        if barrier {
            k.thaw(cg)?;
        }

        // 6. Remove retired entries.
        for (m, _, _) in &removes {
            k.delete_grant(GrantKey {
                cgroup_id: cg.0,
                mnt_id: m.0,
            })?;
        }

        // 7. Verify.
        let after = k.get_subject(cg)?.ok_or(Error::UnknownSubject(cg))?;
        let entries = k.list_grants(cg)?;
        let valid: BTreeSet<MountId> = entries
            .iter()
            .filter(|(_, gr)| gr.valid_at(after.active_gen))
            .map(|(key, _)| MountId(key.mnt_id))
            .collect();
        let want: BTreeSet<MountId> = desired.grants.keys().copied().collect();
        let leftovers = entries.iter().any(|(_, gr)| !gr.valid_at(after.active_gen));
        if after.active_gen != d || valid != want || leftovers {
            let _ = k.put_subject(
                cg,
                Subject {
                    lease_expiry_ns: 0,
                    ..after
                },
            );
            return Err(Error::VerifyFailed(format!(
                "active_gen={} want {d}; valid={valid:?} want {want:?}; leftovers={leftovers}",
                after.active_gen
            )));
        }

        let mut out = Installed {
            cgroup: cg,
            generation: d,
            active: want,
            revocations_acked: BTreeSet::new(),
            revoked_with_residual_mappings: BTreeSet::new(),
        };
        for (m, _, spec) in removes {
            if spec.allow_mmap {
                out.revoked_with_residual_mappings.insert(m);
            } else {
                out.revocations_acked.insert(m);
            }
        }
        Ok(out)
    }
}
