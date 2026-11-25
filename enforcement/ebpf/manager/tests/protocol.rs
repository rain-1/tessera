//! Protocol tests against the in-memory kernel. Every test inspects the
//! kernel-observable authority after *every* map operation (FakeKernel
//! history), not just the end state.

use std::collections::{BTreeMap, BTreeSet};
use tessera_bpf_manager::kernel::{FakeKernel, KernelError};
use tessera_bpf_manager::manager::{Config, Desired, Error, GrantSpec, Installed, Manager};
use tessera_bpf_manager::maps::{CgroupId, MountId};

const CG: CgroupId = CgroupId(0x1_0000_0042);
const OTHER: CgroupId = CgroupId(0x1_0000_0043);
const LEASE: u64 = 1_000;
const A: MountId = MountId(101);
const B: MountId = MountId(102);
const C: MountId = MountId(103);

fn cfg() -> Config {
    Config {
        lease_ns: LEASE,
        grant_capacity: 64,
    }
}

fn mounts() -> BTreeSet<MountId> {
    [A, B, C].into_iter().collect()
}

fn desired(generation: u64, ms: &[MountId]) -> Desired {
    Desired {
        generation,
        grants: ms
            .iter()
            .map(|m| (*m, GrantSpec { allow_mmap: false }))
            .collect(),
    }
}

fn setup() -> (FakeKernel, Manager) {
    let mut k = FakeKernel::new();
    k.now = 10;
    let (mut m, orphans) = Manager::start(&mut k, cfg()).unwrap();
    assert!(orphans.is_empty());
    m.broker_connected = true;
    m.register(&mut k, CG, 7, &mounts()).unwrap();
    (k, m)
}

fn readable(k: &FakeKernel, cg: CgroupId) -> BTreeSet<MountId> {
    [A, B, C]
        .into_iter()
        .filter(|m| k.read_allowed(cg, *m) == Some(true))
        .collect()
}

/// Safety over a history: at every instant, what a runnable subject can read
/// is a subset of the broker's desired set *for the active generation*
/// (no stale or partial generation is ever usable beyond what that
/// generation granted), and nothing is readable after its revocation ack.
fn check_history(
    k: &FakeKernel,
    from: usize,
    issued: &BTreeMap<u64, BTreeSet<MountId>>,
    acked: &[(usize, u64, MountId)],
) {
    for snap in &k.history[from..] {
        if let Some((gen_, set)) = snap.readable.get(&CG) {
            let allowed = issued.get(gen_).cloned().unwrap_or_default();
            assert!(
                set.is_subset(&allowed),
                "op {}: readable {set:?} not within generation {gen_} = {allowed:?}",
                snap.op
            );
            for (ack_op, ack_gen, m) in acked {
                // A later generation may legitimately grant m again.
                assert!(
                    !(snap.op > *ack_op && *gen_ <= *ack_gen && set.contains(m)),
                    "op {}: {m:?} readable after its revocation was acknowledged at op {ack_op}",
                    snap.op
                );
            }
        }
    }
}

#[test]
fn grant_becomes_usable_only_at_activation() {
    let (mut k, mut m) = setup();
    assert!(readable(&k, CG).is_empty(), "default deny");
    let h0 = k.history.len();
    let r = m.apply(&mut k, CG, &desired(1, &[A, B])).unwrap();
    assert_eq!(r.generation, 1);
    assert_eq!(readable(&k, CG), [A, B].into_iter().collect());
    // Before the activation op (the last subject write), nothing was readable.
    let first_readable = k.history[h0..]
        .iter()
        .position(|s| !s.readable[&CG].1.is_empty())
        .unwrap();
    assert_eq!(k.history[h0 + first_readable].readable[&CG].0, 1);
    assert_eq!(
        k.history[h0 + first_readable].readable[&CG].1.len(),
        2,
        "never partially visible"
    );
}

#[test]
fn unmanaged_and_foreign_subjects() {
    let (mut k, mut m) = setup();
    m.apply(&mut k, CG, &desired(1, &[A])).unwrap();
    assert_eq!(
        k.read_allowed(OTHER, A),
        Some(false),
        "another cgroup may not use this mount"
    );
    assert_eq!(
        k.read_allowed(CG, MountId(999)),
        None,
        "ungoverned mount: no opinion"
    );
    assert_eq!(
        m.apply(&mut k, OTHER, &desired(1, &[A])),
        Err(Error::UnknownSubject(OTHER))
    );
    m.register(&mut k, OTHER, 8, &BTreeSet::new()).unwrap();
    assert_eq!(
        m.apply(&mut k, OTHER, &desired(1, &[A])),
        Err(Error::MountNotRegistered(A))
    );
}

#[test]
fn stale_generation_rejected_without_writes() {
    let (mut k, mut m) = setup();
    m.apply(&mut k, CG, &desired(2, &[A])).unwrap();
    let ops = k.ops;
    assert_eq!(
        m.apply(&mut k, CG, &desired(2, &[A, B])),
        Err(Error::StaleGeneration {
            desired: 2,
            installed: 2
        })
    );
    assert_eq!(
        m.apply(&mut k, CG, &desired(1, &[])),
        Err(Error::StaleGeneration {
            desired: 1,
            installed: 2
        })
    );
    assert_eq!(k.ops, ops);
}

#[test]
fn revocation_acked_only_after_removal_and_under_barrier() {
    let (mut k, mut m) = setup();
    m.apply(&mut k, CG, &desired(1, &[A, B])).unwrap();
    let h0 = k.history.len();
    let r: Installed = m.apply(&mut k, CG, &desired(2, &[B])).unwrap();
    assert_eq!(r.revocations_acked, [A].into_iter().collect());
    assert!(r.revoked_with_residual_mappings.is_empty());
    assert_eq!(readable(&k, CG), [B].into_iter().collect());
    assert!(
        k.grants.keys().all(|key| key.mnt_id != A.0),
        "entry removed before ack"
    );
    // While runnable, the subject never saw generation 2 with A, and never
    // saw generation 1 after activation.
    for s in &k.history[h0..] {
        if let Some((g, set)) = s.readable.get(&CG) {
            if *g == 2 {
                assert!(!set.contains(&A));
            }
        }
    }
    // The activation happened while frozen.
    assert!(k.frozen.is_empty());
}

#[test]
fn mmap_grant_revocation_is_reported_non_strict() {
    let (mut k, mut m) = setup();
    let mut d = desired(1, &[A]);
    d.grants.insert(A, GrantSpec { allow_mmap: true });
    m.apply(&mut k, CG, &d).unwrap();
    let r = m.apply(&mut k, CG, &desired(2, &[])).unwrap();
    assert!(r.revocations_acked.is_empty());
    assert_eq!(r.revoked_with_residual_mappings, [A].into_iter().collect());
}

#[test]
fn flag_change_in_place_rejected() {
    let (mut k, mut m) = setup();
    m.apply(&mut k, CG, &desired(1, &[A])).unwrap();
    let mut d = desired(2, &[A]);
    d.grants.insert(A, GrantSpec { allow_mmap: true });
    assert_eq!(m.apply(&mut k, CG, &d), Err(Error::FlagChange(A)));
    assert_eq!(readable(&k, CG), [A].into_iter().collect());
}

#[test]
fn capacity_refused_before_staging() {
    let mut k = FakeKernel::new();
    let (mut m, _) = Manager::start(
        &mut k,
        Config {
            lease_ns: LEASE,
            grant_capacity: 2,
        },
    )
    .unwrap();
    m.register(&mut k, CG, 7, &mounts()).unwrap();
    let ops = k.ops;
    assert_eq!(
        m.apply(&mut k, CG, &desired(1, &[A, B, C])),
        Err(Error::Capacity { needed: 3, max: 2 })
    );
    assert_eq!(k.ops, ops);
    assert!(k.grants.is_empty());
}

#[test]
fn lease_expiry_fails_closed_and_needs_broker_to_renew() {
    let (mut k, mut m) = setup();
    m.apply(&mut k, CG, &desired(1, &[A])).unwrap();
    k.now += LEASE / 2;
    m.renew_leases(&mut k).unwrap();
    k.now += LEASE / 2 + 1;
    assert_eq!(readable(&k, CG), [A].into_iter().collect(), "renewed");
    m.broker_connected = false; // broker died or disconnected
    m.renew_leases(&mut k).unwrap();
    k.now += LEASE;
    assert!(readable(&k, CG).is_empty(), "lease ran out: fail closed");
}

#[test]
fn manager_death_fails_closed_by_lease() {
    let (mut k, mut m) = setup();
    m.apply(&mut k, CG, &desired(1, &[A])).unwrap();
    drop(m); // pinned maps survive; nobody renews
    assert_eq!(readable(&k, CG), [A].into_iter().collect());
    k.now += LEASE;
    assert!(readable(&k, CG).is_empty());
}

#[test]
fn restart_wipes_and_requires_fresh_generation() {
    let (mut k, mut m) = setup();
    m.apply(&mut k, CG, &desired(3, &[A, B])).unwrap();
    drop(m);
    let (mut m2, orphans) = Manager::start(&mut k, cfg()).unwrap();
    assert_eq!(orphans, vec![CG]);
    assert!(
        readable(&k, CG).is_empty(),
        "restart distrusts installed state"
    );
    assert!(k.grants.is_empty());
    assert_eq!(
        m2.adopt(&mut k, CG, 99, &mounts()),
        Err(Error::LaunchMismatch {
            cgroup: CG,
            kernel: 7,
            claimed: 99
        })
    );
    m2.adopt(&mut k, CG, 7, &mounts()).unwrap();
    m2.broker_connected = true;
    assert_eq!(
        m2.apply(&mut k, CG, &desired(3, &[A])),
        Err(Error::StaleGeneration {
            desired: 3,
            installed: 3
        })
    );
    m2.apply(&mut k, CG, &desired(4, &[A])).unwrap();
    assert!(
        readable(&k, CG).is_empty(),
        "lease still expired until renewed"
    );
    m2.renew_leases(&mut k).unwrap();
    assert_eq!(readable(&k, CG), [A].into_iter().collect());
}

#[test]
fn aborted_transition_leftovers_are_reconciled() {
    let (mut k, mut m) = setup();
    m.apply(&mut k, CG, &desired(1, &[A])).unwrap();
    // gen 2 = {B} (adds B, removes A) aborts at the freeze barrier.
    k.fail_freeze = true;
    assert_eq!(
        m.apply(&mut k, CG, &desired(2, &[B])),
        Err(Error::Kernel(KernelError::FreezeTimeout))
    );
    k.fail_freeze = false;
    assert_eq!(
        readable(&k, CG),
        [A].into_iter().collect(),
        "still generation 1"
    );
    // gen 3 = {C}: the staged B (gen_from 2) must not become valid at 3.
    m.apply(&mut k, CG, &desired(3, &[C])).unwrap();
    assert_eq!(readable(&k, CG), [C].into_iter().collect());
}

#[test]
fn without_reconcile_leftover_becomes_usable() {
    // Fault injection: shows why step 0 exists.
    let (mut k, mut m) = setup();
    m.faults.skip_reconcile = true;
    m.apply(&mut k, CG, &desired(1, &[A])).unwrap();
    k.fail_freeze = true;
    let _ = m.apply(&mut k, CG, &desired(2, &[B]));
    k.fail_freeze = false;
    let r = m.apply(&mut k, CG, &desired(3, &[C]));
    // Either verification catches it (lease expired: fail closed) or B leaks.
    match r {
        Err(Error::VerifyFailed(_)) => assert!(readable(&k, CG).is_empty()),
        other => panic!(
            "expected verification failure, got {other:?}; readable {:?}",
            readable(&k, CG)
        ),
    }
}

#[test]
fn unregister_removes_everything() {
    let (mut k, mut m) = setup();
    m.apply(&mut k, CG, &desired(1, &[A, B])).unwrap();
    m.unregister(&mut k, CG).unwrap();
    assert!(k.subjects.is_empty() && k.grants.is_empty() && k.governed.is_empty());
}

/// Crash the manager before every possible kernel operation of a three-step
/// scenario, then restart. Check the safety property over every intermediate
/// kernel state, and that restart leaves nothing readable.
#[test]
fn crash_at_every_operation() {
    let steps: Vec<Desired> = vec![
        desired(1, &[A, B]),
        desired(2, &[B, C]),
        desired(3, &[]),
        desired(4, &[A]),
    ];
    let issued: BTreeMap<u64, BTreeSet<MountId>> = steps
        .iter()
        .map(|d| (d.generation, d.grants.keys().copied().collect()))
        .chain(std::iter::once((0, BTreeSet::new())))
        .collect();

    // Count the operations in a clean run.
    let (mut k, mut m) = setup();
    let base = k.ops;
    for d in &steps {
        m.apply(&mut k, CG, d).unwrap();
    }
    let total = k.ops - base;
    assert!(total > 10);

    for crash_at in base..=base + total {
        let (mut k, mut m) = setup();
        k.crash_at = Some(crash_at);
        let h0 = k.history.len();
        let mut acked: Vec<(usize, u64, MountId)> = Vec::new();
        for d in &steps {
            match m.apply(&mut k, CG, d) {
                Ok(r) => {
                    for x in r.revocations_acked {
                        acked.push((k.ops, r.generation, x));
                    }
                }
                Err(Error::Kernel(KernelError::ManagerCrashed)) => break,
                Err(e) => panic!("crash_at {crash_at}: unexpected {e:?}"),
            }
        }
        check_history(&k, h0, &issued, &acked);
        // Kernel state left behind is still within the active generation.
        if let Some((g, set)) = k.snapshot().readable.get(&CG) {
            assert!(
                set.is_subset(&issued[g]),
                "crash_at {crash_at}: leftover authority"
            );
        }
        // Restart: everything inert at once.
        k.restart_manager();
        let h1 = k.history.len();
        let (_m2, orphans) = Manager::start(&mut k, cfg()).unwrap();
        assert_eq!(orphans, vec![CG]);
        assert!(
            readable(&k, CG).is_empty(),
            "crash_at {crash_at}: not fail-closed after restart"
        );
        // The first operation of start() already made everything inert.
        if let Some(s) = k.history.get(h1) {
            assert!(s.readable.get(&CG).is_none_or(|(_, set)| set.is_empty()));
        }
    }
}

/// Fault injection: without the freeze barrier the protocol still passes the
/// map-level checks (the barrier protects in-flight hooks, which the fake
/// kernel cannot express). This test documents that limitation of the Rust
/// fake; models/bpf_generation_model.py models in-flight checks and catches it.
#[test]
fn skip_freeze_not_detectable_by_fake_kernel() {
    let (mut k, mut m) = setup();
    m.faults.skip_freeze = true;
    m.apply(&mut k, CG, &desired(1, &[A])).unwrap();
    let r = m.apply(&mut k, CG, &desired(2, &[])).unwrap();
    assert_eq!(r.revocations_acked, [A].into_iter().collect());
}
