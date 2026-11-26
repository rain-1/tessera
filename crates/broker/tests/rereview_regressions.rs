//! Regression tests for the re-review of 2026-11-26
//! (`docs/security-review-2026-11-25.md`, section "Re-review 2026-11-26").
//! The approval queue, the approval rate window, the dispatch cap and the
//! ledger record quotas apply per orchestration domain (an operator-created
//! principal and everything spawned under it), so spawning children does
//! not multiply a principal's share (ADR-0033).

mod common;

use std::collections::{BTreeMap, HashMap};
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};

use common::*;
use tessera_broker::{AdminRequest, AdminResponse};
use tessera_broker::{AgentSpawnProfile, AuditLog, SandboxSpawner};
use tessera_capability_core::AgentId;
use tessera_protocol::*;

/// Spawner that hands the sandbox end of every child channel to the test.
#[derive(Clone, Default)]
struct Fake {
    ends: Arc<Mutex<HashMap<AgentId, OwnedFd>>>,
}

impl SandboxSpawner for Fake {
    fn spawn(&mut self, agent: AgentId, _profile: &str) -> Result<OwnedFd, String> {
        let (mine, theirs) = tessera_protocol::unix::seqpacket_pair().unwrap();
        self.ends.lock().unwrap().insert(agent, theirs);
        Ok(mine)
    }
    fn stop(&mut self, agent: AgentId) {
        self.ends.lock().unwrap().remove(&agent);
    }
}

fn with_spawn_profile(h: &mut Harness) {
    h.config.spawn_profiles = BTreeMap::from([(
        1,
        AgentSpawnProfile {
            profile: "worker".into(),
            baseline: vec![],
        },
    )]);
}

/// Spawn `n` children of `parent` and return their clients.
fn spawn_children(parent: &mut Agent, sp: &Fake, n: u128) -> Vec<Agent> {
    (1..=n)
        .map(|i| {
            let r = parent.call(Request::Spawn {
                request_id: 1000 + i,
                launch_profile: 1,
            });
            assert!(matches!(r, Response::Spawned { .. }), "spawn {i}: {r:?}");
            let mut ends = sp.ends.lock().unwrap();
            let id = *ends.keys().next().unwrap();
            let fd = ends.remove(&id).unwrap();
            Agent::from_fd(id, fd)
        })
        .collect()
}

fn grant_req(rid: u128, obj: u64) -> Request {
    Request::RequestGrant {
        request_id: rid,
        requested_scope: read_scope(obj),
        budget: WireBudget::Finite(1),
        depth: WireDepth::Finite(0),
        expiry: WireExpiry::Inherit,
        untrusted_description: None,
    }
}

// ---------------------------------------------------------------------
// N1: the pending cap was per principal, so a spawn tree of 9 principals
// held 17 of 18 approval slots and other domains found the queue full.
// ---------------------------------------------------------------------

#[test]
fn n1_spawn_tree_cannot_fill_the_approval_queue() {
    let mut h = Harness::new();
    with_spawn_profile(&mut h);
    let sp = Fake::default();
    let b = h.start_full(
        h.storage.clone(),
        None,
        Some(Box::new(sp.clone())),
        AuditLog::memory(),
    );
    h.enroll(&b);
    let obj = register_file(&b, "notes.txt");
    let mut attacker = Agent::attach(&b);
    let mut victim = Agent::attach(&b);
    let mut children = spawn_children(&mut attacker, &sp, 8);
    let mut pending = 0;
    for rid in 1..=2u128 {
        for a in std::iter::once(&mut attacker).chain(children.iter_mut()) {
            a.send(grant_req(rid, obj));
            match a.recv_any().unwrap().response {
                Response::GrantPending { .. } => pending += 1,
                r => assert_eq!(code(&r), Some(ErrorCode::RateLimited)),
            }
        }
    }
    assert_eq!(pending, 2, "the whole domain shares one pending cap");
    victim.send(grant_req(1, obj));
    assert!(matches!(
        victim.recv_any().unwrap().response,
        Response::GrantPending { .. }
    ));
}

#[test]
fn n1_spawn_tree_shares_one_approval_rate_window() {
    let mut h = Harness::new();
    with_spawn_profile(&mut h);
    h.config.approval_max_per_window = 1;
    let sp = Fake::default();
    let b = h.start_full(
        h.storage.clone(),
        None,
        Some(Box::new(sp.clone())),
        AuditLog::memory(),
    );
    h.enroll(&b);
    let obj = register_file(&b, "notes.txt");
    let mut parent = Agent::attach(&b);
    let mut other = Agent::attach(&b);
    let mut child = spawn_children(&mut parent, &sp, 1).remove(0);
    parent.send(grant_req(1, obj));
    let ticket = wait_pending(&b);
    assert_eq!(b.admin(AdminRequest::Deny { ticket }), AdminResponse::Ok);
    assert_eq!(
        code(&parent.recv().unwrap().response),
        Some(ErrorCode::ApprovalDenied)
    );
    // The child's prompt would be the domain's second in the window.
    child.send(grant_req(1, obj));
    assert_eq!(
        code(&child.recv().unwrap().response),
        Some(ErrorCode::RateLimited)
    );
    // Another domain still gets its prompt.
    other.send(grant_req(1, obj));
    let ticket = wait_pending(&b);
    assert_eq!(
        pending_agent(&b, ticket),
        other.id,
        "the other domain's request is active"
    );
}

fn pending_agent(b: &tessera_broker::Broker, ticket: u64) -> AgentId {
    match b.admin(AdminRequest::ListPending) {
        AdminResponse::Pending(v) => v.iter().find(|p| p.ticket == ticket).unwrap().agent,
        other => panic!("{other:?}"),
    }
}

/// Sends `n` grant requests and returns how many are pending.
fn flood(a: &mut Agent, obj: u64, n: u128) -> usize {
    let mut pending = 0;
    for rid in 1..=n {
        a.send(grant_req(rid, obj));
        match a.recv_any().unwrap().response {
            Response::GrantPending { .. } => pending += 1,
            r => assert_eq!(code(&r), Some(ErrorCode::RateLimited)),
        }
    }
    pending
}

#[test]
fn n1_approval_slots_are_reserved_for_domains_with_nothing_pending() {
    let mut h = Harness::new();
    // Five slots (four queued + the active one), no small per-domain cap:
    // only the fair share and the reservation limit the domains.
    h.config.approval_queue = 4;
    h.config.max_pending_approvals_per_domain = 100;
    let b = h.start(None);
    h.enroll(&b);
    let obj = register_file(&b, "notes.txt");
    let mut a = Agent::attach(&b);
    let mut bb = Agent::attach(&b);
    let mut v1 = Agent::attach(&b);
    let mut v2 = Agent::attach(&b);
    // Four live domains: fair share ceil(5 / 4) = 2.
    assert_eq!(flood(&mut a, obj, 3), 2);
    // A second request of B would leave one slot for two domains.
    assert_eq!(flood(&mut bb, obj, 2), 1);
    assert_eq!(flood(&mut v1, obj, 1), 1);
    assert_eq!(flood(&mut v2, obj, 1), 1);
}

// ---------------------------------------------------------------------
// Dispatch starvation: the per-agent dispatch cap let a principal and its
// children hold every worker.
// ---------------------------------------------------------------------

/// Executor that holds every job of the `slow` principals until released,
/// and records how many of them ran at once.
struct Gate {
    inner: tessera_broker::AdapterExecutor,
    slow: Mutex<Vec<AgentId>>,
    open: Mutex<bool>,
    cv: std::sync::Condvar,
    running: std::sync::atomic::AtomicUsize,
    peak: std::sync::atomic::AtomicUsize,
}

impl Gate {
    fn new(h: &Harness) -> Arc<Gate> {
        Arc::new(Gate {
            inner: tessera_broker::AdapterExecutor::new(Some(h.root.path())).unwrap(),
            slow: Mutex::new(Vec::new()),
            open: Mutex::new(false),
            cv: std::sync::Condvar::new(),
            running: Default::default(),
            peak: Default::default(),
        })
    }
    fn release(&self) {
        *self.open.lock().unwrap() = true;
        self.cv.notify_all();
    }
}

impl tessera_broker::Executor for Gate {
    fn register_file(
        &self,
        object: tessera_capability_core::ObjectId,
        name: &str,
        r: u64,
        w: u64,
        expected: Option<tessera_broker::entry::FileIdentityRec>,
    ) -> Result<tessera_broker::entry::FileIdentityRec, String> {
        self.inner.register_file(object, name, r, w, expected)
    }
    fn register_endpoint(
        &self,
        id: tessera_capability_core::EndpointId,
        spec: &tessera_broker::EndpointSpec,
        secret: Option<(String, Vec<u8>)>,
    ) -> Result<(), String> {
        self.inner.register_endpoint(id, spec, secret)
    }
    fn execute(&self, job: &tessera_broker::DispatchJob) -> tessera_broker::ExecResult {
        use std::sync::atomic::Ordering::SeqCst;
        if self.slow.lock().unwrap().contains(&job.reservation.owner()) {
            let now = self.running.fetch_add(1, SeqCst) + 1;
            self.peak.fetch_max(now, SeqCst);
            let mut open = self.open.lock().unwrap();
            while !*open {
                open = self.cv.wait(open).unwrap();
            }
            drop(open);
            self.running.fetch_sub(1, SeqCst);
        }
        self.inner.execute(job)
    }
}

fn start_gated(
    h: &Harness,
    gate: &Arc<Gate>,
    spawner: Option<Box<dyn SandboxSpawner>>,
) -> tessera_broker::Broker {
    let journal = tessera_journal::Journal::open_storage(
        h.storage.clone(),
        tessera_journal::JournalOptions::default(),
    )
    .unwrap();
    tessera_broker::Broker::start(
        journal,
        h.config.clone(),
        tessera_broker::Services {
            executor: gate.clone(),
            spawner,
            audit: AuditLog::memory(),
            clock: Arc::new(tessera_broker::MonotonicClock::default()),
            fault: None,
        },
    )
    .unwrap()
}

fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    for _ in 0..1000 {
        if cond() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("timed out waiting for {what}");
}

fn read_req(rid: u128, cap: u128) -> Request {
    Request::Consume {
        request_id: rid,
        cap_id: cap,
        operation: WireOperation::FileReadSnapshot { max_bytes: 64 },
    }
}

fn unlimited_baseline(b: &tessera_broker::Broker, agent: AgentId, obj: u64) -> u128 {
    match b.admin(AdminRequest::InstallBaseline {
        agent,
        scope: read_scope(obj),
        budget: WireBudget::Unlimited,
        depth: WireDepth::Unlimited,
        expiry_ms: None,
    }) {
        AdminResponse::Capability(c) => c,
        other => panic!("baseline failed: {other:?}"),
    }
}

fn delegate_unlimited(
    from: &mut Agent,
    rid: u128,
    cap: u128,
    to: WireAgentId,
    obj: u64,
) -> Response {
    from.call(Request::Delegate {
        request_id: rid,
        cap_id: cap,
        recipient: to,
        child_scope: read_scope(obj),
        child_budget: WireBudget::Unlimited,
        child_depth: WireDepth::Finite(0),
        child_expiry: WireExpiry::Inherit,
    })
}

#[test]
fn n1_spawn_tree_shares_one_dispatch_cap() {
    use std::sync::atomic::Ordering::SeqCst;
    let mut h = Harness::new();
    with_spawn_profile(&mut h);
    h.config.dispatch_workers = 4;
    h.config.max_dispatch_per_domain = 2;
    let gate = Gate::new(&h);
    let sp = Fake::default();
    let b = start_gated(&h, &gate, Some(Box::new(sp.clone())));
    let obj = register_file(&b, "notes.txt");
    let mut parent = Agent::attach(&b);
    let mut victim = Agent::attach(&b);
    let mut children = spawn_children(&mut parent, &sp, 2);
    let cap = unlimited_baseline(&b, parent.id, obj);
    let vcap = baseline(&b, victim.id, obj, 1, 0);
    let mut members = vec![(parent.id, cap)];
    for (i, c) in children.iter().enumerate() {
        let Response::Delegated { child_cap_id, .. } =
            delegate_unlimited(&mut parent, 100 + i as u128, cap, c.wire_id(), obj)
        else {
            panic!("delegate")
        };
        members.push((c.id, child_cap_id));
    }
    *gate.slow.lock().unwrap() = members.iter().map(|(a, _)| *a).collect();
    let mut sent = Vec::new();
    for rid in 1..=2u128 {
        sent.push((parent.id, parent.send(read_req(rid, cap))));
        for (c, (_, ccap)) in children.iter_mut().zip(&members[1..]) {
            sent.push((c.id, c.send(read_req(rid, *ccap))));
        }
    }
    wait_for("six reservations", || reservations(&b).len() == 6);
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert_eq!(gate.running.load(SeqCst), 2, "the domain holds two workers");
    let statuses: Vec<String> = reservations(&b).into_iter().map(|r| r.status).collect();
    assert_eq!(statuses.iter().filter(|s| *s == "dispatched").count(), 2);
    // Another domain is still served promptly.
    assert_eq!(snapshot(&victim.read(1, vcap)), b"top secret notes");

    gate.release();
    let mut answered = 0;
    for a in std::iter::once(&parent).chain(children.iter()) {
        for _ in 0..2 {
            assert_eq!(snapshot(&a.recv().unwrap().response), b"top secret notes");
            answered += 1;
        }
    }
    assert_eq!(answered, sent.len());
    assert_eq!(gate.peak.load(SeqCst), 2, "never more than the cap at once");
}

// ---------------------------------------------------------------------
// Residual of finding 3: a spawn tree could exhaust the global record caps
// within an epoch (the quotas were per principal and per root only).
// ---------------------------------------------------------------------

#[test]
fn n1_ledger_quotas_are_per_domain() {
    let mut h = Harness::new();
    with_spawn_profile(&mut h);
    h.config.ledger_quotas.derived_per_domain = 3;
    h.config.ledger_quotas.reservations_per_domain = 2;
    let sp = Fake::default();
    let b = h.start_full(
        h.storage.clone(),
        None,
        Some(Box::new(sp.clone())),
        AuditLog::memory(),
    );
    let obj = register_file(&b, "notes.txt");
    let mut parent = Agent::attach(&b);
    let mut victim = Agent::attach(&b);
    let mut child = spawn_children(&mut parent, &sp, 1).remove(0);
    let cap = unlimited_baseline(&b, parent.id, obj);
    let vcap = unlimited_baseline(&b, victim.id, obj);
    let me = parent.wire_id();
    let Response::Delegated {
        child_cap_id: ccap, ..
    } = parent.delegate(1, cap, child.wire_id(), read_scope(obj), 5, 1)
    else {
        panic!("delegate to child")
    };
    assert!(matches!(
        delegate_unlimited(&mut parent, 2, cap, me, obj),
        Response::Delegated { .. }
    ));
    let cme = child.wire_id();
    assert!(matches!(
        child.delegate(1, ccap, cme, read_scope(obj), 1, 0),
        Response::Delegated { .. }
    ));
    // Each principal is far below its own quota; the domain is at three.
    assert_eq!(
        code(&child.delegate(2, ccap, cme, read_scope(obj), 1, 0)),
        Some(ErrorCode::LimitExceeded)
    );
    assert_eq!(
        code(&delegate_unlimited(&mut parent, 3, cap, me, obj)),
        Some(ErrorCode::LimitExceeded)
    );
    let vme = victim.wire_id();
    assert!(matches!(
        delegate_unlimited(&mut victim, 1, vcap, vme, obj),
        Response::Delegated { .. }
    ));

    assert_eq!(snapshot(&parent.read(10, cap)), b"top secret notes");
    assert_eq!(snapshot(&child.read(10, ccap)), b"top secret notes");
    assert_eq!(code(&child.read(11, ccap)), Some(ErrorCode::LimitExceeded));
    assert_eq!(snapshot(&victim.read(10, vcap)), b"top secret notes");
}

// ---------------------------------------------------------------------
// Info: an emergency stop bumped the epoch but did not compact it.
// ---------------------------------------------------------------------

fn compactions_after_bumps(h: &Harness) -> Vec<bool> {
    use tessera_broker::entry::Entry;
    use tessera_capability_core::{AdminCommand, AuthenticatedCommand};
    use tessera_journal::{Journal, JournalOptions, RecordKind};
    let mut j = Journal::open_storage(h.storage.clone(), JournalOptions::default()).unwrap();
    let records: Vec<_> = j.replay().map(|r| r.unwrap()).collect();
    records
        .iter()
        .enumerate()
        .filter(|(_, r)| r.kind == RecordKind::EpochBump)
        .map(|(i, _)| {
            records.get(i + 1).is_some_and(|r| {
                matches!(
                    Entry::decode(&r.payload),
                    Ok(Entry::Command {
                        command: AuthenticatedCommand::Operator(AdminCommand::CompactEpoch),
                        ..
                    })
                )
            })
        })
        .collect()
}

#[test]
fn emergency_stop_compacts_the_ended_epoch() {
    let mut h = Harness::new();
    h.config.limits.max_capabilities = 50;
    h.config.limits.max_reservations = 20;
    let b = h.start(None);
    let obj = register_file(&b, "notes.txt");
    let mut attacker = Agent::attach(&b);
    let cap = unlimited_baseline(&b, attacker.id, obj);
    let me = attacker.wire_id();
    let mut rid = 0u128;
    loop {
        rid += 1;
        if let Some(c) = code(&delegate_unlimited(&mut attacker, rid, cap, me, obj)) {
            assert_eq!(c, ErrorCode::LimitExceeded);
            break;
        }
    }
    loop {
        rid += 1;
        if let Some(c) = code(&attacker.read(rid, cap)) {
            assert_eq!(c, ErrorCode::LimitExceeded);
            break;
        }
    }
    assert_eq!(b.admin(AdminRequest::EmergencyStop), AdminResponse::Ok);
    // The ended epoch no longer holds capacity: a fresh principal is served
    // and only its record is in the ledger.
    let mut fresh = Agent::attach(&b);
    let cap = baseline(&b, fresh.id, obj, 1, 0);
    assert_eq!(snapshot(&fresh.read(1, cap)), b"top secret notes");
    assert_eq!(status(&b).capabilities, 1);
    drop((attacker, fresh));
    b.shutdown();
    // Journaled right after the epoch bump, so replay reproduces it.
    assert_eq!(compactions_after_bumps(&h), [true, true]);
    let b = h.start(None);
    assert_eq!(status(&b).capabilities, 0);
    b.shutdown();
    assert_eq!(compactions_after_bumps(&h), [true, true, true]);
}

#[test]
fn emergency_stop_compaction_waits_for_jobs_on_a_worker() {
    use std::sync::atomic::Ordering::SeqCst;
    let h = Harness::new();
    let gate = Gate::new(&h);
    let b = start_gated(&h, &gate, None);
    let obj = register_file(&b, "notes.txt");
    let mut slow = Agent::attach(&b);
    *gate.slow.lock().unwrap() = vec![slow.id];
    let cap = unlimited_baseline(&b, slow.id, obj);
    slow.send(read_req(1, cap));
    wait_for("the job on a worker", || gate.running.load(SeqCst) == 1);
    assert_eq!(b.admin(AdminRequest::EmergencyStop), AdminResponse::Ok);
    // The running job's reservation must stay until its outcome is in.
    assert_eq!(status(&b).capabilities, 1);
    gate.release();
    wait_for("compaction", || status(&b).capabilities == 0);
    assert_eq!(status(&b).principals, 0);
    // The broker is still serving.
    let mut fresh = Agent::attach(&b);
    let cap = baseline(&b, fresh.id, obj, 1, 0);
    assert_eq!(snapshot(&fresh.read(1, cap)), b"top secret notes");
    b.shutdown();
    // The abandoned job's outcome is not journaled (the bump ended its
    // reservation), so the compaction is the next record after the bump.
    assert_eq!(compactions_after_bumps(&h), [true, true]);
}
