//! Regression tests for the independent security review of 2026-11-25
//! (`docs/security-review-2026-11-25.md`). Each test is the review's
//! proof-of-concept turned into an assertion of the fixed behaviour; the
//! finding number is in the test name.

mod common;

use std::sync::Arc;

use common::*;
use tessera_broker::entry::Entry;
use tessera_broker::{AdminRequest, AdminResponse, ManualClock};
use tessera_capability_core::{AdminCommand, AuthenticatedCommand};
use tessera_journal::{Journal, JournalOptions, RecordKind};
use tessera_protocol::*;

fn unlimited_baseline(
    b: &tessera_broker::Broker,
    agent: tessera_capability_core::AgentId,
    obj: u64,
) -> u128 {
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
// Finding 3: global record capacity exhausted by self-delegation, and the
// exhaustion survived restart.
// ---------------------------------------------------------------------

#[test]
fn finding3_record_exhaustion_does_not_survive_restart() {
    let mut h = Harness::new();
    // Scaled-down stand-ins for the 100_000 / 1_000_000 defaults, below the
    // per-principal quotas so the global bound is what the attacker hits.
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
        let r = attacker.call(Request::Delegate {
            request_id: rid,
            cap_id: cap,
            recipient: me,
            child_scope: read_scope(obj),
            child_budget: WireBudget::Unlimited,
            child_depth: WireDepth::Finite(0),
            child_expiry: WireExpiry::Inherit,
        });
        if let Some(c) = code(&r) {
            assert_eq!(c, ErrorCode::LimitExceeded);
            break;
        }
    }
    loop {
        rid += 1;
        let r = attacker.read(rid, cap);
        if let Some(c) = code(&r) {
            assert_eq!(c, ErrorCode::LimitExceeded);
            break;
        }
    }
    let victim = Agent::attach(&b);
    assert!(matches!(
        b.admin(AdminRequest::InstallBaseline {
            agent: victim.id,
            scope: read_scope(obj),
            budget: WireBudget::Finite(1),
            depth: WireDepth::Finite(0),
            expiry_ms: None,
        }),
        AdminResponse::Error(_)
    ));
    drop((attacker, victim));
    b.shutdown();

    // Restart: the previous epoch is compacted, a fresh principal is served.
    for restart in 0..2 {
        let b = h.start(None);
        let mut fresh = Agent::attach(&b);
        let cap = baseline(&b, fresh.id, obj, 1, 0);
        assert_eq!(snapshot(&fresh.read(1, cap)), b"top secret notes");
        // Only this epoch's record remains in the ledger; the previous
        // epoch is visible to the operator as archived views only.
        assert_eq!(status(&b).capabilities, 1, "restart {restart}");
        let live: Vec<_> = caps(&b)
            .into_iter()
            .filter(|c| c.owner.epoch() == status(&b).epoch)
            .collect();
        assert_eq!(live.len(), 1, "restart {restart}");
        drop(fresh);
        b.shutdown();
    }

    // Compaction is journaled right after each epoch bump, so replay (the
    // second restart above) reproduced it.
    let mut j = Journal::open_storage(h.storage.clone(), JournalOptions::default()).unwrap();
    let records: Vec<_> = j.replay().map(|r| r.unwrap()).collect();
    let bumps: Vec<usize> = records
        .iter()
        .enumerate()
        .filter(|(_, r)| r.kind == RecordKind::EpochBump)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(bumps.len(), 3);
    for i in bumps {
        assert!(matches!(
            Entry::decode(&records[i + 1].payload),
            Ok(Entry::Command {
                command: AuthenticatedCommand::Operator(AdminCommand::CompactEpoch),
                ..
            })
        ));
    }
}

// ---------------------------------------------------------------------
// Finding 4: one agent filled the global approval queue.
// ---------------------------------------------------------------------

#[test]
fn finding4_one_agent_cannot_fill_the_approval_queue() {
    let mut h = Harness::new();
    let b = h.start(None);
    h.enroll(&b);
    let obj = register_file(&b, "notes.txt");
    let mut attacker = Agent::attach(&b);
    let mut victim = Agent::attach(&b);
    let mut pending = 0;
    for rid in 1..=17u128 {
        attacker.send(grant_req(rid, obj));
        match attacker.recv_any().unwrap().response {
            Response::GrantPending { .. } => pending += 1,
            r => assert_eq!(code(&r), Some(ErrorCode::RateLimited)),
        }
    }
    assert_eq!(pending, h.config.max_pending_approvals_per_agent);
    victim.send(grant_req(1, obj));
    assert!(matches!(
        victim.recv_any().unwrap().response,
        Response::GrantPending { .. }
    ));
}

// ---------------------------------------------------------------------
// Finding 7: expired queued grants got no answer and leaked in-flight slots.
// ---------------------------------------------------------------------

#[test]
fn finding7_expired_queued_grants_are_answered_and_release_slots() {
    let mut h = Harness::new();
    h.config.approval_timeout_ms = 300;
    h.config.max_in_flight_per_agent = 4;
    let clock = ManualClock::new();
    let b = h.start_with_clock(Arc::new(clock.clone()));
    h.enroll(&b);
    let obj = register_file(&b, "notes.txt");
    let mut a = Agent::attach(&b);
    let corrs: Vec<u64> = (1..=4u128).map(|rid| a.send(grant_req(rid, obj))).collect();
    let mut finals = std::collections::BTreeMap::new();
    let mut pending = 0;
    while finals.len() + pending < corrs.len() {
        let m = a.recv_any().unwrap();
        match m.response {
            Response::GrantPending { .. } => pending += 1,
            r => {
                finals.insert(m.correlation_id, code(&r));
            }
        }
    }
    clock.advance(300);
    while finals.len() < corrs.len() {
        let m = a.recv().unwrap();
        finals.insert(m.correlation_id, code(&m.response));
    }
    assert_eq!(finals.keys().copied().collect::<Vec<_>>(), corrs);
    assert_eq!(
        finals
            .values()
            .filter(|c| **c == Some(ErrorCode::ApprovalTimeout))
            .count(),
        pending
    );
    // Every in-flight slot was released: four more requests are admitted.
    for _ in 0..4 {
        assert!(matches!(
            a.call(Request::ListCapabilities { after: None }),
            Response::Capabilities { .. }
        ));
    }
    a.send(grant_req(9, obj));
    assert!(matches!(
        a.recv_any().unwrap().response,
        Response::GrantPending { .. }
    ));
}

// ---------------------------------------------------------------------
// Finding 8: denial detail revealed whether another principal's
// capability exists.
// ---------------------------------------------------------------------

#[test]
fn finding8_non_owner_sees_one_answer_for_every_foreign_or_unknown_target() {
    let h = Harness::new();
    let clock = ManualClock::new();
    let b = h.start_with_clock(Arc::new(clock.clone()));
    let obj = register_file(&b, "notes.txt");
    let mut attacker = Agent::attach(&b);
    let bystander = Agent::attach(&b);
    let mut victim = Agent::attach(&b);
    let _own = baseline(&b, attacker.id, obj, 5, 1);

    let live = baseline(&b, victim.id, obj, 5, 1);
    let revoked = baseline(&b, victim.id, obj, 5, 1);
    assert_eq!(
        b.admin(AdminRequest::Revoke {
            capability: revoked
        }),
        AdminResponse::Ok
    );
    let dropped = baseline(&b, victim.id, obj, 5, 1);
    assert!(matches!(
        victim.call(Request::Drop {
            request_id: 1,
            cap_id: dropped
        }),
        Response::Dropped { .. }
    ));
    let parent = baseline(&b, victim.id, obj, 5, 2);
    let Response::Delegated { child_cap_id, .. } =
        victim.delegate(2, parent, victim.wire_id(), read_scope(obj), 2, 1)
    else {
        panic!("delegate")
    };
    assert_eq!(
        b.admin(AdminRequest::Revoke { capability: parent }),
        AdminResponse::Ok
    );
    let expiring = match b.admin(AdminRequest::InstallBaseline {
        agent: victim.id,
        scope: read_scope(obj),
        budget: WireBudget::Finite(5),
        depth: WireDepth::Finite(1),
        expiry_ms: Some(10),
    }) {
        AdminResponse::Capability(c) => c,
        other => panic!("{other:?}"),
    };
    let gone = Agent::attach(&b);
    let orphaned = baseline(&b, gone.id, obj, 5, 1);
    assert_eq!(
        b.admin(AdminRequest::TerminatePrincipal { agent: gone.id }),
        AdminResponse::Ok
    );
    clock.advance(20);

    let targets = [
        ("unknown", 9_999u128),
        ("live", live),
        ("revoked", revoked),
        ("dropped", dropped),
        ("ancestor-revoked", child_cap_id),
        ("expired", expiring),
        ("owner-terminated", orphaned),
    ];
    let to = bystander.wire_id();
    type Op = fn(u128, u128, WireAgentId, u64) -> Request;
    let ops: [(&str, Op); 7] = [
        ("consume", |rid, cap, _, _| Request::Consume {
            request_id: rid,
            cap_id: cap,
            operation: WireOperation::FileReadSnapshot { max_bytes: 64 },
        }),
        ("delegate", |rid, cap, to, obj| Request::Delegate {
            request_id: rid,
            cap_id: cap,
            recipient: to,
            child_scope: read_scope(obj),
            child_budget: WireBudget::Finite(1),
            child_depth: WireDepth::Finite(0),
            child_expiry: WireExpiry::Inherit,
        }),
        ("attenuate", |rid, cap, _, obj| Request::Attenuate {
            request_id: rid,
            cap_id: cap,
            reduced_scope: read_scope(obj),
            budget: WireBudget::Finite(1),
            depth: WireDepth::Finite(0),
            expiry: WireExpiry::Inherit,
        }),
        ("transfer", |rid, cap, to, _| Request::Transfer {
            request_id: rid,
            cap_id: cap,
            recipient: to,
        }),
        ("drop", |rid, cap, _, _| Request::Drop {
            request_id: rid,
            cap_id: cap,
        }),
        ("revoke", |rid, cap, _, _| Request::Revoke {
            request_id: rid,
            cap_id: cap,
        }),
        ("inspect", |_, cap, _, _| Request::Inspect { cap_id: cap }),
    ];
    let mut rid = 100u128;
    for (op_name, op) in ops {
        let mut answers = Vec::new();
        for (target, cap) in targets {
            rid += 1;
            let r = attacker.call(op(rid, cap, to, obj));
            let Response::Error { code, detail, .. } = r else {
                panic!("{op_name} on {target}: {r:?}")
            };
            answers.push((target, code, detail.as_str().to_owned()));
        }
        for (target, code, detail) in &answers {
            assert_eq!(
                (code, detail.as_str()),
                (&ErrorCode::UnknownCapability, "UnknownCapability"),
                "{op_name} on {target} differs: {answers:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------
// Finding 9: resetting the authenticator session refunded the approval
// rate window.
// ---------------------------------------------------------------------

#[test]
fn finding9_rate_window_survives_credential_rotation() {
    let mut h = Harness::new();
    h.config.approval_max_per_window = 1;
    let clock = ManualClock::new();
    let b = h.start_with_clock(Arc::new(clock.clone()));
    h.enroll(&b);
    let obj = register_file(&b, "notes.txt");
    let mut a = Agent::attach(&b);
    a.send(grant_req(1, obj));
    let ticket = wait_pending(&b);
    assert_eq!(b.admin(AdminRequest::Deny { ticket }), AdminResponse::Ok);
    assert_eq!(
        code(&a.recv().unwrap().response),
        Some(ErrorCode::ApprovalDenied)
    );
    // Rotating the credential replaces the approval session.
    h.enroll(&b);
    a.send(grant_req(2, obj));
    let m = a.recv_any().unwrap();
    let m = if matches!(m.response, Response::GrantPending { .. }) {
        a.recv().unwrap()
    } else {
        m
    };
    assert_eq!(code(&m.response), Some(ErrorCode::RateLimited));
    clock.advance(h.config.approval_rate_window_ms + 1);
    a.send(grant_req(3, obj));
    wait_pending(&b);
}

// ---------------------------------------------------------------------
// Unconfirmed finding: a slow adapter endpoint used by one principal could
// occupy every dispatch worker.
// ---------------------------------------------------------------------

/// Executor that holds every job of one principal until released, and
/// records how many of that principal's jobs ran at once.
struct Gate {
    inner: tessera_broker::AdapterExecutor,
    slow: std::sync::Mutex<Option<tessera_capability_core::AgentId>>,
    open: std::sync::Mutex<bool>,
    cv: std::sync::Condvar,
    running: std::sync::atomic::AtomicUsize,
    peak: std::sync::atomic::AtomicUsize,
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
        if Some(job.reservation.owner()) == *self.slow.lock().unwrap() {
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

#[test]
fn slow_principal_cannot_hold_every_dispatch_worker() {
    use std::sync::atomic::Ordering::SeqCst;
    let h = Harness::new();
    let config = tessera_broker::BrokerConfig {
        dispatch_workers: 4,
        max_dispatch_per_agent: 2,
        ..tessera_broker::BrokerConfig::default()
    };
    assert!(config.max_dispatch_per_agent < config.dispatch_workers);
    let gate = Arc::new(Gate {
        inner: tessera_broker::AdapterExecutor::new(Some(h.root.path())).unwrap(),
        slow: std::sync::Mutex::new(None),
        open: std::sync::Mutex::new(false),
        cv: std::sync::Condvar::new(),
        running: Default::default(),
        peak: Default::default(),
    });
    let journal = Journal::open_storage(h.storage.clone(), JournalOptions::default()).unwrap();
    let b = tessera_broker::Broker::start(
        journal,
        config,
        tessera_broker::Services {
            executor: gate.clone(),
            spawner: None,
            audit: tessera_broker::AuditLog::memory(),
            clock: Arc::new(tessera_broker::MonotonicClock::default()),
            fault: None,
        },
    )
    .unwrap();
    let obj = register_file(&b, "notes.txt");
    let mut slow = Agent::attach(&b);
    let mut victim = Agent::attach(&b);
    *gate.slow.lock().unwrap() = Some(slow.id);
    let cap = unlimited_baseline(&b, slow.id, obj);
    let vcap = baseline(&b, victim.id, obj, 1, 0);
    let corrs: Vec<u64> = (1..=6u128)
        .map(|rid| {
            slow.send(Request::Consume {
                request_id: rid,
                cap_id: cap,
                operation: WireOperation::FileReadSnapshot { max_bytes: 64 },
            })
        })
        .collect();
    // Wait until the slow principal holds every slot it may hold.
    for _ in 0..500 {
        if gate.running.load(SeqCst) == 2 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert_eq!(gate.running.load(SeqCst), 2);
    // The remaining four are reserved but not marked dispatched.
    let statuses: Vec<String> = reservations(&b).into_iter().map(|r| r.status).collect();
    assert_eq!(statuses.iter().filter(|s| *s == "dispatched").count(), 2);
    assert_eq!(statuses.iter().filter(|s| *s == "reserved").count(), 4);
    // Another principal is still served promptly.
    assert_eq!(snapshot(&victim.read(1, vcap)), b"top secret notes");

    *gate.open.lock().unwrap() = true;
    gate.cv.notify_all();
    let mut answered = Vec::new();
    for _ in &corrs {
        let m = slow.recv().unwrap();
        assert_eq!(snapshot(&m.response), b"top secret notes");
        answered.push(m.correlation_id);
    }
    answered.sort_unstable();
    assert_eq!(answered, corrs);
    assert_eq!(gate.peak.load(SeqCst), 2, "never more than the cap at once");
}

#[test]
fn terminating_a_principal_fails_its_undispatched_jobs() {
    use std::sync::atomic::Ordering::SeqCst;
    let h = Harness::new();
    let gate = Arc::new(Gate {
        inner: tessera_broker::AdapterExecutor::new(Some(h.root.path())).unwrap(),
        slow: std::sync::Mutex::new(None),
        open: std::sync::Mutex::new(false),
        cv: std::sync::Condvar::new(),
        running: Default::default(),
        peak: Default::default(),
    });
    let journal = Journal::open_storage(h.storage.clone(), JournalOptions::default()).unwrap();
    let b = tessera_broker::Broker::start(
        journal,
        tessera_broker::BrokerConfig {
            max_dispatch_per_agent: 1,
            ..tessera_broker::BrokerConfig::default()
        },
        tessera_broker::Services {
            executor: gate.clone(),
            spawner: None,
            audit: tessera_broker::AuditLog::memory(),
            clock: Arc::new(tessera_broker::MonotonicClock::default()),
            fault: None,
        },
    )
    .unwrap();
    let obj = register_file(&b, "notes.txt");
    let mut slow = Agent::attach(&b);
    *gate.slow.lock().unwrap() = Some(slow.id);
    let cap = unlimited_baseline(&b, slow.id, obj);
    for rid in 1..=3u128 {
        slow.send(Request::Consume {
            request_id: rid,
            cap_id: cap,
            operation: WireOperation::FileReadSnapshot { max_bytes: 64 },
        });
    }
    for _ in 0..500 {
        if gate.running.load(SeqCst) == 1 && reservations(&b).len() == 3 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert_eq!(
        b.admin(AdminRequest::TerminatePrincipal { agent: slow.id }),
        AdminResponse::Ok
    );
    let statuses: Vec<String> = reservations(&b).into_iter().map(|r| r.status).collect();
    assert_eq!(statuses, ["dispatched", "failed", "failed"]);
    *gate.open.lock().unwrap() = true;
    gate.cv.notify_all();
    for _ in 0..500 {
        if reservations(&b)[0].status == "completed" {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert_eq!(reservations(&b)[0].status, "completed");
    assert_eq!(gate.peak.load(SeqCst), 1);
}
