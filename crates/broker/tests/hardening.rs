//! Hardening tests: revoke-vs-consume linearization, pending/denied grant
//! request ids, untrusted descriptions, capability discovery, agent spawn
//! (domain, quotas, idempotency, cascade), admission control and the audit
//! hash chain.

mod common;

use std::collections::{BTreeMap, HashMap};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use common::*;
use tessera_broker::entry::Entry;
use tessera_broker::{
    AdminRequest, AdminResponse, AgentSpawnProfile, AuditLog, BaselineGrant, Broker, SandboxSpawner,
};
use tessera_capability_core::{AdminCommand, AgentCommand, AgentId, AuthenticatedCommand};
use tessera_journal::{Journal, JournalOptions, RecordKind};
use tessera_protocol::bounded::BoundedString;
use tessera_protocol::*;

// ---------------------------------------------------------------------
// 1. Revoke vs consume
// ---------------------------------------------------------------------

/// What the journal says happened, in commit order.
#[derive(Debug, Default)]
struct Trace {
    /// Journal seq of every Consume by `consumer`, by request id.
    consumes: BTreeMap<u128, u64>,
    /// Journal seqs of dispatch markers.
    dispatched: Vec<u64>,
    /// Journal seqs of revokes of `target`.
    revokes: Vec<u64>,
}

fn trace(h: &Harness, consumer: AgentId, target: u128) -> Trace {
    let mut j = Journal::open_storage(h.storage.clone(), JournalOptions::default()).unwrap();
    let mut t = Trace::default();
    for rec in j.replay() {
        let rec = rec.unwrap();
        if rec.kind != RecordKind::Data {
            continue;
        }
        match Entry::decode(&rec.payload).unwrap() {
            Entry::Command { command, .. } => match command {
                AuthenticatedCommand::Agent {
                    caller,
                    command: AgentCommand::Consume { request_id, .. },
                } if caller == consumer => {
                    t.consumes.insert(request_id.to_raw(), rec.seq);
                }
                AuthenticatedCommand::Agent {
                    command: AgentCommand::Revoke { capability },
                    ..
                }
                | AuthenticatedCommand::Operator(AdminCommand::Revoke { capability })
                    if capability.to_raw() == target =>
                {
                    t.revokes.push(rec.seq);
                }
                _ => {}
            },
            Entry::Dispatched { .. } => t.dispatched.push(rec.seq),
            _ => {}
        }
    }
    t
}

/// Tiny deterministic PRNG (no extra dev-dependency).
fn jitter(seed: &mut u64) -> Duration {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    Duration::from_micros(*seed % 3000)
}

#[test]
fn revoke_vs_consume_race_matches_a_serial_order() {
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for round in 0..24 {
        let mut h = Harness::new();
        h.config.agent_rate_per_sec = 1_000_000;
        h.config.agent_rate_burst = 1_000_000;
        let b = h.start(None);
        let obj = register_file(&b, "notes.txt");
        let mut a = Agent::attach(&b);
        let mut bb = Agent::attach(&b);
        let parent = baseline(&b, a.id, obj, 100_000, 1);
        let child = match a.delegate(1, parent, bb.wire_id(), read_scope(obj), 50_000, 0) {
            Response::Delegated { child_cap_id, .. } => child_cap_id,
            other => panic!("{other:?}"),
        };
        // Odd rounds: the owner A revokes (agent path); even: the operator.
        let by_agent = round % 2 == 1;
        let (first_tx, first_rx) = std::sync::mpsc::channel::<()>();
        let delay = jitter(&mut seed);

        let results = thread::scope(|s| {
            let (a_ref, b_ref) = (&mut a, &b);
            let revoker = s.spawn(move || {
                first_rx.recv().unwrap();
                thread::sleep(delay);
                if by_agent {
                    let r = a_ref.call(Request::Revoke {
                        request_id: 2,
                        cap_id: parent,
                    });
                    assert!(matches!(r, Response::Revoked { .. }), "{r:?}");
                } else {
                    assert_eq!(
                        b_ref.admin(AdminRequest::Revoke { capability: parent }),
                        AdminResponse::Ok
                    );
                }
            });
            // B keeps 8 consumes in flight until one is refused as revoked.
            let mut results: BTreeMap<u128, Response> = BTreeMap::new();
            let mut next_rid = 1000u128;
            let mut outstanding = 0;
            let mut stop = false;
            let mut signalled = false;
            loop {
                while !stop && outstanding < 8 {
                    bb.send(Request::Consume {
                        request_id: next_rid,
                        cap_id: child,
                        operation: WireOperation::FileReadSnapshot { max_bytes: 64 },
                    });
                    next_rid += 1;
                    outstanding += 1;
                }
                if outstanding == 0 {
                    break;
                }
                let m = bb.recv().expect("response");
                outstanding -= 1;
                let rid = match &m.response {
                    Response::Consumed { request_id, .. } => {
                        if !signalled {
                            signalled = true;
                            let _ = first_tx.send(());
                        }
                        *request_id
                    }
                    Response::Error {
                        request_id: Some(r),
                        code: ErrorCode::Revoked,
                        ..
                    } => {
                        stop = true;
                        *r
                    }
                    other => panic!("unexpected {other:?}"),
                };
                results.insert(rid, m.response);
                assert!(next_rid < 20_000, "revoke never took effect");
            }
            revoker.join().unwrap();
            results
        });
        let consumer = bb.id;
        drop(a);
        drop(bb);
        let calls = h.calls.load(Ordering::SeqCst);
        b.shutdown();

        // Linearization witness: the journal order.
        let t = trace(&h, consumer, parent);
        assert_eq!(t.revokes.len(), 1, "exactly one revoke committed");
        let r = t.revokes[0];
        // (1) No consume was authorized after the revoke's commit.
        assert!(t.consumes.values().all(|s| *s < r), "consume after revoke");
        // (2) Nothing was handed to an adapter after the revoke's commit.
        assert!(t.dispatched.iter().all(|s| *s < r), "dispatch after revoke");
        assert_eq!(t.dispatched.len(), t.consumes.len());
        // (3) The adapter ran exactly the journaled reservations.
        assert_eq!(calls, t.consumes.len());
        // (4) Every answer matches that serial order: request ids are
        // decided in send order, so the outcomes are a run of successes
        // (each journaled before the revoke) followed only by `Revoked`
        // (none journaled).
        let mut seen_revoked = false;
        for (rid, resp) in &results {
            match resp {
                Response::Consumed { .. } => {
                    assert!(!seen_revoked, "success after a revoked answer (rid {rid})");
                    assert!(t.consumes.contains_key(rid), "success not journaled");
                }
                _ => {
                    seen_revoked = true;
                    assert!(!t.consumes.contains_key(rid), "denied but journaled");
                }
            }
        }
        assert!(seen_revoked);
        assert!(!t.consumes.is_empty());
    }
}

// ---------------------------------------------------------------------
// 2. Grant requests: pending signal, description, bound denials
// ---------------------------------------------------------------------

fn grant_req(rid: u128, obj: u64, budget: u64, desc: Option<&str>) -> Request {
    Request::RequestGrant {
        request_id: rid,
        requested_scope: read_scope(obj),
        budget: WireBudget::Finite(budget),
        depth: WireDepth::Finite(0),
        expiry: WireExpiry::Inherit,
        untrusted_description: desc.map(|d| BoundedString::new(d).unwrap()),
    }
}

fn pending_list(b: &Broker) -> Vec<tessera_broker::admin::PendingView> {
    match b.admin(AdminRequest::ListPending) {
        AdminResponse::Pending(p) => p,
        other => panic!("{other:?}"),
    }
}

#[test]
fn grant_pending_signal_description_and_consistent_repeats() {
    let mut h = Harness::new();
    let b = h.start(None);
    h.enroll(&b);
    let obj = register_file(&b, "notes.txt");
    let mut a = Agent::attach(&b);

    // A hostile description: terminal escapes, bidi override, newline.
    let desc = "routine\u{1b}[2J\nAPPROVED BY ADMIN \u{202e}evil";
    let c1 = a.send(grant_req(10, obj, 1, Some(desc)));
    let m = a.recv_any().unwrap();
    assert_eq!(m.correlation_id, c1);
    assert!(
        matches!(m.response, Response::GrantPending { request_id: 10, expires_in_millis } if expires_in_millis > 0),
        "{m:?}"
    );
    let p = pending_list(&b);
    assert_eq!(p.len(), 1);
    assert!(p[0].rendered.contains("UNTRUSTED"), "{}", p[0].rendered);
    assert!(
        !p[0].rendered.contains('\u{1b}'),
        "raw ESC reached the operator"
    );
    assert!(!p[0].rendered.contains('\u{202e}'), "raw bidi override");
    assert!(p[0].rendered.contains("\\u{001b}"));
    assert_eq!(p[0].untrusted_description.as_deref(), Some(desc));
    // The description is not part of what the operator signs.
    let signed = tessera_approval::GrantRequest::decode(&p[0].request).unwrap();
    assert!(!format!("{:?}", signed.fields()).contains("routine"));

    // Status query: same id, same content -> another GrantPending, no new
    // ticket; different content -> conflict.
    let c2 = a.send(grant_req(10, obj, 1, Some(desc)));
    let m = a.recv_any().unwrap();
    assert_eq!(m.correlation_id, c2);
    assert!(matches!(
        m.response,
        Response::GrantPending { request_id: 10, .. }
    ));
    assert_eq!(pending_list(&b).len(), 1);
    let r = a.call(grant_req(10, obj, 1, Some("different")));
    assert_eq!(code(&r), Some(ErrorCode::RequestIdConflict));

    let AdminResponse::Capability(cap) = h.approve(&b) else {
        panic!()
    };
    let mut got = [a.recv().unwrap(), a.recv().unwrap()];
    got.sort_by_key(|m| m.correlation_id);
    assert_eq!(got[0].correlation_id, c1);
    assert_eq!(got[1].correlation_id, c2);
    assert_eq!(granted(&got[0].response), cap);
    assert_eq!(granted(&got[1].response), cap);

    // Denied: a repeat of the id gets the same denial, no new prompt.
    a.send(grant_req(11, obj, 1, None));
    let t = wait_pending(&b);
    assert_eq!(b.admin(AdminRequest::Deny { ticket: t }), AdminResponse::Ok);
    assert_eq!(
        code(&a.recv().unwrap().response),
        Some(ErrorCode::ApprovalDenied)
    );
    for _ in 0..2 {
        let r = a.call(grant_req(11, obj, 1, None));
        assert_eq!(code(&r), Some(ErrorCode::ApprovalDenied), "{r:?}");
        assert!(pending_list(&b).is_empty(), "no new approval request");
    }
    let r = a.call(grant_req(11, obj, 2, None));
    assert_eq!(code(&r), Some(ErrorCode::RequestIdConflict));
    // Validation denials are bound as well.
    let r = a.call(grant_req(12, 999, 1, None));
    assert_eq!(code(&r), Some(ErrorCode::ScopeViolation));
    let _ = register_file(&b, "other.txt");
    let r = a.call(grant_req(12, 999, 1, None));
    assert_eq!(code(&r), Some(ErrorCode::ScopeViolation));

    // The audit trail records the description by length and digest only.
    let AdminResponse::Audit(ev) = b.admin(AdminRequest::Audit {
        since: 0,
        limit: 10_000,
    }) else {
        panic!()
    };
    let all = serde_json::to_string(&ev).unwrap();
    assert!(!all.contains("routine") && !all.contains("APPROVED BY"));
    assert!(all.contains(&format!("untrusted_description_len={}", desc.len())));
}

#[test]
fn timed_out_grant_request_id_is_answered_consistently() {
    let mut h = Harness::new();
    h.config.approval_timeout_ms = 150;
    let b = h.start(None);
    h.enroll(&b);
    let obj = register_file(&b, "notes.txt");
    let mut a = Agent::attach(&b);
    a.send(grant_req(1, obj, 1, None));
    assert_eq!(
        code(&a.recv().unwrap().response),
        Some(ErrorCode::ApprovalTimeout)
    );
    let r = a.call(grant_req(1, obj, 1, None));
    assert_eq!(code(&r), Some(ErrorCode::ApprovalTimeout));
    assert!(pending_list(&b).is_empty());
    // A fresh id is a fresh request.
    a.send(grant_req(2, obj, 1, None));
    wait_pending(&b);
}

// ---------------------------------------------------------------------
// 3. Capability discovery
// ---------------------------------------------------------------------

fn list(a: &mut Agent, after: Option<u128>) -> (Vec<WireCapabilityView>, bool) {
    match a.call(Request::ListCapabilities { after }) {
        Response::Capabilities { caps, more } => (caps.into_inner(), more),
        other => panic!("{other:?}"),
    }
}

#[test]
fn recipients_discover_their_capabilities() {
    let h = Harness::new();
    let b = h.start(None);
    let obj = register_file(&b, "notes.txt");
    let mut a = Agent::attach(&b);
    let mut bb = Agent::attach(&b);
    let parent = baseline(&b, a.id, obj, 5, 1);
    assert_eq!(list(&mut bb, None), (vec![], false));
    let child = match a.delegate(1, parent, bb.wire_id(), read_scope(obj), 2, 0) {
        Response::Delegated { child_cap_id, .. } => child_cap_id,
        other => panic!("{other:?}"),
    };
    // B sees exactly its child (not A's parent), and can use it.
    let (v, more) = list(&mut bb, None);
    assert!(!more);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].cap_id, child);
    assert_eq!(v[0].parent, Some(parent));
    assert_eq!(v[0].owner, bb.wire_id());
    assert_eq!(v[0].status, WireCapStatus::Live);
    assert_eq!(snapshot(&bb.read(2, v[0].cap_id)), b"top secret notes");
    let (va, _) = list(&mut a, None);
    assert_eq!(
        va.iter().map(|c| c.cap_id).collect::<Vec<_>>(),
        vec![parent]
    );
    // Revocation shows up in the listing.
    assert_eq!(
        b.admin(AdminRequest::Revoke { capability: parent }),
        AdminResponse::Ok
    );
    assert_eq!(list(&mut bb, None).0[0].status, WireCapStatus::Revoked);

    // Pagination: 70 more capabilities for A.
    let mut ids: Vec<u128> = (0..70).map(|_| baseline(&b, a.id, obj, 1, 0)).collect();
    ids.insert(0, parent);
    ids.sort_unstable();
    let (p1, more) = list(&mut a, None);
    assert!(more);
    assert_eq!(p1.len(), MAX_LIST);
    let (p2, more) = list(&mut a, Some(p1.last().unwrap().cap_id));
    assert!(!more);
    let all: Vec<u128> = p1.iter().chain(&p2).map(|c| c.cap_id).collect();
    assert_eq!(all, ids);
}

// ---------------------------------------------------------------------
// 4. Agent spawn
// ---------------------------------------------------------------------

#[derive(Clone, Default)]
struct FakeSpawner {
    ends: Arc<Mutex<HashMap<AgentId, OwnedFd>>>,
    spawns: Arc<AtomicUsize>,
    stops: Arc<Mutex<Vec<AgentId>>>,
}

impl SandboxSpawner for FakeSpawner {
    fn spawn(&mut self, agent: AgentId, profile: &str) -> Result<OwnedFd, String> {
        self.spawns.fetch_add(1, Ordering::SeqCst);
        match profile {
            "broken" => return Err("bwrap exploded".into()),
            "slow" => thread::sleep(Duration::from_millis(300)),
            _ => {}
        }
        let (mine, theirs) = tessera_protocol::unix::seqpacket_pair().unwrap();
        self.ends.lock().unwrap().insert(agent, theirs);
        Ok(mine)
    }
    fn stop(&mut self, agent: AgentId) {
        self.stops.lock().unwrap().push(agent);
        self.ends.lock().unwrap().remove(&agent);
    }
}

impl FakeSpawner {
    fn agent(&self, id: AgentId) -> Agent {
        let fd = self.ends.lock().unwrap().remove(&id).expect("spawned");
        Agent::from_fd(id, fd)
    }
}

fn spawn(a: &mut Agent, rid: u128, profile: u64) -> Response {
    a.call(Request::Spawn {
        request_id: rid,
        launch_profile: profile,
    })
}

fn spawned(r: &Response) -> AgentId {
    match r {
        Response::Spawned { agent, .. } => AgentId::new(agent.epoch as u64, agent.serial),
        other => panic!("expected Spawned, got {other:?}"),
    }
}

fn wire(a: AgentId) -> WireAgentId {
    WireAgentId {
        epoch: u128::from(a.epoch()),
        serial: a.serial(),
    }
}

fn principal_status(b: &Broker, a: AgentId) -> String {
    match b.admin(AdminRequest::ListPrincipals) {
        AdminResponse::Principals(p) => p
            .into_iter()
            .find(|p| p.agent == a)
            .map(|p| p.status)
            .unwrap_or_default(),
        other => panic!("{other:?}"),
    }
}

fn spawn_harness() -> (Harness, FakeSpawner, Broker) {
    let mut h = Harness::new();
    let prof = |p: &str, baseline: Vec<BaselineGrant>| AgentSpawnProfile {
        profile: p.into(),
        baseline,
    };
    h.config.spawn_profiles = BTreeMap::from([
        (
            1,
            prof(
                "worker",
                vec![BaselineGrant {
                    // Object 1 = the first registered file.
                    scope: read_scope(1),
                    budget: WireBudget::Finite(1),
                    depth: WireDepth::Finite(0),
                    expiry_ms: None,
                }],
            ),
        ),
        (2, prof("broken", vec![])),
        (3, prof("slow", vec![])),
    ]);
    h.config.max_children_per_agent = 3;
    h.config.max_spawn_depth = 2;
    h.config.max_domain_agents = 5;
    let sp = FakeSpawner::default();
    let b = h.start_full(
        h.storage.clone(),
        None,
        Some(Box::new(sp.clone())),
        AuditLog::memory(),
    );
    (h, sp, b)
}

#[test]
fn agent_spawn_is_idempotent_domain_bounded_and_baseline_only() {
    let (_h, sp, b) = spawn_harness();
    let obj = register_file(&b, "notes.txt");
    assert_eq!(obj, 1);
    let mut a = Agent::attach(&b);
    let a_cap = baseline(&b, a.id, obj, 10, 1);

    // Spawn; the same id again returns the same child, launches nothing.
    let r1 = spawn(&mut a, 5, 1);
    let c1 = spawned(&r1);
    assert_eq!(spawn(&mut a, 5, 1), r1);
    assert_eq!(sp.spawns.load(Ordering::SeqCst), 1);
    assert_eq!(
        code(&spawn(&mut a, 5, 3)),
        Some(ErrorCode::RequestIdConflict)
    );

    // The child holds exactly the profile's baseline, nothing of A's.
    let mut child = sp.agent(c1);
    let (caps, _) = list(&mut child, None);
    assert_eq!(caps.len(), 1);
    assert_ne!(caps[0].cap_id, a_cap);
    assert_eq!(caps[0].budget_remaining, WireBudget::Finite(1));
    assert_eq!(
        code(&child.read(1, a_cap)),
        Some(ErrorCode::UnknownCapability)
    );
    // The parent can delegate to it by the returned id; the child finds
    // the delegation by listing.
    let d = a.delegate(6, a_cap, wire(c1), read_scope(obj), 2, 0);
    let delegated = match d {
        Response::Delegated { child_cap_id, .. } => child_cap_id,
        other => panic!("{other:?}"),
    };
    let (caps, _) = list(&mut child, None);
    assert!(caps.iter().any(|c| c.cap_id == delegated));
    assert_eq!(snapshot(&child.read(2, delegated)), b"top secret notes");

    // Unknown / non-agent profile; launch failure: bound, not retried.
    assert_eq!(code(&spawn(&mut a, 7, 99)), Some(ErrorCode::InvalidProfile));
    let before = sp.spawns.load(Ordering::SeqCst);
    assert_eq!(code(&spawn(&mut a, 8, 2)), Some(ErrorCode::InvalidProfile));
    assert_eq!(code(&spawn(&mut a, 8, 2)), Some(ErrorCode::InvalidProfile));
    assert_eq!(sp.spawns.load(Ordering::SeqCst), before + 1, "no relaunch");

    // A repeat while the launch is still running attaches to it.
    let c_slow1 = a.send(Request::Spawn {
        request_id: 9,
        launch_profile: 3,
    });
    let c_slow2 = a.send(Request::Spawn {
        request_id: 9,
        launch_profile: 3,
    });
    let mut got = [a.recv().unwrap(), a.recv().unwrap()];
    got.sort_by_key(|m| m.correlation_id);
    assert_eq!(
        (got[0].correlation_id, got[1].correlation_id),
        (c_slow1, c_slow2)
    );
    assert_eq!(got[0].response, got[1].response);
    let c_slow = spawned(&got[0].response);
    assert_eq!(sp.spawns.load(Ordering::SeqCst), before + 2);

    // Quotas: A has spawned 3 (c1, broken, slow) = max children.
    assert_eq!(code(&spawn(&mut a, 10, 1)), Some(ErrorCode::RateLimited));
    // Depth: the child (depth 1) may spawn; the grandchild (depth 2) not.
    let g = spawned(&spawn(&mut child, 20, 1));
    let mut grand = sp.agent(g);
    assert_eq!(
        code(&spawn(&mut grand, 21, 1)),
        Some(ErrorCode::PermissionDenied)
    );
    // Domain: A, c1, broken (terminated), slow, g = 5 = max.
    assert_eq!(
        code(&spawn(&mut child, 22, 1)),
        Some(ErrorCode::RateLimited)
    );
    // Another operator-created principal has its own domain.
    let mut other = Agent::attach(&b);
    let o1 = spawned(&spawn(&mut other, 1, 1));

    // Terminating A terminates its whole spawn tree, not other domains.
    assert_eq!(
        b.admin(AdminRequest::TerminatePrincipal { agent: a.id }),
        AdminResponse::Ok
    );
    for x in [a.id, c1, c_slow, g] {
        assert_eq!(principal_status(&b, x), "terminated", "{x:?}");
    }
    assert_eq!(principal_status(&b, o1), "active");
    // Stop requests reach the spawner thread asynchronously.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    for x in [c1, c_slow, g] {
        while !sp.stops.lock().unwrap().contains(&x) {
            assert!(
                std::time::Instant::now() < deadline,
                "sandbox of {x:?} not stopped"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }
    assert!(child.recv().is_none(), "child channel closed");
    assert!(grand.recv().is_none(), "grandchild channel closed");
}

#[test]
fn spawn_is_denied_without_profiles() {
    let h = Harness::new();
    let b = h.start(None);
    let mut a = Agent::attach(&b);
    assert_eq!(code(&spawn(&mut a, 1, 1)), Some(ErrorCode::InvalidProfile));
}

// ---------------------------------------------------------------------
// 5. Admission control
// ---------------------------------------------------------------------

#[test]
fn per_principal_rate_limit_and_in_flight_bound() {
    let mut h = Harness::new();
    h.config.agent_rate_per_sec = 1;
    h.config.agent_rate_burst = 5;
    let b = h.start(None);
    let mut a = Agent::attach(&b);
    let mut other = Agent::attach(&b);
    for _ in 0..20 {
        a.send(Request::Inspect { cap_id: 1 });
    }
    let mut limited = 0;
    for _ in 0..20 {
        match a.recv().unwrap().response {
            Response::Error {
                code: ErrorCode::RateLimited,
                ..
            } => limited += 1,
            Response::Error {
                code: ErrorCode::UnknownCapability,
                ..
            } => {}
            r => panic!("{r:?}"),
        }
    }
    assert!(limited >= 14, "only {limited} of 20 limited");
    // Another principal is unaffected.
    assert_eq!(
        code(&other.call(Request::Inspect { cap_id: 1 })),
        Some(ErrorCode::UnknownCapability)
    );

    // In flight: two pending grant requests occupy both slots.
    let mut h = Harness::new();
    h.config.max_in_flight_per_agent = 2;
    let b = h.start(None);
    h.enroll(&b);
    let obj = register_file(&b, "notes.txt");
    let mut a = Agent::attach(&b);
    for rid in [1, 2] {
        a.send(grant_req(rid, obj, 1, None));
        assert!(matches!(
            a.recv_any().unwrap().response,
            Response::GrantPending { .. }
        ));
    }
    let r = a.call(grant_req(3, obj, 1, None));
    assert_eq!(code(&r), Some(ErrorCode::RateLimited));
    // Not bound: once a slot frees, the same id is a fresh request.
    let t = wait_pending(&b);
    assert_eq!(b.admin(AdminRequest::Deny { ticket: t }), AdminResponse::Ok);
    assert_eq!(
        code(&a.recv().unwrap().response),
        Some(ErrorCode::ApprovalDenied)
    );
    a.send(grant_req(3, obj, 1, None));
    assert!(matches!(
        a.recv_any().unwrap().response,
        Response::GrantPending { request_id: 3, .. }
    ));
}

// ---------------------------------------------------------------------
// 6. Audit hash chain through the broker
// ---------------------------------------------------------------------

#[test]
fn broker_audit_log_is_chained_verifiable_and_content_free() {
    use tessera_broker::audit::{AuditCheckpoint, verify_file};
    let mut h = Harness::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let b = h.start_full(
        h.storage.clone(),
        None,
        None,
        AuditLog::open(&path).unwrap(),
    );
    h.enroll(&b);
    let obj = register_file(&b, "notes.txt");
    let mut a = Agent::attach(&b);
    let cap = baseline(&b, a.id, obj, 2, 0);
    assert_eq!(snapshot(&a.read(1, cap)), b"top secret notes");
    a.send(grant_req(2, obj, 1, Some("secret plan: exfiltrate")));
    let t = wait_pending(&b);
    b.admin(AdminRequest::Deny { ticket: t });
    let _ = a.recv();
    let AdminResponse::AuditCheckpoint { seq, hash } = b.admin(AdminRequest::AuditCheckpoint)
    else {
        panic!()
    };
    let cp = AuditCheckpoint::parse(&format!("{seq}:{hash}")).unwrap();
    // More events after the checkpoint.
    let _ = a.read(3, cap);
    b.shutdown();

    let v = verify_file(&path, Some(cp)).unwrap();
    assert!(v.events > seq);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains("top secret notes"), "file content in audit");
    assert!(!text.contains("exfiltrate"), "description in audit");
    // A restart continues the same chain.
    let b = h.start_full(
        h.storage.clone(),
        None,
        None,
        AuditLog::open(&path).unwrap(),
    );
    b.shutdown();
    let v2 = verify_file(&path, Some(cp)).unwrap();
    assert!(v2.events > v.events);
    // Rewriting an early line is detected against the checkpoint.
    let forged = text.replacen("register-file", "register-fil3", 1);
    std::fs::write(&path, forged).unwrap();
    assert!(verify_file(&path, Some(cp)).is_err());
}
