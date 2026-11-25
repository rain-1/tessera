//! Fault injection around commit, dispatch and response (WP3, §15, T10).
//!
//! The reactor is killed at a chosen point (it stops at once: no further
//! journal writes, no responses), the storage is replaced by what a crash
//! would leave (`LoseUnsynced`), and a fresh broker recovers from it.
//! Expected: no resurrected grants, no re-dispatch, unresolved reservations
//! reported as abandoned/unknown, spent nonces preserved.

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use common::*;
use tessera_broker::{AdminRequest, AdminResponse, FaultPoint, StopReason};
use tessera_journal::testing::CrashMode;
use tessera_protocol::*;

fn kill_at(p: FaultPoint) -> tessera_broker::FaultHook {
    Arc::new(move |q| q == p)
}

/// Run one consume that the reactor dies around; return (harness, expected
/// dispatches, recovered broker).
fn crash_consume(p: FaultPoint) -> (Harness, usize, tessera_broker::Broker, u128) {
    let h = Harness::new();
    let b = h.start(Some(kill_at(p)));
    let obj = register_file(&b, "notes.txt");
    let mut a = Agent::attach(&b);
    let cap = baseline(&b, a.id, obj, 2, 0);
    a.send(Request::Consume {
        request_id: 1,
        cap_id: cap,
        operation: WireOperation::FileReadSnapshot { max_bytes: 64 },
    });
    // No response is ever released after the kill.
    assert!(a.recv().is_none(), "channel closes without a response");
    let b_reason = b.wait();
    assert_eq!(b_reason, StopReason::Killed(p));
    let dispatched_before = h.calls.load(Ordering::SeqCst);
    let crashed = h.storage.crash(CrashMode::LoseUnsynced);
    let b2 = h.start_on(crashed, None);
    (h, dispatched_before, b2, cap)
}

fn only_reservation(b: &tessera_broker::Broker) -> Option<String> {
    let r = reservations(b);
    assert!(r.len() <= 1);
    r.first().map(|r| r.status.clone())
}

fn assert_no_resurrection(b: &tessera_broker::Broker, cap: u128) {
    assert_eq!(status(b).epoch, 2, "epoch bumped on restart");
    let c = common::cap(b, cap);
    assert!(
        c.status.contains("StaleEpoch"),
        "grant not live: {}",
        c.status
    );
    // No principal of the old epoch can act; a new one cannot use the id.
    let mut n = Agent::attach(b);
    assert_eq!(code(&n.read(1, cap)), Some(ErrorCode::UnknownCapability));
}

#[test]
fn crash_before_consume_commit() {
    let (h, before, b, cap) = crash_consume(FaultPoint::BeforeConsumeCommit);
    assert_eq!(before, 0);
    assert_eq!(only_reservation(&b), None, "nothing was durable");
    assert_eq!(common::cap(&b, cap).budget, "2", "no unit spent");
    assert_no_resurrection(&b, cap);
    assert_eq!(h.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn crash_after_consume_commit_before_marker() {
    let (h, before, b, cap) = crash_consume(FaultPoint::AfterConsumeCommit);
    assert_eq!(before, 0);
    assert_eq!(
        only_reservation(&b).as_deref(),
        Some("abandoned-not-dispatched")
    );
    assert_eq!(common::cap(&b, cap).budget, "1", "no refund");
    assert_no_resurrection(&b, cap);
    assert_eq!(h.calls.load(Ordering::SeqCst), 0, "never re-dispatched");
}

#[test]
fn crash_after_marker_before_dispatch() {
    let (h, before, b, cap) = crash_consume(FaultPoint::AfterDispatchMarker);
    assert_eq!(before, 0);
    // The marker is durable, so recovery cannot rule out an effect.
    assert_eq!(
        only_reservation(&b).as_deref(),
        Some("unknown-dispatched-before-restart")
    );
    assert_no_resurrection(&b, cap);
    assert_eq!(h.calls.load(Ordering::SeqCst), 0, "never re-dispatched");
}

#[test]
fn crash_after_dispatch_before_outcome() {
    let (h, before, b, cap) = crash_consume(FaultPoint::AfterDispatchBeforeOutcome);
    assert_eq!(before, 1);
    assert_eq!(
        only_reservation(&b).as_deref(),
        Some("unknown-dispatched-before-restart")
    );
    let AdminResponse::Status(s) = b.admin(AdminRequest::Status) else {
        panic!()
    };
    assert_eq!(s.uncertain_reservations, 1);
    assert_no_resurrection(&b, cap);
    assert_eq!(h.calls.load(Ordering::SeqCst), 1, "never re-dispatched");
    // The uncertainty is reported distinctly in the audit trail.
    let AdminResponse::Audit(ev) = b.admin(AdminRequest::Audit {
        since: 0,
        limit: 100,
    }) else {
        panic!()
    };
    assert!(ev.iter().any(|e| e.kind == "recovery"
        && e.effect.as_deref() == Some("unknown-dispatched-before-restart")));
}

#[test]
fn crash_after_outcome_before_response() {
    let (h, before, b, cap) = crash_consume(FaultPoint::AfterOutcomeBeforeResponse);
    assert_eq!(before, 1);
    assert_eq!(only_reservation(&b).as_deref(), Some("completed"));
    assert_no_resurrection(&b, cap);
    assert_eq!(h.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn journal_sync_failure_fails_closed() {
    let h = Harness::new();
    let b = h.start(None);
    let obj = register_file(&b, "notes.txt");
    let mut a = Agent::attach(&b);
    let cap = baseline(&b, a.id, obj, 2, 0);
    h.storage.fail_syncs(true);
    a.send(Request::Consume {
        request_id: 1,
        cap_id: cap,
        operation: WireOperation::FileReadSnapshot { max_bytes: 64 },
    });
    assert!(a.recv().is_none());
    assert!(matches!(b.wait(), StopReason::JournalFailure(_)));
    assert_eq!(h.calls.load(Ordering::SeqCst), 0, "nothing dispatched");
    let b2 = h.start_on(h.storage.crash(CrashMode::LoseUnsynced), None);
    assert_eq!(only_reservation(&b2), None);
    assert_eq!(common::cap(&b2, cap).budget, "2");
}

#[test]
fn torn_tail_is_recovered() {
    let h = Harness::new();
    let b = h.start(None);
    let obj = register_file(&b, "notes.txt");
    let a = Agent::attach(&b);
    let cap = baseline(&b, a.id, obj, 2, 0);
    drop(a);
    drop(b);
    // Half of an un-synced record survives, or a zero-filled extension.
    for mode in [
        CrashMode::KeepUnsyncedPrefix(7),
        CrashMode::ZeroFilledTail(64),
    ] {
        let b2 = h.start_on(h.storage.crash(mode), None);
        assert!(common::cap(&b2, cap).status.contains("StaleEpoch"));
    }
}

fn mint_crash(p: FaultPoint) -> (Harness, tessera_broker::Broker) {
    let mut h = Harness::new();
    let b = h.start(Some(kill_at(p)));
    h.enroll(&b);
    let obj = register_file(&b, "notes.txt");
    let mut a = Agent::attach(&b);
    a.request_grant(1, read_scope(obj), 2, 0);
    let ticket = wait_pending(&b);
    let asr = h.assertion_for(&b, ticket);
    let r = b.admin(AdminRequest::Approve {
        ticket,
        credential_id: asr.credential_id,
        authenticator_data: asr.authenticator_data,
        signature: asr.signature,
    });
    assert!(
        matches!(r, AdminResponse::Error(_)),
        "killed before replying"
    );
    assert!(a.recv().is_none(), "agent never told");
    assert_eq!(b.wait(), StopReason::Killed(p));
    let b2 = h.start_on(h.storage.crash(CrashMode::LoseUnsynced), None);
    (h, b2)
}

#[test]
fn crash_before_mint_commit_mints_nothing() {
    let (_h, b) = mint_crash(FaultPoint::BeforeMintCommit);
    assert!(caps(&b).is_empty());
    assert!(status(&b).enrolled, "enrollment is durable");
}

#[test]
fn crash_after_mint_commit_resurrects_no_grant() {
    let (_h, b) = mint_crash(FaultPoint::AfterMintCommit);
    let c = caps(&b);
    assert_eq!(c.len(), 1, "mint is durable history");
    assert_eq!(c[0].root_kind, "approved");
    assert!(c[0].status.contains("StaleEpoch"), "{}", c[0].status);
}
