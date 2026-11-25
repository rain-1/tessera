//! WP3 gate and §15 broker tests (in-process principals, real file adapter,
//! software authenticator, in-memory fault-injection journal).

mod common;

use std::os::fd::AsFd;
use std::sync::atomic::Ordering;
use std::thread;

use common::*;
use tessera_broker::{AdminRequest, AdminResponse};
use tessera_protocol::frame::FrameLimits;
use tessera_protocol::unix::send_packet;
use tessera_protocol::*;

#[test]
fn thousand_concurrent_attempts_on_budget_one_dispatch_exactly_once() {
    let mut h = Harness::new();
    // This test is about the single writer, not admission control: let all
    // 1,000 requests through the per-principal rate and in-flight limits.
    h.config.max_in_flight_per_agent = 2000;
    h.config.agent_rate_burst = 2000;
    let b = h.start(None);
    let obj = register_file(&b, "notes.txt");
    let mut a = Agent::attach(&b);
    let cap = baseline(&b, a.id, obj, 1, 0);

    // 20 threads x 50 attempts, all distinct request ids, on A's channel.
    let mut senders = Vec::new();
    for t in 0..20u128 {
        let fd = a.fd.try_clone().unwrap();
        senders.push(thread::spawn(move || {
            for i in 0..50u128 {
                let msg = ClientMessage {
                    correlation_id: (t * 1000 + i) as u64,
                    request: Request::Consume {
                        request_id: 10_000 + t * 1000 + i,
                        cap_id: cap,
                        operation: WireOperation::FileReadSnapshot { max_bytes: 64 },
                    },
                };
                send_packet(fd.as_fd(), &encode_client(&msg).unwrap(), limits()).unwrap();
            }
        }));
    }
    for s in senders {
        s.join().unwrap();
    }
    let mut ok = 0;
    let mut insufficient = 0;
    for _ in 0..1000 {
        let m = a.recv().expect("response");
        match m.response {
            Response::Consumed { .. } => ok += 1,
            Response::Error {
                code: ErrorCode::InsufficientBudget,
                ..
            } => insufficient += 1,
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(ok, 1);
    assert_eq!(insufficient, 999);
    assert_eq!(
        h.calls.load(Ordering::SeqCst),
        1,
        "exactly one adapter dispatch"
    );
    let _ = a.call(Request::Inspect { cap_id: cap });
    let AdminResponse::Accounts(acc) = b.admin(AdminRequest::Accounts) else {
        panic!()
    };
    assert_eq!((acc[0].initial, acc[0].consumed, acc[0].live), (1, 1, 0));
}

#[test]
fn request_id_dedup_with_budget_two() {
    let h = Harness::new();
    let b = h.start(None);
    let obj = register_file(&b, "notes.txt");
    let mut a = Agent::attach(&b);
    let other = Agent::attach(&b);
    let cap = baseline(&b, a.id, obj, 2, 1);

    let r1 = a.read(1, cap);
    assert_eq!(snapshot(&r1), b"top secret notes");
    // Same id, same content: prior status, no new dispatch, budget intact.
    let again = a.read(1, cap);
    assert!(matches!(
        again,
        Response::PriorReservation {
            request_id: 1,
            status: WireReservationStatus::Completed,
            ..
        }
    ));
    // Same id, different content: conflict.
    let conflict = a.call(Request::Consume {
        request_id: 1,
        cap_id: cap,
        operation: WireOperation::FileReadSnapshot { max_bytes: 2 },
    });
    assert_eq!(code(&conflict), Some(ErrorCode::RequestIdConflict));
    assert_eq!(h.calls.load(Ordering::SeqCst), 1);
    assert_eq!(cap_budget(&b, cap), "1", "budget 2 - one attempt");

    // Delegate is idempotent too: the same child id, one child only.
    let d1 = a.delegate(5, cap, other.wire_id(), read_scope(obj), 1, 0);
    let d2 = a.delegate(5, cap, other.wire_id(), read_scope(obj), 1, 0);
    assert_eq!(d1, d2);
    assert!(matches!(d1, Response::Delegated { .. }));
    assert_eq!(caps(&b).len(), 2);
    let d3 = a.delegate(5, cap, other.wire_id(), read_scope(obj), 0, 0);
    assert_eq!(code(&d3), Some(ErrorCode::RequestIdConflict));
}

fn cap_budget(b: &tessera_broker::Broker, id: u128) -> String {
    cap(b, id).budget
}

#[test]
fn copied_capability_id_from_another_principal_is_denied() {
    let h = Harness::new();
    let b = h.start(None);
    let obj = register_file(&b, "notes.txt");
    let a = Agent::attach(&b);
    let mut m = Agent::attach(&b);
    let cap = baseline(&b, a.id, obj, 3, 2);
    for r in [
        m.read(1, cap),
        m.delegate(2, cap, m.wire_id(), read_scope(obj), 1, 0),
        m.call(Request::Inspect { cap_id: cap }),
        m.call(Request::Drop {
            request_id: 3,
            cap_id: cap,
        }),
        m.call(Request::Revoke {
            request_id: 4,
            cap_id: cap,
        }),
        m.call(Request::Transfer {
            request_id: 5,
            cap_id: cap,
            recipient: m.wire_id(),
        }),
    ] {
        assert_eq!(code(&r), Some(ErrorCode::UnknownCapability), "{r:?}");
    }
    assert_eq!(h.calls.load(Ordering::SeqCst), 0);
    assert_eq!(cap_budget(&b, cap), "3");
    // And an unknown id looks exactly the same.
    assert_eq!(
        code(&m.read(9, 999_999)),
        Some(ErrorCode::UnknownCapability)
    );
}

#[test]
fn malformed_oversized_and_fd_passing_frames() {
    let h = Harness::new();
    let b = h.start(None);
    let obj = register_file(&b, "notes.txt");
    let mut good = Agent::attach(&b);
    let good_cap = baseline(&b, good.id, obj, 5, 0);

    // 1. Garbage body after a valid envelope + correlation id: typed error
    //    under the same correlation id, channel stays up.
    let mut a = Agent::attach(&b);
    let cap_a = baseline(&b, a.id, obj, 5, 0);
    let mut junk = PROTOCOL_VERSION.to_be_bytes().to_vec();
    junk.push(42); // correlation id 42 (varint)
    junk.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x0f, 0x01]);
    send_packet(a.fd.as_fd(), &junk, limits()).unwrap();
    let m = a.recv().unwrap();
    assert_eq!(m.correlation_id, 42);
    assert_eq!(code(&m.response), Some(ErrorCode::Malformed));
    // Unknown version.
    let mut v2 = 99u16.to_be_bytes().to_vec();
    v2.push(43);
    send_packet(a.fd.as_fd(), &v2, limits()).unwrap();
    assert_eq!(
        code(&a.recv().unwrap().response),
        Some(ErrorCode::UnsupportedVersion)
    );
    // Still usable.
    assert_eq!(snapshot(&a.read(1, cap_a)), b"top secret notes");

    // 2. Oversized datagram: discarded unread, channel closed, principal
    //    terminated (its identity is gone), nothing else affected.
    let big = vec![0u8; 300 * 1024];
    send_packet(a.fd.as_fd(), &big, FrameLimits::new(1 << 20)).unwrap();
    assert!(a.recv().is_none(), "channel closed");
    assert!(cap(&b, cap_a).status.contains("OwnerTerminated"));

    // 3. SCM_RIGHTS: the fd is closed by the broker, channel closed,
    //    principal terminated.
    let c = Agent::attach(&b);
    let cap_c = baseline(&b, c.id, obj, 5, 0);
    let (x, _y) = tessera_protocol::unix::seqpacket_pair().unwrap();
    let fds = [x.as_fd()];
    let mut space = [std::mem::MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut anc = rustix::net::SendAncillaryBuffer::new(&mut space);
    assert!(anc.push(rustix::net::SendAncillaryMessage::ScmRights(&fds)));
    let msg = ClientMessage {
        correlation_id: 1,
        request: Request::Inspect { cap_id: cap_c },
    };
    let payload = encode_client(&msg).unwrap();
    rustix::net::sendmsg(
        c.fd.as_fd(),
        &[std::io::IoSlice::new(&payload)],
        &mut anc,
        rustix::net::SendFlags::empty(),
    )
    .unwrap();
    assert!(c.recv().is_none(), "channel closed after fd passing");
    assert!(cap(&b, cap_c).status.contains("OwnerTerminated"));

    // The broker and other principals are unaffected; no authority grew.
    assert!(b.is_running());
    assert_eq!(snapshot(&good.read(1, good_cap)), b"top secret notes");
    assert_eq!(caps(&b).len(), 3);
}

#[test]
fn approval_flow_mutated_reused_and_narrowed() {
    let mut h = Harness::new();
    let b = h.start(None);
    h.enroll(&b);
    let obj = register_file(&b, "notes.txt");
    let mut a = Agent::attach(&b);

    // Mutated payload: the operator's assertion covers a different digest.
    let c1 = a.request_grant(1, read_scope(obj), 3, 0);
    let t1 = wait_pending(&b);
    let AdminResponse::Challenge(ch) = b.admin(AdminRequest::Challenge { ticket: t1 }) else {
        panic!()
    };
    let mut tampered = ch.client_data_hash;
    tampered[0] ^= 1;
    let bad = tessera_approval::Authenticator::get_assertion(
        &mut h.auth,
        &tessera_approval::AssertionRequest {
            rp_id: ch.rp_id.clone(),
            client_data_hash: tampered,
            credential_id: ch.credential_id.clone(),
            require_user_verification: false,
        },
    )
    .unwrap();
    let r = b.admin(AdminRequest::Approve {
        ticket: t1,
        credential_id: bad.credential_id,
        authenticator_data: bad.authenticator_data,
        signature: bad.signature,
    });
    assert!(matches!(r, AdminResponse::Error(_)), "{r:?}");
    let m = a.recv().unwrap();
    assert_eq!(m.correlation_id, c1);
    assert_eq!(code(&m.response), Some(ErrorCode::ApprovalDenied));
    assert!(caps(&b).is_empty(), "no mint");

    // Genuine approval, narrowed by the operator from 3 to 2 uses.
    let c2 = a.request_grant(2, read_scope(obj), 3, 0);
    let t2 = wait_pending(&b);
    let AdminResponse::Pending(p) = b.admin(AdminRequest::ListPending) else {
        panic!()
    };
    assert!(p[0].rendered.contains("TESSERA ROOT GRANT APPROVAL"));
    let orig = tessera_approval::GrantRequest::decode(&p[0].request).unwrap();
    let mut f = orig.fields().clone();
    f.budget.amount = tessera_approval::BudgetAmount::Finite(2);
    let narrowed = tessera_approval::GrantRequest::new(f.clone()).unwrap();
    assert_eq!(
        b.admin(AdminRequest::Narrow {
            ticket: t2,
            request: narrowed.encode()
        }),
        AdminResponse::Ok
    );
    // Expansion is refused.
    f.budget.amount = tessera_approval::BudgetAmount::Finite(9);
    let wider = tessera_approval::GrantRequest::new(f).unwrap();
    assert!(matches!(
        b.admin(AdminRequest::Narrow {
            ticket: t2,
            request: wider.encode()
        }),
        AdminResponse::Error(_)
    ));
    let good = h.assertion_for(&b, t2);
    let r = b.admin(AdminRequest::Approve {
        ticket: t2,
        credential_id: good.credential_id.clone(),
        authenticator_data: good.authenticator_data.clone(),
        signature: good.signature.clone(),
    });
    let AdminResponse::Capability(cap) = r else {
        panic!("{r:?}")
    };
    let m = a.recv().unwrap();
    assert_eq!(m.correlation_id, c2);
    assert_eq!(granted(&m.response), cap);
    assert_eq!(cap_budget(&b, cap), "2");
    assert_eq!(super_root_kind(&b, cap), "approved");

    // Reusing that assertion for a new request mints nothing.
    let c3 = a.request_grant(3, read_scope(obj), 1, 0);
    let t3 = wait_pending(&b);
    let r = b.admin(AdminRequest::Approve {
        ticket: t3,
        credential_id: good.credential_id.clone(),
        authenticator_data: good.authenticator_data.clone(),
        signature: good.signature.clone(),
    });
    assert!(matches!(r, AdminResponse::Error(_)));
    let m = a.recv().unwrap();
    assert_eq!(m.correlation_id, c3);
    assert_eq!(code(&m.response), Some(ErrorCode::ApprovalDenied));
    // ... and the old ticket is gone.
    assert!(matches!(
        b.admin(AdminRequest::Approve {
            ticket: t2,
            credential_id: good.credential_id,
            authenticator_data: good.authenticator_data,
            signature: good.signature,
        }),
        AdminResponse::Error(_)
    ));
    assert_eq!(caps(&b).len(), 1);

    // Operator denial.
    let c4 = a.request_grant(4, read_scope(obj), 1, 0);
    let t4 = wait_pending(&b);
    assert_eq!(
        b.admin(AdminRequest::Deny { ticket: t4 }),
        AdminResponse::Ok
    );
    let m = a.recv().unwrap();
    assert_eq!(
        (m.correlation_id, code(&m.response)),
        (c4, Some(ErrorCode::ApprovalDenied))
    );
}

fn super_root_kind(b: &tessera_broker::Broker, id: u128) -> String {
    cap(b, id).root_kind
}

#[test]
fn repeated_grant_request_attaches_and_returns_the_same_capability() {
    let mut h = Harness::new();
    let b = h.start(None);
    h.enroll(&b);
    let obj = register_file(&b, "notes.txt");
    let mut a = Agent::attach(&b);
    let c1 = a.request_grant(77, read_scope(obj), 1, 0);
    wait_pending(&b);
    let c2 = a.request_grant(77, read_scope(obj), 1, 0); // retry: attaches
    let AdminResponse::Pending(p) = b.admin(AdminRequest::ListPending) else {
        panic!()
    };
    assert_eq!(p.len(), 1, "one prompt only");
    let AdminResponse::Capability(cap) = h.approve(&b) else {
        panic!()
    };
    let mut got = [a.recv().unwrap(), a.recv().unwrap()];
    got.sort_by_key(|m| m.correlation_id);
    assert_eq!(got[0].correlation_id, c1);
    assert_eq!(got[1].correlation_id, c2);
    assert_eq!(granted(&got[0].response), cap);
    assert_eq!(granted(&got[1].response), cap);
    // After the mint, the same id returns the same grant; no second prompt.
    let c3 = a.request_grant(77, read_scope(obj), 1, 0);
    let m = a.recv().unwrap();
    assert_eq!((m.correlation_id, granted(&m.response)), (c3, cap));
    let AdminResponse::Pending(p) = b.admin(AdminRequest::ListPending) else {
        panic!()
    };
    assert!(p.is_empty());
    // Different content under the same id conflicts.
    a.request_grant(77, read_scope(obj), 2, 0);
    assert_eq!(
        code(&a.recv().unwrap().response),
        Some(ErrorCode::RequestIdConflict)
    );
    assert_eq!(caps(&b).len(), 1);
}

#[test]
fn end_to_end_two_principals_read_delegate_revoke() {
    let mut h = Harness::new();
    let b = h.start(None);
    h.enroll(&b);
    let obj = register_file(&b, "notes.txt");
    let mut a = Agent::attach(&b);
    let mut bb = Agent::attach(&b);

    // A gets one read, non-delegatable.
    a.request_grant(1, read_scope(obj), 1, 0);
    let AdminResponse::Capability(once) = h.approve(&b) else {
        panic!()
    };
    assert_eq!(granted(&a.recv().unwrap().response), once);
    assert_eq!(snapshot(&a.read(10, once)), b"top secret notes");
    assert_eq!(code(&a.read(11, once)), Some(ErrorCode::InsufficientBudget));
    // B cannot use A's id; A cannot delegate a depth-0 grant.
    assert_eq!(code(&bb.read(1, once)), Some(ErrorCode::UnknownCapability));
    assert_eq!(
        code(&a.delegate(12, once, bb.wire_id(), read_scope(obj), 1, 0)),
        Some(ErrorCode::DepthExhausted)
    );

    // Second approval: 3 uses, depth 1. A delegates 2 to B.
    a.request_grant(2, read_scope(obj), 3, 1);
    let AdminResponse::Capability(parent) = h.approve(&b) else {
        panic!()
    };
    assert_eq!(granted(&a.recv().unwrap().response), parent);
    let Response::Delegated { child_cap_id, .. } =
        a.delegate(13, parent, bb.wire_id(), read_scope(obj), 2, 0)
    else {
        panic!()
    };
    assert_eq!(snapshot(&bb.read(2, child_cap_id)), b"top secret notes");
    // B cannot delegate further (depth 0).
    assert_eq!(
        code(&bb.delegate(3, child_cap_id, a.wire_id(), read_scope(obj), 1, 0)),
        Some(ErrorCode::DepthExhausted)
    );

    // Operator revokes A's capability: B's child stops authorizing even
    // though it still has budget.
    assert_eq!(
        b.admin(AdminRequest::Revoke { capability: parent }),
        AdminResponse::Ok
    );
    assert_eq!(code(&bb.read(4, child_cap_id)), Some(ErrorCode::Revoked));
    assert_eq!(code(&a.read(14, parent)), Some(ErrorCode::Revoked));
    assert_eq!(h.calls.load(Ordering::SeqCst), 2);

    // Lineage view and audit trail.
    let AdminResponse::Caps(l) = b.admin(AdminRequest::Lineage {
        capability: child_cap_id,
    }) else {
        panic!()
    };
    assert_eq!(
        l.iter().map(|c| c.id).collect::<Vec<_>>(),
        vec![parent, child_cap_id]
    );
    let AdminResponse::Audit(ev) = b.admin(AdminRequest::Audit {
        since: 0,
        limit: 1000,
    }) else {
        panic!()
    };
    let effects: Vec<_> = ev.iter().filter(|e| e.kind == "effect").collect();
    assert_eq!(effects.len(), 2);
    assert!(effects.iter().all(|e| e.root.is_some()));
    let json = serde_json::to_string(&ev).unwrap();
    assert!(!json.contains("top secret"), "audit never holds content");
}

#[test]
fn agent_may_revoke_its_own_delegated_child_only() {
    let h = Harness::new();
    let b = h.start(None);
    let obj = register_file(&b, "notes.txt");
    let mut a = Agent::attach(&b);
    let mut bb = Agent::attach(&b);
    let root = baseline(&b, a.id, obj, 4, 2);
    let Response::Delegated { child_cap_id, .. } =
        a.delegate(1, root, bb.wire_id(), read_scope(obj), 2, 1)
    else {
        panic!()
    };
    // B may not revoke A's root (not its own, not below its own).
    assert_eq!(
        code(&bb.call(Request::Revoke {
            request_id: 1,
            cap_id: root
        })),
        Some(ErrorCode::UnknownCapability)
    );
    assert!(matches!(
        a.call(Request::Revoke {
            request_id: 2,
            cap_id: child_cap_id
        }),
        Response::Revoked { request_id: 2 }
    ));
    assert_eq!(code(&bb.read(5, child_cap_id)), Some(ErrorCode::Revoked));
    assert_eq!(snapshot(&a.read(3, root)), b"top secret notes");
}

#[test]
fn emergency_stop_invalidates_everything() {
    let h = Harness::new();
    let b = h.start(None);
    let obj = register_file(&b, "notes.txt");
    let a = Agent::attach(&b);
    let cap = baseline(&b, a.id, obj, 4, 0);
    let e0 = status(&b).epoch;
    assert_eq!(b.admin(AdminRequest::EmergencyStop), AdminResponse::Ok);
    assert_eq!(status(&b).epoch, e0 + 1);
    assert!(a.recv().is_none(), "channel closed");
    assert!(cap_status(&b, cap).contains("StaleEpoch"));
    // New principals work in the new epoch.
    let mut n = Agent::attach(&b);
    let c2 = baseline(&b, n.id, obj, 1, 0);
    assert_eq!(snapshot(&n.read(1, c2)), b"top secret notes");
}

fn cap_status(b: &tessera_broker::Broker, id: u128) -> String {
    cap(b, id).status
}

#[test]
fn admin_socket_is_operator_only_and_works() {
    let h = Harness::new();
    let b = h.start(None);
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("admin.sock");
    b.serve_admin(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let mut c = tessera_broker::AdminClient::connect(&path).unwrap();
    let AdminResponse::Status(s) = c.call(&AdminRequest::Status).unwrap() else {
        panic!()
    };
    assert_eq!(s.epoch, 1);
    // A group/world-writable socket directory is refused.
    let bad = tempfile::tempdir().unwrap();
    std::fs::set_permissions(bad.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(b.serve_admin(&bad.path().join("a.sock")).is_err());
}

#[test]
fn file_backed_journal_restart_resurrects_nothing() {
    let h = Harness::new();
    let state = tempfile::tempdir().unwrap();
    let jpath = state.path().join("journal");
    let start = |h: &Harness| {
        let journal = tessera_journal::Journal::open(&jpath).unwrap();
        let exec = Counting {
            inner: tessera_broker::AdapterExecutor::new(Some(h.root.path())).unwrap(),
            calls: std::sync::Arc::clone(&h.calls),
        };
        tessera_broker::Broker::start(
            journal,
            tessera_broker::BrokerConfig::default(),
            tessera_broker::Services {
                executor: std::sync::Arc::new(exec),
                spawner: None,
                audit: tessera_broker::AuditLog::open(&state.path().join("audit.jsonl")).unwrap(),
                clock: std::sync::Arc::new(tessera_broker::MonotonicClock::default()),
                fault: None,
            },
        )
        .unwrap()
    };
    let b = start(&h);
    let obj = register_file(&b, "notes.txt");
    let mut a = Agent::attach(&b);
    let cap = baseline(&b, a.id, obj, 5, 0);
    assert_eq!(snapshot(&a.read(1, cap)), b"top secret notes");
    assert_eq!(b.shutdown(), tessera_broker::StopReason::Shutdown);

    let b = start(&h);
    assert_eq!(status(&b).epoch, 2);
    let old = common::cap(&b, cap);
    assert_eq!(old.budget, "4", "history preserved");
    assert!(old.status.contains("StaleEpoch"), "{}", old.status);
    // The file slot is re-registered after an identity check and usable.
    let mut n = Agent::attach(&b);
    let c2 = baseline(&b, n.id, obj, 1, 0);
    assert_eq!(snapshot(&n.read(1, c2)), b"top secret notes");
    drop(b);
    // The audit log continues its sequence across restarts.
    let text = std::fs::read_to_string(state.path().join("audit.jsonl")).unwrap();
    let seqs: Vec<u64> = text
        .lines()
        .map(|l| {
            serde_json::from_str::<tessera_broker::AuditEvent>(l)
                .unwrap()
                .seq
        })
        .collect();
    assert!(seqs.windows(2).all(|w| w[1] == w[0] + 1));
}

#[test]
fn replace_updates_slot_identity_and_survives_restart() {
    let h = Harness::new();
    let b = h.start(None);
    let obj = register_file(&b, "notes.txt");
    let mut a = Agent::attach(&b);
    let cap = match b.admin(AdminRequest::InstallBaseline {
        agent: a.id,
        scope: WireScope::File {
            object_id: obj,
            rights: WireFileRights {
                read_snapshot: true,
                replace_content: true,
            },
        },
        budget: WireBudget::Finite(3),
        depth: WireDepth::Finite(0),
        expiry_ms: None,
    }) {
        AdminResponse::Capability(c) => c,
        o => panic!("{o:?}"),
    };
    let r = a.call(Request::Consume {
        request_id: 1,
        cap_id: cap,
        operation: WireOperation::FileReplaceContent {
            bytes: bounded::BoundedBytes::new(b"new content".to_vec()).unwrap(),
        },
    });
    assert!(matches!(
        r,
        Response::Consumed {
            result: WireOperationResult::FileReplaced { bytes_written: 11 },
            ..
        }
    ));
    drop(a);
    drop(b);
    let b = h.start(None);
    let mut n = Agent::attach(&b);
    let c2 = baseline(&b, n.id, obj, 1, 0);
    assert_eq!(snapshot(&n.read(1, c2)), b"new content");
}
