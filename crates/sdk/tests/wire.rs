//! Wire-level tests of the SDK against a mock broker.

mod common;

use std::collections::HashMap;
use std::os::fd::AsFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{Kind, Reply, detail, fast_config, start, start_kind};
use tessera_protocol::bounded::{BoundedBytes, BoundedString, BoundedVec};
use tessera_protocol::{
    ClientMessage, ErrorCode, HttpMethod, PROTOCOL_VERSION, Request, Response, ServerMessage,
    WireAgentId, WireBudget, WireCapStatus, WireCapabilityView, WireDepth, WireExpiry,
    WireFileRights, WireHeader, WireHttpsRequest, WireMethodSet, WireOperation,
    WireOperationResult, WireReservationStatus, WireScope, encode_client, encode_server,
};
use tessera_sdk::{AgentId, ClientConfig, Consumed, Error, HttpsRequest, Terms};

const CAP: u128 = 0x1111_2222_3333_4444_5555_6666_7777_8888;
const CHILD: u128 = 0xc1;
const SELF_EPOCH: u128 = 0xdead_beef_dead_beef_dead_beef_dead_beef;

fn file_scope() -> WireScope {
    WireScope::File {
        object_id: 42,
        rights: WireFileRights {
            read_snapshot: true,
            replace_content: false,
        },
    }
}

fn https_scope() -> WireScope {
    WireScope::Https {
        endpoint_id: 9,
        methods: WireMethodSet {
            get: true,
            ..Default::default()
        },
        max_body_bytes: 0,
    }
}

fn view(cap: u128) -> WireCapabilityView {
    WireCapabilityView {
        cap_id: cap,
        root_id: 1,
        parent: None,
        owner: WireAgentId {
            epoch: SELF_EPOCH,
            serial: 77,
        },
        scope: file_scope(),
        budget_remaining: WireBudget::Finite(3),
        depth: WireDepth::Finite(1),
        expires_in_millis: Some(1000),
        status: WireCapStatus::Live,
    }
}

/// A canned success answer for every request kind.
fn ok(req: &Request) -> Response {
    match req.clone() {
        Request::RequestGrant { request_id, .. } => Response::GrantIssued {
            request_id,
            cap_id: CAP,
        },
        Request::Consume {
            request_id,
            operation,
            ..
        } => Response::Consumed {
            request_id,
            reservation_id: 5,
            result: match operation {
                WireOperation::FileReadSnapshot { .. } => WireOperationResult::FileSnapshot {
                    bytes: BoundedBytes::new(b"hello".to_vec()).unwrap(),
                    truncated: false,
                },
                WireOperation::FileReplaceContent { bytes } => WireOperationResult::FileReplaced {
                    bytes_written: bytes.len() as u64,
                },
                WireOperation::Https(_) => WireOperationResult::Https {
                    status: 200,
                    headers: BoundedVec::default(),
                    body: BoundedBytes::new(b"{}".to_vec()).unwrap(),
                    truncated: false,
                },
            },
        },
        Request::Delegate { request_id, .. } => Response::Delegated {
            request_id,
            child_cap_id: CHILD,
        },
        Request::Attenuate {
            request_id, cap_id, ..
        } => Response::Attenuated { request_id, cap_id },
        Request::Transfer {
            request_id, cap_id, ..
        } => Response::Transferred { request_id, cap_id },
        Request::Drop { request_id, .. } => Response::Dropped { request_id },
        Request::Inspect { cap_id } => Response::Inspected(view(cap_id)),
        Request::Spawn { request_id, .. } => Response::Spawned {
            request_id,
            agent: WireAgentId {
                epoch: 1,
                serial: 2,
            },
        },
        Request::Revoke { request_id, .. } => Response::Revoked { request_id },
        Request::ListCapabilities { .. } => Response::Capabilities {
            caps: BoundedVec::new(vec![view(CAP), view(CAP + 1)]).unwrap(),
            more: false,
        },
    }
}

fn echo() -> common::Mock {
    start(|m: &ClientMessage| vec![Reply::Respond(ok(&m.request))])
}

/// Every typed method produces exactly the specified wire message, with a
/// strictly canonical encoding, and parses the matching response.
#[test]
fn exact_wire_messages() {
    let mock = echo();
    let c = &mock.client;
    let recipient = AgentId::new(0xabc, 9);
    let terms = Terms::new(https_scope(), 100)
        .depth(2)
        .expires_within_millis(60_000);

    assert_eq!(
        c.request_grant_with_id(1, terms, Some("ignored")).unwrap(),
        CAP
    );
    let snap = c.read_file_with_id(2, CAP, 4096).unwrap();
    assert_eq!(snap.bytes, b"hello");
    assert_eq!(c.replace_file_with_id(3, CAP, b"new".to_vec()).unwrap(), 3);
    let req = HttpsRequest {
        method: HttpMethod::Post,
        path: "/v1/x?y=1".into(),
        headers: vec![("content-type".into(), b"application/json".to_vec())],
        body: b"{}".to_vec(),
    };
    let resp = c.https_request_with_id(4, CAP, req).unwrap();
    assert_eq!((resp.status, resp.body.as_slice()), (200, &b"{}"[..]));
    assert_eq!(
        c.delegate_with_id(5, CAP, recipient, Terms::new(https_scope(), 30).depth(1))
            .unwrap(),
        CHILD
    );
    c.attenuate_with_id(6, CAP, Terms::new(https_scope(), 1))
        .unwrap();
    c.transfer_with_id(7, CAP, recipient).unwrap();
    c.drop_with_id(8, CAP).unwrap();
    assert_eq!(c.inspect(CAP).unwrap(), view(CAP));
    assert_eq!(c.spawn_with_id(9, 3).unwrap(), AgentId::new(1, 2));
    c.revoke_with_id(10, CAP).unwrap();
    let listed = c.list_capabilities().unwrap();
    assert_eq!(listed, vec![view(CAP), view(CAP + 1)]);

    let expected = vec![
        Request::RequestGrant {
            request_id: 1,
            requested_scope: https_scope(),
            budget: WireBudget::Finite(100),
            depth: WireDepth::Finite(2),
            expiry: WireExpiry::WithinMillis(60_000),
            untrusted_description: Some(BoundedString::new("ignored").unwrap()),
        },
        Request::Consume {
            request_id: 2,
            cap_id: CAP,
            operation: WireOperation::FileReadSnapshot { max_bytes: 4096 },
        },
        Request::Consume {
            request_id: 3,
            cap_id: CAP,
            operation: WireOperation::FileReplaceContent {
                bytes: BoundedBytes::new(b"new".to_vec()).unwrap(),
            },
        },
        Request::Consume {
            request_id: 4,
            cap_id: CAP,
            operation: WireOperation::Https(WireHttpsRequest {
                method: HttpMethod::Post,
                path: BoundedString::new("/v1/x?y=1").unwrap(),
                headers: BoundedVec::new(vec![WireHeader {
                    name: BoundedString::new("content-type").unwrap(),
                    value: BoundedBytes::new(b"application/json".to_vec()).unwrap(),
                }])
                .unwrap(),
                body: BoundedBytes::new(b"{}".to_vec()).unwrap(),
            }),
        },
        Request::Delegate {
            request_id: 5,
            cap_id: CAP,
            recipient: recipient.0,
            child_scope: https_scope(),
            child_budget: WireBudget::Finite(30),
            child_depth: WireDepth::Finite(1),
            child_expiry: WireExpiry::Inherit,
        },
        Request::Attenuate {
            request_id: 6,
            cap_id: CAP,
            reduced_scope: https_scope(),
            budget: WireBudget::Finite(1),
            depth: WireDepth::Finite(0),
            expiry: WireExpiry::Inherit,
        },
        Request::Transfer {
            request_id: 7,
            cap_id: CAP,
            recipient: recipient.0,
        },
        Request::Drop {
            request_id: 8,
            cap_id: CAP,
        },
        Request::Inspect { cap_id: CAP },
        Request::Spawn {
            request_id: 9,
            launch_profile: 3,
        },
        Request::Revoke {
            request_id: 10,
            cap_id: CAP,
        },
        Request::ListCapabilities { after: None },
    ];
    let got = mock.received();
    assert_eq!(got.len(), expected.len());
    for (i, (r, want)) in got.iter().zip(expected).enumerate() {
        assert_eq!(r.msg.request, want, "message {i}");
        // Correlation ids are sequential from 1.
        assert_eq!(r.msg.correlation_id, i as u64 + 1);
        // Byte-exact: version header + canonical body.
        assert_eq!(&r.raw[..2], &PROTOCOL_VERSION.to_be_bytes());
        assert_eq!(r.raw, encode_client(&r.msg).unwrap());
    }
}

#[test]
fn random_request_ids_are_fresh() {
    let mock = echo();
    for _ in 0..20 {
        mock.client.drop(CAP).unwrap();
    }
    let ids: std::collections::HashSet<_> = mock
        .requests()
        .iter()
        .map(|r| r.request_id().unwrap())
        .collect();
    assert_eq!(ids.len(), 20);
}

/// A broker that dispatches at most once per request id, and answers repeats
/// with `PriorReservation` (spec §5.2).
#[test]
fn request_id_reuse_returns_prior_reservation_never_new_effect() {
    let dispatches = Arc::new(Mutex::new(0u32));
    let d = dispatches.clone();
    let mut seen: HashMap<u128, u128> = HashMap::new();
    let mock = start(move |m: &ClientMessage| {
        let rid = m.request.request_id().unwrap();
        if let Some(res) = seen.get(&rid) {
            return vec![Reply::Respond(Response::PriorReservation {
                request_id: rid,
                reservation_id: *res,
                status: WireReservationStatus::Completed,
            })];
        }
        *d.lock().unwrap() += 1;
        seen.insert(rid, 100 + rid);
        vec![Reply::Respond(ok(&m.request))]
    });
    let c = &mock.client;
    let op = WireOperation::FileReadSnapshot { max_bytes: 10 };

    assert!(matches!(
        c.consume_with_id(77, CAP, op.clone()).unwrap(),
        Consumed::Executed { .. }
    ));
    assert_eq!(
        c.consume_with_id(77, CAP, op.clone()).unwrap(),
        Consumed::Prior {
            reservation_id: 177,
            status: WireReservationStatus::Completed
        }
    );
    // The convenience method surfaces the prior reservation as an error, not
    // as fake content.
    match c.read_file_with_id(77, CAP, 10) {
        Err(Error::PriorReservation {
            request_id: 77,
            reservation_id: 177,
            status: WireReservationStatus::Completed,
        }) => {}
        other => panic!("unexpected {other:?}"),
    }
    // The SDK resent the identical request each time.
    let reqs = mock.requests();
    assert_eq!(reqs.len(), 3);
    assert!(reqs.iter().all(|r| *r == reqs[0]));
    assert_eq!(*dispatches.lock().unwrap(), 1);
}

#[test]
fn every_error_code_maps_to_typed_error() {
    let codes = [
        ErrorCode::UnsupportedVersion,
        ErrorCode::Malformed,
        ErrorCode::LimitExceeded,
        ErrorCode::Unauthenticated,
        ErrorCode::PermissionDenied,
        ErrorCode::UnknownCapability,
        ErrorCode::Expired,
        ErrorCode::Revoked,
        ErrorCode::ScopeViolation,
        ErrorCode::NotSubset,
        ErrorCode::InsufficientBudget,
        ErrorCode::DepthExhausted,
        ErrorCode::ExpiryTooLate,
        ErrorCode::InvalidRecipient,
        ErrorCode::RequestIdConflict,
        ErrorCode::StaleEpoch,
        ErrorCode::ApprovalDenied,
        ErrorCode::ApprovalTimeout,
        ErrorCode::InvalidProfile,
        ErrorCode::RateLimited,
        ErrorCode::AdapterFailed,
        ErrorCode::EffectUnknown,
        ErrorCode::Unavailable,
        ErrorCode::Internal,
    ];
    let queue = Arc::new(Mutex::new(codes.to_vec()));
    let q = queue.clone();
    let mock = start(move |m: &ClientMessage| {
        let code = q.lock().unwrap().remove(0);
        vec![Reply::Respond(Response::Error {
            request_id: m.request.request_id(),
            code,
            detail: detail("nope"),
        })]
    });
    for code in codes {
        let e = mock.client.drop_with_id(5, CAP).unwrap_err();
        assert_eq!(e.code(), Some(code));
        assert_eq!(e.request_id(), Some(5));
        assert_eq!(e.outcome_uncertain(), code == ErrorCode::EffectUnknown);
        match e {
            Error::Broker(b) => assert_eq!(b.detail, "nope"),
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn wrong_response_kind_and_mismatched_ids_are_protocol_errors() {
    let mock = start(|m: &ClientMessage| {
        let rid = m.request.request_id().unwrap();
        match rid {
            1 => vec![Reply::Respond(Response::Dropped { request_id: 1 })],
            2 => vec![Reply::Respond(Response::Dropped { request_id: 999 })],
            _ => vec![Reply::Message(ServerMessage {
                correlation_id: 1_000,
                response: Response::Dropped { request_id: rid },
            })],
        }
    });
    let c = &mock.client;
    assert!(matches!(c.revoke_with_id(1, CAP), Err(Error::Protocol(_))));
    assert!(matches!(c.drop_with_id(2, CAP), Err(Error::Protocol(_))));
    assert!(matches!(c.drop_with_id(3, CAP), Err(Error::Protocol(_))));
}

#[test]
fn undecodable_and_wrong_version_responses_are_rejected() {
    let mock = start(|m: &ClientMessage| {
        let mut wrong_version = encode_server(&ServerMessage {
            correlation_id: m.correlation_id,
            response: Response::Dropped { request_id: 1 },
        })
        .unwrap();
        wrong_version[1] = 99;
        match m.request.request_id() {
            Some(1) => vec![Reply::Raw(wrong_version)],
            _ => vec![Reply::Raw(vec![0, 1, 0xff, 0xff, 0xff])],
        }
    });
    assert!(matches!(
        mock.client.drop_with_id(1, CAP),
        Err(Error::Protocol(_))
    ));
    assert!(matches!(
        mock.client.drop_with_id(2, CAP),
        Err(Error::Protocol(_))
    ));
}

#[test]
fn outbound_frame_limit_is_enforced_before_sending() {
    let config = ClientConfig {
        max_send_frame: 1024,
        ..fast_config()
    };
    let mock = start_kind(Kind::Seqpacket, config, |m: &ClientMessage| {
        vec![Reply::Respond(ok(&m.request))]
    });
    match mock.client.replace_file(CAP, vec![0u8; 2048]) {
        Err(Error::FrameTooLarge {
            outbound: true,
            max: 1024,
            ..
        }) => {}
        other => panic!("{other:?}"),
    }
    // Field bounds are checked locally too.
    let long_path = HttpsRequest::get("/".repeat(tessera_protocol::MAX_HTTP_PATH + 1));
    assert!(matches!(
        mock.client.https_request(CAP, long_path),
        Err(Error::InvalidArgument(_))
    ));
    // Nothing reached the broker; the channel still works.
    mock.client.drop(CAP).unwrap();
    assert_eq!(mock.requests().len(), 1);
}

#[test]
fn inbound_frame_limit_discards_oversized_datagram_and_channel_survives() {
    let config = ClientConfig {
        max_recv_frame: 256,
        ..fast_config()
    };
    let mock = start_kind(Kind::Seqpacket, config, |m: &ClientMessage| {
        let mut r = ok(&m.request);
        if let Response::Consumed { result, .. } = &mut r {
            *result = WireOperationResult::FileSnapshot {
                bytes: BoundedBytes::new(vec![7u8; 4096]).unwrap(),
                truncated: false,
            };
        }
        vec![Reply::Respond(r)]
    });
    match mock.client.read_file(CAP, 4096) {
        Err(Error::FrameTooLarge {
            outbound: false,
            len,
            max: 256,
        }) => assert!(len > 4096),
        other => panic!("{other:?}"),
    }
    mock.client.drop(CAP).unwrap();
}

/// A timed-out request is retried with the same id; the late answer to the
/// first attempt is recognised by its correlation id and discarded.
#[test]
fn timeout_then_idempotent_retry_discards_late_response() {
    let first: Arc<Mutex<Option<u64>>> = Arc::default();
    let f = first.clone();
    let mock = start(move |m: &ClientMessage| {
        let mut slot = f.lock().unwrap();
        match *slot {
            None => {
                *slot = Some(m.correlation_id);
                vec![] // stay silent: the client times out
            }
            Some(old) => vec![
                Reply::Message(ServerMessage {
                    correlation_id: old,
                    response: ok(&m.request),
                }),
                Reply::Respond(Response::PriorReservation {
                    request_id: m.request.request_id().unwrap(),
                    reservation_id: 5,
                    status: WireReservationStatus::Completed,
                }),
            ],
        }
    });
    let op = WireOperation::FileReadSnapshot { max_bytes: 1 };
    let e = mock
        .client
        .consume(CAP, op.clone())
        .expect_err("should time out");
    assert!(matches!(
        e,
        Error::Timeout {
            request_id: Some(_)
        }
    ));
    assert!(e.outcome_uncertain());
    let rid = e.request_id().unwrap();
    assert_eq!(
        mock.client.consume_with_id(rid, CAP, op).unwrap(),
        Consumed::Prior {
            reservation_id: 5,
            status: WireReservationStatus::Completed
        }
    );
    let reqs = mock.requests();
    assert_eq!(reqs[0], reqs[1]);
}

#[test]
fn grant_pending_switches_to_approval_timeout() {
    let config = ClientConfig {
        call_timeout: Duration::from_millis(50),
        approval_timeout: Duration::from_secs(5),
        ..ClientConfig::default()
    };
    let mock = start_kind(Kind::Seqpacket, config, |m: &ClientMessage| {
        let Request::RequestGrant { request_id, .. } = m.request else {
            return vec![Reply::Respond(ok(&m.request))];
        };
        vec![
            Reply::Respond(Response::GrantPending {
                request_id,
                expires_in_millis: 120_000,
            }),
            Reply::Sleep(Duration::from_millis(300)), // "operator touching key"
            Reply::Respond(ok(&m.request)),
        ]
    });
    let mut seen = Vec::new();
    assert_eq!(
        mock.client
            .request_grant_with_progress(7, Terms::new(file_scope(), 1), None, &mut |d| seen
                .push(d))
            .unwrap(),
        CAP
    );
    assert_eq!(seen, vec![Duration::from_secs(120)]);
    // The channel stays in step: the next call works.
    assert_eq!(mock.client.inspect(CAP).unwrap(), view(CAP));
}

#[test]
fn silent_broker_is_a_timeout_pending_broker_is_approval_pending() {
    let config = ClientConfig {
        call_timeout: Duration::from_millis(100),
        approval_timeout: Duration::from_millis(400),
        ..ClientConfig::default()
    };
    // No answer at all: the short call timeout applies (broker hung).
    let silent = start_kind(Kind::Seqpacket, config, |_| vec![]);
    let t = std::time::Instant::now();
    let e = silent
        .client
        .request_grant_with_id(1, Terms::new(file_scope(), 1), None)
        .unwrap_err();
    assert!(
        matches!(
            e,
            Error::Timeout {
                request_id: Some(1)
            }
        ),
        "{e:?}"
    );
    assert!(t.elapsed() < Duration::from_millis(350));

    // Acknowledged but undecided: ApprovalPending, uncertain, same id.
    let pending = start_kind(Kind::Seqpacket, config, |m: &ClientMessage| {
        if let Request::RequestGrant { request_id: 2, .. } = m.request {
            let request_id = 2;
            vec![Reply::Respond(Response::GrantPending {
                request_id,
                expires_in_millis: 60_000,
            })]
        } else {
            vec![Reply::Respond(ok(&m.request))]
        }
    });
    let e = pending
        .client
        .request_grant_with_id(2, Terms::new(file_scope(), 1), None)
        .unwrap_err();
    assert!(
        matches!(e, Error::ApprovalPending { request_id: 2 }),
        "{e:?}"
    );
    assert!(e.outcome_uncertain());
    assert_eq!(e.request_id(), Some(2));
    // The client is still usable.
    assert_eq!(pending.client.inspect(CAP).unwrap(), view(CAP));
}

#[test]
fn raw_interim_response_abandons_the_correlation() {
    // call_raw returns GrantPending; the final answer arriving later is
    // discarded instead of confusing the next call.
    let mock = start(|m: &ClientMessage| match &m.request {
        Request::RequestGrant { request_id, .. } => vec![
            Reply::Respond(Response::GrantPending {
                request_id: *request_id,
                expires_in_millis: 1,
            }),
            Reply::Respond(ok(&m.request)),
        ],
        other => vec![Reply::Respond(ok(other))],
    });
    let r = mock
        .client
        .call_raw(
            Request::RequestGrant {
                request_id: 3,
                requested_scope: file_scope(),
                budget: WireBudget::Finite(1),
                depth: WireDepth::Finite(0),
                expiry: WireExpiry::Inherit,
                untrusted_description: None,
            },
            Duration::from_secs(1),
        )
        .unwrap();
    assert!(matches!(r, Response::GrantPending { request_id: 3, .. }));
    assert_eq!(mock.client.inspect(CAP).unwrap(), view(CAP));
}

#[test]
fn description_is_bounded_and_list_is_validated() {
    let mock = echo();
    let long = "x".repeat(tessera_protocol::MAX_DESCRIPTION + 1);
    assert!(matches!(
        mock.client
            .request_grant(Terms::new(file_scope(), 1), Some(&long)),
        Err(Error::InvalidArgument(_))
    ));
    assert!(mock.received().is_empty(), "nothing sent");

    // A broker listing ids out of order (or looping) is a protocol error.
    let bad = start(|m: &ClientMessage| {
        vec![Reply::Respond(match &m.request {
            Request::ListCapabilities { .. } => Response::Capabilities {
                caps: BoundedVec::new(vec![view(5), view(5)]).unwrap(),
                more: true,
            },
            other => ok(other),
        })]
    });
    assert!(matches!(
        bad.client.list_capabilities(),
        Err(Error::Protocol(_))
    ));
    // Pagination follows the cursor.
    let paged = start(|m: &ClientMessage| {
        vec![Reply::Respond(match &m.request {
            Request::ListCapabilities { after: None } => Response::Capabilities {
                caps: BoundedVec::new(vec![view(1), view(2)]).unwrap(),
                more: true,
            },
            Request::ListCapabilities { after: Some(2) } => Response::Capabilities {
                caps: BoundedVec::new(vec![view(9)]).unwrap(),
                more: false,
            },
            other => panic!("unexpected {other:?}"),
        })]
    });
    let ids: Vec<u128> = paged
        .client
        .list_capabilities()
        .unwrap()
        .iter()
        .map(|v| v.cap_id)
        .collect();
    assert_eq!(ids, vec![1, 2, 9]);
}

#[test]
fn closed_channel_is_reported() {
    let mock = start(|_m: &ClientMessage| vec![Reply::Close]);
    let e = mock.client.drop(CAP).unwrap_err();
    assert!(matches!(e, Error::Closed), "{e:?}");
    assert!(e.outcome_uncertain());
}

/// The SDK never sends the caller's identity. The protocol has no field for
/// it. The only agent ids on the wire are explicit recipients. Even after
/// the client has seen its own id (in an `Inspect` owner field), the id
/// never appears in anything it sends.
#[test]
fn no_identity_claim_is_ever_sent() {
    let mock = echo();
    let c = &mock.client;
    let me = c.inspect(CAP).unwrap().owner;
    assert_eq!(me.epoch, SELF_EPOCH);
    let recipient = AgentId::new(0x5, 6);
    let t = Terms::new(file_scope(), 1);
    c.request_grant(t, Some("please")).unwrap();
    c.read_file(CAP, 10).unwrap();
    c.replace_file(CAP, b"x".to_vec()).unwrap();
    c.https_request(CAP, HttpsRequest::get("/")).unwrap();
    c.delegate(CAP, recipient, t).unwrap();
    c.attenuate(CAP, t).unwrap();
    c.transfer(CAP, recipient).unwrap();
    c.drop(CAP).unwrap();
    c.spawn(1).unwrap();
    c.revoke(CAP).unwrap();

    let me_bytes = SELF_EPOCH.to_le_bytes();
    for r in mock.received() {
        match &r.msg.request {
            Request::Delegate { recipient: who, .. } | Request::Transfer { recipient: who, .. } => {
                assert_eq!(*who, recipient.0)
            }
            _ => {}
        }
        // Not present in any encoding (postcard varint or raw LE).
        let mut varint = Vec::new();
        let mut v = SELF_EPOCH;
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                varint.push(b);
                break;
            }
            varint.push(b | 0x80);
        }
        assert!(!contains(&r.raw, &varint), "own epoch leaked: {:?}", r.msg);
        assert!(!contains(&r.raw, &me_bytes));
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// A broker message carrying a file descriptor is rejected and the
/// descriptor is closed.
#[test]
fn ancillary_data_from_peer_is_rejected() {
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
    use std::mem::MaybeUninit;

    let (client_fd, server_fd) = tessera_protocol::unix::seqpacket_pair().unwrap();
    let client = tessera_sdk::Client::from_fd_with(client_fd, fast_config()).unwrap();
    let t = std::thread::spawn(move || {
        let payload = tessera_protocol::unix::recv_packet(
            &server_fd,
            tessera_protocol::FrameLimits::default(),
        )
        .unwrap()
        .unwrap();
        let msg = tessera_protocol::decode_client(&payload, 1 << 20).unwrap();
        let reply = encode_server(&ServerMessage {
            correlation_id: msg.correlation_id,
            response: Response::Dropped {
                request_id: msg.request.request_id().unwrap(),
            },
        })
        .unwrap();
        let smuggled = std::fs::File::open("/dev/null").unwrap();
        let fds = [smuggled.as_fd()];
        let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        assert!(control.push(SendAncillaryMessage::ScmRights(&fds)));
        rustix::net::sendmsg(
            &server_fd,
            &[std::io::IoSlice::new(&reply)],
            &mut control,
            SendFlags::empty(),
        )
        .unwrap();
        server_fd
    });
    let e = client.drop(CAP).unwrap_err();
    assert!(matches!(e, Error::Protocol(_)), "{e:?}");
    drop(t.join().unwrap());
}

/// Secondary transport: length-prefixed frames on a stream socket.
#[test]
fn stream_transport_round_trip() {
    let mock = start_kind(Kind::Stream, fast_config(), |m: &ClientMessage| {
        vec![Reply::Respond(ok(&m.request))]
    });
    assert_eq!(
        mock.client.transport_kind(),
        tessera_sdk::TransportKind::Stream
    );
    assert_eq!(mock.client.inspect(CAP).unwrap(), view(CAP));
    assert_eq!(mock.client.read_file(CAP, 5).unwrap().bytes, b"hello");
}

/// On a stream, a frame that arrives in pieces across a timeout is kept and
/// completed on the next read.
#[test]
fn stream_partial_frame_survives_timeout() {
    use std::io::Write;
    let (client_fd, server_fd) = tessera_protocol::unix::stream_pair().unwrap();
    let client = tessera_sdk::Client::from_fd_with(
        client_fd,
        ClientConfig {
            call_timeout: Duration::from_millis(200),
            ..ClientConfig::default()
        },
    )
    .unwrap();
    let t = std::thread::spawn(move || {
        let mut r = tessera_protocol::unix::CheckedStream::new(server_fd.as_fd());
        let limits = tessera_protocol::FrameLimits::default();
        let p1 = tessera_protocol::read_frame(&mut r, limits)
            .unwrap()
            .unwrap();
        let m1 = tessera_protocol::decode_client(&p1, 1 << 20).unwrap();
        let frame = |m: &ClientMessage| {
            let p = encode_server(&ServerMessage {
                correlation_id: m.correlation_id,
                response: ok(&m.request),
            })
            .unwrap();
            let mut f = (p.len() as u32).to_be_bytes().to_vec();
            f.extend(p);
            f
        };
        let f1 = frame(&m1);
        let mut w = std::os::unix::net::UnixStream::from(server_fd.try_clone().unwrap());
        w.write_all(&f1[..3]).unwrap(); // half a header, then stall
        let p2 = tessera_protocol::read_frame(&mut r, limits)
            .unwrap()
            .unwrap();
        let m2 = tessera_protocol::decode_client(&p2, 1 << 20).unwrap();
        w.write_all(&f1[3..]).unwrap(); // late answer to #1
        w.write_all(&frame(&m2)).unwrap();
        server_fd
    });
    let e = client.drop_with_id(1, CAP).unwrap_err();
    assert!(matches!(
        e,
        Error::Timeout {
            request_id: Some(1)
        }
    ));
    client.drop_with_id(1, CAP).unwrap();
    drop(t.join().unwrap());
}

#[test]
fn client_is_shareable_across_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<tessera_sdk::Client>();
}
