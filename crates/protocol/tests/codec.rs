//! Codec and framing tests: roundtrips, hostile input, limits.

use std::io::{self, Cursor, Read};

use proptest::prelude::*;
use tessera_protocol::bounded::{BoundedBytes, BoundedString, BoundedVec};
use tessera_protocol::codec::ENVELOPE_HEADER_LEN;
use tessera_protocol::frame::{FRAME_HEADER_LEN, HARD_MAX_FRAME};
use tessera_protocol::*;

// ---------- strategies ----------

fn agent() -> impl Strategy<Value = WireAgentId> {
    (any::<u128>(), any::<u64>()).prop_map(|(epoch, serial)| WireAgentId { epoch, serial })
}

fn budget() -> impl Strategy<Value = WireBudget> {
    prop_oneof![
        any::<u64>().prop_map(WireBudget::Finite),
        Just(WireBudget::Unlimited)
    ]
}

fn depth() -> impl Strategy<Value = WireDepth> {
    prop_oneof![
        any::<u32>().prop_map(WireDepth::Finite),
        Just(WireDepth::Unlimited)
    ]
}

fn expiry() -> impl Strategy<Value = WireExpiry> {
    prop_oneof![
        Just(WireExpiry::Inherit),
        any::<u64>().prop_map(WireExpiry::WithinMillis)
    ]
}

fn methods() -> impl Strategy<Value = WireMethodSet> {
    any::<[bool; 6]>().prop_map(|b| WireMethodSet {
        get: b[0],
        head: b[1],
        post: b[2],
        put: b[3],
        patch: b[4],
        delete: b[5],
    })
}

fn scope() -> impl Strategy<Value = WireScope> {
    prop_oneof![
        (any::<u64>(), any::<bool>(), any::<bool>()).prop_map(|(object_id, r, w)| {
            WireScope::File {
                object_id,
                rights: WireFileRights {
                    read_snapshot: r,
                    replace_content: w,
                },
            }
        }),
        (any::<u64>(), methods(), any::<u64>()).prop_map(
            |(endpoint_id, methods, max_body_bytes)| {
                WireScope::Https {
                    endpoint_id,
                    methods,
                    max_body_bytes,
                }
            }
        ),
    ]
}

fn method() -> impl Strategy<Value = HttpMethod> {
    prop_oneof![
        Just(HttpMethod::Get),
        Just(HttpMethod::Head),
        Just(HttpMethod::Post),
        Just(HttpMethod::Put),
        Just(HttpMethod::Patch),
        Just(HttpMethod::Delete),
    ]
}

fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..max)
}

fn headers() -> impl Strategy<Value = WireHeaders> {
    proptest::collection::vec(("[a-zA-Z-]{1,20}", bytes(40)), 0..5).prop_map(|hs| {
        BoundedVec::new(
            hs.into_iter()
                .map(|(n, v)| WireHeader {
                    name: BoundedString::new(n).unwrap(),
                    value: BoundedBytes::new(v).unwrap(),
                })
                .collect(),
        )
        .unwrap()
    })
}

fn operation() -> impl Strategy<Value = WireOperation> {
    prop_oneof![
        any::<u64>().prop_map(|max_bytes| WireOperation::FileReadSnapshot { max_bytes }),
        bytes(256).prop_map(|b| WireOperation::FileReplaceContent {
            bytes: BoundedBytes::new(b).unwrap()
        }),
        (method(), "\\PC{0,64}", headers(), bytes(256)).prop_map(
            |(method, path, headers, body)| {
                WireOperation::Https(WireHttpsRequest {
                    method,
                    path: BoundedString::new(path).unwrap(),
                    headers,
                    body: BoundedBytes::new(body).unwrap(),
                })
            }
        ),
    ]
}

fn request() -> impl Strategy<Value = Request> {
    let id = any::<u128>();
    prop_oneof![
        (
            id,
            scope(),
            budget(),
            depth(),
            expiry(),
            proptest::option::of("\\PC{0,60}")
        )
            .prop_map(|(request_id, requested_scope, budget, depth, expiry, d)| {
                Request::RequestGrant {
                    request_id,
                    requested_scope,
                    budget,
                    depth,
                    expiry,
                    untrusted_description: d.map(|d| BoundedString::new(d).unwrap()),
                }
            }),
        (id, any::<u128>(), operation()).prop_map(|(request_id, cap_id, operation)| {
            Request::Consume {
                request_id,
                cap_id,
                operation,
            }
        }),
        (
            id,
            any::<u128>(),
            agent(),
            scope(),
            budget(),
            depth(),
            expiry()
        )
            .prop_map(
                |(
                    request_id,
                    cap_id,
                    recipient,
                    child_scope,
                    child_budget,
                    child_depth,
                    child_expiry,
                )| {
                    Request::Delegate {
                        request_id,
                        cap_id,
                        recipient,
                        child_scope,
                        child_budget,
                        child_depth,
                        child_expiry,
                    }
                }
            ),
        (id, any::<u128>(), scope(), budget(), depth(), expiry()).prop_map(
            |(request_id, cap_id, reduced_scope, budget, depth, expiry)| Request::Attenuate {
                request_id,
                cap_id,
                reduced_scope,
                budget,
                depth,
                expiry
            }
        ),
        (id, any::<u128>(), agent()).prop_map(|(request_id, cap_id, recipient)| {
            Request::Transfer {
                request_id,
                cap_id,
                recipient,
            }
        }),
        (id, any::<u128>()).prop_map(|(request_id, cap_id)| Request::Drop { request_id, cap_id }),
        any::<u128>().prop_map(|cap_id| Request::Inspect { cap_id }),
        (id, any::<u64>()).prop_map(|(request_id, launch_profile)| Request::Spawn {
            request_id,
            launch_profile
        }),
        (id, any::<u128>()).prop_map(|(request_id, cap_id)| Request::Revoke { request_id, cap_id }),
        proptest::option::of(any::<u128>()).prop_map(|after| Request::ListCapabilities { after }),
    ]
}

fn error_code() -> impl Strategy<Value = ErrorCode> {
    use ErrorCode::*;
    proptest::sample::select(vec![
        UnsupportedVersion,
        Malformed,
        LimitExceeded,
        Unauthenticated,
        PermissionDenied,
        UnknownCapability,
        Expired,
        Revoked,
        ScopeViolation,
        NotSubset,
        InsufficientBudget,
        DepthExhausted,
        ExpiryTooLate,
        InvalidRecipient,
        RequestIdConflict,
        StaleEpoch,
        ApprovalDenied,
        ApprovalTimeout,
        InvalidProfile,
        RateLimited,
        AdapterFailed,
        EffectUnknown,
        Unavailable,
        Internal,
    ])
}

fn response() -> impl Strategy<Value = Response> {
    let id = any::<u128>();
    let status = proptest::sample::select(vec![
        WireReservationStatus::Reserved,
        WireReservationStatus::Dispatched,
        WireReservationStatus::Completed,
        WireReservationStatus::Unknown,
    ]);
    let result = prop_oneof![
        (bytes(128), any::<bool>()).prop_map(|(b, truncated)| WireOperationResult::FileSnapshot {
            bytes: BoundedBytes::new(b).unwrap(),
            truncated
        }),
        any::<u64>().prop_map(|bytes_written| WireOperationResult::FileReplaced { bytes_written }),
        (any::<u16>(), headers(), bytes(128), any::<bool>()).prop_map(
            |(status, headers, body, truncated)| {
                WireOperationResult::Https {
                    status,
                    headers,
                    body: BoundedBytes::new(body).unwrap(),
                    truncated,
                }
            }
        ),
    ];
    let view = || {
        (
            any::<u128>(),
            any::<u128>(),
            proptest::option::of(any::<u128>()),
            agent(),
            scope(),
            budget(),
            depth(),
            proptest::option::of(any::<u64>()),
        )
            .prop_map(
                |(
                    cap_id,
                    root_id,
                    parent,
                    owner,
                    scope,
                    budget_remaining,
                    depth,
                    expires_in_millis,
                )| {
                    WireCapabilityView {
                        cap_id,
                        root_id,
                        parent,
                        owner,
                        scope,
                        budget_remaining,
                        depth,
                        expires_in_millis,
                        status: WireCapStatus::Live,
                    }
                },
            )
    };
    prop_oneof![
        (id, any::<u128>())
            .prop_map(|(request_id, cap_id)| Response::GrantIssued { request_id, cap_id }),
        (id, any::<u128>(), result).prop_map(|(request_id, reservation_id, result)| {
            Response::Consumed {
                request_id,
                reservation_id,
                result,
            }
        }),
        (id, any::<u128>(), status).prop_map(|(request_id, reservation_id, status)| {
            Response::PriorReservation {
                request_id,
                reservation_id,
                status,
            }
        }),
        (id, any::<u128>()).prop_map(|(request_id, child_cap_id)| Response::Delegated {
            request_id,
            child_cap_id
        }),
        (id, any::<u128>())
            .prop_map(|(request_id, cap_id)| Response::Attenuated { request_id, cap_id }),
        (id, any::<u128>())
            .prop_map(|(request_id, cap_id)| Response::Transferred { request_id, cap_id }),
        id.prop_map(|request_id| Response::Dropped { request_id }),
        view().prop_map(Response::Inspected),
        (id, any::<u64>()).prop_map(|(request_id, expires_in_millis)| Response::GrantPending {
            request_id,
            expires_in_millis
        }),
        (proptest::collection::vec(view(), 0..5), any::<bool>()).prop_map(|(caps, more)| {
            Response::Capabilities {
                caps: BoundedVec::new(caps).unwrap(),
                more,
            }
        }),
        (id, agent()).prop_map(|(request_id, agent)| Response::Spawned { request_id, agent }),
        id.prop_map(|request_id| Response::Revoked { request_id }),
        (
            proptest::option::of(any::<u128>()),
            error_code(),
            "\\PC{0,40}"
        )
            .prop_map(|(request_id, code, d)| {
                Response::Error {
                    request_id,
                    code,
                    detail: BoundedString::new(d).unwrap(),
                }
            }),
    ]
}

const MAX: usize = frame::DEFAULT_MAX_FRAME;

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn client_roundtrip(correlation_id in any::<u64>(), request in request()) {
        let msg = ClientMessage { correlation_id, request };
        let p = encode_client(&msg).unwrap();
        prop_assert_eq!(&p[..2], &PROTOCOL_VERSION.to_be_bytes());
        prop_assert_eq!(decode_client(&p, MAX).unwrap(), msg);
    }

    #[test]
    fn server_roundtrip(correlation_id in any::<u64>(), response in response()) {
        let msg = ServerMessage { correlation_id, response };
        let p = encode_server(&msg).unwrap();
        prop_assert_eq!(decode_server(&p, MAX).unwrap(), msg);
    }

    #[test]
    fn frame_roundtrip(correlation_id in any::<u64>(), request in request()) {
        let msg = ClientMessage { correlation_id, request };
        let mut wire = Vec::new();
        send_message(&mut wire, &msg, FrameLimits::default()).unwrap();
        let mut r = Cursor::new(wire);
        let got: ClientMessage = recv_message(&mut r, FrameLimits::default()).unwrap().unwrap();
        prop_assert_eq!(got, msg);
        prop_assert!(recv_message::<_, ClientMessage>(&mut r, FrameLimits::default()).unwrap().is_none());
    }

    /// Arbitrary bytes never panic, and anything accepted is canonical.
    #[test]
    fn random_payload_never_panics(raw in proptest::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(m) = decode_client(&raw, MAX) {
            prop_assert_eq!(encode_client(&m).unwrap(), raw.clone());
        }
        if let Ok(m) = decode_server(&raw, MAX) {
            prop_assert_eq!(encode_server(&m).unwrap(), raw.clone());
        }
    }

    /// Same, but with a valid version header so the body parser is exercised.
    #[test]
    fn random_body_never_panics(body in proptest::collection::vec(any::<u8>(), 0..512)) {
        let mut raw = PROTOCOL_VERSION.to_be_bytes().to_vec();
        raw.extend_from_slice(&body);
        if let Ok(m) = decode_client(&raw, MAX) {
            prop_assert_eq!(encode_client(&m).unwrap(), raw.clone());
        }
        if let Ok(m) = decode_server(&raw, MAX) {
            prop_assert_eq!(encode_server(&m).unwrap(), raw.clone());
        }
    }

    /// Mutating a valid message never panics; result is error or canonical.
    #[test]
    fn mutated_message_never_panics(request in request(), idx in any::<prop::sample::Index>(), byte in any::<u8>()) {
        let mut p = encode_client(&ClientMessage { correlation_id: 7, request }).unwrap();
        let i = idx.index(p.len());
        p[i] = byte;
        if let Ok(m) = decode_client(&p, MAX) {
            prop_assert_eq!(encode_client(&m).unwrap(), p);
        }
    }

    #[test]
    fn random_stream_never_panics(raw in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let mut r = Cursor::new(raw);
        for _ in 0..8 {
            match recv_message::<_, ClientMessage>(&mut r, FrameLimits::new(256)) {
                Ok(Some(_)) => continue,
                _ => break,
            }
        }
    }
}

#[test]
fn unknown_version_rejected_before_body() {
    let msg = ClientMessage {
        correlation_id: 1,
        request: Request::Inspect { cap_id: 9 },
    };
    let mut p = encode_client(&msg).unwrap();
    for v in [0u16, 1, 3, 0xffff] {
        p[..2].copy_from_slice(&v.to_be_bytes());
        assert_eq!(
            decode_client(&p, MAX),
            Err(DecodeError::UnsupportedVersion(v))
        );
    }
    // Body need not even be parseable.
    assert_eq!(
        decode_client(&[0, 1, 0xff, 0xff], MAX),
        Err(DecodeError::UnsupportedVersion(1))
    );
    assert_eq!(decode_client(&[0], MAX), Err(DecodeError::Truncated));
    assert_eq!(decode_client(&[], MAX), Err(DecodeError::Truncated));
}

#[test]
fn trailing_bytes_and_overlong_varints_rejected() {
    let msg = ClientMessage {
        correlation_id: 0,
        request: Request::Inspect { cap_id: 0 },
    };
    let p = encode_client(&msg).unwrap();
    // version, corr=0, variant Inspect=6, cap_id=0
    assert_eq!(p, vec![0, 2, 0x00, 0x06, 0x00]);
    let mut trailing = p.clone();
    trailing.push(0);
    assert_eq!(
        decode_client(&trailing, MAX),
        Err(DecodeError::NonCanonical)
    );
    // Overlong encoding of correlation_id 0.
    let overlong = vec![0, 2, 0x80, 0x00, 0x06, 0x00];
    assert!(decode_client(&overlong, MAX).is_err());
}

#[test]
fn invalid_bool_and_enum_tag_rejected() {
    // RequestGrant(0), request_id 0, scope File(0), object 0, rights read=2(!), ...
    let bad_bool = vec![
        0, 2, 0, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x01, 0x00,
    ];
    assert_eq!(decode_client(&bad_bool, MAX), Err(DecodeError::Malformed));
    // Unknown Request variant 10 (9 is ListCapabilities).
    assert_eq!(
        decode_client(&[0, 2, 0, 0x0a, 0x00], MAX),
        Err(DecodeError::Malformed)
    );
}

/// Hand-assemble a Consume/Https request with `n_headers` headers.
fn https_with_headers(count_varint: &[u8], n_headers: usize) -> Vec<u8> {
    let mut p = vec![0, 2]; // version
    p.push(0x00); // correlation_id
    p.push(0x01); // Request::Consume
    p.push(0x00); // request_id
    p.push(0x00); // cap_id
    p.push(0x02); // WireOperation::Https
    p.push(0x00); // Get
    p.push(0x00); // path ""
    p.extend_from_slice(count_varint);
    for _ in 0..n_headers {
        p.extend_from_slice(&[0x01, b'a', 0x00]);
    }
    p.push(0x00); // body
    p
}

#[test]
fn header_count_limit_enforced() {
    let ok = https_with_headers(&[64], 64);
    let m = decode_client(&ok, MAX).unwrap();
    match m.request {
        Request::Consume {
            operation: WireOperation::Https(h),
            ..
        } => assert_eq!(h.headers.len(), 64),
        _ => panic!("wrong variant"),
    }
    assert_eq!(
        decode_client(&https_with_headers(&[65], 65), MAX),
        Err(DecodeError::Malformed)
    );
    // Huge declared count with no elements: rejected, no large allocation.
    assert_eq!(
        decode_client(&https_with_headers(&[0xff, 0xff, 0xff, 0xff, 0x0f], 0), MAX),
        Err(DecodeError::Malformed)
    );
}

#[test]
fn field_length_limit_enforced() {
    let long = "x".repeat(wire::MAX_HTTP_PATH + 1);
    // Build a message the encoder would refuse to construct, via bytes.
    let mut p = vec![0, 2, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00];
    let mut n = long.len();
    while n >= 0x80 {
        p.push((n as u8) | 0x80);
        n >>= 7;
    }
    p.push(n as u8);
    p.extend_from_slice(long.as_bytes());
    p.extend_from_slice(&[0x00, 0x00]);
    assert_eq!(decode_client(&p, MAX), Err(DecodeError::Malformed));
    assert!(BoundedString::<{ wire::MAX_HTTP_PATH }>::new(long).is_err());
    // Declared byte length larger than input.
    let p = vec![
        0, 2, 0x00, 0x01, 0x00, 0x00, 0x01, 0xff, 0xff, 0x03, 1, 2, 3,
    ];
    assert_eq!(decode_client(&p, MAX), Err(DecodeError::Malformed));
}

#[test]
fn oversized_payload_rejected_before_parsing() {
    let p = vec![0u8; 1000];
    assert_eq!(
        decode_client(&p, 999),
        Err(DecodeError::TooLarge {
            len: 1000,
            max: 999
        })
    );
    // Configured limit is clamped to the hard limit.
    assert_eq!(FrameLimits::new(usize::MAX).max_frame(), HARD_MAX_FRAME);
}

/// A reader that yields a fixed prefix and panics if read past it.
struct Tripwire {
    data: Vec<u8>,
    pos: usize,
}

impl Read for Tripwire {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        assert!(
            self.pos < self.data.len(),
            "reader consumed beyond the frame header"
        );
        let n = buf.len().min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[test]
fn oversized_frame_rejected_without_reading_body() {
    for len in [u32::MAX, (HARD_MAX_FRAME + 1) as u32, (MAX + 1) as u32] {
        let mut r = Tripwire {
            data: len.to_be_bytes().to_vec(),
            pos: 0,
        };
        match read_frame(&mut r, FrameLimits::default()) {
            Err(FrameError::TooLarge { len: l, max }) => {
                assert_eq!(l, len as usize);
                assert_eq!(max, MAX);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(r.pos, FRAME_HEADER_LEN);
    }
    let mut r = Tripwire {
        data: vec![0, 0, 0, 0],
        pos: 0,
    };
    assert!(matches!(
        read_frame(&mut r, FrameLimits::default()),
        Err(FrameError::Empty)
    ));
    // Writer side refuses too.
    let mut sink = Vec::new();
    assert!(matches!(
        write_frame(&mut sink, &vec![1u8; 300], FrameLimits::new(299)),
        Err(FrameError::TooLarge { .. })
    ));
    assert!(sink.is_empty());
}

#[test]
fn eof_handling() {
    let mut r = Cursor::new(Vec::<u8>::new());
    assert!(
        read_frame(&mut r, FrameLimits::default())
            .unwrap()
            .is_none()
    );
    let mut r = Cursor::new(vec![0, 0]);
    assert!(matches!(
        read_frame(&mut r, FrameLimits::default()),
        Err(FrameError::UnexpectedEof)
    ));
    let mut r = Cursor::new(vec![0, 0, 0, 5, 1, 2]);
    assert!(matches!(
        read_frame(&mut r, FrameLimits::default()),
        Err(FrameError::UnexpectedEof)
    ));
}

#[test]
fn canonical_request_bytes_ignore_correlation() {
    let req = Request::Drop {
        request_id: 5,
        cap_id: 6,
    };
    let a = canonical_request_bytes(&req).unwrap();
    assert_eq!(&a[..ENVELOPE_HEADER_LEN], &PROTOCOL_VERSION.to_be_bytes());
    let b = encode_client(&ClientMessage {
        correlation_id: 99,
        request: req.clone(),
    })
    .unwrap();
    assert_ne!(a, b);
    assert_eq!(decode::<Request>(&a, MAX).unwrap(), req);
    assert_eq!(req.request_id(), Some(5));
    assert_eq!(Request::Inspect { cap_id: 1 }.request_id(), None);
}

#[test]
fn debug_does_not_print_content() {
    let b = BoundedBytes::<16>::new(b"secret".to_vec()).unwrap();
    assert!(!format!("{b:?}").contains("secret"));
}

#[test]
fn v2_additions_are_bounded_and_canonical() {
    // ListCapabilities { after: None }: version 2, corr 0, variant 9, None.
    let msg = ClientMessage {
        correlation_id: 0,
        request: Request::ListCapabilities { after: None },
    };
    let p = encode_client(&msg).unwrap();
    assert_eq!(p, vec![0, 2, 0x00, 0x09, 0x00]);
    assert_eq!(decode_client(&p, MAX).unwrap(), msg);
    // Option tag other than 0/1 is malformed.
    assert_eq!(
        decode_client(&[0, 2, 0x00, 0x09, 0x02], MAX),
        Err(DecodeError::Malformed)
    );
    // The same body under version 1 is refused before parsing.
    assert_eq!(
        decode_client(&[0, 1, 0x00, 0x09, 0x00], MAX),
        Err(DecodeError::UnsupportedVersion(1))
    );

    // A description longer than MAX_DESCRIPTION cannot be built ...
    assert!(BoundedString::<MAX_DESCRIPTION>::new("x".repeat(MAX_DESCRIPTION + 1)).is_err());
    // ... nor decoded: hand-encode one byte too long.
    let ok = ClientMessage {
        correlation_id: 0,
        request: Request::RequestGrant {
            request_id: 0,
            requested_scope: WireScope::File {
                object_id: 0,
                rights: WireFileRights {
                    read_snapshot: true,
                    replace_content: false,
                },
            },
            budget: WireBudget::Finite(1),
            depth: WireDepth::Finite(0),
            expiry: WireExpiry::Inherit,
            untrusted_description: Some(BoundedString::new("y".repeat(MAX_DESCRIPTION)).unwrap()),
        },
    };
    let good = encode_client(&ok).unwrap();
    assert_eq!(decode_client(&good, MAX).unwrap(), ok);
    // The description is the last field: [.. 0x01 (Some), varint len, bytes].
    let len_at = good.len() - MAX_DESCRIPTION - 2;
    assert_eq!(good[len_at - 1], 0x01);
    let mut bad = good[..len_at].to_vec();
    bad.extend_from_slice(&[0x81, 0x04]); // 513 as a varint
    bad.extend(std::iter::repeat_n(b'y', MAX_DESCRIPTION + 1));
    assert_eq!(decode_client(&bad, MAX), Err(DecodeError::Malformed));

    // Capabilities: more than MAX_LIST views are refused by the bound.
    assert!(
        BoundedVec::<WireCapabilityView, MAX_LIST>::new(vec![
            WireCapabilityView {
                cap_id: 1,
                root_id: 1,
                parent: None,
                owner: WireAgentId {
                    epoch: 1,
                    serial: 1
                },
                scope: WireScope::File {
                    object_id: 1,
                    rights: WireFileRights::default(),
                },
                budget_remaining: WireBudget::Unlimited,
                depth: WireDepth::Unlimited,
                expires_in_millis: None,
                status: WireCapStatus::Live,
            };
            MAX_LIST + 1
        ])
        .is_err()
    );
}
