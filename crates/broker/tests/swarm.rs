//! §12.2 multi-agent swarm through the broker with the HTTPS adapter
//! against a local TLS test server (no internet).

mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::*;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tessera_broker::{AdminRequest, AdminResponse, EndpointSpec};
use tessera_protocol::bounded::{BoundedBytes, BoundedString, BoundedVec};
use tessera_protocol::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const HOST: &str = "tessera.test";

struct Server {
    addr: SocketAddr,
    ca: Vec<u8>,
    hits: Arc<AtomicUsize>,
    _rt: tokio::runtime::Runtime,
}

fn start_server() -> Server {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![HOST.to_owned()])
        .unwrap()
        .signed_by(&leaf_key, &ca)
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let listener = rt
        .block_on(tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let h2 = Arc::clone(&hits);
    rt.spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let hits = Arc::clone(&h2);
            tokio::spawn(async move {
                let Ok(mut s) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let Ok(n) = s.read(&mut chunk).await else { return };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                hits.fetch_add(1, Ordering::SeqCst);
                let _ = s
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello",
                    )
                    .await;
                let _ = s.shutdown().await;
            });
        }
    });
    Server {
        addr,
        ca: ca.der().to_vec(),
        hits,
        _rt: rt,
    }
}

fn https_scope(max_body: u64) -> WireScope {
    WireScope::Https {
        endpoint_id: 1,
        methods: WireMethodSet {
            get: true,
            ..WireMethodSet::default()
        },
        max_body_bytes: max_body,
    }
}

fn get(a: &mut Agent, rid: u128, cap: u128) -> Response {
    a.call(Request::Consume {
        request_id: rid,
        cap_id: cap,
        operation: WireOperation::Https(WireHttpsRequest {
            method: HttpMethod::Get,
            path: BoundedString::new("/api/search?q=x".to_owned()).unwrap(),
            headers: BoundedVec::new(Vec::new()).unwrap(),
            body: BoundedBytes::new(Vec::new()).unwrap(),
        }),
    })
}

fn ok_body(r: &Response) -> Vec<u8> {
    match r {
        Response::Consumed {
            result: WireOperationResult::Https {
                status: 200, body, ..
            },
            ..
        } => body.as_slice().to_vec(),
        other => panic!("expected 200, got {other:?}"),
    }
}

fn delegate(a: &mut Agent, rid: u128, cap: u128, to: WireAgentId, n: u64, depth: u32) -> u128 {
    match a.call(Request::Delegate {
        request_id: rid,
        cap_id: cap,
        recipient: to,
        child_scope: https_scope(0),
        child_budget: WireBudget::Finite(n),
        child_depth: WireDepth::Finite(depth),
        child_expiry: WireExpiry::Inherit,
    }) {
        Response::Delegated { child_cap_id, .. } => child_cap_id,
        other => panic!("delegate failed: {other:?}"),
    }
}

#[test]
fn swarm_example_12_2_through_the_broker() {
    let server = start_server();
    let mut h = Harness::new();
    let b = h.start(None);
    h.enroll(&b);
    let spec = EndpointSpec {
        host: HOST.into(),
        port: server.addr.port(),
        path_prefix: "/api".into(),
        methods: vec!["GET".into()],
        request_headers: vec![],
        response_headers: vec!["content-type".into()],
        max_request_body: 1024,
        max_response_body: 4096,
        timeout_ms: 5000,
        allow_private: true,
        pinned_addrs: Some(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
        ca_der: Some(vec![server.ca.clone()]),
    };
    assert_eq!(
        b.admin(AdminRequest::RegisterEndpoint { id: 1, spec }),
        AdminResponse::Object(1)
    );
    let mut a = Agent::attach(&b);
    let mut bb = Agent::attach(&b);
    let mut c = Agent::attach(&b);
    let mut d = Agent::attach(&b);

    // Operator grants A 100 requests to E, depth two (FIDO2 approval).
    a.send(Request::RequestGrant {
        request_id: 1,
        requested_scope: https_scope(0),
        budget: WireBudget::Finite(100),
        depth: WireDepth::Finite(2),
        expiry: WireExpiry::Inherit,
    });
    let AdminResponse::Capability(root_cap) = h.approve(&b) else {
        panic!()
    };
    assert_eq!(granted(&a.recv().unwrap().response), root_cap);

    let cap_b = delegate(&mut a, 2, root_cap, bb.wire_id(), 30, 1);
    let cap_c = delegate(&mut a, 3, root_cap, c.wire_id(), 20, 0);
    let cap_d = delegate(&mut bb, 1, cap_b, d.wire_id(), 10, 0);
    assert_eq!(common::cap(&b, root_cap).budget, "50");
    assert_eq!(common::cap(&b, cap_b).budget, "20");

    for i in 0..3 {
        assert_eq!(ok_body(&get(&mut d, 10 + i, cap_d)), b"hello");
    }
    assert_eq!(server.hits.load(Ordering::SeqCst), 3);
    let AdminResponse::Accounts(acc) = b.admin(AdminRequest::Accounts) else {
        panic!()
    };
    assert_eq!(acc.len(), 1, "one finite pool across A, B, C, D");
    assert_eq!(
        (
            acc[0].initial,
            acc[0].consumed,
            acc[0].live,
            acc[0].discarded
        ),
        (100, 3, 97, 0)
    );

    // Revoking B's capability invalidates B and D, not C.
    assert_eq!(
        b.admin(AdminRequest::Revoke { capability: cap_b }),
        AdminResponse::Ok
    );
    assert_eq!(code(&get(&mut bb, 20, cap_b)), Some(ErrorCode::Revoked));
    assert_eq!(code(&get(&mut d, 21, cap_d)), Some(ErrorCode::Revoked));
    assert_eq!(ok_body(&get(&mut c, 22, cap_c)), b"hello");
    assert_eq!(ok_body(&get(&mut a, 23, root_cap)), b"hello");
    assert_eq!(server.hits.load(Ordering::SeqCst), 5);
    let AdminResponse::Accounts(acc) = b.admin(AdminRequest::Accounts) else {
        panic!()
    };
    // B's 20 and D's 7 are stranded in D; nothing is double counted.
    assert_eq!(
        (
            acc[0].initial,
            acc[0].consumed,
            acc[0].live,
            acc[0].discarded
        ),
        (100, 5, 68, 27)
    );

    // The audit identifies the root approval for every attempt.
    let root_id = common::cap(&b, root_cap).root;
    let AdminResponse::Audit(ev) = b.admin(AdminRequest::Audit {
        since: 0,
        limit: 10_000,
    }) else {
        panic!()
    };
    let effects: Vec<_> = ev.iter().filter(|e| e.kind == "effect").collect();
    assert_eq!(effects.len(), 5);
    assert!(effects.iter().all(|e| e.root == Some(root_id)));
    assert!(
        effects
            .iter()
            .all(|e| e.effect.as_deref() == Some("completed"))
    );
}
