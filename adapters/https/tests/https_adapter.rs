//! HTTPS adapter tests against a local rustls server with an rcgen CA.
//! No test touches the internet: every endpoint is pinned to 127.0.0.1 or
//! resolves `localhost`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http::Method;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tessera_adapter_https::{
    ConfigError, Denial, EffectOutcome, EndpointConfig, EndpointId, HttpsAdapter, HttpsError,
    HttpsOperation, Reservation, ReservationId, SecretHeader, TlsTrust,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const HOST: &str = "tessera.test";
const SECRET_NAME: &str = "x-api-key";
const SECRET_VALUE: &str = "sk-live-SUPERSECRET-0123456789";
const EP: EndpointId = EndpointId(1);

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn rid() -> ReservationId {
    ReservationId(u128::from(NEXT_ID.fetch_add(1, Ordering::Relaxed)))
}

#[derive(Clone, Debug)]
struct Seen {
    target: String,
    head: String,
    body_len: usize,
}

struct Server {
    addr: SocketAddr,
    ca: CertificateDer<'static>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Server {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

async fn start_server() -> Server {
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
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let seen = Arc::clone(&seen2);
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    let _ = serve(tls, seen).await;
                }
            });
        }
    });
    Server {
        addr,
        ca: ca.der().clone(),
        seen,
    }
}

async fn serve<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut s: S,
    seen: Arc<Mutex<Vec<Seen>>>,
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let target = head.split(' ').nth(1).unwrap_or_default().to_owned();
    let content_length = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    while buf.len() < head_end + content_length {
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let echoed_secret = head
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{SECRET_NAME}: ")))
        .unwrap_or("")
        .to_owned();
    seen.lock().unwrap().push(Seen {
        target: target.clone(),
        head,
        body_len: buf.len() - head_end,
    });

    let path = target.split('?').next().unwrap_or_default();
    let resp: Vec<u8> = match path {
        "/api/ok" => format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\nx-reply: yes\r\n\
             set-cookie: session=abc\r\nx-echo: {echoed_secret}\r\n\
             content-length: 5\r\nconnection: close\r\n\r\nhello"
        )
        .into_bytes(),
        "/api/redirect" => b"HTTP/1.1 302 Found\r\nlocation: https://tessera.test/api/target\r\n\
              content-length: 0\r\nconnection: close\r\n\r\n"
            .to_vec(),
        "/api/big" => {
            let mut r =
                b"HTTP/1.1 200 OK\r\ncontent-length: 100000\r\nconnection: close\r\n\r\n".to_vec();
            r.extend(std::iter::repeat_n(b'z', 100_000));
            r
        }
        "/api/big-chunked" => {
            let mut r =
                b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n"
                    .to_vec();
            for _ in 0..100 {
                r.extend_from_slice(b"3e8\r\n");
                r.extend(std::iter::repeat_n(b'z', 1000));
                r.extend_from_slice(b"\r\n");
            }
            r.extend_from_slice(b"0\r\n\r\n");
            r
        }
        "/api/hang" => {
            tokio::time::sleep(Duration::from_secs(30)).await;
            return Ok(());
        }
        _ => b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_vec(),
    };
    s.write_all(&resp).await?;
    s.shutdown().await?;
    Ok(())
}

fn endpoint(server: &Server) -> EndpointConfig {
    let mut cfg = EndpointConfig::new(HOST, server.addr.port(), "/api");
    cfg.methods = vec![Method::GET, Method::POST];
    cfg.request_headers = vec!["content-type".to_owned(), "x-trace".to_owned()];
    cfg.response_headers = vec!["content-type".to_owned(), "x-reply".to_owned()];
    cfg.max_request_body = 1024;
    cfg.max_response_body = 10_000;
    cfg.timeout = Duration::from_secs(5);
    cfg.secret_header = Some(SecretHeader::new(SECRET_NAME, SECRET_VALUE.as_bytes()).unwrap());
    cfg.allow_private = true;
    cfg.pinned_addrs = Some(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    cfg.tls = TlsTrust::CustomRoots(vec![server.ca.clone()]);
    cfg
}

fn adapter_for(server: &Server) -> HttpsAdapter {
    let a = HttpsAdapter::new();
    a.register(EP, endpoint(server)).unwrap();
    a
}

fn get(path: &str) -> Reservation {
    Reservation {
        id: rid(),
        endpoint: EP,
        operation: HttpsOperation {
            method: Method::GET,
            path: path.to_owned(),
            headers: vec![],
            body: vec![],
        },
    }
}

fn denial(r: Result<tessera_adapter_https::HttpsDispatch, HttpsError>) -> Denial {
    match r {
        Err(HttpsError::Denied(d)) => d,
        other => panic!("expected denial, got {other:?}"),
    }
}

fn failed(r: Result<tessera_adapter_https::HttpsDispatch, HttpsError>) -> EffectOutcome {
    match r {
        Err(HttpsError::Failed(effect)) => effect.outcome,
        other => panic!("expected failure, got {other:?}"),
    }
}

#[tokio::test]
async fn success_with_secret_injected_but_never_exposed() {
    let server = start_server().await;
    let adapter = adapter_for(&server);
    let mut res = get("/api/ok?x=1");
    res.operation.method = Method::POST;
    res.operation.body = b"{\"q\":1}".to_vec();
    res.operation.headers = vec![("content-type".into(), b"application/json".to_vec())];
    let out = adapter.dispatch(&res).await.unwrap();
    assert_eq!(out.response.status, 200);
    assert_eq!(&out.response.body[..], b"hello");
    let names: Vec<&str> = out
        .response
        .headers
        .iter()
        .map(|(n, _)| n.as_str())
        .collect();
    assert_eq!(names, vec!["content-type", "x-reply"]);

    // The server received exactly one request, carrying the secret.
    let seen = server.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].target, "/api/ok?x=1");
    assert_eq!(seen[0].body_len, 7);
    assert!(seen[0].head.contains(SECRET_VALUE));
    assert!(
        seen[0]
            .head
            .contains(&format!("host: {HOST}:{}", server.addr.port()))
    );

    // The secret is absent from the effect, the response and all Debug output.
    let effect = &out.effect;
    assert_eq!(effect.peer, Some(server.addr));
    assert_eq!(effect.request_body_len, 7);
    match &effect.outcome {
        EffectOutcome::Response {
            status, body_len, ..
        } => assert_eq!((*status, *body_len), (200, 5)),
        o => panic!("{o:?}"),
    }
    let dump = format!("{out:?} {:?} {res:?}", out.response.headers);
    assert!(!dump.contains("SUPERSECRET"), "{dump}");
    assert!(!dump.contains("hello"));
    assert!(!dump.contains("set-cookie") && !dump.contains("x-echo"));
    for (_, v) in &out.response.headers {
        assert!(!String::from_utf8_lossy(v).contains("SUPERSECRET"));
    }
    let cfg_dump = format!("{:?}", endpoint(&server));
    assert!(!cfg_dump.contains("SUPERSECRET"), "{cfg_dump}");
}

#[tokio::test]
async fn redirect_is_returned_not_followed() {
    let server = start_server().await;
    let adapter = adapter_for(&server);
    let out = adapter.dispatch(&get("/api/redirect")).await.unwrap();
    assert_eq!(out.response.status, 302);
    let seen = server.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].target, "/api/redirect");
}

#[tokio::test]
async fn oversized_response_is_discarded() {
    let server = start_server().await;
    let adapter = adapter_for(&server);
    // Declared Content-Length above the limit.
    assert_eq!(
        failed(adapter.dispatch(&get("/api/big")).await),
        EffectOutcome::ResponseTooLarge {
            status: 200,
            limit: 10_000
        }
    );
    // Chunked body growing past the limit.
    assert_eq!(
        failed(adapter.dispatch(&get("/api/big-chunked")).await),
        EffectOutcome::ResponseTooLarge {
            status: 200,
            limit: 10_000
        }
    );
    assert_eq!(server.seen().len(), 2);
}

#[tokio::test]
async fn oversized_request_body_denied_before_connecting() {
    let server = start_server().await;
    let adapter = adapter_for(&server);
    let mut res = get("/api/ok");
    res.operation.method = Method::POST;
    res.operation.body = vec![0u8; 1025];
    assert_eq!(
        denial(adapter.dispatch(&res).await),
        Denial::BodyTooLarge {
            limit: 1024,
            size: 1025
        }
    );
    assert!(server.seen().is_empty());
}

#[tokio::test]
async fn path_outside_prefix_denied() {
    let server = start_server().await;
    let adapter = adapter_for(&server);
    for p in [
        "/admin",
        "/apix",
        "/api/../admin",
        "/api/%2e%2e/admin",
        "//api/ok",
        "https://evil.example/api/ok",
        "/api/ok#x",
        "/api/ok\r\nx: y",
    ] {
        assert_eq!(
            denial(adapter.dispatch(&get(p)).await),
            Denial::PathNotAllowed,
            "{p:?}"
        );
    }
    assert!(server.seen().is_empty());
}

#[tokio::test]
async fn method_and_header_policy() {
    let server = start_server().await;
    let adapter = adapter_for(&server);
    let mut res = get("/api/ok");
    res.operation.method = Method::DELETE;
    assert_eq!(
        denial(adapter.dispatch(&res).await),
        Denial::MethodNotAllowed
    );
    for (name, value) in [
        ("authorization", &b"Bearer x"[..]),
        ("host", b"evil.example"),
        (SECRET_NAME, b"guess"),
        ("transfer-encoding", b"chunked"),
        ("x-trace", b"a\r\nb"),
    ] {
        let mut res = get("/api/ok");
        res.operation.headers = vec![(name.to_owned(), value.to_vec())];
        assert!(
            matches!(
                denial(adapter.dispatch(&res).await),
                Denial::HeaderNotAllowed(_)
            ),
            "{name}"
        );
    }
    assert!(server.seen().is_empty());

    // Misconfigurations are refused at registration.
    let mut cfg = endpoint(&server);
    cfg.request_headers.push(SECRET_NAME.to_owned());
    assert!(matches!(
        HttpsAdapter::new().register(EP, cfg),
        Err(ConfigError::InvalidHeader(_))
    ));
    let mut cfg = endpoint(&server);
    cfg.response_headers.push(SECRET_NAME.to_owned());
    assert!(matches!(
        HttpsAdapter::new().register(EP, cfg),
        Err(ConfigError::InvalidHeader(_))
    ));
    let mut cfg = endpoint(&server);
    cfg.methods.push(Method::CONNECT);
    assert_eq!(
        HttpsAdapter::new().register(EP, cfg),
        Err(ConfigError::InvalidMethods)
    );
    let mut cfg = endpoint(&server);
    cfg.path_prefix = "/api/../".to_owned();
    assert_eq!(
        HttpsAdapter::new().register(EP, cfg),
        Err(ConfigError::InvalidPrefix)
    );
}

#[tokio::test]
async fn private_destination_rejected_unless_allowed() {
    let server = start_server().await;
    // Pinned loopback without allow_private.
    let adapter = HttpsAdapter::new();
    let mut cfg = endpoint(&server);
    cfg.allow_private = false;
    adapter.register(EP, cfg).unwrap();
    assert_eq!(
        denial(adapter.dispatch(&get("/api/ok")).await),
        Denial::DestinationForbidden(IpAddr::V4(Ipv4Addr::LOCALHOST))
    );
    // DNS path: `localhost` resolves to loopback and is rejected.
    let adapter = HttpsAdapter::new();
    let mut cfg = endpoint(&server);
    cfg.allow_private = false;
    cfg.pinned_addrs = None;
    cfg.host = "localhost".to_owned();
    adapter.register(EP, cfg).unwrap();
    assert!(matches!(
        denial(adapter.dispatch(&get("/api/ok")).await),
        Denial::DestinationForbidden(ip) if ip.is_loopback()
    ));
    // IP-literal host.
    let adapter = HttpsAdapter::new();
    let mut cfg = endpoint(&server);
    cfg.allow_private = false;
    cfg.pinned_addrs = None;
    cfg.host = "169.254.169.254".to_owned();
    adapter.register(EP, cfg).unwrap();
    assert!(matches!(
        denial(adapter.dispatch(&get("/api/ok")).await),
        Denial::DestinationForbidden(_)
    ));
    // Mixed pinned set: one forbidden address taints the whole set.
    let adapter = HttpsAdapter::new();
    let mut cfg = endpoint(&server);
    cfg.allow_private = false;
    cfg.pinned_addrs = Some(vec![
        "1.1.1.1".parse().unwrap(),
        "10.0.0.1".parse().unwrap(),
    ]);
    adapter.register(EP, cfg).unwrap();
    assert_eq!(
        denial(adapter.dispatch(&get("/api/ok")).await),
        Denial::DestinationForbidden("10.0.0.1".parse().unwrap())
    );
    assert!(server.seen().is_empty());
}

#[tokio::test]
async fn tls_identity_is_validated_for_registered_host() {
    let server = start_server().await;
    // Certificate is for tessera.test; endpoint registered as other.test but
    // pinned to the same server.
    let adapter = HttpsAdapter::new();
    let mut cfg = endpoint(&server);
    cfg.host = "other.test".to_owned();
    adapter.register(EP, cfg).unwrap();
    let out = failed(adapter.dispatch(&get("/api/ok")).await);
    assert!(matches!(out, EffectOutcome::TlsFailed(_)), "{out:?}");
    assert!(!out.may_have_reached_server());
    // Public webpki roots do not trust the private test CA.
    let adapter = HttpsAdapter::new();
    let mut cfg = endpoint(&server);
    cfg.tls = TlsTrust::WebPki;
    adapter.register(EP, cfg).unwrap();
    assert!(matches!(
        failed(adapter.dispatch(&get("/api/ok")).await),
        EffectOutcome::TlsFailed(_)
    ));
    assert!(server.seen().is_empty());
}

#[tokio::test]
async fn one_dispatch_per_reservation() {
    let server = start_server().await;
    let adapter = Arc::new(adapter_for(&server));
    let res = get("/api/ok");
    adapter.dispatch(&res).await.unwrap();
    assert_eq!(
        adapter.dispatch(&res).await.unwrap_err(),
        HttpsError::AlreadyDispatched(res.id)
    );

    // Concurrent duplicates: exactly one reaches the server.
    let res = Arc::new(get("/api/ok"));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let a = Arc::clone(&adapter);
        let r = Arc::clone(&res);
        tasks.push(tokio::spawn(async move { a.dispatch(&r).await }));
    }
    let mut ok = 0;
    for t in tasks {
        match t.await.unwrap() {
            Ok(_) => ok += 1,
            Err(HttpsError::AlreadyDispatched(_)) => {}
            Err(e) => panic!("{e:?}"),
        }
    }
    assert_eq!(ok, 1);
    assert_eq!(server.seen().len(), 2);

    // A denied attempt also consumes its id.
    let mut res = get("/nope");
    assert_eq!(denial(adapter.dispatch(&res).await), Denial::PathNotAllowed);
    res.operation.path = "/api/ok".to_owned();
    assert_eq!(
        adapter.dispatch(&res).await.unwrap_err(),
        HttpsError::AlreadyDispatched(res.id)
    );
    assert_eq!(server.seen().len(), 2);
}

#[tokio::test]
async fn timeout_is_reported_as_unknown_outcome() {
    let server = start_server().await;
    let adapter = HttpsAdapter::new();
    let mut cfg = endpoint(&server);
    cfg.timeout = Duration::from_millis(300);
    adapter.register(EP, cfg).unwrap();
    let out = failed(adapter.dispatch(&get("/api/hang")).await);
    assert_eq!(out, EffectOutcome::TimedOut);
    assert!(out.may_have_reached_server());
    assert_eq!(server.seen().len(), 1);
}

#[tokio::test]
async fn unknown_endpoint_denied() {
    let adapter = HttpsAdapter::new();
    let mut res = get("/api/ok");
    res.endpoint = EndpointId(99);
    assert_eq!(
        denial(adapter.dispatch(&res).await),
        Denial::UnknownEndpoint(EndpointId(99))
    );
}
