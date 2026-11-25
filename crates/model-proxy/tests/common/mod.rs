//! Shared test fixtures: a local TLS upstream (rcgen CA) with scripted
//! behaviours, a proxy builder and a small raw HTTP client. No test touches
//! the internet or reads a real credential.

#![allow(dead_code)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tessera_model_proxy::{
    AuditRecord, Credential, Injection, ModelProxy, ProxyConfig, SandboxListener, Upstream,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;

pub const HOST: &str = "tessera.test";
pub const SECRET: &str = "sk-test-SUPERSECRET-0123456789abcdef";

#[derive(Clone, Debug)]
pub struct Seen {
    pub target: String,
    pub head: String,
    pub body_len: usize,
}

pub struct Upstream_ {
    pub addr: SocketAddr,
    pub ca: CertificateDer<'static>,
    pub seen: Arc<Mutex<Vec<Seen>>>,
    /// Releases the second half of `/v1/stream`.
    pub gate: Arc<Notify>,
}

impl Upstream_ {
    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

pub fn ca_and_leaf(names: &[&str]) -> (CertificateDer<'static>, CertificateDer<'static>, KeyPair) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        .unwrap()
        .signed_by(&leaf_key, &ca)
        .unwrap();
    (ca.der().clone(), leaf.der().clone(), leaf_key)
}

pub async fn start_upstream() -> Upstream_ {
    let (ca, leaf, leaf_key) = ca_and_leaf(&[HOST]);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let gate = Arc::new(Notify::new());
    let (seen2, gate2) = (Arc::clone(&seen), Arc::clone(&gate));
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let seen = Arc::clone(&seen2);
            let gate = Arc::clone(&gate2);
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    let _ = serve(tls, seen, gate).await;
                }
            });
        }
    });
    Upstream_ {
        addr,
        ca,
        seen,
        gate,
    }
}

async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> std::io::Result<Option<(String, Vec<u8>)>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..i + 4]).to_string();
            return Ok(Some((head, buf[i + 4..].to_vec())));
        }
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    seen: Arc<Mutex<Vec<Seen>>>,
    gate: Arc<Notify>,
) -> std::io::Result<()> {
    let Some((head, mut rest)) = read_head(&mut s).await? else {
        return Ok(());
    };
    let target = head.split(' ').nth(1).unwrap_or_default().to_owned();
    let len: usize = header(&head, "content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut chunk = [0u8; 8192];
    while rest.len() < len {
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        rest.extend_from_slice(&chunk[..n]);
    }
    seen.lock().unwrap().push(Seen {
        target: target.clone(),
        head: head.clone(),
        body_len: rest.len(),
    });
    let path = target.split('?').next().unwrap_or_default();
    match path {
        "/v1/stream" => {
            s.write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n",
            )
            .await?;
            let ev1 = b"event: message_start\ndata: {\"n\":1}\n\n";
            s.write_all(format!("{:x}\r\n", ev1.len()).as_bytes()).await?;
            s.write_all(ev1).await?;
            s.write_all(b"\r\n").await?;
            s.flush().await?;
            gate.notified().await;
            let ev2 = b"event: message_stop\ndata: {\"n\":2}\n\n";
            s.write_all(format!("{:x}\r\n", ev2.len()).as_bytes()).await?;
            s.write_all(ev2).await?;
            s.write_all(b"\r\n0\r\n\r\n").await?;
        }
        "/v1/big" => {
            let body = vec![b'x'; 100_000];
            s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100000\r\n\r\n")
                .await?;
            s.write_all(&body).await?;
        }
        "/v1/bigchunked" => {
            s.write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n")
                .await?;
            for _ in 0..100 {
                s.write_all(b"3e8\r\n").await?;
                s.write_all(&[b'y'; 1000]).await?;
                s.write_all(b"\r\n").await?;
            }
            s.write_all(b"0\r\n\r\n").await?;
        }
        "/v1/redirect" => {
            s.write_all(
                b"HTTP/1.1 302 Found\r\nlocation: https://evil.example/steal\r\ncontent-length: 0\r\n\r\n",
            )
            .await?;
        }
        _ => {
            // Echo: the full request head (including the injected
            // credential) goes back in the body and in response headers.
            let key = header(&head, "x-api-key").unwrap_or("").to_owned();
            let auth = header(&head, "authorization").unwrap_or("").to_owned();
            let body = serde_json::json!({ "target": target, "head": head }).to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                 x-echo-api-key: {key}\r\nx-echo-authorization: {auth}\r\n\
                 x-api-key: {key}\r\nset-cookie: session=abc\r\nrequest-id: req_1\r\n\
                 content-length: {}\r\n\r\n{body}",
                body.len()
            );
            s.write_all(resp.as_bytes()).await?;
        }
    }
    s.flush().await?;
    let _ = s.shutdown().await;
    Ok(())
}

pub struct Harness {
    pub upstream: Upstream_,
    pub socket: PathBuf,
    pub audit: Arc<Mutex<Vec<AuditRecord>>>,
    pub budget: Arc<tessera_model_proxy::budget::Budget>,
    _dir: tempfile::TempDir,
}

impl Harness {
    pub fn audit(&self) -> Vec<AuditRecord> {
        self.audit.lock().unwrap().clone()
    }

    /// Wait until `n` audit records exist (pump tasks log asynchronously).
    pub async fn wait_audit(&self, n: usize) -> Vec<AuditRecord> {
        for _ in 0..200 {
            let a = self.audit();
            if a.len() >= n {
                return a;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        self.audit()
    }
}

pub fn base_config(port: u16, socket: &Path) -> serde_json::Value {
    serde_json::json!({
        "upstream": {
            "host": HOST, "port": port, "pinned_addrs": ["127.0.0.1"],
            "allow_private": true, "connect_timeout_ms": 5000,
            "response_header_timeout_ms": 5000, "idle_timeout_ms": 5000,
            "max_duration_ms": 20000
        },
        "credential": { "file": "/nonexistent/not-read-in-tests", "inject": "x-api-key" },
        "routes": [
            { "method": "POST", "path": "/v1/messages" },
            { "method": "POST", "path": "/v1/messages/count_tokens" },
            { "method": "GET", "path": "/v1/models", "match": "prefix" },
            { "method": "POST", "path": "/v1/stream" },
            { "method": "GET", "path": "/v1/big" },
            { "method": "GET", "path": "/v1/bigchunked" },
            { "method": "GET", "path": "/v1/redirect" }
        ],
        "limits": { "max_request_body": 4096, "max_response_body": 50000,
                    "max_header_bytes": 8192, "request_read_timeout_ms": 5000 },
        "sandboxes": [ { "label": "agent-1", "socket": socket } ]
    })
}

/// Start a proxy. `tweak` edits the JSON config before parsing.
pub async fn start(tweak: impl FnOnce(&mut serde_json::Value)) -> Harness {
    start_with(tweak, None).await
}

pub async fn start_with(
    tweak: impl FnOnce(&mut serde_json::Value),
    roots: Option<Vec<CertificateDer<'static>>>,
) -> Harness {
    let upstream = start_upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("model.sock");
    let mut v = base_config(upstream.addr.port(), &socket);
    tweak(&mut v);
    let cfg = ProxyConfig::from_json(&v.to_string()).unwrap();
    let cred = Credential::new(SECRET.as_bytes(), cfg.credential.inject).unwrap();
    let up = Upstream::with_roots(
        &cfg.upstream,
        Some(roots.unwrap_or_else(|| vec![upstream.ca.clone()])),
    )
    .unwrap();
    let audit = Arc::new(Mutex::new(Vec::new()));
    let a2 = Arc::clone(&audit);
    let sink: tessera_model_proxy::AuditSink = Arc::new(move |r: &AuditRecord| {
        a2.lock().unwrap().push(r.clone());
    });
    let proxy = ModelProxy::new(&cfg, cred, up, sink).unwrap();
    let l: SandboxListener = proxy.bind(&cfg.sandboxes[0]).unwrap();
    let budget = l.budget();
    tokio::spawn(async move { proxy.serve(l).await });
    Harness {
        upstream,
        socket,
        audit,
        budget,
        _dir: dir,
    }
}

pub fn bearer(v: &mut serde_json::Value) {
    v["credential"]["inject"] = "bearer".into();
}

pub fn _unused(_: Injection) {}

/// Send raw bytes on a fresh connection and read until EOF.
pub async fn raw(socket: &Path, req: &[u8]) -> String {
    let mut s = UnixStream::connect(socket).await.unwrap();
    s.write_all(req).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), s.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).to_string()
}

pub fn status_of(resp: &str) -> u16 {
    resp.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
}

pub fn post(path: &str, extra_headers: &str, body: &str) -> Vec<u8> {
    format!(
        "POST {path} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n{extra_headers}content-length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

pub fn get(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n").into_bytes()
}
