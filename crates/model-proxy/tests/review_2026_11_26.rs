//! Regression tests for the model proxy security review of 2026-11-26
//! (`docs/security-review-2026-11-26-model-proxy.md`). Each test started as a
//! reproducer of a finding and asserts the fixed behaviour.

mod common;

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tessera_model_proxy::{AuditRecord, Credential, ModelProxy, ProxyConfig, Upstream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use tokio_rustls::TlsAcceptor;

fn rss_kb() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    s.lines()
        .find(|l| l.starts_with("VmRSS:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap()
}

fn outcomes(a: &[AuditRecord]) -> Vec<String> {
    a.iter().map(|r| r.outcome.clone()).collect()
}

// ---------------------------------------------------------------- F-1 ---

/// F-1: the in-flight permit is taken before the body is read, so
/// `max_concurrent` bounds buffered request bodies. Before the fix, 16
/// stalled 30 MiB uploads with `max_concurrent: 1` grew RSS by ~480 MiB.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f1_body_not_buffered_before_admission() {
    let body_len: usize = 30 << 20;
    let h = start(|v| {
        v["limits"]["max_request_body"] = (32u64 << 20).into();
        v["limits"]["request_read_timeout_ms"] = 30000.into();
        v["sandboxes"][0]["budget"] = serde_json::json!({ "max_concurrent": 1 });
    })
    .await;
    let payload: Arc<Vec<u8>> = Arc::new(vec![b'a'; body_len - 1]);
    let before = rss_kb();
    let n = 16;
    let mut conns = Vec::new();
    for _ in 0..n {
        let mut s = UnixStream::connect(&h.socket).await.unwrap();
        let head =
            format!("POST /v1/messages HTTP/1.1\r\nhost: x\r\ncontent-length: {body_len}\r\n\r\n");
        s.write_all(head.as_bytes()).await.unwrap();
        let p = Arc::clone(&payload);
        conns.push(tokio::spawn(async move {
            // Refused connections are closed by the proxy: ignore EPIPE.
            let _ = s.write_all(&p).await;
            tokio::time::sleep(Duration::from_secs(20)).await;
            drop(s);
        }));
    }
    tokio::time::sleep(Duration::from_secs(4)).await;
    let grown_mb = rss_kb().saturating_sub(before) / 1024;
    eprintln!("F-1: {n} x 30 MiB stalled uploads, max_concurrent=1: RSS grew {grown_mb} MiB");
    for c in conns {
        c.abort();
    }
    // One body (30 MiB) may be buffered; the other 15 are refused unread.
    assert!(grown_mb < 128, "RSS grew {grown_mb} MiB");
    let denied = h
        .audit()
        .iter()
        .filter(|r| r.outcome == "denied:too_many_in_flight")
        .count();
    assert!(denied >= n - 1, "{:?}", outcomes(&h.audit()));
    assert!(h.upstream.seen().is_empty());
}

/// F-1: a slow-loris request head is cut off by the header deadline.
#[tokio::test]
async fn f1_header_deadline() {
    let h = start(|v| {
        v["limits"]["request_header_timeout_ms"] = 300.into();
        v["limits"]["request_read_timeout_ms"] = 30000.into();
    })
    .await;
    let mut s = UnixStream::connect(&h.socket).await.unwrap();
    s.write_all(b"POST /v1/messages HTTP/1.1\r\nhost: x\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let r = tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut buf)).await;
    assert!(r.is_ok(), "connection still open after header deadline");
}

/// F-1: a stalled body releases the in-flight permit at the body deadline.
#[tokio::test]
async fn f1_body_deadline_releases_permit() {
    let h = start(|v| {
        v["limits"]["request_read_timeout_ms"] = 300.into();
        v["sandboxes"][0]["budget"] = serde_json::json!({ "max_concurrent": 1 });
    })
    .await;
    let mut s = UnixStream::connect(&h.socket).await.unwrap();
    s.write_all(b"POST /v1/messages HTTP/1.1\r\nhost: x\r\ncontent-length: 100\r\n\r\n{\"a\":")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut buf)).await;
    assert_eq!(status_of(&String::from_utf8_lossy(&buf)), 400);
    assert_eq!(
        status_of(&raw(&h.socket, &post("/v1/messages", "", "{}")).await),
        200
    );
}

// ---------------------------------------------------------------- F-2 ---

/// F-2: refused connections no longer write one audit line each; they are
/// rate limited and summarised.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f2_refused_connections_rate_limited_and_summarised() {
    let h = start(|v| {
        v["limits"]["request_read_timeout_ms"] = 30000.into();
        v["limits"]["request_header_timeout_ms"] = 30000.into();
        v["limits"]["audit_denials_per_second"] = 5.into();
        v["limits"]["audit_denials_burst"] = 10.into();
        v["limits"]["audit_summary_interval_ms"] = 300.into();
    })
    .await;
    let mut held = Vec::new();
    for _ in 0..64 {
        held.push(UnixStream::connect(&h.socket).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let t0 = std::time::Instant::now();
    let mut attempts = 0u64;
    while t0.elapsed() < Duration::from_secs(1) {
        if let Ok(s) = UnixStream::connect(&h.socket).await {
            drop(s);
        }
        attempts += 1;
    }
    tokio::time::sleep(Duration::from_millis(800)).await;
    let audit = h.audit();
    let lines = audit
        .iter()
        .filter(|r| r.outcome == "denied:too_many_connections")
        .count();
    let summarised: u64 = audit
        .iter()
        .filter(|r| r.outcome == "suppressed:denied:too_many_connections")
        .map(|r| r.suppressed)
        .sum();
    eprintln!("F-2: {attempts} connects -> {lines} lines, {summarised} summarised");
    assert!(lines <= 25, "{lines} audit lines");
    assert!(attempts > 100);
    assert!(
        summarised as usize + lines >= (attempts as usize) * 9 / 10,
        "{summarised} + {lines} vs {attempts}"
    );
}

/// F-2: denied requests on one keep-alive connection are limited the same
/// way.
#[tokio::test]
async fn f2_denied_requests_rate_limited() {
    let h = start(|v| {
        v["limits"]["audit_denials_per_second"] = 5.into();
        v["limits"]["audit_denials_burst"] = 10.into();
        v["limits"]["audit_summary_interval_ms"] = 200.into();
    })
    .await;
    let mut req = Vec::new();
    for _ in 0..300 {
        req.extend_from_slice(b"GET /v1/admin HTTP/1.1\r\nhost: x\r\n\r\n");
    }
    req.extend_from_slice(&get("/v1/admin"));
    let r = raw(&h.socket, &req).await;
    assert_eq!(r.matches("HTTP/1.1 403").count(), 301);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let audit = h.audit();
    let lines = audit
        .iter()
        .filter(|r| r.outcome == "denied:route_not_allowed")
        .count();
    let summarised: u64 = audit
        .iter()
        .filter(|r| r.outcome == "suppressed:denied:route_not_allowed")
        .map(|r| r.suppressed)
        .sum();
    assert!(lines <= 20, "{lines}");
    assert_eq!(lines as u64 + summarised, 301);
}

// ---------------------------------------------------------------- F-3 ---

/// Upstream that streams chunked data forever; counts open connections.
async fn infinite_upstream() -> (
    u16,
    rustls::pki_types::CertificateDer<'static>,
    Arc<Mutex<u64>>,
) {
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
    let port = listener.local_addr().unwrap().port();
    let open = Arc::new(Mutex::new(0u64));
    let open2 = Arc::clone(&open);
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acc = acceptor.clone();
            let open = Arc::clone(&open2);
            tokio::spawn(async move {
                let Ok(mut s) = acc.accept(tcp).await else {
                    return;
                };
                let mut b = [0u8; 4096];
                let _ = s.read(&mut b).await;
                *open.lock().unwrap() += 1;
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n")
                    .await;
                let chunk = vec![b'z'; 16384];
                loop {
                    let r = async {
                        s.write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                            .await?;
                        s.write_all(&chunk).await?;
                        s.write_all(b"\r\n").await?;
                        s.flush().await
                    }
                    .await;
                    if r.is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                *open.lock().unwrap() -= 1;
            });
        }
    });
    (port, ca, open)
}

struct Infinite {
    socket: std::path::PathBuf,
    open: Arc<Mutex<u64>>,
    audit: Arc<Mutex<Vec<AuditRecord>>>,
    budget: Arc<tessera_model_proxy::budget::Budget>,
    _dir: tempfile::TempDir,
}

async fn start_infinite() -> Infinite {
    let (port, ca, open) = infinite_upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("m.sock");
    let mut v = base_config(port, &socket);
    v["upstream"]["max_duration_ms"] = 2000.into();
    v["upstream"]["idle_timeout_ms"] = 1000.into();
    v["limits"]["max_response_body"] = (1u64 << 40).into();
    v["sandboxes"][0]["budget"] = serde_json::json!({ "max_concurrent": 1 });
    let cfg = ProxyConfig::from_json(&v.to_string()).unwrap();
    let cred = Credential::new(SECRET.as_bytes(), cfg.credential.inject).unwrap();
    let up = Upstream::with_roots(&cfg.upstream, Some(vec![ca])).unwrap();
    let audit = Arc::new(Mutex::new(Vec::<AuditRecord>::new()));
    let a2 = Arc::clone(&audit);
    let sink: tessera_model_proxy::AuditSink =
        Arc::new(move |r: &AuditRecord| a2.lock().unwrap().push(r.clone()));
    let proxy = ModelProxy::new(&cfg, cred, up, sink).unwrap();
    let l = proxy.bind(&cfg.sandboxes[0]).unwrap();
    let budget = l.budget();
    tokio::spawn(async move { proxy.serve(l).await });
    Infinite {
        socket,
        open,
        audit,
        budget,
        _dir: dir,
    }
}

/// F-3: a sandbox that stops reading a streamed response no longer pins
/// the pump: the send is bounded by the idle/max-duration deadline, the
/// permit and the upstream connection are released, and the request is
/// audited (a `forwarded` record before contacting the upstream, then a
/// completion record).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f3_stalled_reader_released_and_audited() {
    let p = start_infinite().await;
    let mut s = UnixStream::connect(&p.socket).await.unwrap();
    s.write_all(&post("/v1/stream", "", "{}")).await.unwrap();
    let mut b = [0u8; 1024];
    assert!(s.read(&mut b).await.unwrap() > 0);
    // Stop reading entirely, keep the socket open.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let up_open = *p.open.lock().unwrap();
    let audit = p.audit.lock().unwrap().clone();
    eprintln!("F-3: upstream open={up_open}, audit={:?}", outcomes(&audit));
    assert_eq!(p.budget.admit(0).map(drop), Ok(()), "permit still held");
    assert_eq!(up_open, 0, "upstream connection still open");
    assert_eq!(audit.len(), 2, "{audit:?}");
    assert_eq!(audit[0].outcome, "forwarded");
    assert_eq!(audit[1].id, audit[0].id);
    assert!(
        audit[1].outcome == "aborted:client_stalled" || audit[1].outcome == "aborted:max_duration",
        "{audit:?}"
    );
    drop(s);
}

/// F-3: a client that closes mid-stream stops the pump at once, even while
/// the pump is waiting for the upstream.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f3_client_close_stops_pump() {
    let h = start(|_| {}).await;
    let mut s = UnixStream::connect(&h.socket).await.unwrap();
    s.write_all(&post("/v1/stream", "", "{}")).await.unwrap();
    let mut b = [0u8; 1024];
    assert!(s.read(&mut b).await.unwrap() > 0);
    // The upstream now holds the second event (gate) indefinitely.
    drop(s);
    let audit = h.wait_audit(2).await;
    assert_eq!(
        outcomes(&audit),
        vec!["forwarded".to_string(), "aborted:client_gone".to_string()]
    );
    assert_eq!(h.budget.admit(0).map(drop), Ok(()));
}

/// F-3: every forwarded request has a `forwarded` record written before the
/// upstream is contacted, even when the upstream then fails.
#[tokio::test]
async fn f3_forwarded_record_precedes_upstream_failure() {
    let (other_ca, _, _) = ca_and_leaf(&["unused.test"]);
    let h = start_with(|_| {}, Some(vec![other_ca])).await;
    assert_eq!(
        status_of(&raw(&h.socket, &post("/v1/messages", "", "{}")).await),
        502
    );
    let audit = h.wait_audit(2).await;
    assert_eq!(
        outcomes(&audit),
        vec!["forwarded".to_string(), "upstream:tls_failed".to_string()]
    );
    assert_eq!(audit[0].request_sha256, audit[1].request_sha256);
    assert_eq!(audit[0].id, audit[1].id);
}

// ---------------------------------------------------------------- F-4 ---

/// F-4: path parameters, double encoding and segments that decode to dot
/// segments are refused (same rules as the HTTPS adapter, 6050055).
#[tokio::test]
async fn f4_semicolon_and_double_encoding_refused() {
    let h = start(|_| {}).await;
    for p in [
        "/v1/models/..;/messages",
        "/v1/models/%252e%252e/files",
        "/v1/models/x;jsessionid=1",
        "/v1/models/%25%32%65%25%32%65",
        "/v1/models/%zz",
    ] {
        let r = raw(&h.socket, &get(p)).await;
        assert_eq!(status_of(&r), 400, "{p}: {r}");
    }
    assert!(h.upstream.seen().is_empty(), "{:?}", h.upstream.seen());
    // A plain percent escape that is not a separator is still fine.
    assert_eq!(
        status_of(&raw(&h.socket, &get("/v1/models/a%20b")).await),
        200
    );
}

// ---------------------------------------------------------------- F-5 ---

/// F-5: account/feature selection headers are not forwarded by default
/// (request header allowlist; `anthropic-beta` values filtered by an
/// allowlist that is empty by default).
#[tokio::test]
async fn f5_selection_headers_not_forwarded() {
    let h = start(|_| {}).await;
    let r = raw(
        &h.socket,
        &post(
            "/v1/messages",
            "openai-organization: org-other\r\nopenai-project: proj-other\r\n\
             anthropic-beta: mcp-client-2025-04-04,web-fetch-2025-09-10\r\n\
             x-custom: 1\r\nanthropic-version: 2023-06-01\r\n\
             connection: x-api-key, keep-alive\r\n",
            "{}",
        ),
    )
    .await;
    assert_eq!(status_of(&r), 200, "{r}");
    let head = h.upstream.seen()[0].head.to_ascii_lowercase();
    for k in [
        "openai-organization",
        "openai-project",
        "anthropic-beta",
        "x-custom",
    ] {
        assert!(!head.contains(k), "{k} forwarded: {head}");
    }
    assert!(head.contains("anthropic-version: 2023-06-01"));
    // Connection-named x-api-key must not remove the injected key.
    assert!(head.contains("x-api-key: sk-test"));
}

/// F-5: `anthropic-beta` values outside the allowlist are removed.
#[tokio::test]
async fn f5_anthropic_beta_value_allowlist() {
    let h = start(|v| {
        v["anthropic_beta_allow"] = serde_json::json!(["claude-code-20250219"]);
    })
    .await;
    let r = raw(
        &h.socket,
        &post(
            "/v1/messages",
            "anthropic-beta: mcp-client-2025-04-04, claude-code-20250219\r\n\
             anthropic-beta: web-fetch-2025-09-10\r\n",
            "{}",
        ),
    )
    .await;
    assert_eq!(status_of(&r), 200, "{r}");
    let head = h.upstream.seen()[0].head.to_ascii_lowercase();
    assert!(
        head.contains("anthropic-beta: claude-code-20250219\r\n"),
        "{head}"
    );
    assert_eq!(head.matches("anthropic-beta").count(), 1, "{head}");
    assert!(!head.contains("mcp-client") && !head.contains("web-fetch"));
}

/// F-5: compressed request bodies are refused (the byte budget and the
/// body policy would see compressed bytes).
#[tokio::test]
async fn f5_request_content_encoding_refused() {
    let h = start(|_| {}).await;
    for ce in ["gzip", "br", "identity, gzip"] {
        let r = raw(
            &h.socket,
            &post("/v1/messages", &format!("content-encoding: {ce}\r\n"), "{}"),
        )
        .await;
        assert_eq!(status_of(&r), 415, "{ce}: {r}");
    }
    assert!(h.upstream.seen().is_empty());
}

// ---------------------------------------------------------- S-1 / S-2 ---

fn with_body_policy(policy: serde_json::Value) -> impl FnOnce(&mut serde_json::Value) {
    move |v| {
        v["body_policy"] = policy;
        v["routes"][1]["token_cap"] = false.into(); // count_tokens
    }
}

/// S-1: provider-side tools that make the provider reach arbitrary hosts
/// are refused by the JSON body policy.
#[tokio::test]
async fn s1_body_policy_refuses_server_side_tools() {
    let h = start(with_body_policy(serde_json::json!({}))).await;
    let denied: &[(&str, u16)] = &[
        (
            r#"{"model":"m","mcp_servers":[{"type":"url","url":"https://evil.example/sse","name":"x"}]}"#,
            403,
        ),
        (
            r#"{"model":"m","tools":[{"type":"web_fetch_20250910","name":"web_fetch"}]}"#,
            403,
        ),
        (
            r#"{"model":"m","tools":[{"type":"web_search_20250305","name":"web_search"}]}"#,
            403,
        ),
        (
            r#"{"model":"m","tools":[{"type":"mcp","server_label":"x","server_url":"https://evil.example"}]}"#,
            403,
        ),
        (r#"{"model":"m","tools":[{"type":"web_search"}]}"#, 403),
        (r#"{"model":"m","tools":{"type":"web_search"}}"#, 403),
        (r#"{"model":"m","tools":[{"type":7}]}"#, 403),
        (r#"{"model":"m","mcp_servers":[]}"#, 403),
        // Duplicate keys: a parser that keeps the first value would see the
        // harmless one; refuse instead of guessing.
        (
            r#"{"model":"m","tools":[],"tools":[{"type":"web_search"}]}"#,
            400,
        ),
        ("not json", 400),
        ("[1,2]", 400),
        (r#"{"model":"m"} trailing"#, 400),
    ];
    for (body, want) in denied {
        let r = raw(&h.socket, &post("/v1/messages", "", body)).await;
        assert_eq!(status_of(&r), *want, "{body}: {r}");
    }
    assert!(h.upstream.seen().is_empty(), "{:?}", h.upstream.seen());
    let allowed = [
        r#"{"model":"m","tools":[{"name":"Bash","input_schema":{"type":"object"}}]}"#,
        r#"{"model":"m","tools":[{"type":"custom","name":"x","input_schema":{}}]}"#,
        r#"{"model":"m","tools":[{"type":"function","name":"f","parameters":{}}]}"#,
        r#"{"model":"m","messages":[{"role":"user","content":"mcp_servers web_search"}]}"#,
    ];
    for body in allowed {
        let r = raw(&h.socket, &post("/v1/messages", "", body)).await;
        assert_eq!(status_of(&r), 200, "{body}: {r}");
    }
    // Requests without a body (GET routes) are not affected.
    assert_eq!(status_of(&raw(&h.socket, &get("/v1/models")).await), 200);
    let audit = h.wait_audit(1).await;
    assert!(
        audit
            .iter()
            .any(|a| a.outcome == "denied:body_policy:mcp_servers"),
        "{:?}",
        outcomes(&audit)
    );
}

/// S-2: optional per-request `max_tokens` cap and model allowlist.
#[tokio::test]
async fn s2_max_tokens_cap_and_model_allowlist() {
    let h = start(with_body_policy(serde_json::json!({
        "max_tokens": 1000,
        "models": ["m1"]
    })))
    .await;
    let cases: &[(&str, &str, u16)] = &[
        ("/v1/messages", r#"{"model":"m1"}"#, 403),
        ("/v1/messages", r#"{"model":"m1","max_tokens":2000}"#, 403),
        ("/v1/messages", r#"{"model":"m1","max_tokens":"10"}"#, 403),
        ("/v1/messages", r#"{"model":"m1","max_tokens":10.5}"#, 403),
        ("/v1/messages", r#"{"model":"m1","max_tokens":-1}"#, 403),
        (
            "/v1/messages",
            r#"{"model":"m1","max_tokens":10,"max_output_tokens":5000}"#,
            403,
        ),
        ("/v1/messages", r#"{"model":"m2","max_tokens":10}"#, 403),
        ("/v1/messages", r#"{"max_tokens":10}"#, 403),
        ("/v1/messages", r#"{"model":"m1","max_tokens":1000}"#, 200),
        // count_tokens is configured without the token cap.
        ("/v1/messages/count_tokens", r#"{"model":"m1"}"#, 200),
        ("/v1/messages/count_tokens", r#"{"model":"m2"}"#, 403),
    ];
    for (path, body, want) in cases {
        let r = raw(&h.socket, &post(path, "", body)).await;
        assert_eq!(status_of(&r), *want, "{path} {body}: {r}");
    }
    assert_eq!(h.upstream.seen().len(), 2);
}

// ---------------------------------------------------------------- S-3 ---

/// S-3: the resolved address of a forbidden destination is kept in the host
/// audit log and not returned to the sandbox.
#[tokio::test]
async fn s3_destination_forbidden_detail_not_returned() {
    let h = start(|v| v["upstream"]["allow_private"] = false.into()).await;
    let resp = raw(&h.socket, &post("/v1/messages", "", "{}")).await;
    assert_eq!(status_of(&resp), 502, "{resp}");
    assert!(resp.contains("destination_forbidden"), "{resp}");
    assert!(!resp.contains("127.0.0.1"), "{resp}");
    let audit = h.wait_audit(2).await;
    assert!(
        audit
            .iter()
            .any(|a| a.outcome == "upstream:destination_forbidden:127.0.0.1"),
        "{:?}",
        outcomes(&audit)
    );
}

// ----------------------------------------------------------- examples ---

/// The shipped example configurations parse, validate and turn the new
/// defences on (header allowlist, body policy).
#[test]
fn example_configs_enable_body_policy() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/compat");
    for name in ["anthropic-proxy.json", "openai-proxy.json"] {
        let text = std::fs::read_to_string(dir.join(name)).unwrap();
        let cfg = ProxyConfig::from_json(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
        cfg.validate().unwrap_or_else(|e| panic!("{name}: {e}"));
        let raw: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(raw["body_policy"].is_object(), "{name}: body_policy");
        assert!(
            raw["forward_request_headers"].is_array(),
            "{name}: forward_request_headers"
        );
        assert!(
            raw["limits"]["max_request_body"]
                .as_u64()
                .is_none_or(|n| n <= 16 << 20),
            "{name}: max_request_body"
        );
    }
}
