//! Model proxy integration tests against a local TLS upstream.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use bytes::Bytes;
use common::*;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

fn assert_no_secret(s: &str) {
    assert!(!s.contains(SECRET), "credential leaked: {s}");
}

#[tokio::test]
async fn allowed_route_forwarded_with_injected_key_and_client_auth_stripped() {
    let h = start(|_| {}).await;
    let resp = raw(
        &h.socket,
        &post(
            "/v1/messages?beta=true",
            "authorization: Bearer sandbox-token\r\nx-api-key: sandbox-key\r\n\
             cookie: c=1\r\nproxy-authorization: Basic eA==\r\naccept-encoding: gzip\r\n\
             x-forwarded-for: 1.2.3.4\r\nanthropic-version: 2023-06-01\r\n",
            "{\"model\":\"m\"}",
        ),
    )
    .await;
    assert_eq!(status_of(&resp), 200, "{resp}");
    let seen = h.upstream.seen();
    assert_eq!(seen.len(), 1);
    let head = seen[0].head.to_ascii_lowercase();
    assert_eq!(seen[0].target, "/v1/messages?beta=true");
    assert_eq!(seen[0].body_len, 13);
    assert!(head.contains(&format!("x-api-key: {}", SECRET.to_ascii_lowercase())));
    assert_eq!(head.matches("x-api-key:").count(), 1, "{head}");
    for gone in [
        "authorization:",
        "sandbox-key",
        "sandbox-token",
        "cookie:",
        "x-forwarded-for",
        "gzip",
    ] {
        assert!(!head.contains(gone), "{gone} forwarded: {head}");
    }
    assert!(head.contains(&format!("host: {HOST}:{}", h.upstream.addr.port())));
    assert!(head.contains("accept-encoding: identity"));
    assert!(head.contains("anthropic-version: 2023-06-01"));

    // The upstream echoed the credential in headers and body: neither
    // reaches the sandbox.
    assert_no_secret(&resp);
    let lower = resp.to_ascii_lowercase();
    assert!(!lower.contains("x-echo-api-key"), "{resp}");
    assert!(!lower.contains("\r\nx-api-key"), "{resp}");
    assert!(!lower.contains("set-cookie"), "{resp}");
    assert!(lower.contains("request-id: req_1"));
    assert!(resp.contains("[REDACTED-BY-TESSERA]"));

    // A `forwarded` record before contacting the upstream, then the
    // completion record (review 2026-11-26, F-3).
    let audit = h.wait_audit(2).await;
    assert_eq!(audit.len(), 2);
    assert_eq!(audit[0].outcome, "forwarded");
    assert_eq!(audit[0].id, audit[1].id);
    assert_eq!(audit[0].request_sha256, audit[1].request_sha256);
    let a = &audit[1];
    assert_eq!(
        (a.sandbox.as_str(), a.method.as_str(), a.path.as_str()),
        ("agent-1", "POST", "/v1/messages")
    );
    assert_eq!((a.status, a.outcome.as_str()), (200, "ok"));
    assert_eq!((a.query_len, a.request_bytes), (9, 13));
    assert!(a.response_bytes > 0 && a.redactions >= 1);
    assert_eq!(a.request_sha256.len(), 64);
    let line = serde_json::to_string(a).unwrap();
    assert_no_secret(&line);
    assert!(
        !line.contains("model"),
        "audit must not contain bodies: {line}"
    );
    assert!(
        !line.contains("beta"),
        "audit must not contain queries: {line}"
    );
}

#[tokio::test]
async fn bearer_injection() {
    let h = start(bearer).await;
    let resp = raw(
        &h.socket,
        &post(
            "/v1/messages",
            "authorization: Bearer sandbox-token\r\n",
            "{}",
        ),
    )
    .await;
    assert_eq!(status_of(&resp), 200, "{resp}");
    let head = h.upstream.seen()[0].head.clone();
    assert!(
        head.contains(&format!("authorization: Bearer {SECRET}")),
        "{head}"
    );
    assert_eq!(
        head.to_ascii_lowercase().matches("authorization:").count(),
        1
    );
    assert!(!head.contains("sandbox-token"));
    assert_no_secret(&resp);
}

#[tokio::test]
async fn disallowed_requests_never_reach_upstream() {
    let h = start(|_| {}).await;
    let cases: Vec<(Vec<u8>, u16)> = vec![
        (get("/v1/messages"), 403),                               // wrong method
        (post("/v1/messages/batches", "", "{}"), 403),            // not a route
        (post("/v1/complete", "", "{}"), 403),                    // not a route
        (get("/v1/modelsx"), 403),                                // prefix boundary
        (post("/v1/../v1/messages", "", "{}"), 400),              // dot segment
        (post("/v1/%2e%2e/messages", "", "{}"), 400),             // encoded dot
        (post("//evil.example/v1/messages", "", "{}"), 400),      // scheme-relative
        (post("http://evil.example/v1/messages", "", "{}"), 400), // absolute-form
        (
            b"CONNECT evil.example:443 HTTP/1.1\r\nhost: evil.example:443\r\n\r\n".to_vec(),
            400,
        ),
        (
            post(
                "/v1/messages",
                "upgrade: websocket\r\nconnection: upgrade\r\n",
                "{}",
            ),
            403,
        ),
        (
            b"DELETE /v1/models/x HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n".to_vec(),
            403,
        ),
    ];
    for (req, want) in cases {
        let resp = raw(&h.socket, &req).await;
        let got = status_of(&resp);
        // hyper itself rejects some malformed targets (CONNECT authority)
        // before the service runs; any 4xx without upstream contact is fine
        // there, but our own denials must have the exact status.
        if want == 400 && got != 400 {
            assert!((400..500).contains(&got) || got == 0, "{resp}");
        } else {
            assert_eq!(got, want, "{}: {resp}", String::from_utf8_lossy(&req));
        }
    }
    assert!(h.upstream.seen().is_empty(), "{:?}", h.upstream.seen());
    // Prefix route still works.
    assert_eq!(
        status_of(&raw(&h.socket, &get("/v1/models/abc")).await),
        200
    );
    // A client Host header never selects the upstream.
    let resp = raw(
        &h.socket,
        b"POST /v1/messages HTTP/1.1\r\nhost: evil.example\r\nconnection: close\r\ncontent-length: 2\r\n\r\n{}",
    )
    .await;
    assert_eq!(status_of(&resp), 200);
    let seen = h.upstream.seen();
    assert!(!seen.last().unwrap().head.contains("evil.example"));
}

#[tokio::test]
async fn non_global_upstream_address_refused_by_default() {
    let h = start(|v| v["upstream"]["allow_private"] = false.into()).await;
    let resp = raw(&h.socket, &post("/v1/messages", "", "{}")).await;
    assert_eq!(status_of(&resp), 502, "{resp}");
    assert!(resp.contains("destination_forbidden"));
    assert!(h.upstream.seen().is_empty());
}

#[tokio::test]
async fn tls_validation_wrong_ca_and_wrong_name() {
    let (other_ca, _, _) = ca_and_leaf(&["unused.test"]);
    let h = start_with(|_| {}, Some(vec![other_ca])).await;
    let resp = raw(&h.socket, &post("/v1/messages", "", "{}")).await;
    assert_eq!(status_of(&resp), 502, "{resp}");
    assert!(resp.contains("tls_failed"));
    assert!(h.upstream.seen().is_empty());

    let h = start(|v| v["upstream"]["host"] = "other.test".into()).await;
    let resp = raw(&h.socket, &post("/v1/messages", "", "{}")).await;
    assert_eq!(status_of(&resp), 502, "{resp}");
    assert!(resp.contains("tls_failed"));
    assert!(h.upstream.seen().is_empty());
}

#[tokio::test]
async fn redirects_are_returned_not_followed() {
    let h = start(|_| {}).await;
    let resp = raw(&h.socket, &get("/v1/redirect")).await;
    assert_eq!(status_of(&resp), 302);
    assert!(resp.contains("evil.example"));
    assert_eq!(h.upstream.seen().len(), 1);
}

#[tokio::test]
async fn size_limits() {
    let h = start(|_| {}).await;
    // Declared body too large.
    let big = "a".repeat(5000);
    let resp = raw(&h.socket, &post("/v1/messages", "", &big)).await;
    assert_eq!(status_of(&resp), 413, "{resp}");
    // Chunked body too large (no content-length).
    let mut req =
        b"POST /v1/messages HTTP/1.1\r\nhost: x\r\nconnection: close\r\ntransfer-encoding: chunked\r\n\r\n"
            .to_vec();
    for _ in 0..5 {
        req.extend_from_slice(b"3e8\r\n");
        req.extend_from_slice(&[b'a'; 1000]);
        req.extend_from_slice(b"\r\n");
    }
    req.extend_from_slice(b"0\r\n\r\n");
    assert_eq!(status_of(&raw(&h.socket, &req).await), 413);
    // Oversized request head.
    let hdr = format!("x-pad: {}\r\n", "p".repeat(20_000));
    let resp = raw(&h.socket, &post("/v1/messages", &hdr, "{}")).await;
    assert_eq!(status_of(&resp), 431, "{resp}");
    assert!(h.upstream.seen().is_empty());
    // Declared response too large: refused before streaming.
    assert_eq!(status_of(&raw(&h.socket, &get("/v1/big")).await), 502);
    // Chunked response too large: stream cut at the limit.
    let resp = raw(&h.socket, &get("/v1/bigchunked")).await;
    assert_eq!(status_of(&resp), 200);
    assert!(resp.matches('y').count() <= 50_000);
    assert!(
        !resp.ends_with("0\r\n\r\n"),
        "truncated stream must not end cleanly"
    );
    let audit = h.wait_audit(5).await;
    assert!(
        audit
            .iter()
            .any(|a| a.outcome == "aborted:response_too_large"),
        "{audit:?}"
    );
}

#[tokio::test]
async fn sse_is_streamed_incrementally() {
    let h = start(|_| {}).await;
    let stream = UnixStream::connect(&h.socket).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = http::Request::post("/v1/stream")
        .header("host", "localhost")
        .body(Full::new(Bytes::from_static(b"{}")))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], "text/event-stream");
    let mut body = resp.into_body();
    // The first event arrives while the upstream is still holding the second.
    let first = tokio::time::timeout(Duration::from_secs(5), body.frame())
        .await
        .expect("first event not streamed")
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert!(String::from_utf8_lossy(&first).contains("message_start"));
    h.upstream.gate.notify_one();
    let mut rest = Vec::new();
    while let Some(f) = body.frame().await {
        if let Ok(d) = f.unwrap().into_data() {
            rest.extend_from_slice(&d);
        }
    }
    assert!(String::from_utf8_lossy(&rest).contains("message_stop"));
}

#[tokio::test]
async fn rate_limit_and_budgets() {
    let h = start(|v| {
        v["sandboxes"][0]["budget"] =
            serde_json::json!({ "requests_per_minute": 1, "burst": 2, "max_requests": 10 });
    })
    .await;
    for _ in 0..2 {
        assert_eq!(
            status_of(&raw(&h.socket, &post("/v1/messages", "", "{}")).await),
            200
        );
    }
    let resp = raw(&h.socket, &post("/v1/messages", "", "{}")).await;
    assert_eq!(status_of(&resp), 429, "{resp}");
    assert_eq!(h.upstream.seen().len(), 2);

    let h = start(|v| {
        v["sandboxes"][0]["budget"] = serde_json::json!({ "max_requests": 1 });
    })
    .await;
    assert_eq!(
        status_of(&raw(&h.socket, &post("/v1/messages", "", "{}")).await),
        200
    );
    let resp = raw(&h.socket, &post("/v1/messages", "", "{}")).await;
    assert_eq!(status_of(&resp), 403, "{resp}");
    assert!(resp.contains("budget_exhausted:requests"));

    let h = start(|v| {
        v["sandboxes"][0]["budget"] = serde_json::json!({ "max_response_bytes": 10 });
    })
    .await;
    let resp = raw(&h.socket, &post("/v1/messages", "", "{}")).await;
    assert_eq!(status_of(&resp), 200);
    assert!(h.budget.usage().response_bytes <= 10);
    let resp = raw(&h.socket, &post("/v1/messages", "", "{}")).await;
    assert_eq!(status_of(&resp), 403, "{resp}");
}

#[tokio::test]
async fn socket_mode_and_tls_on_plain_socket() {
    let h = start(|_| {}).await;
    let mode = std::fs::metadata(&h.socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let mut s = UnixStream::connect(&h.socket).await.unwrap();
    s.write_all(&[0x16, 0x03, 0x01, 0x00, 0x10]).await.unwrap();
    let audit = h.wait_audit(1).await;
    assert_eq!(audit[0].outcome, "denied:tls_on_plain_http_socket");
}

#[tokio::test]
async fn shim_forwards_to_proxy_end_to_end() {
    use tokio::io::AsyncReadExt;
    let h = start(|_| {}).await;
    let listener = tessera_model_proxy::shim::bind_loopback("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(tessera_model_proxy::shim::run(listener, h.socket.clone()));
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    tcp.write_all(&post("/v1/messages", "x-api-key: sandbox\r\n", "{}"))
        .await
        .unwrap();
    let mut out = Vec::new();
    tcp.read_to_end(&mut out).await.unwrap();
    let out = String::from_utf8_lossy(&out);
    assert_eq!(status_of(&out), 200, "{out}");
    assert_no_secret(&out);
    assert!(h.upstream.seen()[0].head.contains(SECRET));
}
