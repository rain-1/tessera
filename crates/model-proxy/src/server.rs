//! The proxy server: one Unix-socket listener per sandbox, plain HTTP/1.1
//! from the sandbox, one fresh TLS connection upstream per request.

use std::convert::Infallible;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use http::header::{ACCEPT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderValue, UPGRADE};
use http::{Method, Request, Response, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

use crate::audit::{AuditRecord, AuditSink, hex, now_ms, sanitise};
use crate::budget::Budget;
use crate::config::{ConfigError, LimitsConfig, ProxyConfig, SandboxConfig, ms};
use crate::policy::{Denial, HeaderPolicy, Route, origin_form, route_allows};
use crate::secret::{Credential, Redactor};
use crate::upstream::{AbortOnDrop, Upstream, UpstreamError};

/// Most simultaneous connections from one sandbox.
const MAX_CONNECTIONS_PER_SANDBOX: usize = 64;
/// First byte of a TLS record carrying a handshake.
const TLS_HANDSHAKE: u8 = 0x16;

struct Inner {
    upstream: Upstream,
    credential: Credential,
    routes: Vec<Route>,
    headers: HeaderPolicy,
    limits: LimitsConfig,
    audit: AuditSink,
}

/// The trusted model proxy. Cheap to clone.
#[derive(Clone)]
pub struct ModelProxy {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for ModelProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelProxy")
            .field("upstream", &self.inner.upstream)
            .field("credential", &self.inner.credential)
            .finish_non_exhaustive()
    }
}

/// A bound per-sandbox socket, ready to [`ModelProxy::serve`].
pub struct SandboxListener {
    label: String,
    path: PathBuf,
    listener: UnixListener,
    budget: Arc<Budget>,
    peer_uids: Vec<u32>,
}

impl SandboxListener {
    /// Sandbox label.
    pub fn label(&self) -> &str {
        &self.label
    }
    /// Socket path on the host.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
    /// Shared budget (for inspection).
    pub fn budget(&self) -> Arc<Budget> {
        Arc::clone(&self.budget)
    }
}

impl ModelProxy {
    /// Build from validated configuration plus an already-loaded credential
    /// and upstream.
    pub fn new(
        cfg: &ProxyConfig,
        credential: Credential,
        upstream: Upstream,
        audit: AuditSink,
    ) -> Result<Self, ConfigError> {
        cfg.validate()?;
        if cfg.credential.inject.header_name() != credential.header_name() {
            return Err(ConfigError("credential injection mismatch".into()));
        }
        let headers = HeaderPolicy::new(
            credential.header_name(),
            &cfg.strip_request_headers,
            cfg.forward_request_headers.as_deref(),
            &cfg.strip_response_headers,
        )
        .map_err(ConfigError)?;
        Ok(Self {
            inner: Arc::new(Inner {
                upstream,
                credential,
                routes: cfg.compile_routes()?,
                headers,
                limits: cfg.limits.clone(),
                audit,
            }),
        })
    }

    /// Create the sandbox's socket (mode 0600). A stale socket at the path is
    /// replaced; any other file there is an error. Must be called inside a
    /// Tokio runtime.
    pub fn bind(&self, s: &SandboxConfig) -> io::Result<SandboxListener> {
        match std::fs::symlink_metadata(&s.socket) {
            Ok(m) if m.file_type().is_socket() => std::fs::remove_file(&s.socket)?,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a socket", s.socket.display()),
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let listener = UnixListener::bind(&s.socket)?;
        std::fs::set_permissions(&s.socket, std::fs::Permissions::from_mode(0o600))?;
        let own_uid = std::fs::metadata(&s.socket)?.uid();
        Ok(SandboxListener {
            label: s.label.clone(),
            path: s.socket.clone(),
            listener,
            budget: Arc::new(Budget::new(s.budget.clone())),
            peer_uids: s.peer_uids.clone().unwrap_or_else(|| vec![own_uid]),
        })
    }

    /// Accept and serve connections forever.
    pub async fn serve(&self, l: SandboxListener) -> io::Result<()> {
        let conns = Arc::new(Semaphore::new(MAX_CONNECTIONS_PER_SANDBOX));
        let label: Arc<str> = Arc::from(l.label.as_str());
        loop {
            let stream = match l.listener.accept().await {
                Ok((s, _)) => s,
                Err(_) => {
                    // EMFILE and friends: back off instead of spinning.
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            let uid_ok = stream
                .peer_cred()
                .map(|c| l.peer_uids.contains(&c.uid()))
                .unwrap_or(false);
            if !uid_ok {
                self.local_event(&label, "denied:peer_uid");
                continue;
            }
            let Ok(permit) = Arc::clone(&conns).try_acquire_owned() else {
                self.local_event(&label, "denied:too_many_connections");
                continue;
            };
            let this = self.clone();
            let budget = Arc::clone(&l.budget);
            let label = Arc::clone(&label);
            tokio::spawn(async move {
                this.connection(stream, label, budget).await;
                drop(permit);
            });
        }
    }

    fn local_event(&self, label: &str, outcome: &str) {
        (self.inner.audit)(&AuditRecord {
            ts_ms: now_ms(),
            sandbox: label.to_owned(),
            method: "-".into(),
            path: "-".into(),
            query_len: 0,
            status: 0,
            outcome: outcome.into(),
            request_bytes: 0,
            request_sha256: String::new(),
            response_bytes: 0,
            response_sha256: String::new(),
            upstream_peer: None,
            redactions: 0,
            duration_ms: 0,
        });
    }

    async fn connection(&self, mut stream: UnixStream, label: Arc<str>, budget: Arc<Budget>) {
        let limits = &self.inner.limits;
        let read_timeout = ms(limits.request_read_timeout_ms);
        let mut first = [0u8; 1];
        match tokio::time::timeout(read_timeout, stream.read(&mut first)).await {
            Ok(Ok(1)) => {}
            _ => return,
        }
        if first[0] == TLS_HANDSHAKE {
            // The harness tried TLS over the socket; tell the operator how to
            // fix the configuration (e.g. ANTHROPIC_BASE_URL=http://localhost).
            self.local_event(&label, "denied:tls_on_plain_http_socket");
            return;
        }
        let io = TokioIo::new(Prefixed {
            first: Some(first[0]),
            inner: stream,
        });
        let this = self.clone();
        let svc = service_fn(move |req| {
            let this = this.clone();
            let label = Arc::clone(&label);
            let budget = Arc::clone(&budget);
            async move { Ok::<_, Infallible>(this.handle(req, &label, &budget).await) }
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(read_timeout)
            .max_buf_size(limits.max_header_bytes.max(8192))
            .max_headers(limits.max_headers)
            .keep_alive(true)
            .serve_connection(io, svc)
            .await;
    }

    async fn handle(
        &self,
        req: Request<Incoming>,
        label: &str,
        budget: &Arc<Budget>,
    ) -> Response<ProxyBody> {
        let start = Instant::now();
        let mut rec = AuditRecord {
            ts_ms: now_ms(),
            sandbox: label.to_owned(),
            method: sanitise(req.method().as_str(), 16),
            path: sanitise(req.uri().path(), 256),
            query_len: req.uri().query().map_or(0, str::len),
            status: 0,
            outcome: String::new(),
            request_bytes: 0,
            request_sha256: String::new(),
            response_bytes: 0,
            response_sha256: String::new(),
            upstream_peer: None,
            redactions: 0,
            duration_ms: 0,
        };
        match self.forward(req, budget, &mut rec, start).await {
            Ok(resp) => resp,
            Err(Failure::Denied(d)) => {
                let r = self.local_response(d.status(), "tessera_proxy_denied", &d.reason());
                self.finish(&mut rec, start, d.status(), format!("denied:{}", d.reason()));
                r
            }
            Err(Failure::Upstream(e)) => {
                let r = self.local_response(e.status(), "api_error", &e.reason());
                self.finish(&mut rec, start, e.status(), format!("upstream:{}", e.reason()));
                r
            }
        }
    }

    fn finish(&self, rec: &mut AuditRecord, start: Instant, status: u16, outcome: String) {
        rec.status = status;
        rec.outcome = outcome;
        rec.duration_ms = start.elapsed().as_millis() as u64;
        (self.inner.audit)(rec);
    }

    fn local_response(&self, status: u16, kind: &str, reason: &str) -> Response<ProxyBody> {
        let body = serde_json::json!({
            "type": "error",
            "error": { "type": kind, "message": format!("tessera model proxy: {reason}") }
        })
        .to_string();
        let mut r = Response::new(ProxyBody::full(Bytes::from(body)));
        *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
        r.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        r.headers_mut().insert(
            "x-tessera-proxy",
            HeaderValue::from_static("local-response"),
        );
        r
    }

    async fn forward(
        &self,
        req: Request<Incoming>,
        budget: &Arc<Budget>,
        rec: &mut AuditRecord,
        start: Instant,
    ) -> Result<Response<ProxyBody>, Failure> {
        let inner = &self.inner;
        let (path, query) = origin_form(req.uri())?;
        let method = req.method().clone();
        if method == Method::CONNECT || req.headers().contains_key(UPGRADE) {
            return Err(Denial::UpgradeNotAllowed.into());
        }
        if !route_allows(&inner.routes, &method, &path, query.is_some()) {
            return Err(Denial::RouteNotAllowed.into());
        }
        let max_body = inner.limits.max_request_body;
        let declared = req
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        if declared.is_some_and(|n| n > max_body) {
            return Err(Denial::BodyTooLarge.into());
        }
        let (parts, body) = req.into_parts();
        let limit = usize::try_from(max_body).unwrap_or(usize::MAX);
        let read = Limited::new(body, limit).collect();
        let body = match tokio::time::timeout(ms(inner.limits.request_read_timeout_ms), read).await
        {
            Err(_) => return Err(Denial::BodyReadFailed.into()),
            Ok(Err(e)) if e.downcast_ref::<LengthLimitError>().is_some() => {
                return Err(Denial::BodyTooLarge.into());
            }
            Ok(Err(_)) => return Err(Denial::BodyReadFailed.into()),
            Ok(Ok(c)) => c.to_bytes(),
        };
        rec.request_bytes = body.len() as u64;
        rec.request_sha256 = hex(&Sha256::digest(&body));
        let permit = budget.admit(body.len() as u64)?;

        let target = match &query {
            Some(q) => format!("{path}?{q}"),
            None => path,
        };
        let mut up = Request::builder()
            .method(method)
            .uri(target)
            .body(Full::new(body))
            .map_err(|_| Denial::BadTarget)?;
        let headers = up.headers_mut();
        *headers = inner.headers.filter_request(&parts.headers);
        headers.insert(
            HOST,
            HeaderValue::from_str(&inner.upstream.host_header).map_err(|_| Denial::BadTarget)?,
        );
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        headers.insert(
            inner.credential.header_name(),
            inner.credential.header_value(),
        );

        let deadline = tokio::time::Instant::from_std(start) + inner.upstream.max_duration;
        let mut conn = inner.upstream.connect().await?;
        rec.upstream_peer = Some(conn.peer.to_string());
        let header_deadline = deadline.min(tokio::time::Instant::now() + inner.upstream.header_timeout);
        let resp = match tokio::time::timeout_at(header_deadline, conn.sender.send_request(up)).await
        {
            Err(_) => return Err(UpstreamError::Timeout.into()),
            Ok(Err(_)) => return Err(UpstreamError::Protocol.into()),
            Ok(Ok(r)) => r,
        };
        let status = resp.status();
        let declared = resp
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        if declared.is_some_and(|n| n > inner.limits.max_response_body) {
            return Err(UpstreamError::Protocol.into());
        }
        let secret = inner.credential.secret();
        let out_headers = inner.headers.filter_response(resp.headers(), secret);
        let (tx, rx) = mpsc::channel(32);
        let mut out = Response::new(ProxyBody::Stream(rx));
        *out.status_mut() = status;
        *out.headers_mut() = out_headers;
        rec.status = status.as_u16();

        let pump = Pump {
            proxy: self.clone(),
            body: resp.into_body(),
            tx,
            redactor: Redactor::new(secret),
            budget: Arc::clone(budget),
            _permit: permit,
            _driver: conn.driver,
            deadline,
            start,
        };
        tokio::spawn(pump.run(std::mem::replace(
            rec,
            AuditRecord {
                outcome: "handed_to_pump".into(),
                ..rec.clone()
            },
        )));
        Ok(out)
    }
}

enum Failure {
    Denied(Denial),
    Upstream(UpstreamError),
}

impl From<Denial> for Failure {
    fn from(d: Denial) -> Self {
        Self::Denied(d)
    }
}

impl From<UpstreamError> for Failure {
    fn from(e: UpstreamError) -> Self {
        Self::Upstream(e)
    }
}

/// Streams one upstream response body to the sandbox.
struct Pump {
    proxy: ModelProxy,
    body: Incoming,
    tx: mpsc::Sender<Result<Bytes, io::Error>>,
    redactor: Redactor,
    budget: Arc<Budget>,
    _permit: OwnedSemaphorePermit,
    _driver: AbortOnDrop,
    deadline: tokio::time::Instant,
    start: Instant,
}

impl Pump {
    async fn run(mut self, mut rec: AuditRecord) {
        let limits = self.proxy.inner.limits.clone();
        let idle = self.proxy.inner.upstream.idle_timeout;
        let mut hasher = Sha256::new();
        let mut sent: u64 = 0;
        let mut outcome: Option<String> = None;
        loop {
            let wait = self.deadline.min(tokio::time::Instant::now() + idle);
            let (chunk, done) = match tokio::time::timeout_at(wait, self.body.frame()).await {
                Err(_) => {
                    outcome = Some("aborted:upstream_timeout".into());
                    break;
                }
                Ok(None) => (self.redactor.finish(), true),
                Ok(Some(Err(_))) => {
                    outcome = Some("aborted:upstream_error".into());
                    break;
                }
                Ok(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => (self.redactor.feed(&data), false),
                    Err(_) => continue, // trailers are dropped
                },
            };
            if !chunk.is_empty() {
                let n = chunk.len() as u64;
                if sent.saturating_add(n) > limits.max_response_body {
                    outcome = Some("aborted:response_too_large".into());
                    break;
                }
                if !self.budget.charge_response(n) {
                    outcome = Some("aborted:budget_exhausted:response_bytes".into());
                    break;
                }
                hasher.update(&chunk);
                sent += n;
                if self.tx.send(Ok(chunk)).await.is_err() {
                    outcome = Some("aborted:client_gone".into());
                    break;
                }
            }
            if done {
                break;
            }
        }
        if let Some(reason) = &outcome {
            // Terminate the chunked response abnormally so the client sees a
            // truncated body rather than a clean end.
            let _ = self.tx.send(Err(io::Error::other(reason.clone()))).await;
        }
        rec.response_bytes = sent;
        rec.response_sha256 = hex(&hasher.finalize());
        rec.redactions = self.redactor.hits;
        rec.outcome = outcome.unwrap_or_else(|| "ok".into());
        rec.duration_ms = self.start.elapsed().as_millis() as u64;
        (self.proxy.inner.audit)(&rec);
    }
}

/// Response body returned to the sandbox.
pub enum ProxyBody {
    /// A complete local body.
    Full(Option<Bytes>),
    /// Streamed from the upstream by a pump task.
    Stream(mpsc::Receiver<Result<Bytes, io::Error>>),
}

impl ProxyBody {
    fn full(b: Bytes) -> Self {
        Self::Full(Some(b))
    }
}

impl Body for ProxyBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        match self.get_mut() {
            Self::Full(b) => Poll::Ready(b.take().map(|b| Ok(Frame::data(b)))),
            Self::Stream(rx) => rx.poll_recv(cx).map(|o| o.map(|r| r.map(Frame::data))),
        }
    }

    fn is_end_stream(&self) -> bool {
        matches!(self, Self::Full(None))
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Full(Some(b)) => SizeHint::with_exact(b.len() as u64),
            Self::Full(None) => SizeHint::with_exact(0),
            Self::Stream(_) => SizeHint::default(),
        }
    }
}

/// Replays one already-read byte before the rest of the stream.
struct Prefixed<S> {
    first: Option<u8>,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(b) = this.first.take() {
            if buf.remaining() == 0 {
                this.first = Some(b);
                return Poll::Ready(Ok(()));
            }
            buf.put_slice(&[b]);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
