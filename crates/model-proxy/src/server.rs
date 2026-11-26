//! The proxy server: one Unix-socket listener per sandbox, plain HTTP/1.1
//! from the sandbox, one fresh TLS connection upstream per request.

use std::convert::Infallible;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use http::header::{
    ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderValue, UPGRADE,
};
use http::{Method, Request, Response, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc};

use crate::audit::{AuditRecord, AuditSink, EventLimiter, hex, sanitise};
use crate::body::BodyPolicy;
use crate::budget::Budget;
use crate::config::{ConfigError, LimitsConfig, ProxyConfig, SandboxConfig, ms};
use crate::policy::{Denial, HeaderPolicy, Route, find_route, origin_form};
use crate::secret::{Credential, Redactor};
use crate::upstream::{AbortOnDrop, Upstream, UpstreamError};

/// Most simultaneous connections from one sandbox.
const MAX_CONNECTIONS_PER_SANDBOX: usize = 64;
/// First byte of a TLS record carrying a handshake.
const TLS_HANDSHAKE: u8 = 0x16;
/// Response chunks buffered between a pump and the sandbox connection.
const STREAM_CHANNEL_CHUNKS: usize = 8;

struct Inner {
    upstream: Upstream,
    credential: Credential,
    routes: Vec<Route>,
    headers: HeaderPolicy,
    body_policy: Option<BodyPolicy>,
    limits: LimitsConfig,
    audit: AuditSink,
    next_id: AtomicU64,
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
            &cfg.anthropic_beta_allow,
        )
        .map_err(ConfigError)?;
        Ok(Self {
            inner: Arc::new(Inner {
                upstream,
                credential,
                routes: cfg.compile_routes()?,
                headers,
                body_policy: cfg.body_policy.as_ref().map(BodyPolicy::new),
                limits: cfg.limits.clone(),
                audit,
                next_id: AtomicU64::new(1),
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
        let limits = &self.inner.limits;
        let ctx = Arc::new(SandboxCtx {
            label: l.label.clone(),
            budget: Arc::clone(&l.budget),
            events: EventLimiter::new(limits.audit_denials_per_second, limits.audit_denials_burst),
        });
        let mut summary = tokio::time::interval(ms(limits.audit_summary_interval_ms));
        summary.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let accepted = tokio::select! {
                _ = summary.tick() => {
                    self.flush_suppressed(&ctx);
                    continue;
                }
                r = l.listener.accept() => r,
            };
            let stream = match accepted {
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
                self.local_event(&ctx, "denied:peer_uid");
                continue;
            }
            let Ok(permit) = Arc::clone(&conns).try_acquire_owned() else {
                self.local_event(&ctx, "denied:too_many_connections");
                continue;
            };
            let this = self.clone();
            let ctx = Arc::clone(&ctx);
            tokio::spawn(async move {
                this.connection(stream, ctx).await;
                drop(permit);
            });
        }
    }

    /// Audit a locally refused connection or request, subject to the
    /// sandbox's audit rate limit (review 2026-11-26, F-2).
    fn audit_limited(&self, ctx: &SandboxCtx, rec: &AuditRecord) {
        if ctx.events.allow(&rec.outcome) {
            (self.inner.audit)(rec);
        }
    }

    fn local_event(&self, ctx: &SandboxCtx, outcome: &str) {
        self.audit_limited(ctx, &AuditRecord::event(&ctx.label, outcome.to_owned()));
    }

    /// Write one `suppressed:<outcome>` summary per outcome with lines
    /// suppressed since the last summary.
    fn flush_suppressed(&self, ctx: &SandboxCtx) {
        for (outcome, n) in ctx.events.take_suppressed() {
            let mut rec = AuditRecord::event(&ctx.label, format!("suppressed:{outcome}"));
            rec.suppressed = n;
            (self.inner.audit)(&rec);
        }
    }

    async fn connection(&self, mut stream: UnixStream, ctx: Arc<SandboxCtx>) {
        let limits = &self.inner.limits;
        let mut first = [0u8; 1];
        match tokio::time::timeout(
            ms(limits.request_header_timeout_ms),
            stream.read(&mut first),
        )
        .await
        {
            Ok(Ok(1)) => {}
            _ => return,
        }
        if first[0] == TLS_HANDSHAKE {
            // The harness tried TLS over the socket; tell the operator how to
            // fix the configuration (e.g. ANTHROPIC_BASE_URL=http://localhost).
            self.local_event(&ctx, "denied:tls_on_plain_http_socket");
            return;
        }
        let io = TokioIo::new(Prefixed {
            first: Some(first[0]),
            inner: stream,
        });
        // Signalled by a pump that gave up on a sandbox that stopped reading:
        // the connection is then closed even though hyper is blocked writing.
        let kill = Arc::new(Notify::new());
        let this = self.clone();
        let svc_kill = Arc::clone(&kill);
        let svc = service_fn(move |req| {
            let this = this.clone();
            let ctx = Arc::clone(&ctx);
            let kill = Arc::clone(&svc_kill);
            async move { Ok::<_, Infallible>(this.handle(req, &ctx, kill).await) }
        });
        let conn = hyper::server::conn::http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(ms(limits.request_header_timeout_ms))
            .max_buf_size(limits.max_header_bytes.max(8192))
            .max_headers(limits.max_headers)
            .keep_alive(true)
            .serve_connection(io, svc);
        tokio::select! {
            _ = conn => {}
            () = kill.notified() => {}
        }
    }

    async fn handle(
        &self,
        req: Request<Incoming>,
        ctx: &SandboxCtx,
        kill: Arc<Notify>,
    ) -> Response<ProxyBody> {
        let start = Instant::now();
        let mut rec = AuditRecord {
            id: self.inner.next_id.fetch_add(1, Ordering::Relaxed),
            path: sanitise(req.uri().path(), 256),
            method: sanitise(req.method().as_str(), 16),
            query_len: req.uri().query().map_or(0, str::len),
            ..AuditRecord::event(&ctx.label, String::new())
        };
        match self.forward(req, ctx, kill, &mut rec, start).await {
            Ok(resp) => resp,
            Err(Failure::Denied(d)) => {
                // Nothing reached the upstream: rate-limited audit (F-2).
                rec.status = d.status();
                rec.outcome = format!("denied:{}", d.reason());
                rec.duration_ms = start.elapsed().as_millis() as u64;
                self.audit_limited(ctx, &rec);
                self.local_response(d.status(), "tessera_proxy_denied", &d.reason())
            }
            Err(Failure::Upstream(e)) => {
                // After admission: bounded by the request budget; always
                // audited, with the detailed reason (S-3) only here.
                rec.status = e.status();
                rec.outcome = format!("upstream:{}", e.reason());
                rec.duration_ms = start.elapsed().as_millis() as u64;
                (self.inner.audit)(&rec);
                self.local_response(e.status(), "api_error", &e.client_reason())
            }
        }
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
        ctx: &SandboxCtx,
        kill: Arc<Notify>,
        rec: &mut AuditRecord,
        start: Instant,
    ) -> Result<Response<ProxyBody>, Failure> {
        let inner = &self.inner;
        let (path, query) = origin_form(req.uri())?;
        let method = req.method().clone();
        if method == Method::CONNECT || req.headers().contains_key(UPGRADE) {
            return Err(Denial::UpgradeNotAllowed.into());
        }
        let route = find_route(&inner.routes, &method, &path, query.is_some())
            .ok_or(Denial::RouteNotAllowed)?;
        // F-5: a compressed body would be counted compressed by the byte
        // budget and could not be inspected by the body policy.
        for v in req.headers().get_all(CONTENT_ENCODING) {
            let identity = v.to_str().is_ok_and(|v| {
                v.split(',')
                    .all(|t| t.trim().eq_ignore_ascii_case("identity"))
            });
            if !identity {
                return Err(Denial::ContentEncoding.into());
            }
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
        // F-1: take the in-flight slot before buffering the body, so
        // `max_concurrent` bounds request memory per sandbox. The permit
        // lives until the response is finished (pump) or this returns.
        let permit = ctx.budget.acquire()?;
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
        // S-1 / S-2: optional JSON body policy.
        if let Some(policy) = &inner.body_policy
            && route.json_body
        {
            policy.check(&body, route.token_cap)?;
        }
        ctx.budget.charge(body.len() as u64)?;

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

        // F-3: the request is on record before anything is sent upstream,
        // whatever happens to the exchange afterwards.
        rec.outcome = "forwarded".into();
        rec.duration_ms = start.elapsed().as_millis() as u64;
        (inner.audit)(rec);

        let deadline = tokio::time::Instant::from_std(start) + inner.upstream.max_duration;
        let mut conn = inner.upstream.connect().await?;
        rec.upstream_peer = Some(conn.peer.to_string());
        let header_deadline =
            deadline.min(tokio::time::Instant::now() + inner.upstream.header_timeout);
        let resp =
            match tokio::time::timeout_at(header_deadline, conn.sender.send_request(up)).await {
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
        let (tx, rx) = mpsc::channel(STREAM_CHANNEL_CHUNKS);
        let complete = Arc::new(AtomicBool::new(false));
        let mut out = Response::new(ProxyBody(Inner_::Stream {
            rx,
            complete: Arc::clone(&complete),
        }));
        *out.status_mut() = status;
        *out.headers_mut() = out_headers;
        rec.status = status.as_u16();

        let pump = Pump {
            proxy: self.clone(),
            body: resp.into_body(),
            tx,
            complete,
            kill,
            redactor: Redactor::new(secret),
            budget: Arc::clone(&ctx.budget),
            permit,
            driver: conn.driver,
            deadline,
            start,
        };
        tokio::spawn(pump.run(rec.clone()));
        Ok(out)
    }
}

/// Per-sandbox state shared by its connections.
struct SandboxCtx {
    label: String,
    budget: Arc<Budget>,
    events: EventLimiter,
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
    tx: mpsc::Sender<Bytes>,
    /// Set only when the whole body was delivered; otherwise the sandbox
    /// sees an error instead of a clean end of the chunked body.
    complete: Arc<AtomicBool>,
    /// Closes the sandbox connection when the sandbox stopped reading.
    kill: Arc<Notify>,
    redactor: Redactor,
    budget: Arc<Budget>,
    permit: OwnedSemaphorePermit,
    driver: AbortOnDrop,
    deadline: tokio::time::Instant,
    start: Instant,
}

impl Pump {
    /// Every exit path is bounded by the idle timeout and the exchange's
    /// `max_duration` deadline, on both the upstream read and the sandbox
    /// send (review 2026-11-26, F-3); the permit, the upstream connection
    /// and the completion record are released/written on every path.
    async fn run(self, mut rec: AuditRecord) {
        let Pump {
            proxy,
            mut body,
            tx,
            complete,
            kill,
            mut redactor,
            budget,
            permit,
            driver,
            deadline,
            start,
        } = self;
        let max_response = proxy.inner.limits.max_response_body;
        let idle = proxy.inner.upstream.idle_timeout;
        let expired = |reason: &'static str| {
            if tokio::time::Instant::now() >= deadline {
                "aborted:max_duration"
            } else {
                reason
            }
        };
        let mut hasher = Sha256::new();
        let mut sent: u64 = 0;
        let outcome: Option<&'static str> = loop {
            let wait = deadline.min(tokio::time::Instant::now() + idle);
            let frame = tokio::select! {
                biased;
                () = tx.closed() => break Some("aborted:client_gone"),
                r = tokio::time::timeout_at(wait, body.frame()) => r,
            };
            let (chunk, last) = match frame {
                Err(_) => break Some(expired("aborted:upstream_timeout")),
                Ok(None) => (redactor.finish(), true),
                Ok(Some(Err(_))) => break Some("aborted:upstream_error"),
                Ok(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => (redactor.feed(&data), false),
                    Err(_) => continue, // trailers are dropped
                },
            };
            if !chunk.is_empty() {
                let n = chunk.len() as u64;
                if sent.saturating_add(n) > max_response {
                    break Some("aborted:response_too_large");
                }
                if !budget.charge_response(n) {
                    break Some("aborted:budget_exhausted:response_bytes");
                }
                hasher.update(&chunk);
                sent += n;
                let wait = deadline.min(tokio::time::Instant::now() + idle);
                match tokio::time::timeout_at(wait, tx.send(chunk)).await {
                    Err(_) => break Some(expired("aborted:client_stalled")),
                    Ok(Err(_)) => break Some("aborted:client_gone"),
                    Ok(Ok(())) => {}
                }
            }
            if last {
                break None;
            }
        };
        if outcome.is_none() {
            complete.store(true, Ordering::Release);
        }
        drop(tx);
        drop(driver);
        drop(permit);
        if matches!(
            outcome,
            Some("aborted:client_stalled" | "aborted:max_duration")
        ) {
            kill.notify_one();
        }
        rec.response_bytes = sent;
        rec.response_sha256 = hex(&hasher.finalize());
        rec.redactions = redactor.hits;
        rec.outcome = outcome.unwrap_or("ok").into();
        rec.duration_ms = start.elapsed().as_millis() as u64;
        (proxy.inner.audit)(&rec);
    }
}

/// Response body returned to the sandbox.
pub struct ProxyBody(Inner_);

enum Inner_ {
    /// A complete local body.
    Full(Option<Bytes>),
    /// Streamed from the upstream by a pump task.
    Stream {
        rx: mpsc::Receiver<Bytes>,
        complete: Arc<AtomicBool>,
    },
}

impl ProxyBody {
    fn full(b: Bytes) -> Self {
        Self(Inner_::Full(Some(b)))
    }
}

impl Body for ProxyBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        match &mut self.get_mut().0 {
            Inner_::Full(b) => Poll::Ready(b.take().map(|b| Ok(Frame::data(b)))),
            Inner_::Stream { rx, complete } => match rx.poll_recv(cx) {
                Poll::Ready(Some(b)) => Poll::Ready(Some(Ok(Frame::data(b)))),
                // A pump that stopped early ends the body with an error so
                // the chunked response is not terminated cleanly.
                Poll::Ready(None) if complete.load(Ordering::Acquire) => Poll::Ready(None),
                Poll::Ready(None) => {
                    Poll::Ready(Some(Err(io::Error::other("upstream stream aborted"))))
                }
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        matches!(self.0, Inner_::Full(None))
    }

    fn size_hint(&self) -> SizeHint {
        match &self.0 {
            Inner_::Full(Some(b)) => SizeHint::with_exact(b.len() as u64),
            Inner_::Full(None) => SizeHint::with_exact(0),
            Inner_::Stream { .. } => SizeHint::default(),
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
