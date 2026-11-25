//! The broker client.

use std::collections::VecDeque;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use tessera_protocol::bounded::{BoundedBytes, BoundedString, BoundedVec};
use tessera_protocol::frame::HARD_MAX_FRAME;
use tessera_protocol::{
    CapId, ClientMessage, CorrelationId, FrameLimits, LaunchProfileId, Request, RequestId,
    Response, ServerMessage, WireHeader, WireHttpsRequest, WireOperation, WireOperationResult,
    decode_server, encode_client,
};

use crate::error::{BrokerError, Error, Result};
use crate::transport::{Transport, TransportKind};
use crate::types::{
    AgentId, CapabilityView, Consumed, FileSnapshot, HttpsRequest, HttpsResponse, Terms,
};

/// Environment variable naming the inherited broker channel descriptor.
pub const BROKER_FD_ENV: &str = "TESSERA_BROKER_FD";

/// Environment variable carrying the launcher's *informational* agent label.
/// The SDK never sends it anywhere: identity comes from the channel.
pub const AGENT_LABEL_ENV: &str = "TESSERA_AGENT_ID";

/// How many abandoned (timed-out) requests we remember, so that their late
/// responses can be recognised and discarded.
const MAX_ABANDONED: usize = 1024;

/// Client configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientConfig {
    /// Deadline for ordinary calls.
    pub call_timeout: Duration,
    /// Deadline for [`Client::request_grant`]. The broker answers only after a
    /// human approves or denies on the trusted approval UI, so this is long.
    pub approval_timeout: Duration,
    /// Largest message the client will send. Larger messages are refused
    /// locally and nothing is sent.
    pub max_send_frame: usize,
    /// Largest message the client will accept. A larger datagram is
    /// discarded and reported as [`Error::FrameTooLarge`].
    pub max_recv_frame: usize,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            call_timeout: Duration::from_secs(30),
            approval_timeout: Duration::from_secs(15 * 60),
            max_send_frame: HARD_MAX_FRAME,
            max_recv_frame: HARD_MAX_FRAME,
        }
    }
}

struct Conn {
    transport: Transport,
    next_correlation: CorrelationId,
    /// Correlation ids of requests that timed out after being sent.
    abandoned: VecDeque<CorrelationId>,
}

/// A connection to the broker over the sandbox's dedicated channel.
///
/// All methods take `&self`. Calls are serialized: one request is in flight
/// at a time, so a call that waits for operator approval blocks other calls
/// on the same client.
///
/// # Idempotency
///
/// Every mutating call carries a *request id*. The plain methods generate a
/// random one. The `*_with_id` methods take one from you. **If a call times
/// out or the outcome is otherwise uncertain ([`Error::outcome_uncertain`]),
/// retry with the same request id** (from [`Error::request_id`]). For a
/// consume, the broker then answers with the status of the earlier
/// reservation ([`Consumed::Prior`]) and **never dispatches a second
/// effect**. Retrying with a *new* id is a new request and may spend budget,
/// and perform the effect, a second time.
pub struct Client {
    conn: Mutex<Conn>,
    config: ClientConfig,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Generate a fresh random request id (128 bits from the kernel CSPRNG).
pub fn new_request_id() -> Result<RequestId> {
    let mut buf = [0u8; 16];
    let mut filled = 0;
    while filled < buf.len() {
        match rustix::rand::getrandom(&mut buf[filled..], rustix::rand::GetRandomFlags::empty()) {
            Ok(n) => filled += n,
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(Error::Io(e.into())),
        }
    }
    Ok(u128::from_le_bytes(buf))
}

fn bounded_str<const N: usize>(what: &str, s: &str) -> Result<BoundedString<N>> {
    BoundedString::new(s).map_err(|e| Error::InvalidArgument(format!("{what}: {e}")))
}

fn bounded_bytes<const N: usize>(what: &str, b: Vec<u8>) -> Result<BoundedBytes<N>> {
    BoundedBytes::new(b).map_err(|e| Error::InvalidArgument(format!("{what}: {e}")))
}

/// Convert a non-success response into an error.
fn unexpected(resp: Response, wanted: &str) -> Error {
    match resp {
        Response::Error {
            request_id,
            code,
            detail,
        } => Error::Broker(BrokerError {
            code,
            detail: detail.into_inner(),
            request_id,
        }),
        other => Error::Protocol(format!("expected {wanted}, got {}", response_kind(&other))),
    }
}

/// An interim response: a final one follows on the same correlation id.
fn is_interim(r: &Response) -> bool {
    matches!(r, Response::GrantPending { .. })
}

fn response_kind(r: &Response) -> &'static str {
    match r {
        Response::GrantIssued { .. } => "GrantIssued",
        Response::Consumed { .. } => "Consumed",
        Response::PriorReservation { .. } => "PriorReservation",
        Response::Delegated { .. } => "Delegated",
        Response::Attenuated { .. } => "Attenuated",
        Response::Transferred { .. } => "Transferred",
        Response::Dropped { .. } => "Dropped",
        Response::Inspected(_) => "Inspected",
        Response::Spawned { .. } => "Spawned",
        Response::Revoked { .. } => "Revoked",
        Response::Error { .. } => "Error",
        Response::GrantPending { .. } => "GrantPending",
        Response::Capabilities { .. } => "Capabilities",
    }
}

fn response_request_id(r: &Response) -> Option<RequestId> {
    match r {
        Response::GrantIssued { request_id, .. }
        | Response::Consumed { request_id, .. }
        | Response::PriorReservation { request_id, .. }
        | Response::Delegated { request_id, .. }
        | Response::Attenuated { request_id, .. }
        | Response::Transferred { request_id, .. }
        | Response::Dropped { request_id }
        | Response::Spawned { request_id, .. }
        | Response::GrantPending { request_id, .. }
        | Response::Revoked { request_id } => Some(*request_id),
        Response::Error { request_id, .. } => *request_id,
        Response::Inspected(_) | Response::Capabilities { .. } => None,
    }
}

fn with_request_id(e: Error, rid: Option<RequestId>) -> Error {
    match e {
        Error::Timeout { request_id: None } => Error::Timeout { request_id: rid },
        other => other,
    }
}

impl Client {
    /// Connect using the descriptor named by `TESSERA_BROKER_FD`, as set up
    /// by the Tessera launcher (fd 3, `SOCK_SEQPACKET`).
    ///
    /// Call this at most once per process: it takes ownership of the
    /// descriptor. A second call fails rather than creating a second owner.
    pub fn from_env() -> Result<Self> {
        Self::from_env_with(ClientConfig::default())
    }

    /// [`Client::from_env`] with an explicit configuration.
    pub fn from_env_with(config: ClientConfig) -> Result<Self> {
        let v = std::env::var(BROKER_FD_ENV).map_err(|_| {
            Error::Config(format!(
                "{BROKER_FD_ENV} is not set: not running inside a Tessera sandbox?"
            ))
        })?;
        let fd = crate::env_fd::parse_fd(&v)?;
        let owned = crate::env_fd::claim(fd)?;
        Self::from_fd_with(owned, config)
    }

    /// Use an already-owned connected socket. `SOCK_SEQPACKET` (one message
    /// per datagram) and `SOCK_STREAM` (length-prefixed frames) are both
    /// supported, and the type is detected.
    pub fn from_fd(fd: OwnedFd) -> Result<Self> {
        Self::from_fd_with(fd, ClientConfig::default())
    }

    /// [`Client::from_fd`] with an explicit configuration.
    pub fn from_fd_with(fd: OwnedFd, config: ClientConfig) -> Result<Self> {
        let transport = Transport::new(fd)?;
        transport.try_size_send_buffer(config.max_send_frame);
        Ok(Self {
            conn: Mutex::new(Conn {
                transport,
                next_correlation: 1,
                abandoned: VecDeque::new(),
            }),
            config,
        })
    }

    /// Use a connected stream socket (length-prefixed framing).
    pub fn from_stream(stream: UnixStream) -> Result<Self> {
        Self::from_fd(OwnedFd::from(stream))
    }

    /// The configuration in use.
    pub fn config(&self) -> ClientConfig {
        self.config
    }

    /// The transport framing in use.
    pub fn transport_kind(&self) -> TransportKind {
        self.lock().transport.kind()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Conn> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Send one raw request and wait for its response.
    ///
    /// This is the low-level entry point under every typed method. It checks
    /// the correlation id and, where present, the echoed request id. It does
    /// *not* turn `Response::Error` into `Err`. An interim
    /// `Response::GrantPending` is returned as the response; the final answer
    /// that follows it on the same correlation id is then discarded when it
    /// arrives (repeat the `RequestGrant` with the same request id to wait
    /// for it).
    pub fn call_raw(&self, request: Request, timeout: Duration) -> Result<Response> {
        self.exchange(request, Instant::now() + timeout, &mut |_| None)
    }

    /// Send `request`, then receive until a response for it arrives or
    /// `deadline` passes. For an interim response, `on_interim` may return a
    /// new deadline to keep waiting for the final one; `None` returns the
    /// interim response (and abandons the correlation id).
    fn exchange(
        &self,
        request: Request,
        mut deadline: Instant,
        on_interim: &mut dyn FnMut(&Response) -> Option<Instant>,
    ) -> Result<Response> {
        let rid = request.request_id();
        let send_limits = FrameLimits::new(self.config.max_send_frame);
        let recv_limits = FrameLimits::new(self.config.max_recv_frame);
        let mut conn = self.lock();

        let correlation_id = conn.next_correlation;
        conn.next_correlation = conn.next_correlation.wrapping_add(1).max(1);
        let payload = encode_client(&ClientMessage {
            correlation_id,
            request,
        })
        .map_err(|e| Error::InvalidArgument(e.to_string()))?;
        if payload.len() > send_limits.max_frame() {
            return Err(Error::FrameTooLarge {
                outbound: true,
                len: payload.len(),
                max: send_limits.max_frame(),
            });
        }
        conn.transport
            .send(&payload, send_limits, deadline)
            .map_err(|e| with_request_id(e, rid))?;

        let abandon = |conn: &mut Conn| {
            if conn.abandoned.len() == MAX_ABANDONED {
                conn.abandoned.pop_front();
            }
            conn.abandoned.push_back(correlation_id);
        };
        loop {
            let p = match conn.transport.recv(recv_limits, deadline) {
                Ok(p) => p,
                Err(e) => {
                    if matches!(e, Error::Timeout { .. }) {
                        abandon(&mut conn);
                    }
                    return Err(with_request_id(e, rid));
                }
            };
            let msg: ServerMessage = decode_server(&p, recv_limits.max_frame())
                .map_err(|e| Error::Protocol(format!("undecodable broker message: {e}")))?;
            if msg.correlation_id != correlation_id {
                if let Some(pos) = conn.abandoned.iter().position(|c| *c == msg.correlation_id) {
                    // Late answer to a request that timed out earlier. An
                    // interim answer may be followed by a final one, so the
                    // id stays remembered for that.
                    if !is_interim(&msg.response) {
                        conn.abandoned.remove(pos);
                    }
                    continue;
                }
                return Err(Error::Protocol(format!(
                    "response for unknown correlation id {} (expected {correlation_id})",
                    msg.correlation_id
                )));
            }
            if let (Some(sent), Some(got)) = (rid, response_request_id(&msg.response)) {
                if sent != got {
                    return Err(Error::Protocol(format!(
                        "response echoes request id {} but {} was sent",
                        crate::format_id(got),
                        crate::format_id(sent)
                    )));
                }
            }
            if is_interim(&msg.response) {
                if let Some(d) = on_interim(&msg.response) {
                    deadline = d;
                    continue;
                }
                abandon(&mut conn);
            }
            return Ok(msg.response);
        }
    }

    fn call(&self, request: Request) -> Result<Response> {
        self.call_raw(request, self.config.call_timeout)
    }

    // ---- RequestGrant -------------------------------------------------

    /// Ask for a new root capability. The broker shows its own normalized
    /// rendering of `terms` to the human operator, who approves, narrows or
    /// denies it on the trusted approval UI (with a security-key touch).
    ///
    /// The broker first answers `GrantPending` (queued for the operator);
    /// that must arrive within [`ClientConfig::call_timeout`], otherwise
    /// this returns [`Error::Timeout`] (the broker is not answering). After
    /// it, this call waits for the decision until
    /// [`ClientConfig::approval_timeout`] (counted from the start), then
    /// returns [`Error::ApprovalPending`]: the request is still queued and a
    /// repeat with the same request id resumes waiting for it.
    ///
    /// `untrusted_description` (at most [`tessera_protocol::MAX_DESCRIPTION`]
    /// bytes) is free text for the operator. It is **untrusted** by
    /// definition (§8.1): the approval UI shows it escaped, in a separate
    /// block labelled UNTRUSTED; it is not part of what the operator signs,
    /// and the audit log records only its length and digest.
    ///
    /// Granted terms may be narrower than requested; call
    /// [`Client::inspect`] to see what was issued.
    pub fn request_grant(
        &self,
        terms: Terms,
        untrusted_description: Option<&str>,
    ) -> Result<CapId> {
        self.request_grant_with_id(new_request_id()?, terms, untrusted_description)
    }

    /// [`Client::request_grant`] with an explicit request id. Repeating it
    /// with the same id and arguments while the grant is pending is a status
    /// query: it attaches to the same approval (one prompt, one mint) and
    /// returns its outcome; after the decision it returns the same
    /// capability id, or the same denial.
    pub fn request_grant_with_id(
        &self,
        request_id: RequestId,
        terms: Terms,
        untrusted_description: Option<&str>,
    ) -> Result<CapId> {
        self.request_grant_with_progress(request_id, terms, untrusted_description, &mut |_| {})
    }

    /// [`Client::request_grant_with_id`], calling `on_pending` with the time
    /// left until the broker's approval request expires each time the
    /// broker reports the request as queued for the operator.
    pub fn request_grant_with_progress(
        &self,
        request_id: RequestId,
        terms: Terms,
        untrusted_description: Option<&str>,
        on_pending: &mut dyn FnMut(Duration),
    ) -> Result<CapId> {
        let untrusted_description = untrusted_description
            .map(|d| bounded_str("untrusted_description", d))
            .transpose()?;
        let req = Request::RequestGrant {
            request_id,
            requested_scope: terms.scope,
            budget: terms.budget,
            depth: terms.depth,
            expiry: terms.expiry,
            untrusted_description,
        };
        let start = Instant::now();
        let mut pending = false;
        let r = self.exchange(
            req,
            start + self.config.call_timeout.min(self.config.approval_timeout),
            &mut |resp| {
                if let Response::GrantPending {
                    expires_in_millis, ..
                } = resp
                {
                    pending = true;
                    on_pending(Duration::from_millis(*expires_in_millis));
                }
                Some(start + self.config.approval_timeout)
            },
        );
        match r {
            Ok(Response::GrantIssued { cap_id, .. }) => Ok(cap_id),
            Ok(other) => Err(unexpected(other, "GrantIssued")),
            Err(Error::Timeout { .. }) if pending => Err(Error::ApprovalPending { request_id }),
            Err(e) => Err(e),
        }
    }

    // ---- Consume ------------------------------------------------------

    /// Spend one unit of `cap` on `operation` (fresh request id).
    pub fn consume(&self, cap: CapId, operation: WireOperation) -> Result<Consumed> {
        self.consume_with_id(new_request_id()?, cap, operation)
    }

    /// Spend one unit of `cap` on `operation` under `request_id`.
    ///
    /// **Retrying with the same `request_id` never causes a second effect.**
    /// If the broker has already seen the id, it returns
    /// [`Consumed::Prior`] with the earlier reservation's status. If the
    /// operation content differs from the original, it returns
    /// `RequestIdConflict`.
    pub fn consume_with_id(
        &self,
        request_id: RequestId,
        cap: CapId,
        operation: WireOperation,
    ) -> Result<Consumed> {
        let req = Request::Consume {
            request_id,
            cap_id: cap,
            operation,
        };
        match self.call(req)? {
            Response::Consumed {
                reservation_id,
                result,
                ..
            } => Ok(Consumed::Executed {
                reservation_id,
                result,
            }),
            Response::PriorReservation {
                reservation_id,
                status,
                ..
            } => Ok(Consumed::Prior {
                reservation_id,
                status,
            }),
            other => Err(unexpected(other, "Consumed")),
        }
    }

    fn consume_expect(
        &self,
        request_id: RequestId,
        cap: CapId,
        op: WireOperation,
    ) -> Result<(u128, WireOperationResult)> {
        match self.consume_with_id(request_id, cap, op)? {
            Consumed::Executed {
                reservation_id,
                result,
            } => Ok((reservation_id, result)),
            Consumed::Prior {
                reservation_id,
                status,
            } => Err(Error::PriorReservation {
                request_id,
                reservation_id,
                status,
            }),
        }
    }

    /// Take one bounded snapshot of a registered file (spends one unit).
    pub fn read_file(&self, cap: CapId, max_bytes: u64) -> Result<FileSnapshot> {
        self.read_file_with_id(new_request_id()?, cap, max_bytes)
    }

    /// [`Client::read_file`] with an explicit request id.
    pub fn read_file_with_id(
        &self,
        request_id: RequestId,
        cap: CapId,
        max_bytes: u64,
    ) -> Result<FileSnapshot> {
        let (reservation_id, result) = self.consume_expect(
            request_id,
            cap,
            WireOperation::FileReadSnapshot { max_bytes },
        )?;
        match result {
            WireOperationResult::FileSnapshot { bytes, truncated } => Ok(FileSnapshot {
                reservation_id,
                bytes: bytes.into_inner(),
                truncated,
            }),
            _ => Err(Error::Protocol("expected a file snapshot result".into())),
        }
    }

    /// Atomically replace a registered file's content (spends one unit).
    /// Returns the number of bytes written.
    pub fn replace_file(&self, cap: CapId, bytes: Vec<u8>) -> Result<u64> {
        self.replace_file_with_id(new_request_id()?, cap, bytes)
    }

    /// [`Client::replace_file`] with an explicit request id.
    pub fn replace_file_with_id(
        &self,
        request_id: RequestId,
        cap: CapId,
        bytes: Vec<u8>,
    ) -> Result<u64> {
        let bytes = bounded_bytes("file content", bytes)?;
        let (_, result) =
            self.consume_expect(request_id, cap, WireOperation::FileReplaceContent { bytes })?;
        match result {
            WireOperationResult::FileReplaced { bytes_written } => Ok(bytes_written),
            _ => Err(Error::Protocol("expected a file replacement result".into())),
        }
    }

    /// Build the wire form of an HTTPS request, checking the bounds.
    pub fn https_operation(req: HttpsRequest) -> Result<WireOperation> {
        let headers = req
            .headers
            .into_iter()
            .map(|(name, value)| {
                Ok(WireHeader {
                    name: bounded_str("header name", &name)?,
                    value: bounded_bytes("header value", value)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(WireOperation::Https(WireHttpsRequest {
            method: req.method,
            path: bounded_str("path", &req.path)?,
            headers: BoundedVec::new(headers)
                .map_err(|e| Error::InvalidArgument(format!("headers: {e}")))?,
            body: bounded_bytes("body", req.body)?,
        }))
    }

    /// Issue one HTTPS request to the capability's registered endpoint
    /// (spends one unit). The broker attaches any credentials; it disables
    /// redirects and retries.
    pub fn https_request(&self, cap: CapId, req: HttpsRequest) -> Result<HttpsResponse> {
        self.https_request_with_id(new_request_id()?, cap, req)
    }

    /// [`Client::https_request`] with an explicit request id.
    pub fn https_request_with_id(
        &self,
        request_id: RequestId,
        cap: CapId,
        req: HttpsRequest,
    ) -> Result<HttpsResponse> {
        let op = Self::https_operation(req)?;
        let (reservation_id, result) = self.consume_expect(request_id, cap, op)?;
        match result {
            WireOperationResult::Https {
                status,
                headers,
                body,
                truncated,
            } => Ok(HttpsResponse {
                reservation_id,
                status,
                headers: headers
                    .into_inner()
                    .into_iter()
                    .map(|h| (h.name.into_inner(), h.value.into_inner()))
                    .collect(),
                body: body.into_inner(),
                truncated,
            }),
            _ => Err(Error::Protocol("expected an HTTPS result".into())),
        }
    }

    // ---- Delegation and lifecycle -------------------------------------

    /// Atomically split a child off `cap` and give it to `recipient`
    /// (§5.1). One delegation generation is used. Returns the child's id.
    /// The recipient must learn the id from you; capability ids are
    /// references, not secrets, so passing them over an ordinary channel is
    /// fine.
    pub fn delegate(&self, cap: CapId, recipient: AgentId, child: Terms) -> Result<CapId> {
        self.delegate_with_id(new_request_id()?, cap, recipient, child)
    }

    /// [`Client::delegate`] with an explicit request id.
    pub fn delegate_with_id(
        &self,
        request_id: RequestId,
        cap: CapId,
        recipient: AgentId,
        child: Terms,
    ) -> Result<CapId> {
        let req = Request::Delegate {
            request_id,
            cap_id: cap,
            recipient: recipient.0,
            child_scope: child.scope,
            child_budget: child.budget,
            child_depth: child.depth,
            child_expiry: child.expiry,
        };
        match self.call(req)? {
            Response::Delegated { child_cap_id, .. } => Ok(child_cap_id),
            other => Err(unexpected(other, "Delegated")),
        }
    }

    /// Reduce `cap` in place. Scope, budget, depth and expiry may only shrink.
    pub fn attenuate(&self, cap: CapId, reduced: Terms) -> Result<()> {
        self.attenuate_with_id(new_request_id()?, cap, reduced)
    }

    /// [`Client::attenuate`] with an explicit request id.
    pub fn attenuate_with_id(
        &self,
        request_id: RequestId,
        cap: CapId,
        reduced: Terms,
    ) -> Result<()> {
        let req = Request::Attenuate {
            request_id,
            cap_id: cap,
            reduced_scope: reduced.scope,
            budget: reduced.budget,
            depth: reduced.depth,
            expiry: reduced.expiry,
        };
        match self.call(req)? {
            Response::Attenuated { cap_id, .. } if cap_id == cap => Ok(()),
            Response::Attenuated { .. } => Err(Error::Protocol(
                "Attenuated response names a different capability".into(),
            )),
            other => Err(unexpected(other, "Attenuated")),
        }
    }

    /// Move ownership of `cap` to `recipient` (uses one delegation
    /// generation).
    pub fn transfer(&self, cap: CapId, recipient: AgentId) -> Result<()> {
        self.transfer_with_id(new_request_id()?, cap, recipient)
    }

    /// [`Client::transfer`] with an explicit request id.
    pub fn transfer_with_id(
        &self,
        request_id: RequestId,
        cap: CapId,
        recipient: AgentId,
    ) -> Result<()> {
        let req = Request::Transfer {
            request_id,
            cap_id: cap,
            recipient: recipient.0,
        };
        match self.call(req)? {
            Response::Transferred { cap_id, .. } if cap_id == cap => Ok(()),
            Response::Transferred { .. } => Err(Error::Protocol(
                "Transferred response names a different capability".into(),
            )),
            other => Err(unexpected(other, "Transferred")),
        }
    }

    /// Discard the remaining balance of `cap`. Children already delegated
    /// from it are not affected.
    pub fn drop(&self, cap: CapId) -> Result<()> {
        self.drop_with_id(new_request_id()?, cap)
    }

    /// [`Client::drop`] with an explicit request id.
    pub fn drop_with_id(&self, request_id: RequestId, cap: CapId) -> Result<()> {
        match self.call(Request::Drop {
            request_id,
            cap_id: cap,
        })? {
            Response::Dropped { .. } => Ok(()),
            other => Err(unexpected(other, "Dropped")),
        }
    }

    /// Read the metadata of a capability you own. Inspect takes no request
    /// id and has no effect.
    pub fn inspect(&self, cap: CapId) -> Result<CapabilityView> {
        match self.call(Request::Inspect { cap_id: cap })? {
            Response::Inspected(view) if view.cap_id == cap => Ok(view),
            Response::Inspected(_) => Err(Error::Protocol(
                "Inspected response names a different capability".into(),
            )),
            other => Err(unexpected(other, "Inspected")),
        }
    }

    /// List metadata of every capability this principal currently owns
    /// (all statuses), in ascending id order. This is how a recipient finds
    /// capabilities delegated or transferred to it; ids need not be passed
    /// out of band. Pages through the broker's `ListCapabilities` (at most
    /// 4096 entries).
    pub fn list_capabilities(&self) -> Result<Vec<CapabilityView>> {
        const MAX_PAGES: usize = 64;
        let mut out: Vec<CapabilityView> = Vec::new();
        let mut after: Option<CapId> = None;
        for _ in 0..MAX_PAGES {
            match self.call(Request::ListCapabilities { after })? {
                Response::Capabilities { caps, more } => {
                    for v in caps.into_inner() {
                        // Ids must strictly increase (also across pages):
                        // a broken broker cannot make this loop forever.
                        if out.last().is_some_and(|l| v.cap_id <= l.cap_id)
                            || after.is_some_and(|a| v.cap_id <= a)
                        {
                            return Err(Error::Protocol(
                                "capability list is not in ascending id order".into(),
                            ));
                        }
                        out.push(v);
                    }
                    match (more, out.last()) {
                        (true, Some(l)) => after = Some(l.cap_id),
                        (true, None) => {
                            return Err(Error::Protocol("empty page claims more".into()));
                        }
                        (false, _) => return Ok(out),
                    }
                }
                other => return Err(unexpected(other, "Capabilities")),
            }
        }
        Err(Error::Protocol("capability list exceeds 64 pages".into()))
    }

    /// Launch a child sandbox from an operator-configured agent launch
    /// profile. The child is a separate principal in this principal's
    /// orchestration domain, subject to the broker's quotas (children per
    /// principal, spawn depth, domain size: `RateLimited` /
    /// `PermissionDenied`), with only the profile's baseline authority,
    /// nothing from the parent. Returns its id, to use as a delegation
    /// recipient. Terminating this principal also terminates its children.
    pub fn spawn(&self, profile: LaunchProfileId) -> Result<AgentId> {
        self.spawn_with_id(new_request_id()?, profile)
    }

    /// [`Client::spawn`] with an explicit request id. A retry with the same
    /// id never launches a second sandbox: it returns the same child (or the
    /// same failure), waiting for the launch if it is still in progress.
    pub fn spawn_with_id(
        &self,
        request_id: RequestId,
        profile: LaunchProfileId,
    ) -> Result<AgentId> {
        match self.call(Request::Spawn {
            request_id,
            launch_profile: profile,
        })? {
            Response::Spawned { agent, .. } => Ok(AgentId(agent)),
            other => Err(unexpected(other, "Spawned")),
        }
    }

    /// Revoke `cap` and its whole subtree. An agent may revoke a capability
    /// it owns or any descendant of one it owns (ADR-0014 as amended); the
    /// operator revokes anything on the admin endpoint. Authorizations
    /// committed before the revoke stand; none after it.
    pub fn revoke(&self, cap: CapId) -> Result<()> {
        self.revoke_with_id(new_request_id()?, cap)
    }

    /// [`Client::revoke`] with an explicit request id.
    pub fn revoke_with_id(&self, request_id: RequestId, cap: CapId) -> Result<()> {
        match self.call(Request::Revoke {
            request_id,
            cap_id: cap,
        })? {
            Response::Revoked { .. } => Ok(()),
            other => Err(unexpected(other, "Revoked")),
        }
    }
}
