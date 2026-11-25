//! Per-principal agent channel threads.
//!
//! Each launcher-created channel (`AF_UNIX`/`SOCK_SEQPACKET`) gets a reader
//! and a writer thread. The reader is created *knowing* the AgentId the
//! channel was bound to at spawn; it stamps every decoded request with that
//! identity. Nothing in a payload can change it (ADR-0004). The reader
//! enforces the frame bound before allocation, rejects (and closes) any
//! ancillary data, decodes strictly, and never touches ledger state: it
//! only forwards `(agent, request, digest)` to the single writer.

use std::os::fd::{AsFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::thread;
use std::time::Instant;

use sha2::{Digest, Sha256};
use tessera_capability_core::AgentId;
use tessera_protocol::bounded::BoundedString;
use tessera_protocol::frame::{FrameError, FrameLimits};
use tessera_protocol::unix::{recv_packet, send_packet};
use tessera_protocol::{
    ErrorCode, Response, ServerMessage, canonical_request_bytes, decode_client, encode_server,
};

use crate::reactor::Inbox;

/// Outbound queue depth per channel; an agent that does not read its
/// responses is disconnected instead of blocking the single writer.
const OUT_QUEUE: usize = 1024;
/// Malformed / oversized frames tolerated before the channel is closed.
const MAX_STRIKES: u32 = 64;

/// Per-channel admission limits, enforced by the reader thread *before* a
/// request reaches the single writer (§9.2: rate limits before expensive
/// work). Both answer `RateLimited` under the request's correlation id; the
/// request is not forwarded, not bound to its id and has no effect, so the
/// client may retry it with the same id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChannelLimits {
    /// Frame bound (bytes).
    pub max_frame: usize,
    /// Requests forwarded to the writer and not yet finally answered. A
    /// pending grant request counts until the operator decides; a consume
    /// counts until its outcome is journaled.
    pub max_in_flight: usize,
    /// Sustained requests per second (token bucket refill rate).
    pub rate_per_sec: u32,
    /// Token bucket capacity (burst).
    pub burst: u32,
}

/// Token bucket.
struct Bucket {
    tokens: f64,
    last: Instant,
    rate: f64,
    cap: f64,
}

impl Bucket {
    fn new(rate: u32, burst: u32) -> Self {
        let cap = f64::from(burst.max(1));
        Bucket {
            tokens: cap,
            last: Instant::now(),
            rate: f64::from(rate),
            cap,
        }
    }

    fn take(&mut self) -> bool {
        let now = Instant::now();
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.cap);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// The reactor's handle on one attached channel.
pub(crate) struct ChannelHandle {
    pub(crate) conn: u64,
    fd: Arc<OwnedFd>,
    out: SyncSender<ServerMessage>,
    in_flight: Arc<AtomicUsize>,
}

impl ChannelHandle {
    /// A forwarded request got its final answer.
    pub(crate) fn finished_one(&self) {
        let mut cur = self.in_flight.load(Ordering::SeqCst);
        while cur > 0 {
            match self
                .in_flight
                .compare_exchange(cur, cur - 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return,
                Err(now) => cur = now,
            }
        }
    }

    /// Queue a response; disconnects a peer whose queue is full.
    pub(crate) fn send(&self, msg: ServerMessage) {
        match self.out.try_send(msg) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => self.close(),
        }
    }

    /// Shut the socket down; both threads exit.
    pub(crate) fn close(&self) {
        let _ = rustix::net::shutdown(self.fd.as_fd(), rustix::net::Shutdown::Both);
    }
}

impl Drop for ChannelHandle {
    fn drop(&mut self) {
        self.close();
    }
}

pub(crate) fn error(request_id: Option<u128>, code: ErrorCode, detail: &str) -> Response {
    let mut d = detail.to_owned();
    d.truncate(tessera_protocol::MAX_DETAIL);
    Response::Error {
        request_id,
        code,
        detail: BoundedString::new(d).unwrap_or_default(),
    }
}

/// Socket buffer size requested on both directions of every agent channel.
/// A `SOCK_SEQPACKET` datagram must fit the sender's `SO_SNDBUF`; the
/// broker's own bound ([`crate::executor::MAX_INLINE_CONTENT`] plus envelope,
/// within `agent_max_frame`) already fits the default `wmem_default`, and
/// this raises the buffers further where permitted (`SO_SNDBUFFORCE` needs
/// `CAP_NET_ADMIN`; otherwise the value is capped at `wmem_max`).
pub(crate) const CHANNEL_BUFFER: usize = 1024 * 1024;

/// Best-effort buffer sizing for one end of a channel.
pub(crate) fn size_buffers(fd: impl AsFd) {
    use rustix::net::sockopt as so;
    let fd = fd.as_fd();
    if so::set_socket_send_buffer_size_force(fd, CHANNEL_BUFFER).is_err() {
        let _ = so::set_socket_send_buffer_size(fd, CHANNEL_BUFFER);
    }
    if so::set_socket_recv_buffer_size_force(fd, CHANNEL_BUFFER).is_err() {
        let _ = so::set_socket_recv_buffer_size(fd, CHANNEL_BUFFER);
    }
}

/// The correlation id of an undecodable payload, if its envelope and first
/// field parse (so the client can match the error to its request).
fn correlation_of(p: &[u8]) -> Option<u64> {
    let body = p.get(tessera_protocol::codec::ENVELOPE_HEADER_LEN..)?;
    let (c, _) = postcard::take_from_bytes::<u64>(body).ok()?;
    Some(c)
}

/// Start the reader/writer threads for a channel bound to `agent`.
pub(crate) fn attach(
    agent: AgentId,
    conn: u64,
    fd: OwnedFd,
    inbox: SyncSender<Inbox>,
    cl: ChannelLimits,
) -> std::io::Result<ChannelHandle> {
    size_buffers(&fd);
    let max_frame = cl.max_frame;
    let fd = Arc::new(fd);
    let limits = FrameLimits::new(max_frame);
    let in_flight = Arc::new(AtomicUsize::new(0));
    let (out, out_rx) = mpsc::sync_channel::<ServerMessage>(OUT_QUEUE);

    let wfd = Arc::clone(&fd);
    // Responses may carry inline content up to the adapter limit; allow a
    // little more than the request bound for the envelope.
    let send_limits = FrameLimits::new(max_frame.saturating_add(4096));
    thread::Builder::new()
        .name(format!("tessera-out-{}.{}", agent.epoch(), agent.serial()))
        .spawn(move || {
            for msg in out_rx {
                let Ok(payload) = encode_server(&msg) else {
                    continue;
                };
                if send_packet(wfd.as_fd(), &payload, send_limits).is_err() {
                    let _ = rustix::net::shutdown(wfd.as_fd(), rustix::net::Shutdown::Both);
                    return;
                }
            }
        })?;

    let rfd = Arc::clone(&fd);
    let rout = out.clone();
    let rin = Arc::clone(&in_flight);
    thread::Builder::new()
        .name(format!("tessera-in-{}.{}", agent.epoch(), agent.serial()))
        .spawn(move || reader(agent, conn, rfd, inbox, rout, limits, cl, rin))?;

    Ok(ChannelHandle {
        conn,
        fd,
        out,
        in_flight,
    })
}

#[allow(clippy::too_many_arguments)]
fn reader(
    agent: AgentId,
    conn: u64,
    fd: Arc<OwnedFd>,
    inbox: SyncSender<Inbox>,
    out: SyncSender<ServerMessage>,
    limits: FrameLimits,
    cl: ChannelLimits,
    in_flight: Arc<AtomicUsize>,
) {
    let mut strikes = 0u32;
    let mut bucket = Bucket::new(cl.rate_per_sec, cl.burst);
    let reject_id =
        |out: &SyncSender<ServerMessage>, corr: u64, rid: Option<u128>, code, detail: &str| {
            let _ = out.try_send(ServerMessage {
                correlation_id: corr,
                response: error(rid, code, detail),
            });
        };
    let reject = |out: &SyncSender<ServerMessage>, corr: u64, code, detail: &str| {
        reject_id(out, corr, None, code, detail)
    };
    let violation = loop {
        match recv_packet(fd.as_fd(), limits) {
            Ok(None) => break None,
            Ok(Some(p)) => match decode_client(&p, limits.max_frame()) {
                Ok(msg) => {
                    let rid = msg.request.request_id();
                    if !bucket.take() {
                        reject_id(
                            &out,
                            msg.correlation_id,
                            rid,
                            ErrorCode::RateLimited,
                            "request rate limit; retry later (same request id is safe)",
                        );
                        continue;
                    }
                    if in_flight.fetch_add(1, Ordering::SeqCst) >= cl.max_in_flight {
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                        reject_id(
                            &out,
                            msg.correlation_id,
                            rid,
                            ErrorCode::RateLimited,
                            "too many requests in flight; retry later",
                        );
                        continue;
                    }
                    let digest: [u8; 32] = match canonical_request_bytes(&msg.request) {
                        Ok(b) => Sha256::digest(&b).into(),
                        Err(_) => {
                            in_flight.fetch_sub(1, Ordering::SeqCst);
                            reject(
                                &out,
                                msg.correlation_id,
                                ErrorCode::Malformed,
                                "unencodable request",
                            );
                            continue;
                        }
                    };
                    let m = Inbox::Agent {
                        agent,
                        conn,
                        correlation: msg.correlation_id,
                        request: msg.request,
                        digest,
                    };
                    if inbox.send(m).is_err() {
                        return;
                    }
                }
                Err(e) => {
                    strikes += 1;
                    // Answer under the received correlation id if it can be
                    // parsed; otherwise the client cannot match a reply and
                    // the channel is closed (docs/sdk.md §7.7).
                    let Some(corr) = correlation_of(&p) else {
                        break Some("undecodable frame without a correlation id");
                    };
                    let code = match e {
                        tessera_protocol::DecodeError::UnsupportedVersion(_) => {
                            ErrorCode::UnsupportedVersion
                        }
                        tessera_protocol::DecodeError::TooLarge { .. } => ErrorCode::LimitExceeded,
                        _ => ErrorCode::Malformed,
                    };
                    reject(&out, corr, code, "request rejected");
                }
            },
            Err(FrameError::TooLarge { .. }) => {
                // The datagram was discarded unread: no correlation id.
                break Some("oversized frame");
            }
            Err(FrameError::AncillaryRejected) => {
                break Some("ancillary data (file descriptors / credentials) on agent channel");
            }
            Err(FrameError::Truncated) => break Some("truncated frame"),
            Err(_) => break None,
        }
        if strikes >= MAX_STRIKES {
            break Some("too many malformed frames");
        }
    };
    let _ = inbox.send(Inbox::ChannelClosed {
        agent,
        conn,
        violation: violation.map(str::to_owned),
    });
}
