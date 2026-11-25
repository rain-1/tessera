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
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::thread;

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

/// The reactor's handle on one attached channel.
pub(crate) struct ChannelHandle {
    pub(crate) conn: u64,
    fd: Arc<OwnedFd>,
    out: SyncSender<ServerMessage>,
}

impl ChannelHandle {
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
    max_frame: usize,
) -> std::io::Result<ChannelHandle> {
    size_buffers(&fd);
    let fd = Arc::new(fd);
    let limits = FrameLimits::new(max_frame);
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
    thread::Builder::new()
        .name(format!("tessera-in-{}.{}", agent.epoch(), agent.serial()))
        .spawn(move || reader(agent, conn, rfd, inbox, rout, limits))?;

    Ok(ChannelHandle { conn, fd, out })
}

fn reader(
    agent: AgentId,
    conn: u64,
    fd: Arc<OwnedFd>,
    inbox: SyncSender<Inbox>,
    out: SyncSender<ServerMessage>,
    limits: FrameLimits,
) {
    let mut strikes = 0u32;
    let reject = |out: &SyncSender<ServerMessage>, corr: u64, code, detail: &str| {
        let _ = out.try_send(ServerMessage {
            correlation_id: corr,
            response: error(None, code, detail),
        });
    };
    let violation = loop {
        match recv_packet(fd.as_fd(), limits) {
            Ok(None) => break None,
            Ok(Some(p)) => match decode_client(&p, limits.max_frame()) {
                Ok(msg) => {
                    let digest: [u8; 32] = match canonical_request_bytes(&msg.request) {
                        Ok(b) => Sha256::digest(&b).into(),
                        Err(_) => {
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
