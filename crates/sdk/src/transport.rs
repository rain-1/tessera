//! Broker channel transports.
//!
//! * [`Transport::Seqpacket`] (primary): `AF_UNIX`/`SOCK_SEQPACKET`. Each
//!   datagram holds one versioned payload. This is what the launcher installs
//!   at `TESSERA_BROKER_FD`. A timeout can never leave half a message behind,
//!   so the channel stays usable after one.
//! * [`Transport::Stream`] (secondary): `AF_UNIX`/`SOCK_STREAM` with `u32`
//!   big-endian length-prefixed frames ([`tessera_protocol::frame`]). Partly
//!   received frames are kept across timeouts. A partial *write* or an
//!   invalid frame header makes the channel unusable ([`Error::Poisoned`]).
//!
//! Both transports reject any ancillary data (for example passed file
//! descriptors) from the peer, and close any descriptors they receive.

use std::io;
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

use rustix::net::sockopt::Timeout;
use rustix::net::{RecvFlags, SendFlags, SocketType};
use tessera_protocol::frame::{FRAME_HEADER_LEN, check_header};
use tessera_protocol::unix::{recv_no_ancillary, recv_packet, send_packet};
use tessera_protocol::{FrameError, FrameLimits};

use crate::error::Error;

/// Which framing the channel uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// One payload per `SOCK_SEQPACKET` datagram.
    Seqpacket,
    /// Length-prefixed frames on a `SOCK_STREAM` socket.
    Stream,
}

pub(crate) struct Transport {
    fd: OwnedFd,
    kind: TransportKind,
    /// Stream only: bytes received but not yet consumed as a frame.
    rx: Vec<u8>,
    poisoned: bool,
}

/// Smallest timeout ever passed to `SO_*TIMEO` (zero means "block forever").
const MIN_TIMEO: Duration = Duration::from_millis(1);
const STREAM_CHUNK: usize = 64 * 1024;

enum Wait {
    Deadline,
    Fail(Error),
}

fn remaining(deadline: Instant) -> Option<Duration> {
    let now = Instant::now();
    if now >= deadline {
        None
    } else {
        Some((deadline - now).max(MIN_TIMEO))
    }
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

impl Transport {
    pub(crate) fn new(fd: OwnedFd) -> Result<Self, Error> {
        let kind = match rustix::net::sockopt::socket_type(&fd).map_err(io::Error::from)? {
            SocketType::SEQPACKET => TransportKind::Seqpacket,
            SocketType::STREAM => TransportKind::Stream,
            other => {
                return Err(Error::Config(format!(
                    "broker channel has unsupported socket type {other:?}"
                )));
            }
        };
        Ok(Self {
            fd,
            kind,
            rx: Vec::new(),
            poisoned: false,
        })
    }

    pub(crate) fn kind(&self) -> TransportKind {
        self.kind
    }

    /// Ask the kernel for a send buffer that fits `max` bytes, so that large
    /// datagrams are accepted. This is best effort: the kernel caps the size
    /// at `net.core.wmem_max`.
    pub(crate) fn try_size_send_buffer(&self, max: usize) {
        if self.kind == TransportKind::Seqpacket {
            let _ = rustix::net::sockopt::set_socket_send_buffer_size(&self.fd, max);
        }
    }

    fn set_timeout(&self, which: Timeout, deadline: Instant) -> Result<(), Wait> {
        let d = remaining(deadline).ok_or(Wait::Deadline)?;
        rustix::net::sockopt::set_socket_timeout(&self.fd, which, Some(d))
            .map_err(|e| Wait::Fail(Error::Io(e.into())))
    }

    /// Send one payload. On `Err(Error::Timeout)` nothing was sent.
    pub(crate) fn send(
        &mut self,
        payload: &[u8],
        limits: FrameLimits,
        deadline: Instant,
    ) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if payload.len() > limits.max_frame() {
            return Err(Error::FrameTooLarge {
                outbound: true,
                len: payload.len(),
                max: limits.max_frame(),
            });
        }
        match self.kind {
            TransportKind::Seqpacket => loop {
                match self.set_timeout(Timeout::Send, deadline) {
                    Ok(()) => {}
                    Err(Wait::Deadline) => return Err(Error::Timeout { request_id: None }),
                    Err(Wait::Fail(e)) => return Err(e),
                }
                match send_packet(&self.fd, payload, limits) {
                    Ok(()) => return Ok(()),
                    Err(FrameError::Io(e)) if is_timeout(&e) => continue,
                    Err(FrameError::Io(e)) if e.raw_os_error() == Some(libc_emsgsize()) => {
                        return Err(Error::InvalidArgument(format!(
                            "message of {} bytes exceeds the socket send buffer (EMSGSIZE); \
                             nothing was sent",
                            payload.len()
                        )));
                    }
                    Err(FrameError::Io(e)) if e.kind() == io::ErrorKind::BrokenPipe => {
                        return Err(Error::Closed);
                    }
                    Err(FrameError::Io(e)) => return Err(Error::Io(e)),
                    Err(other) => return Err(Error::Protocol(other.to_string())),
                }
            },
            TransportKind::Stream => {
                if payload.is_empty() {
                    return Err(Error::InvalidArgument("empty payload".into()));
                }
                let len = u32::try_from(payload.len()).map_err(|_| Error::FrameTooLarge {
                    outbound: true,
                    len: payload.len(),
                    max: limits.max_frame(),
                })?;
                let mut buf = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
                buf.extend_from_slice(&len.to_be_bytes());
                buf.extend_from_slice(payload);
                let mut off = 0;
                while off < buf.len() {
                    match self.set_timeout(Timeout::Send, deadline) {
                        Ok(()) => {}
                        Err(Wait::Deadline) => {
                            if off > 0 {
                                self.poisoned = true;
                            }
                            return Err(Error::Timeout { request_id: None });
                        }
                        Err(Wait::Fail(e)) => return Err(e),
                    }
                    match rustix::net::send(&self.fd, &buf[off..], SendFlags::NOSIGNAL) {
                        Ok(n) => off += n,
                        Err(e) => {
                            let e: io::Error = e.into();
                            if is_timeout(&e) {
                                continue;
                            }
                            if off > 0 {
                                self.poisoned = true;
                            }
                            if e.kind() == io::ErrorKind::BrokenPipe {
                                return Err(Error::Closed);
                            }
                            return Err(Error::Io(e));
                        }
                    }
                }
                Ok(())
            }
        }
    }

    /// Receive one payload, waiting until `deadline`.
    pub(crate) fn recv(
        &mut self,
        limits: FrameLimits,
        deadline: Instant,
    ) -> Result<Vec<u8>, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        match self.kind {
            TransportKind::Seqpacket => loop {
                match self.set_timeout(Timeout::Recv, deadline) {
                    Ok(()) => {}
                    Err(Wait::Deadline) => return Err(Error::Timeout { request_id: None }),
                    Err(Wait::Fail(e)) => return Err(e),
                }
                match recv_packet(&self.fd, limits) {
                    Ok(Some(p)) => return Ok(p),
                    Ok(None) => return Err(Error::Closed),
                    Err(FrameError::Io(e)) if is_timeout(&e) => continue,
                    Err(FrameError::Io(e)) => return Err(Error::Io(e)),
                    // The oversized datagram was consumed and discarded; the
                    // channel stays usable but the response is lost.
                    Err(FrameError::TooLarge { len, max }) => {
                        return Err(Error::FrameTooLarge {
                            outbound: false,
                            len,
                            max,
                        });
                    }
                    Err(FrameError::AncillaryRejected) => {
                        return Err(Error::Protocol(
                            "broker attached ancillary data (rejected and closed)".into(),
                        ));
                    }
                    Err(other) => return Err(Error::Protocol(other.to_string())),
                }
            },
            TransportKind::Stream => loop {
                if self.rx.len() >= FRAME_HEADER_LEN {
                    let mut hdr = [0u8; FRAME_HEADER_LEN];
                    hdr.copy_from_slice(&self.rx[..FRAME_HEADER_LEN]);
                    let len = match check_header(hdr, limits) {
                        Ok(len) => len,
                        Err(FrameError::TooLarge { len, max }) => {
                            self.poisoned = true;
                            return Err(Error::FrameTooLarge {
                                outbound: false,
                                len,
                                max,
                            });
                        }
                        Err(e) => {
                            self.poisoned = true;
                            return Err(Error::Protocol(e.to_string()));
                        }
                    };
                    if self.rx.len() >= FRAME_HEADER_LEN + len {
                        let payload = self.rx[FRAME_HEADER_LEN..FRAME_HEADER_LEN + len].to_vec();
                        self.rx.drain(..FRAME_HEADER_LEN + len);
                        return Ok(payload);
                    }
                }
                match self.set_timeout(Timeout::Recv, deadline) {
                    Ok(()) => {}
                    Err(Wait::Deadline) => return Err(Error::Timeout { request_id: None }),
                    Err(Wait::Fail(e)) => return Err(e),
                }
                let mut chunk = vec![0u8; STREAM_CHUNK];
                match recv_no_ancillary(&self.fd, &mut chunk, RecvFlags::empty()) {
                    Ok(r) if r.bytes == 0 => {
                        return Err(Error::Closed);
                    }
                    Ok(r) => self.rx.extend_from_slice(&chunk[..r.bytes]),
                    Err(FrameError::Io(e)) if is_timeout(&e) => continue,
                    Err(FrameError::Io(e)) => return Err(Error::Io(e)),
                    Err(FrameError::AncillaryRejected) => {
                        self.poisoned = true;
                        return Err(Error::Protocol(
                            "broker attached ancillary data (rejected and closed)".into(),
                        ));
                    }
                    Err(other) => {
                        self.poisoned = true;
                        return Err(Error::Protocol(other.to_string()));
                    }
                }
            },
        }
    }
}

/// `EMSGSIZE` on Linux.
const fn libc_emsgsize() -> i32 {
    rustix::io::Errno::MSGSIZE.raw_os_error()
}
