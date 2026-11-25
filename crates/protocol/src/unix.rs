//! Unix-socket helpers: peer credentials, ancillary-data rejection and
//! `SOCK_SEQPACKET` transport.
//!
//! All system calls go through `rustix`; this crate contains no `unsafe`.
//!
//! # Ancillary data policy
//!
//! The broker never accepts file descriptors or credentials messages from
//! agents (§9.1, §9.2). [`recv_no_ancillary`] receives with `recvmsg(2)`,
//! `MSG_CMSG_CLOEXEC`, and a control buffer large enough for the kernel's
//! per-message descriptor limit (`SCM_MAX_FD` = 253). If *any* control
//! message arrives, every received descriptor is closed immediately and the
//! call fails with [`FrameError::AncillaryRejected`]. A control-truncated
//! receive (`MSG_CTRUNC`) is also rejected; Linux closes descriptors that did
//! not fit. After a rejection the byte stream position is unreliable, so the
//! caller must drop the connection. Do not enable `SO_PASSCRED` on broker
//! sockets: it would cause every message to carry credentials and be
//! rejected.
//!
//! # Peer credentials
//!
//! [`peer_credentials`] returns `SO_PEERCRED`, i.e. the credentials of the
//! peer *at `connect(2)`/`socketpair(2)` time*. The pid is informational
//! only: pids are reused, and the connecting process may have exited or
//! passed the socket on. The broker must combine this with launcher-managed
//! channel membership (a dedicated socket per sandbox, cgroup/pidfd checks)
//! rather than treat a pid as an identity.

use std::io::{self, IoSliceMut, Read};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvFlags, ReturnFlags, SendFlags, SocketFlags, SocketType,
};

use crate::frame::{FrameError, FrameLimits};

/// Credentials of the peer of a connected Unix socket, captured by the kernel
/// at connection time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerCredentials {
    /// Peer pid at connect time (informational; pids are reused).
    pub pid: i32,
    /// Peer effective uid at connect time.
    pub uid: u32,
    /// Peer effective gid at connect time.
    pub gid: u32,
}

/// Read `SO_PEERCRED` from a connected Unix socket.
pub fn peer_credentials<Fd: AsFd>(fd: Fd) -> io::Result<PeerCredentials> {
    let c = rustix::net::sockopt::socket_peercred(fd)?;
    Ok(PeerCredentials {
        pid: c.pid.as_raw_nonzero().get(),
        uid: c.uid.as_raw(),
        gid: c.gid.as_raw(),
    })
}

/// Marker error carried inside `io::Error` when ancillary data was rejected.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("unsolicited ancillary data rejected")]
pub struct AncillaryRejected;

/// Control buffer size: room for a full `SCM_RIGHTS` batch plus credentials,
/// so that the kernel hands us every descriptor and we can close it.
const CONTROL_SPACE: usize = rustix::cmsg_space!(ScmRights(253), ScmCredentials(1));

/// Result of one [`recv_no_ancillary`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received {
    /// Bytes placed in the buffer.
    pub bytes: usize,
    /// For datagram sockets: the datagram was longer than the buffer.
    pub truncated: bool,
}

/// `recvmsg(2)` that rejects (and closes) any ancillary data.
pub fn recv_no_ancillary<Fd: AsFd>(
    fd: Fd,
    buf: &mut [u8],
    flags: RecvFlags,
) -> Result<Received, FrameError> {
    let mut space = [MaybeUninit::<u8>::uninit(); CONTROL_SPACE];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let mut iov = [IoSliceMut::new(buf)];
    let msg = loop {
        match rustix::net::recvmsg(
            fd.as_fd(),
            &mut iov,
            &mut control,
            flags | RecvFlags::CMSG_CLOEXEC,
        ) {
            Ok(m) => break m,
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(FrameError::Io(e.into())),
        }
    };
    // Drain: dropping each message (and its fd iterator) closes the fds.
    let mut saw_ancillary = false;
    for m in control.drain() {
        saw_ancillary = true;
        drop(m);
    }
    drop(control);
    if saw_ancillary || msg.flags.contains(ReturnFlags::CTRUNC) {
        return Err(FrameError::AncillaryRejected);
    }
    Ok(Received {
        bytes: msg.bytes.min(iov[0].len()),
        truncated: msg.flags.contains(ReturnFlags::TRUNC),
    })
}

/// A `Read` adapter over a stream socket that rejects ancillary data on every
/// read. Use with [`crate::frame::read_frame`]; a rejection surfaces as
/// [`FrameError::AncillaryRejected`].
#[derive(Debug)]
pub struct CheckedStream<'fd> {
    fd: BorrowedFd<'fd>,
}

impl<'fd> CheckedStream<'fd> {
    /// Wrap a connected stream socket.
    pub fn new(fd: BorrowedFd<'fd>) -> Self {
        Self { fd }
    }
}

impl Read for CheckedStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match recv_no_ancillary(self.fd, buf, RecvFlags::empty()) {
            Ok(r) => Ok(r.bytes),
            Err(FrameError::Io(e)) => Err(e),
            Err(FrameError::AncillaryRejected) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                AncillaryRejected,
            )),
            Err(other) => Err(io::Error::other(other.to_string())),
        }
    }
}

/// Create a connected `AF_UNIX`/`SOCK_SEQPACKET` pair with `SOCK_CLOEXEC`.
pub fn seqpacket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    Ok(rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )?)
}

/// Create a connected `AF_UNIX`/`SOCK_STREAM` pair with `SOCK_CLOEXEC`.
pub fn stream_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    Ok(rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )?)
}

/// Send one payload as one `SOCK_SEQPACKET` datagram (no length prefix).
pub fn send_packet<Fd: AsFd>(
    fd: Fd,
    payload: &[u8],
    limits: FrameLimits,
) -> Result<(), FrameError> {
    let max = limits.max_frame();
    if payload.len() > max {
        return Err(FrameError::TooLarge {
            len: payload.len(),
            max,
        });
    }
    if payload.is_empty() {
        return Err(FrameError::Empty);
    }
    let n = loop {
        match rustix::net::send(fd.as_fd(), payload, SendFlags::NOSIGNAL) {
            Ok(n) => break n,
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(FrameError::Io(e.into())),
        }
    };
    if n != payload.len() {
        return Err(FrameError::Io(io::Error::new(
            io::ErrorKind::WriteZero,
            "short seqpacket send",
        )));
    }
    Ok(())
}

/// Receive one `SOCK_SEQPACKET` datagram.
///
/// The datagram's size is learned with `MSG_PEEK | MSG_TRUNC` and checked
/// against `limits` before the receive buffer is allocated; an oversized
/// datagram is consumed and discarded and reported as
/// [`FrameError::TooLarge`]. Ancillary data is rejected as in
/// [`recv_no_ancillary`]. Returns `Ok(None)` at end of stream; an empty
/// datagram is indistinguishable from end of stream and is treated as such.
pub fn recv_packet<Fd: AsFd>(fd: Fd, limits: FrameLimits) -> Result<Option<Vec<u8>>, FrameError> {
    let fd = fd.as_fd();
    let max = limits.max_frame();
    let mut empty: [u8; 0] = [];
    let announced = loop {
        match rustix::net::recv(fd, &mut empty[..], RecvFlags::PEEK | RecvFlags::TRUNC) {
            Ok((_, n)) => break n,
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(FrameError::Io(e.into())),
        }
    };
    if announced == 0 {
        // EOF, or an empty datagram: consume (rejecting any fds) and stop.
        recv_no_ancillary(fd, &mut empty, RecvFlags::empty())?;
        return Ok(None);
    }
    if announced > max {
        recv_no_ancillary(fd, &mut empty, RecvFlags::empty())?;
        return Err(FrameError::TooLarge {
            len: announced,
            max,
        });
    }
    let mut buf = vec![0u8; announced];
    let r = recv_no_ancillary(fd, &mut buf, RecvFlags::empty())?;
    if r.truncated || r.bytes != announced {
        return Err(FrameError::Truncated);
    }
    Ok(Some(buf))
}
