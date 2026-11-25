//! Length-prefixed framing for byte-stream transports (`SOCK_STREAM`).
//!
//! ```text
//! +-------------------+----------------------+
//! | length: u32 (BE)  | payload (length B)   |
//! +-------------------+----------------------+
//! ```
//!
//! The length is checked against [`FrameLimits`] (itself clamped to
//! [`HARD_MAX_FRAME`]) immediately after the 4 header bytes are read and
//! before any buffer for the payload is allocated. The payload buffer then
//! grows only as bytes actually arrive, so a peer that announces a large
//! frame and stalls cannot pin the full announced size in broker memory.
//! Zero-length frames are rejected (every valid payload carries at least
//! the version header).
//!
//! Timeouts and rate limits are the caller's responsibility (set
//! `SO_RCVTIMEO` or use non-blocking I/O in the broker reactor).
//!
//! For `SOCK_SEQPACKET` transports, which preserve message boundaries, no
//! length prefix is used; see [`crate::unix::send_packet`] and
//! [`crate::unix::recv_packet`].

use std::io::{self, Read, Write};

use crate::codec::{self, DecodeError, EncodeError, WireMessage};

/// Absolute maximum frame payload size, regardless of configuration.
pub const HARD_MAX_FRAME: usize = 16 * 1024 * 1024;
/// Default maximum frame payload size.
pub const DEFAULT_MAX_FRAME: usize = 1024 * 1024;
/// Length prefix size.
pub const FRAME_HEADER_LEN: usize = 4;

/// Per-connection frame limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameLimits {
    max_frame: usize,
}

impl FrameLimits {
    /// Limits with the given maximum payload size, clamped to
    /// [`HARD_MAX_FRAME`].
    pub const fn new(max_frame: usize) -> Self {
        let max_frame = if max_frame > HARD_MAX_FRAME {
            HARD_MAX_FRAME
        } else {
            max_frame
        };
        Self { max_frame }
    }

    /// Maximum payload size.
    pub const fn max_frame(&self) -> usize {
        self.max_frame
    }
}

impl Default for FrameLimits {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_FRAME)
    }
}

/// Framing failure.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// Underlying I/O error.
    #[error("i/o error: {0}")]
    Io(io::Error),
    /// Announced or supplied payload exceeds the limit.
    #[error("frame of {len} bytes exceeds limit of {max}")]
    TooLarge {
        /// Announced length.
        len: usize,
        /// Limit.
        max: usize,
    },
    /// Zero-length frame.
    #[error("empty frame")]
    Empty,
    /// Peer closed the stream in the middle of a frame.
    #[error("unexpected end of stream inside a frame")]
    UnexpectedEof,
    /// The peer attached ancillary data (e.g. file descriptors). Any received
    /// descriptors have already been closed.
    #[error("unsolicited ancillary data rejected")]
    AncillaryRejected,
    /// A datagram did not fit the receive buffer and was truncated.
    #[error("datagram truncated")]
    Truncated,
}

impl From<io::Error> for FrameError {
    fn from(e: io::Error) -> Self {
        if e.get_ref()
            .is_some_and(|inner| inner.is::<crate::unix::AncillaryRejected>())
        {
            FrameError::AncillaryRejected
        } else {
            FrameError::Io(e)
        }
    }
}

/// Write one frame containing `payload`.
pub fn write_frame<W: Write>(
    w: &mut W,
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
    // `max <= HARD_MAX_FRAME < u32::MAX`, so this cannot truncate.
    let len = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge {
        len: payload.len(),
        max,
    })?;
    let mut buf = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(payload);
    w.write_all(&buf)?;
    w.flush()?;
    Ok(())
}

/// Validate a frame header and return the payload length.
pub fn check_header(
    header: [u8; FRAME_HEADER_LEN],
    limits: FrameLimits,
) -> Result<usize, FrameError> {
    let len = u32::from_be_bytes(header) as usize;
    let max = limits.max_frame();
    if len > max {
        return Err(FrameError::TooLarge { len, max });
    }
    if len == 0 {
        return Err(FrameError::Empty);
    }
    Ok(len)
}

/// Read one frame. Returns `Ok(None)` on a clean end of stream at a frame
/// boundary.
pub fn read_frame<R: Read>(r: &mut R, limits: FrameLimits) -> Result<Option<Vec<u8>>, FrameError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    let mut got = 0;
    while got < FRAME_HEADER_LEN {
        match r.read(&mut header[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(FrameError::UnexpectedEof),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    let len = check_header(header, limits)?;
    // Grow with the data actually received rather than pre-allocating `len`.
    let mut payload = Vec::new();
    r.take(len as u64).read_to_end(&mut payload)?;
    if payload.len() != len {
        return Err(FrameError::UnexpectedEof);
    }
    Ok(Some(payload))
}

/// Failure to receive a typed message.
#[derive(Debug, thiserror::Error)]
pub enum RecvError {
    /// Framing / transport failure.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// Payload decoding failure.
    #[error(transparent)]
    Decode(#[from] DecodeError),
}

/// Failure to send a typed message.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    /// Framing / transport failure.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// Encoding failure.
    #[error(transparent)]
    Encode(#[from] EncodeError),
}

/// Encode and write one message as a frame.
pub fn send_message<W: Write, T: WireMessage>(
    w: &mut W,
    msg: &T,
    limits: FrameLimits,
) -> Result<(), SendError> {
    let payload = codec::encode(msg)?;
    write_frame(w, &payload, limits)?;
    Ok(())
}

/// Read and decode one message. `Ok(None)` on clean end of stream.
pub fn recv_message<R: Read, T: WireMessage>(
    r: &mut R,
    limits: FrameLimits,
) -> Result<Option<T>, RecvError> {
    match read_frame(r, limits)? {
        None => Ok(None),
        Some(p) => Ok(Some(codec::decode(&p, limits.max_frame())?)),
    }
}
