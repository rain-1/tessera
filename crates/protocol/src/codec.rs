//! Versioned envelope and strict, canonical message encoding.
//!
//! A *payload* (the contents of one frame or one SEQPACKET datagram) is:
//!
//! ```text
//! +----------------+-------------------------------+
//! | version: u16be | postcard(ClientMessage | ServerMessage) |
//! +----------------+-------------------------------+
//! ```
//!
//! The version is checked before any body parsing; an unknown version is a
//! hard rejection ([`DecodeError::UnsupportedVersion`]), never a best-effort
//! parse. Decoding is *strict*: the body must be consumed exactly, and the
//! body must be the canonical encoding of the decoded value (we re-encode and
//! compare). Hence for every accepted payload `p`,
//! `encode(decode(p)) == p`, which lets the broker bind request ids to
//! canonical request bytes without worrying about alternative encodings
//! (overlong varints, trailing garbage) of the same logical request.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::frame::HARD_MAX_FRAME;
use crate::wire::{ClientMessage, Request, ServerMessage};

/// Current protocol version.
pub const PROTOCOL_VERSION: u16 = 1;
/// Bytes of envelope header preceding the body.
pub const ENVELOPE_HEADER_LEN: usize = 2;

/// Payload decoding failure. All variants are denials.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// Payload exceeds the permitted size; nothing was parsed.
    #[error("payload of {len} bytes exceeds limit of {max}")]
    TooLarge {
        /// Payload length.
        len: usize,
        /// Limit.
        max: usize,
    },
    /// Payload shorter than the envelope header.
    #[error("payload too short for envelope header")]
    Truncated,
    /// Unknown protocol version.
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),
    /// Body does not parse as the expected message type (includes bound
    /// violations, unknown enum tags, invalid UTF-8, invalid booleans).
    #[error("malformed message body")]
    Malformed,
    /// Body parsed but was not exactly the canonical encoding (trailing
    /// bytes, overlong varints, ...).
    #[error("non-canonical message encoding")]
    NonCanonical,
}

/// Encoding failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    /// Serializer failed.
    #[error("serialization failed")]
    Serialize,
    /// Encoded payload would exceed the hard frame limit.
    #[error("encoded payload of {len} bytes exceeds hard limit {max}")]
    TooLarge {
        /// Encoded length.
        len: usize,
        /// Limit.
        max: usize,
    },
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::ClientMessage {}
    impl Sealed for super::ServerMessage {}
    impl Sealed for super::Request {}
}

/// Types that may appear as the body of a payload.
pub trait WireMessage: sealed::Sealed + Serialize + DeserializeOwned {}
impl WireMessage for ClientMessage {}
impl WireMessage for ServerMessage {}
impl WireMessage for Request {}

/// Encode `msg` as a versioned payload.
pub fn encode<T: WireMessage>(msg: &T) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    let out = postcard::to_extend(msg, out).map_err(|_| EncodeError::Serialize)?;
    if out.len() > HARD_MAX_FRAME {
        return Err(EncodeError::TooLarge {
            len: out.len(),
            max: HARD_MAX_FRAME,
        });
    }
    Ok(out)
}

/// Decode a versioned payload of at most `max_len` bytes.
///
/// Order of checks: size (before touching contents), version (before body
/// parsing), bounded body parse, exact/canonical consumption.
pub fn decode<T: WireMessage>(payload: &[u8], max_len: usize) -> Result<T, DecodeError> {
    let max = max_len.min(HARD_MAX_FRAME);
    if payload.len() > max {
        return Err(DecodeError::TooLarge {
            len: payload.len(),
            max,
        });
    }
    let (hdr, body) = payload
        .split_first_chunk::<ENVELOPE_HEADER_LEN>()
        .ok_or(DecodeError::Truncated)?;
    let version = u16::from_be_bytes(*hdr);
    if version != PROTOCOL_VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }
    let (value, rest): (T, &[u8]) =
        postcard::take_from_bytes(body).map_err(|_| DecodeError::Malformed)?;
    if !rest.is_empty() {
        return Err(DecodeError::NonCanonical);
    }
    // Canonicality: the re-encoding must reproduce the body byte for byte.
    // Bounded by `max`, so this costs at most one extra allocation of the
    // payload size.
    let consumed = &body[..body.len() - rest.len()];
    let re = postcard::to_allocvec(&value).map_err(|_| DecodeError::Malformed)?;
    if re.as_slice() != consumed {
        return Err(DecodeError::NonCanonical);
    }
    Ok(value)
}

/// Encode a client message.
pub fn encode_client(msg: &ClientMessage) -> Result<Vec<u8>, EncodeError> {
    encode(msg)
}

/// Decode a client message (the broker side; input is hostile).
pub fn decode_client(payload: &[u8], max_len: usize) -> Result<ClientMessage, DecodeError> {
    decode(payload, max_len)
}

/// Encode a server message.
pub fn encode_server(msg: &ServerMessage) -> Result<Vec<u8>, EncodeError> {
    encode(msg)
}

/// Decode a server message (the client side).
pub fn decode_server(payload: &[u8], max_len: usize) -> Result<ServerMessage, DecodeError> {
    decode(payload, max_len)
}

/// Canonical bytes of a request, independent of the correlation id, for
/// binding a request id to its content (e.g. hash these into the journal).
/// Includes the protocol version so that bindings never collide across
/// schema versions.
pub fn canonical_request_bytes(req: &Request) -> Result<Vec<u8>, EncodeError> {
    encode(req)
}
