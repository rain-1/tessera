//! # tessera-protocol — the untrusted wire schema
//!
//! This crate defines what agents may *say* to the Tessera broker, and how
//! those bytes are framed and bounded. It never decides what agents may
//! *do*: parsing a message creates no authority. Every identifier in a
//! decoded message is a claim to be checked by the broker against the
//! principal authenticated from the transport, and every [`wire::WireScope`]
//! must be validated and converted into the authority core's own scope type
//! before use. The core does not depend on this crate and this crate does
//! not depend on the core (§7: wire types are distinct from validated
//! internal types).
//!
//! ## Layers
//!
//! * [`wire`] — plain-data requests/responses following §9.2, with
//!   [`wire::ErrorCode`] for typed denials.
//! * [`bounded`] — length-bounded byte/string/vector containers used for every
//!   variable-length field; bounds are checked during deserialisation before
//!   anything is materialised.
//! * [`codec`] — versioned envelope (`u16` big-endian version + body), strict
//!   canonical decoding.
//! * [`frame`] — `u32` big-endian length-prefixed frames for stream sockets
//!   with a hard maximum ([`frame::HARD_MAX_FRAME`]) checked before
//!   allocation.
//! * [`unix`] — `SO_PEERCRED`, `recvmsg` that rejects and closes any
//!   ancillary data / `SCM_RIGHTS`, and `SOCK_SEQPACKET` helpers (preferred
//!   transport: it preserves message boundaries).
//!
//! ## Encoding choice: postcard (serde), strict mode
//!
//! Bodies are encoded with [postcard] 1.x, wrapped in our own version header.
//! Reasons:
//!
//! * **Compact and simple.** Varint integers, length-prefixed bytes/strings,
//!   varint enum discriminants, no field names, no type tags, no
//!   self-description. The decoder is a small, non-recursive-by-schema
//!   state machine with no configuration knobs that could diverge between
//!   peers.
//! * **Deterministic.** A given value has exactly one encoding produced by
//!   the encoder (no maps, no floats, no optional field ordering in our
//!   schema). Because a decoder may still *accept* some non-canonical inputs
//!   (e.g. overlong varints), [`codec::decode`] re-encodes the decoded value
//!   and rejects the payload unless it matches byte for byte, and rejects any
//!   trailing bytes. Accepted payloads therefore have a unique encoding, so
//!   the broker can bind a request id to canonical content
//!   ([`codec::canonical_request_bytes`]).
//! * **Bounded resource use.** postcard borrows byte/str fields from the
//!   input and checks length prefixes against the remaining input, so
//!   allocation is bounded by the (already size-checked) frame; our
//!   [`bounded`] types additionally enforce per-field and per-sequence
//!   limits. Unknown enum discriminants, invalid UTF-8 and booleans other
//!   than 0/1 are errors.
//! * **Not self-describing on purpose.** There is no schema negotiation; the
//!   envelope version selects the schema and an unknown version is rejected
//!   before body parsing.
//!
//! Alternatives considered: bincode (similar, but configuration-dependent
//! encodings and a history of large preallocation on hostile length
//! prefixes), CBOR (self-describing, multiple encodings of one value unless a
//! canonical profile is enforced, larger parser surface), protobuf
//! (unknown-field skipping is the opposite of what an authority boundary
//! wants), JSON (non-canonical and large).
//!
//! ## Nesting and count limits
//!
//! The schema is non-recursive, so the maximum nesting depth is fixed by the
//! types (see [`wire`]). Count/size limits: [`frame::HARD_MAX_FRAME`] per
//! frame (and a configurable lower [`frame::FrameLimits`]),
//! [`wire::MAX_HTTP_HEADERS`] headers, [`wire::MAX_HTTP_PATH`],
//! [`wire::MAX_HEADER_NAME`], [`wire::MAX_HEADER_VALUE`],
//! [`wire::MAX_CONTENT_BYTES`]. Timeouts and rate limits belong to the
//! broker's reactor.
//!
//! [postcard]: https://docs.rs/postcard

pub mod bounded;
pub mod codec;
pub mod frame;
pub mod unix;
pub mod wire;

pub use codec::{
    DecodeError, EncodeError, PROTOCOL_VERSION, canonical_request_bytes, decode, decode_client,
    decode_server, encode, encode_client, encode_server,
};
pub use frame::{
    FrameError, FrameLimits, RecvError, SendError, read_frame, recv_message, send_message,
    write_frame,
};
pub use wire::*;
