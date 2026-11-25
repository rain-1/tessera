//! On-disk format.
//!
//! ```text
//! file   := file_header record*
//! file_header (16 B) := magic "TSRJRNL\0" | format_version u32le (=1) | flags u32le (=0)
//! record := header (32 B) | payload (len B) | chain_hash (32 B)
//! header := len u32le | kind u8 | reserved [0;3] | seq u64le | epoch u64le | header_check [u8;8]
//! header_check = SHA-256("tessera-journal/v1/header" || header[0..24])[0..8]
//! chain_hash   = SHA-256("tessera-journal/v1/record" || prev_hash || header[0..24] || payload)
//! prev_hash of the first record = SHA-256("tessera-journal/v1/genesis")
//! ```
//!
//! The header check lets recovery distinguish "header intact, body
//! incomplete" (a torn append) from "header damaged" (corruption) without
//! trusting a possibly flipped length field. `kind` is never 0, so an
//! all-zero header is never valid.

use sha2::{Digest, Sha256};

/// File magic.
pub const MAGIC: [u8; 8] = *b"TSRJRNL\0";
/// On-disk format version.
pub const FORMAT_VERSION: u32 = 1;
/// File header length.
pub const FILE_HEADER_LEN: u64 = 16;
/// Record header length.
pub const RECORD_HEADER_LEN: usize = 32;
/// Chain hash length.
pub const HASH_LEN: usize = 32;
/// Hard cap on payload length (16 MiB).
pub const HARD_MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// A SHA-256 chain hash.
pub type Hash = [u8; HASH_LEN];

/// Record kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordKind {
    /// Opaque caller payload.
    Data,
    /// Authority epoch bump (empty payload; header epoch is the new epoch).
    EpochBump,
}

impl RecordKind {
    pub(crate) fn to_byte(self) -> u8 {
        match self {
            RecordKind::Data => 1,
            RecordKind::EpochBump => 2,
        }
    }

    pub(crate) fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(RecordKind::Data),
            2 => Some(RecordKind::EpochBump),
            _ => None,
        }
    }
}

pub(crate) fn file_header() -> [u8; FILE_HEADER_LEN as usize] {
    let mut h = [0u8; FILE_HEADER_LEN as usize];
    h[..8].copy_from_slice(&MAGIC);
    h[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    h
}

pub(crate) fn genesis_hash() -> Hash {
    Sha256::digest(b"tessera-journal/v1/genesis").into()
}

/// Decoded record header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    pub len: u32,
    pub kind_byte: u8,
    pub reserved: [u8; 3],
    pub seq: u64,
    pub epoch: u64,
}

impl Header {
    pub fn encode(&self) -> [u8; RECORD_HEADER_LEN] {
        let mut b = [0u8; RECORD_HEADER_LEN];
        b[0..4].copy_from_slice(&self.len.to_le_bytes());
        b[4] = self.kind_byte;
        b[5..8].copy_from_slice(&self.reserved);
        b[8..16].copy_from_slice(&self.seq.to_le_bytes());
        b[16..24].copy_from_slice(&self.epoch.to_le_bytes());
        let check = header_check(&b[..24]);
        b[24..32].copy_from_slice(&check);
        b
    }

    /// Parse, returning `None` if the header check fails.
    pub fn decode(b: &[u8; RECORD_HEADER_LEN]) -> Option<Self> {
        if header_check(&b[..24]) != b[24..32] {
            return None;
        }
        let mut reserved = [0u8; 3];
        reserved.copy_from_slice(&b[5..8]);
        Some(Header {
            len: u32::from_le_bytes(b[0..4].try_into().ok()?),
            kind_byte: b[4],
            reserved,
            seq: u64::from_le_bytes(b[8..16].try_into().ok()?),
            epoch: u64::from_le_bytes(b[16..24].try_into().ok()?),
        })
    }
}

fn header_check(fields: &[u8]) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(b"tessera-journal/v1/header");
    h.update(fields);
    let d = h.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&d[..8]);
    out
}

pub(crate) fn chain_hash(prev: &Hash, header: &[u8; RECORD_HEADER_LEN], payload: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(b"tessera-journal/v1/record");
    h.update(prev);
    h.update(&header[..24]);
    h.update(payload);
    h.finalize().into()
}

/// Total on-disk size of a record with `len` payload bytes.
pub(crate) fn record_size(len: usize) -> u64 {
    (RECORD_HEADER_LEN + len + HASH_LEN) as u64
}
