//! Minimal strict TLV codec shared by the grant-request and enrollment formats.
//!
//! Every integer is big-endian and fixed-width. A field is
//! `tag: u8 || len: u16 (BE) || value[len]`. Decoders demand an exact tag
//! sequence and exact lengths, so each value has exactly one encoding.

use std::fmt;

/// Reasons a canonical byte string was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Input ended before a complete field was read.
    Truncated,
    /// Input exceeds the format's hard size limit.
    TooLarge,
    /// The leading magic bytes did not match.
    BadMagic,
    /// The format version is not supported by this decoder.
    UnsupportedFormatVersion(u16),
    /// A field tag appeared out of order or was unknown.
    UnexpectedTag { expected: u8, found: u8 },
    /// A field's declared length does not match its content.
    BadLength { tag: u8 },
    /// A field's value is outside its permitted domain (non-canonical).
    InvalidValue(&'static str),
    /// Bytes remained after the last field.
    TrailingBytes,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Truncated => write!(f, "input truncated"),
            DecodeError::TooLarge => write!(f, "input exceeds size limit"),
            DecodeError::BadMagic => write!(f, "bad magic"),
            DecodeError::UnsupportedFormatVersion(v) => {
                write!(f, "unsupported format version {v}")
            }
            DecodeError::UnexpectedTag { expected, found } => {
                write!(f, "unexpected tag {found} (expected {expected})")
            }
            DecodeError::BadLength { tag } => write!(f, "bad length for tag {tag}"),
            DecodeError::InvalidValue(what) => write!(f, "invalid or non-canonical value: {what}"),
            DecodeError::TrailingBytes => write!(f, "trailing bytes"),
        }
    }
}

impl std::error::Error for DecodeError {}

#[derive(Default)]
pub(crate) struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub(crate) fn new() -> Self {
        Self::default()
    }
    pub(crate) fn raw(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
    pub(crate) fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub(crate) fn u16(&mut self, v: u16) {
        self.raw(&v.to_be_bytes());
    }
    pub(crate) fn i16(&mut self, v: i16) {
        self.raw(&v.to_be_bytes());
    }
    pub(crate) fn u32(&mut self, v: u32) {
        self.raw(&v.to_be_bytes());
    }
    pub(crate) fn u64(&mut self, v: u64) {
        self.raw(&v.to_be_bytes());
    }
    pub(crate) fn u128(&mut self, v: u128) {
        self.raw(&v.to_be_bytes());
    }
    /// Appends a TLV field whose value is produced by `body`.
    ///
    /// Panics only if a caller produces a value longer than `u16::MAX`, which
    /// the formats in this crate rule out by construction (all values are
    /// bounded and validated before encoding).
    pub(crate) fn field(&mut self, tag: u8, body: impl FnOnce(&mut Writer)) {
        let mut inner = Writer::new();
        body(&mut inner);
        let len = u16::try_from(inner.buf.len()).expect("TLV value bounded by construction");
        self.u8(tag);
        self.u16(len);
        self.raw(&inner.buf);
    }
    pub(crate) fn finish(self) -> Vec<u8> {
        self.buf
    }
}

pub(crate) struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.buf.len() < n {
            return Err(DecodeError::Truncated);
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let s = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Ok(out)
    }
    pub(crate) fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.array::<1>()?[0])
    }
    pub(crate) fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    pub(crate) fn i16(&mut self) -> Result<i16, DecodeError> {
        Ok(i16::from_be_bytes(self.array()?))
    }
    pub(crate) fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    pub(crate) fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub(crate) fn u128(&mut self) -> Result<u128, DecodeError> {
        Ok(u128::from_be_bytes(self.array()?))
    }
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.buf)
    }
    /// Reads the next TLV field, requiring exactly `expected_tag`, and returns
    /// a sub-reader over its value.
    pub(crate) fn field(&mut self, expected_tag: u8) -> Result<Reader<'a>, DecodeError> {
        let tag = self.u8()?;
        if tag != expected_tag {
            return Err(DecodeError::UnexpectedTag {
                expected: expected_tag,
                found: tag,
            });
        }
        let len = usize::from(self.u16()?);
        let value = self.take(len).map_err(|_| DecodeError::BadLength { tag })?;
        Ok(Reader::new(value))
    }
    /// Requires that the whole input has been consumed.
    pub(crate) fn finish(self) -> Result<(), DecodeError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
    /// Like [`Reader::finish`] but reports a length error for `tag`.
    pub(crate) fn finish_field(self, tag: u8) -> Result<(), DecodeError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::BadLength { tag })
        }
    }
}

/// Lower-case hexadecimal rendering.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    s
}
