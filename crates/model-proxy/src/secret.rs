//! The model API credential and response redaction.

use std::fmt;
use std::path::Path;

use bytes::{Bytes, BytesMut};
use http::HeaderValue;

use crate::config::Injection;

/// Replacement written where the credential appeared in a response body.
pub const REDACTED: &[u8] = b"[REDACTED-BY-TESSERA]";

/// Shortest secret accepted; a very short value would make redaction both
/// useless and destructive.
const MIN_SECRET_LEN: usize = 8;

/// The upstream credential. Never printed, never sent to the sandbox.
#[derive(Clone)]
pub struct Credential {
    secret: Vec<u8>,
    inject: Injection,
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("inject", &self.inject)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl Credential {
    /// Build from raw secret bytes.
    pub fn new(secret: &[u8], inject: Injection) -> Result<Self, String> {
        if secret.len() < MIN_SECRET_LEN {
            return Err("credential too short".into());
        }
        if !secret.iter().all(|b| (0x21..=0x7e).contains(b)) {
            return Err("credential must be visible ASCII without spaces".into());
        }
        Ok(Self {
            secret: secret.to_vec(),
            inject,
        })
    }

    /// Read from a host file (single line, trailing whitespace stripped).
    /// The error never contains file contents.
    pub fn from_file(path: &Path, inject: Injection) -> Result<Self, String> {
        let raw = std::fs::read(path).map_err(|e| format!("{}: {}", path.display(), e.kind()))?;
        let trimmed = raw.trim_ascii();
        if trimmed.contains(&b'\n') {
            return Err(format!("{}: expected a single line", path.display()));
        }
        Self::new(trimmed, inject).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Raw secret, for redaction scans.
    pub(crate) fn secret(&self) -> &[u8] {
        &self.secret
    }

    /// Header name used for injection.
    pub fn header_name(&self) -> &'static str {
        self.inject.header_name()
    }

    /// Sensitive header value to inject.
    pub(crate) fn header_value(&self) -> HeaderValue {
        let raw = match self.inject {
            Injection::XApiKey => self.secret.clone(),
            Injection::Bearer => [b"Bearer ".as_slice(), &self.secret].concat(),
        };
        // Validated as visible ASCII in `new`.
        let mut v = HeaderValue::from_bytes(&raw).unwrap_or_else(|_| HeaderValue::from_static(""));
        v.set_sensitive(true);
        v
    }
}

/// Whether `needle` occurs in `hay`.
pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// Streaming redactor: replaces every occurrence of the secret, including
/// occurrences split across chunk boundaries. Only a chunk tail that is a
/// proper prefix of the secret is held back, so ordinary SSE events (which
/// end in `\n\n`) are never delayed.
pub struct Redactor {
    needle: Vec<u8>,
    pending: BytesMut,
    /// Number of replacements made.
    pub hits: u64,
}

impl Redactor {
    /// New redactor for `needle` (must be non-empty).
    pub fn new(needle: &[u8]) -> Self {
        Self {
            needle: needle.to_vec(),
            pending: BytesMut::new(),
            hits: 0,
        }
    }

    /// Feed a chunk; returns bytes safe to emit now.
    pub fn feed(&mut self, chunk: &[u8]) -> Bytes {
        self.pending.extend_from_slice(chunk);
        let buf = std::mem::take(&mut self.pending);
        let n = self.needle.len();
        let mut out = BytesMut::with_capacity(buf.len());
        let mut i = 0;
        while let Some(p) = buf[i..].windows(n).position(|w| w == self.needle) {
            out.extend_from_slice(&buf[i..i + p]);
            out.extend_from_slice(REDACTED);
            self.hits += 1;
            i += p + n;
        }
        // No full match in buf[i..]. Only its last n-1 bytes can start a
        // match that continues in the next chunk: hold back the longest
        // suffix that is a proper prefix of the needle.
        let safe = buf.len().saturating_sub(n - 1).max(i);
        out.extend_from_slice(&buf[i..safe]);
        let tail = &buf[safe..];
        let hold = (1..=tail.len())
            .rev()
            .find(|&k| tail[tail.len() - k..] == self.needle[..k])
            .unwrap_or(0);
        out.extend_from_slice(&tail[..tail.len() - hold]);
        self.pending.extend_from_slice(&tail[tail.len() - hold..]);
        out.freeze()
    }

    /// End of stream: release anything held back (it cannot be the secret).
    pub fn finish(&mut self) -> Bytes {
        std::mem::take(&mut self.pending).freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: &[u8] = b"sk-ant-SECRET-0123";

    fn run(chunks: &[&[u8]]) -> (Vec<u8>, u64) {
        let mut r = Redactor::new(S);
        let mut out = Vec::new();
        for c in chunks {
            out.extend_from_slice(&r.feed(c));
        }
        out.extend_from_slice(&r.finish());
        (out, r.hits)
    }

    #[test]
    fn redacts_whole_and_split() {
        let (o, h) = run(&[b"a sk-ant-SECRET-0123 b"]);
        assert_eq!(o, b"a [REDACTED-BY-TESSERA] b");
        assert_eq!(h, 1);
        let (o, h) = run(&[b"xx sk-ant-SE", b"CRET-0", b"123 yy sk-ant-SECRET-0123"]);
        assert_eq!(o, b"xx [REDACTED-BY-TESSERA] yy [REDACTED-BY-TESSERA]");
        assert_eq!(h, 2);
        // Byte-at-a-time.
        let src = b"--sk-ant-SECRET-0123--sk-ant-SECRET-012";
        let chunks: Vec<&[u8]> = src.chunks(1).collect();
        let (o, h) = run(&chunks);
        assert_eq!(o, b"--[REDACTED-BY-TESSERA]--sk-ant-SECRET-012");
        assert_eq!(h, 1);
    }

    #[test]
    fn does_not_hold_ordinary_events() {
        let mut r = Redactor::new(S);
        let ev = b"event: ping\ndata: {}\n\n";
        assert_eq!(&r.feed(ev)[..], ev);
        // A tail that is a needle prefix is held until disambiguated.
        assert_eq!(&r.feed(b"data: s")[..], b"data: ");
        assert_eq!(&r.feed(b"ure\n\n")[..], b"sure\n\n");
    }

    #[test]
    fn credential_validation_and_debug() {
        assert!(Credential::new(b"short", Injection::XApiKey).is_err());
        assert!(Credential::new(b"has space inside", Injection::XApiKey).is_err());
        let c = Credential::new(S, Injection::Bearer).unwrap();
        assert!(!format!("{c:?}").contains("SECRET"));
        assert_eq!(c.header_value().as_bytes(), b"Bearer sk-ant-SECRET-0123");
        assert!(c.header_value().is_sensitive());
    }
}
