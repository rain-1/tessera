//! Audit records: one JSON line per request. Never contains bodies, header
//! values, query strings or the credential.

use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// One audited request.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AuditRecord {
    /// Unix time in milliseconds when the request was received.
    pub ts_ms: u64,
    /// Sandbox label.
    pub sandbox: String,
    /// Method (sanitised, ≤ 16 chars).
    pub method: String,
    /// Path without query (sanitised, ≤ 256 chars).
    pub path: String,
    /// Length of the query string (its content is not logged).
    pub query_len: usize,
    /// Status returned to the sandbox (0 if none was sent).
    pub status: u16,
    /// `ok`, `denied:<reason>`, `upstream:<reason>` or `aborted:<reason>`.
    pub outcome: String,
    /// Request body bytes forwarded (or received, when denied after reading).
    pub request_bytes: u64,
    /// SHA-256 of the request body, hex (empty when not read).
    pub request_sha256: String,
    /// Response body bytes returned to the sandbox.
    pub response_bytes: u64,
    /// SHA-256 of the response body returned, hex (empty for local denials).
    pub response_sha256: String,
    /// Upstream peer address, when a connection was made.
    pub upstream_peer: Option<String>,
    /// Number of credential occurrences redacted from the response.
    pub redactions: u64,
    /// Wall time in milliseconds.
    pub duration_ms: u64,
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Truncate and replace anything outside visible ASCII.
pub(crate) fn sanitise(s: &str, max: usize) -> String {
    s.chars()
        .take(max)
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .collect()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Where audit records go.
pub type AuditSink = Arc<dyn Fn(&AuditRecord) + Send + Sync>;

/// JSON lines on standard error.
pub fn stderr_sink() -> AuditSink {
    Arc::new(|r: &AuditRecord| {
        if let Ok(line) = serde_json::to_string(r) {
            eprintln!("{line}");
        }
    })
}

/// JSON lines appended to a file (opened once, append mode, 0600).
pub fn file_sink(path: &Path) -> std::io::Result<AuditSink> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    let f = Mutex::new(f);
    Ok(Arc::new(move |r: &AuditRecord| {
        if let Ok(mut line) = serde_json::to_vec(r) {
            line.push(b'\n');
            let mut f = f.lock().unwrap_or_else(PoisonError::into_inner);
            let _ = f.write_all(&line);
        }
    }))
}
