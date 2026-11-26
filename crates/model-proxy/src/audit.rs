//! Audit records: one JSON line per request. Never contains bodies, header
//! values, query strings or the credential.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// One audited request.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AuditRecord {
    /// Per-process request number. A forwarded request has two records with
    /// the same id: `forwarded` (written before the upstream is contacted)
    /// and its completion. 0 for connection-level events and summaries.
    pub id: u64,
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
    /// `forwarded` (request admitted, about to be sent upstream), then one
    /// of `ok`, `upstream:<reason>` or `aborted:<reason>`; or
    /// `denied:<reason>` for requests and connections refused locally; or
    /// `suppressed:<outcome>` for a summary of rate-limited lines.
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
    /// For `suppressed:<outcome>` summaries: how many lines with that
    /// outcome were not written since the previous summary.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub suppressed: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl AuditRecord {
    /// A record for an event that is not tied to a parsed request.
    pub(crate) fn event(sandbox: &str, outcome: String) -> Self {
        Self {
            id: 0,
            ts_ms: now_ms(),
            sandbox: sandbox.to_owned(),
            method: "-".into(),
            path: "-".into(),
            query_len: 0,
            status: 0,
            outcome,
            request_bytes: 0,
            request_sha256: String::new(),
            response_bytes: 0,
            response_sha256: String::new(),
            upstream_peer: None,
            redactions: 0,
            duration_ms: 0,
            suppressed: 0,
        }
    }
}

/// Rate limit for audit lines a sandbox can cause without being admitted
/// (refused connections, locally denied requests): a token bucket, with
/// per-outcome counts of the lines it suppressed (review 2026-11-26, F-2).
/// Outcomes come from a fixed set of reasons, so the map stays small.
#[derive(Debug)]
pub(crate) struct EventLimiter {
    rate: f64,
    burst: f64,
    state: Mutex<LimiterState>,
}

#[derive(Debug)]
struct LimiterState {
    tokens: f64,
    last: Instant,
    suppressed: BTreeMap<String, u64>,
}

impl EventLimiter {
    pub(crate) fn new(per_second: u32, burst: u32) -> Self {
        Self {
            rate: f64::from(per_second),
            burst: f64::from(burst),
            state: Mutex::new(LimiterState {
                tokens: f64::from(burst),
                last: Instant::now(),
                suppressed: BTreeMap::new(),
            }),
        }
    }

    /// Whether a line with `outcome` may be written now; if not it is
    /// counted for the next summary.
    pub(crate) fn allow(&self, outcome: &str) -> bool {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        let refill = now.duration_since(s.last).as_secs_f64() * self.rate;
        s.tokens = (s.tokens + refill).min(self.burst);
        s.last = now;
        if s.tokens >= 1.0 {
            s.tokens -= 1.0;
            return true;
        }
        match s.suppressed.get_mut(outcome) {
            Some(n) => *n = n.saturating_add(1),
            None => {
                s.suppressed.insert(outcome.to_owned(), 1);
            }
        }
        false
    }

    /// Take the suppressed counts accumulated since the last call.
    pub(crate) fn take_suppressed(&self) -> BTreeMap<String, u64> {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        std::mem::take(&mut s.suppressed)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_limiter_counts_suppressed_lines() {
        let l = EventLimiter::new(1, 3);
        let allowed = (0..100).filter(|_| l.allow("denied:x")).count();
        assert_eq!(allowed, 3);
        assert!(!l.allow("denied:y"));
        let s = l.take_suppressed();
        assert_eq!(s["denied:x"], 97);
        assert_eq!(s["denied:y"], 1);
        assert!(l.take_suppressed().is_empty());
    }

    #[test]
    fn summary_field_only_serialised_when_set() {
        let mut r = AuditRecord::event("a", "denied:x".into());
        assert!(!serde_json::to_string(&r).unwrap().contains("suppressed"));
        r.suppressed = 5;
        assert!(
            serde_json::to_string(&r)
                .unwrap()
                .contains("\"suppressed\":5")
        );
    }
}
