//! Audit events (§11), hash-chained.
//!
//! Every authority decision (accepted or denied), every adapter effect and
//! every recovery finding produces one [`AuditEvent`]. Events carry
//! sequence, epoch, trusted tick, authenticated principal, request digest,
//! capability/root/parent/reservation ids, a scope summary, budget before
//! and after, outcome and adapter effect status. They never carry file or
//! HTTP contents, header values, agent-supplied descriptions (length and
//! digest only) or secrets.
//!
//! ## Hash chain
//!
//! The log is JSON lines. Each event's `prev` field is the hex SHA-256 of
//! the previous line's exact bytes (without the newline); the first event
//! of a log has `prev` = 64 zeros. The hash of a line is therefore a
//! commitment to the whole prefix. [`verify_bytes`] / [`verify_file`]
//! recompute the chain and check sequence continuity; given an *externally
//! retained* [`AuditCheckpoint`] (`tessera-admin audit checkpoint`, stored
//! off-host) they also detect a rewritten or truncated prefix. As §11 says,
//! this detects accidental corruption and tampering *relative to a retained
//! checkpoint*; it does not stop an administrator from rewriting the whole
//! history and every checkpoint they hold.
//!
//! ## Durability
//!
//! [`AuditSync`] selects when the file is `fdatasync`ed. The default is
//! after every event. A write or sync failure is returned to the caller;
//! the broker treats it as fatal and fails closed (it stops), so no
//! decision is released without its audit line having been handed to the
//! kernel (and, by default, synced). The journal remains the authoritative
//! record; the audit log is the human-oriented view.
//!
//! On open, an existing log is verified. A torn final line (no trailing
//! newline: an interrupted write) is truncated; any other inconsistency
//! refuses to open (fail closed): rotate the file after investigating it
//! with `tessera-admin audit verify`.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::convert::hex;

/// Bound on events kept in memory.
pub const AUDIT_RING: usize = 20_000;
/// `prev` of the first event of a log.
pub const GENESIS_PREV: [u8; 32] = [0; 32];

/// One audit event.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Audit sequence (monotonic across restarts when a log file is used).
    pub seq: u64,
    /// Hex SHA-256 of the previous line (64 zeros for the first event).
    pub prev: String,
    /// Authority epoch.
    pub epoch: u64,
    /// Trusted tick (milliseconds since the epoch began).
    pub tick: u64,
    /// Journal sequence of the committing record, if any.
    pub journal_seq: Option<u64>,
    /// `operator`, `agent:e<epoch>.s<serial>` or `broker`.
    pub principal: String,
    /// Event kind (`consume`, `delegate`, `mint`, `effect`, ...).
    pub kind: String,
    /// Client request id (hex), if any.
    pub request_id: Option<String>,
    /// SHA-256 of the canonical request bytes (hex), if any.
    pub request_digest: Option<String>,
    /// Capability id.
    pub capability: Option<u128>,
    /// Root id.
    pub root: Option<u128>,
    /// Parent capability id.
    pub parent: Option<u128>,
    /// Child / new capability id.
    pub child: Option<u128>,
    /// Reservation id.
    pub reservation: Option<u64>,
    /// Scope summary (ids and rights only).
    pub scope: Option<String>,
    /// Budget before.
    pub budget_before: Option<String>,
    /// Budget after.
    pub budget_after: Option<String>,
    /// Outcome: `ok` or `denied:<reason>` or `error:<reason>`.
    pub outcome: String,
    /// Adapter effect status: `reserved`, `dispatched`, `completed`,
    /// `failed`, `unknown`, `abandoned-not-dispatched`.
    pub effect: Option<String>,
    /// Non-sensitive detail (sizes, digests, ids).
    pub detail: Option<String>,
}

/// When the audit file is synced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuditSync {
    /// `fdatasync` after every event (default).
    #[default]
    EveryEvent,
    /// `fdatasync` after every `n` events (n ≥ 1); a crash may lose up to
    /// `n - 1` acknowledged lines (detectable against a checkpoint).
    EveryN(u32),
    /// Flush to the kernel only; never `fdatasync`.
    Never,
}

impl std::str::FromStr for AuditSync {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "every-event" | "always" => Ok(AuditSync::EveryEvent),
            "never" | "none" => Ok(AuditSync::Never),
            _ => match s.strip_prefix("every:").map(str::parse::<u32>) {
                Some(Ok(n)) if n >= 1 => Ok(AuditSync::EveryN(n)),
                _ => Err(format!(
                    "audit fsync policy {s:?}: use every-event, every:N or never"
                )),
            },
        }
    }
}

/// An externally retained commitment: the event `seq` has line hash `hash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditCheckpoint {
    /// Sequence of the committed event.
    pub seq: u64,
    /// SHA-256 of that event's line.
    pub hash: [u8; 32],
}

impl AuditCheckpoint {
    /// Parse `SEQ:HEX64`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let (seq, h) = s.split_once(':').ok_or("checkpoint is SEQ:HEX")?;
        let seq = seq.parse().map_err(|_| "checkpoint SEQ: not a number")?;
        let hash = parse_hash(h).ok_or("checkpoint HEX: 64 hex digits")?;
        Ok(AuditCheckpoint { seq, hash })
    }
}

impl std::fmt::Display for AuditCheckpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.seq, hex(&self.hash))
    }
}

fn parse_hash(h: &str) -> Option<[u8; 32]> {
    if h.len() != 64 || !h.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Result of a successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditVerified {
    /// Number of events.
    pub events: u64,
    /// Last event (sequence and line hash), if any.
    pub head: Option<AuditCheckpoint>,
    /// Bytes of a torn final line (no newline) that were ignored.
    pub torn_tail_bytes: usize,
}

/// Verify a log held in memory. `checkpoint`, if given, must name an event
/// present in the log with exactly that line hash.
pub fn verify_bytes(
    bytes: &[u8],
    checkpoint: Option<AuditCheckpoint>,
) -> Result<AuditVerified, String> {
    let complete = match bytes.iter().rposition(|b| *b == b'\n') {
        Some(i) => i + 1,
        None => 0,
    };
    let mut prev = GENESIS_PREV;
    let mut expect_seq: Option<u64> = None;
    let mut events = 0u64;
    let mut head = None;
    let mut cp_seen = false;
    let body = &bytes[..complete];
    let body = body.strip_suffix(b"\n").unwrap_or(body);
    let lines = body.split(|b| *b == b'\n').filter(|_| !body.is_empty());
    for (n, line) in lines.enumerate() {
        if line.is_empty() {
            return Err(format!("line {}: empty line", n + 1));
        }
        let ev: AuditEvent = serde_json::from_slice(line)
            .map_err(|e| format!("line {}: not an audit event: {e}", n + 1))?;
        if ev.prev != hex(&prev) {
            return Err(format!(
                "line {} (seq {}): chain broken: prev {} != hash of previous line {}",
                n + 1,
                ev.seq,
                ev.prev,
                hex(&prev)
            ));
        }
        if let Some(s) = expect_seq
            && ev.seq != s
        {
            return Err(format!(
                "line {}: sequence {} where {s} was expected",
                n + 1,
                ev.seq
            ));
        }
        let h: [u8; 32] = Sha256::digest(line).into();
        if let Some(cp) = checkpoint
            && cp.seq == ev.seq
        {
            if cp.hash != h {
                return Err(format!(
                    "checkpoint mismatch at seq {}: log has {}, checkpoint says {}",
                    cp.seq,
                    hex(&h),
                    hex(&cp.hash)
                ));
            }
            cp_seen = true;
        }
        prev = h;
        expect_seq = Some(ev.seq.saturating_add(1));
        events += 1;
        head = Some(AuditCheckpoint {
            seq: ev.seq,
            hash: h,
        });
    }
    if let Some(cp) = checkpoint
        && !cp_seen
    {
        return Err(format!(
            "checkpoint seq {} is not in the log (truncated or rotated?)",
            cp.seq
        ));
    }
    Ok(AuditVerified {
        events,
        head,
        torn_tail_bytes: bytes.len() - complete,
    })
}

/// Verify a log file (read-only).
pub fn verify_file(
    path: &Path,
    checkpoint: Option<AuditCheckpoint>,
) -> Result<AuditVerified, String> {
    let mut b = Vec::new();
    File::open(path)
        .and_then(|mut f| f.read_to_end(&mut b))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    verify_bytes(&b, checkpoint)
}

/// Audit sink: JSONL file (optional) + bounded ring, hash-chained.
#[derive(Debug)]
pub struct AuditLog {
    file: Option<File>,
    ring: VecDeque<AuditEvent>,
    next_seq: u64,
    head: [u8; 32],
    sync: AuditSync,
    unsynced: u32,
}

impl AuditLog {
    /// In-memory only (still chained, so the ring is verifiable).
    pub fn memory() -> Self {
        AuditLog {
            file: None,
            ring: VecDeque::new(),
            next_seq: 0,
            head: GENESIS_PREV,
            sync: AuditSync::Never,
            unsynced: 0,
        }
    }

    /// [`AuditLog::open_with`] the default policy (sync every event).
    pub fn open(path: &Path) -> std::io::Result<Self> {
        Self::open_with(path, AuditSync::default())
    }

    /// Append to `path`, continuing the chain and sequence found there.
    /// The existing content is verified first: a torn final line is
    /// truncated (durably); any other inconsistency is an error.
    pub fn open_with(path: &Path, sync: AuditSync) -> std::io::Result<Self> {
        let mut existing = Vec::new();
        match File::open(path) {
            Ok(mut f) => {
                f.read_to_end(&mut existing)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let v = verify_bytes(&existing, None).map_err(|e| {
            std::io::Error::other(format!(
                "audit log {} fails verification ({e}); refusing to append. \
                 Investigate with `tessera-admin audit verify --file` and rotate it",
                path.display()
            ))
        })?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(path)?;
        if v.torn_tail_bytes > 0 {
            file.set_len((existing.len() - v.torn_tail_bytes) as u64)?;
            file.sync_data()?;
        }
        let mut ring = VecDeque::new();
        let complete = existing.len() - v.torn_tail_bytes;
        for line in existing[..complete].split(|b| *b == b'\n') {
            if let Ok(ev) = serde_json::from_slice::<AuditEvent>(line) {
                ring.push_back(ev);
                if ring.len() > AUDIT_RING {
                    ring.pop_front();
                }
            }
        }
        let (next_seq, head) = match v.head {
            Some(h) => (h.seq.saturating_add(1), h.hash),
            None => (0, GENESIS_PREV),
        };
        let mut log = AuditLog {
            file: Some(file),
            ring,
            next_seq,
            head,
            sync,
            unsynced: 0,
        };
        if v.torn_tail_bytes > 0 {
            log.record(AuditEvent {
                principal: "broker".into(),
                kind: "audit-torn-tail-truncated".into(),
                outcome: "ok".into(),
                detail: Some(format!("bytes={}", v.torn_tail_bytes)),
                ..AuditEvent::default()
            })?;
        }
        Ok(log)
    }

    /// Record an event: assigns its sequence and `prev`, appends it and
    /// syncs per policy. An error means the line may not be durable; the
    /// broker fails closed on it.
    pub fn record(&mut self, mut ev: AuditEvent) -> std::io::Result<u64> {
        ev.seq = self.next_seq;
        ev.prev = hex(&self.head);
        let line = serde_json::to_string(&ev).map_err(std::io::Error::other)?;
        let h: [u8; 32] = Sha256::digest(line.as_bytes()).into();
        if let Some(f) = self.file.as_mut() {
            let mut buf = line.into_bytes();
            buf.push(b'\n');
            f.write_all(&buf)?;
            f.flush()?;
            let due = match self.sync {
                AuditSync::EveryEvent => true,
                AuditSync::EveryN(n) => self.unsynced.saturating_add(1) >= n,
                AuditSync::Never => false,
            };
            if due {
                f.sync_data()?;
                self.unsynced = 0;
            } else {
                self.unsynced = self.unsynced.saturating_add(1);
            }
        }
        self.head = h;
        self.next_seq = self.next_seq.saturating_add(1);
        let seq = ev.seq;
        self.ring.push_back(ev);
        if self.ring.len() > AUDIT_RING {
            self.ring.pop_front();
        }
        Ok(seq)
    }

    /// The last recorded event as a checkpoint (`None` if empty).
    pub fn checkpoint(&self) -> Option<AuditCheckpoint> {
        self.next_seq.checked_sub(1).map(|seq| AuditCheckpoint {
            seq,
            hash: self.head,
        })
    }

    /// Events with `seq >= since`, at most `limit`.
    pub fn since(&self, since: u64, limit: usize) -> Vec<AuditEvent> {
        self.ring
            .iter()
            .filter(|e| e.seq >= since)
            .take(limit)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: &str) -> AuditEvent {
        AuditEvent {
            principal: "broker".into(),
            kind: kind.into(),
            outcome: "ok".into(),
            ..AuditEvent::default()
        }
    }

    #[test]
    fn chain_verifies_and_detects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        let mut log = AuditLog::open(&p).unwrap();
        for k in ["a", "b", "c", "d"] {
            log.record(ev(k)).unwrap();
        }
        let cp = log.checkpoint().unwrap();
        assert_eq!(cp.seq, 3);
        drop(log);
        let v = verify_file(&p, Some(cp)).unwrap();
        assert_eq!((v.events, v.head), (4, Some(cp)));
        // Reopen continues the chain.
        let mut log = AuditLog::open(&p).unwrap();
        log.record(ev("e")).unwrap();
        let cp2 = log.checkpoint().unwrap();
        drop(log);
        assert_eq!(verify_file(&p, Some(cp)).unwrap().events, 5);
        assert_eq!(verify_file(&p, Some(cp2)).unwrap().head, Some(cp2));
        assert_eq!(AuditCheckpoint::parse(&cp2.to_string()).unwrap(), cp2);

        let orig = std::fs::read_to_string(&p).unwrap();
        // Edit one field of a middle line: the next line's prev breaks.
        let edited = orig.replacen("\"kind\":\"b\"", "\"kind\":\"x\"", 1);
        assert!(
            verify_bytes(edited.as_bytes(), None)
                .unwrap_err()
                .contains("chain broken")
        );
        // Delete a middle line.
        let lines: Vec<&str> = orig.lines().collect();
        let dropped = [&lines[..2], &lines[3..]].concat().join("\n") + "\n";
        assert!(verify_bytes(dropped.as_bytes(), None).is_err());
        // Consistently rewritten history (recomputed chain) passes on its
        // own but not against the externally retained checkpoint.
        let mut forged = AuditLog::memory();
        let mut text = String::new();
        for k in ["a", "B", "c", "d"] {
            let mut e = ev(k);
            e.seq = forged.next_seq;
            e.prev = hex(&forged.head);
            text.push_str(&serde_json::to_string(&e).unwrap());
            text.push('\n');
            forged.record(ev(k)).unwrap();
        }
        assert!(verify_bytes(text.as_bytes(), None).is_ok());
        assert!(
            verify_bytes(text.as_bytes(), Some(cp))
                .unwrap_err()
                .contains("checkpoint mismatch")
        );
        // Truncation below the checkpoint is detected.
        let short = lines[..2].join("\n") + "\n";
        assert!(
            verify_bytes(short.as_bytes(), Some(cp))
                .unwrap_err()
                .contains("not in the log")
        );
        // A modified file refuses to be appended to (fail closed).
        std::fs::write(&p, edited).unwrap();
        assert!(AuditLog::open(&p).is_err());
    }

    #[test]
    fn torn_tail_is_truncated_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.jsonl");
        let mut log = AuditLog::open_with(&p, AuditSync::EveryN(2)).unwrap();
        log.record(ev("a")).unwrap();
        drop(log);
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"{\"seq\":1,\"pre").unwrap();
        drop(f);
        assert_eq!(verify_file(&p, None).unwrap().torn_tail_bytes, 13);
        let log = AuditLog::open(&p).unwrap();
        assert_eq!(
            log.since(0, 10).last().unwrap().kind,
            "audit-torn-tail-truncated"
        );
        drop(log);
        let v = verify_file(&p, None).unwrap();
        assert_eq!((v.events, v.torn_tail_bytes), (2, 0));
    }

    #[test]
    fn sync_policy_parses() {
        assert_eq!("every-event".parse(), Ok(AuditSync::EveryEvent));
        assert_eq!("every:8".parse(), Ok(AuditSync::EveryN(8)));
        assert_eq!("never".parse(), Ok(AuditSync::Never));
        assert!("every:0".parse::<AuditSync>().is_err());
        assert!("sometimes".parse::<AuditSync>().is_err());
    }
}
