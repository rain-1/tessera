//! Audit events (§11).
//!
//! Every authority decision (accepted or denied), every adapter effect and
//! every recovery finding produces one [`AuditEvent`]. Events carry
//! sequence, epoch, trusted tick, authenticated principal, request digest,
//! capability/root/parent/reservation ids, a scope summary, budget before
//! and after, outcome and adapter effect status. They never carry file or
//! HTTP contents, header values or secrets.
//!
//! The journal is the authoritative record; the audit log is a derived,
//! human-oriented view written as JSON lines (flushed, not fsynced) plus a
//! bounded in-memory ring for the admin endpoint.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Bound on events kept in memory.
pub const AUDIT_RING: usize = 20_000;

/// One audit event.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Audit sequence (monotonic across restarts when a log file is used).
    pub seq: u64,
    /// Authority epoch.
    pub epoch: u64,
    /// Trusted tick (milliseconds since the epoch began).
    pub tick: u64,
    /// Journal sequence of the committing record, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub journal_seq: Option<u64>,
    /// `operator`, `agent:e<epoch>.s<serial>` or `broker`.
    pub principal: String,
    /// Event kind (`consume`, `delegate`, `mint`, `effect`, ...).
    pub kind: String,
    /// Client request id (hex), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// SHA-256 of the canonical request bytes (hex), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_digest: Option<String>,
    /// Capability id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<u128>,
    /// Root id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<u128>,
    /// Parent capability id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<u128>,
    /// Child / new capability id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child: Option<u128>,
    /// Reservation id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reservation: Option<u64>,
    /// Scope summary (ids and rights only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Budget before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_before: Option<String>,
    /// Budget after.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_after: Option<String>,
    /// Outcome: `ok` or `denied:<reason>` or `error:<reason>`.
    pub outcome: String,
    /// Adapter effect status: `reserved`, `dispatched`, `completed`,
    /// `failed`, `unknown`, `abandoned-not-dispatched`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effect: Option<String>,
    /// Non-sensitive detail (sizes, digests, ids).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Audit sink: JSONL file (optional) + bounded ring.
#[derive(Debug)]
pub struct AuditLog {
    file: Option<File>,
    ring: VecDeque<AuditEvent>,
    next_seq: u64,
}

impl AuditLog {
    /// In-memory only.
    pub fn memory() -> Self {
        AuditLog {
            file: None,
            ring: VecDeque::new(),
            next_seq: 0,
        }
    }

    /// Append to `path`, continuing the sequence found there.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let mut next_seq = 0;
        let mut ring = VecDeque::new();
        if let Ok(f) = File::open(path) {
            for line in BufReader::new(f).lines() {
                let line = line?;
                if let Ok(ev) = serde_json::from_str::<AuditEvent>(&line) {
                    next_seq = ev.seq.saturating_add(1);
                    ring.push_back(ev);
                    if ring.len() > AUDIT_RING {
                        ring.pop_front();
                    }
                }
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(AuditLog {
            file: Some(file),
            ring,
            next_seq,
        })
    }

    /// Record an event; assigns its sequence number.
    pub fn record(&mut self, mut ev: AuditEvent) -> u64 {
        ev.seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        if let Some(f) = self.file.as_mut()
            && let Ok(mut line) = serde_json::to_string(&ev)
        {
            line.push('\n');
            // Audit-file failures do not affect authority (the journal is
            // authoritative) but are reported on stderr.
            if let Err(e) = f.write_all(line.as_bytes()).and_then(|()| f.flush()) {
                eprintln!("tessera-broker: audit log write failed: {e}");
            }
        }
        let seq = ev.seq;
        self.ring.push_back(ev);
        if self.ring.len() > AUDIT_RING {
            self.ring.pop_front();
        }
        seq
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
