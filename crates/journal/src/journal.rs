//! The journal: recovery, durable append, replay, epochs.

use std::io;
use std::path::Path;

use crate::format::{
    FILE_HEADER_LEN, HARD_MAX_PAYLOAD, HASH_LEN, Hash, Header, RECORD_HEADER_LEN, RecordKind,
    chain_hash, file_header, genesis_hash, record_size,
};
use crate::storage::{FileStorage, Storage};

/// Why recovery refused a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorruptionKind {
    /// Header integrity check failed.
    HeaderCheck,
    /// Unknown record kind or non-zero reserved bytes.
    InvalidHeaderField,
    /// Payload length exceeds the configured maximum.
    OversizedRecord,
    /// Sequence number is not the expected successor.
    SequenceGap,
    /// Epoch did not follow the rules (data must match the current epoch;
    /// an epoch bump must be current + 1 with an empty payload).
    EpochViolation,
    /// Chain hash mismatch (payload, header or predecessor altered).
    HashMismatch,
}

/// Journal error. Every variant is fail-closed.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// I/O failure.
    #[error("journal i/o error: {0}")]
    Io(#[from] io::Error),
    /// Another process holds the writer lock.
    #[error("journal is locked by another writer")]
    Locked,
    /// File header missing, damaged or of an unknown format version.
    #[error("bad or unsupported journal file header")]
    BadFileHeader,
    /// Corruption that is not a torn tail; recovery refuses to continue.
    #[error("journal corrupt at offset {offset} (expected seq {expected_seq}): {kind:?}")]
    Corrupt {
        /// Byte offset of the offending record.
        offset: u64,
        /// Sequence number that was expected there.
        expected_seq: u64,
        /// Classification.
        kind: CorruptionKind,
    },
    /// Payload exceeds the configured maximum.
    #[error("payload of {len} bytes exceeds maximum {max}")]
    PayloadTooLarge {
        /// Length.
        len: usize,
        /// Maximum.
        max: usize,
    },
    /// A previous write or sync failed; the in-process view of durable state
    /// can no longer be trusted. Reopen (and recover) to continue.
    #[error("journal poisoned by an earlier write/sync failure; reopen required")]
    Poisoned,
    /// Sequence or epoch counter would overflow.
    #[error("journal counter overflow")]
    Overflow,
}

/// Handling of a damaged *final* record whose damage cannot be proven to be a
/// torn write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TailPolicy {
    /// Refuse to open (default). An acknowledged record is never silently
    /// discarded.
    #[default]
    Strict,
    /// Operator override: if the final record's header is intact and its
    /// body ends exactly at end of file but the chain hash does not match,
    /// treat it as an unacknowledged torn write and truncate it. (A damaged
    /// header is still refused: its length cannot be trusted, so we cannot
    /// tell whether it is the final record.) Use only
    /// after confirming the storage reorders writes (e.g. a crash exposed
    /// stale blocks inside a size-extended file); this may discard an
    /// acknowledged record if the damage was in fact media corruption.
    TruncateUnverifiableFinalRecord,
}

/// Journal open options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalOptions {
    /// Maximum payload length accepted on append and on recovery (clamped to
    /// [`HARD_MAX_PAYLOAD`]).
    pub max_payload: usize,
    /// Damaged-final-record policy.
    pub tail_policy: TailPolicy,
}

impl Default for JournalOptions {
    fn default() -> Self {
        Self {
            max_payload: 1024 * 1024,
            tail_policy: TailPolicy::Strict,
        }
    }
}

/// What recovery found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryReport {
    /// The journal was empty or newly created.
    pub fresh: bool,
    /// Valid records found (including epoch bumps).
    pub records: u64,
    /// Bytes removed from the tail as a torn write.
    pub truncated_bytes: u64,
    /// Epoch in force at the end of the log.
    pub epoch: u64,
}

/// A replayed record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Sequence number (0-based, contiguous across epochs).
    pub seq: u64,
    /// Epoch the record belongs to (for an epoch bump: the new epoch).
    pub epoch: u64,
    /// Kind.
    pub kind: RecordKind,
    /// Payload (empty for epoch bumps).
    pub payload: Vec<u8>,
    /// Chain hash after this record.
    pub hash: Hash,
}

/// Returned by a successful (durable) append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppendReceipt {
    /// Sequence number assigned.
    pub seq: u64,
    /// Epoch of the record.
    pub epoch: u64,
    /// Chain hash after this record.
    pub hash: Hash,
}

/// A point in the chain that can be retained externally (e.g. printed to an
/// operator or stored off-host) and later checked with
/// [`Journal::verify_checkpoint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    /// Number of records covered.
    pub records: u64,
    /// Chain hash after the last covered record (genesis hash if none).
    pub hash: Hash,
}

/// Single-writer, append-only, hash-chained write-ahead log.
#[derive(Debug)]
pub struct Journal<S: Storage> {
    storage: S,
    end: u64,
    next_seq: u64,
    epoch: u64,
    head: Hash,
    poisoned: bool,
    max_payload: usize,
    report: RecoveryReport,
}

impl Journal<FileStorage> {
    /// Open or create the journal at `path` with default options.
    pub fn open(path: &Path) -> Result<Self, JournalError> {
        Self::open_with(path, JournalOptions::default())
    }

    /// Open or create the journal at `path`, taking an exclusive lock and
    /// running recovery.
    pub fn open_with(path: &Path, opts: JournalOptions) -> Result<Self, JournalError> {
        let opened = FileStorage::open(path).map_err(|e| {
            if e.kind() == io::ErrorKind::WouldBlock {
                JournalError::Locked
            } else {
                JournalError::Io(e)
            }
        })?;
        let created = opened.created;
        let j = Self::open_storage(opened.storage, opts)?;
        if j.report.fresh && !created {
            // Existing but empty/torn-at-creation file: the header was just
            // (re)written; make sure the directory entry is durable too.
            crate::storage::fsync_parent_dir(path)?;
        }
        Ok(j.with_fresh(created))
    }
}

impl<S: Storage> Journal<S> {
    fn with_fresh(mut self, created: bool) -> Self {
        self.report.fresh |= created;
        self
    }

    /// Open a journal on arbitrary storage, running recovery:
    ///
    /// * an empty storage (or a torn prefix of the file header) is
    ///   initialised;
    /// * every record's header check, sequence, epoch rule and chain hash is
    ///   verified;
    /// * an incomplete final record (header or body extending past the end)
    ///   or an all-zero tail is truncated as a torn append and the truncation
    ///   is made durable;
    /// * anything else is [`JournalError::Corrupt`] and the journal is not
    ///   opened.
    pub fn open_storage(mut storage: S, opts: JournalOptions) -> Result<Self, JournalError> {
        let max_payload = opts.max_payload.min(HARD_MAX_PAYLOAD);
        let file_len = storage.len()?;
        let mut fresh = false;
        if file_len < FILE_HEADER_LEN {
            let mut buf = vec![0u8; file_len as usize];
            storage.read_exact_at(&mut buf, 0)?;
            let expected = file_header();
            if !expected.starts_with(&buf) && buf.iter().any(|&b| b != 0) {
                return Err(JournalError::BadFileHeader);
            }
            // Crash during creation: nothing was ever acknowledged.
            storage.truncate(0)?;
            storage.write_all_at(&expected, 0)?;
            storage.sync()?;
            fresh = true;
        } else {
            let mut hdr = [0u8; FILE_HEADER_LEN as usize];
            storage.read_exact_at(&mut hdr, 0)?;
            if hdr != file_header() {
                return Err(JournalError::BadFileHeader);
            }
        }

        let file_len = storage.len()?;
        let mut off = FILE_HEADER_LEN;
        let mut seq = 0u64;
        let mut epoch = 0u64;
        let mut prev = genesis_hash();
        let mut truncate_at: Option<u64> = None;

        let corrupt = |offset, expected_seq, kind| JournalError::Corrupt {
            offset,
            expected_seq,
            kind,
        };

        while off < file_len {
            let rem = file_len - off;
            if rem < RECORD_HEADER_LEN as u64 {
                truncate_at = Some(off);
                break;
            }
            let mut hb = [0u8; RECORD_HEADER_LEN];
            storage.read_exact_at(&mut hb, off)?;
            let Some(h) = Header::decode(&hb) else {
                if all_zero_from(&mut storage, off, file_len)? {
                    truncate_at = Some(off);
                    break;
                }
                return Err(corrupt(off, seq, CorruptionKind::HeaderCheck));
            };
            let Some(kind) = RecordKind::from_byte(h.kind_byte) else {
                return Err(corrupt(off, seq, CorruptionKind::InvalidHeaderField));
            };
            if h.reserved != [0; 3] {
                return Err(corrupt(off, seq, CorruptionKind::InvalidHeaderField));
            }
            let len = h.len as usize;
            if len > max_payload {
                return Err(corrupt(off, seq, CorruptionKind::OversizedRecord));
            }
            if h.seq != seq {
                return Err(corrupt(off, seq, CorruptionKind::SequenceGap));
            }
            let epoch_ok = match kind {
                RecordKind::Data => h.epoch == epoch,
                RecordKind::EpochBump => len == 0 && epoch.checked_add(1) == Some(h.epoch),
            };
            if !epoch_ok {
                return Err(corrupt(off, seq, CorruptionKind::EpochViolation));
            }
            let size = record_size(len);
            if size > rem {
                // Header intact, body incomplete: torn append.
                truncate_at = Some(off);
                break;
            }
            let mut body = vec![0u8; len + HASH_LEN];
            storage.read_exact_at(&mut body, off + RECORD_HEADER_LEN as u64)?;
            let (payload, stored) = body.split_at(len);
            let computed = chain_hash(&prev, &hb, payload);
            if computed.as_slice() != stored {
                if opts.tail_policy == TailPolicy::TruncateUnverifiableFinalRecord
                    && off + size == file_len
                {
                    truncate_at = Some(off);
                    break;
                }
                return Err(corrupt(off, seq, CorruptionKind::HashMismatch));
            }
            prev = computed;
            seq = seq.checked_add(1).ok_or(JournalError::Overflow)?;
            epoch = h.epoch;
            off += size;
        }

        let mut truncated_bytes = 0;
        if let Some(t) = truncate_at {
            truncated_bytes = file_len - t;
            storage.truncate(t)?;
            off = t;
        }

        Ok(Journal {
            storage,
            end: off,
            next_seq: seq,
            epoch,
            head: prev,
            poisoned: false,
            max_payload,
            report: RecoveryReport {
                fresh: fresh || seq == 0,
                records: seq,
                truncated_bytes,
                epoch,
            },
        })
    }

    /// What recovery found when this journal was opened.
    pub fn recovery_report(&self) -> RecoveryReport {
        self.report
    }

    /// Current authority epoch (0 for a journal that never recorded a bump).
    pub fn current_epoch(&self) -> u64 {
        self.epoch
    }

    /// Sequence number the next record will receive.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Chain hash after the last durable record.
    pub fn head_hash(&self) -> Hash {
        self.head
    }

    /// Current checkpoint.
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            records: self.next_seq,
            hash: self.head,
        }
    }

    /// Whether an earlier failure poisoned this handle.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Borrow the underlying storage.
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Append an opaque payload in the current epoch. Returns only once the
    /// record has been written and `sync` has succeeded.
    ///
    /// On any write or sync error the journal is poisoned: the record may or
    /// may not survive a crash, so the caller must treat the operation as
    /// *not* committed (release nothing) and reopen the journal, whose
    /// recovery will either drop a torn record or surface a complete one.
    pub fn append(&mut self, payload: &[u8]) -> Result<AppendReceipt, JournalError> {
        if payload.len() > self.max_payload {
            return Err(JournalError::PayloadTooLarge {
                len: payload.len(),
                max: self.max_payload,
            });
        }
        self.append_record(RecordKind::Data, self.epoch, payload)
    }

    /// Durably record an epoch bump and return the new epoch. The broker
    /// calls this on every start, after recovery and before accepting work,
    /// so that grants from earlier epochs are invalid (§11).
    pub fn begin_new_epoch(&mut self) -> Result<u64, JournalError> {
        let new = self.epoch.checked_add(1).ok_or(JournalError::Overflow)?;
        self.append_record(RecordKind::EpochBump, new, &[])?;
        Ok(new)
    }

    fn append_record(
        &mut self,
        kind: RecordKind,
        epoch: u64,
        payload: &[u8],
    ) -> Result<AppendReceipt, JournalError> {
        if self.poisoned {
            return Err(JournalError::Poisoned);
        }
        let len = u32::try_from(payload.len()).map_err(|_| JournalError::Overflow)?;
        let seq = self.next_seq;
        let next_seq = seq.checked_add(1).ok_or(JournalError::Overflow)?;
        let header = Header {
            len,
            kind_byte: kind.to_byte(),
            reserved: [0; 3],
            seq,
            epoch,
        }
        .encode();
        let hash = chain_hash(&self.head, &header, payload);
        let mut rec = Vec::with_capacity(RECORD_HEADER_LEN + payload.len() + HASH_LEN);
        rec.extend_from_slice(&header);
        rec.extend_from_slice(payload);
        rec.extend_from_slice(&hash);

        // Poison first; clear only once durable.
        self.poisoned = true;
        self.storage.write_all_at(&rec, self.end)?;
        self.storage.sync()?;
        self.poisoned = false;

        self.end += rec.len() as u64;
        self.next_seq = next_seq;
        self.epoch = epoch;
        self.head = hash;
        Ok(AppendReceipt { seq, epoch, hash })
    }

    /// Iterate over all durable records from the start, re-verifying the
    /// chain as it goes. Replay is read-only.
    pub fn replay(&mut self) -> Replay<'_, S> {
        let end = self.end;
        let max_payload = self.max_payload;
        Replay {
            storage: &mut self.storage,
            off: FILE_HEADER_LEN,
            end,
            seq: 0,
            prev: genesis_hash(),
            max_payload,
            done: false,
        }
    }

    /// Check that the log still contains the externally retained checkpoint.
    /// Detects truncation or rewriting of history relative to it; it cannot
    /// detect an attacker who also controls the checkpoint.
    pub fn verify_checkpoint(&mut self, cp: Checkpoint) -> Result<bool, JournalError> {
        if cp.records == 0 {
            return Ok(cp.hash == genesis_hash());
        }
        if cp.records > self.next_seq {
            return Ok(false);
        }
        for r in self.replay() {
            let r = r?;
            if r.seq + 1 == cp.records {
                return Ok(r.hash == cp.hash);
            }
        }
        Ok(false)
    }
}

fn all_zero_from<S: Storage>(s: &mut S, from: u64, to: u64) -> io::Result<bool> {
    let mut off = from;
    let mut buf = vec![0u8; 64 * 1024];
    while off < to {
        let n = ((to - off) as usize).min(buf.len());
        s.read_exact_at(&mut buf[..n], off)?;
        if buf[..n].iter().any(|&b| b != 0) {
            return Ok(false);
        }
        off += n as u64;
    }
    Ok(true)
}

/// Replay iterator; see [`Journal::replay`].
#[derive(Debug)]
pub struct Replay<'a, S: Storage> {
    storage: &'a mut S,
    off: u64,
    end: u64,
    seq: u64,
    prev: Hash,
    max_payload: usize,
    done: bool,
}

impl<S: Storage> Replay<'_, S> {
    fn step(&mut self) -> Result<Record, JournalError> {
        let corrupt = |kind| JournalError::Corrupt {
            offset: self.off,
            expected_seq: self.seq,
            kind,
        };
        let mut hb = [0u8; RECORD_HEADER_LEN];
        self.storage.read_exact_at(&mut hb, self.off)?;
        let h = Header::decode(&hb).ok_or_else(|| corrupt(CorruptionKind::HeaderCheck))?;
        let kind = RecordKind::from_byte(h.kind_byte)
            .ok_or_else(|| corrupt(CorruptionKind::InvalidHeaderField))?;
        let len = h.len as usize;
        if len > self.max_payload {
            return Err(corrupt(CorruptionKind::OversizedRecord));
        }
        if h.seq != self.seq {
            return Err(corrupt(CorruptionKind::SequenceGap));
        }
        if self.off + record_size(len) > self.end {
            return Err(corrupt(CorruptionKind::OversizedRecord));
        }
        let mut body = vec![0u8; len + HASH_LEN];
        self.storage
            .read_exact_at(&mut body, self.off + RECORD_HEADER_LEN as u64)?;
        let stored: Hash = body[len..]
            .try_into()
            .map_err(|_| corrupt(CorruptionKind::HashMismatch))?;
        body.truncate(len);
        let computed = chain_hash(&self.prev, &hb, &body);
        if computed != stored {
            return Err(corrupt(CorruptionKind::HashMismatch));
        }
        self.prev = computed;
        self.off += record_size(len);
        self.seq += 1;
        Ok(Record {
            seq: h.seq,
            epoch: h.epoch,
            kind,
            payload: body,
            hash: computed,
        })
    }
}

impl<S: Storage> Iterator for Replay<'_, S> {
    type Item = Result<Record, JournalError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.off >= self.end {
            return None;
        }
        let r = self.step();
        if r.is_err() {
            self.done = true;
        }
        Some(r)
    }
}
