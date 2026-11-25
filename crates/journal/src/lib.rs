//! # tessera-journal — durable single-writer write-ahead log
//!
//! An append-only log of opaque payloads with contiguous sequence numbers,
//! authority epochs, and a SHA-256 hash chain (format in [`mod@format`]). The
//! broker uses it to commit ledger transitions, request-id bindings,
//! spent approval nonces and dispatch reservations *before* releasing any
//! grant, reservation or result (§11).
//!
//! ## API in brief
//!
//! * [`Journal::open`] / [`Journal::open_storage`] — open with recovery:
//!   verify the chain, truncate a torn final record, refuse on any other
//!   corruption ([`JournalError::Corrupt`]).
//! * [`Journal::append`] — write + `fdatasync`; returns only once durable.
//! * [`Journal::replay`] — read-only iterator re-verifying the chain.
//! * [`Journal::current_epoch`] / [`Journal::begin_new_epoch`] — the broker
//!   bumps the epoch on every start (§11: fail closed across restart; live
//!   grants from earlier epochs are invalid).
//! * [`recovery`] — reservation (`Reserved`/`Dispatched`/`Completed`/`Unknown`)
//!   and spent-nonce helper records plus a fold that rebuilds the spent-nonce
//!   and request-id sets and reports unresolved reservations as `Unknown`
//!   without ever replaying them.
//! * [`testing::MemStorage`] — fault-injection storage (partial writes, sync
//!   failures, crash images).
//!
//! ## Torn tail vs. corruption
//!
//! Recovery truncates exactly these tails, which are what an interrupted,
//! never-acknowledged append can leave behind:
//!
//! * fewer bytes than a record header;
//! * an intact record header (its own 8-byte check passes) whose body
//!   extends past end of file;
//! * a region from the last valid record to end of file that is entirely
//!   zero (size extended, data never written).
//!
//! Everything else — header check failure, bad kind, sequence gap, epoch
//! rule violation, chain hash mismatch — is reported as corruption and the
//! journal refuses to open, even for the final record, because a flipped bit
//! in an *acknowledged* final record must not be silently discarded (that
//! could, e.g., forget a spent nonce). An operator can opt into
//! [`TailPolicy::TruncateUnverifiableFinalRecord`] after investigation.
//! Truncation during recovery is itself made durable before the journal is
//! returned.
//!
//! ## Durability assumptions (stated honestly)
//!
//! "Durable" here means: `append` returned `Ok` only after `fdatasync(2)` on
//! the journal file returned success. Whether that survives power loss
//! depends on things this crate cannot verify:
//!
//! 1. **The storage stack honours flushes.** The kernel, filesystem, any
//!    virtualisation layer and the device must not acknowledge `fdatasync`
//!    before data reaches non-volatile media (no write cache without power
//!    loss protection that ignores FLUSH/FUA; no `nobarrier`; no
//!    `eatmydata`-style shims). We do not detect lying hardware.
//! 2. **fsync failure is fatal.** After a failed `write` or `fdatasync` the
//!    journal is poisoned ([`JournalError::Poisoned`]) and never retries
//!    fsync: on Linux a failed fsync may clear the error and drop dirty pages,
//!    so a retry can falsely report success. The caller must treat the
//!    operation as not committed, and reopen; recovery may then find the
//!    record either absent or present in full. Callers must therefore
//!    tolerate a non-acknowledged record appearing after restart (the
//!    reservation helpers do: such a reservation is reported `Unknown`).
//! 3. **Creation.** A newly created journal file is `fsync`ed and its parent
//!    directory is `fsync`ed before use. Renames/moves of the journal by an
//!    operator are outside this crate's guarantees.
//! 4. **Crash shape.** We assume a crash leaves the file as its last durable
//!    state followed by *some* bytes from un-synced appends: a prefix of them,
//!    zeros, or (on filesystems that reorder data writes within a size
//!    extension) a mix. Prefix and zero tails are recovered automatically; a
//!    mixed tail is refused under the default strict policy.
//! 5. **Single writer.** An exclusive `flock(2)` is held for the lifetime of
//!    a [`storage::FileStorage`]. It is advisory: it protects against a second
//!    broker instance, not against a hostile administrator, and may not work
//!    on some network filesystems. Do not place the journal on NFS.
//! 6. **Integrity, not authenticity.** The hash chain detects accidental
//!    corruption and in-place tampering *relative to an externally retained
//!    [`Checkpoint`]*. Anyone who can write the file can rewrite the entire
//!    history and recompute the chain; truncation of whole records at the
//!    end is undetectable without a checkpoint. Host storage rollback and a
//!    hostile administrator are outside the MVP threat model (§11).
//! 7. **No secret content.** Payloads are stored in clear; callers must not
//!    journal secrets or file/HTTP contents (§11).

pub mod format;
pub mod journal;
pub mod recovery;
pub mod storage;
pub mod testing;

pub use format::{Hash, RecordKind};
pub use journal::{
    AppendReceipt, Checkpoint, CorruptionKind, Journal, JournalError, JournalOptions, Record,
    RecoveryReport, Replay, TailPolicy,
};
pub use recovery::{
    RecoverError, RecoveredState, RecoveryError, RecoveryEvent, RecoveryState, RequestKey,
    ReservationInfo, ReservationStatus, recover,
};
pub use storage::{FileStorage, Storage};
