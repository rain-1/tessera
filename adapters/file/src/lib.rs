//! Tessera trusted file adapter (specification §9.3).
//!
//! The adapter mediates access to a small set of *protected files* that an
//! administrator registers inside one trusted root directory. Untrusted agents
//! never see paths or descriptors: a grant names an [`ObjectId`], and the
//! broker hands the adapter a [`Reservation`] after it has durably committed
//! the corresponding CONSUME transition (§5.2).
//!
//! # Trust and resolution model
//!
//! * The trusted root directory is opened once by the administrator
//!   ([`FileAdapter::open_root`]) and held as a directory descriptor for the
//!   lifetime of the adapter. It must be owned by the expected owner and must
//!   not be group- or world-writable; this is re-checked on every dispatch.
//! * Every registered object is a *logical slot*: a single relative name
//!   component inside the root plus the identity (device, inode, owner,
//!   filesystem type) of the regular file currently occupying that slot.
//! * Every open uses `openat2(2)` relative to the root descriptor with
//!   `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS |
//!   RESOLVE_NO_XDEV` and `O_NOFOLLOW`, followed by `fstat`/`fstatfs` on the
//!   opened descriptor. The descriptor must be a regular file with exactly one
//!   link whose identity equals the registry entry. Any mismatch denies the
//!   operation and is recorded as an [`IntegrityReport`].
//! * Agent-supplied paths do not exist in this API. Slot names are supplied
//!   only by the administrator and must be a single normal path component.
//!
//! # Operations
//!
//! * [`FileOperation::ReadSnapshot`] returns at most `max_bytes` (and at most
//!   the slot's policy limit) as an owned byte vector, never a descriptor or
//!   mapping. **Oversized policy: deny, never truncate.** If the file is larger
//!   than the effective limit the read is denied, so a caller never mistakes a
//!   prefix for the whole object.
//! * [`FileOperation::ReplaceContent`] writes the new content to a temporary
//!   file in the same trusted directory, `fsync`s it, atomically exchanges it
//!   with the slot using `renameat2(RENAME_EXCHANGE)`, verifies that the object
//!   it displaced is exactly the registered one (swapping back and denying if
//!   not), unlinks the displaced object and `fsync`s the directory.
//!
//! # Logical slot semantics for replacement
//!
//! Replacement changes the inode bound to the slot. The slot (root directory +
//! name) is the stable object; after a successful replacement the registry's
//! identity for the slot is updated to the new inode, and the new identity is
//! reported in the [`FileEffect`]. The broker records both identities before
//! the exchange through [`FileAdapter::dispatch_with_replace_intent`]. It can
//! use [`FileAdapter::recover_replacement`] if the outcome is unavailable.
//! Descriptors to the previous inode held by other processes keep observing
//! the previous content; the previous inode is unlinked.
//!
//! # At-most-once dispatch
//!
//! The adapter keeps an in-memory set of reservation ids it has accepted. The
//! first call carrying a given id claims it, whatever the outcome (including
//! denial); every later call with that id fails with
//! [`FileError::AlreadyDispatched`] without touching the filesystem. This set
//! is *not* durable: durable de-duplication across adapter or broker restarts
//! is the broker/journal's responsibility (§5.2, §11) — after a crash,
//! unresolved reservations must be abandoned or reported as unknown and never
//! replayed into a fresh adapter instance.
//!
//! # Residual risks
//!
//! * The trusted root must not be writable by hostile processes. The adapter
//!   checks owner and mode, but a process running as the owning uid can still
//!   rename entries concurrently. Such races are detected (identity checks,
//!   verified `RENAME_EXCHANGE`) and denied/reported, never resolved in the
//!   attacker's favour for reads; a replacement whose revert cannot be
//!   verified leaves objects in place (`reverted: false`) for an operator.
//! * Snapshot consistency against a process rewriting the registered inode
//!   *in place* through a descriptor it already holds is best effort: it is
//!   detected via size/mtime/ctime, which use coarse clock ticks. The snapshot
//!   is always bytes of the registered inode, but may reflect a writer's
//!   intermediate state. Adapter replacements never write in place.
//! * Crash between temp creation and exchange leaves a `.tessera-tmp-<id>`
//!   file; it is never registered or read, and only blocks that reservation.
//!
//! # Audit
//!
//! Effects are described by [`FileEffect`]: reservation, object, slot name,
//! operation kind, byte count, SHA-256 digest and identities. File contents are
//! never placed in effect records, errors, reports or `Debug` output.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};

use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, RenameFlags, ResolveFlags, Stat, fchmod, fstat, fstatfs,
    fsync, openat2, renameat_with, statat, unlinkat,
};
use rustix::io::Errno;
use sha2::{Digest, Sha256};

/// Prefix reserved for adapter temporary files inside the trusted root.
pub const TEMP_PREFIX: &str = ".tessera-tmp-";

/// Maximum number of integrity reports retained in memory.
const MAX_REPORTS: usize = 1024;

/// Opaque reservation identifier issued by the broker.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReservationId(pub u128);

impl fmt::Debug for ReservationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ReservationId({:032x})", self.0)
    }
}

/// Adapter-managed stable handle for a registered protected file slot.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectId(pub u128);

impl fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectId({:032x})", self.0)
    }
}

/// The exact operation a reservation authorizes.
#[derive(Clone, PartialEq, Eq)]
pub enum FileOperation {
    /// Return one bounded snapshot of the slot's content as bytes.
    ReadSnapshot {
        /// Upper bound requested by the grant; the slot policy may be lower.
        max_bytes: u64,
    },
    /// Atomically replace the slot's content with exactly these bytes.
    ReplaceContent {
        /// New content. Never logged.
        bytes: Vec<u8>,
    },
}

impl fmt::Debug for FileOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadSnapshot { max_bytes } => f
                .debug_struct("ReadSnapshot")
                .field("max_bytes", max_bytes)
                .finish(),
            Self::ReplaceContent { bytes } => f
                .debug_struct("ReplaceContent")
                .field("len", &bytes.len())
                .finish_non_exhaustive(),
        }
    }
}

/// A committed reservation: one authorization to attempt exactly `operation`
/// on `object`. Produced by the broker only after the reservation is durable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reservation {
    /// Broker-issued reservation id; at most one dispatch per id.
    pub id: ReservationId,
    /// Target slot.
    pub object: ObjectId,
    /// Exact operation.
    pub operation: FileOperation,
}

/// Observed identity of the regular file bound to a slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    /// Device number.
    pub dev: u64,
    /// Inode number.
    pub ino: u64,
    /// Owning uid.
    pub uid: u32,
    /// Filesystem magic (`statfs.f_type`).
    pub fs_type: i64,
}

/// Per-slot limits set by the administrator at registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotPolicy {
    /// Largest snapshot ever returned for this slot.
    pub max_read_bytes: u64,
    /// Largest replacement ever accepted for this slot.
    pub max_write_bytes: u64,
}

impl Default for SlotPolicy {
    fn default() -> Self {
        Self {
            max_read_bytes: 1 << 20,
            max_write_bytes: 1 << 20,
        }
    }
}

/// Configuration for opening the trusted root.
#[derive(Clone, Copy, Debug, Default)]
pub struct RootConfig {
    /// Uid that must own the root directory and every protected file.
    /// Defaults to the adapter process's effective uid.
    pub expected_owner: Option<u32>,
}

/// Kind of operation recorded in an effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileOpKind {
    /// Snapshot read.
    ReadSnapshot,
    /// Atomic replacement.
    ReplaceContent,
}

/// Audit record of one completed file effect. Contains no file content.
#[derive(Clone, PartialEq, Eq)]
pub struct FileEffect {
    /// Reservation that authorized the effect.
    pub reservation: ReservationId,
    /// Target object.
    pub object: ObjectId,
    /// Slot name relative to the trusted root.
    pub target: String,
    /// Operation performed.
    pub kind: FileOpKind,
    /// Number of bytes read or written.
    pub byte_count: u64,
    /// SHA-256 of the bytes read or written.
    pub sha256: [u8; 32],
    /// Identity bound to the slot before the operation.
    pub identity_before: FileIdentity,
    /// Identity bound to the slot after the operation (differs for replace).
    pub identity_after: FileIdentity,
}

impl FileEffect {
    /// Lower-case hex rendering of the digest.
    pub fn sha256_hex(&self) -> String {
        hex(&self.sha256)
    }
}

impl fmt::Debug for FileEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileEffect")
            .field("reservation", &self.reservation)
            .field("object", &self.object)
            .field("target", &self.target)
            .field("kind", &self.kind)
            .field("byte_count", &self.byte_count)
            .field("sha256", &self.sha256_hex())
            .field("identity_before", &self.identity_before)
            .field("identity_after", &self.identity_after)
            .finish()
    }
}

/// Successful result of a dispatch.
pub enum FileOutcome {
    /// Snapshot bytes and their audit record.
    Snapshot {
        /// Audit record.
        effect: FileEffect,
        /// Snapshot content (returned to the caller, never logged).
        bytes: Vec<u8>,
    },
    /// Replacement audit record.
    Replaced {
        /// Audit record.
        effect: FileEffect,
    },
}

impl FileOutcome {
    /// The effect record of either variant.
    pub fn effect(&self) -> &FileEffect {
        match self {
            Self::Snapshot { effect, .. } | Self::Replaced { effect } => effect,
        }
    }
}

impl fmt::Debug for FileOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Snapshot { effect, bytes } => f
                .debug_struct("Snapshot")
                .field("effect", effect)
                .field("len", &bytes.len())
                .finish_non_exhaustive(),
            Self::Replaced { effect } => {
                f.debug_struct("Replaced").field("effect", effect).finish()
            }
        }
    }
}

/// Integrity violations: the filesystem no longer matches the registry or
/// trust assumptions. Each one denies the operation and is reported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntegrityViolation {
    /// The slot name resolved through a symlink or tried to escape the root
    /// (`ELOOP`/`EXDEV` from `openat2`).
    SymlinkOrEscape,
    /// Nothing is bound to the slot name.
    Missing,
    /// The slot holds something other than a regular file.
    NotRegularFile {
        /// Observed file type.
        observed: String,
    },
    /// The slot holds a different file than the registered one.
    IdentityMismatch {
        /// Registered identity.
        expected: FileIdentity,
        /// Observed identity.
        observed: FileIdentity,
    },
    /// The protected file has additional hard links (possible alias).
    MultipleLinks {
        /// Observed link count.
        nlink: u64,
    },
    /// The trusted root directory lost its required ownership/mode or was
    /// removed.
    RootInsecure {
        /// Reason.
        reason: String,
    },
    /// The object displaced by the atomic exchange was not the registered
    /// one; the exchange was reverted.
    ReplaceTargetChanged {
        /// Whether reverting the exchange succeeded.
        reverted: bool,
    },
}

/// A recorded integrity incident.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegrityReport {
    /// Reservation whose dispatch detected it.
    pub reservation: ReservationId,
    /// Affected object.
    pub object: ObjectId,
    /// Slot name.
    pub target: String,
    /// What was detected.
    pub violation: IntegrityViolation,
}

/// Dispatch failure. Every failure consumes the reservation id.
///
/// Apart from [`IntegrityViolation::ReplaceTargetChanged`] with
/// `reverted: false` and [`FileError::Io`] at stage `"post-exchange"`, a
/// failure means no change was made to the protected slot.
#[derive(Debug, PartialEq, Eq)]
pub enum FileError {
    /// This reservation id was already dispatched (or attempted).
    AlreadyDispatched(ReservationId),
    /// No slot is registered for the object.
    UnknownObject(ObjectId),
    /// Read or write exceeds the effective byte limit.
    Oversized {
        /// Effective limit.
        limit: u64,
        /// Observed or requested size, when known.
        observed: Option<u64>,
    },
    /// The file changed while being read; no snapshot is returned.
    ConcurrentModification,
    /// The caller refused to authorize the prepared replacement.
    ReplacementNotRecorded,
    /// Integrity violation (also recorded via [`FileAdapter::reports`]).
    Integrity(IntegrityViolation),
    /// Unexpected system call failure.
    Io {
        /// Step that failed.
        stage: &'static str,
        /// Error number.
        errno: Errno,
    },
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for FileError {}

/// Administrative (setup/registration) failure.
#[derive(Debug, PartialEq, Eq)]
pub enum SetupError {
    /// Slot name is not a single normal path component.
    InvalidName,
    /// Object id already registered.
    AlreadyRegistered(ObjectId),
    /// Root or file failed a trust check.
    Integrity(IntegrityViolation),
    /// System call failure.
    Io {
        /// Step that failed.
        stage: &'static str,
        /// Error number.
        errno: Errno,
    },
}

impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for SetupError {}

struct Slot {
    name: String,
    policy: SlotPolicy,
    /// Current identity; the mutex also serializes all dispatches on the slot.
    identity: Mutex<FileIdentity>,
}

/// The trusted file adapter. See the crate documentation.
pub struct FileAdapter {
    root: OwnedFd,
    root_dev: u64,
    root_ino: u64,
    owner: u32,
    slots: RwLock<HashMap<ObjectId, Arc<Slot>>>,
    dispatched: Mutex<HashSet<ReservationId>>,
    reports: Mutex<VecDeque<IntegrityReport>>,
}

impl fmt::Debug for FileAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileAdapter")
            .field("owner", &self.owner)
            .finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while holding one of these locks cannot leave a partially
    // updated invariant: each guarded value is replaced wholesale.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Filesystems on which protected files may never live.
const PSEUDO_FS: &[i64] = &[
    0x9fa0,      // proc
    0x6265_6572, // sysfs
    0x1cd1,      // devpts
    0x6462_6720, // debugfs
    0x7363_6673, // securityfs
    0x0027_e0eb, // cgroup
    0x6367_7270, // cgroup2
    0xcafe_4a11, // bpf
    0x7472_6163, // tracefs
    0x6265_6570, // configfs
    0xde5e_81e4, // efivarfs
];

fn resolve_flags() -> ResolveFlags {
    ResolveFlags::BENEATH
        | ResolveFlags::NO_SYMLINKS
        | ResolveFlags::NO_MAGICLINKS
        | ResolveFlags::NO_XDEV
}

#[allow(clippy::unnecessary_cast)]
fn stat_fields(st: &Stat) -> (u64, u64, u32, u32, u64, i64) {
    (
        st.st_dev as u64,
        st.st_ino as u64,
        st.st_uid as u32,
        st.st_mode as u32,
        st.st_nlink as u64,
        st.st_size as i64,
    )
}

#[allow(clippy::unnecessary_cast)]
fn change_marker(st: &Stat) -> (i64, i64, i64, i64, i64, u64) {
    (
        st.st_size as i64,
        st.st_mtime as i64,
        st.st_mtime_nsec as i64,
        st.st_ctime as i64,
        st.st_ctime_nsec as i64,
        st.st_nlink as u64,
    )
}

fn identity_of(st: &Stat, fs_type: i64) -> FileIdentity {
    let (dev, ino, uid, _, _, _) = stat_fields(st);
    FileIdentity {
        dev,
        ino,
        uid,
        fs_type,
    }
}

#[allow(clippy::unnecessary_cast)]
fn fs_type_of(fd: &OwnedFd) -> Result<i64, Errno> {
    Ok(fstatfs(fd)?.f_type as i64)
}

fn type_name(mode: u32) -> String {
    format!("{:?}", FileType::from_raw_mode(mode as _))
}

fn validate_name(name: &str) -> Result<(), SetupError> {
    let ok = !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\0')
        && !name.starts_with(TEMP_PREFIX);
    if ok {
        Ok(())
    } else {
        Err(SetupError::InvalidName)
    }
}

/// Open `name` beneath `root`; map resolution refusals to integrity errors.
fn open_beneath(root: &OwnedFd, name: &str, flags: OFlags, mode: Mode) -> Result<OwnedFd, OpenErr> {
    openat2(
        root,
        name,
        flags | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NOCTTY,
        mode,
        resolve_flags(),
    )
    .map_err(|e| match e {
        Errno::LOOP | Errno::XDEV => OpenErr::Integrity(IntegrityViolation::SymlinkOrEscape),
        Errno::NOENT => OpenErr::Integrity(IntegrityViolation::Missing),
        other => OpenErr::Io(other),
    })
}

enum OpenErr {
    Integrity(IntegrityViolation),
    Io(Errno),
}

/// Reason a slot descriptor failed verification.
enum VerifyErr {
    Integrity(IntegrityViolation),
    Io(&'static str, Errno),
}

impl From<VerifyErr> for FileError {
    fn from(e: VerifyErr) -> Self {
        match e {
            VerifyErr::Integrity(v) => FileError::Integrity(v),
            VerifyErr::Io(stage, errno) => FileError::Io { stage, errno },
        }
    }
}

impl From<VerifyErr> for SetupError {
    fn from(e: VerifyErr) -> Self {
        match e {
            VerifyErr::Integrity(v) => SetupError::Integrity(v),
            VerifyErr::Io(stage, errno) => SetupError::Io { stage, errno },
        }
    }
}

/// Open the slot read-only and verify it is a single-link regular file owned
/// by `owner`, matching `expected` when given. Returns descriptor, stat and
/// observed identity.
fn open_verified(
    root: &OwnedFd,
    name: &str,
    owner: u32,
    expected: Option<&FileIdentity>,
) -> Result<(OwnedFd, Stat, FileIdentity), VerifyErr> {
    // O_NONBLOCK: opening a FIFO planted at the slot must not block.
    let fd = open_beneath(root, name, OFlags::RDONLY | OFlags::NONBLOCK, Mode::empty()).map_err(
        |e| match e {
            OpenErr::Integrity(v) => VerifyErr::Integrity(v),
            OpenErr::Io(errno) => VerifyErr::Io("open", errno),
        },
    )?;
    let st = fstat(&fd).map_err(|e| VerifyErr::Io("fstat", e))?;
    let fs_type = fs_type_of(&fd).map_err(|e| VerifyErr::Io("fstatfs", e))?;
    let (_, _, uid, mode, nlink, _) = stat_fields(&st);
    if FileType::from_raw_mode(mode as _) != FileType::RegularFile {
        return Err(VerifyErr::Integrity(IntegrityViolation::NotRegularFile {
            observed: type_name(mode),
        }));
    }
    let observed = identity_of(&st, fs_type);
    if let Some(expected) = expected {
        if *expected != observed {
            return Err(VerifyErr::Integrity(IntegrityViolation::IdentityMismatch {
                expected: *expected,
                observed,
            }));
        }
    } else if uid != owner || PSEUDO_FS.contains(&fs_type) {
        return Err(VerifyErr::Integrity(IntegrityViolation::IdentityMismatch {
            expected: FileIdentity {
                uid: owner,
                ..observed
            },
            observed,
        }));
    }
    if nlink != 1 {
        return Err(VerifyErr::Integrity(IntegrityViolation::MultipleLinks {
            nlink,
        }));
    }
    Ok((fd, st, observed))
}

impl FileAdapter {
    /// Open the trusted root directory (administrator-supplied path; agents
    /// never supply paths). The directory must be owned by the expected owner,
    /// not be group/world-writable and not live on a pseudo filesystem.
    pub fn open_root(path: &Path, config: RootConfig) -> Result<Self, SetupError> {
        let owner = config
            .expected_owner
            .unwrap_or_else(|| rustix::process::geteuid().as_raw());
        let root = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| SetupError::Io {
            stage: "open-root",
            errno,
        })?;
        let st = fstat(&root).map_err(|errno| SetupError::Io {
            stage: "fstat-root",
            errno,
        })?;
        let (root_dev, root_ino, _, _, _, _) = stat_fields(&st);
        let adapter = Self {
            root,
            root_dev,
            root_ino,
            owner,
            slots: RwLock::new(HashMap::new()),
            dispatched: Mutex::new(HashSet::new()),
            reports: Mutex::new(VecDeque::new()),
        };
        adapter.check_root().map_err(SetupError::from)?;
        Ok(adapter)
    }

    fn check_root(&self) -> Result<(), VerifyErr> {
        let st = fstat(&self.root).map_err(|e| VerifyErr::Io("fstat-root", e))?;
        let fs_type = fs_type_of(&self.root).map_err(|e| VerifyErr::Io("fstatfs-root", e))?;
        let (dev, ino, uid, mode, nlink, _) = stat_fields(&st);
        let reason = if dev != self.root_dev || ino != self.root_ino {
            Some("root identity changed".to_owned())
        } else if uid != self.owner {
            Some(format!("root owned by uid {uid}, expected {}", self.owner))
        } else if mode & 0o022 != 0 {
            Some(format!(
                "root mode {:o} is group/world-writable",
                mode & 0o7777
            ))
        } else if nlink == 0 {
            Some("root directory was removed".to_owned())
        } else if PSEUDO_FS.contains(&fs_type) {
            Some(format!("root on pseudo filesystem {fs_type:#x}"))
        } else {
            None
        };
        match reason {
            Some(reason) => Err(VerifyErr::Integrity(IntegrityViolation::RootInsecure {
                reason,
            })),
            None => Ok(()),
        }
    }

    /// Register `name` (a single path component inside the root) as `object`
    /// and record the identity of the regular file currently there.
    pub fn register(
        &self,
        object: ObjectId,
        name: &str,
        policy: SlotPolicy,
    ) -> Result<FileIdentity, SetupError> {
        self.register_inner(object, name, policy, None)
    }

    /// Re-register a slot whose identity was journaled earlier (e.g. after a
    /// restart, using `identity_after` of the last effect). Fails unless the
    /// file currently in the slot has exactly that identity.
    pub fn register_with_identity(
        &self,
        object: ObjectId,
        name: &str,
        policy: SlotPolicy,
        expected: FileIdentity,
    ) -> Result<FileIdentity, SetupError> {
        self.register_inner(object, name, policy, Some(expected))
    }

    /// Restore a slot with an interrupted replacement. If the new inode is
    /// in the slot and the displaced name still exists, it must hold the
    /// expected old inode. Foreign objects are left in place for the operator.
    pub fn recover_replacement(
        &self,
        object: ObjectId,
        name: &str,
        policy: SlotPolicy,
        reservation: ReservationId,
        before: FileIdentity,
        after: FileIdentity,
    ) -> Result<FileIdentity, SetupError> {
        match self.register_with_identity(object, name, policy, before) {
            Err(SetupError::Integrity(IntegrityViolation::IdentityMismatch {
                observed, ..
            })) if observed == after => {}
            result => return result,
        }
        let tmp_name = format!("{TEMP_PREFIX}{:032x}", reservation.0);
        match statat(&self.root, tmp_name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => {
                open_verified(&self.root, &tmp_name, self.owner, Some(&before))?;
            }
            Err(Errno::NOENT) => {} // The exchange verified and removed the displaced entry.
            Err(errno) => {
                return Err(SetupError::Io {
                    stage: "stat-displaced",
                    errno,
                });
            }
        }
        self.register_with_identity(object, name, policy, after)
    }

    fn register_inner(
        &self,
        object: ObjectId,
        name: &str,
        policy: SlotPolicy,
        expected: Option<FileIdentity>,
    ) -> Result<FileIdentity, SetupError> {
        validate_name(name)?;
        self.check_root()?;
        let (_, _, identity) = open_verified(&self.root, name, self.owner, expected.as_ref())?;
        if identity.uid != self.owner {
            return Err(SetupError::Integrity(
                IntegrityViolation::IdentityMismatch {
                    expected: FileIdentity {
                        uid: self.owner,
                        ..identity
                    },
                    observed: identity,
                },
            ));
        }
        let mut slots = self.slots.write().unwrap_or_else(PoisonError::into_inner);
        if slots.contains_key(&object) || slots.values().any(|s| s.name == name) {
            return Err(SetupError::AlreadyRegistered(object));
        }
        slots.insert(
            object,
            Arc::new(Slot {
                name: name.to_owned(),
                policy,
                identity: Mutex::new(identity),
            }),
        );
        Ok(identity)
    }

    /// Remove a slot from the registry. In-flight dispatches finish.
    pub fn unregister(&self, object: ObjectId) -> bool {
        self.slots
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&object)
            .is_some()
    }

    /// Current registered identity of a slot.
    pub fn slot_identity(&self, object: ObjectId) -> Option<FileIdentity> {
        let slot = self.slot(object)?;
        let id = *lock(&slot.identity);
        Some(id)
    }

    /// Integrity reports recorded so far (bounded; oldest dropped first).
    pub fn reports(&self) -> Vec<IntegrityReport> {
        lock(&self.reports).iter().cloned().collect()
    }

    /// Whether the given reservation id has been claimed by this instance.
    pub fn was_dispatched(&self, id: ReservationId) -> bool {
        lock(&self.dispatched).contains(&id)
    }

    fn slot(&self, object: ObjectId) -> Option<Arc<Slot>> {
        self.slots
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&object)
            .cloned()
    }

    /// Execute at most one dispatch for `reservation`. See crate docs.
    pub fn dispatch(&self, reservation: &Reservation) -> Result<FileOutcome, FileError> {
        self.dispatch_with_replace_intent(reservation, |_, _| true)
    }

    /// As `dispatch`, but calls `record` with the old and new identities after
    /// syncing the prepared file and before exchanging it. The slot stays
    /// locked across the callback. A false result leaves the slot intact.
    pub fn dispatch_with_replace_intent(
        &self,
        reservation: &Reservation,
        record: impl FnOnce(FileIdentity, FileIdentity) -> bool,
    ) -> Result<FileOutcome, FileError> {
        // Claim first: any outcome, including denial, consumes the id.
        if !lock(&self.dispatched).insert(reservation.id) {
            return Err(FileError::AlreadyDispatched(reservation.id));
        }
        let slot = self
            .slot(reservation.object)
            .ok_or(FileError::UnknownObject(reservation.object))?;
        let mut identity = lock(&slot.identity);
        let result = self.check_root().map_err(FileError::from).and_then(|()| {
            match &reservation.operation {
                FileOperation::ReadSnapshot { max_bytes } => {
                    self.read_snapshot(reservation, &slot, &identity, *max_bytes)
                }
                FileOperation::ReplaceContent { bytes } => {
                    self.replace(reservation, &slot, &mut identity, bytes, record)
                }
            }
        });
        if let Err(FileError::Integrity(violation)) = &result {
            let mut reports = lock(&self.reports);
            if reports.len() == MAX_REPORTS {
                reports.pop_front();
            }
            reports.push_back(IntegrityReport {
                reservation: reservation.id,
                object: reservation.object,
                target: slot.name.clone(),
                violation: violation.clone(),
            });
        }
        result
    }

    fn read_snapshot(
        &self,
        reservation: &Reservation,
        slot: &Slot,
        identity: &FileIdentity,
        max_bytes: u64,
    ) -> Result<FileOutcome, FileError> {
        let limit = max_bytes.min(slot.policy.max_read_bytes);
        let (fd, before, _) = open_verified(&self.root, &slot.name, self.owner, Some(identity))?;
        let (_, _, _, _, _, size) = stat_fields(&before);
        let size = u64::try_from(size).unwrap_or(u64::MAX);
        if size > limit {
            return Err(FileError::Oversized {
                limit,
                observed: Some(size),
            });
        }
        let mut file = File::from(fd);
        let capacity = usize::try_from(size).unwrap_or(0);
        let mut bytes = Vec::with_capacity(capacity);
        (&mut file)
            .take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|e| FileError::Io {
                stage: "read",
                errno: Errno::from_io_error(&e).unwrap_or(Errno::IO),
            })?;
        let read_len = bytes.len() as u64;
        if read_len > limit {
            return Err(FileError::Oversized {
                limit,
                observed: None,
            });
        }
        let after = fstat(&file).map_err(|errno| FileError::Io {
            stage: "fstat-after-read",
            errno,
        })?;
        if change_marker(&before) != change_marker(&after) || read_len != size {
            return Err(FileError::ConcurrentModification);
        }
        let sha256: [u8; 32] = Sha256::digest(&bytes).into();
        Ok(FileOutcome::Snapshot {
            effect: FileEffect {
                reservation: reservation.id,
                object: reservation.object,
                target: slot.name.clone(),
                kind: FileOpKind::ReadSnapshot,
                byte_count: read_len,
                sha256,
                identity_before: *identity,
                identity_after: *identity,
            },
            bytes,
        })
    }

    fn replace(
        &self,
        reservation: &Reservation,
        slot: &Slot,
        identity: &mut FileIdentity,
        bytes: &[u8],
        record: impl FnOnce(FileIdentity, FileIdentity) -> bool,
    ) -> Result<FileOutcome, FileError> {
        let limit = slot.policy.max_write_bytes;
        let len = bytes.len() as u64;
        if len > limit {
            return Err(FileError::Oversized {
                limit,
                observed: Some(len),
            });
        }
        let expected = *identity;
        // Verify the current occupant before doing any work.
        let (_, current, _) = open_verified(&self.root, &slot.name, self.owner, Some(&expected))?;
        let (_, _, _, cur_mode, _, _) = stat_fields(&current);
        let mode = Mode::from_raw_mode((cur_mode & 0o755) as _);

        let tmp_name = format!("{TEMP_PREFIX}{:032x}", reservation.id.0);
        let tmp = open_beneath(
            &self.root,
            &tmp_name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|e| match e {
            OpenErr::Integrity(v) => FileError::Integrity(v),
            OpenErr::Io(errno) => FileError::Io {
                stage: "create-temp",
                errno,
            },
        })?;
        let cleanup = |stage: &'static str, errno: Errno| {
            let _ = unlinkat(&self.root, tmp_name.as_str(), AtFlags::empty());
            FileError::Io { stage, errno }
        };
        let mut file = File::from(tmp);
        if let Err(e) = file.write_all(bytes) {
            return Err(cleanup(
                "write-temp",
                Errno::from_io_error(&e).unwrap_or(Errno::IO),
            ));
        }
        fchmod(&file, mode).map_err(|e| cleanup("fchmod-temp", e))?;
        fsync(&file).map_err(|e| cleanup("fsync-temp", e))?;
        let tst = fstat(&file).map_err(|e| cleanup("fstat-temp", e))?;
        let tfs = fstatfs(&file).map_err(|e| cleanup("fstatfs-temp", e))?;
        #[allow(clippy::unnecessary_cast)]
        let new_identity = identity_of(&tst, tfs.f_type as i64);
        if !record(expected, new_identity) {
            let _ = unlinkat(&self.root, tmp_name.as_str(), AtFlags::empty());
            return Err(FileError::ReplacementNotRecorded);
        }

        // Atomic exchange: the slot now holds the new file; tmp_name holds the
        // displaced object, which we verify is the registered one.
        renameat_with(
            &self.root,
            tmp_name.as_str(),
            &self.root,
            slot.name.as_str(),
            RenameFlags::EXCHANGE,
        )
        .map_err(|e| cleanup("exchange", e))?;

        let displaced = statat(&self.root, tmp_name.as_str(), AtFlags::SYMLINK_NOFOLLOW);
        let displaced_ok = match &displaced {
            Ok(st) => {
                let (dev, ino, uid, m, nlink, _) = stat_fields(st);
                FileType::from_raw_mode(m as _) == FileType::RegularFile
                    && dev == expected.dev
                    && ino == expected.ino
                    && uid == expected.uid
                    && nlink == 1
            }
            Err(_) => false,
        };
        if !displaced_ok {
            // Someone swapped the slot between verification and exchange.
            // Put their object back and discard ours.
            // Only remove the temp name if it verifiably holds our own new
            // inode again; otherwise leave everything in place for the
            // administrator rather than risk unlinking a foreign object.
            let exchanged = renameat_with(
                &self.root,
                tmp_name.as_str(),
                &self.root,
                slot.name.as_str(),
                RenameFlags::EXCHANGE,
            )
            .is_ok();
            let ours_at_tmp = statat(&self.root, tmp_name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                .map(|st| {
                    let (dev, ino, ..) = stat_fields(&st);
                    dev == new_identity.dev && ino == new_identity.ino
                })
                .unwrap_or(false);
            let reverted = exchanged && ours_at_tmp;
            if reverted {
                let _ = unlinkat(&self.root, tmp_name.as_str(), AtFlags::empty());
            }
            let _ = fsync(&self.root);
            return Err(FileError::Integrity(
                IntegrityViolation::ReplaceTargetChanged { reverted },
            ));
        }
        // The slot now durably refers to the new inode once the directory is
        // synced; record it immediately so later dispatches verify against it.
        *identity = new_identity;
        unlinkat(&self.root, tmp_name.as_str(), AtFlags::empty()).map_err(|errno| {
            FileError::Io {
                stage: "post-exchange",
                errno,
            }
        })?;
        fsync(&self.root).map_err(|errno| FileError::Io {
            stage: "post-exchange",
            errno,
        })?;
        let sha256: [u8; 32] = Sha256::digest(bytes).into();
        Ok(FileOutcome::Replaced {
            effect: FileEffect {
                reservation: reservation.id,
                object: reservation.object,
                target: slot.name.clone(),
                kind: FileOpKind::ReplaceContent,
                byte_count: len,
                sha256,
                identity_before: expected,
                identity_after: new_identity,
            },
        })
    }
}
