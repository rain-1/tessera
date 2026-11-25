//! Storage abstraction and the real file backend.
//!
//! The journal talks to storage only through [`Storage`], so tests can
//! substitute [`crate::testing::MemStorage`] to inject write/sync failures and
//! simulate crashes that lose or tear un-synced data.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::Path;

use rustix::fs::{FlockOperation, flock};

/// Byte storage underneath a journal.
pub trait Storage {
    /// Current length in bytes.
    fn len(&mut self) -> io::Result<u64>;
    /// Whether the storage is empty.
    fn is_empty(&mut self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }
    /// Fill `buf` from `offset`; error if not enough bytes.
    fn read_exact_at(&mut self, buf: &mut [u8], offset: u64) -> io::Result<()>;
    /// Write all of `buf` at `offset`. Not durable until [`Storage::sync`].
    fn write_all_at(&mut self, buf: &[u8], offset: u64) -> io::Result<()>;
    /// Durability barrier: on success, all prior writes (including the
    /// resulting file size) survive a crash, subject to the documented
    /// storage assumptions. After a failure the storage state is unknown and
    /// the journal must not retry.
    fn sync(&mut self) -> io::Result<()>;
    /// Truncate to `len` and make the truncation durable.
    fn truncate(&mut self, len: u64) -> io::Result<()>;
}

/// File-backed storage holding an exclusive advisory `flock`.
#[derive(Debug)]
pub struct FileStorage {
    file: File,
}

/// Outcome of [`FileStorage::open`].
#[derive(Debug)]
pub struct Opened {
    /// The storage.
    pub storage: FileStorage,
    /// Whether the file was newly created.
    pub created: bool,
}

impl FileStorage {
    /// Open (creating if absent) `path` for reading and writing and take an
    /// exclusive non-blocking `flock`. Fails with `WouldBlock` if another
    /// writer holds the lock. If the file was created, the parent directory
    /// is fsynced so the directory entry is durable.
    pub fn open(path: &Path) -> io::Result<Opened> {
        let (file, created) = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(f) => (f, true),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                (OpenOptions::new().read(true).write(true).open(path)?, false)
            }
            Err(e) => return Err(e),
        };
        flock(&file, FlockOperation::NonBlockingLockExclusive)?;
        if created {
            file.sync_all()?;
            fsync_parent_dir(path)?;
        }
        Ok(Opened {
            storage: FileStorage { file },
            created,
        })
    }
}

/// fsync the directory containing `path`, making a create/rename durable.
pub fn fsync_parent_dir(path: &Path) -> io::Result<()> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    File::open(parent)?.sync_all()
}

impl Storage for FileStorage {
    fn len(&mut self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    fn read_exact_at(&mut self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        FileExt::read_exact_at(&self.file, buf, offset)
    }

    fn write_all_at(&mut self, buf: &[u8], offset: u64) -> io::Result<()> {
        FileExt::write_all_at(&self.file, buf, offset)
    }

    fn sync(&mut self) -> io::Result<()> {
        // fdatasync: flushes data and the metadata needed to read it back,
        // which includes the file size after an append.
        self.file.sync_data()
    }

    fn truncate(&mut self, len: u64) -> io::Result<()> {
        self.file.set_len(len)?;
        self.file.sync_all()
    }
}
