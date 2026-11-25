//! Fault-injection storage for tests (also usable by the broker's own crash
//! tests).
//!
//! [`MemStorage`] models a file as two byte vectors: what the process sees
//! (`visible`) and what has been made durable by a successful `sync`
//! (`durable`). [`MemStorage::crash`] produces the storage a restarted
//! process would see under a chosen [`CrashMode`]. Handles are cheap clones
//! sharing state, so a test can keep one while the journal owns another.

use std::io;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::storage::Storage;

#[derive(Debug, Default)]
struct State {
    visible: Vec<u8>,
    durable: Vec<u8>,
    /// Fail every write once this many more bytes have been written; the
    /// partial write still lands in `visible`.
    write_budget: Option<usize>,
    fail_sync: bool,
    syncs: u64,
}

/// In-memory storage with injectable faults.
#[derive(Debug, Clone, Default)]
pub struct MemStorage {
    st: Arc<Mutex<State>>,
}

/// What survives a simulated crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashMode {
    /// Only synced data survives.
    LoseUnsynced,
    /// Synced data plus the first `n` un-synced bytes survive (a torn
    /// append, as on filesystems that only extend the size once data is
    /// written).
    KeepUnsyncedPrefix(usize),
    /// Synced data plus `n` zero bytes: the size was extended but the data
    /// blocks were not written (unwritten extents read as zeros).
    ZeroFilledTail(usize),
    /// Everything visible survives (as if the crash happened just after a
    /// successful sync).
    KeepAll,
}

impl MemStorage {
    /// Empty storage.
    pub fn new() -> Self {
        Self::default()
    }

    /// Storage whose visible and durable contents are `bytes`.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let s = Self::default();
        {
            let mut st = s.lock();
            st.durable = bytes.clone();
            st.visible = bytes;
        }
        s
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        match self.st.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// Currently visible bytes.
    pub fn visible(&self) -> Vec<u8> {
        self.lock().visible.clone()
    }

    /// Durable bytes.
    pub fn durable(&self) -> Vec<u8> {
        self.lock().durable.clone()
    }

    /// Number of successful syncs.
    pub fn sync_count(&self) -> u64 {
        self.lock().syncs
    }

    /// Make subsequent writes fail after `n` more bytes (partial write).
    pub fn fail_writes_after(&self, n: usize) {
        self.lock().write_budget = Some(n);
    }

    /// Make subsequent syncs fail (data is written but not made durable).
    pub fn fail_syncs(&self, fail: bool) {
        self.lock().fail_sync = fail;
    }

    /// Storage as seen by a process restarting after a crash now.
    pub fn crash(&self, mode: CrashMode) -> MemStorage {
        let st = self.lock();
        let mut bytes = st.durable.clone();
        let unsynced: &[u8] =
            if st.visible.len() > st.durable.len() && st.visible.starts_with(&st.durable) {
                &st.visible[st.durable.len()..]
            } else {
                &[]
            };
        match mode {
            CrashMode::LoseUnsynced => {}
            CrashMode::KeepUnsyncedPrefix(n) => {
                bytes.extend_from_slice(&unsynced[..n.min(unsynced.len())])
            }
            CrashMode::ZeroFilledTail(n) => bytes.resize(bytes.len() + n, 0),
            CrashMode::KeepAll => bytes = st.visible.clone(),
        }
        MemStorage::from_bytes(bytes)
    }
}

impl Storage for MemStorage {
    fn len(&mut self) -> io::Result<u64> {
        Ok(self.lock().visible.len() as u64)
    }

    fn read_exact_at(&mut self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        let st = self.lock();
        let off =
            usize::try_from(offset).map_err(|_| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        let end = off
            .checked_add(buf.len())
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        if end > st.visible.len() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.copy_from_slice(&st.visible[off..end]);
        Ok(())
    }

    fn write_all_at(&mut self, buf: &[u8], offset: u64) -> io::Result<()> {
        let mut st = self.lock();
        let off = usize::try_from(offset).map_err(|_| io::Error::other("offset"))?;
        let (n, fail) = match st.write_budget {
            Some(b) if b < buf.len() => (b, true),
            Some(b) => {
                st.write_budget = Some(b - buf.len());
                (buf.len(), false)
            }
            None => (buf.len(), false),
        };
        if fail {
            st.write_budget = Some(0);
        }
        if st.visible.len() < off + n {
            st.visible.resize(off + n, 0);
        }
        st.visible[off..off + n].copy_from_slice(&buf[..n]);
        if fail {
            return Err(io::Error::other("injected write failure"));
        }
        Ok(())
    }

    fn sync(&mut self) -> io::Result<()> {
        let mut st = self.lock();
        if st.fail_sync {
            return Err(io::Error::other("injected fsync failure"));
        }
        st.durable = st.visible.clone();
        st.syncs += 1;
        Ok(())
    }

    fn truncate(&mut self, len: u64) -> io::Result<()> {
        let mut st = self.lock();
        let len = usize::try_from(len).map_err(|_| io::Error::other("len"))?;
        st.visible.truncate(len);
        if st.fail_sync {
            return Err(io::Error::other("injected fsync failure"));
        }
        st.durable = st.visible.clone();
        st.syncs += 1;
        Ok(())
    }
}
