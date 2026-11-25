//! Adversarial tests for the file adapter. The test process plays both the
//! administrator and a hostile host-side process that mutates the trusted
//! root concurrently.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;

use rustix::fs::{CWD, FileType, Mode, RenameFlags, mknodat, renameat_with};
use sha2::{Digest, Sha256};
use tessera_adapter_file::{
    FileAdapter, FileError, FileOperation, FileOutcome, IntegrityViolation, ObjectId, Reservation,
    ReservationId, RootConfig, SetupError, SlotPolicy, TEMP_PREFIX,
};

const OBJ: ObjectId = ObjectId(0xfeed);
const NAME: &str = "secret.txt";
const SECRET: &[u8] = b"top secret registered content\n";

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn rid() -> ReservationId {
    ReservationId(u128::from(NEXT_ID.fetch_add(1, Ordering::Relaxed)) << 64 | 0xabc)
}

struct Fixture {
    _dir: tempfile::TempDir,
    _outside: tempfile::TempDir,
    root: PathBuf,
    outside_file: PathBuf,
    adapter: Arc<FileAdapter>,
}

impl Fixture {
    fn new(policy: SlotPolicy) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join(NAME), SECRET).unwrap();
        let outside_file = outside.path().join("outside.txt");
        fs::write(&outside_file, b"XXXXXXXX outside file XXXXXXXX").unwrap();
        let adapter = FileAdapter::open_root(&root, RootConfig::default()).unwrap();
        adapter.register(OBJ, NAME, policy).unwrap();
        Self {
            _dir: dir,
            _outside: outside,
            root,
            outside_file,
            adapter: Arc::new(adapter),
        }
    }

    fn slot(&self) -> PathBuf {
        self.root.join(NAME)
    }

    fn read(&self, max_bytes: u64) -> Result<FileOutcome, FileError> {
        self.adapter.dispatch(&Reservation {
            id: rid(),
            object: OBJ,
            operation: FileOperation::ReadSnapshot { max_bytes },
        })
    }

    fn replace(&self, bytes: &[u8]) -> Result<FileOutcome, FileError> {
        self.adapter.dispatch(&Reservation {
            id: rid(),
            object: OBJ,
            operation: FileOperation::ReplaceContent {
                bytes: bytes.to_vec(),
            },
        })
    }

    fn root_entries(&self) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(&self.root)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        v.sort();
        v
    }
}

fn snapshot(o: FileOutcome) -> Vec<u8> {
    match o {
        FileOutcome::Snapshot { effect, bytes } => {
            assert_eq!(effect.byte_count, bytes.len() as u64);
            let d: [u8; 32] = Sha256::digest(&bytes).into();
            assert_eq!(effect.sha256, d);
            bytes
        }
        other => panic!("expected snapshot, got {other:?}"),
    }
}

fn integrity(r: Result<FileOutcome, FileError>) -> IntegrityViolation {
    match r {
        Err(FileError::Integrity(v)) => v,
        other => panic!("expected integrity violation, got {other:?}"),
    }
}

fn mkfifo(path: &Path) {
    mknodat(CWD, path, FileType::Fifo, Mode::from_raw_mode(0o600), 0).unwrap();
}

#[test]
fn read_snapshot_returns_bytes_and_effect() {
    let fx = Fixture::new(SlotPolicy::default());
    let out = fx.read(1024).unwrap();
    let effect = out.effect().clone();
    assert_eq!(effect.target, NAME);
    assert_eq!(effect.identity_before, effect.identity_after);
    assert_eq!(snapshot(out), SECRET);
}

#[test]
fn effect_and_debug_never_contain_contents() {
    let fx = Fixture::new(SlotPolicy::default());
    let out = fx.read(1024).unwrap();
    let dbg = format!("{out:?}");
    assert!(!dbg.contains("top secret"), "{dbg}");
    assert!(dbg.contains(&out.effect().sha256_hex()));
    let op = FileOperation::ReplaceContent {
        bytes: b"new secret value".to_vec(),
    };
    assert!(!format!("{op:?}").contains("new secret"));
    let out = fx.replace(b"new secret value").unwrap();
    assert!(!format!("{out:?}").contains("new secret"));
}

#[test]
fn at_most_once_per_reservation_id() {
    let fx = Fixture::new(SlotPolicy::default());
    let res = Reservation {
        id: rid(),
        object: OBJ,
        operation: FileOperation::ReadSnapshot { max_bytes: 1024 },
    };
    assert!(fx.adapter.dispatch(&res).is_ok());
    assert_eq!(
        fx.adapter.dispatch(&res).unwrap_err(),
        FileError::AlreadyDispatched(res.id)
    );

    // A denied attempt still consumes the id.
    let res = Reservation {
        id: rid(),
        object: OBJ,
        operation: FileOperation::ReadSnapshot { max_bytes: 1 },
    };
    assert!(matches!(
        fx.adapter.dispatch(&res),
        Err(FileError::Oversized { .. })
    ));
    let mut retry = res.clone();
    retry.operation = FileOperation::ReadSnapshot { max_bytes: 1024 };
    assert_eq!(
        fx.adapter.dispatch(&retry).unwrap_err(),
        FileError::AlreadyDispatched(res.id)
    );
}

#[test]
fn concurrent_same_reservation_dispatches_once() {
    let fx = Fixture::new(SlotPolicy::default());
    let res = Arc::new(Reservation {
        id: rid(),
        object: OBJ,
        operation: FileOperation::ReplaceContent {
            bytes: b"replaced once".to_vec(),
        },
    });
    let handles: Vec<_> = (0..32)
        .map(|_| {
            let a = Arc::clone(&fx.adapter);
            let r = Arc::clone(&res);
            thread::spawn(move || a.dispatch(&r))
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let ok = results.iter().filter(|r| r.is_ok()).count();
    let dup = results
        .iter()
        .filter(|r| matches!(r, Err(FileError::AlreadyDispatched(_))))
        .count();
    assert_eq!((ok, dup), (1, 31));
}

#[test]
fn unknown_object_denied() {
    let fx = Fixture::new(SlotPolicy::default());
    let r = fx.adapter.dispatch(&Reservation {
        id: rid(),
        object: ObjectId(1),
        operation: FileOperation::ReadSnapshot { max_bytes: 10 },
    });
    assert_eq!(r.unwrap_err(), FileError::UnknownObject(ObjectId(1)));
}

#[test]
fn registration_rejects_paths_and_untrusted_objects() {
    let fx = Fixture::new(SlotPolicy::default());
    for bad in [
        "/etc/passwd",
        "../secret.txt",
        "a/b",
        "",
        ".",
        "..",
        "x\0y",
        ".tessera-tmp-0",
    ] {
        assert_eq!(
            fx.adapter
                .register(ObjectId(7), bad, SlotPolicy::default())
                .unwrap_err(),
            SetupError::InvalidName,
            "{bad:?}"
        );
    }
    std::os::unix::fs::symlink(&fx.outside_file, fx.root.join("link")).unwrap();
    assert_eq!(
        fx.adapter
            .register(ObjectId(7), "link", SlotPolicy::default())
            .unwrap_err(),
        SetupError::Integrity(IntegrityViolation::SymlinkOrEscape)
    );
    fs::write(fx.root.join("a"), b"a").unwrap();
    fs::hard_link(fx.root.join("a"), fx.root.join("b")).unwrap();
    assert_eq!(
        fx.adapter
            .register(ObjectId(7), "a", SlotPolicy::default())
            .unwrap_err(),
        SetupError::Integrity(IntegrityViolation::MultipleLinks { nlink: 2 })
    );
    mkfifo(&fx.root.join("fifo"));
    assert!(matches!(
        fx.adapter
            .register(ObjectId(7), "fifo", SlotPolicy::default()),
        Err(SetupError::Integrity(
            IntegrityViolation::NotRegularFile { .. }
        ))
    ));
    assert_eq!(
        fx.adapter
            .register(ObjectId(8), NAME, SlotPolicy::default())
            .unwrap_err(),
        SetupError::AlreadyRegistered(ObjectId(8))
    );
}

#[test]
fn insecure_root_rejected_at_open_and_dispatch() {
    let fx = Fixture::new(SlotPolicy::default());
    fs::set_permissions(&fx.root, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        integrity(fx.read(1024)),
        IntegrityViolation::RootInsecure { .. }
    ));
    assert!(matches!(
        FileAdapter::open_root(&fx.root, RootConfig::default()),
        Err(SetupError::Integrity(
            IntegrityViolation::RootInsecure { .. }
        ))
    ));
    fs::set_permissions(&fx.root, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        FileAdapter::open_root(
            &fx.root,
            RootConfig {
                expected_owner: Some(rustix::process::geteuid().as_raw() + 1)
            }
        )
        .is_err()
    );
}

#[test]
fn symlink_swap_denied() {
    let fx = Fixture::new(SlotPolicy::default());
    fs::rename(fx.slot(), fx.root.join("moved")).unwrap();
    std::os::unix::fs::symlink(&fx.outside_file, fx.slot()).unwrap();
    assert_eq!(
        integrity(fx.read(1024)),
        IntegrityViolation::SymlinkOrEscape
    );
    // Even a symlink to the registered inode inside the root is refused.
    fs::remove_file(fx.slot()).unwrap();
    std::os::unix::fs::symlink("moved", fx.slot()).unwrap();
    assert_eq!(
        integrity(fx.read(1024)),
        IntegrityViolation::SymlinkOrEscape
    );
    assert_eq!(
        integrity(fx.replace(b"x")),
        IntegrityViolation::SymlinkOrEscape
    );
    // The outside file was never touched.
    assert_eq!(
        fs::read(&fx.outside_file).unwrap(),
        b"XXXXXXXX outside file XXXXXXXX"
    );
    let reports = fx.adapter.reports();
    assert_eq!(reports.len(), 3);
    assert!(reports.iter().all(|r| r.object == OBJ && r.target == NAME));
}

#[test]
fn symlink_swap_race_never_reads_outside_file() {
    let fx = Fixture::new(SlotPolicy::default());
    let stop = Arc::new(AtomicBool::new(false));
    let attacker = {
        let stop = Arc::clone(&stop);
        let slot = fx.slot();
        let hold = fx.root.join("hold");
        let outside = fx.outside_file.clone();
        thread::spawn(move || {
            let mut flips = 0u64;
            while !stop.load(Ordering::Relaxed) {
                fs::rename(&slot, &hold).unwrap();
                std::os::unix::fs::symlink(&outside, &slot).unwrap();
                fs::remove_file(&slot).unwrap();
                fs::rename(&hold, &slot).unwrap();
                flips += 1;
            }
            flips
        })
    };
    let (mut ok, mut denied) = (0, 0);
    for _ in 0..3000 {
        match fx.read(1024) {
            Ok(o) => {
                assert_eq!(snapshot(o), SECRET);
                ok += 1;
            }
            // Renames update the inode ctime, so a flip during a read can
            // also surface as a detected concurrent modification.
            Err(
                FileError::Integrity(
                    IntegrityViolation::SymlinkOrEscape | IntegrityViolation::Missing,
                )
                | FileError::ConcurrentModification,
            ) => denied += 1,
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    stop.store(true, Ordering::Relaxed);
    let flips = attacker.join().unwrap();
    eprintln!("symlink race: ok={ok} denied={denied} flips={flips}");
    assert_eq!(ok + denied, 3000);
}

#[test]
fn rename_swap_denied_and_reported() {
    let fx = Fixture::new(SlotPolicy::default());
    let evil = fx.root.join("evil");
    fs::write(&evil, b"attacker content").unwrap();
    fs::rename(&evil, fx.slot()).unwrap();
    assert!(matches!(
        integrity(fx.read(1024)),
        IntegrityViolation::IdentityMismatch { .. }
    ));
    assert!(matches!(
        integrity(fx.replace(b"new")),
        IntegrityViolation::IdentityMismatch { .. }
    ));
    // Replacement did not clobber the attacker's object nor leave temp files.
    assert_eq!(fs::read(fx.slot()).unwrap(), b"attacker content");
    assert_eq!(fx.root_entries(), vec![NAME.to_owned()]);
    assert_eq!(fx.adapter.reports().len(), 2);
}

#[test]
fn hardlink_aliases_denied() {
    let fx = Fixture::new(SlotPolicy::default());
    // Extra link to the registered inode: possible alias -> deny.
    fs::hard_link(fx.slot(), fx.root.join("alias")).unwrap();
    assert_eq!(
        integrity(fx.read(1024)),
        IntegrityViolation::MultipleLinks { nlink: 2 }
    );
    assert_eq!(
        integrity(fx.replace(b"x")),
        IntegrityViolation::MultipleLinks { nlink: 2 }
    );
    fs::remove_file(fx.root.join("alias")).unwrap();
    assert_eq!(snapshot(fx.read(1024).unwrap()), SECRET);

    // Slot replaced by a hard link to some other file -> identity mismatch.
    fs::write(fx.root.join("other"), b"other").unwrap();
    fs::remove_file(fx.slot()).unwrap();
    fs::hard_link(fx.root.join("other"), fx.slot()).unwrap();
    assert!(matches!(
        integrity(fx.read(1024)),
        IntegrityViolation::IdentityMismatch { .. }
    ));
}

#[test]
fn file_replaced_by_directory_or_fifo_denied() {
    let fx = Fixture::new(SlotPolicy::default());
    fs::remove_file(fx.slot()).unwrap();
    fs::create_dir(fx.slot()).unwrap();
    assert!(matches!(
        integrity(fx.read(1024)),
        IntegrityViolation::NotRegularFile { .. }
    ));
    fs::remove_dir(fx.slot()).unwrap();
    mkfifo(&fx.slot());
    // Must not block on the FIFO open.
    assert!(matches!(
        integrity(fx.read(1024)),
        IntegrityViolation::NotRegularFile { .. }
    ));
    assert!(matches!(
        integrity(fx.replace(b"x")),
        IntegrityViolation::NotRegularFile { .. }
    ));
    fs::remove_file(fx.slot()).unwrap();
    assert_eq!(integrity(fx.read(1024)), IntegrityViolation::Missing);
}

#[test]
fn oversized_read_is_denied_not_truncated() {
    let fx = Fixture::new(SlotPolicy {
        max_read_bytes: 20,
        max_write_bytes: 1024,
    });
    let len = SECRET.len() as u64;
    // Request limit below size.
    assert_eq!(
        fx.read(5).unwrap_err(),
        FileError::Oversized {
            limit: 5,
            observed: Some(len)
        }
    );
    // Request above policy, policy below size.
    assert_eq!(
        fx.read(10_000).unwrap_err(),
        FileError::Oversized {
            limit: 20,
            observed: Some(len)
        }
    );
    let fx = Fixture::new(SlotPolicy {
        max_read_bytes: len,
        max_write_bytes: 1024,
    });
    assert_eq!(snapshot(fx.read(len).unwrap()), SECRET);
}

#[test]
fn oversized_replace_denied() {
    let fx = Fixture::new(SlotPolicy {
        max_read_bytes: 1024,
        max_write_bytes: 8,
    });
    assert_eq!(
        fx.replace(b"123456789").unwrap_err(),
        FileError::Oversized {
            limit: 8,
            observed: Some(9)
        }
    );
    assert_eq!(fs::read(fx.slot()).unwrap(), SECRET);
    assert_eq!(fx.root_entries(), vec![NAME.to_owned()]);
}

#[test]
fn replace_is_atomic_slot_replacement() {
    let fx = Fixture::new(SlotPolicy::default());
    fs::set_permissions(fx.slot(), fs::Permissions::from_mode(0o640)).unwrap();
    let before = fx.adapter.slot_identity(OBJ).unwrap();
    let out = fx.replace(b"version two").unwrap();
    let effect = out.effect().clone();
    assert_eq!(effect.identity_before, before);
    assert_ne!(effect.identity_after.ino, before.ino);
    assert_eq!(effect.byte_count, 11);
    let d: [u8; 32] = Sha256::digest(b"version two").into();
    assert_eq!(effect.sha256, d);
    assert_eq!(fx.adapter.slot_identity(OBJ), Some(effect.identity_after));
    assert_eq!(fs::read(fx.slot()).unwrap(), b"version two");
    assert_eq!(
        fs::metadata(fx.slot()).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(fx.root_entries(), vec![NAME.to_owned()]);
    assert_eq!(snapshot(fx.read(1024).unwrap()), b"version two");

    // Restart: a fresh adapter re-registers with the journaled identity.
    let fresh = FileAdapter::open_root(&fx.root, RootConfig::default()).unwrap();
    assert!(
        fresh
            .register_with_identity(OBJ, NAME, SlotPolicy::default(), before)
            .is_err()
    );
    fresh
        .register_with_identity(OBJ, NAME, SlotPolicy::default(), effect.identity_after)
        .unwrap();
}

#[test]
fn stale_temp_file_blocks_only_its_reservation() {
    let fx = Fixture::new(SlotPolicy::default());
    let id = rid();
    let tmp = fx.root.join(format!("{TEMP_PREFIX}{:032x}", id.0));
    std::os::unix::fs::symlink(&fx.outside_file, &tmp).unwrap();
    let r = fx.adapter.dispatch(&Reservation {
        id,
        object: OBJ,
        operation: FileOperation::ReplaceContent {
            bytes: b"zzz".to_vec(),
        },
    });
    assert!(r.is_err(), "{r:?}");
    assert_eq!(
        fs::read(&fx.outside_file).unwrap(),
        b"XXXXXXXX outside file XXXXXXXX"
    );
    assert_eq!(fs::read(fx.slot()).unwrap(), SECRET);
}

/// A hostile host process rewrites the registered inode in place while
/// snapshots are taken, and also swaps a foreign file into the slot. Every
/// successful snapshot must come from the registered object (never the
/// foreign file), stay within bounds and match its effect digest.
#[test]
fn concurrent_malicious_writer_during_reads() {
    let fx = Fixture::new(SlotPolicy {
        max_read_bytes: 64 * 1024,
        max_write_bytes: 64 * 1024,
    });
    fs::write(fx.slot(), vec![b'A'; 4096]).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let stop = Arc::clone(&stop);
        // The writer holds a descriptor to the registered inode (it opened
        // it before the swapper started) and rewrites it in place.
        let file = fs::OpenOptions::new().write(true).open(fx.slot()).unwrap();
        thread::spawn(move || {
            use std::os::unix::fs::FileExt;
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let content = if n.is_multiple_of(2) {
                    vec![b'B'; 8192]
                } else {
                    vec![b'A'; 4096]
                };
                file.set_len(0).unwrap();
                file.write_all_at(&content, 0).unwrap();
                n += 1;
            }
            n
        })
    };
    let swapper = {
        let stop = Arc::clone(&stop);
        let slot = fx.slot();
        let decoy = fx.root.join("decoy");
        fs::write(&decoy, vec![b'X'; 4096]).unwrap();
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                renameat_with(CWD, &slot, CWD, &decoy, RenameFlags::EXCHANGE).unwrap();
                thread::yield_now();
                renameat_with(CWD, &slot, CWD, &decoy, RenameFlags::EXCHANGE).unwrap();
                thread::yield_now();
            }
        })
    };
    let (mut ok, mut torn, mut modified, mut mismatch) = (0, 0, 0, 0);
    for _ in 0..3000 {
        match fx.read(64 * 1024) {
            Ok(o) => {
                let bytes = snapshot(o);
                assert!(bytes.len() <= 8192);
                assert!(
                    bytes.iter().all(|b| *b == b'A' || *b == b'B'),
                    "snapshot contains bytes from a foreign object"
                );
                // The writer's own (non-atomic) truncate-then-write protocol
                // has a legitimately observable empty state.
                let uniform = bytes.is_empty()
                    || (bytes.len() == 4096 && bytes.iter().all(|b| *b == b'A'))
                    || (bytes.len() == 8192 && bytes.iter().all(|b| *b == b'B'));
                if !uniform {
                    if torn < 3 {
                        let a = bytes.iter().filter(|b| **b == b'A').count();
                        eprintln!("non-uniform snapshot: len={} A-bytes={a}", bytes.len());
                    }
                    torn += 1;
                }
                ok += 1;
            }
            Err(FileError::ConcurrentModification) => modified += 1,
            Err(FileError::Integrity(IntegrityViolation::IdentityMismatch { .. })) => mismatch += 1,
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    stop.store(true, Ordering::Relaxed);
    let writes = writer.join().unwrap();
    swapper.join().unwrap();
    eprintln!(
        "concurrent writer: ok={ok} torn={torn} modified={modified} mismatch={mismatch} writes={writes}"
    );
    // Binding is guaranteed (asserted above). Snapshot atomicity against a
    // host process rewriting the registered inode *in place* through its own
    // descriptor is NOT guaranteed: detection relies on size/mtime/ctime,
    // which use coarse clock ticks, so `torn` (non-uniform snapshots, e.g. a
    // partially applied pwrite) may be non-zero. This is a documented
    // residual risk; adapter-issued replacements are atomic.
    assert!(ok + modified + mismatch == 3000);
}

/// A hostile process keeps exchanging the slot with a decoy while
/// replacements run. Replacement must only ever displace the registered
/// object: the decoy's content survives and no temp files remain.
#[test]
fn replace_under_rename_exchange_race() {
    let fx = Fixture::new(SlotPolicy::default());
    let decoy = fx.root.join("decoy");
    fs::write(&decoy, b"DECOY").unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let swapper = {
        let stop = Arc::clone(&stop);
        let slot = fx.slot();
        let decoy = decoy.clone();
        thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                renameat_with(CWD, &slot, CWD, &decoy, RenameFlags::EXCHANGE).unwrap();
                n += 1;
            }
            n
        })
    };
    let (mut ok, mut denied, mut reverted, mut stuck) = (0, 0, 0, 0);
    let mut last = SECRET.to_vec();
    for i in 0..500u32 {
        let content = format!("generation {i}").into_bytes();
        match fx.replace(&content) {
            Ok(_) => {
                ok += 1;
                last = content;
            }
            Err(FileError::Integrity(IntegrityViolation::ReplaceTargetChanged { reverted: r })) => {
                if r {
                    reverted += 1;
                } else {
                    // Revert could not be verified; the adapter left the
                    // objects in place. Later dispatches deny.
                    stuck += 1;
                }
            }
            Err(FileError::Integrity(_)) => denied += 1,
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    stop.store(true, Ordering::Relaxed);
    let swaps = swapper.join().unwrap();
    eprintln!(
        "replace race: ok={ok} denied={denied} reverted={reverted} stuck={stuck} swaps={swaps}"
    );
    // Invariant: the inode the registry names carries exactly the content of
    // the last successful replacement, and the decoy object was never
    // written to or unlinked by the adapter.
    use std::os::unix::fs::MetadataExt;
    let registered = fx.adapter.slot_identity(OBJ).unwrap();
    let mut found_registered = false;
    let mut found_decoy = false;
    for entry in fs::read_dir(&fx.root).unwrap() {
        let path = entry.unwrap().path();
        let meta = fs::symlink_metadata(&path).unwrap();
        let content = fs::read(&path).unwrap();
        if meta.ino() == registered.ino && meta.dev() == registered.dev {
            assert_eq!(content, last);
            found_registered = true;
        }
        if content == b"DECOY" {
            found_decoy = true;
        }
    }
    assert!(found_registered && found_decoy);
    if stuck == 0 {
        assert_eq!(fx.root_entries(), vec!["decoy".to_owned(), NAME.to_owned()]);
    }
}
