//! Journal behaviour and fault injection.

use proptest::prelude::*;
use tessera_journal::format::{FILE_HEADER_LEN, HASH_LEN, RECORD_HEADER_LEN};
use tessera_journal::testing::{CrashMode, MemStorage};
use tessera_journal::*;

fn payloads() -> Vec<Vec<u8>> {
    vec![
        b"alpha".to_vec(),
        Vec::new(),
        vec![0xAB; 70],
        b"delta-record".to_vec(),
        vec![0; 3],
    ]
}

/// Build a log: epoch bump, a few data records, another bump, one more.
/// Returns (bytes, end offset of each record, the records' payloads/kinds).
type BuiltLog = (Vec<u8>, Vec<u64>, Vec<(RecordKind, Vec<u8>)>);

fn build_log() -> BuiltLog {
    let mem = MemStorage::new();
    let mut j = Journal::open_storage(mem.clone(), JournalOptions::default()).unwrap();
    let mut ends = Vec::new();
    let mut recs = Vec::new();
    let mut off = FILE_HEADER_LEN;
    let mut push = |kind: RecordKind, p: Vec<u8>, ends: &mut Vec<u64>| {
        off += (RECORD_HEADER_LEN + p.len() + HASH_LEN) as u64;
        ends.push(off);
        recs.push((kind, p));
    };
    j.begin_new_epoch().unwrap();
    push(RecordKind::EpochBump, vec![], &mut ends);
    let ps = payloads();
    for p in &ps[..3] {
        j.append(p).unwrap();
        push(RecordKind::Data, p.clone(), &mut ends);
    }
    j.begin_new_epoch().unwrap();
    push(RecordKind::EpochBump, vec![], &mut ends);
    for p in &ps[3..] {
        j.append(p).unwrap();
        push(RecordKind::Data, p.clone(), &mut ends);
    }
    let bytes = mem.durable();
    assert_eq!(bytes.len() as u64, *ends.last().unwrap());
    (bytes, ends, recs)
}

fn replay_all<S: Storage>(j: &mut Journal<S>) -> Vec<Record> {
    j.replay().collect::<Result<Vec<_>, _>>().unwrap()
}

#[test]
fn file_roundtrip_epochs_and_lock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wal");
    {
        let mut j = Journal::open(&path).unwrap();
        assert!(j.recovery_report().fresh);
        assert_eq!(j.current_epoch(), 0);
        assert_eq!(j.begin_new_epoch().unwrap(), 1);
        let r = j.append(b"one").unwrap();
        assert_eq!((r.seq, r.epoch), (1, 1));
        j.append(b"two").unwrap();
        // Second writer refused while the first holds the lock.
        assert!(matches!(Journal::open(&path), Err(JournalError::Locked)));
    }
    let mut j = Journal::open(&path).unwrap();
    let rep = j.recovery_report();
    assert!(!rep.fresh);
    assert_eq!((rep.records, rep.truncated_bytes, rep.epoch), (3, 0, 1));
    assert_eq!(j.begin_new_epoch().unwrap(), 2);
    let r = j.append(b"three").unwrap();
    assert_eq!((r.seq, r.epoch), (4, 2));
    let recs = replay_all(&mut j);
    let summary: Vec<_> = recs
        .iter()
        .map(|r| (r.seq, r.epoch, r.kind, r.payload.clone()))
        .collect();
    assert_eq!(
        summary,
        vec![
            (0, 1, RecordKind::EpochBump, vec![]),
            (1, 1, RecordKind::Data, b"one".to_vec()),
            (2, 1, RecordKind::Data, b"two".to_vec()),
            (3, 2, RecordKind::EpochBump, vec![]),
            (4, 2, RecordKind::Data, b"three".to_vec()),
        ]
    );
    assert_eq!(recs.last().unwrap().hash, j.head_hash());
}

#[test]
fn file_torn_tail_recovered_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wal");
    {
        let mut j = Journal::open(&path).unwrap();
        j.append(b"keep").unwrap();
        j.append(b"torn-record").unwrap();
    }
    let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    let len = f.metadata().unwrap().len();
    f.set_len(len - 5).unwrap();
    drop(f);
    let mut j = Journal::open(&path).unwrap();
    assert_eq!(j.recovery_report().records, 1);
    assert_eq!(
        j.recovery_report().truncated_bytes,
        (RECORD_HEADER_LEN + 11 + HASH_LEN - 5) as u64
    );
    assert_eq!(replay_all(&mut j)[0].payload, b"keep");
    j.append(b"after").unwrap();
    drop(j);
    let mut j = Journal::open(&path).unwrap();
    assert_eq!(replay_all(&mut j).len(), 2);
}

/// Truncating the log at every byte offset recovers exactly the records that
/// were completely written, and the recovered journal is usable.
#[test]
fn truncated_tail_at_every_offset() {
    let (bytes, ends, recs) = build_log();
    for cut in 0..=bytes.len() {
        let mem = MemStorage::from_bytes(bytes[..cut].to_vec());
        let mut j = Journal::open_storage(mem.clone(), JournalOptions::default())
            .unwrap_or_else(|e| panic!("cut {cut}: {e}"));
        let complete = ends.iter().filter(|&&e| e <= cut as u64).count();
        let rep = j.recovery_report();
        assert_eq!(rep.records as usize, complete, "cut {cut}");
        let boundary = if complete == 0 {
            FILE_HEADER_LEN
        } else {
            ends[complete - 1]
        };
        assert_eq!(
            mem.durable().len() as u64,
            boundary.max(FILE_HEADER_LEN),
            "cut {cut}"
        );
        let got = replay_all(&mut j);
        assert_eq!(got.len(), complete);
        for (g, (k, p)) in got.iter().zip(&recs) {
            assert_eq!((&g.kind, &g.payload), (k, p));
        }
        let expected_epoch = recs[..complete]
            .iter()
            .filter(|(k, _)| *k == RecordKind::EpochBump)
            .count() as u64;
        assert_eq!(j.current_epoch(), expected_epoch, "cut {cut}");
        // Usable after recovery.
        j.append(b"post-recovery").unwrap();
        let mut j2 = Journal::open_storage(
            mem.crash(CrashMode::LoseUnsynced),
            JournalOptions::default(),
        )
        .unwrap();
        assert_eq!(j2.recovery_report().records as usize, complete + 1);
        assert_eq!(
            replay_all(&mut j2).last().unwrap().payload,
            b"post-recovery"
        );
    }
}

/// Any single bit flip anywhere in the file is refused (never silently
/// accepted, never silently truncated) under the strict policy.
#[test]
fn every_single_bit_flip_is_refused() {
    let (bytes, _, _) = build_log();
    for i in 0..bytes.len() {
        for bit in 0..8 {
            let mut b = bytes.clone();
            b[i] ^= 1 << bit;
            let r = Journal::open_storage(MemStorage::from_bytes(b), JournalOptions::default());
            match r {
                Err(JournalError::Corrupt { .. }) => assert!(i as u64 >= FILE_HEADER_LEN),
                Err(JournalError::BadFileHeader) => assert!((i as u64) < FILE_HEADER_LEN),
                other => panic!("flip byte {i} bit {bit}: expected refusal, got {other:?}"),
            }
        }
    }
}

#[test]
fn mid_log_flip_refused_even_with_lenient_policy() {
    let (bytes, ends, _) = build_log();
    let lenient = JournalOptions {
        tail_policy: TailPolicy::TruncateUnverifiableFinalRecord,
        ..Default::default()
    };
    let last_start = ends[ends.len() - 2] as usize;
    for i in FILE_HEADER_LEN as usize..bytes.len() {
        let mut b = bytes.clone();
        b[i] ^= 0x10;
        let r = Journal::open_storage(MemStorage::from_bytes(b), lenient);
        let in_final_body = i >= last_start + RECORD_HEADER_LEN;
        if in_final_body {
            let j = r.unwrap_or_else(|e| panic!("byte {i}: {e}"));
            assert_eq!(j.recovery_report().records as usize, ends.len() - 1);
        } else {
            assert!(matches!(r, Err(JournalError::Corrupt { .. })), "byte {i}");
        }
    }
}

#[test]
fn reports_corruption_location() {
    let (mut bytes, ends, _) = build_log();
    // Corrupt payload of record #2 (data "alpha" at seq 1 ends at ends[1]).
    let at = ends[1] as usize + RECORD_HEADER_LEN; // first payload byte of seq 2
    bytes[at] ^= 1;
    match Journal::open_storage(MemStorage::from_bytes(bytes), JournalOptions::default()) {
        Err(JournalError::Corrupt {
            offset,
            expected_seq,
            kind,
        }) => {
            assert_eq!(offset, ends[1]);
            assert_eq!(expected_seq, 2);
            assert_eq!(kind, CorruptionKind::HashMismatch);
        }
        other => panic!("{other:?}"),
    }
}

/// Simulated crash between write and fsync: the append is never
/// acknowledged; after restart the record is either absent or whole.
#[test]
fn crash_between_write_and_fsync() {
    let mem = MemStorage::new();
    let mut j = Journal::open_storage(mem.clone(), JournalOptions::default()).unwrap();
    j.begin_new_epoch().unwrap();
    j.append(b"acked-1").unwrap();
    j.append(b"acked-2").unwrap();
    mem.fail_syncs(true);
    let err = j.append(b"never-acked").unwrap_err();
    assert!(matches!(err, JournalError::Io(_)));
    assert!(j.is_poisoned());
    assert!(matches!(j.append(b"x"), Err(JournalError::Poisoned)));
    assert!(matches!(j.begin_new_epoch(), Err(JournalError::Poisoned)));
    let rec_len = RECORD_HEADER_LEN + b"never-acked".len() + HASH_LEN;

    let reopen = |m: MemStorage| {
        let mut j = Journal::open_storage(m, JournalOptions::default()).unwrap();
        let ps: Vec<Vec<u8>> = replay_all(&mut j).into_iter().map(|r| r.payload).collect();
        ps
    };
    let acked = vec![vec![], b"acked-1".to_vec(), b"acked-2".to_vec()];
    assert_eq!(reopen(mem.crash(CrashMode::LoseUnsynced)), acked);
    for k in 0..rec_len {
        assert_eq!(
            reopen(mem.crash(CrashMode::KeepUnsyncedPrefix(k))),
            acked,
            "prefix {k}"
        );
        assert_eq!(
            reopen(mem.crash(CrashMode::ZeroFilledTail(k))),
            acked,
            "zeros {k}"
        );
    }
    // Written fully though fsync failed: present after restart (allowed; the
    // caller never released anything for it).
    let mut with = acked.clone();
    with.push(b"never-acked".to_vec());
    assert_eq!(
        reopen(mem.crash(CrashMode::KeepUnsyncedPrefix(rec_len))),
        with
    );
    assert_eq!(reopen(mem.crash(CrashMode::KeepAll)), with);
}

#[test]
fn partial_write_failure_poisons_and_recovers() {
    let mem = MemStorage::new();
    let mut j = Journal::open_storage(mem.clone(), JournalOptions::default()).unwrap();
    j.append(b"ok").unwrap();
    let syncs = mem.sync_count();
    mem.fail_writes_after(20);
    assert!(j.append(&[9u8; 100]).is_err());
    assert_eq!(mem.sync_count(), syncs, "no sync after failed write");
    assert!(matches!(j.append(b"later"), Err(JournalError::Poisoned)));
    // Even if the partial bytes reach disk, recovery truncates them.
    let mut j =
        Journal::open_storage(mem.crash(CrashMode::KeepAll), JournalOptions::default()).unwrap();
    assert_eq!(j.recovery_report().records, 1);
    assert_eq!(j.recovery_report().truncated_bytes, 20);
    assert_eq!(replay_all(&mut j)[0].payload, b"ok");
}

#[test]
fn reordered_tail_strict_vs_lenient() {
    let mem = MemStorage::new();
    let mut j = Journal::open_storage(mem.clone(), JournalOptions::default()).unwrap();
    j.append(b"first").unwrap();
    j.append(&[0x55; 64]).unwrap();
    // Simulate data pages written out of order: final record has full
    // length and intact header, but stale bytes in its body.
    let mut b = mem.durable();
    let n = b.len();
    for x in &mut b[n - HASH_LEN - 40..n - HASH_LEN - 8] {
        *x = 0;
    }
    assert!(matches!(
        Journal::open_storage(MemStorage::from_bytes(b.clone()), JournalOptions::default()),
        Err(JournalError::Corrupt {
            kind: CorruptionKind::HashMismatch,
            ..
        })
    ));
    let lenient = JournalOptions {
        tail_policy: TailPolicy::TruncateUnverifiableFinalRecord,
        ..Default::default()
    };
    let j = Journal::open_storage(MemStorage::from_bytes(b), lenient).unwrap();
    assert_eq!(j.recovery_report().records, 1);
}

#[test]
fn torn_file_header_reinitialised_but_garbage_refused() {
    let full = MemStorage::new();
    drop(Journal::open_storage(full.clone(), JournalOptions::default()).unwrap());
    let hdr = full.durable();
    for cut in 0..hdr.len() {
        let j = Journal::open_storage(
            MemStorage::from_bytes(hdr[..cut].to_vec()),
            JournalOptions::default(),
        )
        .unwrap();
        assert!(j.recovery_report().fresh);
    }
    assert!(matches!(
        Journal::open_storage(
            MemStorage::from_bytes(b"NOTAJRNL".to_vec()),
            JournalOptions::default()
        ),
        Err(JournalError::BadFileHeader)
    ));
    let mut wrong_version = hdr.clone();
    wrong_version[8] = 2;
    assert!(matches!(
        Journal::open_storage(
            MemStorage::from_bytes(wrong_version),
            JournalOptions::default()
        ),
        Err(JournalError::BadFileHeader)
    ));
}

#[test]
fn oversized_payload_rejected_without_poisoning() {
    let opts = JournalOptions {
        max_payload: 16,
        ..Default::default()
    };
    let mut j = Journal::open_storage(MemStorage::new(), opts).unwrap();
    assert!(matches!(
        j.append(&[0; 17]),
        Err(JournalError::PayloadTooLarge { len: 17, max: 16 })
    ));
    assert!(!j.is_poisoned());
    j.append(&[0; 16]).unwrap();
}

#[test]
fn oversized_record_on_disk_refused() {
    let mem = MemStorage::new();
    let mut j = Journal::open_storage(mem.clone(), JournalOptions::default()).unwrap();
    j.append(&[1; 100]).unwrap();
    let opts = JournalOptions {
        max_payload: 50,
        ..Default::default()
    };
    assert!(matches!(
        Journal::open_storage(MemStorage::from_bytes(mem.durable()), opts),
        Err(JournalError::Corrupt {
            kind: CorruptionKind::OversizedRecord,
            ..
        })
    ));
}

#[test]
fn checkpoints() {
    let mem = MemStorage::new();
    let mut j = Journal::open_storage(mem.clone(), JournalOptions::default()).unwrap();
    let cp0 = j.checkpoint();
    j.append(b"a").unwrap();
    let cp1 = j.checkpoint();
    j.append(b"b").unwrap();
    assert!(j.verify_checkpoint(cp0).unwrap());
    assert!(j.verify_checkpoint(cp1).unwrap());
    assert!(j.verify_checkpoint(j.checkpoint()).unwrap());
    // A rewritten history fails the old checkpoint.
    let mut other = Journal::open_storage(MemStorage::new(), JournalOptions::default()).unwrap();
    other.append(b"A").unwrap();
    other.append(b"b").unwrap();
    assert!(!other.verify_checkpoint(cp1).unwrap());
    // Checkpoint beyond the log (e.g. after tail truncation) fails.
    let mut short = Journal::open_storage(MemStorage::new(), JournalOptions::default()).unwrap();
    assert!(!short.verify_checkpoint(cp1).unwrap());
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Arbitrary bytes after a valid file header never panic recovery.
    #[test]
    fn random_log_never_panics(body in proptest::collection::vec(any::<u8>(), 0..400)) {
        let mut b = MemStorage::new();
        drop(Journal::open_storage(b.clone(), JournalOptions::default()).unwrap());
        let mut bytes = b.durable();
        bytes.extend_from_slice(&body);
        b = MemStorage::from_bytes(bytes);
        if let Ok(mut j) = Journal::open_storage(b, JournalOptions::default()) {
            for r in j.replay() { prop_assert!(r.is_ok()); }
        }
    }

    #[test]
    fn random_file_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
        let _ = Journal::open_storage(MemStorage::from_bytes(bytes), JournalOptions::default());
    }

    /// Random append sequences with a crash at a random point inside an
    /// un-synced append: recovery yields exactly the acknowledged records,
    /// plus possibly the in-flight one if it was entirely written.
    #[test]
    fn random_crash_points(
        ps in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..40), 1..8),
        inflight in proptest::collection::vec(any::<u8>(), 0..40),
        keep in 0usize..200,
    ) {
        let mem = MemStorage::new();
        let mut j = Journal::open_storage(mem.clone(), JournalOptions::default()).unwrap();
        for p in &ps { j.append(p).unwrap(); }
        mem.fail_syncs(true);
        prop_assert!(j.append(&inflight).is_err());
        let full = RECORD_HEADER_LEN + inflight.len() + HASH_LEN;
        let mut r = Journal::open_storage(mem.crash(CrashMode::KeepUnsyncedPrefix(keep)), JournalOptions::default()).unwrap();
        let got: Vec<Vec<u8>> = r.replay().map(|x| x.unwrap().payload).collect();
        let mut expected = ps.clone();
        if keep >= full { expected.push(inflight.clone()); }
        prop_assert_eq!(got, expected);
    }
}
