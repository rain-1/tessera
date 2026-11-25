//! Arbitrary bytes as an on-disk journal: open (recovery scan) under both
//! tail policies, replay, fold the recovery state, then append and reopen.
//! Must never panic; a journal that opened must stay consistent.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tessera_journal::testing::MemStorage;
use tessera_journal::{Journal, JournalOptions, TailPolicy, recover};

fuzz_target!(|data: &[u8]| {
    for tail_policy in [
        TailPolicy::Strict,
        TailPolicy::TruncateUnverifiableFinalRecord,
    ] {
        let opts = JournalOptions {
            max_payload: 64 * 1024,
            tail_policy,
        };
        let storage = MemStorage::from_bytes(data.to_vec());
        let Ok(mut j) = Journal::open_storage(storage.clone(), opts) else {
            continue;
        };
        let n = j.replay().filter(|r| r.is_ok()).count() as u64;
        let _ = recover(&mut j);
        let before = j.checkpoint();
        if j.append(b"fuzz").is_err() || j.begin_new_epoch().is_err() {
            continue;
        }
        // Reopen what is durable: everything previously accepted must
        // still verify, plus the two new records.
        let reopened = MemStorage::from_bytes(storage.durable());
        let mut j2 = Journal::open_storage(reopened, opts).expect("reopen after append");
        assert!(
            j2.verify_checkpoint(before).unwrap_or(false),
            "checkpoint lost"
        );
        let m = j2.replay().map(|r| r.expect("replay after reopen")).count() as u64;
        assert!(m >= n + 2);
    }
});
