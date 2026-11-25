//! Arbitrary command sequences through the authority core.
//!
//! Input: 3 bytes selecting small `Limits`, then a postcard stream of
//! `(AuthenticatedCommand, clock_delta: u64)` pairs. Postcard varints make
//! small identifiers cheap, so the fuzzer reaches live capability ids.
//! After every step:
//!   * success  => `check_invariant` holds;
//!   * denial   => the state is byte-for-byte unchanged (denial without
//!                 mutation);
//! and the final state survives a serialize/deserialize round trip.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tessera_capability_core::{AuthenticatedCommand, Limits, State, Tick, check_invariant, step};

fuzz_target!(|data: &[u8]| {
    let Some((lim, mut rest)) = data.split_first_chunk::<3>() else {
        return;
    };
    let limits = Limits {
        max_capabilities: 1 + u64::from(lim[0] % 32),
        max_principals: 1 + u64::from(lim[1] % 8),
        max_roots: 1 + u64::from(lim[1] / 8 % 16),
        max_reservations: 1 + u64::from(lim[2] % 32),
        max_lineage_length: u32::from(lim[2] / 32),
    };
    let mut s = State::new(limits);
    check_invariant(&s).expect("fresh state");
    let mut steps = 0;
    while steps < 256 {
        let Ok(((cmd, delta), tail)) =
            postcard::take_from_bytes::<(AuthenticatedCommand, u64)>(rest)
        else {
            break;
        };
        rest = tail;
        steps += 1;
        let now = Tick::from_raw(s.clock().to_raw().saturating_add(delta));
        let before = postcard::to_allocvec(&s).expect("serialize");
        match step(&mut s, cmd, now) {
            Ok(_) => {
                if let Err(v) = check_invariant(&s) {
                    panic!("invariant violated after {cmd:?} at {now:?}: {v:?}");
                }
            }
            Err(d) => {
                let after = postcard::to_allocvec(&s).expect("serialize");
                assert!(before == after, "denial {d:?} mutated state ({cmd:?})");
            }
        }
    }
    let bytes = postcard::to_allocvec(&s).expect("serialize");
    let back: State = postcard::from_bytes(&bytes).expect("final state must deserialize");
    assert_eq!(back, s);
});
