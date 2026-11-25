//! Arbitrary bytes as a capability-core `State` snapshot (postcard and JSON).
//! `State`'s deserializer re-checks the global invariant; an accepted
//! snapshot must satisfy `check_invariant` and round-trip.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tessera_capability_core::{State, check_invariant};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = postcard::from_bytes::<State>(data) {
        check_invariant(&s).expect("deserialized state violates invariant");
        let bytes = postcard::to_allocvec(&s).expect("serialize");
        let back: State = postcard::from_bytes(&bytes).expect("round trip");
        assert_eq!(back, s);
    }
    if let Ok(s) = serde_json::from_slice::<State>(data) {
        check_invariant(&s).expect("deserialized state violates invariant");
    }
});
