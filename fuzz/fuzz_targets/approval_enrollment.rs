//! Hostile bytes into the operator-enrollment storage decoder. Accepted
//! inputs must round-trip exactly.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tessera_approval::Enrollment;

fuzz_target!(|data: &[u8]| {
    if let Ok(e) = Enrollment::decode(data) {
        assert_eq!(e.encode(), data, "enrollment decode is not injective");
    }
});
