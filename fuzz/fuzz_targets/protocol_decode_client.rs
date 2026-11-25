//! Hostile bytes into the client-message decoder. Any accepted payload must
//! be canonical: re-encoding reproduces the input byte for byte.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tessera_protocol::frame::HARD_MAX_FRAME;
use tessera_protocol::{decode_client, encode_client};

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = decode_client(data, HARD_MAX_FRAME) {
        let re = encode_client(&msg).expect("decoded message must re-encode");
        assert_eq!(re, data, "decoder accepted a non-canonical payload");
    }
    // A smaller limit must never accept more than the larger one.
    let small = data.len().saturating_sub(1);
    assert!(decode_client(data, small).is_err() || data.is_empty());
});
