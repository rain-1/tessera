//! Hostile bytes into the server-message decoder. Any accepted payload must
//! be canonical: re-encoding reproduces the input byte for byte.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tessera_protocol::frame::HARD_MAX_FRAME;
use tessera_protocol::{decode_server, encode_server};

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = decode_server(data, HARD_MAX_FRAME) {
        let re = encode_server(&msg).expect("decoded message must re-encode");
        assert_eq!(re, data, "decoder accepted a non-canonical payload");
    }
    // A smaller limit must never accept more than the larger one.
    let small = data.len().saturating_sub(1);
    assert!(decode_server(data, small).is_err() || data.is_empty());
});
