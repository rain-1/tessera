//! Hostile byte stream into the length-prefixed frame reader. The first byte
//! picks a frame limit; the reader must never return a frame above it and
//! must never allocate based on an unchecked length.
#![no_main]
use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use tessera_protocol::frame::{FrameLimits, read_frame};
use tessera_protocol::{ClientMessage, recv_message};

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let limit = match sel % 4 {
        0 => 0,
        1 => 16,
        2 => 4096,
        _ => usize::MAX, // clamped to HARD_MAX_FRAME
    };
    let limits = FrameLimits::new(limit);
    let mut r = Cursor::new(rest);
    for _ in 0..1024 {
        match read_frame(&mut r, limits) {
            Ok(Some(f)) => assert!(f.len() <= limits.max_frame()),
            Ok(None) | Err(_) => break,
        }
    }
    let mut r = Cursor::new(rest);
    for _ in 0..1024 {
        if recv_message::<_, ClientMessage>(&mut r, limits).is_err() {
            break;
        }
    }
});
