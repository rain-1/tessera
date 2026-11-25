//! Hostile bytes into the canonical grant-request decoder (what the human
//! approves). Accepted inputs must round-trip exactly, and rendering an
//! accepted request (shown to the operator) must not panic.
#![no_main]
use std::num::NonZeroU64;

use libfuzzer_sys::fuzz_target;
use tessera_approval::{GrantRequest, RenderContext, Tick, render_request};

fuzz_target!(|data: &[u8]| {
    let Ok(req) = GrantRequest::decode(data) else {
        return;
    };
    assert_eq!(req.encode(), data, "decode is not injective");
    let again = GrantRequest::new(req.fields().clone()).expect("decoded fields re-validate");
    assert_eq!(again.digest().0, req.digest().0);
    for now in [0, u64::MAX / 2, u64::MAX] {
        let ctx = RenderContext {
            now: Tick(now),
            ticks_per_second: NonZeroU64::new(1000),
        };
        let _ = render_request(&req, Some("untrusted \u{202e}desc\x1b[2J"), &ctx);
    }
});
