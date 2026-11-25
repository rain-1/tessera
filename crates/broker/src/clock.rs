//! Trusted time.
//!
//! Ticks are milliseconds of a monotonic source, measured from the start of
//! the current authority epoch. A restart or emergency stop begins a new
//! epoch and a fresh clock (the core permits the clock to restart only on
//! `BumpEpoch`), so wall-clock changes can never extend a grant (§11).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tessera_capability_core::Tick;

/// Monotonic millisecond source.
pub trait TickSource: Send + Sync + 'static {
    /// Milliseconds since an arbitrary fixed origin; never decreases.
    fn now_ms(&self) -> u64;
}

/// `CLOCK_MONOTONIC` via [`Instant`].
#[derive(Debug)]
pub struct MonotonicClock(Instant);

impl Default for MonotonicClock {
    fn default() -> Self {
        MonotonicClock(Instant::now())
    }
}

impl TickSource for MonotonicClock {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// Manually advanced clock for tests.
#[derive(Debug, Default, Clone)]
pub struct ManualClock(Arc<AtomicU64>);

impl ManualClock {
    /// New clock at 0.
    pub fn new() -> Self {
        Self::default()
    }
    /// Advance by `ms`.
    pub fn advance(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }
}

impl TickSource for ManualClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Epoch-relative clock used by the reactor.
pub(crate) struct Clock {
    source: Arc<dyn TickSource>,
    base: u64,
}

impl Clock {
    pub(crate) fn new(source: Arc<dyn TickSource>) -> Self {
        let base = source.now_ms();
        Clock { source, base }
    }

    /// Start a fresh epoch clock at tick 0.
    pub(crate) fn reset(&mut self) {
        self.base = self.source.now_ms();
    }

    pub(crate) fn now(&self) -> Tick {
        Tick::from_raw(self.source.now_ms().saturating_sub(self.base))
    }
}
