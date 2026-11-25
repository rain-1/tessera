//! Per-sandbox rate limit and byte budget.
//!
//! These are operator-configured *resource* limits on a baseline channel.
//! They are not capability units: the model route is an unmediated baseline
//! effect (ADR-0020, ADR-0030) and is not accounted in the authority core.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::BudgetConfig;
use crate::policy::Denial;

#[derive(Debug)]
struct State {
    tokens: f64,
    last: Instant,
    requests: u64,
    request_bytes: u64,
    response_bytes: u64,
}

/// Shared budget of one sandbox.
#[derive(Debug)]
pub struct Budget {
    cfg: BudgetConfig,
    state: Mutex<State>,
    in_flight: Arc<Semaphore>,
}

/// Snapshot of consumption (for tests and status lines).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Usage {
    /// Admitted requests.
    pub requests: u64,
    /// Request body bytes admitted.
    pub request_bytes: u64,
    /// Response body bytes returned.
    pub response_bytes: u64,
}

impl Budget {
    /// New budget with a full token bucket.
    pub fn new(cfg: BudgetConfig) -> Self {
        let in_flight = Arc::new(Semaphore::new(cfg.max_concurrent as usize));
        Self {
            state: Mutex::new(State {
                tokens: f64::from(cfg.burst),
                last: Instant::now(),
                requests: 0,
                request_bytes: 0,
                response_bytes: 0,
            }),
            cfg,
            in_flight,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Admit one request carrying `body_len` bytes: checks concurrency, the
    /// token bucket and the lifetime totals, and charges them atomically.
    /// The returned permit must be held until the response is finished.
    pub fn admit(&self, body_len: u64) -> Result<OwnedSemaphorePermit, Denial> {
        let permit = Arc::clone(&self.in_flight)
            .try_acquire_owned()
            .map_err(|_| Denial::TooManyInFlight)?;
        let mut s = self.lock();
        if self
            .cfg
            .max_requests
            .is_some_and(|max| s.requests.saturating_add(1) > max)
        {
            return Err(Denial::BudgetExhausted("requests"));
        }
        if self
            .cfg
            .max_request_bytes
            .is_some_and(|max| s.request_bytes.saturating_add(body_len) > max)
        {
            return Err(Denial::BudgetExhausted("request_bytes"));
        }
        if self
            .cfg
            .max_response_bytes
            .is_some_and(|max| s.response_bytes >= max)
        {
            return Err(Denial::BudgetExhausted("response_bytes"));
        }
        let now = Instant::now();
        let refill = now.duration_since(s.last).as_secs_f64()
            * f64::from(self.cfg.requests_per_minute)
            / 60.0;
        s.tokens = (s.tokens + refill).min(f64::from(self.cfg.burst));
        s.last = now;
        if s.tokens < 1.0 {
            return Err(Denial::RateLimited);
        }
        s.tokens -= 1.0;
        s.requests += 1;
        s.request_bytes = s.request_bytes.saturating_add(body_len);
        Ok(permit)
    }

    /// Charge `n` response bytes. Returns false if that would exceed the
    /// lifetime response budget; the budget is then marked exhausted (the
    /// caller aborts the stream) so later requests are refused.
    pub fn charge_response(&self, n: u64) -> bool {
        let mut s = self.lock();
        let next = s.response_bytes.saturating_add(n);
        if let Some(max) = self.cfg.max_response_bytes
            && next > max
        {
            s.response_bytes = max;
            return false;
        }
        s.response_bytes = next;
        true
    }

    /// Current consumption.
    pub fn usage(&self) -> Usage {
        let s = self.lock();
        Usage {
            requests: s.requests,
            request_bytes: s.request_bytes,
            response_bytes: s.response_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_and_totals() {
        let b = Budget::new(BudgetConfig {
            requests_per_minute: 1,
            burst: 2,
            max_concurrent: 10,
            max_requests: Some(10),
            max_request_bytes: Some(100),
            max_response_bytes: Some(50),
        });
        let _p1 = b.admit(10).unwrap();
        let _p2 = b.admit(10).unwrap();
        assert_eq!(b.admit(10).unwrap_err(), Denial::RateLimited);
        assert_eq!(
            b.admit(1000).unwrap_err(),
            Denial::BudgetExhausted("request_bytes")
        );
        assert!(b.charge_response(50));
        assert!(!b.charge_response(1));
        assert_eq!(b.usage().response_bytes, 50);
    }

    #[test]
    fn concurrency() {
        let b = Budget::new(BudgetConfig {
            max_concurrent: 1,
            ..BudgetConfig::default()
        });
        let p = b.admit(0).unwrap();
        assert_eq!(b.admit(0).unwrap_err(), Denial::TooManyInFlight);
        drop(p);
        assert!(b.admit(0).is_ok());
    }
}
