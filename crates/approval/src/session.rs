//! Per-authenticator approval state machine.
//!
//! ```text
//!            begin (not busy, not rate-limited, context ok)
//!   Idle ─────────────────────────────────────────────▶ AwaitingTouch
//!    ▲                                                   │  │  │   │
//!    │  complete(ok)  -> VerifiedApproval               │  │  │   │ narrow(subset)
//!    ├──────────────────────────────────────────────────┘  │  │   └──▶ AwaitingTouch
//!    │  complete(err) -> Rejected (fail closed)            │  │
//!    ├─────────────────────────────────────────────────────┘  │
//!    │  deny / timeout (poll or any call after deadline)       │
//!    └─────────────────────────────────────────────────────────┘
//! ```
//!
//! Exactly one touch request may be outstanding per authenticator (one
//! session per enrolled credential). Any verification failure ends the
//! pending request: the broker must issue a fresh challenge, so a workload
//! cannot drive repeated touches on one challenge. The session also refuses
//! to re-issue any nonce it has seen (defense in depth; the durable ledger's
//! nonce redemption remains authoritative).

use std::collections::{HashSet, VecDeque};
use std::fmt;

use crate::assertion::{
    Assertion, VerifiedApproval, VerifierPolicy, VerifyError, check_request_context,
    verify_assertion,
};
use crate::authenticator::{AssertionRequest, Authenticator, AuthenticatorError};
use crate::enrollment::Enrollment;
use crate::request::{GrantRequest, NarrowingError, Nonce, Tick};

/// Bound on remembered nonces (oldest forgotten first).
pub const MAX_REMEMBERED_NONCES: usize = 4096;

/// Session limits, in trusted ticks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionConfig {
    /// How long a touch request stays outstanding (also capped by the
    /// request's own expiration).
    pub approval_timeout: u64,
    /// Sliding-window length for rate limiting.
    pub rate_window: u64,
    /// Maximum `begin` calls accepted per window.
    pub max_requests_per_window: u32,
}

/// The touch request currently awaiting the operator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingApproval {
    original: GrantRequest,
    current: GrantRequest,
    issued_at: Tick,
    deadline: Tick,
}

impl PendingApproval {
    /// The request as originally proposed by the broker.
    pub fn original(&self) -> &GrantRequest {
        &self.original
    }
    /// The request that will be signed (possibly narrowed by the operator).
    pub fn current(&self) -> &GrantRequest {
        &self.current
    }
    pub fn is_narrowed(&self) -> bool {
        self.original != self.current
    }
    pub fn issued_at(&self) -> Tick {
        self.issued_at
    }
    pub fn deadline(&self) -> Tick {
        self.deadline
    }
}

/// Session-level errors.
#[derive(Debug)]
pub enum SessionError {
    /// A touch request is already outstanding on this authenticator.
    Busy,
    RateLimited,
    NoPendingRequest,
    /// The pending request timed out (it has been discarded).
    TimedOut,
    /// The nonce was already issued by this session.
    NonceReused,
    /// The request is not valid for this installation/epoch/operator/time.
    InvalidRequest(VerifyError),
    Narrowing(NarrowingError),
    /// The assertion was rejected (the pending request has been discarded).
    Rejected(VerifyError),
    /// The device failed (the pending request has been discarded).
    Device(AuthenticatorError),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::Busy => write!(f, "a touch request is already outstanding"),
            SessionError::RateLimited => write!(f, "approval requests rate-limited"),
            SessionError::NoPendingRequest => write!(f, "no pending approval request"),
            SessionError::TimedOut => write!(f, "approval request timed out"),
            SessionError::NonceReused => write!(f, "nonce already used"),
            SessionError::InvalidRequest(e) => write!(f, "invalid request: {e}"),
            SessionError::Narrowing(e) => write!(f, "invalid narrowing: {e}"),
            SessionError::Rejected(e) => write!(f, "assertion rejected: {e}"),
            SessionError::Device(e) => write!(f, "authenticator failed: {e}"),
        }
    }
}

impl std::error::Error for SessionError {}

/// How a pending request ended without approval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Closed {
    Denied(GrantRequest),
    TimedOut(GrantRequest),
}

/// Approval state machine for one enrolled authenticator.
pub struct ApprovalSession {
    enrollment: Enrollment,
    policy: VerifierPolicy,
    approval_timeout: u64,
    rate_limit: Option<SessionConfig>,
    pending: Option<PendingApproval>,
    recent_begins: VecDeque<Tick>,
    seen_nonces: HashSet<Nonce>,
    seen_order: VecDeque<Nonce>,
}

impl ApprovalSession {
    pub fn new(enrollment: Enrollment, policy: VerifierPolicy, config: SessionConfig) -> Self {
        Self::with_rate_limit(enrollment, policy, config.approval_timeout, Some(config))
    }

    /// Use when the caller enforces admission independently of this session.
    pub fn with_external_rate_limit(
        enrollment: Enrollment,
        policy: VerifierPolicy,
        approval_timeout: u64,
    ) -> Self {
        Self::with_rate_limit(enrollment, policy, approval_timeout, None)
    }

    fn with_rate_limit(
        enrollment: Enrollment,
        policy: VerifierPolicy,
        approval_timeout: u64,
        rate_limit: Option<SessionConfig>,
    ) -> Self {
        ApprovalSession {
            enrollment,
            policy,
            approval_timeout,
            rate_limit,
            pending: None,
            recent_begins: VecDeque::new(),
            seen_nonces: HashSet::new(),
            seen_order: VecDeque::new(),
        }
    }

    pub fn enrollment(&self) -> &Enrollment {
        &self.enrollment
    }

    pub fn pending(&self) -> Option<&PendingApproval> {
        self.pending.as_ref()
    }

    /// Expires the pending request if its deadline has passed.
    pub fn poll(&mut self, now: Tick) -> Option<Closed> {
        match &self.pending {
            Some(p) if now >= p.deadline => {
                self.pending.take().map(|p| Closed::TimedOut(p.current))
            }
            _ => None,
        }
    }

    fn active(&mut self, now: Tick) -> Result<&PendingApproval, SessionError> {
        if self.poll(now).is_some() {
            return Err(SessionError::TimedOut);
        }
        self.pending.as_ref().ok_or(SessionError::NoPendingRequest)
    }

    fn remember(&mut self, nonce: Nonce) {
        if self.seen_nonces.insert(nonce) {
            self.seen_order.push_back(nonce);
            if self.seen_order.len() > MAX_REMEMBERED_NONCES {
                if let Some(old) = self.seen_order.pop_front() {
                    self.seen_nonces.remove(&old);
                }
            }
        }
    }

    /// Presents a new broker-built request to the operator.
    pub fn begin(
        &mut self,
        request: GrantRequest,
        now: Tick,
    ) -> Result<&PendingApproval, SessionError> {
        self.poll(now);
        if self.pending.is_some() {
            return Err(SessionError::Busy);
        }
        if let Some(limit) = self.rate_limit {
            let window_start = now.0.saturating_sub(limit.rate_window);
            while self
                .recent_begins
                .front()
                .is_some_and(|t| t.0 < window_start)
            {
                self.recent_begins.pop_front();
            }
            if self.recent_begins.len() >= limit.max_requests_per_window as usize {
                return Err(SessionError::RateLimited);
            }
        }
        if self.seen_nonces.contains(request.nonce()) {
            return Err(SessionError::NonceReused);
        }
        check_request_context(&self.enrollment, &self.policy, &request, now)
            .map_err(SessionError::InvalidRequest)?;
        if self.rate_limit.is_some() {
            self.recent_begins.push_back(now);
        }
        self.remember(*request.nonce());
        let deadline = Tick(now.0.saturating_add(self.approval_timeout))
            .min(request.fields().request_expires_at);
        Ok(self.pending.insert(PendingApproval {
            original: request.clone(),
            current: request,
            issued_at: now,
            deadline,
        }))
    }

    /// Operator narrows the pending request. The new request must be a
    /// narrowing of the *original* (and hence cannot re-expand an earlier
    /// narrowing beyond the original) and of the current one.
    pub fn narrow(
        &mut self,
        narrowed: GrantRequest,
        now: Tick,
    ) -> Result<&PendingApproval, SessionError> {
        let p = self.active(now)?;
        narrowed
            .check_narrowing_of(&p.current)
            .and_then(|()| narrowed.check_narrowing_of(&p.original))
            .map_err(SessionError::Narrowing)?;
        check_request_context(&self.enrollment, &self.policy, &narrowed, now)
            .map_err(SessionError::InvalidRequest)?;
        let p = self
            .pending
            .as_mut()
            .ok_or(SessionError::NoPendingRequest)?;
        p.deadline = p.deadline.min(narrowed.fields().request_expires_at);
        p.current = narrowed;
        Ok(p)
    }

    /// Operator explicitly denies the pending request.
    pub fn deny(&mut self, now: Tick) -> Result<Closed, SessionError> {
        self.active(now)?;
        let p = self.pending.take().ok_or(SessionError::NoPendingRequest)?;
        Ok(Closed::Denied(p.current))
    }

    /// What to send to the authenticator for the pending request.
    pub fn assertion_request(&mut self, now: Tick) -> Result<AssertionRequest, SessionError> {
        let client_data_hash = self.active(now)?.current.digest().0;
        Ok(AssertionRequest {
            rp_id: self.enrollment.rp_id().to_owned(),
            client_data_hash,
            credential_id: self.enrollment.credential_id().to_vec(),
            require_user_verification: self.policy.require_user_verification,
        })
    }

    /// Verifies an assertion against the pending request. The pending request
    /// is consumed whatever the outcome.
    pub fn complete(
        &mut self,
        assertion: &Assertion,
        now: Tick,
    ) -> Result<VerifiedApproval, SessionError> {
        self.active(now)?;
        let p = self.pending.take().ok_or(SessionError::NoPendingRequest)?;
        verify_assertion(
            &self.enrollment,
            &self.policy,
            &p.current,
            p.current.nonce(),
            assertion,
            now,
        )
        .map_err(SessionError::Rejected)
    }

    /// Convenience: ask `authenticator` for the touch, then verify. `clock` is
    /// read after the device returns, so a slow touch can still time out.
    pub fn touch(
        &mut self,
        authenticator: &mut dyn Authenticator,
        now: Tick,
        clock: impl FnOnce() -> Tick,
    ) -> Result<VerifiedApproval, SessionError> {
        let req = self.assertion_request(now)?;
        match authenticator.get_assertion(&req) {
            Ok(a) => self.complete(&a, clock()),
            Err(e) => {
                self.pending = None;
                Err(SessionError::Device(e))
            }
        }
    }
}
