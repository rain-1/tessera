//! SDK-level value types and textual id formats.

use std::fmt;
use std::str::FromStr;

use tessera_protocol::{
    HttpMethod, ReservationId, WireAgentId, WireBudget, WireCapabilityView, WireDepth, WireExpiry,
    WireOperationResult, WireReservationStatus, WireScope,
};

use crate::error::Error;

/// Format a 128-bit id (capability, request, root) as 32 lowercase hex digits.
pub fn format_id(id: u128) -> String {
    format!("{id:032x}")
}

/// Parse a 128-bit id written as hex (an optional `0x` prefix is accepted).
pub fn parse_id(s: &str) -> Result<u128, Error> {
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if t.is_empty() || t.len() > 32 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::InvalidArgument(format!(
            "{s:?} is not a hex id (up to 32 hex digits)"
        )));
    }
    u128::from_str_radix(t, 16).map_err(|_| Error::InvalidArgument(format!("bad id {s:?}")))
}

/// A principal (sandbox) as named on the wire, for example as a delegation
/// recipient. **A principal id names; it never authenticates.** The SDK never
/// sends the caller's own identity: the broker learns it from the channel.
///
/// Text form: `<epoch as 32 hex digits>:<serial in decimal>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AgentId(pub WireAgentId);

impl AgentId {
    /// Construct from parts.
    pub const fn new(epoch: u128, serial: u64) -> Self {
        Self(WireAgentId { epoch, serial })
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032x}:{}", self.0.epoch, self.0.serial)
    }
}

impl FromStr for AgentId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        let (e, n) = s.trim().split_once(':').ok_or_else(|| {
            Error::InvalidArgument(format!(
                "agent id {s:?} must look like <epoch-hex>:<serial>"
            ))
        })?;
        let epoch = parse_id(e)?;
        let serial = n
            .parse()
            .map_err(|_| Error::InvalidArgument(format!("bad agent serial in {s:?}")))?;
        Ok(Self::new(epoch, serial))
    }
}

impl From<WireAgentId> for AgentId {
    fn from(w: WireAgentId) -> Self {
        Self(w)
    }
}

/// The terms of a grant, delegation or attenuation: scope, budget, depth and
/// expiry. These are *requests*: the broker checks them (subset, budget
/// conservation, depth, expiry clamping) and may refuse them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Terms {
    /// Scope.
    pub scope: WireScope,
    /// Budget (number of uses).
    pub budget: WireBudget,
    /// Delegation depth.
    pub depth: WireDepth,
    /// Expiry, relative to when the broker processes the request.
    pub expiry: WireExpiry,
}

impl Terms {
    /// Terms with `budget` uses, depth 0 (not delegatable) and inherited
    /// expiry.
    pub const fn new(scope: WireScope, budget: u64) -> Self {
        Self {
            scope,
            budget: WireBudget::Finite(budget),
            depth: WireDepth::Finite(0),
            expiry: WireExpiry::Inherit,
        }
    }

    /// Set the delegation depth.
    pub const fn depth(mut self, depth: u32) -> Self {
        self.depth = WireDepth::Finite(depth);
        self
    }

    /// Set the expiry to `millis` after the broker processes the request.
    pub const fn expires_within_millis(mut self, millis: u64) -> Self {
        self.expiry = WireExpiry::WithinMillis(millis);
        self
    }
}

/// Result of a consume call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Consumed {
    /// A new reservation was made and the operation dispatched.
    Executed {
        /// Reservation used.
        reservation_id: ReservationId,
        /// Adapter result.
        result: WireOperationResult,
    },
    /// The request id was already used. This is the status of the earlier
    /// reservation, and **no new effect was dispatched**.
    Prior {
        /// Earlier reservation.
        reservation_id: ReservationId,
        /// Its status.
        status: WireReservationStatus,
    },
}

/// Bounded file snapshot.
#[derive(Clone, PartialEq, Eq)]
pub struct FileSnapshot {
    /// Reservation used.
    pub reservation_id: ReservationId,
    /// Content (at most the requested `max_bytes`).
    pub bytes: Vec<u8>,
    /// Whether the file was longer than `max_bytes`.
    pub truncated: bool,
}

impl fmt::Debug for FileSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print file content.
        f.debug_struct("FileSnapshot")
            .field("reservation_id", &self.reservation_id)
            .field("len", &self.bytes.len())
            .field("truncated", &self.truncated)
            .finish()
    }
}

/// One outbound HTTPS request (origin-relative; the endpoint is fixed by the
/// capability).
#[derive(Clone, PartialEq, Eq)]
pub struct HttpsRequest {
    /// Method.
    pub method: HttpMethod,
    /// Path and query, for example `/v1/search?q=x`.
    pub path: String,
    /// Headers (name, value). Credentials are added by the broker, never by
    /// the agent.
    pub headers: Vec<(String, Vec<u8>)>,
    /// Body.
    pub body: Vec<u8>,
}

impl HttpsRequest {
    /// A `GET` of `path` with no headers.
    pub fn get(path: impl Into<String>) -> Self {
        Self {
            method: HttpMethod::Get,
            path: path.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

impl fmt::Debug for HttpsRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpsRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("headers", &self.headers.len())
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// HTTPS response returned by the adapter.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpsResponse {
    /// Reservation used.
    pub reservation_id: ReservationId,
    /// Status code.
    pub status: u16,
    /// Headers.
    pub headers: Vec<(String, Vec<u8>)>,
    /// Body (possibly truncated to the grant's limit).
    pub body: Vec<u8>,
    /// Whether the body was truncated.
    pub truncated: bool,
}

impl fmt::Debug for HttpsResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpsResponse")
            .field("reservation_id", &self.reservation_id)
            .field("status", &self.status)
            .field("headers", &self.headers.len())
            .field("body_len", &self.body.len())
            .field("truncated", &self.truncated)
            .finish()
    }
}

/// Capability metadata (owner-visible).
pub type CapabilityView = WireCapabilityView;
