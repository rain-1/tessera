//! Wire types: plain, untrusted data.
//!
//! Nothing in this module confers authority. A [`CapId`] received from a
//! client is a *reference* the broker looks up against the authenticated
//! caller; a [`WireScope`] is a *request* the broker checks against policy and
//! converts into a validated core scope; a [`WireAgentId`] in a `recipient`
//! field names a principal but never authenticates one. The broker must
//! derive the caller identity from the transport (see
//! [`crate::unix::peer_credentials`] and the launcher's channel membership),
//! never from message contents.
//!
//! All types are non-recursive, so the nesting depth of any message is a
//! static property of the schema (at most 6 levels: frame -> request ->
//! operation -> https request -> header list -> header). Every
//! variable-length field is a [`crate::bounded`] type.

use serde::{Deserialize, Serialize};

use crate::bounded::{BoundedBytes, BoundedString, BoundedVec};

/// Maximum bytes of file content or HTTP body carried inline in one message.
/// The per-connection frame limit (see [`crate::frame::FrameLimits`]) may be
/// lower and is enforced first.
pub const MAX_CONTENT_BYTES: usize = 8 * 1024 * 1024;
/// Maximum HTTP request path length (bytes, including query).
pub const MAX_HTTP_PATH: usize = 2048;
/// Maximum number of HTTP headers in a request or response.
pub const MAX_HTTP_HEADERS: usize = 64;
/// Maximum HTTP header name length.
pub const MAX_HEADER_NAME: usize = 128;
/// Maximum HTTP header value length.
pub const MAX_HEADER_VALUE: usize = 8192;
/// Maximum length of a free-form diagnostic string in an error response.
pub const MAX_DETAIL: usize = 256;

/// Client-chosen request identifier. Scoped by the broker to the
/// authenticated principal and authority epoch.
pub type RequestId = u128;
/// Capability reference (not a bearer secret).
pub type CapId = u128;
/// Root authorization identifier.
pub type RootId = u128;
/// Dispatch reservation identifier.
pub type ReservationId = u128;
/// Adapter-registered stable file object identifier.
pub type ObjectId = u64;
/// Adapter-registered HTTPS endpoint identifier.
pub type EndpointId = u64;
/// Trusted launch profile identifier.
pub type LaunchProfileId = u64;
/// Client-chosen correlation number echoed in the matching response.
pub type CorrelationId = u64;

/// Opaque bytes carried as file content or HTTP body.
pub type ContentBytes = BoundedBytes<MAX_CONTENT_BYTES>;

/// Principal identifier as it appears on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WireAgentId {
    /// Installation/authority epoch in which the principal was created.
    pub epoch: u128,
    /// Serial number within the epoch.
    pub serial: u64,
}

/// Budget: number of uses. `Unlimited` is an explicit variant, never a magic
/// number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WireBudget {
    /// At most this many uses.
    Finite(u64),
    /// No use bound.
    Unlimited,
}

/// Delegation depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WireDepth {
    /// At most this many further delegation generations.
    Finite(u32),
    /// No depth bound.
    Unlimited,
}

/// Requested expiry. Absolute times are never accepted from clients: the
/// broker's trusted monotonic clock is the only time source, so clients only
/// ask for a duration relative to the moment the broker processes the
/// request. The broker clamps the result to the parent/session expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WireExpiry {
    /// Same as the parent (or the session default for a root request).
    Inherit,
    /// Expire this many milliseconds after the broker processes the request.
    WithinMillis(u64),
}

/// File rights. Explicit booleans so that no unknown bits can be smuggled in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct WireFileRights {
    /// May take one bounded snapshot of the content.
    pub read_snapshot: bool,
    /// May atomically replace the content.
    pub replace_content: bool,
}

/// HTTP methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HttpMethod {
    /// GET
    Get,
    /// HEAD
    Head,
    /// POST
    Post,
    /// PUT
    Put,
    /// PATCH
    Patch,
    /// DELETE
    Delete,
}

/// Set of HTTP methods. Explicit booleans; no CONNECT/TRACE/OPTIONS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct WireMethodSet {
    /// GET allowed.
    pub get: bool,
    /// HEAD allowed.
    pub head: bool,
    /// POST allowed.
    pub post: bool,
    /// PUT allowed.
    pub put: bool,
    /// PATCH allowed.
    pub patch: bool,
    /// DELETE allowed.
    pub delete: bool,
}

impl WireMethodSet {
    /// Whether `m` is in the set.
    pub fn contains(&self, m: HttpMethod) -> bool {
        match m {
            HttpMethod::Get => self.get,
            HttpMethod::Head => self.head,
            HttpMethod::Post => self.post,
            HttpMethod::Put => self.put,
            HttpMethod::Patch => self.patch,
            HttpMethod::Delete => self.delete,
        }
    }
}

/// Requested scope. Must be validated and converted by the broker/core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WireScope {
    /// Exact registered file object.
    File {
        /// Registered object.
        object_id: ObjectId,
        /// Rights requested.
        rights: WireFileRights,
    },
    /// Registered HTTPS endpoint.
    Https {
        /// Registered endpoint.
        endpoint_id: EndpointId,
        /// Allowed methods.
        methods: WireMethodSet,
        /// Maximum request body size.
        max_body_bytes: u64,
    },
}

/// HTTP header. Syntax (token characters, no CR/LF) is validated by the
/// HTTPS adapter, not here.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WireHeader {
    /// Header name.
    pub name: BoundedString<MAX_HEADER_NAME>,
    /// Header value.
    pub value: BoundedBytes<MAX_HEADER_VALUE>,
}

/// Header list.
pub type WireHeaders = BoundedVec<WireHeader, MAX_HTTP_HEADERS>;

/// One outbound HTTPS request attempt.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WireHttpsRequest {
    /// Method.
    pub method: HttpMethod,
    /// Origin-relative path and query.
    pub path: BoundedString<MAX_HTTP_PATH>,
    /// Headers.
    pub headers: WireHeaders,
    /// Body.
    pub body: ContentBytes,
}

/// Concrete protected operation requested under a capability.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WireOperation {
    /// Take one snapshot of a registered file, at most `max_bytes` long.
    FileReadSnapshot {
        /// Upper bound on returned bytes.
        max_bytes: u64,
    },
    /// Atomically replace the content of a registered file.
    FileReplaceContent {
        /// New content.
        bytes: ContentBytes,
    },
    /// Issue one HTTPS request to the capability's endpoint.
    Https(WireHttpsRequest),
}

/// Requests from an (untrusted) agent. Field names follow §9.2.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Request {
    /// Ask a human-authorised root grant.
    RequestGrant {
        /// Request id.
        request_id: RequestId,
        /// Scope asked for.
        requested_scope: WireScope,
        /// Budget asked for.
        budget: WireBudget,
        /// Delegation depth asked for.
        depth: WireDepth,
        /// Expiry asked for.
        expiry: WireExpiry,
    },
    /// Consume one unit to perform `operation`.
    Consume {
        /// Request id.
        request_id: RequestId,
        /// Capability to use.
        cap_id: CapId,
        /// Exact operation.
        operation: WireOperation,
    },
    /// Atomically split off and hand a child to `recipient`.
    Delegate {
        /// Request id.
        request_id: RequestId,
        /// Parent capability.
        cap_id: CapId,
        /// Receiving principal.
        recipient: WireAgentId,
        /// Child scope (must be a subset).
        child_scope: WireScope,
        /// Child budget.
        child_budget: WireBudget,
        /// Child depth.
        child_depth: WireDepth,
        /// Child expiry.
        child_expiry: WireExpiry,
    },
    /// Reduce a capability in place.
    Attenuate {
        /// Request id.
        request_id: RequestId,
        /// Capability.
        cap_id: CapId,
        /// New (smaller) scope.
        reduced_scope: WireScope,
        /// New (smaller) budget.
        budget: WireBudget,
        /// New (smaller) depth.
        depth: WireDepth,
        /// New (earlier) expiry.
        expiry: WireExpiry,
    },
    /// Move ownership to `recipient`.
    Transfer {
        /// Request id.
        request_id: RequestId,
        /// Capability.
        cap_id: CapId,
        /// Receiving principal.
        recipient: WireAgentId,
    },
    /// Discard remaining balance.
    Drop {
        /// Request id.
        request_id: RequestId,
        /// Capability.
        cap_id: CapId,
    },
    /// Read metadata of an owned capability.
    Inspect {
        /// Capability.
        cap_id: CapId,
    },
    /// Launch a child sandbox from a trusted profile.
    Spawn {
        /// Request id.
        request_id: RequestId,
        /// Trusted profile.
        launch_profile: LaunchProfileId,
    },
    /// Revoke a capability subtree (admin or designated revoker only).
    Revoke {
        /// Request id.
        request_id: RequestId,
        /// Capability.
        cap_id: CapId,
    },
}

impl Request {
    /// The request id, if this request kind carries one.
    pub fn request_id(&self) -> Option<RequestId> {
        match self {
            Request::RequestGrant { request_id, .. }
            | Request::Consume { request_id, .. }
            | Request::Delegate { request_id, .. }
            | Request::Attenuate { request_id, .. }
            | Request::Transfer { request_id, .. }
            | Request::Drop { request_id, .. }
            | Request::Spawn { request_id, .. }
            | Request::Revoke { request_id, .. } => Some(*request_id),
            Request::Inspect { .. } => None,
        }
    }
}

/// Status of a dispatch reservation, as reported to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WireReservationStatus {
    /// Budget deducted, not yet handed to the adapter.
    Reserved,
    /// Handed to the adapter; outcome not yet recorded.
    Dispatched,
    /// Adapter reported completion.
    Completed,
    /// Outcome uncertain (e.g. broker restarted mid-dispatch). Never retried.
    Unknown,
    /// Adapter reported a definite failure: no effect took place. The budget
    /// unit stays spent (no refund, ADR-0012). Appended last so the encoding
    /// of the earlier variants is unchanged.
    Failed,
}

/// Liveness of a capability as reported by `Inspect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WireCapStatus {
    /// Can authorise new uses.
    Live,
    /// Expired.
    Expired,
    /// It or an ancestor was revoked.
    Revoked,
    /// Dropped by its owner.
    Dropped,
}

/// Capability metadata visible to its owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WireCapabilityView {
    /// Capability id.
    pub cap_id: CapId,
    /// Root id.
    pub root_id: RootId,
    /// Parent, if not a root.
    pub parent: Option<CapId>,
    /// Current owner.
    pub owner: WireAgentId,
    /// Scope.
    pub scope: WireScope,
    /// Remaining budget.
    pub budget_remaining: WireBudget,
    /// Remaining delegation depth.
    pub depth: WireDepth,
    /// Milliseconds until expiry on the broker's monotonic clock; `None` if
    /// bounded only by the session.
    pub expires_in_millis: Option<u64>,
    /// Status.
    pub status: WireCapStatus,
}

/// Adapter-specific result of a consumed operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WireOperationResult {
    /// Snapshot content.
    FileSnapshot {
        /// Bytes read (at most the requested `max_bytes`).
        bytes: ContentBytes,
        /// Whether the file was longer than `max_bytes`.
        truncated: bool,
    },
    /// Replacement committed.
    FileReplaced {
        /// Bytes written.
        bytes_written: u64,
    },
    /// HTTP response.
    Https {
        /// Status code.
        status: u16,
        /// Response headers.
        headers: WireHeaders,
        /// Response body (possibly truncated to the grant's limit).
        body: ContentBytes,
        /// Whether the body was truncated.
        truncated: bool,
    },
}

/// Typed error codes (§9.2). Denials are deliberately coarse where finer
/// detail would give an oracle to a principal that does not own the
/// capability: "unknown" and "not yours" are both [`ErrorCode::UnknownCapability`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorCode {
    /// Frame carried a protocol version this peer does not speak.
    UnsupportedVersion,
    /// Frame could not be parsed.
    Malformed,
    /// Frame or field exceeded a size/count limit.
    LimitExceeded,
    /// Caller could not be authenticated from the transport.
    Unauthenticated,
    /// Caller is authenticated but not permitted to make this call.
    PermissionDenied,
    /// Capability does not exist or is not owned by the caller.
    UnknownCapability,
    /// Capability expired.
    Expired,
    /// Capability or an ancestor was revoked.
    Revoked,
    /// Operation is outside the capability's scope.
    ScopeViolation,
    /// Requested child/attenuated scope is not a subset of the parent.
    NotSubset,
    /// Not enough budget.
    InsufficientBudget,
    /// Delegation depth exhausted or child depth not strictly lower.
    DepthExhausted,
    /// Requested expiry is later than permitted.
    ExpiryTooLate,
    /// Recipient principal is unknown or inactive.
    InvalidRecipient,
    /// Request id reused with different content.
    RequestIdConflict,
    /// Request id references a request from a stale epoch.
    StaleEpoch,
    /// Human approval was denied.
    ApprovalDenied,
    /// Human approval timed out.
    ApprovalTimeout,
    /// Launch profile unknown or not permitted.
    InvalidProfile,
    /// Rate or quota limit hit.
    RateLimited,
    /// Adapter failed before any effect could have occurred.
    AdapterFailed,
    /// Effect outcome is uncertain; it will not be retried.
    EffectUnknown,
    /// Broker is shutting down or unavailable.
    Unavailable,
    /// Internal error; fail closed.
    Internal,
}

/// Responses from the broker.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Response {
    /// Root grant created.
    GrantIssued {
        /// Request id.
        request_id: RequestId,
        /// New capability.
        cap_id: CapId,
    },
    /// Operation consumed and executed.
    Consumed {
        /// Request id.
        request_id: RequestId,
        /// Reservation used.
        reservation_id: ReservationId,
        /// Result.
        result: WireOperationResult,
    },
    /// Repeated request id: status of the earlier reservation. No new
    /// dispatch took place.
    PriorReservation {
        /// Request id.
        request_id: RequestId,
        /// Reservation.
        reservation_id: ReservationId,
        /// Status.
        status: WireReservationStatus,
    },
    /// Child created and delivered.
    Delegated {
        /// Request id.
        request_id: RequestId,
        /// Child capability.
        child_cap_id: CapId,
    },
    /// Capability attenuated.
    Attenuated {
        /// Request id.
        request_id: RequestId,
        /// Capability.
        cap_id: CapId,
    },
    /// Ownership moved.
    Transferred {
        /// Request id.
        request_id: RequestId,
        /// Capability.
        cap_id: CapId,
    },
    /// Balance discarded.
    Dropped {
        /// Request id.
        request_id: RequestId,
    },
    /// Metadata.
    Inspected(WireCapabilityView),
    /// Child sandbox launched.
    Spawned {
        /// Request id.
        request_id: RequestId,
        /// New principal.
        agent: WireAgentId,
    },
    /// Subtree revoked.
    Revoked {
        /// Request id.
        request_id: RequestId,
    },
    /// Denial or failure.
    Error {
        /// Request id, if known.
        request_id: Option<RequestId>,
        /// Code.
        code: ErrorCode,
        /// Non-sensitive diagnostic.
        detail: BoundedString<MAX_DETAIL>,
    },
}

/// Client-to-broker message body.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClientMessage {
    /// Echoed in the response.
    pub correlation_id: CorrelationId,
    /// The request.
    pub request: Request,
}

/// Broker-to-client message body.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServerMessage {
    /// Correlation id of the request this answers.
    pub correlation_id: CorrelationId,
    /// The response.
    pub response: Response,
}
