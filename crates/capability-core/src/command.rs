//! Authenticated command inputs, effects and typed denials.
//!
//! The broker authenticates the peer (kernel-observed identity, §9.1) and
//! only then constructs an [`AuthenticatedCommand`]. Caller identity is never
//! a field supplied by the client: agent commands carry the caller as a
//! separate, broker-established [`AgentId`], and administrative commands can
//! only be expressed as [`AuthenticatedCommand::Operator`], which the broker
//! must only construct for its separate operator endpoint.
//!
//! Commands are `Serialize`/`Deserialize` so the trusted journal can record
//! and replay them; deserializing a command from an *untrusted* source and
//! passing it to [`crate::step`] would bypass authentication and is a broker
//! bug. Untrusted wire types live in the protocol crate.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::budget::Tick;
use crate::ids::{AgentId, CapabilityId, Nonce, PoolId, RequestId, ReservationId, RootId};
use crate::scope::Operation;
use crate::state::{NotLive, Outcome, ReservationStatus, RootKind, Terms};

/// The exact canonical grant request that the human approved (§8.1). Only
/// the fields the core acts on are represented; protocol version,
/// installation identity and operator identity are bound and checked by the
/// approval service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRequest {
    /// Authority epoch the approval was issued for.
    pub epoch: u64,
    /// Recipient principal.
    pub recipient: AgentId,
    /// Exact terms to mint.
    pub terms: Terms,
    /// The approval itself is only redeemable while `now < request_expires`.
    pub request_expires: Tick,
}

/// Approval evidence whose FIDO2 assertion has *already been verified* by the
/// trusted approval service against the enrolled credential, RP id,
/// client-data hash (binding `nonce` and the exact `request`) and signed
/// user-presence flag.
///
/// Trusted assumption (proof register A3): only the approval service
/// constructs this value, and only after successful verification. The core
/// enforces freshness (single redemption of `nonce`), epoch and request
/// expiry, and mints exactly `request.terms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedApproval {
    nonce: Nonce,
    request: GrantRequest,
}

impl VerifiedApproval {
    /// Wrap verified evidence. Callable only by the trusted approval path.
    pub const fn new(nonce: Nonce, request: GrantRequest) -> Self {
        Self { nonce, request }
    }
    /// The nonce bound into the signed payload.
    pub const fn nonce(&self) -> Nonce {
        self.nonce
    }
    /// The exact approved request.
    pub const fn request(&self) -> &GrantRequest {
        &self.request
    }
}

/// Commands an authenticated workload principal may issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentCommand {
    /// CONSUME one unit and reserve a single dispatch of `operation`.
    Consume {
        /// Principal-scoped request id (idempotency key).
        request_id: RequestId,
        /// Capability to charge.
        capability: CapabilityId,
        /// Exact canonical operation.
        operation: Operation,
    },
    /// SPLIT: create a fresh same-owner child with attenuated terms; the
    /// child's finite budget is deducted from the parent.
    Split {
        /// Parent.
        capability: CapabilityId,
        /// Child terms.
        terms: Terms,
    },
    /// DELEGATE: atomic split + ownership update to `recipient`, consuming one
    /// delegation generation (not two).
    Delegate {
        /// Parent.
        capability: CapabilityId,
        /// New owner of the child.
        recipient: AgentId,
        /// Child terms.
        terms: Terms,
    },
    /// ATTENUATE in place: every component may only decrease; discarded
    /// budget is accounted. No effect on existing descendants.
    Attenuate {
        /// Target.
        capability: CapabilityId,
        /// New (smaller or equal) terms.
        terms: Terms,
    },
    /// TRANSFER ownership, preserving identity and provenance; decrements a
    /// finite depth by one.
    Transfer {
        /// Target.
        capability: CapabilityId,
        /// New owner.
        recipient: AgentId,
    },
    /// REVOKE `capability` and (prospectively) its whole subtree. An agent
    /// may revoke a capability it owns or one descended from a capability it
    /// currently owns.
    Revoke {
        /// Target.
        capability: CapabilityId,
    },
    /// DROP: discard the remaining balance; descendants are unaffected.
    Drop {
        /// Target.
        capability: CapabilityId,
    },
}

/// Commands from the trusted operator / broker administrative endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdminCommand {
    /// Allocate a fresh principal in the current epoch (launcher, §9.1).
    CreatePrincipal,
    /// Terminate a principal: its capabilities stop authorizing. Capabilities
    /// it already delegated to other principals are *not* revoked (§4.4);
    /// revoke explicitly if desired.
    TerminatePrincipal {
        /// Principal to terminate.
        agent: AgentId,
    },
    /// Record the passage of trusted time (no other effect).
    AdvanceClock,
    /// Fail-closed restart (§11): increment the epoch, terminate every
    /// principal, abandon unresolved reservations, keep spent nonces and all
    /// history. The only transition allowed to move the clock backwards
    /// (a fresh monotonic clock after restart), which is safe because no
    /// capability of an earlier epoch can be live again.
    BumpEpoch,
    /// MINT a root from verified human approval: atomically redeem the nonce
    /// and create the root.
    Mint {
        /// Verified evidence.
        approval: VerifiedApproval,
    },
    /// Install an operator baseline grant (R2): a root recorded as
    /// [`RootKind::Baseline`], not backed by a hardware approval.
    InstallBaseline {
        /// Recipient principal.
        recipient: AgentId,
        /// Exact terms.
        terms: Terms,
    },
    /// Operator REVOKE of any capability and its subtree.
    Revoke {
        /// Target.
        capability: CapabilityId,
    },
    /// Record the adapter outcome of a reservation (no refund on failure).
    RecordOutcome {
        /// Reservation.
        reservation: ReservationId,
        /// Outcome.
        outcome: Outcome,
    },
    /// Appended last: the journal encodes commands by variant index.
    ///
    /// Prune every record that belongs to an earlier epoch (ADR-0031):
    /// principals of earlier epochs, roots issued in earlier epochs with
    /// their whole capability trees, pools and reservations, and the
    /// request-id index entries of those reservations. Such records can never
    /// authorize again (their owners are terminated and stale), so pruning
    /// them changes no answer about current authority; it only frees the
    /// configured record capacity for the current epoch.
    ///
    /// Kept: every spent nonce (T7), the id allocation counters (ids are
    /// never reused), and cumulative totals of the pruned pools
    /// ([`crate::State::retired`]): `initial = consumed + discarded`, where
    /// `discarded` includes the balances stranded in the pruned records.
    /// The broker journals this command at startup, right after `BumpEpoch`,
    /// so replay reproduces it.
    CompactEpoch,
}

/// A command together with its externally established caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthenticatedCommand {
    /// Issued by an authenticated workload principal.
    Agent {
        /// Broker-established identity of the peer.
        caller: AgentId,
        /// The command.
        command: AgentCommand,
    },
    /// Issued over the trusted operator endpoint.
    Operator(AdminCommand),
}

impl AuthenticatedCommand {
    /// Agent command with broker-authenticated caller.
    pub const fn agent(caller: AgentId, command: AgentCommand) -> Self {
        AuthenticatedCommand::Agent { caller, command }
    }
    /// Operator command.
    pub const fn operator(command: AdminCommand) -> Self {
        AuthenticatedCommand::Operator(command)
    }
}

/// A single-dispatch authorization handed to an adapter. Deliberately not
/// `Clone`/`Copy`/`Deserialize`: the adapter executes at most one dispatch
/// per reservation, and a reservation cannot be fabricated from bytes.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Reservation {
    pub(crate) id: ReservationId,
    pub(crate) owner: AgentId,
    pub(crate) request_id: RequestId,
    pub(crate) capability: CapabilityId,
    pub(crate) root: RootId,
    pub(crate) pool: Option<PoolId>,
    pub(crate) operation: Operation,
}

impl Reservation {
    /// Id.
    pub fn id(&self) -> ReservationId {
        self.id
    }
    /// Principal on whose behalf the effect runs.
    pub fn owner(&self) -> AgentId {
        self.owner
    }
    /// Request id it is bound to.
    pub fn request_id(&self) -> RequestId {
        self.request_id
    }
    /// Capability charged.
    pub fn capability(&self) -> CapabilityId {
        self.capability
    }
    /// Root authorization (audit, R8).
    pub fn root(&self) -> RootId {
        self.root
    }
    /// Pool charged.
    pub fn pool(&self) -> Option<PoolId> {
        self.pool
    }
    /// The exact operation the adapter may perform once.
    pub fn operation(&self) -> Operation {
        self.operation
    }
}

/// Successful result of [`crate::step`]. Pure data; the broker performs any
/// I/O after durably committing it.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub enum Effect {
    /// New principal.
    PrincipalCreated {
        /// Its id.
        agent: AgentId,
    },
    /// Principal terminated.
    PrincipalTerminated {
        /// Its id.
        agent: AgentId,
    },
    /// Clock recorded.
    ClockAdvanced {
        /// New clock.
        now: Tick,
    },
    /// Epoch incremented.
    EpochAdvanced {
        /// New epoch.
        epoch: u64,
        /// Principals terminated by the bump.
        terminated_principals: u64,
        /// Reservations moved to `Abandoned`.
        abandoned_reservations: u64,
    },
    /// Root created (MINT or baseline).
    RootCreated {
        /// Root id.
        root: RootId,
        /// Root capability.
        capability: CapabilityId,
        /// Provenance.
        kind: RootKind,
    },
    /// CONSUME succeeded; dispatch at most once.
    Reserved(Reservation),
    /// Repeated request id: no new reservation, no state change.
    AlreadyReserved {
        /// The earlier reservation.
        reservation: ReservationId,
        /// Its current status.
        status: ReservationStatus,
    },
    /// SPLIT or DELEGATE created a child.
    Derived {
        /// Parent.
        parent: CapabilityId,
        /// New child.
        child: CapabilityId,
        /// Child owner.
        owner: AgentId,
    },
    /// ATTENUATE applied.
    Attenuated {
        /// Target.
        capability: CapabilityId,
        /// Finite units moved to D.
        discarded: u64,
    },
    /// TRANSFER applied.
    Transferred {
        /// Target.
        capability: CapabilityId,
        /// Previous owner.
        from: AgentId,
        /// New owner.
        to: AgentId,
    },
    /// REVOKE applied.
    Revoked {
        /// Target.
        capability: CapabilityId,
    },
    /// DROP applied.
    Dropped {
        /// Target.
        capability: CapabilityId,
        /// Finite units moved to D.
        discarded: u64,
    },
    /// Reservation outcome recorded.
    OutcomeRecorded {
        /// Reservation.
        reservation: ReservationId,
        /// New status.
        status: ReservationStatus,
    },
    /// [`AdminCommand::CompactEpoch`]: what was pruned. The unit totals are
    /// those of the pruned pools only; `initial == consumed + discarded`.
    EpochCompacted {
        /// Principal records removed.
        principals: u64,
        /// Capability records removed.
        capabilities: u64,
        /// Root records removed.
        roots: u64,
        /// Pools removed.
        pools: u64,
        /// Reservation records (and request-id entries) removed.
        reservations: u64,
        /// N of the pruned pools.
        initial: u128,
        /// U of the pruned pools.
        consumed: u128,
        /// D of the pruned pools (explicit and stranded).
        discarded: u128,
    },
}

/// Bounded resource named in [`Denial::CapacityExceeded`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Resource {
    /// Capability records.
    Capabilities,
    /// Principal records.
    Principals,
    /// Root records.
    Roots,
    /// Reservation records.
    Reservations,
}

/// Typed denial. A denial never changes the state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Denial {
    /// `now` is earlier than the recorded clock (only `BumpEpoch` may reset).
    ClockRegression,
    /// Caller/recipient id belongs to an earlier epoch.
    StaleEpoch,
    /// Caller/recipient is not a known principal.
    UnknownPrincipal,
    /// Caller/recipient has been terminated.
    PrincipalTerminated,
    /// No such capability.
    UnknownCapability,
    /// Caller is not the owner (copied identifier, §15).
    NotOwner,
    /// Capability is not live.
    NotLive(NotLive),
    /// Scope does not permit the operation.
    OperationNotPermitted,
    /// Not enough budget.
    InsufficientBudget,
    /// Depth zero: no split, delegate or transfer.
    NotDelegatable,
    /// Requested scope is empty / malformed.
    InvalidScope,
    /// Requested scope is not a subset of the source scope.
    ScopeNotAttenuated,
    /// Requested budget exceeds the source or is unlimited from finite.
    BudgetNotAttenuated,
    /// Requested depth not strictly lower (derive) / not lower-or-equal
    /// (attenuate).
    DepthNotAttenuated,
    /// Requested expiry later than the source.
    ExpiryNotAttenuated,
    /// Requested terms are already expired at `now`.
    AlreadyExpired,
    /// Zero allocation for a new grant.
    ZeroAllocation,
    /// Transfer to the current owner.
    SelfTransfer,
    /// Caller may not revoke this capability.
    NotAuthorizedToRevoke,
    /// Capability already revoked.
    AlreadyRevoked,
    /// Principal already terminated.
    AlreadyTerminated,
    /// Approval nonce already redeemed.
    NonceReused,
    /// Approval issued for a different epoch.
    ApprovalEpochMismatch,
    /// Approval request has expired.
    ApprovalExpired,
    /// Request id reused with different content.
    RequestIdConflict,
    /// No such reservation.
    UnknownReservation,
    /// Reservation outcome already recorded.
    ReservationAlreadyResolved,
    /// A configured bound would be exceeded.
    CapacityExceeded(Resource),
    /// Lineage would exceed `max_lineage_length`.
    LineageTooLong,
    /// A counter or id space would overflow.
    ArithmeticOverflow,
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for Denial {}
