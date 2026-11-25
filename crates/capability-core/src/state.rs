//! Ledger state (spec §4.4) and read-only queries.
//!
//! All fields are private. The only way to change a [`State`] is
//! [`crate::step`]; the only way to obtain one is [`State::new`],
//! [`State::replay`] or deserialization, which re-checks every invariant
//! ([`crate::check_invariant`]) and refuses an inconsistent snapshot.
//!
//! `State` intentionally does not implement `Clone`: there is one ledger.
//! It implements `PartialEq` so tests can assert that denials do not mutate.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};

use crate::budget::{Budget, Depth, Expiry, Tick};
use crate::command::{AuthenticatedCommand, Denial};
use crate::ids::{AgentId, CapabilityId, Nonce, PoolId, RequestId, ReservationId, RootId};
use crate::invariant::{InvariantViolation, check_invariant};
use crate::scope::{Operation, Scope};
use crate::seq_map;

/// Configured resource bounds. Exceeding any bound is a denial
/// ([`Denial::CapacityExceeded`] / [`Denial::LineageTooLong`]), never a panic
/// or silent truncation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// Maximum number of capability records ever held (live or dead).
    pub max_capabilities: u64,
    /// Maximum number of principal records.
    pub max_principals: u64,
    /// Maximum number of root records (approved mints + baseline grants).
    pub max_roots: u64,
    /// Maximum number of reservation records.
    pub max_reservations: u64,
    /// Maximum lineage length: a root has generation 0, a child of a node of
    /// generation `g` has generation `g + 1`, which must be `<=` this bound.
    /// Bounds every ancestor walk, including for unlimited-depth chains.
    pub max_lineage_length: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_capabilities: 100_000,
            max_principals: 10_000,
            max_roots: 10_000,
            max_reservations: 1_000_000,
            max_lineage_length: 64,
        }
    }
}

/// Grant terms: scope, budget, delegation depth and expiry. Used both as
/// command input (requested terms) and as each capability's immutable
/// creation-time snapshot. A description, not authority, hence `Copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Terms {
    /// Permitted operations.
    pub scope: Scope,
    /// Use budget (for a child: the allocation moved from the parent).
    pub budget: Budget,
    /// Delegation depth.
    pub depth: Depth,
    /// Expiry.
    pub expiry: Expiry,
}

/// Lifecycle status of a principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrincipalStatus {
    /// May authenticate and own live authority.
    Active,
    /// Permanently inactive; its capabilities no longer authorize anything.
    Terminated,
}

/// Recorded status of a capability. Expiry and owner/epoch invalidity are
/// *not* recorded here; they are evaluated by [`State::live`] at a given
/// time. All three non-`Live` statuses are permanent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    /// Not explicitly invalidated.
    Live,
    /// Owner discarded it (DROP). Descendants are unaffected.
    Dropped,
    /// Revoked; it and every descendant cease to authorize.
    Revoked,
}

/// Provenance of a root authorization (R2, R8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RootKind {
    /// Minted from a fresh, verified human approval; the nonce is redeemed.
    Approved {
        /// Redeemed approval nonce.
        nonce: Nonce,
    },
    /// Operator-installed baseline grant (trusted administrative action,
    /// recorded separately; not backed by a FIDO2 assertion).
    Baseline,
}

/// Immutable record of an originating authorization.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootRecord {
    pub(crate) id: RootId,
    pub(crate) capability: CapabilityId,
    pub(crate) kind: RootKind,
    pub(crate) recipient: AgentId,
    pub(crate) terms: Terms,
    pub(crate) epoch: u64,
    pub(crate) issued_at: Tick,
}

impl RootRecord {
    /// Root id.
    pub fn id(&self) -> RootId {
        self.id
    }
    /// The root capability created by this authorization.
    pub fn capability(&self) -> CapabilityId {
        self.capability
    }
    /// Approved (with nonce) or baseline.
    pub fn kind(&self) -> RootKind {
        self.kind
    }
    /// Original recipient.
    pub fn recipient(&self) -> AgentId {
        self.recipient
    }
    /// Exact granted terms.
    pub fn terms(&self) -> Terms {
        self.terms
    }
    /// Epoch of issuance.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Trusted time of issuance.
    pub fn issued_at(&self) -> Tick {
        self.issued_at
    }
}

/// A capability record `c = (id, root, parent, owner, scope, budget, depth,
/// expiry, status)` (§4.3), plus its immutable creation snapshot (`origin`),
/// its finite allocation boundary (`pool`) and lineage `generation`.
///
/// Not `Clone`: records are owned by the ledger.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    pub(crate) id: CapabilityId,
    pub(crate) root: RootId,
    pub(crate) parent: Option<CapabilityId>,
    pub(crate) owner: AgentId,
    pub(crate) origin: Terms,
    pub(crate) scope: Scope,
    pub(crate) budget: Budget,
    pub(crate) depth: Depth,
    pub(crate) expiry: Expiry,
    pub(crate) pool: Option<PoolId>,
    pub(crate) generation: u32,
    pub(crate) status: Status,
}

impl Capability {
    /// Identity.
    pub fn id(&self) -> CapabilityId {
        self.id
    }
    /// Originating root.
    pub fn root(&self) -> RootId {
        self.root
    }
    /// Immutable provenance edge (`None` for a root capability).
    pub fn parent(&self) -> Option<CapabilityId> {
        self.parent
    }
    /// Current owner.
    pub fn owner(&self) -> AgentId {
        self.owner
    }
    /// Terms at creation (never changes).
    pub fn origin(&self) -> Terms {
        self.origin
    }
    /// Current scope (only ever narrowed).
    pub fn scope(&self) -> Scope {
        self.scope
    }
    /// Current remaining balance (finite) or `Unlimited`.
    pub fn budget(&self) -> Budget {
        self.budget
    }
    /// Current delegation depth.
    pub fn depth(&self) -> Depth {
        self.depth
    }
    /// Current expiry.
    pub fn expiry(&self) -> Expiry {
        self.expiry
    }
    /// Finite allocation boundary this balance belongs to (`None` iff the
    /// budget is unlimited).
    pub fn pool(&self) -> Option<PoolId> {
        self.pool
    }
    /// Lineage generation (root = 0).
    pub fn generation(&self) -> u32 {
        self.generation
    }
    /// Recorded status.
    pub fn status(&self) -> Status {
        self.status
    }
}

/// A finite allocation boundary (§6.1): a finite root, or a finite
/// allocation carved out of an unlimited capability (by SPLIT/DELEGATE or by
/// ATTENUATE from unlimited to finite). All finite descendants of the anchor
/// draw from the same pool.
///
/// Stored identity (checked by [`crate::check_invariant`]):
/// `initial == consumed + discarded + Σ balance(c) for c in pool`.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pool {
    pub(crate) id: PoolId,
    pub(crate) root: RootId,
    pub(crate) anchor: CapabilityId,
    pub(crate) initial: u64,
    pub(crate) consumed: u64,
    pub(crate) discarded: u64,
}

/// Accounting view of one finite allocation boundary at a given time:
/// `initial == consumed + live + discarded` (N = U + L + D).
///
/// * `consumed` (U): units reserved by CONSUME. Never refunded.
/// * `live` (L): balances held by capabilities that are live at the time.
/// * `discarded` (D): balances explicitly discarded by DROP/ATTENUATE
///   (`discarded_explicit`) plus balances *stranded* in capabilities that are
///   no longer live (revoked or below a revoked ancestor, expired, owner
///   terminated, stale epoch) — `discarded_stranded`. Every record's balance
///   is counted exactly once, in L or in D, according to liveness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolAccount {
    /// Pool id.
    pub pool: PoolId,
    /// Root lineage.
    pub root: RootId,
    /// Capability that established the boundary.
    pub anchor: CapabilityId,
    /// N.
    pub initial: u64,
    /// U.
    pub consumed: u64,
    /// L.
    pub live: u64,
    /// Explicitly discarded part of D.
    pub discarded_explicit: u64,
    /// Stranded (invalidated but still recorded) part of D.
    pub discarded_stranded: u64,
}

impl PoolAccount {
    /// D = explicit + stranded (saturating only for display; the invariant
    /// checker uses checked arithmetic).
    pub fn discarded(&self) -> u64 {
        self.discarded_explicit
            .saturating_add(self.discarded_stranded)
    }
}

/// Cumulative accounting of the pools pruned by
/// [`crate::AdminCommand::CompactEpoch`] (ADR-0031). Every pruned pool had no
/// live member (all of its holders belonged to an earlier epoch), so its
/// N = U + L + D identity had L = 0; the balances still held by its records
/// are added to `discarded` (they were already counted as stranded D).
/// Checked by [`crate::check_invariant`]: `initial == consumed + discarded`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetiredPools {
    /// Number of pools pruned.
    pub pools: u64,
    /// Σ N of the pruned pools.
    pub initial: u128,
    /// Σ U of the pruned pools.
    pub consumed: u128,
    /// Σ D (explicit and stranded) of the pruned pools.
    pub discarded: u128,
}

/// Dispatch status of a reservation. No transition ever refunds budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReservationStatus {
    /// Reserved; the adapter may dispatch at most once.
    Reserved,
    /// Adapter reported success.
    Completed,
    /// Adapter reported failure (budget stays spent).
    Failed,
    /// Adapter could not determine the outcome.
    Unknown,
    /// Unresolved at an epoch change (crash/restart); never replayed.
    Abandoned,
}

/// Adapter-reported outcome for [`crate::AdminCommand::RecordOutcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    /// Effect happened.
    Completed,
    /// Effect definitely did not happen.
    Failed,
    /// Uncertain.
    Unknown,
}

/// Ledger entry for one CONSUME (the consumption ledger of §4.4).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservationRecord {
    pub(crate) id: ReservationId,
    pub(crate) owner: AgentId,
    pub(crate) request_id: RequestId,
    pub(crate) capability: CapabilityId,
    pub(crate) root: RootId,
    pub(crate) pool: Option<PoolId>,
    pub(crate) operation: Operation,
    pub(crate) status: ReservationStatus,
    pub(crate) reserved_at: Tick,
}

impl ReservationRecord {
    /// Id.
    pub fn id(&self) -> ReservationId {
        self.id
    }
    /// Authenticated principal that consumed.
    pub fn owner(&self) -> AgentId {
        self.owner
    }
    /// Principal-scoped request id.
    pub fn request_id(&self) -> RequestId {
        self.request_id
    }
    /// Capability charged.
    pub fn capability(&self) -> CapabilityId {
        self.capability
    }
    /// Root lineage (for audit, R8).
    pub fn root(&self) -> RootId {
        self.root
    }
    /// Pool charged (`None` for an unlimited capability).
    pub fn pool(&self) -> Option<PoolId> {
        self.pool
    }
    /// Exact authorized operation.
    pub fn operation(&self) -> Operation {
        self.operation
    }
    /// Current status.
    pub fn status(&self) -> ReservationStatus {
        self.status
    }
    /// Trusted time of reservation.
    pub fn reserved_at(&self) -> Tick {
        self.reserved_at
    }
}

/// Why a capability is not live (see [`State::live`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotLive {
    /// No such capability.
    Unknown,
    /// The capability itself was revoked.
    Revoked,
    /// The capability was dropped.
    Dropped,
    /// Its expiry has elapsed.
    Expired,
    /// An ancestor was revoked.
    AncestorRevoked(CapabilityId),
    /// An ancestor's creation-time expiry has elapsed (implied by the
    /// capability's own expiry under the attenuation invariant; checked
    /// defensively).
    AncestorExpired(CapabilityId),
    /// Owner is terminated.
    OwnerTerminated,
    /// Owner is unknown to the ledger (corrupt state; fail closed).
    OwnerUnknown,
    /// Owner belongs to an earlier authority epoch.
    StaleEpoch,
    /// Lineage is missing a parent or exceeds the configured bound (corrupt
    /// state; fail closed).
    LineageCorrupt,
}

/// The authority ledger `S = (principals, capabilities, roots, spent_nonces,
/// consumption_ledger, revoked, epoch, sequence, clock)` (§4.4).
///
/// `revoked` is represented by [`Status::Revoked`]; the consumption ledger by
/// the reservation records and per-pool counters.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct State {
    pub(crate) limits: Limits,
    pub(crate) epoch: u64,
    pub(crate) sequence: u64,
    pub(crate) clock: Tick,
    pub(crate) next_agent_serial: u64,
    pub(crate) next_capability: u128,
    pub(crate) next_root: u128,
    pub(crate) next_pool: u64,
    pub(crate) next_reservation: u64,
    #[serde(with = "seq_map")]
    pub(crate) principals: BTreeMap<AgentId, PrincipalStatus>,
    #[serde(with = "seq_map")]
    pub(crate) capabilities: BTreeMap<CapabilityId, Capability>,
    #[serde(with = "seq_map")]
    pub(crate) roots: BTreeMap<RootId, RootRecord>,
    #[serde(with = "seq_map")]
    pub(crate) pools: BTreeMap<PoolId, Pool>,
    #[serde(with = "seq_map")]
    pub(crate) spent_nonces: BTreeMap<Nonce, RootId>,
    #[serde(with = "seq_map")]
    pub(crate) reservations: BTreeMap<ReservationId, ReservationRecord>,
    #[serde(with = "seq_map")]
    pub(crate) requests: BTreeMap<(AgentId, RequestId), ReservationId>,
    /// Every root id below this was pruned by `CompactEpoch`; their spent
    /// nonces remain in `spent_nonces`.
    pub(crate) retired_roots_below: u128,
    /// Accounting of pruned pools.
    pub(crate) retired: RetiredPools,
}

/// Unchecked mirror of [`State`] used only for deserialization.
#[derive(Deserialize)]
struct StateRepr {
    limits: Limits,
    epoch: u64,
    sequence: u64,
    clock: Tick,
    next_agent_serial: u64,
    next_capability: u128,
    next_root: u128,
    next_pool: u64,
    next_reservation: u64,
    #[serde(with = "seq_map")]
    principals: BTreeMap<AgentId, PrincipalStatus>,
    #[serde(with = "seq_map")]
    capabilities: BTreeMap<CapabilityId, Capability>,
    #[serde(with = "seq_map")]
    roots: BTreeMap<RootId, RootRecord>,
    #[serde(with = "seq_map")]
    pools: BTreeMap<PoolId, Pool>,
    #[serde(with = "seq_map")]
    spent_nonces: BTreeMap<Nonce, RootId>,
    #[serde(with = "seq_map")]
    reservations: BTreeMap<ReservationId, ReservationRecord>,
    #[serde(with = "seq_map")]
    requests: BTreeMap<(AgentId, RequestId), ReservationId>,
    retired_roots_below: u128,
    retired: RetiredPools,
}

impl<'de> Deserialize<'de> for State {
    /// Deserializes a snapshot and rejects it unless [`check_invariant`]
    /// holds. An inconsistent journal snapshot cannot produce a `State`.
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let r = StateRepr::deserialize(d)?;
        let s = State {
            limits: r.limits,
            epoch: r.epoch,
            sequence: r.sequence,
            clock: r.clock,
            next_agent_serial: r.next_agent_serial,
            next_capability: r.next_capability,
            next_root: r.next_root,
            next_pool: r.next_pool,
            next_reservation: r.next_reservation,
            principals: r.principals,
            capabilities: r.capabilities,
            roots: r.roots,
            pools: r.pools,
            spent_nonces: r.spent_nonces,
            reservations: r.reservations,
            requests: r.requests,
            retired_roots_below: r.retired_roots_below,
            retired: r.retired,
        };
        check_invariant(&s)
            .map_err(|v| serde::de::Error::custom(format!("invariant violation: {v:?}")))?;
        Ok(s)
    }
}

/// Failure while rebuilding a state from a command log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    /// Entry `index` was denied: the log does not match this ledger.
    Denied {
        /// Zero-based log index.
        index: usize,
        /// Denial reason.
        denial: Denial,
    },
    /// The rebuilt state failed the invariant check (indicates a core bug).
    Invariant(InvariantViolation),
}

impl State {
    /// Empty ledger at epoch 0, tick 0.
    ///
    /// ensures: check_invariant(&result).is_ok()
    pub fn new(limits: Limits) -> State {
        State {
            limits,
            epoch: 0,
            sequence: 0,
            clock: Tick::ZERO,
            next_agent_serial: 0,
            next_capability: 0,
            next_root: 0,
            next_pool: 0,
            next_reservation: 0,
            principals: BTreeMap::new(),
            capabilities: BTreeMap::new(),
            roots: BTreeMap::new(),
            pools: BTreeMap::new(),
            spent_nonces: BTreeMap::new(),
            reservations: BTreeMap::new(),
            requests: BTreeMap::new(),
            retired_roots_below: 0,
            retired: RetiredPools::default(),
        }
    }

    /// Rebuild a ledger by replaying a log of *successful* commands with the
    /// trusted time each was applied at. Any denial means the log and the
    /// core disagree and is reported (fail closed).
    pub fn replay<I>(limits: Limits, log: I) -> Result<State, ReplayError>
    where
        I: IntoIterator<Item = (AuthenticatedCommand, Tick)>,
    {
        let mut s = State::new(limits);
        for (index, (cmd, now)) in log.into_iter().enumerate() {
            crate::step(&mut s, cmd, now)
                .map_err(|denial| ReplayError::Denied { index, denial })?;
        }
        check_invariant(&s).map_err(ReplayError::Invariant)?;
        Ok(s)
    }

    /// Configured bounds.
    pub fn limits(&self) -> Limits {
        self.limits
    }
    /// Current authority epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Number of successful state-changing transitions.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Last trusted time at which a transition was committed.
    pub fn clock(&self) -> Tick {
        self.clock
    }
    /// Principal status, if known.
    pub fn principal(&self, agent: AgentId) -> Option<PrincipalStatus> {
        self.principals.get(&agent).copied()
    }
    /// Is `agent` an active principal of the current epoch?
    pub fn is_active(&self, agent: AgentId) -> bool {
        agent.epoch() == self.epoch && self.principals.get(&agent) == Some(&PrincipalStatus::Active)
    }
    /// Capability record (metadata only; grants nothing).
    pub fn capability(&self, id: CapabilityId) -> Option<&Capability> {
        self.capabilities.get(&id)
    }
    /// All capability records in id order.
    pub fn capabilities(&self) -> impl Iterator<Item = &Capability> {
        self.capabilities.values()
    }
    /// Root record.
    pub fn root(&self, id: RootId) -> Option<&RootRecord> {
        self.roots.get(&id)
    }
    /// All root records in id order.
    pub fn roots(&self) -> impl Iterator<Item = &RootRecord> {
        self.roots.values()
    }
    /// Has this approval nonce been redeemed (in any epoch)?
    pub fn is_nonce_spent(&self, nonce: &Nonce) -> bool {
        self.spent_nonces.contains_key(nonce)
    }
    /// All reservation records in id order.
    pub fn reservations(&self) -> impl Iterator<Item = &ReservationRecord> {
        self.reservations.values()
    }
    /// Root ids below this value were pruned by `CompactEpoch`.
    pub fn retired_roots_below(&self) -> u128 {
        self.retired_roots_below
    }
    /// Cumulative accounting of pools pruned by `CompactEpoch`.
    pub fn retired(&self) -> RetiredPools {
        self.retired
    }
    /// Reservation record.
    pub fn reservation(&self, id: ReservationId) -> Option<&ReservationRecord> {
        self.reservations.get(&id)
    }
    /// Reservation previously created for `(agent, request_id)`, if any.
    pub fn reservation_for_request(
        &self,
        agent: AgentId,
        request_id: RequestId,
    ) -> Option<&ReservationRecord> {
        self.requests
            .get(&(agent, request_id))
            .and_then(|r| self.reservations.get(r))
    }

    /// Provenance path from `id` up to its root (inclusive), for audit and
    /// lineage display. Bounded by `max_lineage_length + 1` steps.
    pub fn lineage(&self, id: CapabilityId) -> Vec<CapabilityId> {
        let mut out = Vec::new();
        let mut cur = Some(id);
        let bound = (self.limits.max_lineage_length as usize).saturating_add(1);
        while let Some(c) = cur {
            if out.len() >= bound {
                break;
            }
            match self.capabilities.get(&c) {
                Some(rec) => {
                    out.push(c);
                    cur = rec.parent;
                }
                None => break,
            }
        }
        out
    }

    /// `Live(c, S, now)` (§4.4): `c` exists, has status `Live`, has not
    /// expired, its owner is an active principal of the current epoch, and
    /// no ancestor is revoked or past its creation-time expiry. Parent
    /// *owner* termination and parent DROP do not affect descendants;
    /// descendant authority is not conditioned on parent balance.
    ///
    /// Liveness is monotone: once `Err` at `(S, t)`, it is `Err` in every
    /// later state at every later time of the same epoch, and in every later
    /// epoch (stale owner).
    pub fn live(&self, id: CapabilityId, now: Tick) -> Result<&Capability, NotLive> {
        let cap = self.capabilities.get(&id).ok_or(NotLive::Unknown)?;
        match cap.status {
            Status::Live => {}
            Status::Dropped => return Err(NotLive::Dropped),
            Status::Revoked => return Err(NotLive::Revoked),
        }
        if cap.expiry.is_expired_at(now) {
            return Err(NotLive::Expired);
        }
        if cap.owner.epoch() != self.epoch {
            return Err(NotLive::StaleEpoch);
        }
        match self.principals.get(&cap.owner) {
            None => return Err(NotLive::OwnerUnknown),
            Some(PrincipalStatus::Terminated) => return Err(NotLive::OwnerTerminated),
            Some(PrincipalStatus::Active) => {}
        }
        // Ancestor walk, bounded by the lineage limit so that it terminates
        // even on a corrupt state.
        let mut cur = cap.parent;
        let mut steps: u32 = 0;
        while let Some(pid) = cur {
            if steps >= self.limits.max_lineage_length {
                return Err(NotLive::LineageCorrupt);
            }
            steps += 1;
            let p = self.capabilities.get(&pid).ok_or(NotLive::LineageCorrupt)?;
            if p.status == Status::Revoked {
                return Err(NotLive::AncestorRevoked(pid));
            }
            if p.origin.expiry.is_expired_at(now) {
                return Err(NotLive::AncestorExpired(pid));
            }
            cur = p.parent;
        }
        Ok(cap)
    }

    /// Convenience: `live(id, now).is_ok()`.
    pub fn is_live(&self, id: CapabilityId, now: Tick) -> bool {
        self.live(id, now).is_ok()
    }

    /// N = U + L + D view of every finite allocation boundary at `now`.
    /// Returns `None` only if the stored identity is broken (impossible for
    /// a state that satisfies [`check_invariant`]).
    pub fn accounts_at(&self, now: Tick) -> Option<Vec<PoolAccount>> {
        let mut out: BTreeMap<PoolId, PoolAccount> = self
            .pools
            .values()
            .map(|p| {
                (
                    p.id,
                    PoolAccount {
                        pool: p.id,
                        root: p.root,
                        anchor: p.anchor,
                        initial: p.initial,
                        consumed: p.consumed,
                        live: 0,
                        discarded_explicit: p.discarded,
                        discarded_stranded: 0,
                    },
                )
            })
            .collect();
        for c in self.capabilities.values() {
            if let (Some(pid), Budget::Finite(b)) = (c.pool, c.budget) {
                let acct = out.get_mut(&pid)?;
                if self.is_live(c.id, now) {
                    acct.live = acct.live.checked_add(b)?;
                } else {
                    acct.discarded_stranded = acct.discarded_stranded.checked_add(b)?;
                }
            }
        }
        Some(out.into_values().collect())
    }

    /// [`State::accounts_at`] evaluated at the recorded clock.
    pub fn accounts(&self) -> Option<Vec<PoolAccount>> {
        self.accounts_at(self.clock)
    }
}
