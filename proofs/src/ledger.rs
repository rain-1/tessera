//! Mirror of `crates/capability-core/src/{ids,command,state,step}.rs`.
//!
//! Representation: the core keeps `BTreeMap`s keyed by identifiers that are
//! allocated from monotone counters and never recycled. The only removal is
//! `CompactEpoch` (ADR-0031). The model stores one dense vector per map,
//! indexed by the raw identifier (ghost view: `Seq`), so the counters
//! `next_*` are the vector lengths. A record that compaction removes stays
//! in its slot as a tombstone (`pruned == true`). Every lookup treats a
//! tombstone exactly like a missing key, so ids remain indices and are
//! never reused:
//!
//! | core                                       | model                                   |
//! |--------------------------------------------|-----------------------------------------|
//! | `principals: BTreeMap<AgentId, _>`         | `principals[serial]` + stored epoch     |
//! | `capabilities: BTreeMap<CapabilityId, _>`  | `capabilities[id]`                      |
//! | `roots`, `pools`, `reservations`           | `roots[id]`, `pools[id]`, `reservations[id]` |
//! | key absent after `CompactEpoch`            | slot with `pruned == true`              |
//! | `map.len()` (capacity checks)              | `n_principals`, `n_capabilities`, `n_roots`, `n_reservations` |
//! | `spent_nonces: BTreeMap<Nonce, RootId>`    | `spent_nonces: Vec<SpentNonce>` (insertion order) |
//! | `requests: BTreeMap<(AgentId, RequestId), ReservationId>` | linear search over non-pruned `reservations` |
//! | `retired_roots_below`, `retired`           | same fields                             |
//! | `Nonce([u8; 32])`                          | `Nonce { hi: u128, lo: u128 }` (big-endian halves) |
//!
//! Every transition validates completely before its first write, so the
//! plan/commit split of the core becomes "checks, then writes" inside one
//! function; `step`'s postcondition proves that a denial leaves the state
//! unchanged (T8).
use vstd::prelude::*;

use crate::quantity::*;
use crate::scope::*;

verus! {

global size_of usize == 8;

// ======================================================================
// Identifiers and records (mirror of ids.rs, state.rs, command.rs)
// ======================================================================

pub type CapabilityId = u128;
pub type RootId = u128;
pub type PoolId = u64;
pub type ReservationId = u64;
pub type RequestId = u128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentId {
    pub epoch: u64,
    pub serial: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nonce {
    pub hi: u128,
    pub lo: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_capabilities: u64,
    pub max_principals: u64,
    pub max_roots: u64,
    pub max_reservations: u64,
    pub max_lineage_length: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Terms {
    pub scope: Scope,
    pub budget: Budget,
    pub depth: Depth,
    pub expiry: Expiry,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrincipalStatus {
    Active,
    Terminated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Live,
    Dropped,
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootKind {
    Approved { nonce: Nonce },
    Baseline,
}

/// `principals[serial]`; the core key is `AgentId { epoch, serial }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Principal {
    pub epoch: u64,
    pub status: PrincipalStatus,
    /// Tombstone: removed by `CompactEpoch` (absent from the core's map).
    pub pruned: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootRecord {
    pub capability: CapabilityId,
    pub kind: RootKind,
    pub recipient: AgentId,
    pub terms: Terms,
    pub epoch: u64,
    pub issued_at: Tick,
    pub pruned: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capability {
    pub root: RootId,
    pub parent: Option<CapabilityId>,
    pub owner: AgentId,
    pub origin: Terms,
    pub scope: Scope,
    pub budget: Budget,
    pub depth: Depth,
    pub expiry: Expiry,
    pub pool: Option<PoolId>,
    pub generation: u32,
    pub status: Status,
    pub pruned: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pool {
    pub root: RootId,
    pub anchor: CapabilityId,
    pub initial: u64,
    pub consumed: u64,
    pub discarded: u64,
    pub pruned: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationStatus {
    Reserved,
    Completed,
    Failed,
    Unknown,
    Abandoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Completed,
    Failed,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservationRecord {
    pub owner: AgentId,
    pub request_id: RequestId,
    pub capability: CapabilityId,
    pub root: RootId,
    pub pool: Option<PoolId>,
    pub operation: Operation,
    pub status: ReservationStatus,
    pub reserved_at: Tick,
    pub pruned: bool,
}

/// Mirror of `RetiredPools`: cumulative totals of the pools that
/// `CompactEpoch` removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetiredPools {
    pub pools: u64,
    pub initial: u128,
    pub consumed: u128,
    pub discarded: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpentNonce {
    pub nonce: Nonce,
    pub root: RootId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotLive {
    Unknown,
    Revoked,
    Dropped,
    Expired,
    AncestorRevoked(CapabilityId),
    AncestorExpired(CapabilityId),
    OwnerTerminated,
    OwnerUnknown,
    StaleEpoch,
    LineageCorrupt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resource {
    Capabilities,
    Principals,
    Roots,
    Reservations,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denial {
    ClockRegression,
    StaleEpoch,
    UnknownPrincipal,
    PrincipalTerminated,
    UnknownCapability,
    NotOwner,
    NotLive(NotLive),
    OperationNotPermitted,
    InsufficientBudget,
    NotDelegatable,
    InvalidScope,
    ScopeNotAttenuated,
    BudgetNotAttenuated,
    DepthNotAttenuated,
    ExpiryNotAttenuated,
    AlreadyExpired,
    ZeroAllocation,
    SelfTransfer,
    NotAuthorizedToRevoke,
    AlreadyRevoked,
    AlreadyTerminated,
    NonceReused,
    ApprovalEpochMismatch,
    ApprovalExpired,
    RequestIdConflict,
    UnknownReservation,
    ReservationAlreadyResolved,
    CapacityExceeded(Resource),
    LineageTooLong,
    ArithmeticOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantRequest {
    pub epoch: u64,
    pub recipient: AgentId,
    pub terms: Terms,
    pub request_expires: Tick,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedApproval {
    pub nonce: Nonce,
    pub request: GrantRequest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentCommand {
    Consume { request_id: RequestId, capability: CapabilityId, operation: Operation },
    Split { capability: CapabilityId, terms: Terms },
    Delegate { capability: CapabilityId, recipient: AgentId, terms: Terms },
    Attenuate { capability: CapabilityId, terms: Terms },
    Transfer { capability: CapabilityId, recipient: AgentId },
    Revoke { capability: CapabilityId },
    Drop { capability: CapabilityId },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminCommand {
    CreatePrincipal,
    TerminatePrincipal { agent: AgentId },
    AdvanceClock,
    BumpEpoch,
    CompactEpoch,
    Mint { approval: VerifiedApproval },
    InstallBaseline { recipient: AgentId, terms: Terms },
    Revoke { capability: CapabilityId },
    RecordOutcome { reservation: ReservationId, outcome: Outcome },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthenticatedCommand {
    Agent { caller: AgentId, command: AgentCommand },
    Operator(AdminCommand),
}

/// Mirror of `Effect` (`Reserved` carries the reservation id; the full
/// record is in `reservations[id]`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(inconsistent_fields)]
pub enum Effect {
    PrincipalCreated { agent: AgentId },
    PrincipalTerminated { agent: AgentId },
    ClockAdvanced { now: Tick },
    EpochAdvanced { epoch: u64, terminated_principals: u64, abandoned_reservations: u64 },
    EpochCompacted {
        principals: u64, capabilities: u64, roots: u64, pools: u64, reservations: u64,
        initial: u128, consumed: u128, discarded: u128,
    },
    RootCreated { root: RootId, capability: CapabilityId, kind: RootKind },
    Reserved { reservation: ReservationId },
    AlreadyReserved { reservation: ReservationId, status: ReservationStatus },
    Derived { parent: CapabilityId, child: CapabilityId, owner: AgentId },
    Attenuated { capability: CapabilityId, discarded: u64 },
    Transferred { capability: CapabilityId, from: AgentId, to: AgentId },
    Revoked { capability: CapabilityId },
    Dropped { capability: CapabilityId, discarded: u64 },
    OutcomeRecorded { reservation: ReservationId, status: ReservationStatus },
}

/// Mirror of `State`.
pub struct State {
    pub limits: Limits,
    pub epoch: u64,
    pub sequence: u64,
    pub clock: Tick,
    pub principals: Vec<Principal>,
    pub capabilities: Vec<Capability>,
    pub roots: Vec<RootRecord>,
    pub pools: Vec<Pool>,
    pub spent_nonces: Vec<SpentNonce>,
    pub reservations: Vec<ReservationRecord>,
    /// Number of non-pruned records (the core's `BTreeMap::len()`), used by
    /// the capacity checks.
    pub n_principals: usize,
    pub n_capabilities: usize,
    pub n_roots: usize,
    pub n_reservations: usize,
    pub retired_roots_below: u128,
    pub retired: RetiredPools,
}

// ======================================================================
// Specifications
// ======================================================================

/// Units of pool `p` held by capability `c`.
pub open spec fn bal(c: Capability, p: int) -> int {
    match c.pool {
        Some(q) => if q as int == p { c.budget.units() } else { 0 },
        None => 0,
    }
}

/// Σ balances of pool `p` over a sequence of capability records.
pub open spec fn pool_sum(caps: Seq<Capability>, p: int) -> int
    decreases caps.len(),
{
    if caps.len() == 0 { 0 } else { pool_sum(caps.drop_last(), p) + bal(caps.last(), p) }
}

/// T2 per-edge attenuation on immutable creation snapshots.
pub open spec fn edge_ok(parent: Terms, child: Terms) -> bool {
    &&& is_subset_spec(child.scope, parent.scope)
    &&& child.expiry.within_spec(parent.expiry)
    &&& parent.depth.admits_child_spec(child.depth)
    &&& (child.budget is Unlimited ==> parent.budget is Unlimited)
}

/// Current terms are within creation terms.
pub open spec fn current_within_origin(c: Capability) -> bool {
    &&& is_subset_spec(c.scope, c.origin.scope)
    &&& c.expiry.within_spec(c.origin.expiry)
    &&& c.depth.within_spec(c.origin.depth)
    &&& c.budget.within_spec(c.origin.budget)
}

pub open spec fn nonce_in(spent: Seq<SpentNonce>, n: Nonce) -> bool {
    exists|k: int| 0 <= k < spent.len() && #[trigger] spent[k].nonce == n
}

/// Spent-nonce entry `k` records nonce `n` for root `r`.
pub open spec fn nonce_recorded(spent: Seq<SpentNonce>, n: Nonce, r: int) -> bool {
    exists|k: int| 0 <= k < spent.len() && (#[trigger] spent[k]).nonce == n && spent[k].root as int == r
}

pub open spec fn approved_nonce(r: RootRecord) -> Option<Nonce> {
    match r.kind {
        RootKind::Approved { nonce } => Some(nonce),
        RootKind::Baseline => None,
    }
}

/// Bounded ancestor walk of `State::live`: every ancestor reached within
/// `fuel` steps exists, is not revoked and had not expired at creation
/// terms; the walk reaches the root within `fuel` steps.
pub open spec fn chain_ok(caps: Seq<Capability>, cur: Option<CapabilityId>, now: Tick, fuel: nat) -> bool
    decreases fuel,
{
    match cur {
        None => true,
        Some(p) => {
            &&& fuel > 0
            &&& (p as int) < caps.len()
            &&& !caps[p as int].pruned
            &&& caps[p as int].status != Status::Revoked
            &&& !caps[p as int].origin.expiry.is_expired_at_spec(now)
            &&& chain_ok(caps, caps[p as int].parent, now, (fuel - 1) as nat)
        },
    }
}

/// Selected field of a pool: 0 = count, 1 = initial, 2 = consumed,
/// 3 = discarded.
pub open spec fn pfield(p: Pool, f: int) -> int {
    if f == 0 { 1 } else if f == 1 { p.initial as int } else if f == 2 { p.consumed as int } else { p.discarded as int }
}

/// Σ of field `f` over the pools whose `pruned` flag is `v`.
pub open spec fn psum(pools: Seq<Pool>, v: bool, f: int) -> int
    decreases pools.len(),
{
    if pools.len() == 0 { 0 } else {
        psum(pools.drop_last(), v, f) + if pools.last().pruned == v { pfield(pools.last(), f) } else { 0 }
    }
}

/// Σ finite balances of the capability records whose `pruned` flag is `v`.
pub open spec fn csum(caps: Seq<Capability>, v: bool) -> int
    decreases caps.len(),
{
    if caps.len() == 0 { 0 } else {
        csum(caps.drop_last(), v) + if caps.last().pruned == v { caps.last().budget.units() } else { 0 }
    }
}

impl State {
    pub open spec fn principal_spec(&self, a: AgentId) -> Option<PrincipalStatus> {
        if (a.serial as int) < self.principals@.len() && self.principals@[a.serial as int].epoch == a.epoch
            && !self.principals@[a.serial as int].pruned {
            Some(self.principals@[a.serial as int].status)
        } else {
            None
        }
    }

    /// Mirror of `State::is_active`.
    pub open spec fn active_spec(&self, a: AgentId) -> bool {
        a.epoch == self.epoch && self.principal_spec(a) == Some(PrincipalStatus::Active)
    }

    /// Mirror of `State::live` as a predicate (T5, T6 core part).
    pub open spec fn live_spec(&self, id: CapabilityId, now: Tick) -> bool {
        let caps = self.capabilities@;
        &&& (id as int) < caps.len()
        &&& !caps[id as int].pruned
        &&& caps[id as int].status == Status::Live
        &&& !caps[id as int].expiry.is_expired_at_spec(now)
        &&& caps[id as int].owner.epoch == self.epoch
        &&& self.principal_spec(caps[id as int].owner) == Some(PrincipalStatus::Active)
        &&& chain_ok(caps, caps[id as int].parent, now, self.limits.max_lineage_length as nat)
    }

    pub open spec fn cap_ok(&self, i: int) -> bool {
        let c = self.capabilities@[i];
        &&& (c.budget is Finite <==> c.pool is Some)
        &&& (c.pool matches Some(q) ==> (q as int) < self.pools@.len())
        &&& current_within_origin(c)
        &&& (c.status == Status::Dropped ==> c.budget.units() == 0)
        &&& (c.parent matches Some(p) ==> (p as int) < i && edge_ok(self.capabilities@[p as int].origin, c.origin))
        // Structure used by compaction: every record of a lineage shares
        // its root, and a record is pruned exactly when its root is.
        &&& (c.root as int) < self.roots@.len()
        &&& c.pruned == self.roots@[c.root as int].pruned
        &&& c.owner.epoch == self.roots@[c.root as int].epoch
        &&& (c.parent matches Some(p) ==> self.capabilities@[p as int].root == c.root)
        &&& (c.pool matches Some(q) ==> self.pools@[q as int].root == c.root)
        &&& (!c.pruned ==> self.principal_spec(c.owner) is Some)
    }

    pub open spec fn pool_ref_ok(&self, q: int) -> bool {
        let pl = self.pools@[q];
        &&& (pl.root as int) < self.roots@.len()
        &&& pl.pruned == self.roots@[pl.root as int].pruned
        &&& (pl.anchor as int) < self.capabilities@.len()
        &&& self.capabilities@[pl.anchor as int].root == pl.root
    }

    pub open spec fn root_ok(&self, r: int) -> bool {
        let rr = self.roots@[r];
        &&& (rr.capability as int) < self.capabilities@.len()
        &&& self.capabilities@[rr.capability as int].root as int == r
        &&& rr.epoch <= self.epoch
        &&& rr.recipient.epoch == rr.epoch
        // The pruned roots are exactly the ids below `retired_roots_below`.
        &&& (rr.pruned <==> r < self.retired_roots_below)
        &&& (!rr.pruned ==> self.principal_spec(rr.recipient) is Some)
    }

    pub open spec fn res_ok(&self, k: int) -> bool {
        let rv = self.reservations@[k];
        &&& (rv.root as int) < self.roots@.len()
        &&& rv.pruned == self.roots@[rv.root as int].pruned
        &&& (rv.capability as int) < self.capabilities@.len()
        &&& self.capabilities@[rv.capability as int].root == rv.root
        &&& (rv.pool matches Some(q) ==> (q as int) < self.pools@.len() && self.pools@[q as int].root == rv.root)
    }

    /// Root ids grow with epochs.
    pub open spec fn roots_sorted(&self) -> bool {
        &&& forall|r1: int, r2: int| #![trigger self.roots@[r1], self.roots@[r2]] 0 <= r1 < r2 < self.roots@.len()
                ==> self.roots@[r1].epoch <= self.roots@[r2].epoch
        &&& self.retired_roots_below <= self.roots@.len()
    }

    /// Accounting of pruned pools (ADR-0031): the `retired` totals are the
    /// sums over the pruned pools, and `retired.discarded` also holds the
    /// balances stranded in pruned capability records.
    pub open spec fn retired_ok(&self) -> bool {
        &&& self.retired.pools as int == psum(self.pools@, true, 0)
        &&& self.retired.initial as int == psum(self.pools@, true, 1)
        &&& self.retired.consumed as int == psum(self.pools@, true, 2)
        &&& self.retired.discarded as int == psum(self.pools@, true, 3) + csum(self.capabilities@, true)
    }

    /// T1: per-pool stored identity `N = U + D_explicit + Σ balances`.
    pub open spec fn pool_ok(&self, p: int) -> bool {
        let pl = self.pools@[p];
        pl.initial as int == pl.consumed as int + pl.discarded as int + pool_sum(self.capabilities@, p)
    }

    /// T7 ledger part.
    pub open spec fn nonces_ok(&self) -> bool {
        &&& forall|i: int, j: int| #![trigger self.spent_nonces@[i], self.spent_nonces@[j]] 0 <= i < j < self.spent_nonces@.len()
                ==> self.spent_nonces@[i].nonce != self.spent_nonces@[j].nonce
        &&& forall|r: int| 0 <= r < self.roots@.len() && (#[trigger] self.roots@[r]).kind is Approved
                ==> nonce_recorded(self.spent_nonces@, self.roots@[r].kind->nonce, r)
        // Every spent nonce names the (possibly pruned) root that redeemed it.
        &&& forall|k: int| 0 <= k < self.spent_nonces@.len() ==> {
                &&& ((#[trigger] self.spent_nonces@[k]).root as int) < self.roots@.len()
                &&& self.roots@[self.spent_nonces@[k].root as int].kind == (RootKind::Approved { nonce: self.spent_nonces@[k].nonce })
            }
    }

    /// The proved ledger invariant (subset of `check_invariant`).
    pub open spec fn inv(&self) -> bool {
        &&& forall|i: int| 0 <= i < self.capabilities@.len() ==> #[trigger] self.cap_ok(i)
        &&& forall|p: int| 0 <= p < self.pools@.len() ==> #[trigger] self.pool_ok(p)
        &&& self.nonces_ok()
        &&& forall|q: int| 0 <= q < self.pools@.len() ==> #[trigger] self.pool_ref_ok(q)
        &&& forall|r: int| 0 <= r < self.roots@.len() ==> #[trigger] self.root_ok(r)
        &&& forall|k: int| 0 <= k < self.reservations@.len() ==> #[trigger] self.res_ok(k)
        &&& self.roots_sorted()
        &&& self.retired_ok()
    }
}

/// Spent nonces are append-only (T7: once redeemed, redeemed forever).
pub open spec fn nonces_extend(old: &State, new: &State) -> bool {
    &&& old.spent_nonces@.len() <= new.spent_nonces@.len()
    &&& forall|k: int| 0 <= k < old.spent_nonces@.len() ==> new.spent_nonces@[k] == old.spent_nonces@[k]
}

/// Postconditions shared by every transition.
pub open spec fn post(old: &State, new: &State, r: Result<Effect, Denial>) -> bool {
    &&& new.inv()
    &&& (r is Err ==> *new == *old)                                       // T8
    &&& (r matches Ok(Effect::AlreadyReserved { .. }) ==> *new == *old)  // idempotent repeat
    &&& nonces_extend(old, new)                                           // T7
    &&& new.limits == old.limits
    &&& old.capabilities@.len() <= new.capabilities@.len()
    &&& records_monotone(old, new)                                        // T5
    &&& frozen(old, new)                                                  // ADR-0031
}

/// Id counters (the vector lengths) never decrease, the epoch and the
/// retired-root floor never decrease, and a pruned record never changes
/// again (in particular it is never un-pruned: no resurrection).
pub open spec fn frozen(old: &State, new: &State) -> bool {
    &&& old.principals@.len() <= new.principals@.len()
    &&& old.roots@.len() <= new.roots@.len()
    &&& old.pools@.len() <= new.pools@.len()
    &&& old.reservations@.len() <= new.reservations@.len()
    &&& old.epoch <= new.epoch
    &&& old.retired_roots_below <= new.retired_roots_below
    &&& forall|i: int| 0 <= i < old.principals@.len() && (#[trigger] old.principals@[i]).pruned
            ==> new.principals@[i] == old.principals@[i]
    &&& forall|i: int| 0 <= i < old.capabilities@.len() && (#[trigger] old.capabilities@[i]).pruned
            ==> new.capabilities@[i] == old.capabilities@[i]
    &&& forall|i: int| 0 <= i < old.roots@.len() && (#[trigger] old.roots@[i]).pruned
            ==> new.roots@[i] == old.roots@[i]
    &&& forall|i: int| 0 <= i < old.pools@.len() && (#[trigger] old.pools@[i]).pruned
            ==> new.pools@[i] == old.pools@[i]
    &&& forall|i: int| 0 <= i < old.reservations@.len() && (#[trigger] old.reservations@[i]).pruned
            ==> new.reservations@[i] == old.reservations@[i]
}

/// Existing records keep their lineage and creation terms, and revocation
/// is permanent (T5: a revoked capability or subtree never authorizes again).
pub open spec fn records_monotone(old: &State, new: &State) -> bool {
    forall|i: int| 0 <= i < old.capabilities@.len() ==> {
        &&& (#[trigger] new.capabilities@[i]).parent == old.capabilities@[i].parent
        &&& new.capabilities@[i].origin == old.capabilities@[i].origin
        &&& new.capabilities@[i].root == old.capabilities@[i].root
        &&& (old.capabilities@[i].status == Status::Revoked ==> new.capabilities@[i].status == Status::Revoked)
    }
}

// ======================================================================
// Lemmas
// ======================================================================

pub proof fn lemma_sum_push(caps: Seq<Capability>, c: Capability, p: int)
    ensures pool_sum(caps.push(c), p) == pool_sum(caps, p) + bal(c, p),
{
    assert(caps.push(c).drop_last() =~= caps);
}

pub proof fn lemma_sum_update(caps: Seq<Capability>, i: int, c: Capability, p: int)
    requires 0 <= i < caps.len(),
    ensures pool_sum(caps.update(i, c), p) == pool_sum(caps, p) - bal(caps[i], p) + bal(c, p),
    decreases caps.len(),
{
    let u = caps.update(i, c);
    if i == caps.len() - 1 {
        assert(u.drop_last() =~= caps.drop_last());
    } else {
        lemma_sum_update(caps.drop_last(), i, c, p);
        assert(u.drop_last() =~= caps.drop_last().update(i, c));
    }
}

pub proof fn lemma_sum_zero(caps: Seq<Capability>, p: int)
    requires forall|j: int| 0 <= j < caps.len() ==> bal(#[trigger] caps[j], p) == 0,
    ensures pool_sum(caps, p) == 0,
    decreases caps.len(),
{
    if caps.len() > 0 {
        let d = caps.drop_last();
        assert forall|j: int| 0 <= j < d.len() implies bal(#[trigger] d[j], p) == 0 by {
            assert(d[j] == caps[j]);
        }
        lemma_sum_zero(d, p);
    }
}

/// No capability yet references a pool with index `>= pools.len()`.
pub proof fn lemma_fresh_pool_empty(s: &State)
    requires s.inv(),
    ensures pool_sum(s.capabilities@, s.pools@.len() as int) == 0,
{
    let caps = s.capabilities@;
    let p = s.pools@.len() as int;
    assert forall|j: int| 0 <= j < caps.len() implies bal(#[trigger] caps[j], p) == 0 by {
        assert(s.cap_ok(j));
    }
    lemma_sum_zero(caps, p);
}

/// Every balance is non-negative and bounded by the pool sum, so the stored
/// identity rules out overspend: `Σ balances <= N`.
pub proof fn lemma_sum_nonneg(caps: Seq<Capability>, p: int)
    ensures pool_sum(caps, p) >= 0,
    decreases caps.len(),
{
    if caps.len() > 0 {
        lemma_sum_nonneg(caps.drop_last(), p);
    }
}

/// `b` extends `a` without touching pruned entries or pruned flags.
pub open spec fn pools_frame(a: Seq<Pool>, b: Seq<Pool>) -> bool {
    &&& a.len() <= b.len()
    &&& forall|i: int| 0 <= i < a.len() ==> (#[trigger] b[i]).pruned == a[i].pruned && (a[i].pruned ==> b[i] == a[i])
    &&& forall|i: int| a.len() <= i < b.len() ==> !(#[trigger] b[i]).pruned
}

pub open spec fn caps_frame(a: Seq<Capability>, b: Seq<Capability>) -> bool {
    &&& a.len() <= b.len()
    &&& forall|i: int| 0 <= i < a.len() ==> (#[trigger] b[i]).pruned == a[i].pruned && (a[i].pruned ==> b[i] == a[i])
    &&& forall|i: int| a.len() <= i < b.len() ==> !(#[trigger] b[i]).pruned
}

pub proof fn lemma_psum_frame(a: Seq<Pool>, b: Seq<Pool>, f: int)
    requires pools_frame(a, b),
    ensures psum(b, true, f) == psum(a, true, f),
    decreases b.len(),
{
    if b.len() > a.len() {
        let d = b.drop_last();
        assert forall|i: int| a.len() <= i < d.len() implies !(#[trigger] d[i]).pruned by { assert(d[i] == b[i]); }
        assert forall|i: int| 0 <= i < a.len() implies (#[trigger] d[i]).pruned == a[i].pruned && (a[i].pruned ==> d[i] == a[i]) by {
            assert(d[i] == b[i]);
        }
        lemma_psum_frame(a, d, f);
        assert(!b[b.len() - 1].pruned);
    } else if b.len() > 0 {
        let (da, db) = (a.drop_last(), b.drop_last());
        assert forall|i: int| 0 <= i < da.len() implies (#[trigger] db[i]).pruned == da[i].pruned && (da[i].pruned ==> db[i] == da[i]) by {
            assert(db[i] == b[i] && da[i] == a[i]);
        }
        lemma_psum_frame(da, db, f);
        assert(b[b.len() - 1].pruned == a[a.len() - 1].pruned);
    }
}

pub proof fn lemma_csum_frame(a: Seq<Capability>, b: Seq<Capability>)
    requires caps_frame(a, b),
    ensures csum(b, true) == csum(a, true),
    decreases b.len(),
{
    if b.len() > a.len() {
        let d = b.drop_last();
        assert forall|i: int| a.len() <= i < d.len() implies !(#[trigger] d[i]).pruned by { assert(d[i] == b[i]); }
        assert forall|i: int| 0 <= i < a.len() implies (#[trigger] d[i]).pruned == a[i].pruned && (a[i].pruned ==> d[i] == a[i]) by {
            assert(d[i] == b[i]);
        }
        lemma_csum_frame(a, d);
        assert(!b[b.len() - 1].pruned);
    } else if b.len() > 0 {
        let (da, db) = (a.drop_last(), b.drop_last());
        assert forall|i: int| 0 <= i < da.len() implies (#[trigger] db[i]).pruned == da[i].pruned && (da[i].pruned ==> db[i] == da[i]) by {
            assert(db[i] == b[i] && da[i] == a[i]);
        }
        lemma_csum_frame(da, db);
        assert(b[b.len() - 1].pruned == a[a.len() - 1].pruned);
    }
}

/// Transitions other than compaction leave the retired accounting intact.
pub proof fn lemma_retired_frame(s0: &State, s1: &State)
    requires
        s0.retired_ok(), s1.retired == s0.retired,
        pools_frame(s0.pools@, s1.pools@), caps_frame(s0.capabilities@, s1.capabilities@),
    ensures s1.retired_ok(),
{
    lemma_psum_frame(s0.pools@, s1.pools@, 0);
    lemma_psum_frame(s0.pools@, s1.pools@, 1);
    lemma_psum_frame(s0.pools@, s1.pools@, 2);
    lemma_psum_frame(s0.pools@, s1.pools@, 3);
    lemma_csum_frame(s0.capabilities@, s1.capabilities@);
}

pub open spec fn same_res_refs(a: ReservationRecord, b: ReservationRecord) -> bool {
    a.root == b.root && a.pruned == b.pruned && a.capability == b.capability && a.pool == b.pool
}

/// Frame: a transition that changes no capability, pool, root or spent
/// nonce, keeps every known principal known (status may change), keeps the
/// reservations' references, and does not decrease the epoch preserves `inv`.
pub proof fn lemma_inv_frame(s0: &State, s1: &State)
    requires
        s0.inv(),
        s1.capabilities@ == s0.capabilities@, s1.pools@ == s0.pools@,
        s1.roots@ == s0.roots@, s1.spent_nonces@ == s0.spent_nonces@,
        s1.retired == s0.retired, s1.retired_roots_below == s0.retired_roots_below,
        s0.epoch <= s1.epoch,
        forall|a: AgentId| s0.principal_spec(a) is Some ==> #[trigger] s1.principal_spec(a) is Some,
        s1.reservations@.len() == s0.reservations@.len(),
        forall|k: int| 0 <= k < s0.reservations@.len() ==> same_res_refs(s0.reservations@[k], #[trigger] s1.reservations@[k]),
    ensures s1.inv(),
{
    assert forall|i: int| 0 <= i < s1.capabilities@.len() implies #[trigger] s1.cap_ok(i) by {
        assert(s0.cap_ok(i));
        if !s1.capabilities@[i].pruned {
            assert(s0.principal_spec(s0.capabilities@[i].owner) is Some);
        }
    }
    assert forall|p: int| 0 <= p < s1.pools@.len() implies #[trigger] s1.pool_ok(p) by {
        assert(s0.pool_ok(p));
    }
    assert forall|q: int| 0 <= q < s1.pools@.len() implies #[trigger] s1.pool_ref_ok(q) by {
        assert(s0.pool_ref_ok(q));
    }
    assert forall|r: int| 0 <= r < s1.roots@.len() implies #[trigger] s1.root_ok(r) by {
        assert(s0.root_ok(r));
        if !s1.roots@[r].pruned {
            assert(s0.principal_spec(s0.roots@[r].recipient) is Some);
        }
    }
    assert forall|k: int| 0 <= k < s1.reservations@.len() implies #[trigger] s1.res_ok(k) by {
        assert(s0.res_ok(k));
        assert(same_res_refs(s0.reservations@[k], s1.reservations@[k]));
    }
}

/// T1 corollary (no overspend): consumed plus discarded units never exceed
/// the pool's initial allocation, and no single balance exceeds it.
pub proof fn lemma_no_overspend(s: &State, p: int, i: int)
    requires s.inv(), 0 <= p < s.pools@.len(), 0 <= i < s.capabilities@.len(),
    ensures
        s.pools@[p].consumed + s.pools@[p].discarded <= s.pools@[p].initial,
        bal(s.capabilities@[i], p) <= s.pools@[p].initial,
{
    assert(s.pool_ok(p));
    lemma_sum_nonneg(s.capabilities@, p);
    lemma_bal_le_sum(s, s.capabilities@, p, i);
}

pub proof fn lemma_bal_le_sum(s: &State, caps: Seq<Capability>, p: int, i: int)
    requires
        0 <= i < caps.len(),
        forall|j: int| 0 <= j < caps.len() ==> bal(#[trigger] caps[j], p) >= 0,
    ensures bal(caps[i], p) <= pool_sum(caps, p),
    decreases caps.len(),
{
    let d = caps.drop_last();
    if i == caps.len() - 1 {
        lemma_sum_nonneg(d, p);
    } else {
        assert forall|j: int| 0 <= j < d.len() implies bal(#[trigger] d[j], p) >= 0 by {
            assert(d[j] == caps[j]);
        }
        lemma_bal_le_sum(s, d, p, i);
        assert(d[i] == caps[i]);
    }
}

/// T7 corollary: distinct approved roots carry distinct nonces, i.e. each
/// approval nonce has been redeemed by at most one root.
pub proof fn lemma_roots_distinct_nonces(s: &State, r1: int, r2: int)
    requires
        s.inv(),
        0 <= r1 < s.roots@.len(), 0 <= r2 < s.roots@.len(), r1 != r2,
        s.roots@[r1].kind is Approved, s.roots@[r2].kind is Approved,
    ensures s.roots@[r1].kind->nonce != s.roots@[r2].kind->nonce,
{
    let sp = s.spent_nonces@;
    let n1 = s.roots@[r1].kind->nonce;
    let n2 = s.roots@[r2].kind->nonce;
    assert(nonce_recorded(sp, n1, r1));
    assert(nonce_recorded(sp, n2, r2));
    let k1 = choose|k: int| 0 <= k < sp.len() && (#[trigger] sp[k]).nonce == n1 && sp[k].root as int == r1;
    let k2 = choose|k: int| 0 <= k < sp.len() && (#[trigger] sp[k]).nonce == n2 && sp[k].root as int == r2;
    assert(k1 != k2);
    if k1 < k2 {
        assert(sp[k1].nonce != sp[k2].nonce);
    } else {
        assert(sp[k2].nonce != sp[k1].nonce);
    }
}

/// T2 along a whole lineage: `k` parent steps from `i`.
pub open spec fn ancestor(caps: Seq<Capability>, i: int, k: nat) -> Option<int>
    decreases k,
{
    if k == 0 {
        Some(i)
    } else {
        match ancestor(caps, i, (k - 1) as nat) {
            Some(a) => if 0 <= a < caps.len() {
                match caps[a].parent {
                    Some(p) => Some(p as int),
                    None => None,
                }
            } else { None },
            None => None,
        }
    }
}

/// T2: every capability's creation scope and lifetime are contained in those
/// of each of its ancestors (in particular its root).
pub proof fn lemma_lineage_attenuated(s: &State, i: int, k: nat)
    requires s.inv(), 0 <= i < s.capabilities@.len(),
    ensures
        ancestor(s.capabilities@, i, k) matches Some(a) ==> {
            &&& 0 <= a <= i
            &&& is_subset_spec(s.capabilities@[i].origin.scope, s.capabilities@[a].origin.scope)
            &&& s.capabilities@[i].origin.expiry.within_spec(s.capabilities@[a].origin.expiry)
        },
    decreases k,
{
    let caps = s.capabilities@;
    if k == 0 {
        lemma_subset_refl(caps[i].origin.scope);
        lemma_expiry_within_refl(caps[i].origin.expiry);
    } else {
        lemma_lineage_attenuated(s, i, (k - 1) as nat);
        if let Some(a) = ancestor(caps, i, (k - 1) as nat) {
            if 0 <= a < caps.len() {
                if let Some(p) = caps[a].parent {
                    assert(s.cap_ok(a));
                    let p = p as int;
                    lemma_subset_trans(caps[i].origin.scope, caps[a].origin.scope, caps[p].origin.scope);
                    lemma_expiry_within_trans(caps[i].origin.expiry, caps[a].origin.expiry, caps[p].origin.expiry);
                }
            }
        }
    }
}

/// T2 + soundness: any operation permitted by a capability's current scope
/// is permitted by the creation scope of each of its ancestors.
pub proof fn lemma_use_within_ancestor(s: &State, i: int, k: nat, o: Operation)
    requires
        s.inv(), 0 <= i < s.capabilities@.len(),
        permits_spec(s.capabilities@[i].scope, o),
        ancestor(s.capabilities@, i, k) is Some,
    ensures permits_spec(s.capabilities@[ancestor(s.capabilities@, i, k)->0].origin.scope, o),
{
    let caps = s.capabilities@;
    lemma_lineage_attenuated(s, i, k);
    assert(s.cap_ok(i));
    let a = ancestor(caps, i, k)->0;
    lemma_subset_sound_chain(caps[i].scope, caps[i].origin.scope, caps[a].origin.scope, o);
}

// ======================================================================
// Compaction (ADR-0031): specification
// ======================================================================

/// Root `r` is retired by a compaction in epoch `e`: it exists, is not
/// pruned yet and was issued in an earlier epoch.
pub open spec fn retire_root(roots: Seq<RootRecord>, r: RootId, e: u64) -> bool {
    (r as int) < roots.len() && !roots[r as int].pruned && roots[r as int].epoch < e
}

/// The records `CompactEpoch` removes in epoch `e`, as tombstones: exactly
/// the principals of earlier epochs, the roots issued in earlier epochs,
/// and every capability, pool and reservation of those roots.
pub open spec fn compact_principals(ps: Seq<Principal>, e: u64) -> Seq<Principal> {
    Seq::new(ps.len(), |i: int| if !ps[i].pruned && ps[i].epoch < e { Principal { pruned: true, ..ps[i] } } else { ps[i] })
}

pub open spec fn compact_roots(rs: Seq<RootRecord>, e: u64) -> Seq<RootRecord> {
    Seq::new(rs.len(), |i: int| if !rs[i].pruned && rs[i].epoch < e { RootRecord { pruned: true, ..rs[i] } } else { rs[i] })
}

pub open spec fn compact_caps(cs: Seq<Capability>, rs: Seq<RootRecord>, e: u64) -> Seq<Capability> {
    Seq::new(cs.len(), |i: int| if !cs[i].pruned && retire_root(rs, cs[i].root, e) { Capability { pruned: true, ..cs[i] } } else { cs[i] })
}

pub open spec fn compact_pools(ps: Seq<Pool>, rs: Seq<RootRecord>, e: u64) -> Seq<Pool> {
    Seq::new(ps.len(), |i: int| if !ps[i].pruned && retire_root(rs, ps[i].root, e) { Pool { pruned: true, ..ps[i] } } else { ps[i] })
}

pub open spec fn compact_reservations(vs: Seq<ReservationRecord>, rs: Seq<RootRecord>, e: u64) -> Seq<ReservationRecord> {
    Seq::new(vs.len(), |i: int| if !vs[i].pruned && retire_root(rs, vs[i].root, e) { ReservationRecord { pruned: true, ..vs[i] } } else { vs[i] })
}

/// First root that is not pruned and was issued in epoch `e` or later
/// (`roots.len()` if none): `min` over the core's current-epoch root ids.
pub open spec fn first_current(rs: Seq<RootRecord>, e: u64, m: int) -> bool {
    &&& 0 <= m <= rs.len()
    &&& forall|j: int| 0 <= j < m ==> (#[trigger] rs[j]).pruned || rs[j].epoch < e
    &&& m < rs.len() ==> !rs[m].pruned && rs[m].epoch >= e
}

/// What a successful `CompactEpoch` does (beyond `post`).
pub open spec fn compacted(old: &State, new: &State, eff: Effect) -> bool {
    let e = old.epoch;
    &&& new.principals@ == compact_principals(old.principals@, e)
    &&& new.roots@ == compact_roots(old.roots@, e)
    &&& new.capabilities@ == compact_caps(old.capabilities@, old.roots@, e)
    &&& new.pools@ == compact_pools(old.pools@, old.roots@, e)
    &&& new.reservations@ == compact_reservations(old.reservations@, old.roots@, e)
    // T7: every spent nonce is kept.
    &&& new.spent_nonces@ == old.spent_nonces@
    // The epoch and every id counter are unchanged.
    &&& new.epoch == old.epoch
    &&& new.limits == old.limits
    // No live capability is pruned and none becomes live.
    &&& forall|id: CapabilityId, now: Tick| #[trigger] new.live_spec(id, now) == old.live_spec(id, now)
    // The effect reports the pruned pools' totals, which join `retired`.
    &&& eff matches Effect::EpochCompacted { pools, initial, consumed, discarded, .. } && {
        &&& new.retired.pools as int == old.retired.pools + pools
        &&& new.retired.initial as int == old.retired.initial + initial
        &&& new.retired.consumed as int == old.retired.consumed + consumed
        &&& new.retired.discarded as int == old.retired.discarded + discarded
    }
}

pub proof fn lemma_psum_push(ps: Seq<Pool>, x: Pool, v: bool, f: int)
    ensures psum(ps.push(x), v, f) == psum(ps, v, f) + if x.pruned == v { pfield(x, f) } else { 0 },
{
    assert(ps.push(x).drop_last() =~= ps);
}

pub proof fn lemma_csum_push(cs: Seq<Capability>, x: Capability, v: bool)
    ensures csum(cs.push(x), v) == csum(cs, v) + if x.pruned == v { x.budget.units() } else { 0 },
{
    assert(cs.push(x).drop_last() =~= cs);
}

/// `pool_sum` ignores the `pruned` flag.
pub proof fn lemma_sum_same_bal(a: Seq<Capability>, b: Seq<Capability>, p: int)
    requires a.len() == b.len(), forall|i: int| 0 <= i < a.len() ==> bal(#[trigger] a[i], p) == bal(b[i], p),
    ensures pool_sum(a, p) == pool_sum(b, p),
    decreases a.len(),
{
    if a.len() > 0 {
        let (da, db) = (a.drop_last(), b.drop_last());
        assert forall|i: int| 0 <= i < da.len() implies bal(#[trigger] da[i], p) == bal(db[i], p) by {
            assert(da[i] == a[i] && db[i] == b[i]);
        }
        lemma_sum_same_bal(da, db, p);
        assert(bal(a[a.len() - 1], p) == bal(b[b.len() - 1], p));
    }
}

/// Liveness walk on the compacted records implies the walk before.
pub proof fn lemma_chain_compact_back(c0: Seq<Capability>, rs: Seq<RootRecord>, e: u64, cur: Option<CapabilityId>, now: Tick, fuel: nat)
    requires chain_ok(compact_caps(c0, rs, e), cur, now, fuel),
    ensures chain_ok(c0, cur, now, fuel),
    decreases fuel,
{
    let c1 = compact_caps(c0, rs, e);
    if let Some(p) = cur {
        assert(c1[p as int].parent == c0[p as int].parent);
        lemma_chain_compact_back(c0, rs, e, c0[p as int].parent, now, (fuel - 1) as nat);
    }
}

/// Parent of record `j` is older and has the same root.
pub open spec fn parent_same_root(c0: Seq<Capability>, j: int) -> bool {
    c0[j].parent matches Some(q) ==> (q as int) < j && c0[q as int].root == c0[j].root
}

/// A walk over records of one root that compaction keeps survives it.
pub proof fn lemma_chain_compact_fwd(c0: Seq<Capability>, rs: Seq<RootRecord>, e: u64, root: RootId,
                                     cur: Option<CapabilityId>, now: Tick, fuel: nat)
    requires
        chain_ok(c0, cur, now, fuel),
        !retire_root(rs, root, e),
        cur matches Some(p) ==> (p as int) < c0.len() ==> c0[p as int].root == root,
        forall|j: int| 0 <= j < c0.len() ==> #[trigger] parent_same_root(c0, j),
    ensures chain_ok(compact_caps(c0, rs, e), cur, now, fuel),
    decreases fuel,
{
    let c1 = compact_caps(c0, rs, e);
    if let Some(p) = cur {
        let pc = c0[p as int];
        assert(c1[p as int] == pc);
        assert(parent_same_root(c0, p as int));
        lemma_chain_compact_fwd(c0, rs, e, root, pc.parent, now, (fuel - 1) as nat);
    }
}

// ----------------------------------------------------------------------
// Conservation across compaction (ADR-0031 global identity)
// ----------------------------------------------------------------------

/// Σ over the pools whose flag is `v` of `bal(c, p)`.
pub open spec fn pbal(c: Capability, pools: Seq<Pool>, v: bool) -> int
    decreases pools.len(),
{
    if pools.len() == 0 { 0 } else {
        pbal(c, pools.drop_last(), v) + if pools.last().pruned == v { bal(c, pools.len() - 1) } else { 0 }
    }
}

/// Σ over the pools whose flag is `v` of their member balances.
pub open spec fn psum_bal(caps: Seq<Capability>, pools: Seq<Pool>, v: bool) -> int
    decreases pools.len(),
{
    if pools.len() == 0 { 0 } else {
        psum_bal(caps, pools.drop_last(), v) + if pools.last().pruned == v { pool_sum(caps, pools.len() - 1) } else { 0 }
    }
}

pub proof fn lemma_pbal(c: Capability, pools: Seq<Pool>, v: bool)
    ensures pbal(c, pools, v) == (if c.pool matches Some(q) && (q as int) < pools.len() && pools[q as int].pruned == v { c.budget.units() } else { 0 }),
    decreases pools.len(),
{
    if pools.len() > 0 {
        let d = pools.drop_last();
        lemma_pbal(c, d, v);
        if let Some(q) = c.pool {
            if (q as int) < d.len() { assert(d[q as int] == pools[q as int]); }
        }
    }
}

pub proof fn lemma_psum_bal_push(caps: Seq<Capability>, c: Capability, pools: Seq<Pool>, v: bool)
    ensures psum_bal(caps.push(c), pools, v) == psum_bal(caps, pools, v) + pbal(c, pools, v),
    decreases pools.len(),
{
    if pools.len() > 0 {
        lemma_psum_bal_push(caps, c, pools.drop_last(), v);
        lemma_sum_push(caps, c, pools.len() - 1);
    }
}

/// Exchange of summation: Σ_{pools p with flag v} Σ_{caps} bal = Σ finite
/// balances of the caps with flag v (members share their pool's flag).
pub proof fn lemma_psum_bal_csum(caps: Seq<Capability>, pools: Seq<Pool>, v: bool)
    requires
        forall|i: int| 0 <= i < caps.len() ==> ((#[trigger] caps[i]).budget is Finite <==> caps[i].pool is Some),
        forall|i: int| 0 <= i < caps.len() ==> ((#[trigger] caps[i]).pool matches Some(q) ==>
            (q as int) < pools.len() && pools[q as int].pruned == caps[i].pruned),
    ensures psum_bal(caps, pools, v) == csum(caps, v),
    decreases caps.len(),
{
    if caps.len() == 0 {
        assert forall|p: int| true implies pool_sum(caps, p) == 0 by {}
        lemma_psum_bal_zero(caps, pools, v);
    } else {
        let d = caps.drop_last();
        let c = caps.last();
        assert forall|i: int| 0 <= i < d.len() implies ((#[trigger] d[i]).budget is Finite <==> d[i].pool is Some) by { assert(d[i] == caps[i]); }
        assert forall|i: int| 0 <= i < d.len() implies (#[trigger] d[i]).pool matches Some(q) ==>
            (q as int) < pools.len() && pools[q as int].pruned == d[i].pruned by { assert(d[i] == caps[i]); }
        lemma_psum_bal_csum(d, pools, v);
        assert(caps == d.push(c));
        lemma_psum_bal_push(d, c, pools, v);
        lemma_pbal(c, pools, v);
        assert(caps[caps.len() - 1] == c);
    }
}

pub proof fn lemma_psum_bal_zero(caps: Seq<Capability>, pools: Seq<Pool>, v: bool)
    requires caps.len() == 0,
    ensures psum_bal(caps, pools, v) == 0,
    decreases pools.len(),
{
    if pools.len() > 0 { lemma_psum_bal_zero(caps, pools.drop_last(), v); }
}

/// Σ of the per-pool identities over the pools with flag `v`.
pub proof fn lemma_psum_identity(caps: Seq<Capability>, pools: Seq<Pool>, v: bool)
    requires forall|p: int| 0 <= p < pools.len() ==>
        (#[trigger] pools[p]).initial as int == pools[p].consumed as int + pools[p].discarded as int + pool_sum(caps, p),
    ensures psum(pools, v, 1) == psum(pools, v, 2) + psum(pools, v, 3) + psum_bal(caps, pools, v),
    decreases pools.len(),
{
    if pools.len() > 0 {
        let d = pools.drop_last();
        assert forall|p: int| 0 <= p < d.len() implies
            (#[trigger] d[p]).initial as int == d[p].consumed as int + d[p].discarded as int + pool_sum(caps, p) by {
            assert(d[p] == pools[p]);
        }
        lemma_psum_identity(caps, d, v);
        assert(pools[pools.len() - 1] == pools.last());
    }
}

/// Members of a pool share its `pruned` flag; finite iff in a pool.
pub proof fn lemma_members_share_flag(s: &State)
    requires s.inv(),
    ensures
        forall|i: int| 0 <= i < s.capabilities@.len() ==> ((#[trigger] s.capabilities@[i]).budget is Finite <==> s.capabilities@[i].pool is Some),
        forall|i: int| 0 <= i < s.capabilities@.len() ==> ((#[trigger] s.capabilities@[i]).pool matches Some(q) ==>
            (q as int) < s.pools@.len() && s.pools@[q as int].pruned == s.capabilities@[i].pruned),
        forall|p: int| 0 <= p < s.pools@.len() ==> (#[trigger] s.pools@[p]).initial as int
            == s.pools@[p].consumed as int + s.pools@[p].discarded as int + pool_sum(s.capabilities@, p),
{
    assert forall|i: int| 0 <= i < s.capabilities@.len() implies (#[trigger] s.capabilities@[i]).pool matches Some(q) ==>
        (q as int) < s.pools@.len() && s.pools@[q as int].pruned == s.capabilities@[i].pruned by {
        assert(s.cap_ok(i));
        if let Some(q) = s.capabilities@[i].pool { assert(s.pool_ref_ok(q as int)); }
    }
    assert forall|i: int| 0 <= i < s.capabilities@.len() implies ((#[trigger] s.capabilities@[i]).budget is Finite <==> s.capabilities@[i].pool is Some) by {
        assert(s.cap_ok(i));
    }
    assert forall|p: int| 0 <= p < s.pools@.len() implies (#[trigger] s.pools@[p]).initial as int
        == s.pools@[p].consumed as int + s.pools@[p].discarded as int + pool_sum(s.capabilities@, p) by {
        assert(s.pool_ok(p));
    }
}

/// ADR-0031: the pruned pools balance, `retired.initial = retired.consumed
/// + retired.discarded` (stranded balances counted as discarded).
pub proof fn lemma_retired_balanced(s: &State)
    requires s.inv(),
    ensures s.retired.initial as int == s.retired.consumed as int + s.retired.discarded as int,
{
    lemma_members_share_flag(s);
    lemma_psum_identity(s.capabilities@, s.pools@, true);
    lemma_psum_bal_csum(s.capabilities@, s.pools@, true);
}

/// ADR-0031 global conservation identity across compactions:
/// `Σ_pools N + retired.N = Σ_pools U + retired.U + Σ_pools D_explicit
///  + Σ balances + retired.D` (sums over the records still present).
pub proof fn lemma_global_conservation(s: &State)
    requires s.inv(),
    ensures
        psum(s.pools@, false, 1) + s.retired.initial
            == psum(s.pools@, false, 2) + s.retired.consumed + psum(s.pools@, false, 3)
               + csum(s.capabilities@, false) + s.retired.discarded,
{
    lemma_members_share_flag(s);
    lemma_psum_identity(s.capabilities@, s.pools@, false);
    lemma_psum_bal_csum(s.capabilities@, s.pools@, false);
    lemma_retired_balanced(s);
}

/// No present record refers to a pruned (or missing) one: capabilities.
pub proof fn lemma_no_dangling_cap(s: &State, i: int)
    requires s.inv(), 0 <= i < s.capabilities@.len(), !s.capabilities@[i].pruned,
    ensures ({
        let c = s.capabilities@[i];
        &&& (c.root as int) < s.roots@.len() && !s.roots@[c.root as int].pruned
        &&& (c.parent matches Some(p) ==> (p as int) < s.capabilities@.len() && !s.capabilities@[p as int].pruned)
        &&& (c.pool matches Some(q) ==> (q as int) < s.pools@.len() && !s.pools@[q as int].pruned)
        &&& s.principal_spec(c.owner) is Some
    }),
{
    let c = s.capabilities@[i];
    assert(s.cap_ok(i));
    if let Some(p) = c.parent { assert(s.cap_ok(p as int)); }
    if let Some(q) = c.pool { assert(s.pool_ref_ok(q as int)); }
}

/// No present pool refers to a pruned root or anchor.
pub proof fn lemma_no_dangling_pool(s: &State, q: int)
    requires s.inv(), 0 <= q < s.pools@.len(), !s.pools@[q].pruned,
    ensures
        (s.pools@[q].root as int) < s.roots@.len() && !s.roots@[s.pools@[q].root as int].pruned,
        (s.pools@[q].anchor as int) < s.capabilities@.len() && !s.capabilities@[s.pools@[q].anchor as int].pruned,
{
    assert(s.pool_ref_ok(q));
    assert(s.cap_ok(s.pools@[q].anchor as int));
}

/// No present root refers to a pruned capability or recipient.
pub proof fn lemma_no_dangling_root(s: &State, r: int)
    requires s.inv(), 0 <= r < s.roots@.len(), !s.roots@[r].pruned,
    ensures
        (s.roots@[r].capability as int) < s.capabilities@.len() && !s.capabilities@[s.roots@[r].capability as int].pruned,
        s.principal_spec(s.roots@[r].recipient) is Some,
{
    assert(s.root_ok(r));
    assert(s.cap_ok(s.roots@[r].capability as int));
}

/// No present reservation refers to a pruned capability, root or pool.
pub proof fn lemma_no_dangling_reservation(s: &State, k: int)
    requires s.inv(), 0 <= k < s.reservations@.len(), !s.reservations@[k].pruned,
    ensures ({
        let v = s.reservations@[k];
        &&& (v.root as int) < s.roots@.len() && !s.roots@[v.root as int].pruned
        &&& (v.capability as int) < s.capabilities@.len() && !s.capabilities@[v.capability as int].pruned
        &&& (v.pool matches Some(q) ==> (q as int) < s.pools@.len() && !s.pools@[q as int].pruned)
    }),
{
    let v = s.reservations@[k];
    assert(s.res_ok(k));
    assert(s.cap_ok(v.capability as int));
    if let Some(q) = v.pool { assert(s.pool_ref_ok(q as int)); }
}

/// T7 across the compaction boundary: every spent nonce names either a
/// present root that carries exactly that nonce (id `>= retired_roots_below`)
/// or a pruned one (id `< retired_roots_below`); spent nonces stay pairwise
/// distinct, so a pruned approval can never be redeemed again.
pub proof fn lemma_spent_nonce_boundary(s: &State, k: int)
    requires s.inv(), 0 <= k < s.spent_nonces@.len(),
    ensures ({
        let sn = s.spent_nonces@[k];
        &&& (sn.root as int) < s.roots@.len()
        &&& s.roots@[sn.root as int].kind == (RootKind::Approved { nonce: sn.nonce })
        &&& (sn.root >= s.retired_roots_below <==> !s.roots@[sn.root as int].pruned)
        &&& forall|j: int| 0 <= j < s.spent_nonces@.len() && j != k ==> (#[trigger] s.spent_nonces@[j]).nonce != sn.nonce
    }),
{
    let sn = s.spent_nonces@[k];
    assert(s.root_ok(sn.root as int));
    assert forall|j: int| 0 <= j < s.spent_nonces@.len() && j != k implies (#[trigger] s.spent_nonces@[j]).nonce != sn.nonce by {
        if j < k { assert(s.spent_nonces@[j].nonce != s.spent_nonces@[k].nonce); }
        else { assert(s.spent_nonces@[k].nonce != s.spent_nonces@[j].nonce); }
    }
}

/// Compaction preserves the invariant and liveness.
pub proof fn lemma_compact(s0: &State, s1: &State, m: int)
    requires
        s0.inv(),
        s1.principals@ == compact_principals(s0.principals@, s0.epoch),
        s1.roots@ == compact_roots(s0.roots@, s0.epoch),
        s1.capabilities@ == compact_caps(s0.capabilities@, s0.roots@, s0.epoch),
        s1.pools@ == compact_pools(s0.pools@, s0.roots@, s0.epoch),
        s1.reservations@ == compact_reservations(s0.reservations@, s0.roots@, s0.epoch),
        s1.spent_nonces@ == s0.spent_nonces@,
        s1.epoch == s0.epoch, s1.limits == s0.limits,
        first_current(s0.roots@, s0.epoch, m),
        s1.retired_roots_below as int == if m > s0.retired_roots_below { m } else { s0.retired_roots_below as int },
        s1.retired.pools as int == s0.retired.pools + psum(s1.pools@, true, 0) - psum(s0.pools@, true, 0),
        s1.retired.initial as int == s0.retired.initial + psum(s1.pools@, true, 1) - psum(s0.pools@, true, 1),
        s1.retired.consumed as int == s0.retired.consumed + psum(s1.pools@, true, 2) - psum(s0.pools@, true, 2),
        s1.retired.discarded as int == s0.retired.discarded + psum(s1.pools@, true, 3) - psum(s0.pools@, true, 3)
            + csum(s1.capabilities@, true) - csum(s0.capabilities@, true),
    ensures
        s1.inv(),
        records_monotone(s0, s1),
        frozen(s0, s1),
        forall|id: CapabilityId, now: Tick| #[trigger] s1.live_spec(id, now) == s0.live_spec(id, now),
{
    let e = s0.epoch;
    let (c0, c1) = (s0.capabilities@, s1.capabilities@);
    let (r0, r1) = (s0.roots@, s1.roots@);
    let (p0, p1) = (s0.principals@, s1.principals@);
    let fl = s1.retired_roots_below as int;
    // A principal of epoch >= e keeps its entry.
    assert forall|a: AgentId| a.epoch >= e && s0.principal_spec(a) is Some implies #[trigger] s1.principal_spec(a) == s0.principal_spec(a) by {
        assert(p1[a.serial as int] == p0[a.serial as int]);
    }
    // Pruned roots are exactly those below the new floor.
    assert forall|r: int| 0 <= r < r1.len() implies (#[trigger] r1[r]).pruned <==> r < fl by {
        assert(s0.root_ok(r));
        if r >= s0.retired_roots_below && !(r0[r].epoch < e) {
            // a current root: m <= r
            if m > r { assert(r0[r].pruned || r0[r].epoch < e); }
        }
        if r >= s0.retired_roots_below && r0[r].epoch < e && m < r0.len() {
            // every candidate is later than r
            assert(s0.root_ok(m));
            if m <= r {
                if m < r { assert(r0[m].epoch <= r0[r].epoch); }
            }
        }
    }
    assert forall|i: int| 0 <= i < c1.len() implies #[trigger] s1.cap_ok(i) by {
        assert(s0.cap_ok(i));
        let c = c0[i];
        if let Some(p) = c.parent { assert(c1[p as int].origin == c0[p as int].origin && c1[p as int].root == c0[p as int].root); }
        if let Some(q) = c.pool { assert(s1.pools@[q as int].root == s0.pools@[q as int].root); }
        assert(r1[c.root as int].epoch == r0[c.root as int].epoch);
        if !c1[i].pruned {
            assert(!r1[c.root as int].pruned);
            assert(s1.principal_spec(c.owner) == s0.principal_spec(c.owner));
        }
    }
    assert forall|p: int| 0 <= p < s1.pools@.len() implies #[trigger] s1.pool_ok(p) by {
        assert(s0.pool_ok(p));
        assert forall|i: int| 0 <= i < c0.len() implies bal(#[trigger] c0[i], p) == bal(c1[i], p) by {}
        lemma_sum_same_bal(c0, c1, p);
    }
    assert forall|q: int| 0 <= q < s1.pools@.len() implies #[trigger] s1.pool_ref_ok(q) by {
        assert(s0.pool_ref_ok(q));
        assert(c1[s0.pools@[q].anchor as int].root == c0[s0.pools@[q].anchor as int].root);
    }
    assert forall|r: int| 0 <= r < r1.len() implies #[trigger] s1.root_ok(r) by {
        assert(s0.root_ok(r));
        assert(c1[r0[r].capability as int].root == c0[r0[r].capability as int].root);
        if !r1[r].pruned {
            assert(s1.principal_spec(r0[r].recipient) == s0.principal_spec(r0[r].recipient));
        }
    }
    assert forall|k: int| 0 <= k < s1.reservations@.len() implies #[trigger] s1.res_ok(k) by {
        assert(s0.res_ok(k));
        let v = s0.reservations@[k];
        assert(c1[v.capability as int].root == c0[v.capability as int].root);
        if let Some(q) = v.pool { assert(s1.pools@[q as int].root == s0.pools@[q as int].root); }
    }
    assert forall|r1i: int, r2i: int| #![trigger r1[r1i], r1[r2i]] 0 <= r1i < r2i < r1.len()
        implies r1[r1i].epoch <= r1[r2i].epoch by {
        assert(r0[r1i].epoch <= r0[r2i].epoch);
    }
    assert(s1.roots_sorted());
    // T7 clauses: spent nonces unchanged, root kinds unchanged.
    assert forall|r: int| 0 <= r < r1.len() && (#[trigger] r1[r]).kind is Approved
        implies nonce_recorded(s1.spent_nonces@, r1[r].kind->nonce, r) by {
        assert(r1[r].kind == r0[r].kind);
    }
    assert forall|k: int| 0 <= k < s1.spent_nonces@.len() implies {
        &&& ((#[trigger] s1.spent_nonces@[k]).root as int) < r1.len()
        &&& r1[s1.spent_nonces@[k].root as int].kind == (RootKind::Approved { nonce: s1.spent_nonces@[k].nonce })
    } by {
        assert(r1[s0.spent_nonces@[k].root as int].kind == r0[s0.spent_nonces@[k].root as int].kind);
    }
    assert(s1.nonces_ok());
    assert(s1.retired_ok());
    // records_monotone and frozen: only `pruned` flags of non-pruned records change.
    assert forall|i: int| 0 <= i < c0.len() implies {
        &&& (#[trigger] c1[i]).parent == c0[i].parent
        &&& c1[i].origin == c0[i].origin
        &&& c1[i].root == c0[i].root
        &&& (c0[i].status == Status::Revoked ==> c1[i].status == Status::Revoked)
    } by {}
    // Liveness is unchanged.
    assert forall|id: CapabilityId, now: Tick| #[trigger] s1.live_spec(id, now) == s0.live_spec(id, now) by {
        let fuel = s0.limits.max_lineage_length as nat;
        if (id as int) < c0.len() {
            let c = c0[id as int];
            if s1.live_spec(id, now) {
                lemma_chain_compact_back(c0, r0, e, c.parent, now, fuel);
                assert(p1[c.owner.serial as int].epoch == p0[c.owner.serial as int].epoch);
            }
            if s0.live_spec(id, now) {
                assert(s0.cap_ok(id as int));
                assert(!retire_root(r0, c.root, e));
                assert(s1.principal_spec(c.owner) == s0.principal_spec(c.owner));
                assert forall|j: int| 0 <= j < c0.len() implies #[trigger] parent_same_root(c0, j) by { assert(s0.cap_ok(j)); }
                lemma_chain_compact_fwd(c0, r0, e, c.root, c.parent, now, fuel);
            }
        }
    }
}

// ======================================================================
// Executable helpers
// ======================================================================

pub fn agent_eq(a: AgentId, b: AgentId) -> (r: bool)
    ensures r == (a == b),
{
    a.epoch == b.epoch && a.serial == b.serial
}

pub fn nonce_eq(a: Nonce, b: Nonce) -> (r: bool)
    ensures r == (a == b),
{
    a.hi == b.hi && a.lo == b.lo
}

pub fn operation_eq(a: Operation, b: Operation) -> (r: bool)
    ensures r == (a == b),
{
    match (a, b) {
        (Operation::File { object: o1, right: r1 }, Operation::File { object: o2, right: r2 }) => {
            o1.0 == o2.0 && match (r1, r2) {
                (FileRight::Read, FileRight::Read) => true,
                (FileRight::Replace, FileRight::Replace) => true,
                _ => false,
            }
        },
        (Operation::Https { endpoint: e1, method: m1, body_bytes: b1 },
         Operation::Https { endpoint: e2, method: m2, body_bytes: b2 }) => {
            e1.0 == e2.0 && b1 == b2 && m1.bit() == m2.bit()
        },
        _ => false,
    }
}

/// Mirror of `require_capacity`.
pub fn require_capacity(len: usize, max: u64, r: Resource) -> (res: Result<(), Denial>)
    ensures res is Ok <==> (len as int) < (max as int),
            res matches Err(d) ==> d == Denial::CapacityExceeded(r),
{
    if (len as u64) >= max { Err(Denial::CapacityExceeded(r)) } else { Ok(()) }
}

/// Mirror of `require_issuable`.
pub fn require_issuable(terms: &Terms, now: Tick) -> (r: Result<(), Denial>)
    ensures r is Ok <==> (terms.scope.is_well_formed_spec() && !terms.expiry.is_expired_at_spec(now)
                          && terms.budget != Budget::Finite(0)),
{
    if !terms.scope.is_well_formed() {
        return Err(Denial::InvalidScope);
    }
    if terms.expiry.is_expired_at(now) {
        return Err(Denial::AlreadyExpired);
    }
    match terms.budget {
        Budget::Finite(0) => Err(Denial::ZeroAllocation),
        _ => Ok(()),
    }
}

pub enum ChildPool {
    Same,
    Fresh(u64),
}

/// Mirror of `derive_budget`. Finite parents never yield unlimited or
/// over-allocated children.
pub fn derive_budget(parent: Budget, child: Budget) -> (r: Result<(Budget, Option<ChildPool>), Denial>)
    ensures
        r matches Ok((pb, cp)) ==> {
            &&& child != Budget::Finite(0)
            &&& match (parent, child) {
                (Budget::Finite(b), Budget::Finite(q)) => q <= b && pb == Budget::Finite((b - q) as u64) && cp == Some(ChildPool::Same),
                (Budget::Finite(_), Budget::Unlimited) => false,
                (Budget::Unlimited, Budget::Finite(q)) => pb == Budget::Unlimited && cp == Some(ChildPool::Fresh(q)),
                (Budget::Unlimited, Budget::Unlimited) => pb == Budget::Unlimited && cp is None,
            }
        },
{
    match (parent, child) {
        (_, Budget::Finite(0)) => Err(Denial::ZeroAllocation),
        (Budget::Finite(b), Budget::Finite(q)) => {
            if q > b {
                return Err(Denial::InsufficientBudget);
            }
            Ok((Budget::Finite(b - q), Some(ChildPool::Same)))
        },
        (Budget::Finite(_), Budget::Unlimited) => Err(Denial::BudgetNotAttenuated),
        (Budget::Unlimited, Budget::Finite(q)) => Ok((Budget::Unlimited, Some(ChildPool::Fresh(q)))),
        (Budget::Unlimited, Budget::Unlimited) => Ok((Budget::Unlimited, None)),
    }
}

/// BumpEpoch over principals: every (non-pruned) principal becomes
/// `Terminated`; returns how many were active.
fn terminate_all(ps: &Vec<Principal>) -> (r: (Vec<Principal>, u64))
    ensures
        r.0@.len() == ps@.len(),
        forall|i: int| 0 <= i < ps@.len() ==> {
            &&& (#[trigger] r.0@[i]).epoch == ps@[i].epoch
            &&& r.0@[i].pruned == ps@[i].pruned
            &&& (ps@[i].pruned ==> r.0@[i] == ps@[i])
        },
{
    let mut out: Vec<Principal> = Vec::new();
    let mut n: u64 = 0;
    let mut i: usize = 0;
    while i < ps.len()
        invariant
            i <= ps@.len(), out@.len() == i, n <= i,
            forall|j: int| 0 <= j < i ==> {
                &&& (#[trigger] out@[j]).epoch == ps@[j].epoch
                &&& out@[j].pruned == ps@[j].pruned
                &&& (ps@[j].pruned ==> out@[j] == ps@[j])
            },
        decreases ps@.len() - i,
    {
        let p = ps[i];
        if p.pruned {
            out.push(p);
        } else {
            if let PrincipalStatus::Active = p.status {
                n = n + 1;
            }
            out.push(Principal { epoch: p.epoch, status: PrincipalStatus::Terminated, pruned: false });
        }
        i = i + 1;
    }
    (out, n)
}

/// BumpEpoch over reservations: every (non-pruned) `Reserved` one becomes
/// `Abandoned`; returns how many.
fn abandon_all(rs: &Vec<ReservationRecord>) -> (r: (Vec<ReservationRecord>, u64))
    ensures
        r.0@.len() == rs@.len(),
        forall|i: int| 0 <= i < rs@.len() ==> {
            &&& same_res_refs(rs@[i], #[trigger] r.0@[i])
            &&& (rs@[i].pruned ==> r.0@[i] == rs@[i])
        },
{
    let mut out: Vec<ReservationRecord> = Vec::new();
    let mut n: u64 = 0;
    let mut i: usize = 0;
    while i < rs.len()
        invariant
            i <= rs@.len(), out@.len() == i, n <= i,
            forall|j: int| 0 <= j < i ==> {
                &&& same_res_refs(rs@[j], #[trigger] out@[j])
                &&& (rs@[j].pruned ==> out@[j] == rs@[j])
            },
        decreases rs@.len() - i,
    {
        let mut r = rs[i];
        if !r.pruned {
            if let ReservationStatus::Reserved = r.status {
                n = n + 1;
                r.status = ReservationStatus::Abandoned;
            }
        }
        out.push(r);
        i = i + 1;
    }
    (out, n)
}

// ----------------------------------------------------------------------
// Compaction sweeps (mirror of `plan_compact_epoch`): each returns the
// tombstoned vector, the number pruned and the number kept.
// ----------------------------------------------------------------------

fn sweep_principals(ps: &Vec<Principal>, e: u64) -> (r: (Vec<Principal>, u64, usize))
    ensures r.0@ == compact_principals(ps@, e),
{
    let mut out: Vec<Principal> = Vec::new();
    let (mut n, mut kept): (u64, usize) = (0, 0);
    let mut i: usize = 0;
    while i < ps.len()
        invariant
            i <= ps@.len(), out@.len() == i, n as int + kept as int <= i,
            forall|j: int| 0 <= j < i ==> #[trigger] out@[j] == compact_principals(ps@, e)[j],
        decreases ps@.len() - i,
    {
        let p = ps[i];
        if !p.pruned && p.epoch < e {
            n = n + 1;
            out.push(Principal { pruned: true, ..p });
        } else {
            if !p.pruned { kept = kept + 1; }
            out.push(p);
        }
        i = i + 1;
    }
    assert(out@ =~= compact_principals(ps@, e));
    (out, n, kept)
}

fn sweep_roots(rs: &Vec<RootRecord>, e: u64) -> (r: (Vec<RootRecord>, u64, usize))
    ensures r.0@ == compact_roots(rs@, e),
{
    let mut out: Vec<RootRecord> = Vec::new();
    let (mut n, mut kept): (u64, usize) = (0, 0);
    let mut i: usize = 0;
    while i < rs.len()
        invariant
            i <= rs@.len(), out@.len() == i, n as int + kept as int <= i,
            forall|j: int| 0 <= j < i ==> #[trigger] out@[j] == compact_roots(rs@, e)[j],
        decreases rs@.len() - i,
    {
        let r = rs[i];
        if !r.pruned && r.epoch < e {
            n = n + 1;
            out.push(RootRecord { pruned: true, ..r });
        } else {
            if !r.pruned { kept = kept + 1; }
            out.push(r);
        }
        i = i + 1;
    }
    assert(out@ =~= compact_roots(rs@, e));
    (out, n, kept)
}

/// `min` of the non-pruned current-epoch root ids, or `roots.len()`.
fn first_current_root(rs: &Vec<RootRecord>, e: u64) -> (m: usize)
    ensures first_current(rs@, e, m as int),
{
    let mut i: usize = 0;
    while i < rs.len()
        invariant i <= rs@.len(), forall|j: int| 0 <= j < i ==> (#[trigger] rs@[j]).pruned || rs@[j].epoch < e,
        decreases rs@.len() - i,
    {
        if !rs[i].pruned && rs[i].epoch >= e {
            return i;
        }
        i = i + 1;
    }
    i
}

/// Exec form of `retire_root`.
fn retires(rs: &Vec<RootRecord>, root: RootId, e: u64) -> (b: bool)
    ensures b == retire_root(rs@, root, e),
{
    root < rs.len() as u128 && !rs[root as usize].pruned && rs[root as usize].epoch < e
}

/// Capabilities, plus Σ of the finite balances stranded in the pruned ones.
fn sweep_caps(cs: &Vec<Capability>, rs: &Vec<RootRecord>, e: u64) -> (r: Option<(Vec<Capability>, u64, usize, u128)>)
    ensures
        r matches Some((out, _, _, stranded)) ==> {
            &&& out@ == compact_caps(cs@, rs@, e)
            &&& stranded as int == csum(out@, true) - csum(cs@, true)
        },
{
    let mut out: Vec<Capability> = Vec::new();
    let (mut n, mut kept): (u64, usize) = (0, 0);
    let mut stranded: u128 = 0;
    let mut i: usize = 0;
    while i < cs.len()
        invariant
            i <= cs@.len(), out@.len() == i, n as int + kept as int <= i,
            forall|j: int| 0 <= j < i ==> #[trigger] out@[j] == compact_caps(cs@, rs@, e)[j],
            stranded as int == csum(out@, true) - csum(cs@.subrange(0, i as int), true),
        decreases cs@.len() - i,
    {
        let c = cs[i];
        let ghost (o0, s0) = (out@, cs@.subrange(0, i as int));
        assert(cs@.subrange(0, i + 1) =~= s0.push(c));
        proof { lemma_csum_push(s0, c, true); }
        if !c.pruned && retires(rs, c.root, e) {
            if let Budget::Finite(b) = c.budget {
                if stranded > u128::MAX - (b as u128) {
                    return None;
                }
                stranded = stranded + b as u128;
            }
            n = n + 1;
            let x = Capability { pruned: true, ..c };
            out.push(x);
            proof { lemma_csum_push(o0, x, true); }
        } else {
            if !c.pruned { kept = kept + 1; }
            out.push(c);
            proof { lemma_csum_push(o0, c, true); }
        }
        i = i + 1;
    }
    assert(out@ =~= compact_caps(cs@, rs@, e));
    assert(cs@.subrange(0, cs@.len() as int) =~= cs@);
    Some((out, n, kept, stranded))
}

/// Pools, plus Σ N, U, D of the pruned ones.
fn sweep_pools(ps: &Vec<Pool>, rs: &Vec<RootRecord>, e: u64) -> (r: Option<(Vec<Pool>, u64, u128, u128, u128)>)
    ensures
        r matches Some((out, n, initial, consumed, discarded)) ==> {
            &&& out@ == compact_pools(ps@, rs@, e)
            &&& n as int == psum(out@, true, 0) - psum(ps@, true, 0)
            &&& initial as int == psum(out@, true, 1) - psum(ps@, true, 1)
            &&& consumed as int == psum(out@, true, 2) - psum(ps@, true, 2)
            &&& discarded as int == psum(out@, true, 3) - psum(ps@, true, 3)
        },
{
    let mut out: Vec<Pool> = Vec::new();
    let mut n: u64 = 0;
    let (mut initial, mut consumed, mut discarded): (u128, u128, u128) = (0, 0, 0);
    let mut i: usize = 0;
    while i < ps.len()
        invariant
            i <= ps@.len(), out@.len() == i, n <= i,
            forall|j: int| 0 <= j < i ==> #[trigger] out@[j] == compact_pools(ps@, rs@, e)[j],
            n as int == psum(out@, true, 0) - psum(ps@.subrange(0, i as int), true, 0),
            initial as int == psum(out@, true, 1) - psum(ps@.subrange(0, i as int), true, 1),
            consumed as int == psum(out@, true, 2) - psum(ps@.subrange(0, i as int), true, 2),
            discarded as int == psum(out@, true, 3) - psum(ps@.subrange(0, i as int), true, 3),
        decreases ps@.len() - i,
    {
        let p = ps[i];
        let ghost (o0, s0) = (out@, ps@.subrange(0, i as int));
        assert(ps@.subrange(0, i + 1) =~= s0.push(p));
        proof {
            lemma_psum_push(s0, p, true, 0); lemma_psum_push(s0, p, true, 1);
            lemma_psum_push(s0, p, true, 2); lemma_psum_push(s0, p, true, 3);
        }
        if !p.pruned && retires(rs, p.root, e) {
            if initial > u128::MAX - (p.initial as u128) || consumed > u128::MAX - (p.consumed as u128)
                || discarded > u128::MAX - (p.discarded as u128) {
                return None;
            }
            initial = initial + p.initial as u128;
            consumed = consumed + p.consumed as u128;
            discarded = discarded + p.discarded as u128;
            n = n + 1;
            let x = Pool { pruned: true, ..p };
            out.push(x);
            proof {
                lemma_psum_push(o0, x, true, 0); lemma_psum_push(o0, x, true, 1);
                lemma_psum_push(o0, x, true, 2); lemma_psum_push(o0, x, true, 3);
            }
        } else {
            out.push(p);
            proof {
                lemma_psum_push(o0, p, true, 0); lemma_psum_push(o0, p, true, 1);
                lemma_psum_push(o0, p, true, 2); lemma_psum_push(o0, p, true, 3);
            }
        }
        i = i + 1;
    }
    assert(out@ =~= compact_pools(ps@, rs@, e));
    assert(ps@.subrange(0, ps@.len() as int) =~= ps@);
    Some((out, n, initial, consumed, discarded))
}

fn sweep_reservations(vs: &Vec<ReservationRecord>, rs: &Vec<RootRecord>, e: u64) -> (r: (Vec<ReservationRecord>, u64, usize))
    ensures r.0@ == compact_reservations(vs@, rs@, e),
{
    let mut out: Vec<ReservationRecord> = Vec::new();
    let (mut n, mut kept): (u64, usize) = (0, 0);
    let mut i: usize = 0;
    while i < vs.len()
        invariant
            i <= vs@.len(), out@.len() == i, n as int + kept as int <= i,
            forall|j: int| 0 <= j < i ==> #[trigger] out@[j] == compact_reservations(vs@, rs@, e)[j],
        decreases vs@.len() - i,
    {
        let v = vs[i];
        if !v.pruned && retires(rs, v.root, e) {
            n = n + 1;
            out.push(ReservationRecord { pruned: true, ..v });
        } else {
            if !v.pruned { kept = kept + 1; }
            out.push(v);
        }
        i = i + 1;
    }
    assert(out@ =~= compact_reservations(vs@, rs@, e));
    (out, n, kept)
}

// ======================================================================
// Read-only queries (mirror of state.rs)
// ======================================================================

impl State {
    /// Mirror of `State::new`.
    pub fn new(limits: Limits) -> (s: State)
        ensures s.inv(), s.limits == limits, s.capabilities@.len() == 0,
    {
        State {
            limits,
            epoch: 0,
            sequence: 0,
            clock: Tick(0),
            principals: Vec::new(),
            capabilities: Vec::new(),
            roots: Vec::new(),
            pools: Vec::new(),
            spent_nonces: Vec::new(),
            reservations: Vec::new(),
            n_principals: 0,
            n_capabilities: 0,
            n_roots: 0,
            n_reservations: 0,
            retired_roots_below: 0,
            retired: RetiredPools { pools: 0, initial: 0, consumed: 0, discarded: 0 },
        }
    }

    /// Mirror of `State::principal`.
    pub fn principal(&self, a: AgentId) -> (r: Option<PrincipalStatus>)
        ensures r == self.principal_spec(a),
    {
        if (a.serial as u128) < (self.principals.len() as u128) {
            let p = self.principals[a.serial as usize];
            if p.epoch == a.epoch && !p.pruned { Some(p.status) } else { None }
        } else {
            None
        }
    }

    /// Mirror of `require_active`.
    pub fn require_active(&self, a: AgentId) -> (r: Result<(), Denial>)
        ensures r is Ok <==> self.active_spec(a),
    {
        if a.epoch != self.epoch {
            return Err(Denial::StaleEpoch);
        }
        match self.principal(a) {
            None => Err(Denial::UnknownPrincipal),
            Some(PrincipalStatus::Terminated) => Err(Denial::PrincipalTerminated),
            Some(PrincipalStatus::Active) => Ok(()),
        }
    }

    /// Mirror of `State::live` (T5/T6 core part): `Ok` only if the
    /// capability, its owner and every ancestor are live.
    pub fn live(&self, id: CapabilityId, now: Tick) -> (r: Result<Capability, NotLive>)
        ensures
            r is Ok ==> self.live_spec(id, now) && r->Ok_0 == self.capabilities@[id as int],
    {
        if id >= self.capabilities.len() as u128 {
            return Err(NotLive::Unknown);
        }
        let cap = self.capabilities[id as usize];
        if cap.pruned {
            return Err(NotLive::Unknown);
        }
        match cap.status {
            Status::Live => {},
            Status::Dropped => return Err(NotLive::Dropped),
            Status::Revoked => return Err(NotLive::Revoked),
        }
        if cap.expiry.is_expired_at(now) {
            return Err(NotLive::Expired);
        }
        if cap.owner.epoch != self.epoch {
            return Err(NotLive::StaleEpoch);
        }
        match self.principal(cap.owner) {
            None => return Err(NotLive::OwnerUnknown),
            Some(PrincipalStatus::Terminated) => return Err(NotLive::OwnerTerminated),
            Some(PrincipalStatus::Active) => {},
        }
        let max = self.limits.max_lineage_length;
        let mut cur = cap.parent;
        let mut steps: u32 = 0;
        loop
            invariant
                steps <= max,
                chain_ok(self.capabilities@, cap.parent, now, max as nat)
                    == chain_ok(self.capabilities@, cur, now, (max - steps) as nat),
            ensures cur is None,
            decreases max - steps,
        {
            match cur {
                None => break,
                Some(pid) => {
                    if steps >= max {
                        return Err(NotLive::LineageCorrupt);
                    }
                    steps = steps + 1;
                    if pid >= self.capabilities.len() as u128 {
                        return Err(NotLive::LineageCorrupt);
                    }
                    let p = self.capabilities[pid as usize];
                    if p.pruned {
                        return Err(NotLive::LineageCorrupt);
                    }
                    if let Status::Revoked = p.status {
                        return Err(NotLive::AncestorRevoked(pid));
                    }
                    if p.origin.expiry.is_expired_at(now) {
                        return Err(NotLive::AncestorExpired(pid));
                    }
                    cur = p.parent;
                },
            }
        }
        Ok(cap)
    }

    /// Mirror of `owned_live`.
    pub fn owned_live(&self, caller: AgentId, id: CapabilityId, now: Tick) -> (r: Result<Capability, Denial>)
        ensures
            r is Ok ==> {
                &&& self.live_spec(id, now)
                &&& r->Ok_0 == self.capabilities@[id as int]
                &&& r->Ok_0.owner == caller
                &&& (id as int) < self.capabilities@.len() <= usize::MAX
                &&& !self.capabilities@[id as int].pruned
            },
    {
        if id >= self.capabilities.len() as u128 || self.capabilities[id as usize].pruned {
            return Err(Denial::UnknownCapability);
        }
        let cap = self.capabilities[id as usize];
        if !agent_eq(cap.owner, caller) {
            return Err(Denial::NotOwner);
        }
        match self.live(id, now) {
            Ok(c) => Ok(c),
            Err(e) => Err(Denial::NotLive(e)),
        }
    }

    /// Mirror of `State::is_nonce_spent` (`spent_nonces.contains_key`).
    pub fn is_nonce_spent(&self, n: Nonce) -> (r: bool)
        ensures r == nonce_in(self.spent_nonces@, n),
    {
        let mut k: usize = 0;
        while k < self.spent_nonces.len()
            invariant
                k <= self.spent_nonces@.len(),
                forall|j: int| 0 <= j < k ==> (#[trigger] self.spent_nonces@[j]).nonce != n,
            decreases self.spent_nonces@.len() - k,
        {
            if nonce_eq(self.spent_nonces[k].nonce, n) {
                assert(self.spent_nonces@[k as int].nonce == n);
                return true;
            }
            k = k + 1;
        }
        false
    }

    /// Mirror of `requests.get(&(caller, request_id))`: the reservation
    /// recorded for this (authenticated caller, request id), if any.
    pub fn find_request(&self, caller: AgentId, request_id: RequestId) -> (r: Option<usize>)
        ensures r matches Some(k) ==> (k as int) < self.reservations@.len() && !self.reservations@[k as int].pruned,
    {
        let mut k: usize = 0;
        while k < self.reservations.len()
            invariant k <= self.reservations@.len(),
            decreases self.reservations@.len() - k,
        {
            let r = self.reservations[k];
            if !r.pruned && agent_eq(r.owner, caller) && r.request_id == request_id {
                return Some(k);
            }
            k = k + 1;
        }
        None
    }

    /// Mirror of the ancestor walk in `plan_agent_revoke`: may `caller`
    /// revoke `id` (it owns `id` or one of its ancestors)?
    pub fn may_revoke(&self, caller: AgentId, id: CapabilityId) -> (r: bool) {
        let max = self.limits.max_lineage_length;
        let mut cur: Option<CapabilityId> = Some(id);
        let mut steps: u32 = 0;
        loop
            invariant steps <= max,
            decreases max - steps,
        {
            match cur {
                None => return false,
                Some(c) => {
                    if c >= self.capabilities.len() as u128 {
                        return false;
                    }
                    let rec = self.capabilities[c as usize];
                    if rec.pruned {
                        return false;
                    }
                    if agent_eq(rec.owner, caller) {
                        return true;
                    }
                    if steps >= max {
                        return false;
                    }
                    steps = steps + 1;
                    cur = rec.parent;
                },
            }
        }
    }

    /// Mirror of `discard_into`: the new `discarded` value for a pool.
    fn discard_into(&self, pool: Option<PoolId>, amount: u64) -> (r: Result<Option<(PoolId, u64)>, Denial>)
        ensures
            r matches Ok(v) ==> match pool {
                None => v is None,
                Some(pid) => (pid as int) < self.pools@.len() && !self.pools@[pid as int].pruned
                    && self.pools@[pid as int].discarded + amount <= u64::MAX
                    && v == Some((pid, (self.pools@[pid as int].discarded + amount) as u64)),
            },
    {
        match pool {
            None => Ok(None),
            Some(pid) => {
                if pid >= self.pools.len() as u64 || self.pools[pid as usize].pruned {
                    return Err(Denial::ArithmeticOverflow);
                }
                let d = self.pools[pid as usize].discarded;
                if d > u64::MAX - amount {
                    return Err(Denial::ArithmeticOverflow);
                }
                Ok(Some((pid, d + amount)))
            },
        }
    }

    fn set_pool_discarded(&mut self, upd: Option<(PoolId, u64)>)
        requires upd matches Some((pid, _)) ==> (pid as int) < old(self).pools@.len(),
        ensures
            final(self).limits == old(self).limits, final(self).epoch == old(self).epoch,
            final(self).sequence == old(self).sequence, final(self).clock == old(self).clock,
            final(self).principals == old(self).principals, final(self).capabilities == old(self).capabilities,
            final(self).roots == old(self).roots, final(self).spent_nonces == old(self).spent_nonces,
            final(self).reservations == old(self).reservations,
            final(self).n_principals == old(self).n_principals, final(self).n_capabilities == old(self).n_capabilities,
            final(self).n_roots == old(self).n_roots, final(self).n_reservations == old(self).n_reservations,
            final(self).retired == old(self).retired, final(self).retired_roots_below == old(self).retired_roots_below,
            match upd {
                None => final(self).pools == old(self).pools,
                Some((pid, v)) => final(self).pools@ == old(self).pools@.update(pid as int,
                    Pool { discarded: v, ..old(self).pools@[pid as int] }),
            },
    {
        if let Some((pid, v)) = upd {
            let mut p = self.pools[pid as usize];
            p.discarded = v;
            self.pools.set(pid as usize, p);
        }
    }
}

// ======================================================================
// The transition function (mirror of step.rs)
// ======================================================================

impl State {
    /// Mirror of `step`. Main theorem (see `post`): from any state satisfying
    /// `inv`, every command either is denied without any change (T8) or
    /// commits a state that again satisfies `inv` (T1, T2, T4 edges, T7).
    pub fn step(&mut self, command: AuthenticatedCommand, now: Tick) -> (r: Result<Effect, Denial>)
        requires old(self).inv(),
        ensures
            post(&*old(self), &*final(self), r),
            // T7: MINT succeeds only for a fresh nonce, and records it.
            command matches AuthenticatedCommand::Operator(AdminCommand::Mint { approval }) ==> (r is Ok ==> {
                &&& !nonce_in(old(self).spent_nonces@, approval.nonce)
                &&& nonce_in(final(self).spent_nonces@, approval.nonce)
                // exact request binding
                &&& final(self).capabilities@.last().origin == approval.request.terms
                &&& final(self).capabilities@.last().owner == approval.request.recipient
                &&& final(self).roots@.last().terms == approval.request.terms
            }),
            // ADR-0031: compaction prunes exactly the earlier-epoch records,
            // keeps spent nonces, counters and liveness.
            command matches AuthenticatedCommand::Operator(AdminCommand::CompactEpoch)
                ==> (r matches Ok(eff) ==> compacted(&*old(self), &*final(self), eff)),
            // T3/T5/T6 core part + scope soundness: a reservation is issued only
            // through a live capability owned by the authenticated caller whose
            // scope permits exactly the reserved operation.
            command matches AuthenticatedCommand::Agent { caller, command: AgentCommand::Consume { capability, operation, .. } }
                ==> (r is Ok && r->Ok_0 is Reserved ==> {
                &&& old(self).active_spec(caller)
                &&& old(self).live_spec(capability, now)
                &&& old(self).capabilities@[capability as int].owner == caller
                &&& permits_spec(old(self).capabilities@[capability as int].scope, operation)
            }),
            // T4: no split/delegate/transfer from depth zero.
            command matches AuthenticatedCommand::Agent { command: AgentCommand::Split { capability, .. }, .. }
                ==> (r is Ok ==> old(self).capabilities@[capability as int].depth != Depth::Finite(0)),
            command matches AuthenticatedCommand::Agent { command: AgentCommand::Delegate { capability, .. }, .. }
                ==> (r is Ok ==> old(self).capabilities@[capability as int].depth != Depth::Finite(0)),
            command matches AuthenticatedCommand::Agent { command: AgentCommand::Transfer { capability, .. }, .. }
                ==> (r is Ok ==> {
                    &&& old(self).capabilities@[capability as int].depth != Depth::Finite(0)
                    &&& Some(final(self).capabilities@[capability as int].depth) == old(self).capabilities@[capability as int].depth.decrement_spec()
                }),
    {
        let is_bump = match command {
            AuthenticatedCommand::Operator(AdminCommand::BumpEpoch) => true,
            _ => false,
        };
        if !is_bump && now.0 < self.clock.0 {
            return Err(Denial::ClockRegression);
        }
        if self.sequence == u64::MAX {
            return Err(Denial::ArithmeticOverflow);
        }
        let sequence = self.sequence + 1;
        match command {
            AuthenticatedCommand::Operator(cmd) => self.admin(cmd, sequence, now),
            AuthenticatedCommand::Agent { caller, command } => {
                if let Err(e) = self.require_active(caller) {
                    return Err(e);
                }
                self.agent(caller, command, sequence, now)
            },
        }
    }

    fn admin(&mut self, cmd: AdminCommand, sequence: u64, now: Tick) -> (r: Result<Effect, Denial>)
        requires old(self).inv(),
        ensures
            post(&*old(self), &*final(self), r),
            cmd matches AdminCommand::Mint { approval } ==> (r is Ok ==> {
                &&& !nonce_in(old(self).spent_nonces@, approval.nonce)
                &&& nonce_in(final(self).spent_nonces@, approval.nonce)
                &&& final(self).capabilities@.last().origin == approval.request.terms
                &&& final(self).capabilities@.last().owner == approval.request.recipient
                &&& final(self).roots@.last().terms == approval.request.terms
            }),
            cmd matches AdminCommand::CompactEpoch ==> (r matches Ok(eff) ==> compacted(&*old(self), &*final(self), eff)),
    {
        match cmd {
            AdminCommand::CreatePrincipal => {
                if let Err(e) = require_capacity(self.n_principals, self.limits.max_principals, Resource::Principals) {
                    return Err(e);
                }
                let agent = AgentId { epoch: self.epoch, serial: self.principals.len() as u64 };
                if self.principals.len() as u64 == u64::MAX {
                    return Err(Denial::ArithmeticOverflow);
                }
                let ghost s0 = *old(self);
                self.sequence = sequence;
                self.clock = now;
                self.principals.push(Principal { epoch: self.epoch, status: PrincipalStatus::Active, pruned: false });
                self.n_principals = self.n_principals + 1;
                proof {
                    assert forall|a: AgentId| s0.principal_spec(a) is Some implies #[trigger] self.principal_spec(a) is Some by {
                        assert(self.principals@[a.serial as int] == s0.principals@[a.serial as int]);
                    }
                    assert forall|i: int| 0 <= i < s0.principals@.len() && (#[trigger] s0.principals@[i]).pruned
                        implies self.principals@[i] == s0.principals@[i] by {}
                    lemma_inv_frame(&s0, &*self);
                }
                Ok(Effect::PrincipalCreated { agent })
            },
            AdminCommand::TerminatePrincipal { agent } => {
                match self.principal(agent) {
                    None => Err(Denial::UnknownPrincipal),
                    Some(PrincipalStatus::Terminated) => Err(Denial::AlreadyTerminated),
                    Some(PrincipalStatus::Active) => {
                        let ghost s0 = *old(self);
                        self.sequence = sequence;
                        self.clock = now;
                        let i = agent.serial as usize;
                        let p = Principal { epoch: self.principals[i].epoch, status: PrincipalStatus::Terminated, pruned: false };
                        self.principals.set(i, p);
                        proof {
                            assert forall|a: AgentId| s0.principal_spec(a) is Some implies #[trigger] self.principal_spec(a) is Some by {
                                assert(self.principals@[a.serial as int].epoch == s0.principals@[a.serial as int].epoch);
                            }
                            lemma_inv_frame(&s0, &*self);
                        }
                        Ok(Effect::PrincipalTerminated { agent })
                    },
                }
            },
            AdminCommand::AdvanceClock => {
                self.sequence = sequence;
                self.clock = now;
                proof {
                    assert forall|k: int| 0 <= k < old(self).reservations@.len()
                        implies same_res_refs(old(self).reservations@[k], #[trigger] self.reservations@[k]) by {}
                    lemma_inv_frame(&*old(self), &*self);
                }
                Ok(Effect::ClockAdvanced { now })
            },
            AdminCommand::BumpEpoch => {
                if self.epoch == u64::MAX {
                    return Err(Denial::ArithmeticOverflow);
                }
                let epoch = self.epoch + 1;
                let (ps, terminated) = terminate_all(&self.principals);
                let (rs, abandoned) = abandon_all(&self.reservations);
                let ghost s0 = *old(self);
                self.sequence = sequence;
                self.clock = now;
                self.epoch = epoch;
                self.principals = ps;
                self.reservations = rs;
                proof {
                    assert forall|a: AgentId| s0.principal_spec(a) is Some implies #[trigger] self.principal_spec(a) is Some by {
                        assert(self.principals@[a.serial as int].epoch == s0.principals@[a.serial as int].epoch);
                    }
                    lemma_inv_frame(&s0, &*self);
                }
                Ok(Effect::EpochAdvanced { epoch, terminated_principals: terminated, abandoned_reservations: abandoned })
            },
            AdminCommand::Mint { approval } => {
                let nonce = approval.nonce;
                let req = approval.request;
                if self.is_nonce_spent(nonce) {
                    return Err(Denial::NonceReused);
                }
                if req.epoch != self.epoch {
                    return Err(Denial::ApprovalEpochMismatch);
                }
                if now.0 >= req.request_expires.0 {
                    return Err(Denial::ApprovalExpired);
                }
                self.new_root(req.recipient, req.terms, RootKind::Approved { nonce }, Some(nonce), sequence, now)
            },
            AdminCommand::InstallBaseline { recipient, terms } => {
                self.new_root(recipient, terms, RootKind::Baseline, None, sequence, now)
            },
            AdminCommand::CompactEpoch => self.compact(sequence, now),
            AdminCommand::Revoke { capability } => {
                if capability >= self.capabilities.len() as u128 || self.capabilities[capability as usize].pruned {
                    return Err(Denial::UnknownCapability);
                }
                if let Status::Revoked = self.capabilities[capability as usize].status {
                    return Err(Denial::AlreadyRevoked);
                }
                self.commit_revoke(capability, sequence, now);
                Ok(Effect::Revoked { capability })
            },
            AdminCommand::RecordOutcome { reservation, outcome } => {
                if reservation >= self.reservations.len() as u64 || self.reservations[reservation as usize].pruned {
                    return Err(Denial::UnknownReservation);
                }
                let mut rec = self.reservations[reservation as usize];
                match rec.status {
                    ReservationStatus::Reserved => {},
                    _ => return Err(Denial::ReservationAlreadyResolved),
                }
                let status = match outcome {
                    Outcome::Completed => ReservationStatus::Completed,
                    Outcome::Failed => ReservationStatus::Failed,
                    Outcome::Unknown => ReservationStatus::Unknown,
                };
                rec.status = status;
                self.sequence = sequence;
                self.clock = now;
                self.reservations.set(reservation as usize, rec);
                proof {
                    assert forall|k: int| 0 <= k < old(self).reservations@.len()
                        implies same_res_refs(old(self).reservations@[k], #[trigger] self.reservations@[k]) by {}
                    lemma_inv_frame(&*old(self), &*self);
                }
                Ok(Effect::OutcomeRecorded { reservation, status })
            },
        }
    }

    /// Mirror of `plan_new_root` + the `NewRoot` commit.
    fn new_root(&mut self, recipient: AgentId, terms: Terms, kind: RootKind, nonce: Option<Nonce>,
                sequence: u64, now: Tick) -> (r: Result<Effect, Denial>)
        requires
            old(self).inv(),
            nonce matches Some(n) ==> !nonce_in(old(self).spent_nonces@, n) && kind == (RootKind::Approved { nonce: n }),
            nonce is None ==> kind is Baseline,
        ensures
            post(&*old(self), &*final(self), r),
            r is Ok ==> {
                &&& final(self).capabilities@.last().origin == terms
                &&& final(self).capabilities@.last().owner == recipient
                &&& final(self).roots@.last().terms == terms
                &&& (nonce matches Some(n) ==> nonce_in(final(self).spent_nonces@, n))
            },
    {
        if let Err(e) = self.require_active(recipient) {
            return Err(e);
        }
        if let Err(e) = require_issuable(&terms, now) {
            return Err(e);
        }
        if let Err(e) = require_capacity(self.n_capabilities, self.limits.max_capabilities, Resource::Capabilities) {
            return Err(e);
        }
        if let Err(e) = require_capacity(self.n_roots, self.limits.max_roots, Resource::Roots) {
            return Err(e);
        }
        let root_id = self.roots.len() as u128;
        let cap_id = self.capabilities.len() as u128;
        let pool_id: Option<PoolId> = match terms.budget {
            Budget::Unlimited => None,
            Budget::Finite(_) => {
                if self.pools.len() as u64 == u64::MAX {
                    return Err(Denial::ArithmeticOverflow);
                }
                Some(self.pools.len() as u64)
            },
        };
        let capability = Capability {
            root: root_id,
            parent: None,
            owner: recipient,
            origin: terms,
            scope: terms.scope,
            budget: terms.budget,
            depth: terms.depth,
            expiry: terms.expiry,
            pool: pool_id,
            generation: 0,
            status: Status::Live,
            pruned: false,
        };
        let root = RootRecord { capability: cap_id, kind, recipient, terms, epoch: self.epoch, issued_at: now, pruned: false };

        // ---- commit
        let ghost s0 = *old(self);
        self.sequence = sequence;
        self.clock = now;
        if let Some(n) = nonce {
            self.spent_nonces.push(SpentNonce { nonce: n, root: root_id });
        }
        if let Budget::Finite(n) = terms.budget {
            self.pools.push(Pool { root: root_id, anchor: cap_id, initial: n, consumed: 0, discarded: 0, pruned: false });
        }
        self.capabilities.push(capability);
        self.roots.push(root);
        self.n_capabilities = self.n_capabilities + 1;
        self.n_roots = self.n_roots + 1;

        proof {
            lemma_subset_refl(terms.scope);
            lemma_expiry_within_refl(terms.expiry);
            lemma_depth_within_refl(terms.depth);
            lemma_budget_within_refl(terms.budget);
            lemma_fresh_pool_empty(&s0);
            let caps0 = s0.capabilities@;
            assert(self.capabilities@ == caps0.push(capability));
            assert(self.roots@ == s0.roots@.push(root));
            assert(self.principals == s0.principals);
            assert forall|i: int| 0 <= i < self.capabilities@.len() implies #[trigger] self.cap_ok(i) by {
                if i < caps0.len() {
                    assert(s0.cap_ok(i));
                    assert(self.capabilities@[i] == caps0[i]);
                    assert(self.roots@[caps0[i].root as int] == s0.roots@[caps0[i].root as int]);
                    if let Some(p) = caps0[i].parent {
                        assert(self.capabilities@[p as int] == caps0[p as int]);
                    }
                    if let Some(q) = caps0[i].pool {
                        assert(self.pools@[q as int] == s0.pools@[q as int]);
                    }
                } else {
                    assert(self.roots@[root_id as int] == root);
                    if let Some(q) = capability.pool {
                        assert(self.pools@[q as int].root == root_id);
                    }
                }
            }
            assert forall|q: int| 0 <= q < self.pools@.len() implies #[trigger] self.pool_ref_ok(q) by {
                if q < s0.pools@.len() {
                    assert(s0.pool_ref_ok(q));
                    assert(self.pools@[q] == s0.pools@[q]);
                    assert(self.roots@[s0.pools@[q].root as int] == s0.roots@[s0.pools@[q].root as int]);
                    assert(self.capabilities@[s0.pools@[q].anchor as int] == caps0[s0.pools@[q].anchor as int]);
                } else {
                    assert(self.roots@[root_id as int] == root);
                    assert(self.capabilities@[cap_id as int] == capability);
                }
            }
            assert forall|r: int| 0 <= r < self.roots@.len() implies #[trigger] self.root_ok(r) by {
                if r < s0.roots@.len() {
                    assert(s0.root_ok(r));
                    assert(self.roots@[r] == s0.roots@[r]);
                    assert(self.capabilities@[s0.roots@[r].capability as int] == caps0[s0.roots@[r].capability as int]);
                } else {
                    assert(self.roots@[r] == root);
                    assert(self.capabilities@[cap_id as int] == capability);
                }
            }
            assert forall|k: int| 0 <= k < self.reservations@.len() implies #[trigger] self.res_ok(k) by {
                assert(s0.res_ok(k));
                let rv = s0.reservations@[k];
                assert(self.roots@[rv.root as int] == s0.roots@[rv.root as int]);
                assert(self.capabilities@[rv.capability as int] == caps0[rv.capability as int]);
                if let Some(q) = rv.pool {
                    assert(self.pools@[q as int] == s0.pools@[q as int]);
                }
            }
            assert forall|r1: int, r2: int| #![trigger self.roots@[r1], self.roots@[r2]] 0 <= r1 < r2 < self.roots@.len()
                implies self.roots@[r1].epoch <= self.roots@[r2].epoch by {
                assert(s0.root_ok(r1));
                if r2 < s0.roots@.len() {
                    assert(self.roots@[r1] == s0.roots@[r1]);
                    assert(self.roots@[r2] == s0.roots@[r2]);
                }
            }
            lemma_retired_frame(&s0, &*self);
            assert forall|p: int| 0 <= p < self.pools@.len() implies #[trigger] self.pool_ok(p) by {
                lemma_sum_push(caps0, capability, p);
                if p < s0.pools@.len() {
                    assert(s0.pool_ok(p));
                    assert(self.pools@[p] == s0.pools@[p]);
                }
            }
            assert forall|k: int| 0 <= k < self.spent_nonces@.len() implies {
                &&& ((#[trigger] self.spent_nonces@[k]).root as int) < self.roots@.len()
                &&& self.roots@[self.spent_nonces@[k].root as int].kind == (RootKind::Approved { nonce: self.spent_nonces@[k].nonce })
            } by {
                if k < s0.spent_nonces@.len() {
                    assert(self.spent_nonces@[k] == s0.spent_nonces@[k]);
                    assert(self.roots@[s0.spent_nonces@[k].root as int] == s0.roots@[s0.spent_nonces@[k].root as int]);
                } else {
                    assert(self.spent_nonces@[k] == (SpentNonce { nonce: nonce->0, root: root_id }));
                    assert(self.roots@[root_id as int] == root);
                }
            }
            assert forall|r: int| 0 <= r < self.roots@.len() && (#[trigger] self.roots@[r]).kind is Approved
                implies nonce_recorded(self.spent_nonces@, self.roots@[r].kind->nonce, r) by {
                if r < s0.roots@.len() {
                    assert(self.roots@[r] == s0.roots@[r]);
                    let n = s0.roots@[r].kind->nonce;
                    assert(nonce_recorded(s0.spent_nonces@, n, r));
                    let k = choose|k: int| 0 <= k < s0.spent_nonces@.len() && (#[trigger] s0.spent_nonces@[k]).nonce == n && s0.spent_nonces@[k].root as int == r;
                    assert(self.spent_nonces@[k] == s0.spent_nonces@[k]);
                } else {
                    let k = s0.spent_nonces@.len() as int;
                    assert(self.spent_nonces@[k] == (SpentNonce { nonce: nonce->0, root: root_id }));
                }
            }
            if let Some(n) = nonce {
                let k = s0.spent_nonces@.len() as int;
                assert(self.spent_nonces@[k].nonce == n);
                assert forall|i: int, j: int| #![trigger self.spent_nonces@[i], self.spent_nonces@[j]] 0 <= i < j < self.spent_nonces@.len()
                    implies self.spent_nonces@[i].nonce != self.spent_nonces@[j].nonce by {
                    if j == k {
                        assert(self.spent_nonces@[i] == s0.spent_nonces@[i]);
                    } else {
                        assert(self.spent_nonces@[i] == s0.spent_nonces@[i]);
                        assert(self.spent_nonces@[j] == s0.spent_nonces@[j]);
                    }
                }
            } else {
                assert(self.spent_nonces@ == s0.spent_nonces@);
            }
        }
        Ok(Effect::RootCreated { root: root_id, capability: cap_id, kind })
    }

    fn commit_revoke(&mut self, id: CapabilityId, sequence: u64, now: Tick)
        requires old(self).inv(), (id as int) < old(self).capabilities@.len(), !old(self).capabilities@[id as int].pruned,
        ensures
            post(&*old(self), &*final(self), Ok(Effect::Revoked { capability: id })),
    {
        let ghost s0 = *old(self);
        let _len = self.capabilities.len();
        assert(_len as int == s0.capabilities@.len());
        let ix = id as usize;
        assert(ix as int == id as int);
        let mut c = self.capabilities[ix];
        c.status = Status::Revoked;
        self.sequence = sequence;
        self.clock = now;
        self.capabilities.set(ix, c);
        proof {
            assert(self.capabilities@ == s0.capabilities@.update(id as int, c));
            assert(s0.cap_ok(id as int));
            self.lemma_update_same_terms(&s0, id as int);
        }
    }

    /// Updating a record's status/owner (not budget, pool, terms or parent)
    /// preserves `inv`.
    proof fn lemma_update_same_terms(&self, s0: &State, i: int)
        requires
            s0.inv(), 0 <= i < s0.capabilities@.len(),
            self.capabilities@ == s0.capabilities@.update(i, self.capabilities@[i]),
            self.pools == s0.pools, self.roots == s0.roots, self.spent_nonces == s0.spent_nonces,
            self.capabilities@[i].budget == s0.capabilities@[i].budget,
            self.capabilities@[i].pool == s0.capabilities@[i].pool,
            self.capabilities@[i].origin == s0.capabilities@[i].origin,
            self.capabilities@[i].parent == s0.capabilities@[i].parent,
            self.capabilities@[i].scope == s0.capabilities@[i].scope,
            self.capabilities@[i].expiry == s0.capabilities@[i].expiry,
            self.capabilities@[i].depth.within_spec(s0.capabilities@[i].depth),
            self.capabilities@[i].status == Status::Dropped ==> self.capabilities@[i].budget.units() == 0,
            self.principals == s0.principals, self.reservations == s0.reservations, self.epoch == s0.epoch,
            self.retired == s0.retired, self.retired_roots_below == s0.retired_roots_below,
            self.capabilities@[i].root == s0.capabilities@[i].root,
            !self.capabilities@[i].pruned, !s0.capabilities@[i].pruned,
            self.capabilities@[i].owner.epoch == s0.capabilities@[i].owner.epoch,
            s0.principal_spec(self.capabilities@[i].owner) is Some,
        ensures self.inv(),
    {
        let caps0 = s0.capabilities@;
        let c = self.capabilities@[i];
        assert forall|j: int| 0 <= j < self.capabilities@.len() implies #[trigger] self.cap_ok(j) by {
            assert(s0.cap_ok(j));
            if j == i {
                lemma_depth_within_trans(c.depth, caps0[i].depth, caps0[i].origin.depth);
            }
            if let Some(p) = self.capabilities@[j].parent {
                assert(self.capabilities@[p as int].origin == caps0[p as int].origin);
                assert(self.capabilities@[p as int].root == caps0[p as int].root);
            }
        }
        assert forall|p: int| 0 <= p < self.pools@.len() implies #[trigger] self.pool_ok(p) by {
            assert(s0.pool_ok(p));
            lemma_sum_update(caps0, i, c, p);
        }
        assert forall|q: int| 0 <= q < self.pools@.len() implies #[trigger] self.pool_ref_ok(q) by {
            assert(s0.pool_ref_ok(q));
        }
        assert forall|r: int| 0 <= r < self.roots@.len() implies #[trigger] self.root_ok(r) by {
            assert(s0.root_ok(r));
        }
        assert forall|k: int| 0 <= k < self.reservations@.len() implies #[trigger] self.res_ok(k) by {
            assert(s0.res_ok(k));
        }
        lemma_retired_frame(s0, self);
    }

    fn agent(&mut self, caller: AgentId, cmd: AgentCommand, sequence: u64, now: Tick) -> (r: Result<Effect, Denial>)
        requires old(self).inv(), old(self).active_spec(caller),
        ensures
            post(&*old(self), &*final(self), r),
            cmd matches AgentCommand::Consume { capability, operation, .. } ==> (r is Ok && r->Ok_0 is Reserved ==> {
                &&& old(self).live_spec(capability, now)
                &&& old(self).capabilities@[capability as int].owner == caller
                &&& permits_spec(old(self).capabilities@[capability as int].scope, operation)
            }),
            cmd matches AgentCommand::Split { capability, .. }
                ==> (r is Ok ==> old(self).capabilities@[capability as int].depth != Depth::Finite(0)),
            cmd matches AgentCommand::Delegate { capability, .. }
                ==> (r is Ok ==> old(self).capabilities@[capability as int].depth != Depth::Finite(0)),
            cmd matches AgentCommand::Transfer { capability, .. } ==> (r is Ok ==> {
                &&& old(self).capabilities@[capability as int].depth != Depth::Finite(0)
                &&& Some(final(self).capabilities@[capability as int].depth) == old(self).capabilities@[capability as int].depth.decrement_spec()
            }),
    {
        match cmd {
            AgentCommand::Consume { request_id, capability, operation } =>
                self.consume(caller, request_id, capability, operation, sequence, now),
            AgentCommand::Split { capability, terms } =>
                self.derive(caller, capability, caller, terms, sequence, now),
            AgentCommand::Delegate { capability, recipient, terms } => {
                if let Err(e) = self.require_active(recipient) {
                    return Err(e);
                }
                self.derive(caller, capability, recipient, terms, sequence, now)
            },
            AgentCommand::Attenuate { capability, terms } =>
                self.attenuate(caller, capability, terms, sequence, now),
            AgentCommand::Transfer { capability, recipient } =>
                self.transfer(caller, capability, recipient, sequence, now),
            AgentCommand::Revoke { capability } => {
                if capability >= self.capabilities.len() as u128 || self.capabilities[capability as usize].pruned {
                    return Err(Denial::UnknownCapability);
                }
                let authorized = self.may_revoke(caller, capability);
                if !authorized {
                    return Err(Denial::NotAuthorizedToRevoke);
                }
                if let Status::Revoked = self.capabilities[capability as usize].status {
                    return Err(Denial::AlreadyRevoked);
                }
                self.commit_revoke(capability, sequence, now);
                Ok(Effect::Revoked { capability })
            },
            AgentCommand::Drop { capability } => self.drop_cap(caller, capability, sequence, now),
        }
    }

    /// Mirror of `plan_consume` + the `Consume` commit.
    fn consume(&mut self, caller: AgentId, request_id: RequestId, id: CapabilityId, operation: Operation,
               sequence: u64, now: Tick) -> (r: Result<Effect, Denial>)
        requires old(self).inv(),
        ensures
            post(&*old(self), &*final(self), r),
            r matches Ok(Effect::Reserved { .. }) ==> {
                &&& old(self).live_spec(id, now)
                &&& old(self).capabilities@[id as int].owner == caller
                &&& permits_spec(old(self).capabilities@[id as int].scope, operation)
            },
    {
        // Request-id idempotency (core: `requests` map).
        if let Some(k) = self.find_request(caller, request_id) {
            let r = self.reservations[k];
            if r.capability == id && operation_eq(r.operation, operation) {
                return Ok(Effect::AlreadyReserved { reservation: k as u64, status: r.status });
            } else {
                return Err(Denial::RequestIdConflict);
            }
        }
        let cap = match self.owned_live(caller, id, now) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };
        if !permits(&cap.scope, &operation) {
            return Err(Denial::OperationNotPermitted);
        }
        let ghost s0 = *old(self);
        proof { assert(s0.cap_ok(id as int)); }
        let (new_budget, pool_consumed): (Budget, Option<(PoolId, u64)>) = match (cap.budget, cap.pool) {
            (Budget::Unlimited, _) => (Budget::Unlimited, None),
            (Budget::Finite(b), Some(pid)) => {
                if b == 0 {
                    return Err(Denial::InsufficientBudget);
                }
                if pid >= self.pools.len() as u64 || self.pools[pid as usize].pruned {
                    return Err(Denial::ArithmeticOverflow);
                }
                let c = self.pools[pid as usize].consumed;
                if c == u64::MAX {
                    return Err(Denial::ArithmeticOverflow);
                }
                (Budget::Finite(b - 1), Some((pid, c + 1)))
            },
            (Budget::Finite(_), None) => return Err(Denial::InsufficientBudget),
        };
        if let Err(e) = require_capacity(self.n_reservations, self.limits.max_reservations, Resource::Reservations) {
            return Err(e);
        }
        if self.reservations.len() as u64 == u64::MAX {
            return Err(Denial::ArithmeticOverflow);
        }
        let rid = self.reservations.len() as u64;
        let record = ReservationRecord {
            owner: caller,
            request_id,
            capability: id,
            root: cap.root,
            pool: cap.pool,
            operation,
            status: ReservationStatus::Reserved,
            reserved_at: now,
            pruned: false,
        };

        // ---- commit
        self.sequence = sequence;
        self.clock = now;
        let mut c = cap;
        c.budget = new_budget;
        self.capabilities.set(id as usize, c);
        if let Some((pid, v)) = pool_consumed {
            let mut p = self.pools[pid as usize];
            p.consumed = v;
            self.pools.set(pid as usize, p);
        }
        self.reservations.push(record);
        self.n_reservations = self.n_reservations + 1;

        proof {
            let caps0 = s0.capabilities@;
            let i = id as int;
            assert(self.capabilities@ == caps0.update(i, c));
            assert(self.reservations@ == s0.reservations@.push(record));
            assert forall|j: int| 0 <= j < self.capabilities@.len() implies #[trigger] self.cap_ok(j) by {
                assert(s0.cap_ok(j));
                if let Some(p) = self.capabilities@[j].parent {
                    assert(self.capabilities@[p as int].origin == caps0[p as int].origin);
                    assert(self.capabilities@[p as int].root == caps0[p as int].root);
                }
            }
            assert forall|p: int| 0 <= p < self.pools@.len() implies #[trigger] self.pool_ok(p) by {
                assert(s0.pool_ok(p));
                lemma_sum_update(caps0, i, c, p);
            }
            assert forall|q: int| 0 <= q < self.pools@.len() implies #[trigger] self.pool_ref_ok(q) by {
                assert(s0.pool_ref_ok(q));
            }
            assert forall|r: int| 0 <= r < self.roots@.len() implies #[trigger] self.root_ok(r) by {
                assert(s0.root_ok(r));
            }
            assert forall|k: int| 0 <= k < self.reservations@.len() implies #[trigger] self.res_ok(k) by {
                if k < s0.reservations@.len() {
                    assert(s0.res_ok(k));
                    assert(self.reservations@[k] == s0.reservations@[k]);
                } else {
                    assert(self.reservations@[k] == record);
                }
            }
            lemma_retired_frame(&s0, &*self);
        }
        Ok(Effect::Reserved { reservation: rid })
    }

    /// Mirror of `plan_derive` + the `Derive` commit (SPLIT and DELEGATE).
    fn derive(&mut self, caller: AgentId, parent_id: CapabilityId, owner: AgentId, terms: Terms,
              sequence: u64, now: Tick) -> (r: Result<Effect, Denial>)
        requires old(self).inv(), old(self).active_spec(owner),
        ensures
            post(&*old(self), &*final(self), r),
            r is Ok ==> old(self).capabilities@[parent_id as int].depth != Depth::Finite(0),
    {
        let parent = match self.owned_live(caller, parent_id, now) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };
        if !parent.depth.can_delegate() {
            return Err(Denial::NotDelegatable);
        }
        if !terms.scope.is_well_formed() {
            return Err(Denial::InvalidScope);
        }
        if !is_subset(&terms.scope, &parent.scope) {
            return Err(Denial::ScopeNotAttenuated);
        }
        if !parent.depth.admits_child(terms.depth) {
            return Err(Denial::DepthNotAttenuated);
        }
        if !terms.expiry.within(parent.expiry) {
            return Err(Denial::ExpiryNotAttenuated);
        }
        if let Err(e) = require_issuable(&terms, now) {
            return Err(e);
        }
        let (parent_budget, child_pool) = match derive_budget(parent.budget, terms.budget) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        if parent.generation == u32::MAX {
            return Err(Denial::ArithmeticOverflow);
        }
        let generation = parent.generation + 1;
        if generation > self.limits.max_lineage_length {
            return Err(Denial::LineageTooLong);
        }
        if let Err(e) = require_capacity(self.n_capabilities, self.limits.max_capabilities, Resource::Capabilities) {
            return Err(e);
        }
        let child_id = self.capabilities.len() as u128;
        let ghost s0 = *old(self);
        proof { assert(s0.cap_ok(parent_id as int)); }
        let (pool, new_pool): (Option<PoolId>, Option<Pool>) = match child_pool {
            None => (None, None),
            Some(ChildPool::Same) => (parent.pool, None),
            Some(ChildPool::Fresh(n)) => {
                if self.pools.len() as u64 == u64::MAX {
                    return Err(Denial::ArithmeticOverflow);
                }
                let pid = self.pools.len() as u64;
                (Some(pid), Some(Pool { root: parent.root, anchor: child_id, initial: n, consumed: 0, discarded: 0, pruned: false }))
            },
        };
        let child = Capability {
            root: parent.root,
            parent: Some(parent_id),
            owner,
            origin: terms,
            scope: terms.scope,
            budget: terms.budget,
            depth: terms.depth,
            expiry: terms.expiry,
            pool,
            generation,
            status: Status::Live,
            pruned: false,
        };

        // ---- commit
        self.sequence = sequence;
        self.clock = now;
        let mut pc = parent;
        pc.budget = parent_budget;
        self.capabilities.set(parent_id as usize, pc);
        if let Some(p) = new_pool {
            self.pools.push(p);
        }
        self.capabilities.push(child);
        self.n_capabilities = self.n_capabilities + 1;

        proof {
            let caps0 = s0.capabilities@;
            let i = parent_id as int;
            let caps1 = caps0.update(i, pc);
            assert(self.capabilities@ == caps1.push(child));
            let po = parent.origin;
            // T2 edge for the child.
            lemma_subset_trans(terms.scope, parent.scope, po.scope);
            lemma_expiry_within_trans(terms.expiry, parent.expiry, po.expiry);
            lemma_admits_child_weaken(parent.depth, po.depth, terms.depth);
            lemma_subset_refl(terms.scope);
            lemma_expiry_within_refl(terms.expiry);
            lemma_depth_within_refl(terms.depth);
            lemma_budget_within_refl(terms.budget);
            assert(edge_ok(po, terms));
            lemma_fresh_pool_empty(&s0);
            assert(s0.cap_ok(i));
            assert forall|j: int| 0 <= j < self.capabilities@.len() implies #[trigger] self.cap_ok(j) by {
                if j < caps0.len() {
                    assert(s0.cap_ok(j));
                    if let Some(p) = self.capabilities@[j].parent {
                        assert(self.capabilities@[p as int].origin == caps0[p as int].origin);
                        assert(self.capabilities@[p as int].root == caps0[p as int].root);
                    }
                    if let Some(q) = caps0[j].pool {
                        assert(self.pools@[q as int] == s0.pools@[q as int]);
                    }
                } else {
                    assert(self.capabilities@[j] == child);
                    assert(self.capabilities@[i].origin == po);
                    if let Some(q) = child.pool {
                        if new_pool is None {
                            assert(self.pools@[q as int] == s0.pools@[q as int]);
                        }
                    }
                }
            }
            assert forall|p: int| 0 <= p < self.pools@.len() implies #[trigger] self.pool_ok(p) by {
                lemma_sum_update(caps0, i, pc, p);
                lemma_sum_push(caps1, child, p);
                if p < s0.pools@.len() {
                    assert(s0.pool_ok(p));
                    assert(self.pools@[p] == s0.pools@[p]);
                }
            }
            assert forall|q: int| 0 <= q < self.pools@.len() implies #[trigger] self.pool_ref_ok(q) by {
                if q < s0.pools@.len() {
                    assert(s0.pool_ref_ok(q));
                    assert(self.pools@[q] == s0.pools@[q]);
                }
            }
            assert forall|r: int| 0 <= r < self.roots@.len() implies #[trigger] self.root_ok(r) by {
                assert(s0.root_ok(r));
            }
            assert forall|k: int| 0 <= k < self.reservations@.len() implies #[trigger] self.res_ok(k) by {
                assert(s0.res_ok(k));
                if let Some(q) = s0.reservations@[k].pool {
                    assert(self.pools@[q as int] == s0.pools@[q as int]);
                }
            }
            lemma_retired_frame(&s0, &*self);
        }
        Ok(Effect::Derived { parent: parent_id, child: child_id, owner })
    }

    /// Mirror of `plan_attenuate` + the `Attenuate` commit.
    fn attenuate(&mut self, caller: AgentId, id: CapabilityId, terms: Terms, sequence: u64, now: Tick)
        -> (r: Result<Effect, Denial>)
        requires old(self).inv(),
        ensures post(&*old(self), &*final(self), r),
    {
        let cap = match self.owned_live(caller, id, now) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };
        if !terms.scope.is_well_formed() {
            return Err(Denial::InvalidScope);
        }
        if !is_subset(&terms.scope, &cap.scope) {
            return Err(Denial::ScopeNotAttenuated);
        }
        if !terms.depth.within(cap.depth) {
            return Err(Denial::DepthNotAttenuated);
        }
        if !terms.expiry.within(cap.expiry) {
            return Err(Denial::ExpiryNotAttenuated);
        }
        if terms.expiry.is_expired_at(now) {
            return Err(Denial::AlreadyExpired);
        }
        let ghost s0 = *old(self);
        proof { assert(s0.cap_ok(id as int)); }
        let (pool, pool_discarded, new_pool, discarded): (Option<PoolId>, Option<(PoolId, u64)>, Option<Pool>, u64) =
            match (cap.budget, terms.budget) {
                (Budget::Finite(b), Budget::Finite(n)) => {
                    if n > b {
                        return Err(Denial::BudgetNotAttenuated);
                    }
                    let discarded = b - n;
                    let pd = match self.discard_into(cap.pool, discarded) {
                        Ok(v) => v,
                        Err(e) => return Err(e),
                    };
                    (cap.pool, pd, None, discarded)
                },
                (Budget::Finite(_), Budget::Unlimited) => return Err(Denial::BudgetNotAttenuated),
                (Budget::Unlimited, Budget::Unlimited) => (None, None, None, 0),
                (Budget::Unlimited, Budget::Finite(n)) => {
                    if self.pools.len() as u64 == u64::MAX {
                        return Err(Denial::ArithmeticOverflow);
                    }
                    let pid = self.pools.len() as u64;
                    (Some(pid), None, Some(Pool { root: cap.root, anchor: id, initial: n, consumed: 0, discarded: 0, pruned: false }), 0)
                },
            };

        // ---- commit
        self.sequence = sequence;
        self.clock = now;
        let mut c = cap;
        c.scope = terms.scope;
        c.budget = terms.budget;
        c.depth = terms.depth;
        c.expiry = terms.expiry;
        c.pool = pool;
        self.capabilities.set(id as usize, c);
        self.set_pool_discarded(pool_discarded);
        if let Some(p) = new_pool {
            self.pools.push(p);
        }

        proof {
            let caps0 = s0.capabilities@;
            let i = id as int;
            let o = cap.origin;
            assert(self.capabilities@ == caps0.update(i, c));
            lemma_subset_trans(terms.scope, cap.scope, o.scope);
            lemma_expiry_within_trans(terms.expiry, cap.expiry, o.expiry);
            lemma_depth_within_trans(terms.depth, cap.depth, o.depth);
            lemma_budget_within_trans(terms.budget, cap.budget, o.budget);
            lemma_fresh_pool_empty(&s0);
            assert forall|j: int| 0 <= j < self.capabilities@.len() implies #[trigger] self.cap_ok(j) by {
                assert(s0.cap_ok(j));
                if let Some(p) = self.capabilities@[j].parent {
                    assert(self.capabilities@[p as int].origin == caps0[p as int].origin);
                    assert(self.capabilities@[p as int].root == caps0[p as int].root);
                }
                if let Some(q) = self.capabilities@[j].pool {
                    if q < s0.pools@.len() {
                        assert(self.pools@[q as int].root == s0.pools@[q as int].root);
                    }
                }
            }
            assert forall|p: int| 0 <= p < self.pools@.len() implies #[trigger] self.pool_ok(p) by {
                lemma_sum_update(caps0, i, c, p);
                if p < s0.pools@.len() {
                    assert(s0.pool_ok(p));
                }
            }
            assert forall|q: int| 0 <= q < self.pools@.len() implies #[trigger] self.pool_ref_ok(q) by {
                if q < s0.pools@.len() {
                    assert(s0.pool_ref_ok(q));
                }
            }
            assert forall|r: int| 0 <= r < self.roots@.len() implies #[trigger] self.root_ok(r) by {
                assert(s0.root_ok(r));
            }
            assert forall|k: int| 0 <= k < self.reservations@.len() implies #[trigger] self.res_ok(k) by {
                assert(s0.res_ok(k));
                if let Some(q) = s0.reservations@[k].pool {
                    assert(self.pools@[q as int].root == s0.pools@[q as int].root);
                }
            }
            lemma_retired_frame(&s0, &*self);
        }
        Ok(Effect::Attenuated { capability: id, discarded })
    }

    /// Mirror of `plan_transfer` + the `Transfer` commit.
    fn transfer(&mut self, caller: AgentId, id: CapabilityId, to: AgentId, sequence: u64, now: Tick)
        -> (r: Result<Effect, Denial>)
        requires old(self).inv(),
        ensures
            post(&*old(self), &*final(self), r),
            r is Ok ==> {
                &&& old(self).capabilities@[id as int].depth != Depth::Finite(0)
                &&& Some(final(self).capabilities@[id as int].depth) == old(self).capabilities@[id as int].depth.decrement_spec()
            },
    {
        let cap = match self.owned_live(caller, id, now) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };
        let depth = match cap.depth.decrement() {
            Some(d) => d,
            None => return Err(Denial::NotDelegatable),
        };
        if let Err(e) = self.require_active(to) {
            return Err(e);
        }
        if agent_eq(to, caller) {
            return Err(Denial::SelfTransfer);
        }
        let ghost s0 = *old(self);
        self.sequence = sequence;
        self.clock = now;
        let mut c = cap;
        c.owner = to;
        c.depth = depth;
        self.capabilities.set(id as usize, c);
        proof {
            assert(s0.cap_ok(id as int));
            self.lemma_update_same_terms(&s0, id as int);
        }
        Ok(Effect::Transferred { capability: id, from: caller, to })
    }

    /// Mirror of `plan_compact_epoch` + the `CompactEpoch` commit (ADR-0031).
    /// Pruned records become tombstones (`pruned`), which every lookup
    /// treats as absent, so ids stay indices and are never reused.
    fn compact(&mut self, sequence: u64, now: Tick) -> (r: Result<Effect, Denial>)
        requires old(self).inv(),
        ensures
            post(&*old(self), &*final(self), r),
            r matches Ok(eff) ==> compacted(&*old(self), &*final(self), eff),
    {
        let e = self.epoch;
        let (ps, n_principals, kept_principals) = sweep_principals(&self.principals, e);
        let (rs, n_roots, kept_roots) = sweep_roots(&self.roots, e);
        let m = first_current_root(&self.roots, e);
        let below: u128 = if (m as u128) > self.retired_roots_below { m as u128 } else { self.retired_roots_below };
        let (pl, n_pools, initial, consumed, pool_discarded) = match sweep_pools(&self.pools, &self.roots, e) {
            Some(v) => v,
            None => return Err(Denial::ArithmeticOverflow),
        };
        let (cs, n_caps, kept_caps, stranded) = match sweep_caps(&self.capabilities, &self.roots, e) {
            Some(v) => v,
            None => return Err(Denial::ArithmeticOverflow),
        };
        let (vs, n_res, kept_res) = sweep_reservations(&self.reservations, &self.roots, e);
        // Balances stranded in pruned records join D.
        if pool_discarded > u128::MAX - stranded {
            return Err(Denial::ArithmeticOverflow);
        }
        let discarded = pool_discarded + stranded;
        let old_r = self.retired;
        if old_r.pools > u64::MAX - n_pools || old_r.initial > u128::MAX - initial
            || old_r.consumed > u128::MAX - consumed || old_r.discarded > u128::MAX - discarded {
            return Err(Denial::ArithmeticOverflow);
        }
        let retired = RetiredPools {
            pools: old_r.pools + n_pools,
            initial: old_r.initial + initial,
            consumed: old_r.consumed + consumed,
            discarded: old_r.discarded + discarded,
        };

        // ---- commit
        let ghost s0 = *old(self);
        self.sequence = sequence;
        self.clock = now;
        self.principals = ps;
        self.roots = rs;
        self.capabilities = cs;
        self.pools = pl;
        self.reservations = vs;
        self.n_principals = kept_principals;
        self.n_capabilities = kept_caps;
        self.n_roots = kept_roots;
        self.n_reservations = kept_res;
        self.retired_roots_below = below;
        self.retired = retired;
        proof { lemma_compact(&s0, &*self, m as int); }
        Ok(Effect::EpochCompacted {
            principals: n_principals,
            capabilities: n_caps,
            roots: n_roots,
            pools: n_pools,
            reservations: n_res,
            initial,
            consumed,
            discarded,
        })
    }

    /// Mirror of `plan_drop` + the `Drop` commit.
    fn drop_cap(&mut self, caller: AgentId, id: CapabilityId, sequence: u64, now: Tick)
        -> (r: Result<Effect, Denial>)
        requires old(self).inv(),
        ensures post(&*old(self), &*final(self), r),
    {
        let cap = match self.owned_live(caller, id, now) {
            Ok(c) => c,
            Err(e) => return Err(e),
        };
        let discarded = match cap.budget {
            Budget::Finite(b) => b,
            Budget::Unlimited => 0,
        };
        let pool_discarded = match self.discard_into(cap.pool, discarded) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        let ghost s0 = *old(self);
        proof { assert(s0.cap_ok(id as int)); }
        self.sequence = sequence;
        self.clock = now;
        let mut c = cap;
        if cap.budget.is_finite() {
            c.budget = Budget::Finite(0);
        }
        c.status = Status::Dropped;
        self.capabilities.set(id as usize, c);
        self.set_pool_discarded(pool_discarded);
        proof {
            let caps0 = s0.capabilities@;
            let i = id as int;
            assert(self.capabilities@ == caps0.update(i, c));
            assert forall|j: int| 0 <= j < self.capabilities@.len() implies #[trigger] self.cap_ok(j) by {
                assert(s0.cap_ok(j));
                if let Some(p) = self.capabilities@[j].parent {
                    assert(self.capabilities@[p as int].origin == caps0[p as int].origin);
                    assert(self.capabilities@[p as int].root == caps0[p as int].root);
                }
                if let Some(q) = self.capabilities@[j].pool {
                    assert(self.pools@[q as int].root == s0.pools@[q as int].root);
                }
            }
            assert forall|p: int| 0 <= p < self.pools@.len() implies #[trigger] self.pool_ok(p) by {
                assert(s0.pool_ok(p));
                lemma_sum_update(caps0, i, c, p);
            }
            assert forall|q: int| 0 <= q < self.pools@.len() implies #[trigger] self.pool_ref_ok(q) by {
                assert(s0.pool_ref_ok(q));
            }
            assert forall|r: int| 0 <= r < self.roots@.len() implies #[trigger] self.root_ok(r) by {
                assert(s0.root_ok(r));
            }
            assert forall|k: int| 0 <= k < self.reservations@.len() implies #[trigger] self.res_ok(k) by {
                assert(s0.res_ok(k));
                if let Some(q) = s0.reservations@[k].pool {
                    assert(self.pools@[q as int].root == s0.pools@[q as int].root);
                }
            }
            lemma_retired_frame(&s0, &*self);
        }
        Ok(Effect::Dropped { capability: id, discarded })
    }
}

} // verus!
