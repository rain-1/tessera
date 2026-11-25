//! Mirror of `crates/capability-core/src/{ids,command,state,step}.rs`.
//!
//! Representation: the core keeps `BTreeMap`s keyed by identifiers that are
//! allocated from monotone counters and never removed or recycled. Such a
//! map is exactly a dense vector indexed by the raw identifier, so the
//! model stores `Vec`s (ghost view: `Seq`) and the counters `next_*` are the
//! vector lengths:
//!
//! | core                                       | model                                   |
//! |--------------------------------------------|-----------------------------------------|
//! | `principals: BTreeMap<AgentId, _>`         | `principals[serial]` + stored epoch     |
//! | `capabilities: BTreeMap<CapabilityId, _>`  | `capabilities[id]`                      |
//! | `roots`, `pools`, `reservations`           | `roots[id]`, `pools[id]`, `reservations[id]` |
//! | `spent_nonces: BTreeMap<Nonce, RootId>`    | `spent_nonces: Vec<SpentNonce>` (insertion order) |
//! | `requests: BTreeMap<(AgentId, RequestId), ReservationId>` | linear search over `reservations` |
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootRecord {
    pub capability: CapabilityId,
    pub kind: RootKind,
    pub recipient: AgentId,
    pub terms: Terms,
    pub epoch: u64,
    pub issued_at: Tick,
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pool {
    pub root: RootId,
    pub anchor: CapabilityId,
    pub initial: u64,
    pub consumed: u64,
    pub discarded: u64,
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
pub enum Effect {
    PrincipalCreated { agent: AgentId },
    PrincipalTerminated { agent: AgentId },
    ClockAdvanced { now: Tick },
    EpochAdvanced { epoch: u64, terminated_principals: u64, abandoned_reservations: u64 },
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
            &&& caps[p as int].status != Status::Revoked
            &&& !caps[p as int].origin.expiry.is_expired_at_spec(now)
            &&& chain_ok(caps, caps[p as int].parent, now, (fuel - 1) as nat)
        },
    }
}

impl State {
    pub open spec fn principal_spec(&self, a: AgentId) -> Option<PrincipalStatus> {
        if (a.serial as int) < self.principals@.len() && self.principals@[a.serial as int].epoch == a.epoch {
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
    }

    /// The proved ledger invariant (subset of `check_invariant`).
    pub open spec fn inv(&self) -> bool {
        &&& forall|i: int| 0 <= i < self.capabilities@.len() ==> #[trigger] self.cap_ok(i)
        &&& forall|p: int| 0 <= p < self.pools@.len() ==> #[trigger] self.pool_ok(p)
        &&& self.nonces_ok()
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

/// Frame: `inv` depends only on capabilities, pools, roots and spent nonces.
pub proof fn lemma_inv_frame(s0: &State, s1: &State)
    requires
        s0.inv(),
        s1.capabilities@ == s0.capabilities@, s1.pools@ == s0.pools@,
        s1.roots@ == s0.roots@, s1.spent_nonces@ == s0.spent_nonces@,
    ensures s1.inv(),
{
    assert forall|i: int| 0 <= i < s1.capabilities@.len() implies #[trigger] s1.cap_ok(i) by {
        assert(s0.cap_ok(i));
    }
    assert forall|p: int| 0 <= p < s1.pools@.len() implies #[trigger] s1.pool_ok(p) by {
        assert(s0.pool_ok(p));
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

fn terminate_all(ps: &Vec<Principal>) -> (r: (Vec<Principal>, u64))
    ensures r.0@.len() == ps@.len(),
{
    let mut out: Vec<Principal> = Vec::new();
    let mut n: u64 = 0;
    let mut i: usize = 0;
    while i < ps.len()
        invariant i <= ps@.len(), out@.len() == i, n <= i,
        decreases ps@.len() - i,
    {
        let p = ps[i];
        if let PrincipalStatus::Active = p.status {
            n = n + 1;
        }
        out.push(Principal { epoch: p.epoch, status: PrincipalStatus::Terminated });
        i = i + 1;
    }
    (out, n)
}

fn abandon_all(rs: &Vec<ReservationRecord>) -> (r: (Vec<ReservationRecord>, u64))
    ensures r.0@.len() == rs@.len(),
{
    let mut out: Vec<ReservationRecord> = Vec::new();
    let mut n: u64 = 0;
    let mut i: usize = 0;
    while i < rs.len()
        invariant i <= rs@.len(), out@.len() == i, n <= i,
        decreases rs@.len() - i,
    {
        let mut r = rs[i];
        if let ReservationStatus::Reserved = r.status {
            n = n + 1;
            r.status = ReservationStatus::Abandoned;
        }
        out.push(r);
        i = i + 1;
    }
    (out, n)
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
        }
    }

    /// Mirror of `State::principal`.
    pub fn principal(&self, a: AgentId) -> (r: Option<PrincipalStatus>)
        ensures r == self.principal_spec(a),
    {
        if (a.serial as u128) < (self.principals.len() as u128) {
            let p = self.principals[a.serial as usize];
            if p.epoch == a.epoch { Some(p.status) } else { None }
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
            },
    {
        if id >= self.capabilities.len() as u128 {
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
        ensures r matches Some(k) ==> (k as int) < self.reservations@.len(),
    {
        let mut k: usize = 0;
        while k < self.reservations.len()
            invariant k <= self.reservations@.len(),
            decreases self.reservations@.len() - k,
        {
            let r = self.reservations[k];
            if agent_eq(r.owner, caller) && r.request_id == request_id {
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
                Some(pid) => (pid as int) < self.pools@.len()
                    && self.pools@[pid as int].discarded + amount <= u64::MAX
                    && v == Some((pid, (self.pools@[pid as int].discarded + amount) as u64)),
            },
    {
        match pool {
            None => Ok(None),
            Some(pid) => {
                if pid >= self.pools.len() as u64 {
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
    {
        match cmd {
            AdminCommand::CreatePrincipal => {
                if let Err(e) = require_capacity(self.principals.len(), self.limits.max_principals, Resource::Principals) {
                    return Err(e);
                }
                let agent = AgentId { epoch: self.epoch, serial: self.principals.len() as u64 };
                if self.principals.len() as u64 == u64::MAX {
                    return Err(Denial::ArithmeticOverflow);
                }
                self.sequence = sequence;
                self.clock = now;
                self.principals.push(Principal { epoch: self.epoch, status: PrincipalStatus::Active });
                proof { lemma_inv_frame(&*old(self), &*self); }
                Ok(Effect::PrincipalCreated { agent })
            },
            AdminCommand::TerminatePrincipal { agent } => {
                match self.principal(agent) {
                    None => Err(Denial::UnknownPrincipal),
                    Some(PrincipalStatus::Terminated) => Err(Denial::AlreadyTerminated),
                    Some(PrincipalStatus::Active) => {
                        self.sequence = sequence;
                        self.clock = now;
                        let i = agent.serial as usize;
                        let p = Principal { epoch: self.principals[i].epoch, status: PrincipalStatus::Terminated };
                        self.principals.set(i, p);
                        proof { lemma_inv_frame(&*old(self), &*self); }
                        Ok(Effect::PrincipalTerminated { agent })
                    },
                }
            },
            AdminCommand::AdvanceClock => {
                self.sequence = sequence;
                self.clock = now;
                proof { lemma_inv_frame(&*old(self), &*self); }
                Ok(Effect::ClockAdvanced { now })
            },
            AdminCommand::BumpEpoch => {
                if self.epoch == u64::MAX {
                    return Err(Denial::ArithmeticOverflow);
                }
                let epoch = self.epoch + 1;
                let (ps, terminated) = terminate_all(&self.principals);
                let (rs, abandoned) = abandon_all(&self.reservations);
                self.sequence = sequence;
                self.clock = now;
                self.epoch = epoch;
                self.principals = ps;
                self.reservations = rs;
                proof { lemma_inv_frame(&*old(self), &*self); }
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
            AdminCommand::Revoke { capability } => {
                if capability >= self.capabilities.len() as u128 {
                    return Err(Denial::UnknownCapability);
                }
                if let Status::Revoked = self.capabilities[capability as usize].status {
                    return Err(Denial::AlreadyRevoked);
                }
                self.commit_revoke(capability, sequence, now);
                Ok(Effect::Revoked { capability })
            },
            AdminCommand::RecordOutcome { reservation, outcome } => {
                if reservation >= self.reservations.len() as u64 {
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
                proof { lemma_inv_frame(&*old(self), &*self); }
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
        if let Err(e) = require_capacity(self.capabilities.len(), self.limits.max_capabilities, Resource::Capabilities) {
            return Err(e);
        }
        if let Err(e) = require_capacity(self.roots.len(), self.limits.max_roots, Resource::Roots) {
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
        };
        let root = RootRecord { capability: cap_id, kind, recipient, terms, epoch: self.epoch, issued_at: now };

        // ---- commit
        let ghost s0 = *old(self);
        self.sequence = sequence;
        self.clock = now;
        if let Some(n) = nonce {
            self.spent_nonces.push(SpentNonce { nonce: n, root: root_id });
        }
        if let Budget::Finite(n) = terms.budget {
            self.pools.push(Pool { root: root_id, anchor: cap_id, initial: n, consumed: 0, discarded: 0 });
        }
        self.capabilities.push(capability);
        self.roots.push(root);

        proof {
            lemma_subset_refl(terms.scope);
            lemma_expiry_within_refl(terms.expiry);
            lemma_depth_within_refl(terms.depth);
            lemma_budget_within_refl(terms.budget);
            lemma_fresh_pool_empty(&s0);
            let caps0 = s0.capabilities@;
            assert(self.capabilities@ == caps0.push(capability));
            assert forall|i: int| 0 <= i < self.capabilities@.len() implies #[trigger] self.cap_ok(i) by {
                if i < caps0.len() {
                    assert(s0.cap_ok(i));
                    assert(self.capabilities@[i] == caps0[i]);
                    if let Some(p) = caps0[i].parent {
                        assert(self.capabilities@[p as int] == caps0[p as int]);
                    }
                }
            }
            assert forall|p: int| 0 <= p < self.pools@.len() implies #[trigger] self.pool_ok(p) by {
                lemma_sum_push(caps0, capability, p);
                if p < s0.pools@.len() {
                    assert(s0.pool_ok(p));
                    assert(self.pools@[p] == s0.pools@[p]);
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
        requires old(self).inv(), (id as int) < old(self).capabilities@.len(),
        ensures
            post(&*old(self), &*final(self), Ok(Effect::Revoked { capability: id })),
    {
        let ghost s0 = *old(self);
        let mut c = self.capabilities[id as usize];
        c.status = Status::Revoked;
        self.sequence = sequence;
        self.clock = now;
        self.capabilities.set(id as usize, c);
        proof { self.lemma_update_same_terms(&s0, id as int); }
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
            }
        }
        assert forall|p: int| 0 <= p < self.pools@.len() implies #[trigger] self.pool_ok(p) by {
            assert(s0.pool_ok(p));
            lemma_sum_update(caps0, i, c, p);
        }
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
                if capability >= self.capabilities.len() as u128 {
                    return Err(Denial::UnknownCapability);
                }
                if let Status::Revoked = self.capabilities[capability as usize].status {
                    return Err(Denial::AlreadyRevoked);
                }
                let authorized = self.may_revoke(caller, capability);
                if !authorized {
                    return Err(Denial::NotAuthorizedToRevoke);
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
                if pid >= self.pools.len() as u64 {
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
        if let Err(e) = require_capacity(self.reservations.len(), self.limits.max_reservations, Resource::Reservations) {
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

        proof {
            let caps0 = s0.capabilities@;
            let i = id as int;
            assert(self.capabilities@ == caps0.update(i, c));
            assert forall|j: int| 0 <= j < self.capabilities@.len() implies #[trigger] self.cap_ok(j) by {
                assert(s0.cap_ok(j));
                if let Some(p) = self.capabilities@[j].parent {
                    assert(self.capabilities@[p as int].origin == caps0[p as int].origin);
                }
            }
            assert forall|p: int| 0 <= p < self.pools@.len() implies #[trigger] self.pool_ok(p) by {
                assert(s0.pool_ok(p));
                lemma_sum_update(caps0, i, c, p);
            }
        }
        Ok(Effect::Reserved { reservation: rid })
    }

    /// Mirror of `plan_derive` + the `Derive` commit (SPLIT and DELEGATE).
    fn derive(&mut self, caller: AgentId, parent_id: CapabilityId, owner: AgentId, terms: Terms,
              sequence: u64, now: Tick) -> (r: Result<Effect, Denial>)
        requires old(self).inv(),
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
        if let Err(e) = require_capacity(self.capabilities.len(), self.limits.max_capabilities, Resource::Capabilities) {
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
                (Some(pid), Some(Pool { root: parent.root, anchor: child_id, initial: n, consumed: 0, discarded: 0 }))
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
            assert forall|j: int| 0 <= j < self.capabilities@.len() implies #[trigger] self.cap_ok(j) by {
                if j < caps0.len() {
                    assert(s0.cap_ok(j));
                    if let Some(p) = self.capabilities@[j].parent {
                        assert(self.capabilities@[p as int].origin == caps0[p as int].origin);
                    }
                } else {
                    assert(self.capabilities@[j] == child);
                    assert(self.capabilities@[i].origin == po);
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
                    (Some(pid), None, Some(Pool { root: cap.root, anchor: id, initial: n, consumed: 0, discarded: 0 }), 0)
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
                }
            }
            assert forall|p: int| 0 <= p < self.pools@.len() implies #[trigger] self.pool_ok(p) by {
                lemma_sum_update(caps0, i, c, p);
                if p < s0.pools@.len() {
                    assert(s0.pool_ok(p));
                }
            }
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
                }
            }
            assert forall|p: int| 0 <= p < self.pools@.len() implies #[trigger] self.pool_ok(p) by {
                assert(s0.pool_ok(p));
                lemma_sum_update(caps0, i, c, p);
            }
        }
        Ok(Effect::Dropped { capability: id, discarded })
    }
}

} // verus!
