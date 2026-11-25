//! The deterministic transition function (spec §5).
//!
//! Structure (designed for a later Verus port):
//!
//! 1. [`plan`] is a pure, read-only function `(&State, &Command, now) ->
//!    Result<Plan, Denial>`. It performs *every* check, including all
//!    checked arithmetic, id allocation and capacity checks, and computes the
//!    exact new values to write.
//! 2. [`commit`] applies a [`Plan`] and cannot fail: no arithmetic, no
//!    lookups that can miss on a state that `plan` accepted.
//!
//! Hence a denial never mutates the state (T8), and every successful
//! transition is atomic at the single call to `commit`.

// Plans are short-lived stack values built once per step; boxing the large
// variants would only add allocation and indirection for the verifier.
#![allow(clippy::large_enum_variant)]

use crate::budget::{Budget, Depth, Tick};
use crate::command::{
    AdminCommand, AgentCommand, AuthenticatedCommand, Denial, Effect, Reservation, Resource,
    VerifiedApproval,
};
use crate::ids::{AgentId, CapabilityId, Nonce, PoolId, RequestId, ReservationId, RootId};
use crate::scope::{Operation, is_subset, permits};
use crate::state::{
    Capability, Outcome, Pool, PrincipalStatus, ReservationRecord, ReservationStatus, RootKind,
    RootRecord, State, Status, Terms,
};

/// Apply one authenticated command at trusted time `now`.
///
/// requires: `check_invariant(state).is_ok()`
/// ensures:  `Err(_) ==> *state == old(*state)`
/// ensures:  `check_invariant(state).is_ok()` (preservation; T1-T8)
/// ensures:  `Ok(Effect::AlreadyReserved{..}) ==> *state == old(*state)`
pub fn step(state: &mut State, command: AuthenticatedCommand, now: Tick) -> Result<Effect, Denial> {
    match plan(state, &command, now)? {
        Plan::Duplicate {
            reservation,
            status,
        } => Ok(Effect::AlreadyReserved {
            reservation,
            status,
        }),
        Plan::Apply { sequence, change } => Ok(commit(state, sequence, now, change)),
    }
}

/// Would `command` succeed at `now`? Pure; never mutates.
///
/// ensures: `result.is_ok() == step(&mut copy_of(state), command, now).is_ok()`
pub fn validate_command(
    state: &State,
    command: &AuthenticatedCommand,
    now: Tick,
) -> Result<(), Denial> {
    plan(state, command, now).map(|_| ())
}

// ---------------------------------------------------------------------------
// Plans
// ---------------------------------------------------------------------------

/// Fully validated transition with all new values precomputed.
enum Plan {
    /// Repeated CONSUME request id: report, do not mutate.
    Duplicate {
        reservation: ReservationId,
        status: ReservationStatus,
    },
    /// Mutating transition; `sequence` is the new sequence number.
    Apply { sequence: u64, change: Change },
}

/// New-root payload (MINT / baseline).
struct NewRoot {
    root: RootRecord,
    capability: Capability,
    pool: Option<Pool>,
    nonce: Option<Nonce>,
    next_capability: u128,
    next_root: u128,
    next_pool: u64,
}

enum Change {
    CreatePrincipal {
        agent: AgentId,
        next_serial: u64,
    },
    TerminatePrincipal {
        agent: AgentId,
    },
    AdvanceClock,
    BumpEpoch {
        epoch: u64,
        terminated: u64,
        abandoned: u64,
    },
    NewRoot(NewRoot),
    Consume {
        capability: CapabilityId,
        new_budget: Budget,
        pool_consumed: Option<(PoolId, u64)>,
        record: ReservationRecord,
        next_reservation: u64,
    },
    Derive {
        parent: CapabilityId,
        parent_budget: Budget,
        child: Capability,
        new_pool: Option<Pool>,
        next_capability: u128,
        next_pool: u64,
    },
    Attenuate {
        capability: CapabilityId,
        terms: Terms,
        pool: Option<PoolId>,
        pool_discarded: Option<(PoolId, u64)>,
        new_pool: Option<Pool>,
        next_pool: u64,
        discarded: u64,
    },
    Transfer {
        capability: CapabilityId,
        from: AgentId,
        to: AgentId,
        depth: Depth,
    },
    Revoke {
        capability: CapabilityId,
    },
    Drop {
        capability: CapabilityId,
        pool_discarded: Option<(PoolId, u64)>,
        discarded: u64,
    },
    RecordOutcome {
        reservation: ReservationId,
        status: ReservationStatus,
    },
}

fn plan(s: &State, command: &AuthenticatedCommand, now: Tick) -> Result<Plan, Denial> {
    // Trusted time is monotonic within an epoch. BumpEpoch is exempt (fresh
    // monotonic clock after restart); see AdminCommand::BumpEpoch.
    let is_bump = matches!(
        command,
        AuthenticatedCommand::Operator(AdminCommand::BumpEpoch)
    );
    if !is_bump && now < s.clock {
        return Err(Denial::ClockRegression);
    }
    let sequence = s
        .sequence
        .checked_add(1)
        .ok_or(Denial::ArithmeticOverflow)?;
    let change = match command {
        AuthenticatedCommand::Operator(cmd) => plan_admin(s, cmd, now)?,
        AuthenticatedCommand::Agent { caller, command } => {
            require_active(s, *caller)?;
            match plan_agent(s, *caller, command, now)? {
                AgentPlan::Change(c) => c,
                AgentPlan::Duplicate(reservation, status) => {
                    return Ok(Plan::Duplicate {
                        reservation,
                        status,
                    });
                }
            }
        }
    };
    Ok(Plan::Apply { sequence, change })
}

enum AgentPlan {
    Change(Change),
    Duplicate(ReservationId, ReservationStatus),
}

fn plan_admin(s: &State, cmd: &AdminCommand, now: Tick) -> Result<Change, Denial> {
    match cmd {
        AdminCommand::CreatePrincipal => plan_create_principal(s),
        AdminCommand::TerminatePrincipal { agent } => plan_terminate(s, *agent),
        AdminCommand::AdvanceClock => Ok(Change::AdvanceClock),
        AdminCommand::BumpEpoch => plan_bump_epoch(s),
        AdminCommand::Mint { approval } => plan_mint(s, approval, now),
        AdminCommand::InstallBaseline { recipient, terms } => {
            plan_new_root(s, *recipient, *terms, RootKind::Baseline, None, now)
        }
        AdminCommand::Revoke { capability } => plan_admin_revoke(s, *capability),
        AdminCommand::RecordOutcome {
            reservation,
            outcome,
        } => plan_record_outcome(s, *reservation, *outcome),
    }
}

fn plan_agent(
    s: &State,
    caller: AgentId,
    cmd: &AgentCommand,
    now: Tick,
) -> Result<AgentPlan, Denial> {
    let c = match cmd {
        AgentCommand::Consume {
            request_id,
            capability,
            operation,
        } => {
            return plan_consume(s, caller, *request_id, *capability, *operation, now);
        }
        AgentCommand::Split { capability, terms } => {
            plan_derive(s, caller, *capability, caller, *terms, now)?
        }
        AgentCommand::Delegate {
            capability,
            recipient,
            terms,
        } => {
            require_active(s, *recipient)?;
            plan_derive(s, caller, *capability, *recipient, *terms, now)?
        }
        AgentCommand::Attenuate { capability, terms } => {
            plan_attenuate(s, caller, *capability, *terms, now)?
        }
        AgentCommand::Transfer {
            capability,
            recipient,
        } => plan_transfer(s, caller, *capability, *recipient, now)?,
        AgentCommand::Revoke { capability } => plan_agent_revoke(s, caller, *capability)?,
        AgentCommand::Drop { capability } => plan_drop(s, caller, *capability, now)?,
    };
    Ok(AgentPlan::Change(c))
}

// ---------------------------------------------------------------------------
// Shared checks (small pure functions)
// ---------------------------------------------------------------------------

/// ensures: Ok ==> s.is_active(agent)
fn require_active(s: &State, agent: AgentId) -> Result<(), Denial> {
    if agent.epoch() != s.epoch {
        return Err(Denial::StaleEpoch);
    }
    match s.principals.get(&agent) {
        None => Err(Denial::UnknownPrincipal),
        Some(PrincipalStatus::Terminated) => Err(Denial::PrincipalTerminated),
        Some(PrincipalStatus::Active) => Ok(()),
    }
}

/// ensures: Ok(c) ==> c.owner == caller && s.live(c.id, now).is_ok()
fn owned_live(
    s: &State,
    caller: AgentId,
    id: CapabilityId,
    now: Tick,
) -> Result<&Capability, Denial> {
    let cap = s.capabilities.get(&id).ok_or(Denial::UnknownCapability)?;
    if cap.owner != caller {
        return Err(Denial::NotOwner);
    }
    s.live(id, now).map_err(Denial::NotLive)
}

/// Terms acceptable for a *new* grant (root or child) at `now`.
fn require_issuable(terms: &Terms, now: Tick) -> Result<(), Denial> {
    if !terms.scope.is_well_formed() {
        return Err(Denial::InvalidScope);
    }
    if terms.expiry.is_expired_at(now) {
        return Err(Denial::AlreadyExpired);
    }
    if terms.budget == Budget::Finite(0) {
        return Err(Denial::ZeroAllocation);
    }
    Ok(())
}

fn require_capacity(len: usize, max: u64, r: Resource) -> Result<(), Denial> {
    // usize -> u64 is lossless on every supported (<= 64-bit) target; fall
    // back to "full" otherwise.
    let len = u64::try_from(len).unwrap_or(u64::MAX);
    if len >= max {
        Err(Denial::CapacityExceeded(r))
    } else {
        Ok(())
    }
}

fn bump_u128(x: u128) -> Result<u128, Denial> {
    x.checked_add(1).ok_or(Denial::ArithmeticOverflow)
}

fn bump_u64(x: u64) -> Result<u64, Denial> {
    x.checked_add(1).ok_or(Denial::ArithmeticOverflow)
}

/// Discard `amount` finite units into `pool`: returns the pool's new
/// `discarded` counter.
fn discard_into(
    s: &State,
    pool: Option<PoolId>,
    amount: u64,
) -> Result<Option<(PoolId, u64)>, Denial> {
    match pool {
        None => Ok(None),
        Some(pid) => {
            let p = s.pools.get(&pid).ok_or(Denial::ArithmeticOverflow)?;
            let d = p
                .discarded
                .checked_add(amount)
                .ok_or(Denial::ArithmeticOverflow)?;
            Ok(Some((pid, d)))
        }
    }
}

// ---------------------------------------------------------------------------
// Administrative transitions
// ---------------------------------------------------------------------------

/// requires: true
/// ensures:  Ok ==> fresh AgentId { epoch: s.epoch, serial: s.next_agent_serial }
fn plan_create_principal(s: &State) -> Result<Change, Denial> {
    require_capacity(
        s.principals.len(),
        s.limits.max_principals,
        Resource::Principals,
    )?;
    let agent = AgentId::new(s.epoch, s.next_agent_serial);
    let next_serial = bump_u64(s.next_agent_serial)?;
    Ok(Change::CreatePrincipal { agent, next_serial })
}

/// ensures: Ok ==> principals[agent] == Active (any epoch)
fn plan_terminate(s: &State, agent: AgentId) -> Result<Change, Denial> {
    match s.principals.get(&agent) {
        None => Err(Denial::UnknownPrincipal),
        Some(PrincipalStatus::Terminated) => Err(Denial::AlreadyTerminated),
        Some(PrincipalStatus::Active) => Ok(Change::TerminatePrincipal { agent }),
    }
}

/// ensures: Ok ==> new epoch = s.epoch + 1 (checked)
fn plan_bump_epoch(s: &State) -> Result<Change, Denial> {
    let epoch = bump_u64(s.epoch)?;
    let terminated = s
        .principals
        .values()
        .filter(|p| **p == PrincipalStatus::Active)
        .count();
    let abandoned = s
        .reservations
        .values()
        .filter(|r| r.status == ReservationStatus::Reserved)
        .count();
    Ok(Change::BumpEpoch {
        epoch,
        terminated: u64::try_from(terminated).map_err(|_| Denial::ArithmeticOverflow)?,
        abandoned: u64::try_from(abandoned).map_err(|_| Denial::ArithmeticOverflow)?,
    })
}

/// MINT. requires: approval verified by the trusted approval service (A3).
/// ensures: Ok ==> nonce unspent in s && request.epoch == s.epoch &&
///          now < request.request_expires && recipient active &&
///          the root's terms == request.terms exactly.
fn plan_mint(s: &State, approval: &VerifiedApproval, now: Tick) -> Result<Change, Denial> {
    let nonce = approval.nonce();
    let req = approval.request();
    if s.spent_nonces.contains_key(&nonce) {
        return Err(Denial::NonceReused);
    }
    if req.epoch != s.epoch {
        return Err(Denial::ApprovalEpochMismatch);
    }
    if now >= req.request_expires {
        return Err(Denial::ApprovalExpired);
    }
    plan_new_root(
        s,
        req.recipient,
        req.terms,
        RootKind::Approved { nonce },
        Some(nonce),
        now,
    )
}

/// Shared root creation for MINT and baseline installation.
fn plan_new_root(
    s: &State,
    recipient: AgentId,
    terms: Terms,
    kind: RootKind,
    nonce: Option<Nonce>,
    now: Tick,
) -> Result<Change, Denial> {
    require_active(s, recipient)?;
    require_issuable(&terms, now)?;
    require_capacity(
        s.capabilities.len(),
        s.limits.max_capabilities,
        Resource::Capabilities,
    )?;
    require_capacity(s.roots.len(), s.limits.max_roots, Resource::Roots)?;
    let root_id = RootId::from_raw(s.next_root);
    let cap_id = CapabilityId::from_raw(s.next_capability);
    let next_root = bump_u128(s.next_root)?;
    let next_capability = bump_u128(s.next_capability)?;
    let (pool, pool_id, next_pool) = match terms.budget {
        Budget::Unlimited => (None, None, s.next_pool),
        Budget::Finite(n) => {
            let pid = PoolId::from_raw(s.next_pool);
            let p = Pool {
                id: pid,
                root: root_id,
                anchor: cap_id,
                initial: n,
                consumed: 0,
                discarded: 0,
            };
            (Some(p), Some(pid), bump_u64(s.next_pool)?)
        }
    };
    let capability = Capability {
        id: cap_id,
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
    let root = RootRecord {
        id: root_id,
        capability: cap_id,
        kind,
        recipient,
        terms,
        epoch: s.epoch,
        issued_at: now,
    };
    Ok(Change::NewRoot(NewRoot {
        root,
        capability,
        pool,
        nonce,
        next_capability,
        next_root,
        next_pool,
    }))
}

/// ensures: Ok ==> capability exists && status != Revoked
fn plan_admin_revoke(s: &State, id: CapabilityId) -> Result<Change, Denial> {
    let cap = s.capabilities.get(&id).ok_or(Denial::UnknownCapability)?;
    if cap.status == Status::Revoked {
        return Err(Denial::AlreadyRevoked);
    }
    Ok(Change::Revoke { capability: id })
}

/// ensures: Ok ==> reservation exists && status == Reserved
fn plan_record_outcome(s: &State, id: ReservationId, outcome: Outcome) -> Result<Change, Denial> {
    let r = s.reservations.get(&id).ok_or(Denial::UnknownReservation)?;
    if r.status != ReservationStatus::Reserved {
        return Err(Denial::ReservationAlreadyResolved);
    }
    let status = match outcome {
        Outcome::Completed => ReservationStatus::Completed,
        Outcome::Failed => ReservationStatus::Failed,
        Outcome::Unknown => ReservationStatus::Unknown,
    };
    Ok(Change::RecordOutcome {
        reservation: id,
        status,
    })
}

// ---------------------------------------------------------------------------
// Agent transitions
// ---------------------------------------------------------------------------

/// CONSUME.
/// requires: caller active (checked by `plan`)
/// ensures:  repeated (caller, request_id) with identical content ==>
///           Duplicate (no mutation); with different content ==> deny.
/// ensures:  Ok(Change) ==> caller owns live cap && permits(cap.scope, op) &&
///           (finite b ==> b >= 1, new balance b - 1, pool.consumed + 1).
fn plan_consume(
    s: &State,
    caller: AgentId,
    request_id: RequestId,
    id: CapabilityId,
    operation: Operation,
    now: Tick,
) -> Result<AgentPlan, Denial> {
    if let Some(rid) = s.requests.get(&(caller, request_id)) {
        let r = s.reservations.get(rid).ok_or(Denial::UnknownReservation)?;
        return if r.capability == id && r.operation == operation {
            Ok(AgentPlan::Duplicate(r.id, r.status))
        } else {
            Err(Denial::RequestIdConflict)
        };
    }
    let cap = owned_live(s, caller, id, now)?;
    if !permits(&cap.scope, &operation) {
        return Err(Denial::OperationNotPermitted);
    }
    let (new_budget, pool_consumed) = match (cap.budget, cap.pool) {
        (Budget::Unlimited, _) => (Budget::Unlimited, None),
        (Budget::Finite(b), Some(pid)) => {
            let nb = b.checked_sub(1).ok_or(Denial::InsufficientBudget)?;
            let p = s.pools.get(&pid).ok_or(Denial::ArithmeticOverflow)?;
            let consumed = p
                .consumed
                .checked_add(1)
                .ok_or(Denial::ArithmeticOverflow)?;
            (Budget::Finite(nb), Some((pid, consumed)))
        }
        // A finite capability without a pool violates the invariant; fail closed.
        (Budget::Finite(_), None) => return Err(Denial::InsufficientBudget),
    };
    require_capacity(
        s.reservations.len(),
        s.limits.max_reservations,
        Resource::Reservations,
    )?;
    let rid = ReservationId::from_raw(s.next_reservation);
    let next_reservation = bump_u64(s.next_reservation)?;
    let record = ReservationRecord {
        id: rid,
        owner: caller,
        request_id,
        capability: id,
        root: cap.root,
        pool: cap.pool,
        operation,
        status: ReservationStatus::Reserved,
        reserved_at: now,
    };
    Ok(AgentPlan::Change(Change::Consume {
        capability: id,
        new_budget,
        pool_consumed,
        record,
        next_reservation,
    }))
}

/// Child budget rule for SPLIT/DELEGATE. Returns the parent's new budget and
/// the child's pool assignment (`Ok((parent', None))` for an unlimited
/// child, `Some(Same)` to join the parent's pool, `Some(Fresh(n))` for a new
/// boundary of `n` units carved from an unlimited parent).
///
/// ensures: Finite parent b, Finite child q ==> 0 < q <= b, parent' = b - q
/// ensures: Finite parent ==> child is Finite (no unlimited from finite)
/// ensures: Unlimited parent ==> parent' = Unlimited
fn derive_budget(parent: Budget, child: Budget) -> Result<(Budget, Option<ChildPool>), Denial> {
    match (parent, child) {
        (_, Budget::Finite(0)) => Err(Denial::ZeroAllocation),
        (Budget::Finite(b), Budget::Finite(q)) => {
            let rest = b.checked_sub(q).ok_or(Denial::InsufficientBudget)?;
            Ok((Budget::Finite(rest), Some(ChildPool::Same)))
        }
        (Budget::Finite(_), Budget::Unlimited) => Err(Denial::BudgetNotAttenuated),
        (Budget::Unlimited, Budget::Finite(q)) => {
            Ok((Budget::Unlimited, Some(ChildPool::Fresh(q))))
        }
        (Budget::Unlimited, Budget::Unlimited) => Ok((Budget::Unlimited, None)),
    }
}

enum ChildPool {
    Same,
    Fresh(u64),
}

/// SPLIT (owner == caller) and DELEGATE (owner == recipient): one shared
/// implementation, consuming exactly one delegation generation.
///
/// requires: caller active; for DELEGATE, recipient active (checked by caller)
/// ensures:  Ok ==> parent owned by caller and live && parent.depth.can_delegate()
///        && is_subset(child.scope, parent.scope) && parent.depth.admits_child(child.depth)
///        && child.expiry.within(parent.expiry) && !child.expiry.is_expired_at(now)
///        && budget moved per `derive_budget` && child.generation = parent.generation + 1
fn plan_derive(
    s: &State,
    caller: AgentId,
    parent_id: CapabilityId,
    owner: AgentId,
    terms: Terms,
    now: Tick,
) -> Result<Change, Denial> {
    let parent = owned_live(s, caller, parent_id, now)?;
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
    require_issuable(&terms, now)?;
    let (parent_budget, child_pool) = derive_budget(parent.budget, terms.budget)?;
    let generation = parent
        .generation
        .checked_add(1)
        .ok_or(Denial::ArithmeticOverflow)?;
    if generation > s.limits.max_lineage_length {
        return Err(Denial::LineageTooLong);
    }
    require_capacity(
        s.capabilities.len(),
        s.limits.max_capabilities,
        Resource::Capabilities,
    )?;
    let child_id = CapabilityId::from_raw(s.next_capability);
    let next_capability = bump_u128(s.next_capability)?;
    let (pool, new_pool, next_pool) = match child_pool {
        None => (None, None, s.next_pool),
        Some(ChildPool::Same) => (parent.pool, None, s.next_pool),
        Some(ChildPool::Fresh(n)) => {
            let pid = PoolId::from_raw(s.next_pool);
            let p = Pool {
                id: pid,
                root: parent.root,
                anchor: child_id,
                initial: n,
                consumed: 0,
                discarded: 0,
            };
            (Some(pid), Some(p), bump_u64(s.next_pool)?)
        }
    };
    let child = Capability {
        id: child_id,
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
    Ok(Change::Derive {
        parent: parent_id,
        parent_budget,
        child,
        new_pool,
        next_capability,
        next_pool,
    })
}

/// ATTENUATE in place.
/// ensures: Ok ==> every component of `terms` is within the current value,
///          scope well-formed, expiry not elapsed, discarded units (finite ->
///          smaller finite) moved to pool.discarded, or (unlimited -> finite
///          n) a fresh boundary of n anchored at this capability.
fn plan_attenuate(
    s: &State,
    caller: AgentId,
    id: CapabilityId,
    terms: Terms,
    now: Tick,
) -> Result<Change, Denial> {
    let cap = owned_live(s, caller, id, now)?;
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
    match (cap.budget, terms.budget) {
        (Budget::Finite(b), Budget::Finite(n)) => {
            let discarded = b.checked_sub(n).ok_or(Denial::BudgetNotAttenuated)?;
            let pool_discarded = discard_into(s, cap.pool, discarded)?;
            Ok(Change::Attenuate {
                capability: id,
                terms,
                pool: cap.pool,
                pool_discarded,
                new_pool: None,
                next_pool: s.next_pool,
                discarded,
            })
        }
        (Budget::Finite(_), Budget::Unlimited) => Err(Denial::BudgetNotAttenuated),
        (Budget::Unlimited, Budget::Unlimited) => Ok(Change::Attenuate {
            capability: id,
            terms,
            pool: None,
            pool_discarded: None,
            new_pool: None,
            next_pool: s.next_pool,
            discarded: 0,
        }),
        (Budget::Unlimited, Budget::Finite(n)) => {
            let pid = PoolId::from_raw(s.next_pool);
            let next_pool = bump_u64(s.next_pool)?;
            let p = Pool {
                id: pid,
                root: cap.root,
                anchor: id,
                initial: n,
                consumed: 0,
                discarded: 0,
            };
            Ok(Change::Attenuate {
                capability: id,
                terms,
                pool: Some(pid),
                pool_discarded: None,
                new_pool: Some(p),
                next_pool,
                discarded: 0,
            })
        }
    }
}

/// TRANSFER.
/// ensures: Ok ==> caller owns live cap, cap.depth.can_delegate(), recipient
///          active and != caller; new depth = cap.depth.decrement().
fn plan_transfer(
    s: &State,
    caller: AgentId,
    id: CapabilityId,
    to: AgentId,
    now: Tick,
) -> Result<Change, Denial> {
    let cap = owned_live(s, caller, id, now)?;
    let depth = cap.depth.decrement().ok_or(Denial::NotDelegatable)?;
    require_active(s, to)?;
    if to == caller {
        return Err(Denial::SelfTransfer);
    }
    Ok(Change::Transfer {
        capability: id,
        from: caller,
        to,
        depth,
    })
}

/// Agent REVOKE: permitted if the caller currently owns the target or any
/// ancestor of it (it is the delegator of that subtree). Revocation only
/// removes authority, so this cannot amplify.
fn plan_agent_revoke(s: &State, caller: AgentId, id: CapabilityId) -> Result<Change, Denial> {
    let target = s.capabilities.get(&id).ok_or(Denial::UnknownCapability)?;
    if target.status == Status::Revoked {
        return Err(Denial::AlreadyRevoked);
    }
    let mut cur = Some(id);
    let mut steps: u32 = 0;
    while let Some(c) = cur {
        let rec = s
            .capabilities
            .get(&c)
            .ok_or(Denial::NotAuthorizedToRevoke)?;
        if rec.owner == caller {
            return Ok(Change::Revoke { capability: id });
        }
        if steps >= s.limits.max_lineage_length {
            break;
        }
        steps += 1;
        cur = rec.parent;
    }
    Err(Denial::NotAuthorizedToRevoke)
}

/// DROP.
/// ensures: Ok ==> caller owns live cap; finite balance moved to D;
///          status := Dropped; descendants untouched.
fn plan_drop(s: &State, caller: AgentId, id: CapabilityId, now: Tick) -> Result<Change, Denial> {
    let cap = owned_live(s, caller, id, now)?;
    let discarded = match cap.budget {
        Budget::Finite(b) => b,
        Budget::Unlimited => 0,
    };
    let pool_discarded = discard_into(s, cap.pool, discarded)?;
    Ok(Change::Drop {
        capability: id,
        pool_discarded,
        discarded,
    })
}

// ---------------------------------------------------------------------------
// Commit (infallible)
// ---------------------------------------------------------------------------

fn set_pool_consumed(s: &mut State, upd: Option<(PoolId, u64)>) {
    if let Some((pid, v)) = upd
        && let Some(p) = s.pools.get_mut(&pid)
    {
        p.consumed = v;
    }
}

fn set_pool_discarded(s: &mut State, upd: Option<(PoolId, u64)>) {
    if let Some((pid, v)) = upd
        && let Some(p) = s.pools.get_mut(&pid)
    {
        p.discarded = v;
    }
}

fn commit(s: &mut State, sequence: u64, now: Tick, change: Change) -> Effect {
    s.sequence = sequence;
    s.clock = now;
    match change {
        Change::CreatePrincipal { agent, next_serial } => {
            s.principals.insert(agent, PrincipalStatus::Active);
            s.next_agent_serial = next_serial;
            Effect::PrincipalCreated { agent }
        }
        Change::TerminatePrincipal { agent } => {
            s.principals.insert(agent, PrincipalStatus::Terminated);
            Effect::PrincipalTerminated { agent }
        }
        Change::AdvanceClock => Effect::ClockAdvanced { now },
        Change::BumpEpoch {
            epoch,
            terminated,
            abandoned,
        } => {
            s.epoch = epoch;
            for p in s.principals.values_mut() {
                *p = PrincipalStatus::Terminated;
            }
            for r in s.reservations.values_mut() {
                if r.status == ReservationStatus::Reserved {
                    r.status = ReservationStatus::Abandoned;
                }
            }
            Effect::EpochAdvanced {
                epoch,
                terminated_principals: terminated,
                abandoned_reservations: abandoned,
            }
        }
        Change::NewRoot(nr) => {
            let effect = Effect::RootCreated {
                root: nr.root.id,
                capability: nr.capability.id,
                kind: nr.root.kind,
            };
            if let Some(nonce) = nr.nonce {
                s.spent_nonces.insert(nonce, nr.root.id);
            }
            if let Some(p) = nr.pool {
                s.pools.insert(p.id, p);
            }
            s.capabilities.insert(nr.capability.id, nr.capability);
            s.roots.insert(nr.root.id, nr.root);
            s.next_capability = nr.next_capability;
            s.next_root = nr.next_root;
            s.next_pool = nr.next_pool;
            effect
        }
        Change::Consume {
            capability,
            new_budget,
            pool_consumed,
            record,
            next_reservation,
        } => {
            if let Some(c) = s.capabilities.get_mut(&capability) {
                c.budget = new_budget;
            }
            set_pool_consumed(s, pool_consumed);
            let reservation = Reservation {
                id: record.id,
                owner: record.owner,
                request_id: record.request_id,
                capability: record.capability,
                root: record.root,
                pool: record.pool,
                operation: record.operation,
            };
            s.requests
                .insert((record.owner, record.request_id), record.id);
            s.reservations.insert(record.id, record);
            s.next_reservation = next_reservation;
            Effect::Reserved(reservation)
        }
        Change::Derive {
            parent,
            parent_budget,
            child,
            new_pool,
            next_capability,
            next_pool,
        } => {
            if let Some(p) = s.capabilities.get_mut(&parent) {
                p.budget = parent_budget;
            }
            if let Some(p) = new_pool {
                s.pools.insert(p.id, p);
            }
            let effect = Effect::Derived {
                parent,
                child: child.id,
                owner: child.owner,
            };
            s.capabilities.insert(child.id, child);
            s.next_capability = next_capability;
            s.next_pool = next_pool;
            effect
        }
        Change::Attenuate {
            capability,
            terms,
            pool,
            pool_discarded,
            new_pool,
            next_pool,
            discarded,
        } => {
            if let Some(c) = s.capabilities.get_mut(&capability) {
                c.scope = terms.scope;
                c.budget = terms.budget;
                c.depth = terms.depth;
                c.expiry = terms.expiry;
                c.pool = pool;
            }
            set_pool_discarded(s, pool_discarded);
            if let Some(p) = new_pool {
                s.pools.insert(p.id, p);
            }
            s.next_pool = next_pool;
            Effect::Attenuated {
                capability,
                discarded,
            }
        }
        Change::Transfer {
            capability,
            from,
            to,
            depth,
        } => {
            if let Some(c) = s.capabilities.get_mut(&capability) {
                c.owner = to;
                c.depth = depth;
            }
            Effect::Transferred {
                capability,
                from,
                to,
            }
        }
        Change::Revoke { capability } => {
            if let Some(c) = s.capabilities.get_mut(&capability) {
                c.status = Status::Revoked;
            }
            Effect::Revoked { capability }
        }
        Change::Drop {
            capability,
            pool_discarded,
            discarded,
        } => {
            if let Some(c) = s.capabilities.get_mut(&capability) {
                if c.budget.is_finite() {
                    c.budget = Budget::Finite(0);
                }
                c.status = Status::Dropped;
            }
            set_pool_discarded(s, pool_discarded);
            Effect::Dropped {
                capability,
                discarded,
            }
        }
        Change::RecordOutcome {
            reservation,
            status,
        } => {
            if let Some(r) = s.reservations.get_mut(&reservation) {
                r.status = status;
            }
            Effect::OutcomeRecorded {
                reservation,
                status,
            }
        }
    }
}
