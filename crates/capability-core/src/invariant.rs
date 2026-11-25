//! Executable statement of the ledger invariant (spec §6.1). Used by tests,
//! by snapshot deserialization and as the intended Verus `spec fn inv`.
//!
//! `check_invariant` is a diagnostic: it is O(n · lineage) and is not called
//! on the hot path by `step`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::budget::Budget;
use crate::ids::{AgentId, CapabilityId, Nonce, PoolId, ReservationId, RootId};
use crate::scope::is_subset;
use crate::state::{PrincipalStatus, RootKind, State, Status};

/// A violated invariant (indicates a core bug or a corrupt snapshot).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvariantViolation {
    /// A map key disagrees with the record's id.
    KeyMismatch,
    /// An id is not below its allocation counter (freshness broken).
    IdNotFresh,
    /// A configured bound is exceeded.
    LimitExceeded,
    /// A principal from a future epoch, or a non-terminated principal from an
    /// old epoch.
    PrincipalEpoch(AgentId),
    /// Capability owner unknown.
    UnknownOwner(CapabilityId),
    /// Parent missing, not older than the child, wrong generation, or root
    /// mismatch (acyclicity / lineage).
    Lineage(CapabilityId),
    /// Root capability without matching root record or vice versa.
    RootRecord(CapabilityId),
    /// Child origin scope not a subset of parent origin scope, or current
    /// scope not a subset of origin.
    ScopeEdge(CapabilityId),
    /// Expiry edge or current-vs-origin expiry broken.
    ExpiryEdge(CapabilityId),
    /// Depth edge (strictly decreasing for finite parents) or current depth
    /// above origin.
    DepthEdge(CapabilityId),
    /// Budget edge: unlimited from finite, or current above origin.
    BudgetEdge(CapabilityId),
    /// Finite capability without pool, unlimited with pool, or pool
    /// lineage wrong.
    PoolMembership(CapabilityId),
    /// `initial != consumed + discarded + Σ balances` for a pool.
    Conservation(PoolId),
    /// Computed N = U + L + D fails at the recorded clock.
    Accounting(PoolId),
    /// Dropped finite capability still holds balance.
    DroppedBalance(CapabilityId),
    /// Spent-nonce table and approved roots disagree.
    Nonce(Nonce),
    /// Approved root without its nonce recorded.
    RootNonce(RootId),
    /// Reservation refers to unknown capability/root/pool or index broken.
    Reservation(ReservationId),
    /// Pool consumed counter disagrees with its reservation count.
    ConsumedMismatch(PoolId),
}

/// Check every structural and accounting invariant:
///
/// * unique ids and freshness of all allocation counters;
/// * principals and owners exist; old-epoch principals are terminated;
/// * lineage: parent exists with a strictly smaller id (⇒ acyclic),
///   generation = parent + 1 ≤ bound, same root;
/// * each root capability matches its root record exactly;
/// * attenuation on every edge (at creation snapshots): scope subset,
///   expiry no later, depth strictly lower for finite parents, no unlimited
///   child of a finite parent; current terms within origin terms;
/// * pool membership and conservation `N = U + D_explicit + Σ balances`,
///   and the derived `N = U + L + D` at the recorded clock;
/// * U equals the number of reservations charged to the pool;
/// * nonce table ↔ approved roots is a bijection (each nonce once).
pub fn check_invariant(s: &State) -> Result<(), InvariantViolation> {
    use InvariantViolation as V;

    // -- limits -------------------------------------------------------------
    let len = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
    if len(s.capabilities.len()) > s.limits.max_capabilities
        || len(s.principals.len()) > s.limits.max_principals
        || len(s.roots.len()) > s.limits.max_roots
        || len(s.reservations.len()) > s.limits.max_reservations
    {
        return Err(V::LimitExceeded);
    }

    // -- principals -----------------------------------------------------------
    for (a, st) in &s.principals {
        if a.serial() >= s.next_agent_serial {
            return Err(V::IdNotFresh);
        }
        if a.epoch() > s.epoch || (a.epoch() < s.epoch && *st != PrincipalStatus::Terminated) {
            return Err(V::PrincipalEpoch(*a));
        }
    }

    // -- capabilities ----------------------------------------------------------
    for (k, c) in &s.capabilities {
        if *k != c.id {
            return Err(V::KeyMismatch);
        }
        if c.id.to_raw() >= s.next_capability {
            return Err(V::IdNotFresh);
        }
        if !s.principals.contains_key(&c.owner) {
            return Err(V::UnknownOwner(c.id));
        }
        if c.generation > s.limits.max_lineage_length {
            return Err(V::Lineage(c.id));
        }
        // current within origin
        if !is_subset(&c.scope, &c.origin.scope) {
            return Err(V::ScopeEdge(c.id));
        }
        if !c.expiry.within(c.origin.expiry) {
            return Err(V::ExpiryEdge(c.id));
        }
        if !c.depth.within(c.origin.depth) {
            return Err(V::DepthEdge(c.id));
        }
        if !c.budget.within(c.origin.budget) {
            return Err(V::BudgetEdge(c.id));
        }
        if c.status == Status::Dropped && matches!(c.budget, Budget::Finite(b) if b != 0) {
            return Err(V::DroppedBalance(c.id));
        }
        match c.parent {
            None => {
                let r = s.roots.get(&c.root).ok_or(V::RootRecord(c.id))?;
                if r.capability != c.id || r.terms != c.origin || c.generation != 0 {
                    return Err(V::RootRecord(c.id));
                }
            }
            Some(pid) => {
                let p = s.capabilities.get(&pid).ok_or(V::Lineage(c.id))?;
                if pid >= c.id
                    || p.root != c.root
                    || p.generation.checked_add(1) != Some(c.generation)
                {
                    return Err(V::Lineage(c.id));
                }
                if !is_subset(&c.origin.scope, &p.origin.scope) {
                    return Err(V::ScopeEdge(c.id));
                }
                if !c.origin.expiry.within(p.origin.expiry) {
                    return Err(V::ExpiryEdge(c.id));
                }
                if !p.origin.depth.admits_child(c.origin.depth) {
                    return Err(V::DepthEdge(c.id));
                }
                if c.origin.budget == Budget::Unlimited && p.origin.budget != Budget::Unlimited {
                    return Err(V::BudgetEdge(c.id));
                }
            }
        }
        // pool membership
        match (c.budget, c.pool) {
            (Budget::Unlimited, None) => {}
            (Budget::Finite(_), Some(pid)) => {
                let pool = s.pools.get(&pid).ok_or(V::PoolMembership(c.id))?;
                if pool.root != c.root {
                    return Err(V::PoolMembership(c.id));
                }
                if pool.anchor == c.id {
                    // A boundary: a finite root, a finite child of an
                    // unlimited parent, or an unlimited capability
                    // attenuated to finite.
                    let ok = match c.parent {
                        None => true,
                        Some(ppid) => {
                            c.origin.budget == Budget::Unlimited
                                || s.capabilities.get(&ppid).map(|p| p.origin.budget)
                                    == Some(Budget::Unlimited)
                        }
                    };
                    if !ok {
                        return Err(V::PoolMembership(c.id));
                    }
                } else {
                    // Otherwise it was split from a finite parent in the same pool.
                    let same = c
                        .parent
                        .and_then(|ppid| s.capabilities.get(&ppid))
                        .and_then(|p| p.pool)
                        == Some(pid);
                    if !same {
                        return Err(V::PoolMembership(c.id));
                    }
                }
            }
            _ => return Err(V::PoolMembership(c.id)),
        }
    }

    // -- roots and nonces -------------------------------------------------------
    for (k, r) in &s.roots {
        if *k != r.id || r.id.to_raw() >= s.next_root {
            return Err(V::KeyMismatch);
        }
        let c = s
            .capabilities
            .get(&r.capability)
            .ok_or(V::RootRecord(r.capability))?;
        if c.parent.is_some() || c.root != r.id {
            return Err(V::RootRecord(r.capability));
        }
        if !s.principals.contains_key(&r.recipient) || r.epoch > s.epoch {
            return Err(V::RootRecord(r.capability));
        }
        if let RootKind::Approved { nonce } = r.kind
            && s.spent_nonces.get(&nonce) != Some(&r.id)
        {
            return Err(V::RootNonce(r.id));
        }
    }
    for (n, rid) in &s.spent_nonces {
        let r = s.roots.get(rid).ok_or(V::Nonce(*n))?;
        if r.kind != (RootKind::Approved { nonce: *n }) {
            return Err(V::Nonce(*n));
        }
    }

    // -- reservations ---------------------------------------------------------
    let mut per_pool: BTreeMap<PoolId, u64> = BTreeMap::new();
    let mut seen_requests = BTreeSet::new();
    for (k, r) in &s.reservations {
        if *k != r.id || r.id.to_raw() >= s.next_reservation {
            return Err(V::Reservation(r.id));
        }
        let c = s
            .capabilities
            .get(&r.capability)
            .ok_or(V::Reservation(r.id))?;
        if c.root != r.root || s.requests.get(&(r.owner, r.request_id)) != Some(&r.id) {
            return Err(V::Reservation(r.id));
        }
        if !seen_requests.insert((r.owner, r.request_id)) {
            return Err(V::Reservation(r.id));
        }
        if let Some(pid) = r.pool {
            if !s.pools.contains_key(&pid) {
                return Err(V::Reservation(r.id));
            }
            let e = per_pool.entry(pid).or_insert(0);
            *e = e.checked_add(1).ok_or(V::ConsumedMismatch(pid))?;
        }
    }
    if s.requests.len() != s.reservations.len() {
        return Err(V::Reservation(ReservationId::from_raw(u64::MAX)));
    }

    // -- pools / conservation (T1) ---------------------------------------------
    let mut balances: BTreeMap<PoolId, u128> = BTreeMap::new();
    for c in s.capabilities.values() {
        if let (Some(pid), Budget::Finite(b)) = (c.pool, c.budget) {
            let e = balances.entry(pid).or_insert(0);
            *e = e.checked_add(u128::from(b)).ok_or(V::Conservation(pid))?;
        }
    }
    for (k, p) in &s.pools {
        if *k != p.id || p.id.to_raw() >= s.next_pool {
            return Err(V::KeyMismatch);
        }
        let anchor = s.capabilities.get(&p.anchor).ok_or(V::Conservation(p.id))?;
        if anchor.pool != Some(p.id) || anchor.root != p.root {
            return Err(V::Conservation(p.id));
        }
        let held = balances.get(&p.id).copied().unwrap_or(0);
        let total = u128::from(p.consumed) + u128::from(p.discarded) + held;
        if total != u128::from(p.initial) {
            return Err(V::Conservation(p.id));
        }
        if per_pool.get(&p.id).copied().unwrap_or(0) != p.consumed {
            return Err(V::ConsumedMismatch(p.id));
        }
    }
    for pid in balances.keys() {
        if !s.pools.contains_key(pid) {
            return Err(V::Conservation(*pid));
        }
    }

    // -- derived N = U + L + D at the recorded clock ---------------------------
    let accounts = s
        .accounts()
        .ok_or(V::Accounting(PoolId::from_raw(u64::MAX)))?;
    for a in accounts {
        let sum = u128::from(a.consumed)
            + u128::from(a.live)
            + u128::from(a.discarded_explicit)
            + u128::from(a.discarded_stranded);
        if sum != u128::from(a.initial) {
            return Err(V::Accounting(a.pool));
        }
    }

    Ok(())
}
