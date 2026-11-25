//! Mirror of `crates/capability-core/src/budget.rs`.
use vstd::prelude::*;

verus! {

/// Mirror of `Budget`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Budget {
    Finite(u64),
    Unlimited,
}

/// Mirror of `Depth`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Depth {
    Finite(u32),
    Unlimited,
}

/// Mirror of `Tick` (opaque trusted time).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tick(pub u64);

/// Mirror of `Expiry`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expiry {
    At(Tick),
    Never,
}

// ---------------------------------------------------------------- Budget

impl Budget {
    pub open spec fn within_spec(self, bound: Budget) -> bool {
        match (self, bound) {
            (_, Budget::Unlimited) => true,
            (Budget::Unlimited, Budget::Finite(_)) => false,
            (Budget::Finite(a), Budget::Finite(b)) => a <= b,
        }
    }

    /// Mirror of `Budget::within`.
    pub fn within(self, bound: Budget) -> (r: bool)
        ensures r == self.within_spec(bound),
    {
        match (self, bound) {
            (_, Budget::Unlimited) => true,
            (Budget::Unlimited, Budget::Finite(_)) => false,
            (Budget::Finite(a), Budget::Finite(b)) => a <= b,
        }
    }

    /// Mirror of `Budget::is_finite`.
    pub fn is_finite(self) -> (r: bool)
        ensures r == (self is Finite),
    {
        match self {
            Budget::Finite(_) => true,
            Budget::Unlimited => false,
        }
    }

    /// Balance held by a budget, as an integer (unlimited holds no finite units).
    pub open spec fn units(self) -> int {
        match self {
            Budget::Finite(b) => b as int,
            Budget::Unlimited => 0,
        }
    }
}

pub proof fn lemma_budget_within_refl(a: Budget)
    ensures a.within_spec(a),
{
}

pub proof fn lemma_budget_within_trans(a: Budget, b: Budget, c: Budget)
    requires a.within_spec(b), b.within_spec(c),
    ensures a.within_spec(c),
{
}

/// Only an unlimited bound admits an unlimited budget ("finite never yields
/// unlimited").
pub proof fn lemma_unlimited_within_only_unlimited(a: Budget, b: Budget)
    requires a.within_spec(b), a is Unlimited,
    ensures b is Unlimited,
{
}

// ---------------------------------------------------------------- Depth

impl Depth {
    pub open spec fn within_spec(self, bound: Depth) -> bool {
        match (self, bound) {
            (_, Depth::Unlimited) => true,
            (Depth::Unlimited, Depth::Finite(_)) => false,
            (Depth::Finite(a), Depth::Finite(b)) => a <= b,
        }
    }

    /// Mirror of `Depth::within`.
    pub fn within(self, bound: Depth) -> (r: bool)
        ensures r == self.within_spec(bound),
    {
        match (self, bound) {
            (_, Depth::Unlimited) => true,
            (Depth::Unlimited, Depth::Finite(_)) => false,
            (Depth::Finite(a), Depth::Finite(b)) => a <= b,
        }
    }

    pub open spec fn can_delegate_spec(self) -> bool {
        self != Depth::Finite(0)
    }

    /// Mirror of `Depth::can_delegate`.
    pub fn can_delegate(self) -> (r: bool)
        ensures r == self.can_delegate_spec(),
    {
        match self {
            Depth::Finite(0) => false,
            _ => true,
        }
    }

    pub open spec fn decrement_spec(self) -> Option<Depth> {
        match self {
            Depth::Unlimited => Some(Depth::Unlimited),
            Depth::Finite(d) => if d == 0 { None } else { Some(Depth::Finite((d - 1) as u32)) },
        }
    }

    /// Mirror of `Depth::decrement`.
    pub fn decrement(self) -> (r: Option<Depth>)
        ensures
            r == self.decrement_spec(),
            r is None <==> self == Depth::Finite(0),
            r matches Some(d) ==> d.within_spec(self),
    {
        match self {
            Depth::Unlimited => Some(Depth::Unlimited),
            Depth::Finite(0) => None,
            Depth::Finite(d) => Some(Depth::Finite(d - 1)),
        }
    }

    pub open spec fn admits_child_spec(self, child: Depth) -> bool {
        match (self, child) {
            (Depth::Unlimited, _) => true,
            (Depth::Finite(_), Depth::Unlimited) => false,
            (Depth::Finite(p), Depth::Finite(c)) => c < p,
        }
    }

    /// Mirror of `Depth::admits_child`.
    pub fn admits_child(self, child: Depth) -> (r: bool)
        ensures
            r == self.admits_child_spec(child),
            r ==> self.can_delegate_spec(),
    {
        match (self, child) {
            (Depth::Unlimited, _) => true,
            (Depth::Finite(_), Depth::Unlimited) => false,
            (Depth::Finite(p), Depth::Finite(c)) => c < p,
        }
    }
}

pub proof fn lemma_depth_within_refl(a: Depth)
    ensures a.within_spec(a),
{
}

pub proof fn lemma_depth_within_trans(a: Depth, b: Depth, c: Depth)
    requires a.within_spec(b), b.within_spec(c),
    ensures a.within_spec(c),
{
}

/// T4 building block: admitting a child against a current depth that is
/// within the creation-time depth also admits it against the latter.
pub proof fn lemma_admits_child_weaken(cur: Depth, origin: Depth, child: Depth)
    requires cur.admits_child_spec(child), cur.within_spec(origin),
    ensures origin.admits_child_spec(child),
{
}

/// T4: a finite chain of admitted children strictly decreases.
pub proof fn lemma_admits_child_strict(p: Depth, c: Depth)
    requires p.admits_child_spec(c), p is Finite,
    ensures c is Finite, c->Finite_0 < p->Finite_0, p != Depth::Finite(0),
{
}

// ---------------------------------------------------------------- Expiry

impl Expiry {
    pub open spec fn is_expired_at_spec(self, now: Tick) -> bool {
        match self {
            Expiry::Never => false,
            Expiry::At(t) => now.0 >= t.0,
        }
    }

    /// Mirror of `Expiry::is_expired_at`.
    pub fn is_expired_at(self, now: Tick) -> (r: bool)
        ensures r == self.is_expired_at_spec(now),
    {
        match self {
            Expiry::Never => false,
            Expiry::At(t) => now.0 >= t.0,
        }
    }

    pub open spec fn within_spec(self, bound: Expiry) -> bool {
        match (self, bound) {
            (_, Expiry::Never) => true,
            (Expiry::Never, Expiry::At(_)) => false,
            (Expiry::At(a), Expiry::At(b)) => a.0 <= b.0,
        }
    }

    /// Mirror of `Expiry::within`.
    pub fn within(self, bound: Expiry) -> (r: bool)
        ensures r == self.within_spec(bound),
    {
        match (self, bound) {
            (_, Expiry::Never) => true,
            (Expiry::Never, Expiry::At(_)) => false,
            (Expiry::At(a), Expiry::At(b)) => a.0 <= b.0,
        }
    }
}

pub proof fn lemma_expiry_within_refl(a: Expiry)
    ensures a.within_spec(a),
{
}

pub proof fn lemma_expiry_within_trans(a: Expiry, b: Expiry, c: Expiry)
    requires a.within_spec(b), b.within_spec(c),
    ensures a.within_spec(c),
{
}

/// Lifetime soundness: if `a` ends no later than `b` and `b` has expired,
/// then `a` has expired too (an expired ancestor bounds every descendant).
pub proof fn lemma_expiry_within_expired(a: Expiry, b: Expiry, now: Tick)
    requires a.within_spec(b), b.is_expired_at_spec(now),
    ensures a.is_expired_at_spec(now),
{
}

/// Expiry is monotone in time: once expired, expired forever.
pub proof fn lemma_expiry_monotone(a: Expiry, t1: Tick, t2: Tick)
    requires a.is_expired_at_spec(t1), t1.0 <= t2.0,
    ensures a.is_expired_at_spec(t2),
{
}

} // verus!
