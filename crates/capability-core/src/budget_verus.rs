// Verus-only (included into budget.rs under cfg(verus_keep_ghost)):
// spec twins and lemmas for the production code.

verus! {

impl Budget {
    /// Specification of `within`.
    pub open spec fn within_spec(self, bound: Budget) -> bool {
        match (self, bound) {
            (_, Budget::Unlimited) => true,
            (Budget::Unlimited, Budget::Finite(_)) => false,
            (Budget::Finite(a), Budget::Finite(b)) => a <= b,
        }
    }
}

pub proof fn lemma_budget_within_refl(a: Budget) ensures a.within_spec(a) {}
pub proof fn lemma_budget_within_trans(a: Budget, b: Budget, c: Budget)
    requires a.within_spec(b), b.within_spec(c), ensures a.within_spec(c) {}

impl Depth {
    /// Specification of `within`.
    pub open spec fn within_spec(self, bound: Depth) -> bool {
        match (self, bound) {
            (_, Depth::Unlimited) => true,
            (Depth::Unlimited, Depth::Finite(_)) => false,
            (Depth::Finite(a), Depth::Finite(b)) => a <= b,
        }
    }
    /// Specification of `can_delegate`.
    pub open spec fn can_delegate_spec(self) -> bool { self != Depth::Finite(0) }
    /// Specification of `decrement`.
    pub open spec fn decrement_spec(self) -> Option<Depth> {
        match self {
            Depth::Unlimited => Some(Depth::Unlimited),
            Depth::Finite(d) => if d == 0 { None } else { Some(Depth::Finite((d - 1) as u32)) },
        }
    }
    /// Specification of `admits_child`.
    pub open spec fn admits_child_spec(self, child: Depth) -> bool {
        match (self, child) {
            (Depth::Unlimited, _) => true,
            (Depth::Finite(_), Depth::Unlimited) => false,
            (Depth::Finite(p), Depth::Finite(c)) => c < p,
        }
    }
}

pub proof fn lemma_depth_within_trans(a: Depth, b: Depth, c: Depth)
    requires a.within_spec(b), b.within_spec(c), ensures a.within_spec(c) {}
pub proof fn lemma_admits_child_weaken(cur: Depth, origin: Depth, child: Depth)
    requires cur.admits_child_spec(child), cur.within_spec(origin),
    ensures origin.admits_child_spec(child) {}

impl Tick {
    /// The wrapped raw value (spec only).
    pub closed spec fn raw(self) -> u64 { self.0 }
}

impl Expiry {
    /// Specification of `is_expired_at`.
    pub open spec fn is_expired_at_spec(self, now: Tick) -> bool {
        match self {
            Expiry::Never => false,
            Expiry::At(t) => now.raw() >= t.raw(),
        }
    }
    /// Specification of `within`.
    pub open spec fn within_spec(self, bound: Expiry) -> bool {
        match (self, bound) {
            (_, Expiry::Never) => true,
            (Expiry::Never, Expiry::At(_)) => false,
            (Expiry::At(a), Expiry::At(b)) => a.raw() <= b.raw(),
        }
    }
}

pub proof fn lemma_expiry_within_monotone(c: Expiry, p: Expiry, now: Tick)
    requires c.within_spec(p), p.is_expired_at_spec(now), ensures c.is_expired_at_spec(now) {}

} // verus!
