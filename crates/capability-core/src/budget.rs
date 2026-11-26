//! Quantities: budgets, delegation depth, trusted time and expiry.
//!
//! Infinity is always an explicit enum variant, never a magic number (§7).
//! Every ordering used for attenuation is a small total function so that it
//! can later be given a Verus `spec fn` twin.

use serde::{Deserialize, Serialize};
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

/// Use budget, in units of one protected operation (MVP: every operation
/// costs exactly one unit, §4.2).
#[cfg_attr(verus_keep_ghost, verus_verify(external_derive))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Budget {
    /// Exactly this many remaining uses.
    Finite(u64),
    /// Unbounded uses; remains unlimited after use.
    Unlimited,
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Budget {
    /// Attenuation order: `self` grants no more uses than `bound`.
    ///
    /// ensures: `Finite(a).within(Finite(b)) == (a <= b)`;
    ///          `x.within(Unlimited)`; `!Unlimited.within(Finite(_))`.
    #[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r == self.within_spec(bound)))]
    pub const fn within(self, bound: Budget) -> bool {
        match (self, bound) {
            (_, Budget::Unlimited) => true,
            (Budget::Unlimited, Budget::Finite(_)) => false,
            (Budget::Finite(a), Budget::Finite(b)) => a <= b,
        }
    }

    /// True for `Finite(_)`.
    #[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r == (self is Finite)))]
    pub const fn is_finite(self) -> bool {
        matches!(self, Budget::Finite(_))
    }
}

/// Remaining delegation generations. `Finite(0)` means non-delegatable:
/// the capability may be used and attenuated but not split, delegated or
/// transferred (§5.1).
#[cfg_attr(verus_keep_ghost, verus_verify(external_derive))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Depth {
    /// This many further generations.
    Finite(u32),
    /// Unbounded delegation.
    Unlimited,
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Depth {
    /// Attenuation order (same shape as [`Budget::within`]).
    #[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r == self.within_spec(bound)))]
    pub const fn within(self, bound: Depth) -> bool {
        match (self, bound) {
            (_, Depth::Unlimited) => true,
            (Depth::Unlimited, Depth::Finite(_)) => false,
            (Depth::Finite(a), Depth::Finite(b)) => a <= b,
        }
    }

    /// May this capability be split, delegated or transferred at all?
    #[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r == self.can_delegate_spec()))]
    pub const fn can_delegate(self) -> bool {
        !matches!(self, Depth::Finite(0))
    }

    /// Depth after one delegation generation (used by TRANSFER).
    ///
    /// ensures: `None` iff `self == Finite(0)`;
    ///          `Finite(d) -> Finite(d - 1)`; `Unlimited -> Unlimited`.
    #[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r == self.decrement_spec()))]
    pub const fn decrement(self) -> Option<Depth> {
        match self {
            Depth::Unlimited => Some(Depth::Unlimited),
            Depth::Finite(0) => None,
            Depth::Finite(d) => Some(Depth::Finite(d - 1)),
        }
    }

    /// Is `child` a permissible depth for a child derived from a parent of
    /// depth `self`? A finite parent requires a strictly lower finite child;
    /// an unlimited parent may issue any depth (§4.3).
    ///
    /// ensures: result ==> self.can_delegate()
    #[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r == self.admits_child_spec(child), r ==> self.can_delegate_spec()))]
    pub const fn admits_child(self, child: Depth) -> bool {
        match (self, child) {
            (Depth::Unlimited, _) => true,
            (Depth::Finite(_), Depth::Unlimited) => false,
            (Depth::Finite(p), Depth::Finite(c)) => c < p,
        }
    }
}

/// Trusted monotonic time, in opaque ticks supplied by the broker. Never a
/// client field. Ticks are monotonic within an authority epoch; see
/// [`crate::AdminCommand::BumpEpoch`].
#[cfg_attr(verus_keep_ghost, verus_verify(external_derive))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Tick(u64);

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Tick {
    /// The zero tick.
    #[cfg_attr(verus_keep_ghost, verus_spec(ensures Tick::ZERO.raw() == 0))]
    pub const ZERO: Tick = Tick(0);

    /// Wrap a raw tick count.
    #[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r.raw() == raw))]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Raw tick count.
    #[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r == self.raw()))]
    pub const fn to_raw(self) -> u64 {
        self.0
    }
}

/// Capability lifetime. A capability expiring `At(t)` is valid for all
/// `now < t` and expired for every `now >= t`.
#[cfg_attr(verus_keep_ghost, verus_verify(external_derive))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Expiry {
    /// Expires at this tick.
    At(Tick),
    /// Never expires on its own (still subject to revocation, owner
    /// termination and epoch change).
    Never,
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Expiry {
    /// ensures: `At(t).is_expired_at(now) == (now >= t)`; `Never` never expires.
    #[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r == self.is_expired_at_spec(now)))]
    pub const fn is_expired_at(self, now: Tick) -> bool {
        match self {
            Expiry::Never => false,
            Expiry::At(t) => now.0 >= t.0,
        }
    }

    /// Attenuation order: `self` ends no later than `bound`.
    #[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r == self.within_spec(bound)))]
    pub const fn within(self, bound: Expiry) -> bool {
        match (self, bound) {
            (_, Expiry::Never) => true,
            (Expiry::Never, Expiry::At(_)) => false,
            (Expiry::At(a), Expiry::At(b)) => a.0 <= b.0,
        }
    }
}

#[cfg(verus_keep_ghost)]
include!("budget_verus.rs");
