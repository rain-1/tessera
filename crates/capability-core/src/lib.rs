//! # Tessera authority core
//!
//! Pure, deterministic capability ledger implementing the formal authority
//! model of `docs/specification.md` §4–§7 (work packages WP1 and WP2).
//!
//! * No I/O, no clocks, no randomness, no `unsafe`. Caller identity and
//!   trusted time are explicit inputs ([`AuthenticatedCommand`], [`Tick`]).
//! * One entry point mutates authority: [`step`]. It validates completely
//!   before mutating, so a [`Denial`] never changes the [`State`].
//! * [`check_invariant`] states conservation, lineage, attenuation and
//!   nonce invariants executably. This crate is not itself machine-proved.
//!   A function-by-function mirror in `proofs/` is verified with Verus and
//!   differentially tested against it; see `proofs/README.md` and
//!   `docs/proof-register.md`.
//!
//! ## Broker integration sketch
//!
//! ```
//! use tessera_capability_core::*;
//!
//! let mut s = State::new(Limits::default());
//! let t = Tick::from_raw(0);
//! let Ok(Effect::PrincipalCreated { agent }) =
//!     step(&mut s, AuthenticatedCommand::operator(AdminCommand::CreatePrincipal), t)
//! else { unreachable!() };
//!
//! let object = ObjectId::from_raw(7);
//! let terms = Terms {
//!     scope: Scope::File { object, rights: FileRights::READ },
//!     budget: Budget::Finite(1),
//!     depth: Depth::Finite(0),
//!     expiry: Expiry::At(Tick::from_raw(300)),
//! };
//! // Evidence produced by the approval service after FIDO2 verification.
//! let approval = VerifiedApproval::new(
//!     Nonce::from_bytes([1; 32]),
//!     GrantRequest { epoch: s.epoch(), recipient: agent, terms, request_expires: Tick::from_raw(60) },
//! );
//! let Ok(Effect::RootCreated { capability, .. }) =
//!     step(&mut s, AuthenticatedCommand::operator(AdminCommand::Mint { approval }), t)
//! else { unreachable!() };
//!
//! let read = Operation::File { object, right: FileRight::Read };
//! let consume = AgentCommand::Consume { request_id: RequestId::from_raw(1), capability, operation: read };
//! let Ok(Effect::Reserved(reservation)) = step(&mut s, AuthenticatedCommand::agent(agent, consume), t)
//! else { unreachable!() };
//! assert_eq!(reservation.operation(), read);
//!
//! // Budget is now spent: a different request is denied.
//! let again = AgentCommand::Consume { request_id: RequestId::from_raw(2), capability, operation: read };
//! assert_eq!(step(&mut s, AuthenticatedCommand::agent(agent, again), t), Err(Denial::InsufficientBudget));
//! check_invariant(&s).unwrap();
//! ```
//!
//! ## Accounting semantics (N = U + L + D)
//!
//! Every finite balance belongs to exactly one *pool* (finite allocation
//! boundary): a finite root, or a finite allocation carved from an unlimited
//! capability. Per pool the ledger stores `initial` (N), `consumed` (U) and
//! `discarded` (explicit part of D), and each member capability stores its
//! balance. The stored identity `N = U + D_explicit + Σ balances` holds after
//! every transition.
//!
//! * CONSUME moves one unit from a balance to U (never refunded).
//! * SPLIT/DELEGATE move units between balances of the same pool.
//! * DROP and budget-reducing ATTENUATE move units to D *transactionally*.
//! * REVOKE, expiry, owner termination and epoch change do **not** move
//!   units; they make the holder non-live, and the spec's L/D split is
//!   *computed* ([`State::accounts_at`]): a balance counts in L iff its
//!   holder is live at the given time, otherwise in D ("stranded"). Because
//!   liveness is monotone, a stranded balance can never become usable again,
//!   and no unit is ever counted twice.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(verus_keep_ghost)]
#[allow(unused_imports)]
use vstd::prelude::*;

mod budget;
mod command;
mod ids;
mod invariant;
mod scope;
mod seq_map;
mod state;
mod step;

pub use budget::{Budget, Depth, Expiry, Tick};
pub use command::{
    AdminCommand, AgentCommand, AuthenticatedCommand, Denial, Effect, GrantRequest, Reservation,
    Resource, VerifiedApproval,
};
pub use ids::{
    AgentId, CapabilityId, EndpointId, Nonce, ObjectId, PoolId, RequestId, ReservationId, RootId,
};
pub use invariant::{InvariantViolation, check_invariant};
pub use scope::{
    FileRight, FileRights, HttpMethod, MethodSet, Operation, Scope, is_subset, permits,
};
pub use state::{
    Capability, Limits, NotLive, Outcome, PoolAccount, PrincipalStatus, ReplayError,
    ReservationRecord, ReservationStatus, RetiredPools, RootKind, RootRecord, State, Status, Terms,
};
pub use step::{step, validate_command};
