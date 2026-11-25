//! Tessera human-approval binding (specification §8, WP4).
//!
//! Flow: the broker builds a canonical [`GrantRequest`] with a fresh
//! [`Nonce`]; an [`ApprovalSession`] (one per enrolled authenticator) shows it
//! via [`render_request`], lets the operator narrow or deny it, and obtains a
//! FIDO2 assertion whose `clientDataHash` is [`GrantRequest::digest`]. The
//! assertion is verified in pure Rust ([`verify_assertion`]) and yields a
//! [`VerifiedApproval`].
//!
//! **Replay defense is the ledger's job**: the broker must atomically redeem
//! [`VerifiedApproval::nonce`] in the durable ledger in the same transaction
//! that mints the root, refusing if already redeemed. This crate keeps no
//! durable state.
#![forbid(unsafe_code)]

pub mod assertion;
pub mod authenticator;
mod codec;
pub mod enrollment;
pub mod render;
pub mod request;
pub mod session;

pub use assertion::{
    Assertion, AuthenticatorData, VerifiedApproval, VerifierPolicy, VerifyError,
    check_request_context, verify_assertion,
};
pub use authenticator::{
    AssertionRequest, Authenticator, AuthenticatorError, CredentialRequest, NewCredential, enroll,
};
pub use codec::DecodeError;
pub use enrollment::{CoseAlgorithm, CosePublicKey, Enrollment, EnrollmentError, KeyError};
pub use render::{RenderContext, escape_untrusted, render_request};
pub use request::{
    AgentId, AuthorityEpoch, Budget, BudgetAmount, BudgetUnit, Depth, EndpointId, FileRights,
    GrantRequest, GrantRequestFields, InstallationId, MethodSet, NarrowingError, Nonce, ObjectId,
    OperatorId, ProtocolVersion, RequestDigest, RequestError, Scope, Tick,
};
pub use session::{ApprovalSession, Closed, PendingApproval, SessionConfig, SessionError};

#[cfg(test)]
mod tests;
