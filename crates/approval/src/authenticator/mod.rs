//! Authenticator device abstraction.
//!
//! Implementations:
//! - [`SoftwareAuthenticator`] (tests / `software-authenticator` feature):
//!   produces real CTAP2-format authenticator data and ES256/EdDSA signatures
//!   from in-memory keys. It simulates the *device*, not the cryptography.
//! - [`Fido2CliAuthenticator`] (`fido2-cli` feature): drives a real FIDO2
//!   token through Yubico's `fido2-cred`/`fido2-assert`. **Untested** against
//!   hardware in this repository.

use std::fmt;

use crate::assertion::Assertion;
use crate::enrollment::{CoseAlgorithm, CosePublicKey, Enrollment, EnrollmentError};
use crate::request::OperatorId;

#[cfg(any(test, feature = "software-authenticator"))]
mod software;
#[cfg(any(test, feature = "software-authenticator"))]
pub use software::SoftwareAuthenticator;

#[cfg(feature = "fido2-cli")]
mod fido2_cli;
#[cfg(feature = "fido2-cli")]
pub use fido2_cli::Fido2CliAuthenticator;

/// Input to `authenticatorGetAssertion`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssertionRequest {
    pub rp_id: String,
    /// The canonical request digest.
    pub client_data_hash: [u8; 32],
    /// The single allowed credential.
    pub credential_id: Vec<u8>,
    pub require_user_verification: bool,
}

/// Input to `authenticatorMakeCredential` (enrollment).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRequest {
    pub rp_id: String,
    pub operator: OperatorId,
    /// Display name stored on the token.
    pub user_name: String,
    pub algorithm: CoseAlgorithm,
    pub require_user_verification: bool,
}

/// A freshly created credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewCredential {
    pub credential_id: Vec<u8>,
    pub public_key: CosePublicKey,
}

/// Device-level failure.
#[derive(Debug)]
pub enum AuthenticatorError {
    /// No matching credential on the device.
    NoCredential,
    /// Requested algorithm not supported by the device/implementation.
    UnsupportedAlgorithm,
    /// The operator declined or the touch timed out on the device.
    Cancelled,
    /// Underlying tool or device I/O failed.
    Io(String),
    /// Device output could not be parsed.
    Protocol(String),
    /// Resulting enrollment invalid.
    Enrollment(EnrollmentError),
}

impl fmt::Display for AuthenticatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthenticatorError::NoCredential => write!(f, "no matching credential"),
            AuthenticatorError::UnsupportedAlgorithm => write!(f, "unsupported algorithm"),
            AuthenticatorError::Cancelled => write!(f, "cancelled"),
            AuthenticatorError::Io(e) => write!(f, "authenticator I/O error: {e}"),
            AuthenticatorError::Protocol(e) => write!(f, "authenticator protocol error: {e}"),
            AuthenticatorError::Enrollment(e) => write!(f, "enrollment error: {e}"),
        }
    }
}

impl std::error::Error for AuthenticatorError {}

/// A FIDO2 authenticator that can enroll a credential and sign assertions.
pub trait Authenticator {
    fn make_credential(
        &mut self,
        request: &CredentialRequest,
    ) -> Result<NewCredential, AuthenticatorError>;
    fn get_assertion(
        &mut self,
        request: &AssertionRequest,
    ) -> Result<Assertion, AuthenticatorError>;
}

/// Operator-only enrollment: creates a credential and returns the record the
/// broker should persist. Attestation is not evaluated (see module docs of
/// [`crate::enrollment`]).
pub fn enroll(
    authenticator: &mut dyn Authenticator,
    request: &CredentialRequest,
) -> Result<Enrollment, AuthenticatorError> {
    let cred = authenticator.make_credential(request)?;
    if cred.public_key.algorithm() != request.algorithm {
        return Err(AuthenticatorError::Protocol(
            "device returned a key for a different algorithm".into(),
        ));
    }
    Enrollment::new(
        request.operator,
        request.rp_id.clone(),
        cred.credential_id,
        cred.public_key,
    )
    .map_err(AuthenticatorError::Enrollment)
}
