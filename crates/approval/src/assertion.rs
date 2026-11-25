//! FIDO2/CTAP2 assertion verification over a canonical grant request.
//!
//! A CTAP2 `authenticatorGetAssertion` signature covers
//! `authenticatorData || clientDataHash`. Tessera sets
//! `clientDataHash = GrantRequest::digest()` (no WebAuthn `clientDataJSON`), so
//! a valid signature binds the authenticator's user-presence flag to every
//! field of the canonical request.
//!
//! Verification is stateless. **Nonce redemption is not done here**: a
//! [`VerifiedApproval`] is evidence, not authority. The broker must atomically
//! redeem `VerifiedApproval::nonce()` in the durable ledger in the same
//! transaction that mints the root capability, and must refuse to mint if the
//! nonce was already redeemed. That is the replay defense; signature counters
//! are only recorded as evidence.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::enrollment::{CosePublicKey, Enrollment};
use crate::request::{
    AuthorityEpoch, GrantRequest, InstallationId, Nonce, RequestDigest, SUPPORTED_PROTOCOL_VERSION,
    Tick,
};

/// Domain separator for the evidence digest.
pub const APPROVAL_EVIDENCE_DOMAIN: &[u8] = b"tessera/v1/approval-evidence\0";

/// Authenticator data flag: user present.
pub const FLAG_UP: u8 = 0x01;
/// Authenticator data flag: user verified.
pub const FLAG_UV: u8 = 0x04;
/// Authenticator data flag: attested credential data included.
pub const FLAG_AT: u8 = 0x40;
/// Authenticator data flag: extension data included.
pub const FLAG_ED: u8 = 0x80;

const MAX_AUTH_DATA_LEN: usize = 1024;
const MAX_SIGNATURE_LEN: usize = 128;

/// Raw assertion as returned by an authenticator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    /// Raw (not CBOR-wrapped) authenticator data.
    pub authenticator_data: Vec<u8>,
    /// ES256: ASN.1 DER ECDSA signature. EdDSA: 64 raw bytes.
    pub signature: Vec<u8>,
}

/// Broker-side verification policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierPolicy {
    pub installation: InstallationId,
    /// Current authority epoch; requests from other epochs are rejected.
    pub authority_epoch: AuthorityEpoch,
    /// Require the UV (PIN/biometric) flag in addition to UP.
    pub require_user_verification: bool,
}

/// Reasons an assertion was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    UnsupportedProtocolVersion,
    WrongInstallation,
    WrongAuthorityEpoch,
    OperatorMismatch,
    NonceMismatch,
    RequestExpired,
    GrantAlreadyExpired,
    CredentialIdMismatch,
    MalformedAuthenticatorData,
    UnexpectedAttestedCredentialData,
    RpIdHashMismatch,
    UserPresenceMissing,
    UserVerificationMissing,
    MalformedSignature,
    BadSignature,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            VerifyError::UnsupportedProtocolVersion => "unsupported protocol version",
            VerifyError::WrongInstallation => "request is for a different installation",
            VerifyError::WrongAuthorityEpoch => "request is for a different authority epoch",
            VerifyError::OperatorMismatch => "request operator does not own this credential",
            VerifyError::NonceMismatch => "nonce does not match the outstanding challenge",
            VerifyError::RequestExpired => "approval request expired",
            VerifyError::GrantAlreadyExpired => "requested grant already expired",
            VerifyError::CredentialIdMismatch => "assertion from an unexpected credential",
            VerifyError::MalformedAuthenticatorData => "malformed authenticator data",
            VerifyError::UnexpectedAttestedCredentialData => {
                "attested credential data in an assertion"
            }
            VerifyError::RpIdHashMismatch => "relying-party id hash mismatch",
            VerifyError::UserPresenceMissing => "user presence flag not set",
            VerifyError::UserVerificationMissing => "user verification required but absent",
            VerifyError::MalformedSignature => "malformed signature",
            VerifyError::BadSignature => "signature verification failed",
        };
        f.write_str(s)
    }
}

impl std::error::Error for VerifyError {}

/// Parsed fixed-length portion of authenticator data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatorData {
    pub rp_id_hash: [u8; 32],
    pub flags: u8,
    pub sign_count: u32,
}

impl AuthenticatorData {
    /// Parses raw authenticator data. Assertions must not carry attested
    /// credential data; extension bytes (ED flag) are permitted but must be
    /// present iff ED is set. They are covered by the signature and ignored.
    pub fn parse(raw: &[u8]) -> Result<Self, VerifyError> {
        if raw.len() < 37 || raw.len() > MAX_AUTH_DATA_LEN {
            return Err(VerifyError::MalformedAuthenticatorData);
        }
        let mut rp_id_hash = [0u8; 32];
        rp_id_hash.copy_from_slice(&raw[..32]);
        let flags = raw[32];
        let sign_count = u32::from_be_bytes([raw[33], raw[34], raw[35], raw[36]]);
        if flags & FLAG_AT != 0 {
            return Err(VerifyError::UnexpectedAttestedCredentialData);
        }
        let has_ext = raw.len() > 37;
        if has_ext != (flags & FLAG_ED != 0) {
            return Err(VerifyError::MalformedAuthenticatorData);
        }
        Ok(AuthenticatorData {
            rp_id_hash,
            flags,
            sign_count,
        })
    }

    /// Serializes the 37-byte fixed portion.
    pub fn to_bytes(&self) -> [u8; 37] {
        let mut out = [0u8; 37];
        out[..32].copy_from_slice(&self.rp_id_hash);
        out[32] = self.flags;
        out[33..].copy_from_slice(&self.sign_count.to_be_bytes());
        out
    }
}

/// SHA-256 of a relying-party id, as in authenticator data.
pub fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    Sha256::digest(rp_id.as_bytes()).into()
}

/// Proof that the enrolled operator touched the authenticator for exactly
/// `request`. Not authority by itself: the ledger must redeem the nonce.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedApproval {
    request: GrantRequest,
    request_digest: RequestDigest,
    evidence_digest: [u8; 32],
    sign_count: u32,
    user_verified: bool,
}

impl VerifiedApproval {
    pub fn request(&self) -> &GrantRequest {
        &self.request
    }
    /// The nonce the ledger must atomically redeem when minting.
    pub fn nonce(&self) -> &Nonce {
        self.request.nonce()
    }
    pub fn request_digest(&self) -> &RequestDigest {
        &self.request_digest
    }
    /// Digest over credential id, authenticator data, signature and request
    /// digest; suitable as an audit-log reference to the raw evidence.
    pub fn evidence_digest(&self) -> &[u8; 32] {
        &self.evidence_digest
    }
    /// Authenticator signature counter (evidence only; may be zero/unreliable).
    pub fn sign_count(&self) -> u32 {
        self.sign_count
    }
    pub fn user_verified(&self) -> bool {
        self.user_verified
    }
    pub fn into_request(self) -> GrantRequest {
        self.request
    }
}

/// Computes the evidence digest:
/// `SHA-256(domain || u16 len || cred_id || u16 len || auth_data || u16 len || sig || request_digest)`.
pub fn evidence_digest(assertion: &Assertion, request_digest: &RequestDigest) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(APPROVAL_EVIDENCE_DOMAIN);
    for part in [
        &assertion.credential_id[..],
        &assertion.authenticator_data[..],
        &assertion.signature[..],
    ] {
        // Lengths are bounded well below u16::MAX by the verifier.
        h.update(u16::try_from(part.len()).unwrap_or(u16::MAX).to_be_bytes());
        h.update(part);
    }
    h.update(request_digest.0);
    h.finalize().into()
}

/// Verifies `assertion` as the enrolled operator's approval of `request`.
///
/// `expected_nonce` is the nonce of the challenge the broker currently has
/// outstanding for this authenticator; `now` is trusted time.
pub fn verify_assertion(
    enrollment: &Enrollment,
    policy: &VerifierPolicy,
    request: &GrantRequest,
    expected_nonce: &Nonce,
    assertion: &Assertion,
    now: Tick,
) -> Result<VerifiedApproval, VerifyError> {
    check_request_context(enrollment, policy, request, now)?;
    if request.nonce() != expected_nonce {
        return Err(VerifyError::NonceMismatch);
    }
    if assertion.credential_id != enrollment.credential_id() {
        return Err(VerifyError::CredentialIdMismatch);
    }
    let ad = AuthenticatorData::parse(&assertion.authenticator_data)?;
    if ad.rp_id_hash != rp_id_hash(enrollment.rp_id()) {
        return Err(VerifyError::RpIdHashMismatch);
    }
    if ad.flags & FLAG_UP == 0 {
        return Err(VerifyError::UserPresenceMissing);
    }
    let user_verified = ad.flags & FLAG_UV != 0;
    if policy.require_user_verification && !user_verified {
        return Err(VerifyError::UserVerificationMissing);
    }
    if assertion.signature.len() > MAX_SIGNATURE_LEN {
        return Err(VerifyError::MalformedSignature);
    }

    let request_digest = request.digest();
    let mut signed = Vec::with_capacity(assertion.authenticator_data.len() + 32);
    signed.extend_from_slice(&assertion.authenticator_data);
    signed.extend_from_slice(&request_digest.0);

    match enrollment.public_key() {
        CosePublicKey::Es256(vk) => {
            use p256::ecdsa::signature::Verifier;
            let sig = p256::ecdsa::Signature::from_der(&assertion.signature)
                .map_err(|_| VerifyError::MalformedSignature)?;
            vk.verify(&signed, &sig)
                .map_err(|_| VerifyError::BadSignature)?;
        }
        CosePublicKey::EdDsa(vk) => {
            let bytes: &[u8; 64] = assertion
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| VerifyError::MalformedSignature)?;
            let sig = ed25519_dalek::Signature::from_bytes(bytes);
            vk.verify_strict(&signed, &sig)
                .map_err(|_| VerifyError::BadSignature)?;
        }
    }

    Ok(VerifiedApproval {
        request: request.clone(),
        evidence_digest: evidence_digest(assertion, &request_digest),
        request_digest,
        sign_count: ad.sign_count,
        user_verified,
    })
}

/// Checks the parts of a request that do not depend on the assertion:
/// version, installation, epoch, operator binding and expiry.
pub fn check_request_context(
    enrollment: &Enrollment,
    policy: &VerifierPolicy,
    request: &GrantRequest,
    now: Tick,
) -> Result<(), VerifyError> {
    let f = request.fields();
    if f.protocol_version != SUPPORTED_PROTOCOL_VERSION {
        return Err(VerifyError::UnsupportedProtocolVersion);
    }
    if f.installation != policy.installation {
        return Err(VerifyError::WrongInstallation);
    }
    if f.authority_epoch != policy.authority_epoch {
        return Err(VerifyError::WrongAuthorityEpoch);
    }
    if f.operator != enrollment.operator() {
        return Err(VerifyError::OperatorMismatch);
    }
    if now >= f.request_expires_at {
        return Err(VerifyError::RequestExpired);
    }
    if now >= f.grant_expires_at {
        return Err(VerifyError::GrantAlreadyExpired);
    }
    Ok(())
}
