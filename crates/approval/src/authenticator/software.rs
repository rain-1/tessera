//! In-memory authenticator producing CTAP2-format assertions.
//!
//! SIMULATED DEVICE, REAL CRYPTOGRAPHY: keys live in process memory, "touch"
//! is a boolean. For tests and demos only; never enroll one in production.

use p256::ecdsa::signature::Signer;

use super::{
    AssertionRequest, Authenticator, AuthenticatorError, CredentialRequest, NewCredential,
};
use crate::assertion::{Assertion, AuthenticatorData, FLAG_UP, FLAG_UV, rp_id_hash};
use crate::enrollment::{CoseAlgorithm, CosePublicKey};

enum SoftKey {
    Es256(p256::ecdsa::SigningKey),
    EdDsa(ed25519_dalek::SigningKey),
}

/// Software FIDO2 authenticator (see module docs).
pub struct SoftwareAuthenticator {
    credentials: Vec<(Vec<u8>, String, SoftKey)>,
    counter: u32,
    /// Whether the simulated user touches the device (sets UP).
    pub user_present: bool,
    /// Whether the simulated user passes PIN/biometric (sets UV).
    pub user_verified: bool,
}

impl Default for SoftwareAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

fn random<const N: usize>() -> Result<[u8; N], AuthenticatorError> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|e| AuthenticatorError::Io(e.to_string()))?;
    Ok(b)
}

impl SoftwareAuthenticator {
    pub fn new() -> Self {
        SoftwareAuthenticator {
            credentials: Vec::new(),
            counter: 0,
            user_present: true,
            user_verified: false,
        }
    }
}

impl Authenticator for SoftwareAuthenticator {
    fn make_credential(
        &mut self,
        request: &CredentialRequest,
    ) -> Result<NewCredential, AuthenticatorError> {
        let (key, public_key) = match request.algorithm {
            CoseAlgorithm::Es256 => {
                let sk = loop {
                    let seed = random::<32>()?;
                    if let Ok(sk) = p256::ecdsa::SigningKey::from_bytes(&seed.into()) {
                        break sk;
                    }
                };
                let pk = CosePublicKey::Es256(*sk.verifying_key());
                (SoftKey::Es256(sk), pk)
            }
            CoseAlgorithm::EdDsa => {
                let sk = ed25519_dalek::SigningKey::from_bytes(&random::<32>()?);
                let pk = CosePublicKey::EdDsa(sk.verifying_key());
                (SoftKey::EdDsa(sk), pk)
            }
        };
        // Round-trip through COSE_Key exactly as a real device would report it.
        let public_key = CosePublicKey::from_cose_key(&public_key.to_cose_key())
            .map_err(|e| AuthenticatorError::Protocol(e.to_string()))?;
        let credential_id = random::<32>()?.to_vec();
        self.credentials
            .push((credential_id.clone(), request.rp_id.clone(), key));
        Ok(NewCredential {
            credential_id,
            public_key,
        })
    }

    fn get_assertion(
        &mut self,
        request: &AssertionRequest,
    ) -> Result<Assertion, AuthenticatorError> {
        // Like a real token, credentials are scoped to the RP id they were
        // created for; the rpIdHash is computed from the *requested* RP id.
        let (_, _, key) = self
            .credentials
            .iter()
            .find(|(id, rp, _)| *id == request.credential_id && *rp == request.rp_id)
            .ok_or(AuthenticatorError::NoCredential)?;
        self.counter = self.counter.wrapping_add(1);
        let mut flags = 0;
        if self.user_present {
            flags |= FLAG_UP;
        }
        if self.user_verified {
            flags |= FLAG_UV;
        }
        let ad = AuthenticatorData {
            rp_id_hash: rp_id_hash(&request.rp_id),
            flags,
            sign_count: self.counter,
        }
        .to_bytes()
        .to_vec();
        let mut msg = ad.clone();
        msg.extend_from_slice(&request.client_data_hash);
        let signature = match key {
            SoftKey::Es256(sk) => {
                let sig: p256::ecdsa::Signature = sk.sign(&msg);
                sig.to_der().as_bytes().to_vec()
            }
            SoftKey::EdDsa(sk) => {
                use ed25519_dalek::Signer as _;
                sk.sign(&msg).to_bytes().to_vec()
            }
        };
        Ok(Assertion {
            credential_id: request.credential_id.clone(),
            authenticator_data: ad,
            signature,
        })
    }
}
