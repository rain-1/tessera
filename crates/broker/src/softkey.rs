//! File-backed *software* FIDO2 authenticator for the operator CLI.
//!
//! SIMULATED DEVICE, REAL CRYPTOGRAPHY: an ES256 key stored in a 0600 file,
//! producing CTAP2-format authenticator data and signatures that the broker
//! verifies exactly like a hardware token's. It proves nothing about
//! physical presence; use it only for development and tests. Production
//! uses a hardware token (`fido2-cli` feature).

use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use p256::ecdsa::signature::Signer;
use serde::{Deserialize, Serialize};
use tessera_approval::assertion::{AuthenticatorData, FLAG_UP, FLAG_UV, rp_id_hash};
use tessera_approval::{
    Assertion, AssertionRequest, Authenticator, AuthenticatorError, CoseAlgorithm, CosePublicKey,
    CredentialRequest, NewCredential,
};

use crate::convert::hex;

#[derive(Serialize, Deserialize)]
struct KeyFile {
    rp_id: String,
    credential_id: String,
    secret: String,
    counter: u32,
}

/// Software authenticator whose single credential lives in a key file.
pub struct FileAuthenticator {
    path: std::path::PathBuf,
    key: Option<(String, Vec<u8>, p256::ecdsa::SigningKey, u32)>,
    /// Report user verification (PIN) as performed.
    pub user_verified: bool,
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn io(e: impl std::fmt::Display) -> AuthenticatorError {
    AuthenticatorError::Io(e.to_string())
}

impl FileAuthenticator {
    /// Use (or, on `make_credential`, create) the key file at `path`.
    pub fn open(path: &Path) -> Result<Self, AuthenticatorError> {
        let key = match std::fs::read_to_string(path) {
            Ok(s) => {
                let k: KeyFile = serde_json::from_str(&s).map_err(io)?;
                let secret = unhex(&k.secret).ok_or_else(|| io("bad key file"))?;
                let sk = p256::ecdsa::SigningKey::from_slice(&secret).map_err(io)?;
                Some((
                    k.rp_id,
                    unhex(&k.credential_id).ok_or_else(|| io("bad key file"))?,
                    sk,
                    k.counter,
                ))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(io(e)),
        };
        Ok(FileAuthenticator {
            path: path.to_path_buf(),
            key,
            user_verified: false,
        })
    }

    fn save(&self) -> Result<(), AuthenticatorError> {
        let Some((rp, cred, sk, counter)) = &self.key else {
            return Ok(());
        };
        let k = KeyFile {
            rp_id: rp.clone(),
            credential_id: hex(cred),
            secret: hex(&sk.to_bytes()),
            counter: *counter,
        };
        let tmp = self.path.with_extension("tmp");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(io)?;
        std::io::Write::write_all(&mut f, serde_json::to_string(&k).map_err(io)?.as_bytes())
            .map_err(io)?;
        f.sync_all().map_err(io)?;
        std::fs::rename(&tmp, &self.path).map_err(io)
    }
}

impl Authenticator for FileAuthenticator {
    fn make_credential(
        &mut self,
        request: &CredentialRequest,
    ) -> Result<NewCredential, AuthenticatorError> {
        if request.algorithm != CoseAlgorithm::Es256 {
            return Err(AuthenticatorError::UnsupportedAlgorithm);
        }
        let sk = loop {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(io)?;
            if let Ok(sk) = p256::ecdsa::SigningKey::from_slice(&seed) {
                break sk;
            }
        };
        let mut cred = [0u8; 32];
        getrandom::getrandom(&mut cred).map_err(io)?;
        let public_key =
            CosePublicKey::from_cose_key(&CosePublicKey::Es256(*sk.verifying_key()).to_cose_key())
                .map_err(|e| AuthenticatorError::Protocol(e.to_string()))?;
        self.key = Some((request.rp_id.clone(), cred.to_vec(), sk, 0));
        self.save()?;
        Ok(NewCredential {
            credential_id: cred.to_vec(),
            public_key,
        })
    }

    fn get_assertion(
        &mut self,
        request: &AssertionRequest,
    ) -> Result<Assertion, AuthenticatorError> {
        let (rp, cred, sk, counter) = self.key.as_mut().ok_or(AuthenticatorError::NoCredential)?;
        if *cred != request.credential_id || *rp != request.rp_id {
            return Err(AuthenticatorError::NoCredential);
        }
        *counter = counter.wrapping_add(1);
        let mut flags = FLAG_UP;
        if self.user_verified {
            flags |= FLAG_UV;
        }
        let ad = AuthenticatorData {
            rp_id_hash: rp_id_hash(&request.rp_id),
            flags,
            sign_count: *counter,
        }
        .to_bytes();
        let mut msg = ad.to_vec();
        msg.extend_from_slice(&request.client_data_hash);
        let sig: p256::ecdsa::Signature = sk.sign(&msg);
        let a = Assertion {
            credential_id: cred.clone(),
            authenticator_data: ad.to_vec(),
            signature: sig.to_der().as_bytes().to_vec(),
        };
        self.save()?;
        Ok(a)
    }
}
