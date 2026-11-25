//! FIDO2 token access through Yubico's libfido2 command-line tools.
//!
//! **UNTESTED**: written against the `fido2-cred(1)` and `fido2-assert(1)`
//! manual pages (<https://developers.yubico.com/libfido2/Manuals/>) without a
//! device or the tools available. Validate against real hardware before
//! relying on it. Cryptographic verification never trusts this module: every
//! assertion it returns is checked by [`crate::verify_assertion`].
//!
//! Formats used (one item per line, binary blobs base64):
//! - `fido2-cred -M` input: clientDataHash, rp id, user name, user id.
//!   Output: clientDataHash, rp id, fmt, authData (CBOR bstr), credential id,
//!   attestation signature, [x5c]. That output is piped to `fido2-cred -V`,
//!   which prints credential id and the PEM public key.
//! - `fido2-assert -G` input: clientDataHash, rp id, credential id.
//!   Output: clientDataHash, rp id, authData (CBOR bstr), signature, ...
//!
//! PIN entry (for UV) happens on the controlling terminal through the tool's
//! own prompt; stderr and the TTY are inherited. The process blocks until the
//! token is touched or the token's own timeout elapses.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use base64ct::{Base64, Encoding};

use super::{
    AssertionRequest, Authenticator, AuthenticatorError, CredentialRequest, NewCredential,
};
use crate::assertion::Assertion;
use crate::enrollment::{CoseAlgorithm, CosePublicKey};

/// Authenticator backed by `fido2-cred` / `fido2-assert` (UNTESTED).
pub struct Fido2CliAuthenticator {
    /// Device path, e.g. `/dev/hidraw3` (see `fido2-token -L`).
    pub device: PathBuf,
    pub fido2_cred: PathBuf,
    pub fido2_assert: PathBuf,
}

impl Fido2CliAuthenticator {
    pub fn new(device: impl Into<PathBuf>) -> Self {
        Fido2CliAuthenticator {
            device: device.into(),
            fido2_cred: PathBuf::from("fido2-cred"),
            fido2_assert: PathBuf::from("fido2-assert"),
        }
    }
}

fn run(
    program: &PathBuf,
    args: &[&str],
    device: Option<&PathBuf>,
    input: &str,
) -> Result<String, AuthenticatorError> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    if let Some(d) = device {
        cmd.arg(d);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| AuthenticatorError::Io(format!("{}: {e}", program.display())))?;
    child
        .stdin
        .take()
        .ok_or_else(|| AuthenticatorError::Io("no stdin".into()))?
        .write_all(input.as_bytes())
        .map_err(|e| AuthenticatorError::Io(e.to_string()))?;
    let out = child
        .wait_with_output()
        .map_err(|e| AuthenticatorError::Io(e.to_string()))?;
    if !out.status.success() {
        return Err(AuthenticatorError::Io(format!(
            "{} exited with {}",
            program.display(),
            out.status
        )));
    }
    String::from_utf8(out.stdout)
        .map_err(|_| AuthenticatorError::Protocol("non-UTF-8 output".into()))
}

fn b64(data: &[u8]) -> String {
    Base64::encode_string(data)
}

fn unb64(s: &str) -> Result<Vec<u8>, AuthenticatorError> {
    Base64::decode_vec(s.trim()).map_err(|_| AuthenticatorError::Protocol("bad base64".into()))
}

/// libfido2 prints authenticator data as a CBOR byte string; unwrap it.
fn unwrap_cbor_bstr(b: &[u8]) -> Result<Vec<u8>, AuthenticatorError> {
    let err = || AuthenticatorError::Protocol("authData is not a CBOR byte string".into());
    let (&h, rest) = b.split_first().ok_or_else(err)?;
    let (len, body) = match h {
        0x40..=0x57 => (usize::from(h - 0x40), rest),
        0x58 => {
            let (&l, r) = rest.split_first().ok_or_else(err)?;
            (usize::from(l), r)
        }
        0x59 => {
            let l = rest.get(..2).ok_or_else(err)?;
            (usize::from(u16::from_be_bytes([l[0], l[1]])), &rest[2..])
        }
        _ => return Err(err()),
    };
    if body.len() != len {
        return Err(err());
    }
    Ok(body.to_vec())
}

fn alg_name(alg: CoseAlgorithm) -> &'static str {
    match alg {
        CoseAlgorithm::Es256 => "es256",
        CoseAlgorithm::EdDsa => "eddsa",
    }
}

impl Authenticator for Fido2CliAuthenticator {
    fn make_credential(
        &mut self,
        request: &CredentialRequest,
    ) -> Result<NewCredential, AuthenticatorError> {
        let mut cdh = [0u8; 32];
        getrandom::getrandom(&mut cdh).map_err(|e| AuthenticatorError::Io(e.to_string()))?;
        let input = format!(
            "{}\n{}\n{}\n{}\n",
            b64(&cdh),
            request.rp_id,
            request.user_name,
            b64(&request.operator.0.to_be_bytes())
        );
        let mut args = vec!["-M"];
        if request.require_user_verification {
            args.push("-v");
        }
        // `fido2-cred -M [opts] device [type]`
        let mut cmd_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        cmd_args.push(self.device.to_string_lossy().into_owned());
        cmd_args.push(alg_name(request.algorithm).into());
        let made = run(
            &self.fido2_cred,
            &cmd_args.iter().map(String::as_str).collect::<Vec<_>>(),
            None,
            &input,
        )?;
        // Verify the attestation statement's internal consistency and extract
        // the public key: `fido2-cred -V [type]`.
        let mut vargs = vec!["-V"];
        if request.require_user_verification {
            vargs.push("-v");
        }
        vargs.push(alg_name(request.algorithm));
        let verified = run(&self.fido2_cred, &vargs, None, &made)?;
        let mut lines = verified.lines();
        let credential_id = unb64(
            lines
                .next()
                .ok_or_else(|| AuthenticatorError::Protocol("missing credential id".into()))?,
        )?;
        let pem: String = lines.collect::<Vec<_>>().join("\n");
        let public_key = CosePublicKey::from_pem(request.algorithm, &pem)
            .map_err(|e| AuthenticatorError::Protocol(e.to_string()))?;
        Ok(NewCredential {
            credential_id,
            public_key,
        })
    }

    fn get_assertion(
        &mut self,
        request: &AssertionRequest,
    ) -> Result<Assertion, AuthenticatorError> {
        let input = format!(
            "{}\n{}\n{}\n",
            b64(&request.client_data_hash),
            request.rp_id,
            b64(&request.credential_id)
        );
        let mut args = vec!["-G", "-t", "up=true"];
        if request.require_user_verification {
            args.extend(["-t", "uv=true"]);
        }
        let out = run(&self.fido2_assert, &args, Some(&self.device), &input)?;
        let lines: Vec<&str> = out.lines().collect();
        if lines.len() < 4 {
            return Err(AuthenticatorError::Protocol(
                "short fido2-assert output".into(),
            ));
        }
        // Echoed clientDataHash and rp id must match what we asked for.
        if unb64(lines[0])? != request.client_data_hash || lines[1] != request.rp_id {
            return Err(AuthenticatorError::Protocol(
                "fido2-assert echoed different inputs".into(),
            ));
        }
        Ok(Assertion {
            credential_id: request.credential_id.clone(),
            authenticator_data: unwrap_cbor_bstr(&unb64(lines[2])?)?,
            signature: unb64(lines[3])?,
        })
    }
}
