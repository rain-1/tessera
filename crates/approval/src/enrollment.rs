//! Operator credential enrollment record and its storage format.
//!
//! # Storage encoding, format version 1
//!
//! ```text
//! record = magic "TSEN" || format_version u16 = 1 || field{1..4}
//! tag  value
//!  1   operator_id u128                                   (len 16)
//!  2   rp_id, ASCII, 1..=253 bytes, printable, no spaces
//!  3   credential_id, 1..=1023 bytes
//!  4   cose_alg i16 || key bytes  (ES256 -7: x||y 64 bytes; EdDSA -8: 32 bytes)
//! ```
//!
//! Decoding is strict (same TLV rules as the grant request) and re-validates
//! the public key (P-256 point must be on the curve; Ed25519 point must
//! decompress).
//!
//! Enrollment itself is an operator-only administrative action. This crate
//! does not evaluate FIDO2 attestation; the administrative channel is trusted
//! to bind the credential to the operator.

use std::fmt;

use crate::codec::{DecodeError, Reader, Writer};
use crate::request::OperatorId;

pub const ENROLLMENT_MAGIC: [u8; 4] = *b"TSEN";
pub const ENROLLMENT_FORMAT_VERSION: u16 = 1;
pub const MAX_CREDENTIAL_ID_LEN: usize = 1023;
pub const MAX_RP_ID_LEN: usize = 253;

/// COSE algorithm identifiers supported for approval credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CoseAlgorithm {
    /// ECDSA P-256 with SHA-256 (COSE -7).
    Es256,
    /// Ed25519 (COSE -8).
    EdDsa,
}

impl CoseAlgorithm {
    pub fn cose_id(self) -> i16 {
        match self {
            CoseAlgorithm::Es256 => -7,
            CoseAlgorithm::EdDsa => -8,
        }
    }
    pub fn from_cose_id(id: i16) -> Option<Self> {
        match id {
            -7 => Some(CoseAlgorithm::Es256),
            -8 => Some(CoseAlgorithm::EdDsa),
            _ => None,
        }
    }
}

/// A validated credential public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CosePublicKey {
    Es256(p256::ecdsa::VerifyingKey),
    EdDsa(ed25519_dalek::VerifyingKey),
}

/// Errors parsing or validating a public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyError {
    MalformedCose,
    UnsupportedKeyType,
    InvalidPoint,
    MalformedPem,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            KeyError::MalformedCose => "malformed COSE_Key",
            KeyError::UnsupportedKeyType => "unsupported key type or algorithm",
            KeyError::InvalidPoint => "invalid public key point",
            KeyError::MalformedPem => "malformed PEM public key",
        };
        f.write_str(s)
    }
}

impl std::error::Error for KeyError {}

impl CosePublicKey {
    pub fn algorithm(&self) -> CoseAlgorithm {
        match self {
            CosePublicKey::Es256(_) => CoseAlgorithm::Es256,
            CosePublicKey::EdDsa(_) => CoseAlgorithm::EdDsa,
        }
    }

    /// ES256 from affine coordinates; rejects points not on P-256.
    pub fn es256_from_xy(x: &[u8; 32], y: &[u8; 32]) -> Result<Self, KeyError> {
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(x);
        sec1[33..].copy_from_slice(y);
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
            .map(CosePublicKey::Es256)
            .map_err(|_| KeyError::InvalidPoint)
    }

    /// Ed25519 from its 32-byte encoding; rejects non-decompressible and
    /// small-order (weak) points.
    pub fn eddsa_from_bytes(x: &[u8; 32]) -> Result<Self, KeyError> {
        let k = ed25519_dalek::VerifyingKey::from_bytes(x).map_err(|_| KeyError::InvalidPoint)?;
        if k.is_weak() {
            return Err(KeyError::InvalidPoint);
        }
        Ok(CosePublicKey::EdDsa(k))
    }

    /// Raw key bytes as stored (ES256: x||y; EdDSA: 32-byte point).
    pub fn raw_bytes(&self) -> Vec<u8> {
        match self {
            CosePublicKey::Es256(k) => k.to_encoded_point(false).as_bytes()[1..].to_vec(),
            CosePublicKey::EdDsa(k) => k.as_bytes().to_vec(),
        }
    }

    fn from_raw(alg: CoseAlgorithm, raw: &[u8]) -> Result<Self, KeyError> {
        match alg {
            CoseAlgorithm::Es256 => {
                let (x, y) = raw.split_at_checked(32).ok_or(KeyError::InvalidPoint)?;
                let x: &[u8; 32] = x.try_into().map_err(|_| KeyError::InvalidPoint)?;
                let y: &[u8; 32] = y.try_into().map_err(|_| KeyError::InvalidPoint)?;
                Self::es256_from_xy(x, y)
            }
            CoseAlgorithm::EdDsa => {
                let x: &[u8; 32] = raw.try_into().map_err(|_| KeyError::InvalidPoint)?;
                Self::eddsa_from_bytes(x)
            }
        }
    }

    /// Canonical CTAP2 COSE_Key CBOR encoding.
    pub fn to_cose_key(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            CosePublicKey::Es256(k) => {
                let pt = k.to_encoded_point(false);
                // {1: 2, 3: -7, -1: 1, -2: x, -3: y}
                out.extend_from_slice(&[
                    0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20,
                ]);
                out.extend_from_slice(&pt.as_bytes()[1..33]);
                out.extend_from_slice(&[0x22, 0x58, 0x20]);
                out.extend_from_slice(&pt.as_bytes()[33..65]);
            }
            CosePublicKey::EdDsa(k) => {
                // {1: 1, 3: -8, -1: 6, -2: x}
                out.extend_from_slice(&[
                    0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20,
                ]);
                out.extend_from_slice(k.as_bytes());
            }
        }
        out
    }

    /// Parses a COSE_Key as found in CTAP2 attested credential data. Only
    /// definite-length maps with small-integer keys are accepted; duplicate or
    /// unknown labels are rejected.
    pub fn from_cose_key(bytes: &[u8]) -> Result<Self, KeyError> {
        let mut c = Cbor { buf: bytes };
        let n = c.map_header()?;
        let mut kty = None;
        let mut alg = None;
        let mut crv = None;
        let mut x: Option<[u8; 32]> = None;
        let mut y: Option<[u8; 32]> = None;
        for _ in 0..n {
            let label = c.int()?;
            let slot_taken = match label {
                1 => kty.replace(c.int()?).is_some(),
                3 => alg.replace(c.int()?).is_some(),
                -1 => crv.replace(c.int()?).is_some(),
                -2 => x.replace(c.bstr32()?).is_some(),
                -3 => y.replace(c.bstr32()?).is_some(),
                _ => return Err(KeyError::MalformedCose),
            };
            if slot_taken {
                return Err(KeyError::MalformedCose);
            }
        }
        if !c.buf.is_empty() {
            return Err(KeyError::MalformedCose);
        }
        match (kty, alg, crv, x, y) {
            (Some(2), Some(-7), Some(1), Some(x), Some(y)) => Self::es256_from_xy(&x, &y),
            (Some(1), Some(-8), Some(6), Some(x), None) => Self::eddsa_from_bytes(&x),
            _ => Err(KeyError::UnsupportedKeyType),
        }
    }

    /// Parses a PEM SubjectPublicKeyInfo (as printed by `fido2-cred -V`).
    pub fn from_pem(alg: CoseAlgorithm, pem: &str) -> Result<Self, KeyError> {
        match alg {
            CoseAlgorithm::Es256 => {
                use p256::pkcs8::DecodePublicKey;
                p256::ecdsa::VerifyingKey::from_public_key_pem(pem)
                    .map(CosePublicKey::Es256)
                    .map_err(|_| KeyError::MalformedPem)
            }
            CoseAlgorithm::EdDsa => {
                use ed25519_dalek::pkcs8::DecodePublicKey;
                let k = ed25519_dalek::VerifyingKey::from_public_key_pem(pem)
                    .map_err(|_| KeyError::MalformedPem)?;
                Self::eddsa_from_bytes(k.as_bytes())
            }
        }
    }
}

/// Tiny strict CBOR reader sufficient for COSE_Key.
struct Cbor<'a> {
    buf: &'a [u8],
}

impl Cbor<'_> {
    fn byte(&mut self) -> Result<u8, KeyError> {
        let (&b, rest) = self.buf.split_first().ok_or(KeyError::MalformedCose)?;
        self.buf = rest;
        Ok(b)
    }
    fn map_header(&mut self) -> Result<u8, KeyError> {
        match self.byte()? {
            b @ 0xa0..=0xb7 => Ok(b - 0xa0),
            _ => Err(KeyError::MalformedCose),
        }
    }
    fn int(&mut self) -> Result<i64, KeyError> {
        match self.byte()? {
            b @ 0x00..=0x17 => Ok(i64::from(b)),
            0x18 => {
                let v = self.byte()?;
                if v < 24 {
                    return Err(KeyError::MalformedCose);
                }
                Ok(i64::from(v))
            }
            b @ 0x20..=0x37 => Ok(-1 - i64::from(b - 0x20)),
            0x38 => {
                let v = self.byte()?;
                if v < 24 {
                    return Err(KeyError::MalformedCose);
                }
                Ok(-1 - i64::from(v))
            }
            _ => Err(KeyError::MalformedCose),
        }
    }
    fn bstr32(&mut self) -> Result<[u8; 32], KeyError> {
        if self.byte()? != 0x58 || self.byte()? != 32 {
            return Err(KeyError::MalformedCose);
        }
        let (v, rest) = self
            .buf
            .split_at_checked(32)
            .ok_or(KeyError::MalformedCose)?;
        self.buf = rest;
        v.try_into().map_err(|_| KeyError::MalformedCose)
    }
}

/// Error building an [`Enrollment`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnrollmentError {
    InvalidCredentialId,
    InvalidRpId,
}

impl fmt::Display for EnrollmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnrollmentError::InvalidCredentialId => write!(f, "credential id length out of range"),
            EnrollmentError::InvalidRpId => write!(f, "invalid relying-party id"),
        }
    }
}

impl std::error::Error for EnrollmentError {}

/// An enrolled operator approval credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enrollment {
    operator: OperatorId,
    rp_id: String,
    credential_id: Vec<u8>,
    public_key: CosePublicKey,
}

fn valid_rp_id(rp: &str) -> bool {
    !rp.is_empty() && rp.len() <= MAX_RP_ID_LEN && rp.bytes().all(|b| b.is_ascii_graphic())
}

impl Enrollment {
    pub fn new(
        operator: OperatorId,
        rp_id: impl Into<String>,
        credential_id: Vec<u8>,
        public_key: CosePublicKey,
    ) -> Result<Self, EnrollmentError> {
        let rp_id = rp_id.into();
        if credential_id.is_empty() || credential_id.len() > MAX_CREDENTIAL_ID_LEN {
            return Err(EnrollmentError::InvalidCredentialId);
        }
        if !valid_rp_id(&rp_id) {
            return Err(EnrollmentError::InvalidRpId);
        }
        Ok(Enrollment {
            operator,
            rp_id,
            credential_id,
            public_key,
        })
    }

    pub fn operator(&self) -> OperatorId {
        self.operator
    }
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }
    pub fn public_key(&self) -> &CosePublicKey {
        &self.public_key
    }
    pub fn algorithm(&self) -> CoseAlgorithm {
        self.public_key.algorithm()
    }

    /// Storage serialization (see module docs).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.raw(&ENROLLMENT_MAGIC);
        w.u16(ENROLLMENT_FORMAT_VERSION);
        w.field(1, |w| w.u128(self.operator.0));
        w.field(2, |w| w.raw(self.rp_id.as_bytes()));
        w.field(3, |w| w.raw(&self.credential_id));
        w.field(4, |w| {
            w.i16(self.algorithm().cose_id());
            w.raw(&self.public_key.raw_bytes());
        });
        w.finish()
    }

    /// Strict decoder for [`Enrollment::encode`] output.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > 4096 {
            return Err(DecodeError::TooLarge);
        }
        let mut r = Reader::new(bytes);
        if r.array::<4>()? != ENROLLMENT_MAGIC {
            return Err(DecodeError::BadMagic);
        }
        let v = r.u16()?;
        if v != ENROLLMENT_FORMAT_VERSION {
            return Err(DecodeError::UnsupportedFormatVersion(v));
        }
        let mut f = r.field(1)?;
        let operator = OperatorId(f.u128().map_err(|_| DecodeError::BadLength { tag: 1 })?);
        f.finish_field(1)?;
        let rp = r.field(2)?.rest();
        let rp_id = std::str::from_utf8(rp)
            .map_err(|_| DecodeError::InvalidValue("rp id"))?
            .to_owned();
        let credential_id = r.field(3)?.rest().to_vec();
        let mut k = r.field(4)?;
        let alg =
            CoseAlgorithm::from_cose_id(k.i16().map_err(|_| DecodeError::BadLength { tag: 4 })?)
                .ok_or(DecodeError::InvalidValue("cose algorithm"))?;
        let public_key = CosePublicKey::from_raw(alg, k.rest())
            .map_err(|_| DecodeError::InvalidValue("public key"))?;
        r.finish()?;
        let e = Enrollment::new(operator, rp_id, credential_id, public_key)
            .map_err(|_| DecodeError::InvalidValue("enrollment fields"))?;
        if e.encode() != bytes {
            return Err(DecodeError::InvalidValue("non-canonical encoding"));
        }
        Ok(e)
    }
}
