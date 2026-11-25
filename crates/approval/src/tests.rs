//! WP4 gate tests.

use proptest::prelude::*;
use sha2::{Digest, Sha256};

use crate::assertion::{APPROVAL_EVIDENCE_DOMAIN, FLAG_AT, FLAG_ED, FLAG_UP, rp_id_hash};
use crate::authenticator::SoftwareAuthenticator;
use crate::request::{GRANT_APPROVAL_DOMAIN, MAX_ENCODED_REQUEST_LEN};
use crate::*;

const RP: &str = "tessera.local";
const OP: OperatorId = OperatorId(0x0bad_cafe);

fn policy() -> VerifierPolicy {
    VerifierPolicy {
        installation: InstallationId(0x1111),
        authority_epoch: AuthorityEpoch(7),
        require_user_verification: false,
    }
}

fn base_fields() -> GrantRequestFields {
    GrantRequestFields {
        protocol_version: ProtocolVersion(1),
        installation: InstallationId(0x1111),
        authority_epoch: AuthorityEpoch(7),
        operator: OP,
        recipient: AgentId {
            epoch: 0xabcd,
            serial: 42,
        },
        scope: Scope::File {
            object: ObjectId(0x5150),
            rights: FileRights::new(FileRights::READ | FileRights::REPLACE).unwrap(),
        },
        budget: Budget {
            amount: BudgetAmount::Finite(3),
            unit: BudgetUnit::Operations,
        },
        depth: Depth::Finite(2),
        grant_expires_at: Tick(10_000),
        nonce: Nonce([0x5a; 32]),
        request_expires_at: Tick(1_000),
    }
}

fn req(f: GrantRequestFields) -> GrantRequest {
    GrantRequest::new(f).unwrap()
}

fn fresh_nonce_fields() -> GrantRequestFields {
    GrantRequestFields {
        nonce: Nonce::random().unwrap(),
        ..base_fields()
    }
}

fn setup(alg: CoseAlgorithm) -> (SoftwareAuthenticator, Enrollment) {
    let mut a = SoftwareAuthenticator::new();
    let e = enroll(
        &mut a,
        &CredentialRequest {
            rp_id: RP.into(),
            operator: OP,
            user_name: "operator".into(),
            algorithm: alg,
            require_user_verification: false,
        },
    )
    .unwrap();
    (a, e)
}

fn sign(a: &mut SoftwareAuthenticator, e: &Enrollment, r: &GrantRequest) -> Assertion {
    a.get_assertion(&AssertionRequest {
        rp_id: e.rp_id().into(),
        client_data_hash: r.digest().0,
        credential_id: e.credential_id().to_vec(),
        require_user_verification: false,
    })
    .unwrap()
}

fn verify(
    e: &Enrollment,
    r: &GrantRequest,
    a: &Assertion,
) -> Result<VerifiedApproval, VerifyError> {
    verify_assertion(e, &policy(), r, r.nonce(), a, Tick(100))
}

// ---------------------------------------------------------------- assertion

#[test]
fn valid_assertion_verifies_es256_and_eddsa() {
    for alg in [CoseAlgorithm::Es256, CoseAlgorithm::EdDsa] {
        let (mut a, e) = setup(alg);
        let r = req(base_fields());
        let asn = sign(&mut a, &e, &r);
        let v = verify(&e, &r, &asn).unwrap();
        assert_eq!(v.request(), &r);
        assert_eq!(v.nonce(), r.nonce());
        assert_eq!(v.request_digest(), &r.digest());
        assert_eq!(
            v.evidence_digest(),
            &assertion::evidence_digest(&asn, &r.digest())
        );
        assert!(!v.user_verified());
        assert_eq!(v.sign_count(), 1);
    }
}

/// Every bound field, mutated; also verified under a policy/enrollment that
/// would accept the mutated context, so the *signature* must be what fails.
#[test]
fn mutating_any_bound_field_rejects() {
    let (mut a, e) = setup(CoseAlgorithm::Es256);
    let orig = req(base_fields());
    let asn = sign(&mut a, &e, &orig);
    type Mutation = Box<dyn Fn(&mut GrantRequestFields)>;
    let muts: Vec<(&str, Mutation)> = vec![
        ("installation", Box::new(|f| f.installation.0 ^= 1)),
        ("epoch", Box::new(|f| f.authority_epoch.0 += 1)),
        ("operator", Box::new(|f| f.operator.0 ^= 1)),
        ("recipient.epoch", Box::new(|f| f.recipient.epoch ^= 1)),
        ("recipient.serial", Box::new(|f| f.recipient.serial ^= 1)),
        (
            "scope.object",
            Box::new(|f| {
                if let Scope::File { object, .. } = &mut f.scope {
                    object.0 ^= 1
                }
            }),
        ),
        (
            "scope.rights",
            Box::new(|f| {
                if let Scope::File { rights, .. } = &mut f.scope {
                    *rights = FileRights::new(FileRights::READ).unwrap()
                }
            }),
        ),
        (
            "scope.kind",
            Box::new(|f| {
                f.scope = Scope::Https {
                    endpoint: EndpointId(0x5150),
                    methods: MethodSet::new(MethodSet::GET).unwrap(),
                    max_body_bytes: 0,
                }
            }),
        ),
        (
            "budget.amount",
            Box::new(|f| f.budget.amount = BudgetAmount::Finite(4)),
        ),
        (
            "budget.unlimited",
            Box::new(|f| f.budget.amount = BudgetAmount::Unlimited),
        ),
        (
            "budget.unit",
            Box::new(|f| f.budget.unit = BudgetUnit::Requests),
        ),
        ("depth", Box::new(|f| f.depth = Depth::Finite(3))),
        ("depth.unlimited", Box::new(|f| f.depth = Depth::Unlimited)),
        ("grant_expiry", Box::new(|f| f.grant_expires_at.0 += 1)),
        ("nonce", Box::new(|f| f.nonce.0[31] ^= 1)),
        ("request_expiry", Box::new(|f| f.request_expires_at.0 += 1)),
    ];
    for (name, m) in muts {
        let mut f = base_fields();
        m(&mut f);
        let mutated = req(f.clone());
        assert_ne!(mutated.encode(), orig.encode(), "{name}");
        assert!(verify(&e, &mutated, &asn).is_err(), "{name} accepted");
        // Context adapted to the mutation: only the signature can fail now.
        let pol = VerifierPolicy {
            installation: f.installation,
            authority_epoch: f.authority_epoch,
            require_user_verification: false,
        };
        let e2 = Enrollment::new(
            f.operator,
            RP,
            e.credential_id().to_vec(),
            e.public_key().clone(),
        )
        .unwrap();
        assert_eq!(
            verify_assertion(&e2, &pol, &mutated, mutated.nonce(), &asn, Tick(100)),
            Err(VerifyError::BadSignature),
            "{name}"
        );
    }
}

#[test]
fn every_single_bit_flip_of_encoding_rejects() {
    let (mut a, e) = setup(CoseAlgorithm::Es256);
    let orig = req(base_fields());
    let asn = sign(&mut a, &e, &orig);
    let bytes = orig.encode();
    for i in 0..bytes.len() * 8 {
        let mut b = bytes.clone();
        b[i / 8] ^= 1 << (i % 8);
        if let Ok(m) = GrantRequest::decode(&b) {
            let f = m.fields();
            let pol = VerifierPolicy {
                installation: f.installation,
                authority_epoch: f.authority_epoch,
                require_user_verification: false,
            };
            let e2 = Enrollment::new(
                f.operator,
                RP,
                e.credential_id().to_vec(),
                e.public_key().clone(),
            )
            .unwrap();
            assert!(
                verify_assertion(&e2, &pol, &m, m.nonce(), &asn, Tick(0)).is_err(),
                "bit {i}"
            );
        }
    }
}

#[test]
fn stale_or_mismatched_nonce_rejects() {
    let (mut a, e) = setup(CoseAlgorithm::Es256);
    let r = req(base_fields());
    let asn = sign(&mut a, &e, &r);
    let other = Nonce([0x77; 32]);
    assert_eq!(
        verify_assertion(&e, &policy(), &r, &other, &asn, Tick(100)),
        Err(VerifyError::NonceMismatch)
    );
}

#[test]
fn wrong_key_rejects() {
    let (mut a, e) = setup(CoseAlgorithm::Es256);
    let (_, other) = setup(CoseAlgorithm::Es256);
    let r = req(base_fields());
    let asn = sign(&mut a, &e, &r);
    let forged = Enrollment::new(
        OP,
        RP,
        e.credential_id().to_vec(),
        other.public_key().clone(),
    )
    .unwrap();
    assert_eq!(verify(&forged, &r, &asn), Err(VerifyError::BadSignature));
    // EdDSA wrong key too.
    let (mut a, e) = setup(CoseAlgorithm::EdDsa);
    let (_, other) = setup(CoseAlgorithm::EdDsa);
    let asn = sign(&mut a, &e, &r);
    let forged = Enrollment::new(
        OP,
        RP,
        e.credential_id().to_vec(),
        other.public_key().clone(),
    )
    .unwrap();
    assert_eq!(verify(&forged, &r, &asn), Err(VerifyError::BadSignature));
    // Algorithm confusion: ES256 signature against an EdDSA key.
    let (mut a, e) = setup(CoseAlgorithm::Es256);
    let asn = sign(&mut a, &e, &r);
    let forged = Enrollment::new(
        OP,
        RP,
        e.credential_id().to_vec(),
        other.public_key().clone(),
    )
    .unwrap();
    assert!(verify(&forged, &r, &asn).is_err());
}

#[test]
fn wrong_rp_id_rejects() {
    let (mut a, e) = setup(CoseAlgorithm::Es256);
    let r = req(base_fields());
    let asn = sign(&mut a, &e, &r);
    let other_rp = Enrollment::new(
        OP,
        "evil.example",
        e.credential_id().to_vec(),
        e.public_key().clone(),
    )
    .unwrap();
    assert_eq!(
        verify(&other_rp, &r, &asn),
        Err(VerifyError::RpIdHashMismatch)
    );
    // And a token asked to sign for another RP does not hold our credential.
    let res = a.get_assertion(&AssertionRequest {
        rp_id: "evil.example".into(),
        client_data_hash: r.digest().0,
        credential_id: e.credential_id().to_vec(),
        require_user_verification: false,
    });
    assert!(matches!(res, Err(AuthenticatorError::NoCredential)));
}

#[test]
fn user_presence_absent_rejects() {
    let (mut a, e) = setup(CoseAlgorithm::Es256);
    a.user_present = false;
    let r = req(base_fields());
    let asn = sign(&mut a, &e, &r);
    assert_eq!(verify(&e, &r, &asn), Err(VerifyError::UserPresenceMissing));
    // Setting UP after signing breaks the signature.
    let mut tampered = asn.clone();
    tampered.authenticator_data[32] |= FLAG_UP;
    assert_eq!(verify(&e, &r, &tampered), Err(VerifyError::BadSignature));
}

#[test]
fn user_verification_required_but_absent_rejects() {
    let (mut a, e) = setup(CoseAlgorithm::Es256);
    let r = req(base_fields());
    let pol = VerifierPolicy {
        require_user_verification: true,
        ..policy()
    };
    let asn = sign(&mut a, &e, &r);
    assert_eq!(
        verify_assertion(&e, &pol, &r, r.nonce(), &asn, Tick(100)),
        Err(VerifyError::UserVerificationMissing)
    );
    a.user_verified = true;
    let asn = sign(&mut a, &e, &r);
    let v = verify_assertion(&e, &pol, &r, r.nonce(), &asn, Tick(100)).unwrap();
    assert!(v.user_verified());
}

#[test]
fn expired_request_or_grant_rejects() {
    let (mut a, e) = setup(CoseAlgorithm::Es256);
    let r = req(base_fields());
    let asn = sign(&mut a, &e, &r);
    assert!(verify_assertion(&e, &policy(), &r, r.nonce(), &asn, Tick(999)).is_ok());
    assert_eq!(
        verify_assertion(&e, &policy(), &r, r.nonce(), &asn, Tick(1_000)),
        Err(VerifyError::RequestExpired)
    );
    let r2 = req(GrantRequestFields {
        grant_expires_at: Tick(50),
        ..base_fields()
    });
    let asn2 = sign(&mut a, &e, &r2);
    assert_eq!(
        verify_assertion(&e, &policy(), &r2, r2.nonce(), &asn2, Tick(50)),
        Err(VerifyError::GrantAlreadyExpired)
    );
}

#[test]
fn wrong_credential_id_rejects() {
    let (mut a, e) = setup(CoseAlgorithm::Es256);
    let r = req(base_fields());
    let mut asn = sign(&mut a, &e, &r);
    asn.credential_id[0] ^= 1;
    assert_eq!(verify(&e, &r, &asn), Err(VerifyError::CredentialIdMismatch));
}

#[test]
fn wrong_context_rejects() {
    let (mut a, e) = setup(CoseAlgorithm::Es256);
    let r = req(base_fields());
    let asn = sign(&mut a, &e, &r);
    let p = VerifierPolicy {
        authority_epoch: AuthorityEpoch(8),
        ..policy()
    };
    assert_eq!(
        verify_assertion(&e, &p, &r, r.nonce(), &asn, Tick(1)),
        Err(VerifyError::WrongAuthorityEpoch)
    );
    let p = VerifierPolicy {
        installation: InstallationId(2),
        ..policy()
    };
    assert_eq!(
        verify_assertion(&e, &p, &r, r.nonce(), &asn, Tick(1)),
        Err(VerifyError::WrongInstallation)
    );
    let other_op = Enrollment::new(
        OperatorId(9),
        RP,
        e.credential_id().to_vec(),
        e.public_key().clone(),
    )
    .unwrap();
    assert_eq!(
        verify(&other_op, &r, &asn),
        Err(VerifyError::OperatorMismatch)
    );
}

#[test]
fn malformed_authenticator_data_and_signature_reject() {
    let (mut a, e) = setup(CoseAlgorithm::Es256);
    let r = req(base_fields());
    let asn = sign(&mut a, &e, &r);
    let mut t = asn.clone();
    t.authenticator_data.truncate(36);
    assert_eq!(
        verify(&e, &r, &t),
        Err(VerifyError::MalformedAuthenticatorData)
    );
    let mut t = asn.clone();
    t.authenticator_data[32] |= FLAG_AT;
    assert_eq!(
        verify(&e, &r, &t),
        Err(VerifyError::UnexpectedAttestedCredentialData)
    );
    let mut t = asn.clone();
    t.authenticator_data[32] |= FLAG_ED;
    assert_eq!(
        verify(&e, &r, &t),
        Err(VerifyError::MalformedAuthenticatorData)
    );
    let mut t = asn.clone();
    t.authenticator_data.push(0xa0);
    assert_eq!(
        verify(&e, &r, &t),
        Err(VerifyError::MalformedAuthenticatorData)
    );
    let mut t = asn.clone();
    t.signature = vec![0x30, 0x00];
    assert_eq!(verify(&e, &r, &t), Err(VerifyError::MalformedSignature));
    let mut t = asn.clone();
    let n = t.signature.len();
    t.signature[n - 1] ^= 1;
    assert!(verify(&e, &r, &t).is_err());
    let mut t = asn.clone();
    t.authenticator_data[36] ^= 1; // sign counter is signed too
    assert_eq!(verify(&e, &r, &t), Err(VerifyError::BadSignature));
    assert_eq!(
        rp_id_hash(RP).to_vec(),
        asn.authenticator_data[..32].to_vec()
    );
}

// ----------------------------------------------------------------- encoding

#[test]
fn encoding_layout_and_roundtrip() {
    for f in [
        base_fields(),
        GrantRequestFields {
            scope: Scope::Https {
                endpoint: EndpointId(u128::MAX),
                methods: MethodSet::new(MethodSet::ALL).unwrap(),
                max_body_bytes: u64::MAX,
            },
            budget: Budget {
                amount: BudgetAmount::Unlimited,
                unit: BudgetUnit::Bytes,
            },
            depth: Depth::Unlimited,
            ..base_fields()
        },
    ] {
        let r = req(f);
        let b = r.encode();
        assert_eq!(&b[..6], b"TSGR\x00\x01");
        assert_eq!(GrantRequest::decode(&b).unwrap(), r);
        assert!(b.len() <= MAX_ENCODED_REQUEST_LEN);
    }
    // Exact length of the File variant: 6 + 11*3 + (2+16+8+16+24+18+10+5+8+32+8).
    assert_eq!(req(base_fields()).encode().len(), 6 + 33 + 147);
}

#[test]
fn non_canonical_encodings_rejected() {
    let good = req(base_fields()).encode();
    let off = |tag: u8| -> usize {
        // offset of the TLV header for `tag`
        let mut i = 6;
        loop {
            if good[i] == tag {
                return i;
            }
            i += 3 + usize::from(u16::from_be_bytes([good[i + 1], good[i + 2]]));
        }
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("trailing", [good.clone(), vec![0]].concat()),
        ("magic", {
            let mut b = good.clone();
            b[0] = b'X';
            b
        }),
        ("format version", {
            let mut b = good.clone();
            b[5] = 2;
            b
        }),
        ("protocol version", {
            let mut b = good.clone();
            b[off(1) + 4] = 2;
            b
        }),
        ("tag order", {
            let mut b = good.clone();
            b[off(2)] = 3;
            b
        }),
        ("length too long", {
            let mut b = good.clone();
            b[off(1) + 2] = 3;
            b
        }),
        ("length too short", {
            // protocol version encoded in 1 byte with adjusted length
            let mut b = good[..off(1)].to_vec();
            b.extend_from_slice(&[1, 0, 1, 1]);
            b.extend_from_slice(&good[off(2)..]);
            b
        }),
        ("unlimited budget nonzero amount", {
            let mut b = good.clone();
            let o = off(7) + 3;
            b[o] = 1;
            b[o + 8] = 1;
            b
        }),
        ("zero budget", {
            let mut b = good.clone();
            let o = off(7) + 3;
            b[o + 8] = 0;
            b
        }),
        ("budget kind", {
            let mut b = good.clone();
            b[off(7) + 3] = 2;
            b
        }),
        ("budget unit", {
            let mut b = good.clone();
            b[off(7) + 3 + 9] = 9;
            b
        }),
        ("depth kind", {
            let mut b = good.clone();
            b[off(8) + 3] = 7;
            b
        }),
        ("unlimited depth nonzero", {
            let mut b = good.clone();
            let o = off(8) + 3;
            b[o] = 1;
            b
        }),
        ("unknown rights bit", {
            let mut b = good.clone();
            b[off(6) + 3 + 17] |= 0x80;
            b
        }),
        ("empty rights", {
            let mut b = good.clone();
            b[off(6) + 3 + 17] = 0;
            b
        }),
        ("scope kind", {
            let mut b = good.clone();
            b[off(6) + 3] = 3;
            b
        }),
        ("scope kind https with file length", {
            let mut b = good.clone();
            b[off(6) + 3] = 2;
            b
        }),
        ("zero nonce", {
            let mut b = good.clone();
            let o = off(10) + 3;
            b[o..o + 32].fill(0);
            b
        }),
        ("too large", vec![0u8; MAX_ENCODED_REQUEST_LEN + 1]),
        ("empty", vec![]),
    ];
    for (name, b) in cases {
        assert!(GrantRequest::decode(&b).is_err(), "{name} accepted");
    }
    for n in 0..good.len() {
        assert!(GrantRequest::decode(&good[..n]).is_err(), "prefix {n}");
    }
}

#[test]
fn digest_is_domain_separated() {
    let r = req(base_fields());
    let enc = r.encode();
    let d = r.digest().0;
    let plain: [u8; 32] = Sha256::digest(&enc).into();
    assert_ne!(d, plain);
    let mut h = Sha256::new();
    h.update(GRANT_APPROVAL_DOMAIN);
    h.update(&enc);
    assert_eq!(d, <[u8; 32]>::from(h.finalize()));
    let mut h = Sha256::new();
    h.update(APPROVAL_EVIDENCE_DOMAIN);
    h.update(&enc);
    assert_ne!(d, <[u8; 32]>::from(h.finalize()));
    assert_eq!(GRANT_APPROVAL_DOMAIN, b"tessera/v1/grant-approval\0");
    assert!(!GRANT_APPROVAL_DOMAIN.starts_with(APPROVAL_EVIDENCE_DOMAIN));
    assert!(!APPROVAL_EVIDENCE_DOMAIN.starts_with(GRANT_APPROVAL_DOMAIN));
}

// ------------------------------------------------------------- enrollment

#[test]
fn enrollment_storage_roundtrip_and_rejection() {
    for alg in [CoseAlgorithm::Es256, CoseAlgorithm::EdDsa] {
        let (_, e) = setup(alg);
        assert_eq!(e.algorithm(), alg);
        let b = e.encode();
        assert_eq!(Enrollment::decode(&b).unwrap(), e);
        assert!(Enrollment::decode(&[b.clone(), vec![0]].concat()).is_err());
        for n in 0..b.len() {
            assert!(Enrollment::decode(&b[..n]).is_err());
        }
        // COSE_Key roundtrip.
        let cose = e.public_key().to_cose_key();
        assert_eq!(
            &CosePublicKey::from_cose_key(&cose).unwrap(),
            e.public_key()
        );
    }
    // Off-curve P-256 point.
    assert_eq!(
        CosePublicKey::es256_from_xy(&[1; 32], &[2; 32]),
        Err(KeyError::InvalidPoint)
    );
    // Corrupt the stored ES256 key's y coordinate.
    let (_, e) = setup(CoseAlgorithm::Es256);
    let mut b = e.encode();
    let n = b.len();
    b[n - 1] ^= 1;
    assert!(Enrollment::decode(&b).is_err());
    // COSE duplicate label / trailing bytes.
    let cose = e.public_key().to_cose_key();
    let mut dup = cose.clone();
    dup[0] = 0xa6;
    dup.extend_from_slice(&[0x01, 0x02]);
    assert!(CosePublicKey::from_cose_key(&dup).is_err());
    assert!(CosePublicKey::from_cose_key(&[cose, vec![0]].concat()).is_err());
    assert!(Enrollment::new(OP, "", vec![1], e.public_key().clone()).is_err());
    assert!(Enrollment::new(OP, RP, vec![], e.public_key().clone()).is_err());
    assert!(Enrollment::new(OP, "has space", vec![1], e.public_key().clone()).is_err());
}

#[test]
fn es256_pem_parsing() {
    use p256::pkcs8::EncodePublicKey;
    let (_, e) = setup(CoseAlgorithm::Es256);
    let CosePublicKey::Es256(vk) = e.public_key() else {
        unreachable!()
    };
    let pem = vk.to_public_key_pem(p256::pkcs8::LineEnding::LF).unwrap();
    assert_eq!(
        &CosePublicKey::from_pem(CoseAlgorithm::Es256, &pem).unwrap(),
        e.public_key()
    );
    assert!(CosePublicKey::from_pem(CoseAlgorithm::EdDsa, &pem).is_err());
}

// ---------------------------------------------------------------- narrowing

fn narrowed(m: impl FnOnce(&mut GrantRequestFields)) -> GrantRequest {
    let mut f = base_fields();
    m(&mut f);
    req(f)
}

#[test]
fn narrowing_accepts_subsets() {
    let o = req(base_fields());
    let ok = [
        narrowed(|_| {}),
        narrowed(|f| {
            f.scope = Scope::File {
                object: ObjectId(0x5150),
                rights: FileRights::new(FileRights::READ).unwrap(),
            }
        }),
        narrowed(|f| f.budget.amount = BudgetAmount::Finite(1)),
        narrowed(|f| f.depth = Depth::Finite(0)),
        narrowed(|f| f.grant_expires_at = Tick(500)),
        narrowed(|f| f.request_expires_at = Tick(200)),
    ];
    for n in ok {
        n.check_narrowing_of(&o).unwrap();
    }
    let unl = narrowed(|f| {
        f.budget.amount = BudgetAmount::Unlimited;
        f.depth = Depth::Unlimited;
    });
    narrowed(|f| f.budget.amount = BudgetAmount::Finite(u64::MAX))
        .check_narrowing_of(&unl)
        .unwrap();
    narrowed(|f| f.depth = Depth::Finite(u32::MAX))
        .check_narrowing_of(&unl)
        .unwrap();
    assert_eq!(
        unl.check_narrowing_of(&o),
        Err(NarrowingError::BudgetExpanded)
    );
    narrowed(|f| {
        f.budget.amount = BudgetAmount::Unlimited;
        f.depth = Depth::Finite(9)
    })
    .check_narrowing_of(&unl)
    .unwrap();
    let https = |m: u16, s: u64| {
        narrowed(|f| {
            f.scope = Scope::Https {
                endpoint: EndpointId(1),
                methods: MethodSet::new(m).unwrap(),
                max_body_bytes: s,
            }
        })
    };
    https(MethodSet::GET, 10)
        .check_narrowing_of(&https(MethodSet::GET | MethodSet::POST, 100))
        .unwrap();
}

#[test]
fn narrowing_rejects_expansion() {
    use NarrowingError::*;
    let o = req(base_fields());
    let bad: Vec<(GrantRequest, NarrowingError)> = vec![
        (
            narrowed(|f| {
                f.scope = Scope::File {
                    object: ObjectId(0x5150),
                    rights: FileRights::new(FileRights::ALL).unwrap(),
                }
            }),
            ScopeExpanded,
        ),
        (
            narrowed(|f| {
                f.scope = Scope::File {
                    object: ObjectId(1),
                    rights: FileRights::new(FileRights::READ).unwrap(),
                }
            }),
            ScopeExpanded,
        ),
        (
            narrowed(|f| {
                f.scope = Scope::Https {
                    endpoint: EndpointId(0x5150),
                    methods: MethodSet::new(MethodSet::GET).unwrap(),
                    max_body_bytes: 0,
                }
            }),
            ScopeExpanded,
        ),
        (
            narrowed(|f| f.budget.amount = BudgetAmount::Finite(4)),
            BudgetExpanded,
        ),
        (
            narrowed(|f| f.budget.amount = BudgetAmount::Unlimited),
            BudgetExpanded,
        ),
        (
            narrowed(|f| {
                f.budget.unit = BudgetUnit::Bytes;
                f.budget.amount = BudgetAmount::Finite(1)
            }),
            BudgetExpanded,
        ),
        (narrowed(|f| f.depth = Depth::Finite(3)), DepthExpanded),
        (narrowed(|f| f.depth = Depth::Unlimited), DepthExpanded),
        (
            narrowed(|f| f.grant_expires_at = Tick(10_001)),
            GrantExpiryExtended,
        ),
        (
            narrowed(|f| f.request_expires_at = Tick(1_001)),
            RequestExpiryExtended,
        ),
        (narrowed(|f| f.recipient.serial = 43), BindingFieldChanged),
        (narrowed(|f| f.nonce = Nonce([1; 32])), BindingFieldChanged),
        (
            narrowed(|f| f.operator = OperatorId(1)),
            BindingFieldChanged,
        ),
        (
            narrowed(|f| f.authority_epoch = AuthorityEpoch(6)),
            BindingFieldChanged,
        ),
        (
            narrowed(|f| f.installation = InstallationId(1)),
            BindingFieldChanged,
        ),
    ];
    for (n, want) in bad {
        assert_eq!(n.check_narrowing_of(&o), Err(want));
    }
    let https = |m: u16, s: u64| {
        narrowed(|f| {
            f.scope = Scope::Https {
                endpoint: EndpointId(1),
                methods: MethodSet::new(m).unwrap(),
                max_body_bytes: s,
            }
        })
    };
    let base = https(MethodSet::GET, 100);
    assert_eq!(
        https(MethodSet::GET, 101).check_narrowing_of(&base),
        Err(ScopeExpanded)
    );
    assert_eq!(
        https(MethodSet::GET | MethodSet::PUT, 1).check_narrowing_of(&base),
        Err(ScopeExpanded)
    );
}

// ------------------------------------------------------------------ session

fn config() -> SessionConfig {
    SessionConfig {
        approval_timeout: 60,
        rate_window: 100,
        max_requests_per_window: 3,
    }
}

fn session(alg: CoseAlgorithm) -> (SoftwareAuthenticator, ApprovalSession) {
    let (a, e) = setup(alg);
    (a, ApprovalSession::new(e, policy(), config()))
}

#[test]
fn session_happy_path_and_reuse() {
    let (mut a, mut s) = session(CoseAlgorithm::Es256);
    let r = req(base_fields());
    s.begin(r.clone(), Tick(10)).unwrap();
    let ar = s.assertion_request(Tick(11)).unwrap();
    assert_eq!(ar.client_data_hash, r.digest().0);
    let asn = a.get_assertion(&ar).unwrap();
    let v = s.complete(&asn, Tick(12)).unwrap();
    assert_eq!(v.request(), &r);
    // Same assertion again: nothing outstanding.
    assert!(matches!(
        s.complete(&asn, Tick(13)),
        Err(SessionError::NoPendingRequest)
    ));
    // Same nonce again: refused.
    assert!(matches!(
        s.begin(r.clone(), Tick(14)),
        Err(SessionError::NonceReused)
    ));
    // Fresh challenge: the old assertion does not satisfy it.
    s.begin(req(fresh_nonce_fields()), Tick(15)).unwrap();
    assert!(matches!(
        s.complete(&asn, Tick(16)),
        Err(SessionError::Rejected(VerifyError::BadSignature))
    ));
    assert!(
        s.pending().is_none(),
        "failure must discard the pending request"
    );
}

#[test]
fn session_one_outstanding_deny_and_timeout() {
    let (mut a, mut s) = session(CoseAlgorithm::Es256);
    s.begin(req(fresh_nonce_fields()), Tick(0)).unwrap();
    assert!(matches!(
        s.begin(req(fresh_nonce_fields()), Tick(1)),
        Err(SessionError::Busy)
    ));
    let ar = s.assertion_request(Tick(1)).unwrap();
    assert!(matches!(s.deny(Tick(2)), Ok(Closed::Denied(_))));
    let asn = a.get_assertion(&ar).unwrap();
    assert!(matches!(
        s.complete(&asn, Tick(3)),
        Err(SessionError::NoPendingRequest)
    ));

    // Timeout via poll.
    let r = req(fresh_nonce_fields());
    s.begin(r.clone(), Tick(10)).unwrap();
    assert_eq!(s.pending().unwrap().deadline(), Tick(70));
    assert_eq!(s.poll(Tick(69)), None);
    assert_eq!(s.poll(Tick(70)), Some(Closed::TimedOut(r)));

    // Timeout during a slow touch.
    s.begin(req(fresh_nonce_fields()), Tick(20)).unwrap();
    let res = s.touch(&mut a, Tick(21), || Tick(81));
    assert!(matches!(res, Err(SessionError::TimedOut)));
    assert!(s.pending().is_none());
}

#[test]
fn session_deadline_capped_by_request_expiry_and_context_checked() {
    let (_, mut s) = session(CoseAlgorithm::Es256);
    let r = req(GrantRequestFields {
        request_expires_at: Tick(30),
        ..fresh_nonce_fields()
    });
    s.begin(r, Tick(0)).unwrap();
    assert_eq!(s.pending().unwrap().deadline(), Tick(30));
    s.deny(Tick(1)).unwrap();
    let bad = req(GrantRequestFields {
        authority_epoch: AuthorityEpoch(99),
        ..fresh_nonce_fields()
    });
    assert!(matches!(
        s.begin(bad, Tick(2)),
        Err(SessionError::InvalidRequest(
            VerifyError::WrongAuthorityEpoch
        ))
    ));
    let expired = req(fresh_nonce_fields());
    assert!(matches!(
        s.begin(expired, Tick(5_000)),
        Err(SessionError::InvalidRequest(VerifyError::RequestExpired))
    ));
}

#[test]
fn session_rate_limit() {
    let (_, mut s) = session(CoseAlgorithm::Es256);
    for t in 0..3 {
        s.begin(req(fresh_nonce_fields()), Tick(t)).unwrap();
        s.deny(Tick(t)).unwrap();
    }
    assert!(matches!(
        s.begin(req(fresh_nonce_fields()), Tick(50)),
        Err(SessionError::RateLimited)
    ));
    s.begin(req(fresh_nonce_fields()), Tick(101)).unwrap();
}

#[test]
fn session_narrowing_binds_signature_to_narrowed_request() {
    let (mut a, mut s) = session(CoseAlgorithm::Es256);
    let f = fresh_nonce_fields();
    let original = req(f.clone());
    s.begin(original.clone(), Tick(0)).unwrap();
    // A signature obtained for the original is useless after narrowing.
    let ar_orig = s.assertion_request(Tick(0)).unwrap();
    let asn_orig = a.get_assertion(&ar_orig).unwrap();
    let narrow = req(GrantRequestFields {
        scope: Scope::File {
            object: ObjectId(0x5150),
            rights: FileRights::new(FileRights::READ).unwrap(),
        },
        budget: Budget {
            amount: BudgetAmount::Finite(1),
            unit: BudgetUnit::Operations,
        },
        depth: Depth::Finite(0),
        ..f.clone()
    });
    s.narrow(narrow.clone(), Tick(1)).unwrap();
    assert!(s.pending().unwrap().is_narrowed());
    // Cannot re-expand back to the original.
    assert!(matches!(
        s.narrow(original.clone(), Tick(2)),
        Err(SessionError::Narrowing(_))
    ));
    // Cannot expand beyond.
    let wider = req(GrantRequestFields {
        depth: Depth::Unlimited,
        ..narrow.fields().clone()
    });
    assert!(matches!(
        s.narrow(wider, Tick(2)),
        Err(SessionError::Narrowing(NarrowingError::DepthExpanded))
    ));
    assert!(matches!(
        s.complete(&asn_orig, Tick(3)),
        Err(SessionError::Rejected(VerifyError::BadSignature))
    ));

    // Now the proper flow.
    let f2 = fresh_nonce_fields();
    s.begin(req(f2.clone()), Tick(4)).unwrap();
    let narrow2 = req(GrantRequestFields {
        grant_expires_at: Tick(900),
        ..f2
    });
    s.narrow(narrow2.clone(), Tick(5)).unwrap();
    let v = s.touch(&mut a, Tick(6), || Tick(7)).unwrap();
    assert_eq!(v.request(), &narrow2);
}

#[test]
fn session_device_failure_discards_pending() {
    let (_, mut s) = session(CoseAlgorithm::Es256);
    let mut stranger = SoftwareAuthenticator::new();
    s.begin(req(fresh_nonce_fields()), Tick(0)).unwrap();
    assert!(matches!(
        s.touch(&mut stranger, Tick(1), || Tick(2)),
        Err(SessionError::Device(AuthenticatorError::NoCredential))
    ));
    assert!(s.pending().is_none());
}

// ---------------------------------------------------------------- rendering

#[test]
fn rendering_shows_normalized_fields_and_consequences() {
    let r = req(base_fields());
    let ctx = RenderContext {
        now: Tick(100),
        ticks_per_second: None,
    };
    let evil = "Totally harmless\x1b[2J\x1b[1;1HAPPROVED\r\n\u{202e}gnp.exe\u{0007}\\";
    let out = render_request(&r, Some(evil), &ctx);
    for needle in [
        "file object 00000000000000000000000000005150",
        "read, replace",
        "3 operation attempts",
        "can be delegated up to 2 levels",
        "can OVERWRITE",
        "in 9900 ticks",
        "UNTRUSTED",
        &crate::codec::hex(&r.digest().0),
    ] {
        assert!(out.contains(needle), "missing {needle:?} in\n{out}");
    }
    assert!(!out.contains('\x1b'));
    assert!(!out.contains('\r'));
    assert!(!out.contains('\u{202e}'));
    assert!(!out.contains('\u{0007}'));
    assert!(out.contains("\\u{001b}[2J"));
    assert!(out.contains("\\u{202e}"));
    // The untrusted text appears only inside the labelled block.
    let start = out.find("UNTRUSTED agent-supplied").unwrap();
    assert!(out[..start].find("Totally harmless").is_none());

    let r = req(GrantRequestFields {
        budget: Budget {
            amount: BudgetAmount::Unlimited,
            unit: BudgetUnit::Operations,
        },
        depth: Depth::Finite(0),
        ..base_fields()
    });
    let out = render_request(
        &r,
        None,
        &RenderContext {
            now: Tick(0),
            ticks_per_second: std::num::NonZeroU64::new(1),
        },
    );
    assert!(out.contains("UNLIMITED use"));
    assert!(out.contains("cannot be delegated"));
    assert!(out.contains("in ~2h 46m"));
    assert!(!out.contains("UNTRUSTED"));
    let long = "a".repeat(5000);
    assert!(escape_untrusted(&long).ends_with("[truncated]"));
}

#[test]
fn description_wraps_with_prefixes_and_escapes_unicode_format_characters() {
    let description = format!("{}é\u{061c}\u{2028}\u{2029}\u{e0061}", " ".repeat(130));
    let out = render_request(
        &req(base_fields()),
        Some(&description),
        &RenderContext {
            now: Tick(100),
            ticks_per_second: None,
        },
    );
    let lines = out
        .lines()
        .skip_while(|line| !line.starts_with("--- UNTRUSTED"))
        .skip(1)
        .take_while(|line| !line.starts_with("--- end UNTRUSTED"))
        .collect::<Vec<_>>();
    assert!(lines.len() >= 3);
    assert!(lines.iter().all(|line| line.starts_with("  | ")));
    assert!(lines.iter().any(|line| line.contains("é")));
    for escaped in ["\\u{061c}", "\\u{2028}", "\\u{2029}", "\\u{e0061}"] {
        assert!(out.contains(escaped), "missing {escaped} in {out}");
    }
}

// ---------------------------------------------------------------- proptests

fn arb_fields() -> impl Strategy<Value = GrantRequestFields> {
    let scope = prop_oneof![
        (any::<u128>(), 1u8..=FileRights::ALL).prop_map(|(o, r)| Scope::File {
            object: ObjectId(o),
            rights: FileRights::new(r).unwrap()
        }),
        (any::<u128>(), 1u16..=MethodSet::ALL, any::<u64>()).prop_map(|(e, m, s)| Scope::Https {
            endpoint: EndpointId(e),
            methods: MethodSet::new(m).unwrap(),
            max_body_bytes: s
        }),
    ];
    let amount = prop_oneof![
        (1u64..).prop_map(BudgetAmount::Finite),
        Just(BudgetAmount::Unlimited)
    ];
    let unit = prop_oneof![
        Just(BudgetUnit::Operations),
        Just(BudgetUnit::Bytes),
        Just(BudgetUnit::Requests)
    ];
    let depth = prop_oneof![any::<u32>().prop_map(Depth::Finite), Just(Depth::Unlimited)];
    (
        (
            any::<u128>(),
            any::<u64>(),
            any::<u128>(),
            any::<u128>(),
            any::<u64>(),
        ),
        scope,
        amount,
        unit,
        depth,
        (1u64.., any::<[u8; 32]>(), 1u64..),
    )
        .prop_filter_map(
            "zero nonce",
            |((i, ep, op, re, rs), scope, amount, unit, depth, (ge, n, rq))| {
                (n != [0; 32]).then_some(GrantRequestFields {
                    protocol_version: ProtocolVersion(1),
                    installation: InstallationId(i),
                    authority_epoch: AuthorityEpoch(ep),
                    operator: OperatorId(op),
                    recipient: AgentId {
                        epoch: re,
                        serial: rs,
                    },
                    scope,
                    budget: Budget { amount, unit },
                    depth,
                    grant_expires_at: Tick(ge),
                    nonce: Nonce(n),
                    request_expires_at: Tick(rq),
                })
            },
        )
}

proptest! {
    #[test]
    fn prop_roundtrip(f in arb_fields()) {
        let r = req(f);
        let b = r.encode();
        prop_assert_eq!(GrantRequest::decode(&b).unwrap(), r);
    }

    #[test]
    fn prop_decode_arbitrary_is_canonical(b in proptest::collection::vec(any::<u8>(), 0..300)) {
        if let Ok(r) = GrantRequest::decode(&b) {
            prop_assert_eq!(r.encode(), b);
        }
    }

    #[test]
    fn prop_mutated_encoding_is_canonical(f in arb_fields(), idx in any::<usize>(), val in any::<u8>()) {
        let r = req(f);
        let mut b = r.encode();
        let i = idx % b.len();
        b[i] = val;
        if let Ok(m) = GrantRequest::decode(&b) {
            prop_assert_eq!(m.encode(), b.clone());
            prop_assert_eq!(m == r, b == r.encode());
            prop_assert_eq!(m.digest() == r.digest(), m == r);
        }
    }

    #[test]
    fn prop_distinct_requests_distinct_encodings(a in arb_fields(), b in arb_fields()) {
        let (ra, rb) = (req(a), req(b));
        prop_assert_eq!(ra == rb, ra.encode() == rb.encode());
    }

    #[test]
    fn prop_shrinking_is_narrowing_growing_is_not(
        f in arb_fields(),
        rights_mask in any::<u8>(),
        budget_cut in any::<u64>(),
        depth_cut in any::<u32>(),
        exp_cut in any::<u64>(),
        grow in 0usize..5,
    ) {
        let o = req(f.clone());
        let mut n = f.clone();
        n.scope = match f.scope {
            Scope::File { object, rights } => Scope::File {
                object,
                rights: FileRights::new(rights.bits() & rights_mask).unwrap_or(rights),
            },
            Scope::Https { endpoint, methods, max_body_bytes } => Scope::Https {
                endpoint,
                methods: MethodSet::new(methods.bits() & u16::from(rights_mask)).unwrap_or(methods),
                max_body_bytes: max_body_bytes.saturating_sub(budget_cut),
            },
        };
        if let BudgetAmount::Finite(x) = f.budget.amount {
            n.budget.amount = BudgetAmount::Finite(x.saturating_sub(budget_cut).max(1));
        }
        if let Depth::Finite(x) = f.depth { n.depth = Depth::Finite(x.saturating_sub(depth_cut)); }
        n.grant_expires_at = Tick(f.grant_expires_at.0.saturating_sub(exp_cut).max(1));
        n.request_expires_at = Tick(f.request_expires_at.0.saturating_sub(exp_cut).max(1));
        prop_assert!(req(n.clone()).check_narrowing_of(&o).is_ok());

        // Grow one dimension strictly beyond the original, if possible.
        let mut g = f.clone();
        let grew = match grow {
            0 => match f.scope {
                Scope::File { object, rights } if rights.bits() != FileRights::ALL => {
                    g.scope = Scope::File { object, rights: FileRights::new(FileRights::ALL).unwrap() }; true }
                Scope::Https { endpoint, methods, max_body_bytes } if max_body_bytes < u64::MAX => {
                    g.scope = Scope::Https { endpoint, methods, max_body_bytes: max_body_bytes + 1 }; true }
                _ => false,
            },
            1 => match f.budget.amount {
                BudgetAmount::Finite(_) => { g.budget.amount = BudgetAmount::Unlimited; true }
                BudgetAmount::Unlimited => false,
            },
            2 => match f.depth {
                Depth::Finite(x) if x < u32::MAX => { g.depth = Depth::Finite(x + 1); true }
                _ => false,
            },
            3 => if f.grant_expires_at.0 < u64::MAX { g.grant_expires_at.0 += 1; true } else { false },
            _ => if f.request_expires_at.0 < u64::MAX { g.request_expires_at.0 += 1; true } else { false },
        };
        if grew {
            prop_assert!(req(g).check_narrowing_of(&o).is_err());
        }
    }
}
