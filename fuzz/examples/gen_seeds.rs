//! Writes structurally valid seed inputs into `fuzz/seeds/<target>/` so the
//! fuzzer starts past magic numbers, TLV framing and hash chains.
//!
//!     cd fuzz && cargo +nightly run --example gen_seeds
use std::path::Path;

use tessera_approval as ap;
use tessera_capability_core as core;
use tessera_journal::testing::MemStorage;
use tessera_journal::{Journal, JournalOptions, RecoveryEvent, RequestKey, ReservationStatus};

fn write(target: &str, name: &str, bytes: &[u8]) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("seeds")
        .join(target);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(name), bytes).unwrap();
}

fn grant_request(budget: ap::BudgetAmount, depth: ap::Depth) -> ap::GrantRequest {
    ap::GrantRequest::new(ap::GrantRequestFields {
        protocol_version: ap::ProtocolVersion(1),
        installation: ap::InstallationId(7),
        authority_epoch: ap::AuthorityEpoch(1),
        operator: ap::OperatorId(42),
        recipient: ap::AgentId {
            epoch: 1,
            serial: 3,
        },
        scope: ap::Scope::File {
            object: ap::ObjectId(5),
            rights: ap::FileRights::new(ap::FileRights::READ).unwrap(),
        },
        budget: ap::Budget {
            amount: budget,
            unit: ap::BudgetUnit::Operations,
        },
        depth,
        grant_expires_at: ap::Tick(1_000_000),
        nonce: ap::Nonce([0xa5; 32]),
        request_expires_at: ap::Tick(60_000),
    })
    .unwrap()
}

fn main() {
    // Grant requests.
    let r = grant_request(ap::BudgetAmount::Finite(3), ap::Depth::Finite(1));
    write("approval_grant_request", "finite", &r.encode());
    let r = grant_request(ap::BudgetAmount::Unlimited, ap::Depth::Unlimited);
    write("approval_grant_request", "unlimited", &r.encode());

    // Enrollment: Ed25519 base point (a valid, non-weak public key).
    let mut base = [0x66u8; 32];
    base[0] = 0x58;
    let key = ap::CosePublicKey::eddsa_from_bytes(&base).unwrap();
    let e =
        ap::Enrollment::new(ap::OperatorId(42), "tessera.local", vec![1, 2, 3, 4], key).unwrap();
    write("approval_enrollment", "eddsa", &e.encode());

    // Journal with recovery events, an epoch bump and an opaque record.
    let storage = MemStorage::new();
    let mut j = Journal::open_storage(storage.clone(), JournalOptions::default()).unwrap();
    let req = RequestKey {
        principal_epoch: 1,
        principal_serial: 2,
        request_id: 3,
    };
    j.append(
        &RecoveryEvent::Reserved {
            reservation_id: 9,
            request: req,
            request_digest: [7; 32],
        }
        .encode(),
    )
    .unwrap();
    j.append(
        &RecoveryEvent::Status {
            reservation_id: 9,
            status: ReservationStatus::Dispatched,
        }
        .encode(),
    )
    .unwrap();
    j.append(&RecoveryEvent::NonceSpent { nonce: [1; 32] }.encode())
        .unwrap();
    j.begin_new_epoch().unwrap();
    j.append(b"opaque broker payload").unwrap();
    write("journal_recover", "events", &storage.durable());

    // Core: create two principals, baseline, consume, delegate, revoke.
    use core::{AdminCommand as A, AgentCommand as G, AuthenticatedCommand as C};
    let a = core::AgentId::new(0, 0);
    let b = core::AgentId::new(0, 1);
    let file = core::Scope::File {
        object: core::ObjectId::from_raw(1),
        rights: core::FileRights::READ,
    };
    let terms = |n, d| core::Terms {
        scope: file,
        budget: core::Budget::Finite(n),
        depth: core::Depth::Finite(d),
        expiry: core::Expiry::Never,
    };
    let cap0 = core::CapabilityId::from_raw(0);
    let cmds: Vec<(C, u64)> = vec![
        (C::operator(A::CreatePrincipal), 0),
        (C::operator(A::CreatePrincipal), 0),
        (
            C::operator(A::InstallBaseline {
                recipient: a,
                terms: terms(5, 2),
            }),
            1,
        ),
        (
            C::agent(
                a,
                G::Consume {
                    request_id: core::RequestId::from_raw(1),
                    capability: cap0,
                    operation: core::Operation::File {
                        object: core::ObjectId::from_raw(1),
                        right: core::FileRight::Read,
                    },
                },
            ),
            1,
        ),
        (
            C::agent(
                a,
                G::Delegate {
                    capability: cap0,
                    recipient: b,
                    terms: terms(2, 1),
                },
            ),
            1,
        ),
        (C::operator(A::Revoke { capability: cap0 }), 1),
        (C::operator(A::BumpEpoch), 1),
    ];
    let mut bytes = vec![31, 7, 0xff];
    for c in &cmds {
        bytes.extend(postcard::to_allocvec(c).unwrap());
    }
    write("core_step", "lifecycle", &bytes);

    // A valid snapshot after the prefix that succeeds.
    let mut s = core::State::new(core::Limits::default());
    for (c, d) in &cmds[..5] {
        let now = core::Tick::from_raw(s.clock().to_raw() + d);
        core::step(&mut s, *c, now).unwrap();
    }
    write(
        "core_state_decode",
        "postcard",
        &postcard::to_allocvec(&s).unwrap(),
    );
    write(
        "core_state_decode",
        "json",
        serde_json::to_string(&s).unwrap().as_bytes(),
    );
}
