//! Reservation / nonce recovery helpers.

use tessera_journal::testing::{CrashMode, MemStorage};
use tessera_journal::*;

fn key(n: u128) -> RequestKey {
    RequestKey {
        principal_epoch: 7,
        principal_serial: 3,
        request_id: n,
    }
}

fn reserved(id: u128, req: u128) -> Vec<u8> {
    RecoveryEvent::Reserved {
        reservation_id: id,
        request: key(req),
        request_digest: [req as u8; 32],
    }
    .encode()
}

fn status(id: u128, s: ReservationStatus) -> Vec<u8> {
    RecoveryEvent::Status {
        reservation_id: id,
        status: s,
    }
    .encode()
}

#[test]
fn encode_decode_roundtrip_and_foreign_payloads() {
    let evs = [
        RecoveryEvent::Reserved {
            reservation_id: u128::MAX,
            request: key(5),
            request_digest: [9; 32],
        },
        RecoveryEvent::Status {
            reservation_id: 1,
            status: ReservationStatus::Dispatched,
        },
        RecoveryEvent::Status {
            reservation_id: 1,
            status: ReservationStatus::Completed,
        },
        RecoveryEvent::Status {
            reservation_id: 1,
            status: ReservationStatus::Unknown,
        },
        RecoveryEvent::NonceSpent { nonce: [4; 32] },
    ];
    for ev in evs {
        assert_eq!(RecoveryEvent::decode(&ev.encode()).unwrap(), Some(ev));
    }
    assert_eq!(
        RecoveryEvent::decode(b"some other broker record").unwrap(),
        None
    );
    let mut bad = evs[0].encode();
    bad.push(0);
    assert_eq!(RecoveryEvent::decode(&bad), Err(RecoveryError::Malformed));
    let mut bad = evs[1].encode();
    *bad.last_mut().unwrap() = 1; // "Reserved" via status record
    assert_eq!(RecoveryEvent::decode(&bad), Err(RecoveryError::Malformed));
    let enc = evs[0].encode();
    for cut in 4..enc.len() {
        assert_eq!(
            RecoveryEvent::decode(&enc[..cut]),
            Err(RecoveryError::Malformed)
        );
    }
}

/// Broker crashes with reservations in various states; restart reports the
/// unresolved ones as Unknown, keeps request-id and nonce sets, bumps the
/// epoch, and makes the Unknown verdict durable. Nothing is re-dispatched:
/// the API offers no way to.
#[test]
fn restart_reports_unresolved_as_unknown() {
    let mem = MemStorage::new();
    let mut j = Journal::open_storage(mem.clone(), JournalOptions::default()).unwrap();
    assert_eq!(j.begin_new_epoch().unwrap(), 1);
    j.append(&RecoveryEvent::NonceSpent { nonce: [1; 32] }.encode())
        .unwrap();
    j.append(b"opaque ledger transition").unwrap();
    // r1: completed.
    j.append(&reserved(1, 100)).unwrap();
    j.append(&status(1, ReservationStatus::Dispatched)).unwrap();
    j.append(&status(1, ReservationStatus::Completed)).unwrap();
    // r2: dispatched, crash before completion.
    j.append(&reserved(2, 101)).unwrap();
    j.append(&status(2, ReservationStatus::Dispatched)).unwrap();
    // r3: reserved only.
    j.append(&reserved(3, 102)).unwrap();
    // r4: in-flight append that never became durable.
    mem.fail_syncs(true);
    assert!(j.append(&reserved(4, 103)).is_err());
    drop(j);

    let mem = mem.crash(CrashMode::LoseUnsynced);
    let mut j = Journal::open_storage(mem.clone(), JournalOptions::default()).unwrap();
    let st = recover(&mut j).unwrap();
    assert_eq!(st.reservation_count(), 3);
    assert_eq!(st.unresolved(), &[2, 3]);
    assert_eq!(
        st.reservation(1).unwrap().reported_status(),
        ReservationStatus::Completed
    );
    assert_eq!(
        st.reservation(2).unwrap().recorded_status,
        ReservationStatus::Dispatched
    );
    assert_eq!(
        st.reservation(2).unwrap().reported_status(),
        ReservationStatus::Unknown
    );
    assert_eq!(
        st.reservation(3).unwrap().reported_status(),
        ReservationStatus::Unknown
    );
    assert_eq!(st.reservation(3).unwrap().epoch, 1);
    // Duplicate request detection survives restart.
    let (id, info) = st.lookup_request(&key(101)).unwrap();
    assert_eq!(id, 2);
    assert_eq!(info.request_digest, [101; 32]);
    assert!(st.lookup_request(&key(103)).is_none());
    assert!(st.nonce_spent(&[1; 32]));
    assert!(!st.nonce_spent(&[2; 32]));

    // Broker restart protocol: new epoch, durable Unknown verdicts.
    assert_eq!(j.begin_new_epoch().unwrap(), 2);
    for p in st.unknown_resolution_payloads() {
        j.append(&p).unwrap();
    }
    drop(j);
    let mut j = Journal::open_storage(
        mem.crash(CrashMode::LoseUnsynced),
        JournalOptions::default(),
    )
    .unwrap();
    assert_eq!(j.current_epoch(), 2);
    let st = recover(&mut j).unwrap();
    assert!(st.unresolved().is_empty());
    assert_eq!(
        st.reservation(2).unwrap().recorded_status,
        ReservationStatus::Unknown
    );
    assert_eq!(
        st.reservation(3).unwrap().recorded_status,
        ReservationStatus::Unknown
    );
}

#[test]
fn inconsistent_histories_fail_closed() {
    let cases: Vec<(Vec<Vec<u8>>, RecoveryError)> = vec![
        (
            vec![reserved(1, 1), reserved(1, 2)],
            RecoveryError::DuplicateReservation(1),
        ),
        (
            vec![reserved(1, 1), reserved(2, 1)],
            RecoveryError::DuplicateRequest(key(1)),
        ),
        (
            vec![status(9, ReservationStatus::Dispatched)],
            RecoveryError::UnknownReservation(9),
        ),
        (
            vec![reserved(1, 1), status(1, ReservationStatus::Completed)],
            RecoveryError::IllegalTransition {
                id: 1,
                from: ReservationStatus::Reserved,
                to: ReservationStatus::Completed,
            },
        ),
        (
            vec![
                reserved(1, 1),
                status(1, ReservationStatus::Dispatched),
                status(1, ReservationStatus::Unknown),
                status(1, ReservationStatus::Completed),
            ],
            RecoveryError::IllegalTransition {
                id: 1,
                from: ReservationStatus::Unknown,
                to: ReservationStatus::Completed,
            },
        ),
        (
            vec![
                RecoveryEvent::NonceSpent { nonce: [3; 32] }.encode(),
                RecoveryEvent::NonceSpent { nonce: [3; 32] }.encode(),
            ],
            RecoveryError::NonceReused,
        ),
    ];
    for (payloads, expected) in cases {
        let mut j = Journal::open_storage(MemStorage::new(), JournalOptions::default()).unwrap();
        for p in &payloads {
            j.append(p).unwrap();
        }
        match recover(&mut j) {
            Err(RecoverError::Recovery(e)) => assert_eq!(e, expected),
            other => panic!("expected {expected:?}, got {other:?}"),
        }
    }
}
