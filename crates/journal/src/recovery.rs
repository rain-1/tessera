//! Typed helper records for broker recovery: dispatch reservations and spent
//! approval nonces.
//!
//! The journal itself stores opaque payloads. These helpers define a small,
//! fixed-layout encoding (tagged so that other broker payloads are simply
//! ignored) and a [`RecoveryState`] that folds replayed records into:
//!
//! * the set of spent approval nonces (never cleared across epochs, §11);
//! * the request-id → reservation map used for duplicate-request detection
//!   (§5.2: a repeated request id returns the earlier status and never
//!   dispatches again);
//! * the list of reservations whose outcome is unresolved. These are reported
//!   as [`ReservationStatus::Unknown`]; recovery **never** re-dispatches
//!   them. [`RecoveredState::unknown_resolution_payloads`] yields records the
//!   broker should append so that the `Unknown` verdict is itself durable.
//!
//! Ordering the broker must follow (§5.2, §11): append `Reserved` (durable)
//! before handing the operation to an adapter; append `Dispatched` before the
//! adapter performs the effect; append `Completed`/`Unknown` after. Only
//! release results to the agent after the corresponding append returns.

use std::collections::{HashMap, HashSet};

use crate::format::RecordKind;
use crate::journal::Record;

const TAG: [u8; 4] = *b"TSRV";
const ENC_VERSION: u8 = 1;
const K_RESERVED: u8 = 1;
const K_STATUS: u8 = 2;
const K_NONCE: u8 = 3;

/// Reservation lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReservationStatus {
    /// Budget deducted and reservation durable; not yet handed to an adapter.
    Reserved,
    /// Handed to the adapter; the effect may or may not have happened.
    Dispatched,
    /// Adapter reported an outcome (success or definite failure).
    Completed,
    /// Outcome is unknown (e.g. crash after dispatch). Terminal; never
    /// retried.
    Unknown,
}

impl ReservationStatus {
    fn to_byte(self) -> u8 {
        match self {
            ReservationStatus::Reserved => 1,
            ReservationStatus::Dispatched => 2,
            ReservationStatus::Completed => 3,
            ReservationStatus::Unknown => 4,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            1 => ReservationStatus::Reserved,
            2 => ReservationStatus::Dispatched,
            3 => ReservationStatus::Completed,
            4 => ReservationStatus::Unknown,
            _ => return None,
        })
    }

    /// Whether no further transition is allowed.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            ReservationStatus::Completed | ReservationStatus::Unknown
        )
    }

    fn may_follow(self, prev: ReservationStatus) -> bool {
        use ReservationStatus::*;
        matches!(
            (prev, self),
            (Reserved, Dispatched)
                | (Reserved, Unknown)
                | (Dispatched, Completed)
                | (Dispatched, Unknown)
        )
    }
}

/// Principal-and-epoch-scoped request key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestKey {
    /// Principal epoch.
    pub principal_epoch: u128,
    /// Principal serial.
    pub principal_serial: u64,
    /// Client request id.
    pub request_id: u128,
}

/// A helper record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryEvent {
    /// A reservation was created for `request`, bound to `request_digest`
    /// (e.g. SHA-256 of canonical request bytes).
    Reserved {
        /// Reservation id.
        reservation_id: u128,
        /// Request key.
        request: RequestKey,
        /// Digest binding the request id to its content.
        request_digest: [u8; 32],
    },
    /// Status transition.
    Status {
        /// Reservation id.
        reservation_id: u128,
        /// New status (not `Reserved`).
        status: ReservationStatus,
    },
    /// An approval nonce was redeemed.
    NonceSpent {
        /// Nonce.
        nonce: [u8; 32],
    },
}

impl RecoveryEvent {
    /// Encode as a journal payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(96);
        v.extend_from_slice(&TAG);
        v.push(ENC_VERSION);
        match self {
            RecoveryEvent::Reserved {
                reservation_id,
                request,
                request_digest,
            } => {
                v.push(K_RESERVED);
                v.extend_from_slice(&reservation_id.to_le_bytes());
                v.extend_from_slice(&request.principal_epoch.to_le_bytes());
                v.extend_from_slice(&request.principal_serial.to_le_bytes());
                v.extend_from_slice(&request.request_id.to_le_bytes());
                v.extend_from_slice(request_digest);
            }
            RecoveryEvent::Status {
                reservation_id,
                status,
            } => {
                v.push(K_STATUS);
                v.extend_from_slice(&reservation_id.to_le_bytes());
                v.push(status.to_byte());
            }
            RecoveryEvent::NonceSpent { nonce } => {
                v.push(K_NONCE);
                v.extend_from_slice(nonce);
            }
        }
        v
    }

    /// Decode a payload. `Ok(None)` if the payload is not a helper record
    /// (different tag); `Err` if it carries the tag but is malformed.
    pub fn decode(p: &[u8]) -> Result<Option<Self>, RecoveryError> {
        let Some(rest) = p.strip_prefix(&TAG) else {
            return Ok(None);
        };
        let mut r = Reader(rest);
        if r.u8()? != ENC_VERSION {
            return Err(RecoveryError::Malformed);
        }
        let ev = match r.u8()? {
            K_RESERVED => RecoveryEvent::Reserved {
                reservation_id: r.u128()?,
                request: RequestKey {
                    principal_epoch: r.u128()?,
                    principal_serial: r.u64()?,
                    request_id: r.u128()?,
                },
                request_digest: r.arr32()?,
            },
            K_STATUS => {
                let reservation_id = r.u128()?;
                let status =
                    ReservationStatus::from_byte(r.u8()?).ok_or(RecoveryError::Malformed)?;
                if status == ReservationStatus::Reserved {
                    return Err(RecoveryError::Malformed);
                }
                RecoveryEvent::Status {
                    reservation_id,
                    status,
                }
            }
            K_NONCE => RecoveryEvent::NonceSpent { nonce: r.arr32()? },
            _ => return Err(RecoveryError::Malformed),
        };
        if !r.0.is_empty() {
            return Err(RecoveryError::Malformed);
        }
        Ok(Some(ev))
    }
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], RecoveryError> {
        let (a, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(RecoveryError::Malformed)?;
        self.0 = rest;
        Ok(*a)
    }
    fn u8(&mut self) -> Result<u8, RecoveryError> {
        Ok(self.take::<1>()?[0])
    }
    fn u64(&mut self) -> Result<u64, RecoveryError> {
        Ok(u64::from_le_bytes(self.take()?))
    }
    fn u128(&mut self) -> Result<u128, RecoveryError> {
        Ok(u128::from_le_bytes(self.take()?))
    }
    fn arr32(&mut self) -> Result<[u8; 32], RecoveryError> {
        self.take()
    }
}

/// Recovery fold failure. Fail closed: the broker must not start.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryError {
    /// Tagged payload could not be decoded.
    #[error("malformed recovery record")]
    Malformed,
    /// Reservation id created twice.
    #[error("duplicate reservation id {0}")]
    DuplicateReservation(u128),
    /// Request key reserved twice (would mean two dispatches for one request).
    #[error("request reserved twice")]
    DuplicateRequest(RequestKey),
    /// Status for an unknown reservation.
    #[error("status for unknown reservation {0}")]
    UnknownReservation(u128),
    /// Illegal status transition.
    #[error("illegal transition {from:?} -> {to:?} for reservation {id}")]
    IllegalTransition {
        /// Reservation.
        id: u128,
        /// Previous status.
        from: ReservationStatus,
        /// Attempted status.
        to: ReservationStatus,
    },
    /// Nonce recorded as spent twice.
    #[error("nonce spent twice")]
    NonceReused,
}

/// Reservation details after replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReservationInfo {
    /// Request key.
    pub request: RequestKey,
    /// Request digest.
    pub request_digest: [u8; 32],
    /// Last status recorded in the log.
    pub recorded_status: ReservationStatus,
    /// Epoch in which the reservation was created.
    pub epoch: u64,
}

impl ReservationInfo {
    /// Status to report: anything not terminal is `Unknown` after a restart.
    pub fn reported_status(&self) -> ReservationStatus {
        if self.recorded_status.is_terminal() {
            self.recorded_status
        } else {
            ReservationStatus::Unknown
        }
    }
}

/// Incremental fold over replayed records.
#[derive(Debug, Default)]
pub struct RecoveryState {
    reservations: HashMap<u128, ReservationInfo>,
    by_request: HashMap<RequestKey, u128>,
    nonces: HashSet<[u8; 32]>,
}

impl RecoveryState {
    /// Empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one record. Non-helper payloads and epoch bumps are ignored.
    pub fn observe(&mut self, rec: &Record) -> Result<(), RecoveryError> {
        if rec.kind != RecordKind::Data {
            return Ok(());
        }
        let Some(ev) = RecoveryEvent::decode(&rec.payload)? else {
            return Ok(());
        };
        self.apply(ev, rec.epoch)
    }

    /// Apply an event (also usable by the live broker to keep the same state
    /// it would rebuild on recovery).
    pub fn apply(&mut self, ev: RecoveryEvent, epoch: u64) -> Result<(), RecoveryError> {
        match ev {
            RecoveryEvent::Reserved {
                reservation_id,
                request,
                request_digest,
            } => {
                if self.reservations.contains_key(&reservation_id) {
                    return Err(RecoveryError::DuplicateReservation(reservation_id));
                }
                if self.by_request.contains_key(&request) {
                    return Err(RecoveryError::DuplicateRequest(request));
                }
                self.reservations.insert(
                    reservation_id,
                    ReservationInfo {
                        request,
                        request_digest,
                        recorded_status: ReservationStatus::Reserved,
                        epoch,
                    },
                );
                self.by_request.insert(request, reservation_id);
            }
            RecoveryEvent::Status {
                reservation_id,
                status,
            } => {
                let info = self
                    .reservations
                    .get_mut(&reservation_id)
                    .ok_or(RecoveryError::UnknownReservation(reservation_id))?;
                if !status.may_follow(info.recorded_status) {
                    return Err(RecoveryError::IllegalTransition {
                        id: reservation_id,
                        from: info.recorded_status,
                        to: status,
                    });
                }
                info.recorded_status = status;
            }
            RecoveryEvent::NonceSpent { nonce } => {
                if !self.nonces.insert(nonce) {
                    return Err(RecoveryError::NonceReused);
                }
            }
        }
        Ok(())
    }

    /// Finish the fold.
    pub fn finish(self) -> RecoveredState {
        let mut unresolved: Vec<u128> = self
            .reservations
            .iter()
            .filter(|(_, i)| !i.recorded_status.is_terminal())
            .map(|(id, _)| *id)
            .collect();
        unresolved.sort_unstable();
        RecoveredState {
            reservations: self.reservations,
            by_request: self.by_request,
            nonces: self.nonces,
            unresolved,
        }
    }
}

/// Result of recovery replay.
#[derive(Debug)]
pub struct RecoveredState {
    reservations: HashMap<u128, ReservationInfo>,
    by_request: HashMap<RequestKey, u128>,
    nonces: HashSet<[u8; 32]>,
    unresolved: Vec<u128>,
}

impl RecoveredState {
    /// Whether `nonce` was already redeemed.
    pub fn nonce_spent(&self, nonce: &[u8; 32]) -> bool {
        self.nonces.contains(nonce)
    }

    /// All spent nonces.
    pub fn spent_nonces(&self) -> &HashSet<[u8; 32]> {
        &self.nonces
    }

    /// Look up a prior reservation for a request key.
    pub fn lookup_request(&self, key: &RequestKey) -> Option<(u128, &ReservationInfo)> {
        let id = self.by_request.get(key)?;
        self.reservations.get(id).map(|i| (*id, i))
    }

    /// Reservation by id.
    pub fn reservation(&self, id: u128) -> Option<&ReservationInfo> {
        self.reservations.get(&id)
    }

    /// Number of reservations.
    pub fn reservation_count(&self) -> usize {
        self.reservations.len()
    }

    /// Reservations whose outcome was not recorded; all reported as
    /// `Unknown`. Sorted by id. These are never re-dispatched.
    pub fn unresolved(&self) -> &[u128] {
        &self.unresolved
    }

    /// Payloads marking every unresolved reservation `Unknown`, to append
    /// (durably) before accepting new work.
    pub fn unknown_resolution_payloads(&self) -> Vec<Vec<u8>> {
        self.unresolved
            .iter()
            .map(|&reservation_id| {
                RecoveryEvent::Status {
                    reservation_id,
                    status: ReservationStatus::Unknown,
                }
                .encode()
            })
            .collect()
    }
}

/// Convenience: replay a whole journal into a [`RecoveredState`].
pub fn recover<S: crate::storage::Storage>(
    journal: &mut crate::journal::Journal<S>,
) -> Result<RecoveredState, RecoverError> {
    let mut st = RecoveryState::new();
    for r in journal.replay() {
        st.observe(&r?)?;
    }
    Ok(st.finish())
}

/// Error from [`recover`].
#[derive(Debug, thiserror::Error)]
pub enum RecoverError {
    /// Journal read/verification failure.
    #[error(transparent)]
    Journal(#[from] crate::journal::JournalError),
    /// Helper-record inconsistency.
    #[error(transparent)]
    Recovery(#[from] RecoveryError),
}
