//! Typed SDK errors.

use std::io;

use tessera_protocol::{ErrorCode, RequestId, ReservationId, WireReservationStatus};

/// Result alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// A denial or failure reported by the broker (`Response::Error`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code:?}: {detail}")]
pub struct BrokerError {
    /// Typed code (§9.2).
    pub code: ErrorCode,
    /// Diagnostic text from the broker. It is not sensitive and not stable;
    /// do not match on it.
    pub detail: String,
    /// The request id the broker attributes the error to, if any.
    pub request_id: Option<RequestId>,
}

/// Everything that can go wrong in an SDK call.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The broker denied or failed the request.
    #[error("broker error {0}")]
    Broker(BrokerError),

    /// No response arrived before the deadline.
    ///
    /// **The request may still take effect.** If `request_id` is `Some`,
    /// retry with the *same* id (the `*_with_id` methods). The broker then
    /// returns the status of the earlier request rather than performing it
    /// again. A retry with a fresh id is a new request and may spend budget a
    /// second time.
    #[error("timed out waiting for the broker (request id {})", fmt_opt_id(*.request_id))]
    Timeout {
        /// Request id that was sent, if the request carried one.
        request_id: Option<RequestId>,
    },

    /// A grant request was acknowledged by the broker (`GrantPending`: it is
    /// queued for the human operator) but no decision arrived before
    /// [`crate::ClientConfig::approval_timeout`]. The broker is alive. The
    /// request is still pending: repeat it with the *same* request id (the
    /// `*_with_id` method) to keep waiting for the same approval, which
    /// never opens a second prompt.
    #[error("grant request {} is still waiting for the operator", crate::format_id(*.request_id))]
    ApprovalPending {
        /// Request id of the pending grant.
        request_id: RequestId,
    },

    /// A consume retry (same request id) found an earlier reservation. No
    /// new effect was dispatched. Returned by the convenience methods
    /// (`read_file`, `replace_file`, `https_request`) because they cannot
    /// return an operation result for an earlier dispatch; use
    /// [`crate::Client::consume_with_id`] to receive it as a value.
    #[error(
        "request id already used: reservation {reservation_id:#x} is {status:?}; no new effect"
    )]
    PriorReservation {
        /// Request id.
        request_id: RequestId,
        /// Earlier reservation.
        reservation_id: ReservationId,
        /// Its status.
        status: WireReservationStatus,
    },

    /// The broker closed the channel.
    #[error("broker channel closed")]
    Closed,

    /// An earlier failure left the channel unusable. This happens only on a
    /// byte-stream transport after a partial write or an invalid frame
    /// header. Message-oriented (`SOCK_SEQPACKET`) channels do not get into
    /// this state.
    #[error("broker channel is unusable after an earlier transport failure")]
    Poisoned,

    /// A message exceeded the frame limit. If `outbound`, nothing was sent.
    #[error("{} message of {len} bytes exceeds limit {max}", if *.outbound { "outgoing" } else { "incoming" })]
    FrameTooLarge {
        /// Whether the oversized message was ours.
        outbound: bool,
        /// Size.
        len: usize,
        /// Limit.
        max: usize,
    },

    /// The broker sent something that does not follow the protocol: an
    /// undecodable payload, a response for a request we never sent, or a
    /// response of the wrong kind.
    #[error("protocol violation: {0}")]
    Protocol(String),

    /// An argument does not fit the wire format (for example a header that is
    /// too long). Nothing was sent.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Environment / setup problem (for example `TESSERA_BROKER_FD` missing).
    #[error("configuration: {0}")]
    Config(String),

    /// I/O error on the channel.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
}

fn fmt_opt_id(id: Option<RequestId>) -> String {
    match id {
        Some(id) => crate::format_id(id),
        None => "none".into(),
    }
}

impl Error {
    /// The broker's error code, if this is a broker denial.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Error::Broker(b) => Some(b.code),
            _ => None,
        }
    }

    /// The request id this error concerns, if known. Use it to retry
    /// idempotently after [`Error::Timeout`].
    pub fn request_id(&self) -> Option<RequestId> {
        match self {
            Error::Broker(b) => b.request_id,
            Error::Timeout { request_id } => *request_id,
            Error::ApprovalPending { request_id } => Some(*request_id),
            Error::PriorReservation { request_id, .. } => Some(*request_id),
            _ => None,
        }
    }

    /// Whether the outcome is uncertain: the request may or may not have
    /// taken effect. Never re-issue such a request with a fresh id unless
    /// you accept that it may happen twice.
    pub fn outcome_uncertain(&self) -> bool {
        matches!(
            self,
            Error::Timeout { .. }
                | Error::ApprovalPending { .. }
                | Error::Closed
                | Error::Poisoned
                | Error::Io(_)
        ) || self.code() == Some(ErrorCode::EffectUnknown)
    }
}
