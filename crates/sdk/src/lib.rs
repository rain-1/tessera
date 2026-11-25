//! # tessera-sdk — untrusted client for the Tessera broker
//!
//! This crate is the agent side of the Tessera capability protocol
//! ([`tessera_protocol`]). It runs inside an untrusted sandbox and is itself
//! **untrusted**: nothing it does can grant authority. It only *asks*. The
//! broker authenticates the caller from the channel the launcher bound to
//! the sandbox and decides everything else.
//!
//! * The SDK never sends an identity claim. The protocol has no field for
//!   the caller's identity. `TESSERA_AGENT_ID` in the environment is an
//!   informational label and the SDK never reads it.
//! * Capability ids are references, not secrets. Holding an id authorizes
//!   nothing unless the broker's ledger says the authenticated caller owns
//!   that capability.
//! * Every request id is random by default. Retrying with the **same** id
//!   never causes a second effect (see [`Client`], "Idempotency").
//!
//! ```no_run
//! use tessera_sdk::{Client, Terms, HttpsRequest};
//! use tessera_sdk::wire::{WireScope, WireMethodSet};
//!
//! let client = Client::from_env()?;
//! let scope = WireScope::Https {
//!     endpoint_id: 7,
//!     methods: WireMethodSet { get: true, ..Default::default() },
//!     max_body_bytes: 0,
//! };
//! let cap = client.request_grant(Terms::new(scope, 10).depth(1), Some("search API"))?;
//! let resp = client.https_request(cap, HttpsRequest::get("/search?q=tessera"))?;
//! println!("status {}", resp.status);
//! # Ok::<(), tessera_sdk::Error>(())
//! ```
//!
//! See `docs/sdk.md` for the usage guide.

mod client;
mod env_fd;
mod error;
mod transport;
mod types;

pub use client::{AGENT_LABEL_ENV, BROKER_FD_ENV, Client, ClientConfig, new_request_id};
pub use error::{BrokerError, Error, Result};
pub use transport::TransportKind;
pub use types::{
    AgentId, CapabilityView, Consumed, FileSnapshot, HttpsRequest, HttpsResponse, Terms, format_id,
    parse_id,
};

/// The wire types, re-exported for building scopes and reading results.
pub mod wire {
    pub use tessera_protocol::wire::*;
    pub use tessera_protocol::{FrameLimits, PROTOCOL_VERSION};
}
pub use tessera_protocol::{CapId, ErrorCode, LaunchProfileId, RequestId, ReservationId};
