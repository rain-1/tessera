//! Opaque identifier newtypes.
//!
//! Identifiers are *references*, not secrets and not authority: holding or
//! copying an identifier never confers the right to use the capability it
//! names (spec §7, §9.2). They are therefore `Copy`. Authority lives only in
//! the [`crate::State`] ledger, bound to an authenticated owner.

use serde::{Deserialize, Serialize};
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

macro_rules! opaque_id {
    ($(#[$meta:meta])* $name:ident, $raw:ty) => {
        $(#[$meta])*
        #[cfg_attr(verus_keep_ghost, verus_verify(external_derive))]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name($raw);

        #[cfg(verus_keep_ghost)]
        verus! { impl $name { /// The wrapped raw value (spec only).
            pub closed spec fn raw(self) -> $raw { self.0 } } }

        #[cfg_attr(verus_keep_ghost, verus_verify)]
        impl $name {
            /// Wrap a raw value (e.g. decoded from the wire or the journal).
            /// Constructing an id grants nothing.
            #[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r.raw() == raw))]
            pub const fn from_raw(raw: $raw) -> Self {
                Self(raw)
            }

            /// The raw value, for encoding.
            #[cfg_attr(verus_keep_ghost, verus_spec(r => ensures r == self.raw()))]
            pub const fn to_raw(self) -> $raw {
                self.0
            }
        }
    };
}

opaque_id!(
    /// Identity of a capability record. Allocated by the core from a
    /// monotonic counter; never recycled (not even across epochs).
    CapabilityId,
    u128
);
opaque_id!(
    /// Identity of an originating authorization (approved mint or baseline).
    RootId,
    u128
);
opaque_id!(
    /// Stable, adapter-registered protected object (e.g. a file slot).
    ObjectId,
    u64
);
opaque_id!(
    /// Registered HTTPS endpoint.
    EndpointId,
    u64
);
opaque_id!(
    /// Client-chosen request identifier, scoped by the core to the
    /// authenticated principal (and therefore to its epoch).
    RequestId,
    u128
);
opaque_id!(
    /// Identity of a dispatch reservation issued by CONSUME.
    ReservationId,
    u64
);
opaque_id!(
    /// Identity of a finite allocation boundary (a budget pool); see
    /// [`crate::PoolAccount`].
    PoolId,
    u64
);

/// Authenticated sandbox principal. Allocated by the core
/// ([`crate::AdminCommand::CreatePrincipal`]) and scoped to an authority
/// epoch; an id from an older epoch is stale and authorizes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AgentId {
    epoch: u64,
    serial: u64,
}

impl AgentId {
    /// Construct from raw parts (used by the broker to name a principal it
    /// already learned from a `PrincipalCreated` effect).
    pub const fn new(epoch: u64, serial: u64) -> Self {
        Self { epoch, serial }
    }

    /// Authority epoch in which the principal was created.
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Serial number within the installation.
    pub const fn serial(self) -> u64 {
        self.serial
    }
}

/// Fresh, cryptographically random approval nonce (32 bytes), bound into the
/// signed canonical grant payload (spec §8.1). Redeemed at most once, ever.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Nonce([u8; 32]);

impl Nonce {
    /// Wrap raw nonce bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw nonce bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
