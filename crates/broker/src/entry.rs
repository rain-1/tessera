//! Broker journal records.
//!
//! The journal stores opaque payloads; the broker's payload is a tagged,
//! versioned postcard encoding of [`Entry`]. Every state-changing
//! authenticated command is journaled *with the trusted tick it was applied
//! at* before its effect is released; replaying the `Command` entries (with
//! each journal `EpochBump` record mapped to `AdminCommand::BumpEpoch` at
//! tick 0) through `State::replay` rebuilds the ledger exactly.
//!
//! Entries hold identifiers, digests and sizes, never file/HTTP content or
//! secrets (§11).

use serde::{Deserialize, Serialize};
use tessera_capability_core::{
    AgentId, AuthenticatedCommand, CapabilityId, EndpointId, ObjectId, RequestId, ReservationId,
    Tick,
};

const TAG: [u8; 4] = *b"TSBK";
const VERSION: u8 = 1;

/// Request-id binding (§9.2, ADR-0012): `(principal, request id)` is bound
/// to the SHA-256 of the canonical request bytes. Journaled in the same
/// record as the command it created, so the binding is durable before any
/// response is released. The result (ids) is recomputed from the command's
/// effect on replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    /// Authenticated principal.
    pub agent: AgentId,
    /// Client request id.
    pub request_id: RequestId,
    /// Digest of the canonical request content.
    pub digest: [u8; 32],
}

/// Result recorded for a bound request id (derived from the effect).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingResult {
    /// Root grant issued.
    Granted(CapabilityId),
    /// Reservation created.
    Reserved(ReservationId),
    /// Child created by DELEGATE.
    Delegated(CapabilityId),
    /// ATTENUATE applied.
    Attenuated(CapabilityId),
    /// TRANSFER applied.
    Transferred(CapabilityId),
    /// DROP applied.
    Dropped(CapabilityId),
    /// REVOKE applied.
    Revoked(CapabilityId),
    /// SPAWN created this child principal.
    Spawned(AgentId),
    /// The request reached a final denial (a grant request denied or timed
    /// out, a spawn that failed). Kept *in memory only* so that a repeat of
    /// the id gets the same answer for the rest of the epoch; never
    /// journaled (nothing was created, and every restart ends the epoch and
    /// with it every principal that could repeat the id).
    Denied(tessera_protocol::ErrorCode),
}

impl BindingResult {
    /// The result a successful effect binds, if it is a bindable one.
    pub fn of(effect: &tessera_capability_core::Effect) -> Option<Self> {
        use tessera_capability_core::Effect as E;
        Some(match effect {
            E::RootCreated { capability, .. } => BindingResult::Granted(*capability),
            E::Reserved(r) => BindingResult::Reserved(r.id()),
            E::Derived { child, .. } => BindingResult::Delegated(*child),
            E::Attenuated { capability, .. } => BindingResult::Attenuated(*capability),
            E::Transferred { capability, .. } => BindingResult::Transferred(*capability),
            E::Dropped { capability, .. } => BindingResult::Dropped(*capability),
            E::Revoked { capability } => BindingResult::Revoked(*capability),
            // Only bound when the command carried a binding, i.e. an
            // agent-initiated SPAWN (operator-created principals have none).
            E::PrincipalCreated { agent } => BindingResult::Spawned(*agent),
            _ => return None,
        })
    }
}

/// Identity of a registered file slot (mirror of the adapter type).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileIdentityRec {
    /// Device.
    pub dev: u64,
    /// Inode.
    pub ino: u64,
    /// Owner uid.
    pub uid: u32,
    /// Filesystem magic.
    pub fs_type: i64,
}

/// Administrator-registered file slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSlotRec {
    /// Object id.
    pub object: ObjectId,
    /// Single path component inside the trusted root.
    pub name: String,
    /// Largest snapshot.
    pub max_read_bytes: u64,
    /// Largest replacement.
    pub max_write_bytes: u64,
    /// Identity at registration.
    pub identity: FileIdentityRec,
}

/// Non-secret HTTPS endpoint description (secrets come only from the
/// daemon configuration and are never journaled).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointSpec {
    /// Host name used for DNS, SNI, certificate validation and `Host`.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// Allowed path prefix.
    pub path_prefix: String,
    /// Allowed methods (upper-case names).
    pub methods: Vec<String>,
    /// Request headers agents may set.
    #[serde(default)]
    pub request_headers: Vec<String>,
    /// Response headers returned to agents.
    #[serde(default)]
    pub response_headers: Vec<String>,
    /// Largest request body.
    pub max_request_body: u64,
    /// Largest response body.
    pub max_response_body: u64,
    /// Overall deadline in milliseconds.
    pub timeout_ms: u64,
    /// Permit private/loopback destinations (tests, approved internal).
    #[serde(default)]
    pub allow_private: bool,
    /// Pinned destination addresses (no DNS).
    #[serde(default)]
    pub pinned_addrs: Option<Vec<std::net::IpAddr>>,
    /// Custom CA certificates (DER); `None` = webpki roots.
    #[serde(default)]
    pub ca_der: Option<Vec<Vec<u8>>>,
}

/// A configured endpoint: `(id, spec, secret header (name, value))`.
pub type ConfiguredEndpoint = (u64, EndpointSpec, Option<(String, Vec<u8>)>);

/// One broker journal record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Entry {
    /// First record of an installation.
    Genesis {
        /// Random installation identity bound into approvals.
        installation: u128,
    },
    /// A successful authenticated command and the trusted tick it was
    /// applied at.
    Command {
        /// Tick.
        tick: Tick,
        /// The command (caller identity included).
        command: AuthenticatedCommand,
        /// Request-id binding created by this command, if any.
        binding: Option<Binding>,
        /// New identity of a file slot after a replacement outcome.
        file_identity: Option<(ObjectId, FileIdentityRec)>,
    },
    /// The reservation is about to be handed to its adapter. Written after
    /// the `Consume` record and before dispatch, so recovery can tell
    /// "never dispatched" from "dispatched, outcome lost".
    Dispatched {
        /// Reservation.
        reservation: ReservationId,
    },
    /// File slot registered.
    FileRegistered(FileSlotRec),
    /// Endpoint registered through the admin endpoint.
    EndpointRegistered {
        /// Id.
        id: EndpointId,
        /// Spec.
        spec: EndpointSpec,
    },
    /// Operator approval credential enrolled (encoded `Enrollment`; public
    /// key material only). Replaces any earlier enrollment (rotation).
    Enrolled {
        /// `Enrollment::encode` bytes.
        enrollment: Vec<u8>,
    },
}

/// Encoding / decoding failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryError {
    /// Missing tag or unknown version.
    BadHeader,
    /// Body does not decode.
    Malformed,
}

impl Entry {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(96);
        v.extend_from_slice(&TAG);
        v.push(VERSION);
        // Serializing plain data into a Vec cannot fail.
        postcard::to_extend(self, v).unwrap_or_default()
    }

    /// Decode (journal content is trusted but still checked).
    pub fn decode(bytes: &[u8]) -> Result<Entry, EntryError> {
        let body = bytes
            .strip_prefix(&TAG[..])
            .and_then(|b| b.strip_prefix(&[VERSION][..]))
            .ok_or(EntryError::BadHeader)?;
        let (e, rest) = postcard::take_from_bytes(body).map_err(|_| EntryError::Malformed)?;
        if !rest.is_empty() {
            return Err(EntryError::Malformed);
        }
        Ok(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tessera_capability_core::AdminCommand;

    #[test]
    fn roundtrip() {
        let e = Entry::Command {
            tick: Tick::from_raw(5),
            command: AuthenticatedCommand::operator(AdminCommand::CreatePrincipal),
            binding: None,
            file_identity: None,
        };
        assert_eq!(Entry::decode(&e.encode()), Ok(e));
        assert_eq!(Entry::decode(b"xxxx"), Err(EntryError::BadHeader));
        let mut bad = Entry::Dispatched {
            reservation: ReservationId::from_raw(1),
        }
        .encode();
        bad.push(0);
        assert_eq!(Entry::decode(&bad), Err(EntryError::Malformed));
    }
}
