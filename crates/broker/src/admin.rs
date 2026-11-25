//! Operator administrative protocol and endpoint (§9.2: separate from agent
//! IPC).
//!
//! Transport: a Unix stream socket at an operator-chosen path inside a
//! directory owned by the broker user and not group/world-writable; the
//! socket itself is mode 0600. Every connection's `SO_PEERCRED` uid must
//! equal the broker's effective uid (the operator account), ancillary data
//! is rejected and closes the connection, and frames are length-prefixed
//! and bounded. Sandboxes have no route to the socket (no mount, separate
//! network namespace, Landlock).
//!
//! Encoding: `b"TSAD" | u8 version | postcard(body)` inside
//! `tessera_protocol::frame` frames.

use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tessera_capability_core::AgentId;
use tessera_protocol::frame::{FrameLimits, read_frame, write_frame};
use tessera_protocol::unix::{CheckedStream, peer_credentials};
use tessera_protocol::{WireBudget, WireDepth, WireScope};

use crate::audit::AuditEvent;
use crate::entry::EndpointSpec;

const TAG: [u8; 4] = *b"TSAD";
const VERSION: u8 = 1;
/// Admin frame limit.
pub const ADMIN_MAX_FRAME: usize = 4 * 1024 * 1024;

/// Operator requests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AdminRequest {
    /// Broker status summary.
    Status,
    /// Enroll (or rotate) the operator's approval credential
    /// (`tessera_approval::Enrollment::encode` bytes).
    Enroll {
        /// Encoded enrollment.
        enrollment: Vec<u8>,
    },
    /// Register a file slot (a single name inside the trusted root).
    RegisterFile {
        /// Slot name.
        name: String,
        /// Largest snapshot.
        max_read_bytes: u64,
        /// Largest replacement.
        max_write_bytes: u64,
    },
    /// Register an HTTPS endpoint (no secrets; those come from the daemon
    /// configuration only).
    RegisterEndpoint {
        /// Endpoint id.
        id: u64,
        /// Description.
        spec: EndpointSpec,
    },
    /// Create a principal and launch its sandbox from a trusted profile.
    CreatePrincipal {
        /// Profile name from the daemon configuration.
        profile: String,
    },
    /// Terminate a principal (closes its channel, stops its sandbox).
    TerminatePrincipal {
        /// Principal.
        agent: AgentId,
    },
    /// List principals of the current epoch.
    ListPrincipals,
    /// Install an operator baseline grant (R2: recorded separately).
    InstallBaseline {
        /// Recipient.
        agent: AgentId,
        /// Scope.
        scope: WireScope,
        /// Budget.
        budget: WireBudget,
        /// Depth.
        depth: WireDepth,
        /// Lifetime in ms, `None` = until revoked / epoch end.
        expiry_ms: Option<u64>,
    },
    /// Pending approval requests.
    ListPending,
    /// Narrow the pending request `ticket` to `request`
    /// (`GrantRequest::encode` bytes; must be a narrowing).
    Narrow {
        /// Ticket.
        ticket: u64,
        /// Narrowed canonical request.
        request: Vec<u8>,
    },
    /// What the authenticator must sign for `ticket`.
    Challenge {
        /// Ticket.
        ticket: u64,
    },
    /// Submit the FIDO2 assertion for `ticket`.
    Approve {
        /// Ticket.
        ticket: u64,
        /// Credential id.
        credential_id: Vec<u8>,
        /// Authenticator data.
        authenticator_data: Vec<u8>,
        /// Signature.
        signature: Vec<u8>,
    },
    /// Deny `ticket`.
    Deny {
        /// Ticket.
        ticket: u64,
    },
    /// Revoke a capability subtree.
    Revoke {
        /// Capability.
        capability: u128,
    },
    /// Inspect one capability.
    Inspect {
        /// Capability.
        capability: u128,
    },
    /// Ancestors and the full subtree of one capability.
    Lineage {
        /// Capability.
        capability: u128,
    },
    /// Every capability record.
    Tree,
    /// N = U + L + D per finite pool.
    Accounts,
    /// Reservations (optionally only uncertain / abandoned ones).
    Reservations {
        /// Only Unknown / abandoned / in-flight.
        only_uncertain: bool,
    },
    /// Audit events from `since`.
    Audit {
        /// First sequence.
        since: u64,
        /// Max events.
        limit: u32,
    },
    /// Emergency stop: bump the epoch now (every grant invalid, every
    /// principal terminated, every sandbox stopped).
    EmergencyStop,
    /// Journal head (for an external checkpoint).
    Checkpoint,
}

/// Broker status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusView {
    /// Installation id (hex).
    pub installation: String,
    /// Epoch.
    pub epoch: u64,
    /// Ledger sequence.
    pub sequence: u64,
    /// Trusted tick.
    pub tick: u64,
    /// Active principals.
    pub principals: u64,
    /// Capability records.
    pub capabilities: u64,
    /// Whether an approval credential is enrolled.
    pub enrolled: bool,
    /// Pending approvals.
    pub pending_approvals: u64,
    /// Reservations from earlier epochs whose outcome is unknown.
    pub uncertain_reservations: u64,
}

/// Principal view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalView {
    /// Id.
    pub agent: AgentId,
    /// `active` / `terminated`.
    pub status: String,
    /// Whether a channel is attached.
    pub connected: bool,
}

/// Pending approval view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingView {
    /// Ticket.
    pub ticket: u64,
    /// Requesting principal.
    pub agent: AgentId,
    /// Whether this request currently owns the authenticator (others queue).
    pub active: bool,
    /// Canonical request to sign (`GrantRequest::encode`), current version.
    pub request: Vec<u8>,
    /// Broker-normalized rendering (trusted fields only).
    pub rendered: String,
}

/// Challenge for the authenticator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeView {
    /// RP id.
    pub rp_id: String,
    /// `clientDataHash` = canonical request digest.
    pub client_data_hash: [u8; 32],
    /// Allowed credential.
    pub credential_id: Vec<u8>,
    /// UV required.
    pub require_user_verification: bool,
    /// The canonical request this digest covers (so the CLI can recompute it).
    pub request: Vec<u8>,
}

/// Capability view (metadata only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapView {
    /// Id.
    pub id: u128,
    /// Root id.
    pub root: u128,
    /// Parent.
    pub parent: Option<u128>,
    /// Owner.
    pub owner: AgentId,
    /// Scope summary.
    pub scope: String,
    /// Remaining budget.
    pub budget: String,
    /// Depth.
    pub depth: String,
    /// Expiry.
    pub expiry: String,
    /// `live` or the reason it is not.
    pub status: String,
    /// `approved` or `baseline`.
    pub root_kind: String,
    /// Lineage generation.
    pub generation: u32,
}

/// Pool account view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountView {
    /// Pool.
    pub pool: u64,
    /// Root.
    pub root: u128,
    /// Anchor capability.
    pub anchor: u128,
    /// N.
    pub initial: u64,
    /// U.
    pub consumed: u64,
    /// L.
    pub live: u64,
    /// D.
    pub discarded: u64,
}

/// Reservation view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservationView {
    /// Id.
    pub id: u64,
    /// Owner.
    pub owner: AgentId,
    /// Capability.
    pub capability: u128,
    /// Root.
    pub root: u128,
    /// `reserved`, `dispatched`, `completed`, `failed`, `unknown`,
    /// `abandoned-not-dispatched`, `unknown-dispatched-before-restart`.
    pub status: String,
    /// Operation summary.
    pub operation: String,
}

/// Operator responses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AdminResponse {
    /// Done.
    Ok,
    /// Refused / failed.
    Error(String),
    /// Status.
    Status(StatusView),
    /// Registered object id.
    Object(u64),
    /// Principal.
    Agent(AgentId),
    /// Principals.
    Principals(Vec<PrincipalView>),
    /// New capability.
    Capability(u128),
    /// Pending approvals.
    Pending(Vec<PendingView>),
    /// Challenge.
    Challenge(ChallengeView),
    /// Capability records.
    Caps(Vec<CapView>),
    /// Accounts.
    Accounts(Vec<AccountView>),
    /// Reservations.
    Reservations(Vec<ReservationView>),
    /// Audit events.
    Audit(Vec<AuditEvent>),
    /// Journal checkpoint.
    Checkpoint {
        /// Records covered.
        records: u64,
        /// Head hash (hex).
        head: String,
    },
}

/// Encode an admin message body.
pub fn encode<T: Serialize>(m: &T) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    v.extend_from_slice(&TAG);
    v.push(VERSION);
    postcard::to_extend(m, v).unwrap_or_default()
}

/// Decode an admin message body (strict: tag, version, no trailing bytes).
pub fn decode<T: DeserializeOwned>(b: &[u8]) -> Option<T> {
    let body = b.strip_prefix(&TAG[..])?.strip_prefix(&[VERSION][..])?;
    let (v, rest) = postcard::take_from_bytes(body).ok()?;
    rest.is_empty().then_some(v)
}

fn limits() -> FrameLimits {
    FrameLimits::new(ADMIN_MAX_FRAME)
}

/// Blocking admin client.
pub struct AdminClient {
    stream: UnixStream,
}

impl AdminClient {
    /// Connect to the admin socket.
    pub fn connect(path: &Path) -> io::Result<Self> {
        Ok(AdminClient {
            stream: UnixStream::connect(path)?,
        })
    }

    /// One request/response round trip.
    pub fn call(&mut self, req: &AdminRequest) -> io::Result<AdminResponse> {
        write_frame(&mut self.stream, &encode(req), limits())
            .map_err(|e| io::Error::other(e.to_string()))?;
        let payload = read_frame(&mut self.stream, limits())
            .map_err(|e| io::Error::other(e.to_string()))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "broker closed"))?;
        decode(&payload).ok_or_else(|| io::Error::other("malformed admin response"))
    }
}

/// Something that executes admin requests (the reactor's inbox).
pub(crate) type AdminSubmit =
    std::sync::Arc<dyn Fn(AdminRequest) -> Option<AdminResponse> + Send + Sync>;

/// Check (or create) the socket directory: owned by us, not group/world
/// writable.
fn check_dir(dir: &Path) -> io::Result<()> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let md = std::fs::symlink_metadata(dir)?;
    let euid = rustix::process::geteuid().as_raw();
    if !md.is_dir() || md.uid() != euid || md.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "admin socket directory {} must be a directory owned by uid {euid} and not group/world-writable",
                dir.display()
            ),
        ));
    }
    Ok(())
}

/// Bind the admin socket and serve it on background threads.
pub(crate) fn serve(path: &Path, submit: AdminSubmit) -> io::Result<PathBuf> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    check_dir(dir)?;
    if let Ok(md) = std::fs::symlink_metadata(path) {
        use std::os::unix::fs::FileTypeExt;
        if md.file_type().is_socket() {
            std::fs::remove_file(path)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    let euid = rustix::process::geteuid().as_raw();
    thread::Builder::new()
        .name("tessera-admin-accept".into())
        .spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { continue };
                // Operator-only: the peer must run as the broker's uid.
                match peer_credentials(conn.as_fd()) {
                    Ok(c) if c.uid == euid => {}
                    _ => continue,
                }
                let submit = submit.clone();
                let _ = thread::Builder::new()
                    .name("tessera-admin-conn".into())
                    .spawn(move || serve_conn(conn, submit));
            }
        })?;
    Ok(path.to_path_buf())
}

fn serve_conn(mut conn: UnixStream, submit: AdminSubmit) {
    loop {
        let frame = {
            let mut r = CheckedStream::new(conn.as_fd());
            read_frame(&mut r, limits())
        };
        let payload = match frame {
            Ok(Some(p)) => p,
            // EOF, ancillary data, oversize, i/o error: close.
            _ => return,
        };
        let resp = match decode::<AdminRequest>(&payload) {
            Some(req) => {
                submit(req).unwrap_or_else(|| AdminResponse::Error("broker unavailable".into()))
            }
            None => AdminResponse::Error("malformed admin request".into()),
        };
        if write_frame(&mut conn, &encode(&resp), limits()).is_err() {
            return;
        }
    }
}

/// In-process submission helper used by [`crate::Broker::admin`].
pub(crate) fn call_via(
    tx: &mpsc::SyncSender<crate::reactor::Inbox>,
    req: AdminRequest,
) -> Option<AdminResponse> {
    let (rtx, rrx) = mpsc::channel();
    tx.send(crate::reactor::Inbox::Admin { req, reply: rtx })
        .ok()?;
    rrx.recv().ok()
}
