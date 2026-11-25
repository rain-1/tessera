//! Shared harness for broker integration tests.
#![allow(dead_code)]

use std::os::fd::{AsFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tessera_approval as ap;
use tessera_approval::Authenticator;
use tessera_broker::{
    AdapterExecutor, AdminRequest, AdminResponse, AuditLog, Broker, BrokerConfig, DispatchJob,
    EndpointSpec, ExecResult, Executor, FaultHook, MonotonicClock, Services,
    entry::FileIdentityRec,
};
use tessera_capability_core::{AgentId, EndpointId, ObjectId};
use tessera_journal::testing::MemStorage;
use tessera_journal::{Journal, JournalOptions};
use tessera_protocol::bounded::BoundedString;
use tessera_protocol::frame::FrameLimits;
use tessera_protocol::unix::{recv_packet, send_packet};
use tessera_protocol::*;

pub const RP_ID: &str = "tessera.test";

/// Counts adapter dispatches across broker instances.
pub struct Counting {
    pub inner: AdapterExecutor,
    pub calls: Arc<AtomicUsize>,
}

impl Executor for Counting {
    fn register_file(
        &self,
        object: ObjectId,
        name: &str,
        r: u64,
        w: u64,
        expected: Option<FileIdentityRec>,
    ) -> Result<FileIdentityRec, String> {
        self.inner.register_file(object, name, r, w, expected)
    }
    fn register_endpoint(
        &self,
        id: EndpointId,
        spec: &EndpointSpec,
        secret: Option<(String, Vec<u8>)>,
    ) -> Result<(), String> {
        self.inner.register_endpoint(id, spec, secret)
    }
    fn execute(&self, job: &DispatchJob) -> ExecResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.execute(job)
    }
}

pub struct Harness {
    pub storage: MemStorage,
    pub root: tempfile::TempDir,
    pub calls: Arc<AtomicUsize>,
    pub auth: ap::authenticator::SoftwareAuthenticator,
    pub enrollment: Option<ap::Enrollment>,
    pub config: BrokerConfig,
}

impl Harness {
    pub fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for (n, c) in [
            ("notes.txt", &b"top secret notes"[..]),
            ("other.txt", b"other"),
        ] {
            let p = root.path().join(n);
            std::fs::write(&p, c).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        Harness {
            storage: MemStorage::new(),
            root,
            calls: Arc::new(AtomicUsize::new(0)),
            auth: ap::authenticator::SoftwareAuthenticator::new(),
            enrollment: None,
            config: BrokerConfig::default(),
        }
    }

    pub fn root_path(&self) -> PathBuf {
        self.root.path().to_path_buf()
    }

    /// Start (or restart) a broker on the harness storage.
    pub fn start(&self, fault: Option<FaultHook>) -> Broker {
        self.start_on(self.storage.clone(), fault)
    }

    pub fn start_on(&self, storage: MemStorage, fault: Option<FaultHook>) -> Broker {
        let journal = Journal::open_storage(storage, JournalOptions::default()).unwrap();
        let exec = Counting {
            inner: AdapterExecutor::new(Some(self.root.path())).unwrap(),
            calls: Arc::clone(&self.calls),
        };
        Broker::start(
            journal,
            self.config.clone(),
            Services {
                executor: Arc::new(exec),
                spawner: None,
                audit: AuditLog::memory(),
                clock: Arc::new(MonotonicClock::default()),
                fault,
            },
        )
        .unwrap()
    }

    /// Enroll the software authenticator.
    pub fn enroll(&mut self, b: &Broker) {
        let req = ap::CredentialRequest {
            rp_id: RP_ID.into(),
            operator: ap::OperatorId(7),
            user_name: "operator".into(),
            algorithm: ap::CoseAlgorithm::Es256,
            require_user_verification: false,
        };
        let e = ap::enroll(&mut self.auth, &req).unwrap();
        assert_eq!(
            b.admin(AdminRequest::Enroll {
                enrollment: e.encode()
            }),
            AdminResponse::Ok
        );
        self.enrollment = Some(e);
    }

    /// Approve the active pending request with a genuine assertion.
    pub fn approve(&mut self, b: &Broker) -> AdminResponse {
        let ticket = wait_pending(b);
        let a = self.assertion_for(b, ticket);
        b.admin(AdminRequest::Approve {
            ticket,
            credential_id: a.credential_id,
            authenticator_data: a.authenticator_data,
            signature: a.signature,
        })
    }

    pub fn assertion_for(&mut self, b: &Broker, ticket: u64) -> ap::Assertion {
        let AdminResponse::Challenge(c) = b.admin(AdminRequest::Challenge { ticket }) else {
            panic!("no challenge")
        };
        // The CLI recomputes the digest over the request it was shown.
        let req = ap::GrantRequest::decode(&c.request).unwrap();
        assert_eq!(req.digest().0, c.client_data_hash);
        self.auth
            .get_assertion(&ap::AssertionRequest {
                rp_id: c.rp_id,
                client_data_hash: c.client_data_hash,
                credential_id: c.credential_id,
                require_user_verification: c.require_user_verification,
            })
            .unwrap()
    }
}

/// Wait until an active pending approval exists; return its ticket.
pub fn wait_pending(b: &Broker) -> u64 {
    for _ in 0..500 {
        if let AdminResponse::Pending(v) = b.admin(AdminRequest::ListPending)
            && let Some(p) = v.iter().find(|p| p.active)
        {
            return p.ticket;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("no pending approval appeared");
}

pub fn register_file(b: &Broker, name: &str) -> u64 {
    match b.admin(AdminRequest::RegisterFile {
        name: name.into(),
        max_read_bytes: 4096,
        max_write_bytes: 4096,
    }) {
        AdminResponse::Object(o) => o,
        other => panic!("register failed: {other:?}"),
    }
}

pub fn read_scope(object: u64) -> WireScope {
    WireScope::File {
        object_id: object,
        rights: WireFileRights {
            read_snapshot: true,
            replace_content: false,
        },
    }
}

/// Operator baseline grant (no approval needed) for fast setup.
pub fn baseline(b: &Broker, agent: AgentId, object: u64, budget: u64, depth: u32) -> u128 {
    match b.admin(AdminRequest::InstallBaseline {
        agent,
        scope: read_scope(object),
        budget: WireBudget::Finite(budget),
        depth: WireDepth::Finite(depth),
        expiry_ms: None,
    }) {
        AdminResponse::Capability(c) => c,
        other => panic!("baseline failed: {other:?}"),
    }
}

/// Minimal synchronous agent client over a seqpacket channel.
pub struct Agent {
    pub id: AgentId,
    pub fd: OwnedFd,
    next: u64,
}

pub fn limits() -> FrameLimits {
    FrameLimits::new(512 * 1024)
}

impl Agent {
    pub fn attach(b: &Broker) -> Agent {
        let (id, fd) = b.attach_principal().unwrap();
        rustix::net::sockopt::set_socket_timeout(
            &fd,
            rustix::net::sockopt::Timeout::Recv,
            Some(Duration::from_secs(20)),
        )
        .unwrap();
        Agent { id, fd, next: 1 }
    }

    pub fn wire_id(&self) -> WireAgentId {
        WireAgentId {
            epoch: u128::from(self.id.epoch()),
            serial: self.id.serial(),
        }
    }

    pub fn send(&mut self, request: Request) -> u64 {
        let c = self.next;
        self.next += 1;
        let msg = ClientMessage {
            correlation_id: c,
            request,
        };
        send_packet(self.fd.as_fd(), &encode_client(&msg).unwrap(), limits()).unwrap();
        c
    }

    /// Next final message (interim `GrantPending` notices are skipped).
    pub fn recv(&self) -> Option<ServerMessage> {
        loop {
            let m = self.recv_any()?;
            if !matches!(m.response, Response::GrantPending { .. }) {
                return Some(m);
            }
        }
    }

    /// Next message of any kind.
    pub fn recv_any(&self) -> Option<ServerMessage> {
        let p = recv_packet(self.fd.as_fd(), limits()).ok()??;
        Some(decode_server(&p, limits().max_frame()).unwrap())
    }

    pub fn call(&mut self, request: Request) -> Response {
        let c = self.send(request);
        let m = self.recv().expect("broker closed channel");
        assert_eq!(m.correlation_id, c, "correlation echoed");
        m.response
    }

    pub fn read(&mut self, rid: u128, cap: u128) -> Response {
        self.call(Request::Consume {
            request_id: rid,
            cap_id: cap,
            operation: WireOperation::FileReadSnapshot { max_bytes: 1024 },
        })
    }

    pub fn delegate(
        &mut self,
        rid: u128,
        cap: u128,
        to: WireAgentId,
        scope: WireScope,
        budget: u64,
        depth: u32,
    ) -> Response {
        self.call(Request::Delegate {
            request_id: rid,
            cap_id: cap,
            recipient: to,
            child_scope: scope,
            child_budget: WireBudget::Finite(budget),
            child_depth: WireDepth::Finite(depth),
            child_expiry: WireExpiry::Inherit,
        })
    }

    pub fn request_grant(&mut self, rid: u128, scope: WireScope, budget: u64, depth: u32) -> u64 {
        self.send(Request::RequestGrant {
            request_id: rid,
            requested_scope: scope,
            budget: WireBudget::Finite(budget),
            depth: WireDepth::Finite(depth),
            expiry: WireExpiry::Inherit,
            untrusted_description: None,
        })
    }
}

pub fn code(r: &Response) -> Option<ErrorCode> {
    match r {
        Response::Error { code, .. } => Some(*code),
        _ => None,
    }
}

pub fn snapshot(r: &Response) -> Vec<u8> {
    match r {
        Response::Consumed {
            result: WireOperationResult::FileSnapshot { bytes, .. },
            ..
        } => bytes.as_slice().to_vec(),
        other => panic!("expected a snapshot, got {other:?}"),
    }
}

pub fn granted(r: &Response) -> u128 {
    match r {
        Response::GrantIssued { cap_id, .. } => *cap_id,
        other => panic!("expected a grant, got {other:?}"),
    }
}

pub fn caps(b: &Broker) -> Vec<tessera_broker::admin::CapView> {
    match b.admin(AdminRequest::Tree) {
        AdminResponse::Caps(c) => c,
        other => panic!("{other:?}"),
    }
}

pub fn cap(b: &Broker, id: u128) -> tessera_broker::admin::CapView {
    caps(b)
        .into_iter()
        .find(|c| c.id == id)
        .expect("cap exists")
}

pub fn reservations(b: &Broker) -> Vec<tessera_broker::admin::ReservationView> {
    match b.admin(AdminRequest::Reservations {
        only_uncertain: false,
    }) {
        AdminResponse::Reservations(r) => r,
        other => panic!("{other:?}"),
    }
}

pub fn status(b: &Broker) -> tessera_broker::admin::StatusView {
    match b.admin(AdminRequest::Status) {
        AdminResponse::Status(s) => s,
        other => panic!("{other:?}"),
    }
}

pub fn detail(s: &str) -> BoundedString<MAX_DETAIL> {
    BoundedString::new(s.to_owned()).unwrap()
}
