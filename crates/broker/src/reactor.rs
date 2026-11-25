//! The single-writer reactor (ADR-0001).
//!
//! One thread owns the [`State`], the [`Journal`], the request-id bindings,
//! the approval session and the channel table. Per-principal reader threads
//! and dispatch workers only post [`Inbox`] messages. For every
//! state-changing command the reactor:
//!
//! 1. validates it against committed state (`validate_command`, pure);
//! 2. appends `Entry::Command { tick, command, binding }` and `fdatasync`s;
//! 3. applies it with `step` (deterministic, so it succeeds exactly as
//!    validated; a mismatch halts the broker);
//! 4. only then releases the response, grant or reservation.
//!
//! A CONSUME is followed by a durable `Dispatched` marker *before* the job is
//! handed to an adapter worker, and by a durable `RecordOutcome` before the
//! agent sees any result. No step is pipelined: the next message is not
//! looked at until the current commit returned.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::num::NonZeroU64;
use std::os::fd::OwnedFd;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use tessera_approval as ap;
use tessera_capability_core::{
    AdminCommand, AgentCommand, AgentId, AuthenticatedCommand, Budget, CapabilityId, Denial,
    EndpointId, Expiry, FileRight, Limits, ObjectId, Operation, Outcome, PrincipalStatus,
    RequestId, ReservationId, ReservationStatus, RootKind, Scope, State, Tick, check_invariant,
    step, validate_command,
};
use tessera_journal::{Journal, JournalError, RecordKind, Storage};
use tessera_protocol::{
    ErrorCode, Request, Response, ServerMessage, WireCapStatus, WireCapabilityView, WireOperation,
    WireReservationStatus,
};

use crate::admin::{
    AccountView, AdminRequest, AdminResponse, CapView, ChallengeView, PendingView, PrincipalView,
    ReservationView, StatusView,
};
use crate::audit::{AuditEvent, AuditLog};
use crate::clock::{Clock, TickSource};
use crate::conn::{self, ChannelHandle, error};
use crate::convert::{self as cv, hex};
use crate::entry::{Binding, BindingResult, EndpointSpec, Entry, FileIdentityRec, FileSlotRec};
use crate::executor::{DispatchJob, ExecResult, Executor, JobOperation, MAX_INLINE_CONTENT};
use crate::spawner::{SandboxSpawner, SpawnerMsg, SpawnerThread};

/// Points at which a test can kill the reactor (simulated crash).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultPoint {
    /// Consume validated, nothing journaled yet.
    BeforeConsumeCommit,
    /// Consume (reservation) durable; no dispatch marker yet.
    AfterConsumeCommit,
    /// Dispatch marker durable; job not yet handed to the adapter.
    AfterDispatchMarker,
    /// Adapter finished; outcome not yet journaled.
    AfterDispatchBeforeOutcome,
    /// Outcome durable; response not yet sent.
    AfterOutcomeBeforeResponse,
    /// Approval verified; mint not yet journaled.
    BeforeMintCommit,
    /// Mint durable; agent not yet told.
    AfterMintCommit,
}

/// Fault hook: return `true` to kill the reactor at that point.
pub type FaultHook = Arc<dyn Fn(FaultPoint) -> bool + Send + Sync>;

/// Static broker configuration.
#[derive(Clone)]
pub struct BrokerConfig {
    /// Core resource bounds.
    pub limits: Limits,
    /// Lifetime of a root grant whose request says `Inherit`.
    pub default_grant_ttl_ms: u64,
    /// Upper bound on any requested root lifetime.
    pub max_grant_ttl_ms: u64,
    /// How long an approval request waits for the operator.
    pub approval_timeout_ms: u64,
    /// Approval rate-limit window.
    pub approval_rate_window_ms: u64,
    /// Approval requests per window.
    pub approval_max_per_window: u32,
    /// Grant requests queued behind the active one.
    pub approval_queue: usize,
    /// Require FIDO2 user verification (PIN) on every mint.
    pub require_user_verification: bool,
    /// Agent channel frame bound (bytes).
    pub agent_max_frame: usize,
    /// Adapter worker threads.
    pub dispatch_workers: usize,
    /// Endpoints from the daemon configuration `(id, spec, secret header)`.
    pub endpoints: Vec<(u64, EndpointSpec, Option<(String, Vec<u8>)>)>,
}

impl std::fmt::Debug for BrokerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerConfig")
            .field("limits", &self.limits)
            .field("endpoints", &self.endpoints.len())
            .finish_non_exhaustive()
    }
}

impl Default for BrokerConfig {
    fn default() -> Self {
        BrokerConfig {
            limits: Limits::default(),
            default_grant_ttl_ms: 5 * 60 * 1000,
            max_grant_ttl_ms: 24 * 60 * 60 * 1000,
            approval_timeout_ms: 2 * 60 * 1000,
            approval_rate_window_ms: 60 * 1000,
            approval_max_per_window: 30,
            approval_queue: 16,
            require_user_verification: false,
            agent_max_frame: 128 * 1024,
            dispatch_workers: 4,
            endpoints: Vec::new(),
        }
    }
}

/// Collaborators of the reactor.
pub struct Services {
    /// Adapter executor.
    pub executor: Arc<dyn Executor>,
    /// Sandbox spawner (`None`: only in-process principals).
    pub spawner: Option<Box<dyn SandboxSpawner>>,
    /// Audit sink.
    pub audit: AuditLog,
    /// Trusted monotonic time.
    pub clock: Arc<dyn TickSource>,
    /// Crash-injection hook (tests).
    pub fault: Option<FaultHook>,
}

/// Why the reactor stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// Orderly shutdown.
    Shutdown,
    /// A fault hook killed it (simulated crash).
    Killed(FaultPoint),
    /// Journal write/sync failed: fail closed, restart required.
    JournalFailure(String),
    /// Journaled command could not be applied (core/journal disagree).
    Inconsistent(String),
}

/// Startup failure.
#[derive(Debug)]
pub enum StartError {
    /// Journal could not be read.
    Journal(JournalError),
    /// A journal record is not a valid broker entry.
    BadEntry(u64),
    /// Replaying the log through the core failed.
    Replay(String),
    /// Startup configuration problem.
    Config(String),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::Journal(e) => write!(f, "journal: {e}"),
            StartError::BadEntry(s) => write!(f, "journal record {s} is not a broker entry"),
            StartError::Replay(e) => write!(f, "replay failed: {e}"),
            StartError::Config(e) => write!(f, "configuration: {e}"),
        }
    }
}

impl std::error::Error for StartError {}

/// Messages to the single writer.
pub(crate) enum Inbox {
    Agent {
        agent: AgentId,
        conn: u64,
        correlation: u64,
        request: Request,
        digest: [u8; 32],
    },
    ChannelClosed {
        agent: AgentId,
        conn: u64,
        violation: Option<String>,
    },
    Admin {
        req: AdminRequest,
        reply: Sender<AdminResponse>,
    },
    Attach {
        reply: Sender<Result<(AgentId, OwnedFd), String>>,
    },
    SpawnDone {
        agent: AgentId,
        result: Result<OwnedFd, String>,
        reply: Sender<AdminResponse>,
    },
    DispatchDone {
        reservation: ReservationId,
        result: ExecResult,
    },
    Shutdown,
}

struct PendingGrant {
    ticket: u64,
    agent: AgentId,
    correlation: u64,
    /// Correlation ids of repeated identical requests attached to this one
    /// (the SDK retries with the same request id after a timeout).
    waiters: Vec<u64>,
    request_id: RequestId,
    digest: [u8; 32],
    request: ap::GrantRequest,
}

impl PendingGrant {
    fn correlations(&self) -> impl Iterator<Item = u64> + '_ {
        std::iter::once(self.correlation).chain(self.waiters.iter().copied())
    }
}

struct PendingDispatch {
    agent: AgentId,
    correlation: u64,
    request_id: RequestId,
    capability: CapabilityId,
    root: u128,
}

#[derive(Debug)]
enum Stop {
    Killed(FaultPoint),
    Journal(String),
    Inconsistent(String),
    Shutdown,
}

type Flow = Result<(), Stop>;

pub(crate) struct Reactor<S: Storage> {
    cfg: BrokerConfig,
    state: State,
    journal: Journal<S>,
    installation: u128,
    clock: Clock,
    executor: Arc<dyn Executor>,
    audit: AuditLog,
    fault: Option<FaultHook>,
    bindings: HashMap<(AgentId, RequestId), ([u8; 32], BindingResult)>,
    dispatched: BTreeSet<ReservationId>,
    pending_dispatch: HashMap<ReservationId, PendingDispatch>,
    principals: BTreeSet<AgentId>,
    channels: HashMap<AgentId, ChannelHandle>,
    next_conn: u64,
    files: HashMap<ObjectId, FileSlotRec>,
    file_ok: BTreeSet<ObjectId>,
    endpoints: BTreeSet<EndpointId>,
    enrollment: Option<ap::Enrollment>,
    session: Option<ap::ApprovalSession>,
    active: Option<PendingGrant>,
    queue: VecDeque<PendingGrant>,
    next_ticket: u64,
    inbox_tx: SyncSender<Inbox>,
    jobs: Option<Sender<DispatchJob>>,
    spawner: Option<SpawnerThread>,
}

fn journal_err(e: JournalError) -> Stop {
    Stop::Journal(e.to_string())
}

impl<S: Storage> Reactor<S> {
    /// Recover from the journal, then begin a new epoch (ADR-0003).
    pub(crate) fn open(
        mut journal: Journal<S>,
        cfg: BrokerConfig,
        services: Services,
        inbox_tx: SyncSender<Inbox>,
    ) -> Result<Self, StartError> {
        let mut state = State::new(cfg.limits);
        let mut installation = None;
        let mut bindings = HashMap::new();
        let mut dispatched = BTreeSet::new();
        let mut principals = BTreeSet::new();
        let mut files: HashMap<ObjectId, FileSlotRec> = HashMap::new();
        let mut endpoint_recs: Vec<(EndpointId, EndpointSpec)> = Vec::new();
        let mut enrollment = None;
        let mut n_records = 0u64;
        // Equivalent to `State::replay` (the same `step` loop over the same
        // `(command, tick)` log, then `check_invariant`), but stepping here
        // also yields the effects that the request-id bindings refer to.
        for rec in journal.replay() {
            let rec = rec.map_err(StartError::Journal)?;
            n_records += 1;
            let (cmd, tick, binding, fid) = match rec.kind {
                RecordKind::EpochBump => (
                    AuthenticatedCommand::operator(AdminCommand::BumpEpoch),
                    Tick::ZERO,
                    None,
                    None,
                ),
                RecordKind::Data => match Entry::decode(&rec.payload) {
                    Err(_) => return Err(StartError::BadEntry(rec.seq)),
                    Ok(Entry::Genesis { installation: i }) => {
                        installation = Some(i);
                        continue;
                    }
                    Ok(Entry::Dispatched { reservation }) => {
                        dispatched.insert(reservation);
                        continue;
                    }
                    Ok(Entry::FileRegistered(f)) => {
                        files.insert(f.object, f);
                        continue;
                    }
                    Ok(Entry::EndpointRegistered { id, spec }) => {
                        endpoint_recs.push((id, spec));
                        continue;
                    }
                    Ok(Entry::Enrolled { enrollment: e }) => {
                        enrollment = Some(
                            ap::Enrollment::decode(&e)
                                .map_err(|_| StartError::BadEntry(rec.seq))?,
                        );
                        continue;
                    }
                    Ok(Entry::Command {
                        tick,
                        command,
                        binding,
                        file_identity,
                    }) => (command, tick, binding, file_identity),
                },
            };
            let eff = step(&mut state, cmd, tick)
                .map_err(|d| StartError::Replay(format!("record {}: {d:?}", rec.seq)))?;
            if let tessera_capability_core::Effect::PrincipalCreated { agent } = &eff {
                principals.insert(*agent);
            }
            if let (Some(b), Some(r)) = (binding, BindingResult::of(&eff)) {
                bindings.insert((b.agent, b.request_id), (b.digest, r));
            }
            if let Some((obj, id)) = fid
                && let Some(f) = files.get_mut(&obj)
            {
                f.identity = id;
            }
        }
        check_invariant(&state).map_err(|v| StartError::Replay(format!("{v:?}")))?;

        let installation = match installation {
            Some(i) => i,
            None if n_records == 0 => {
                let mut b = [0u8; 16];
                getrandom::getrandom(&mut b).map_err(|e| StartError::Config(e.to_string()))?;
                let i = u128::from_be_bytes(b);
                journal
                    .append(&Entry::Genesis { installation: i }.encode())
                    .map_err(StartError::Journal)?;
                i
            }
            None => return Err(StartError::Replay("journal has no genesis record".into())),
        };

        // Reservations still unresolved in the previous epoch: never
        // re-dispatched; reported as abandoned (no marker) or unknown
        // (dispatched, outcome lost).
        let unresolved: Vec<ReservationId> = (0u64..)
            .map(ReservationId::from_raw)
            .map_while(|id| state.reservation(id).map(|r| (id, r.status())))
            .filter(|(_, s)| *s == ReservationStatus::Reserved)
            .map(|(id, _)| id)
            .collect();

        // Fail closed across restart: new epoch, fresh clock.
        journal.begin_new_epoch().map_err(StartError::Journal)?;
        step(
            &mut state,
            AuthenticatedCommand::operator(AdminCommand::BumpEpoch),
            Tick::ZERO,
        )
        .map_err(|d| StartError::Replay(format!("epoch bump: {d:?}")))?;
        if journal.current_epoch() != state.epoch() {
            return Err(StartError::Replay(format!(
                "journal epoch {} != ledger epoch {}",
                journal.current_epoch(),
                state.epoch()
            )));
        }
        let epoch = state.epoch();
        bindings.retain(|(a, _), _| a.epoch() == epoch);

        let mut r = Reactor {
            clock: Clock::new(services.clock),
            executor: services.executor,
            audit: services.audit,
            fault: services.fault,
            spawner: services.spawner.map(SpawnerThread::start),
            cfg,
            state,
            journal,
            installation,
            bindings,
            dispatched,
            pending_dispatch: HashMap::new(),
            principals,
            channels: HashMap::new(),
            next_conn: 0,
            files: HashMap::new(),
            file_ok: BTreeSet::new(),
            endpoints: BTreeSet::new(),
            enrollment: None,
            session: None,
            active: None,
            queue: VecDeque::new(),
            next_ticket: 1,
            inbox_tx,
            jobs: None,
        };
        r.record(AuditEvent {
            principal: "broker".into(),
            kind: "epoch-start".into(),
            outcome: "ok".into(),
            detail: Some(format!(
                "installation={:032x} replayed_records={n_records} unresolved={}",
                r.installation,
                unresolved.len()
            )),
            ..r.ev()
        });
        for id in unresolved {
            let rec = r.state.reservation(id);
            let effect = if r.dispatched.contains(&id) {
                "unknown-dispatched-before-restart"
            } else {
                "abandoned-not-dispatched"
            };
            let ev = AuditEvent {
                principal: rec.map(|x| agent_str(x.owner())).unwrap_or_default(),
                kind: "recovery".into(),
                reservation: Some(id.to_raw()),
                capability: rec.map(|x| x.capability().to_raw()),
                root: rec.map(|x| x.root().to_raw()),
                outcome: "ok".into(),
                effect: Some(effect.into()),
                detail: Some("never re-dispatched".into()),
                ..r.ev()
            };
            r.record(ev);
        }
        // Registries (re-registration checks every file identity).
        for (_, f) in files {
            r.restore_file(f);
        }
        let cfg_endpoints = r.cfg.endpoints.clone();
        for (id, spec, secret) in cfg_endpoints {
            let id = EndpointId::from_raw(id);
            r.executor
                .register_endpoint(id, &spec, secret)
                .map_err(|e| StartError::Config(format!("endpoint {}: {e}", id.to_raw())))?;
            r.endpoints.insert(id);
        }
        for (id, spec) in endpoint_recs {
            if r.endpoints.contains(&id) {
                return Err(StartError::Config(format!(
                    "endpoint id {} both configured and journaled",
                    id.to_raw()
                )));
            }
            match r.executor.register_endpoint(id, &spec, None) {
                Ok(()) => {
                    r.endpoints.insert(id);
                }
                Err(e) => r.audit_error("endpoint-restore", &e),
            }
        }
        if let Some(e) = enrollment {
            r.install_enrollment(e);
        }
        Ok(r)
    }

    fn restore_file(&mut self, f: FileSlotRec) {
        match self.executor.register_file(
            f.object,
            &f.name,
            f.max_read_bytes,
            f.max_write_bytes,
            Some(f.identity),
        ) {
            Ok(_) => {
                self.file_ok.insert(f.object);
            }
            Err(e) => self.audit_error(
                "file-restore",
                &format!("object {} ({}) unavailable: {e}", f.object.to_raw(), f.name),
            ),
        }
        self.files.insert(f.object, f);
    }

    fn install_enrollment(&mut self, e: ap::Enrollment) {
        let policy = ap::VerifierPolicy {
            installation: ap::InstallationId(self.installation),
            authority_epoch: ap::AuthorityEpoch(self.state.epoch()),
            require_user_verification: self.cfg.require_user_verification,
        };
        let sc = ap::SessionConfig {
            approval_timeout: self.cfg.approval_timeout_ms,
            rate_window: self.cfg.approval_rate_window_ms,
            max_requests_per_window: self.cfg.approval_max_per_window,
        };
        self.session = Some(ap::ApprovalSession::new(e.clone(), policy, sc));
        self.enrollment = Some(e);
    }

    // ------------------------------------------------------------------
    // Main loop
    // ------------------------------------------------------------------

    pub(crate) fn run(mut self, inbox: Receiver<Inbox>) -> StopReason {
        // Dispatch workers.
        let (jtx, jrx) = mpsc::channel::<DispatchJob>();
        let jrx = Arc::new(Mutex::new(jrx));
        for i in 0..self.cfg.dispatch_workers.max(1) {
            let jrx = Arc::clone(&jrx);
            let exec = Arc::clone(&self.executor);
            let tx = self.inbox_tx.clone();
            let _ = thread::Builder::new()
                .name(format!("tessera-dispatch-{i}"))
                .spawn(move || {
                    loop {
                        let job = {
                            let g = jrx.lock().unwrap_or_else(|p| p.into_inner());
                            g.recv()
                        };
                        let Ok(job) = job else { return };
                        let result = exec.execute(&job);
                        let reservation = job.id();
                        drop(job);
                        if tx
                            .send(Inbox::DispatchDone {
                                reservation,
                                result,
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                });
        }
        self.jobs = Some(jtx);

        let reason = loop {
            let msg = match inbox.recv_timeout(Duration::from_millis(50)) {
                Ok(m) => m,
                Err(RecvTimeoutError::Timeout) => {
                    self.poll_approvals();
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => break Stop::Shutdown,
            };
            let r = self.handle(msg);
            self.poll_approvals();
            if let Err(stop) = r {
                break stop;
            }
        };
        // Whatever the reason: release nothing more, close every channel.
        self.jobs = None;
        self.channels.clear();
        self.spawner = None;
        match reason {
            Stop::Shutdown => StopReason::Shutdown,
            Stop::Killed(p) => StopReason::Killed(p),
            Stop::Journal(e) => {
                eprintln!("tessera-broker: journal failure, failing closed: {e}");
                StopReason::JournalFailure(e)
            }
            Stop::Inconsistent(e) => {
                eprintln!("tessera-broker: inconsistency, failing closed: {e}");
                StopReason::Inconsistent(e)
            }
        }
    }

    fn handle(&mut self, msg: Inbox) -> Flow {
        match msg {
            Inbox::Agent {
                agent,
                conn,
                correlation,
                request,
                digest,
            } => {
                if self.channels.get(&agent).is_some_and(|c| c.conn == conn) {
                    self.on_agent(agent, correlation, request, digest)?;
                }
                Ok(())
            }
            Inbox::ChannelClosed {
                agent,
                conn,
                violation,
            } => self.on_closed(agent, conn, violation),
            Inbox::Admin { req, reply } => {
                let resp = self.on_admin(req, &reply)?;
                if let Some(resp) = resp {
                    let _ = reply.send(resp);
                }
                Ok(())
            }
            Inbox::Attach { reply } => {
                let r = self.attach_in_process()?;
                let _ = reply.send(r);
                Ok(())
            }
            Inbox::SpawnDone {
                agent,
                result,
                reply,
            } => self.on_spawned(agent, result, reply),
            Inbox::DispatchDone {
                reservation,
                result,
            } => self.on_dispatched(reservation, result),
            Inbox::Shutdown => Err(Stop::Shutdown),
        }
    }

    // ------------------------------------------------------------------
    // Commit path
    // ------------------------------------------------------------------

    fn fault(&self, p: FaultPoint) -> Flow {
        match &self.fault {
            Some(h) if h(p) => Err(Stop::Killed(p)),
            _ => Ok(()),
        }
    }

    /// Validate, journal (durably), then apply. `Ok(Err(denial))` changes
    /// nothing and journals nothing.
    fn commit(
        &mut self,
        command: AuthenticatedCommand,
        binding: Option<Binding>,
        file_identity: Option<(ObjectId, FileIdentityRec)>,
    ) -> Result<Result<(tessera_capability_core::Effect, u64), Denial>, Stop> {
        let now = self.clock.now();
        if let Err(d) = validate_command(&self.state, &command, now) {
            return Ok(Err(d));
        }
        let entry = Entry::Command {
            tick: now,
            command,
            binding,
            file_identity,
        };
        let receipt = self.journal.append(&entry.encode()).map_err(journal_err)?;
        match step(&mut self.state, command, now) {
            Ok(eff) => {
                if let tessera_capability_core::Effect::PrincipalCreated { agent } = &eff {
                    self.principals.insert(*agent);
                }
                if let (Some(b), Some(r)) = (binding, BindingResult::of(&eff)) {
                    self.bindings.insert((b.agent, b.request_id), (b.digest, r));
                }
                Ok(Ok((eff, receipt.seq)))
            }
            Err(d) => Err(Stop::Inconsistent(format!(
                "journaled command not applicable: {d:?}"
            ))),
        }
    }

    // ------------------------------------------------------------------
    // Audit helpers
    // ------------------------------------------------------------------

    fn ev(&self) -> AuditEvent {
        AuditEvent {
            epoch: self.state.epoch(),
            tick: self.clock.now().to_raw(),
            ..AuditEvent::default()
        }
    }

    fn record(&mut self, ev: AuditEvent) {
        self.audit.record(ev);
    }

    fn audit_error(&mut self, kind: &str, detail: &str) {
        let ev = AuditEvent {
            principal: "broker".into(),
            kind: kind.into(),
            outcome: format!("error:{detail}"),
            ..self.ev()
        };
        self.record(ev);
    }

    fn cap_audit(&self, ev: &mut AuditEvent, cap: CapabilityId) {
        ev.capability = Some(cap.to_raw());
        if let Some(c) = self.state.capability(cap) {
            ev.root = Some(c.root().to_raw());
            ev.parent = c.parent().map(|p| p.to_raw());
            ev.scope = Some(cv::scope_summary(&c.scope()));
        }
    }

    fn budget_of(&self, cap: CapabilityId) -> Option<String> {
        self.state
            .capability(cap)
            .map(|c| cv::budget_summary(c.budget()))
    }

    // ------------------------------------------------------------------
    // Agent requests
    // ------------------------------------------------------------------

    fn reply(&self, agent: AgentId, correlation: u64, response: Response) {
        if let Some(ch) = self.channels.get(&agent) {
            ch.send(ServerMessage {
                correlation_id: correlation,
                response,
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn deny_agent(
        &mut self,
        agent: AgentId,
        correlation: u64,
        kind: &str,
        request_id: Option<RequestId>,
        digest: Option<[u8; 32]>,
        cap: Option<CapabilityId>,
        code: ErrorCode,
        reason: &str,
    ) {
        let mut ev = AuditEvent {
            principal: agent_str(agent),
            kind: kind.into(),
            request_id: request_id.map(|r| format!("{:x}", r.to_raw())),
            request_digest: digest.map(|d| hex(&d)),
            outcome: format!("denied:{reason}"),
            ..self.ev()
        };
        if let Some(c) = cap {
            // Record the target id, but only describe it to the audit log,
            // never to the (possibly non-owner) caller.
            self.cap_audit(&mut ev, c);
        }
        self.record(ev);
        self.reply(
            agent,
            correlation,
            error(request_id.map(|r| r.to_raw()), code, reason),
        );
    }

    fn prior_response(&self, rid: RequestId, r: BindingResult) -> Response {
        let request_id = rid.to_raw();
        match r {
            BindingResult::Granted(c) => Response::GrantIssued {
                request_id,
                cap_id: c.to_raw(),
            },
            BindingResult::Reserved(res) => Response::PriorReservation {
                request_id,
                reservation_id: u128::from(res.to_raw()),
                status: self.wire_status(res),
            },
            BindingResult::Delegated(c) => Response::Delegated {
                request_id,
                child_cap_id: c.to_raw(),
            },
            BindingResult::Attenuated(c) => Response::Attenuated {
                request_id,
                cap_id: c.to_raw(),
            },
            BindingResult::Transferred(c) => Response::Transferred {
                request_id,
                cap_id: c.to_raw(),
            },
            BindingResult::Dropped(_) => Response::Dropped { request_id },
            BindingResult::Revoked(_) => Response::Revoked { request_id },
        }
    }

    fn wire_status(&self, id: ReservationId) -> WireReservationStatus {
        match self.state.reservation(id).map(|r| r.status()) {
            Some(ReservationStatus::Reserved) if self.dispatched.contains(&id) => {
                WireReservationStatus::Dispatched
            }
            Some(ReservationStatus::Reserved) => WireReservationStatus::Reserved,
            Some(ReservationStatus::Completed) => WireReservationStatus::Completed,
            Some(ReservationStatus::Failed) => WireReservationStatus::Failed,
            _ => WireReservationStatus::Unknown,
        }
    }

    fn on_agent(&mut self, agent: AgentId, corr: u64, request: Request, digest: [u8; 32]) -> Flow {
        let kind = request_kind(&request);
        // Request-id binding (ADR-0012): same id + same content returns the
        // earlier result without any new effect; different content is
        // denied. Checked before anything else.
        if let Some(rid) = request.request_id() {
            let rid = RequestId::from_raw(rid);
            if let Some((d, r)) = self.bindings.get(&(agent, rid)).copied() {
                if d == digest {
                    let resp = self.prior_response(rid, r);
                    let ev = AuditEvent {
                        principal: agent_str(agent),
                        kind: kind.into(),
                        request_id: Some(format!("{:x}", rid.to_raw())),
                        request_digest: Some(hex(&digest)),
                        outcome: "duplicate:prior-result-returned".into(),
                        ..self.ev()
                    };
                    self.record(ev);
                    self.reply(agent, corr, resp);
                } else {
                    self.deny_agent(
                        agent,
                        corr,
                        kind,
                        Some(rid),
                        Some(digest),
                        None,
                        ErrorCode::RequestIdConflict,
                        "RequestIdConflict",
                    );
                }
                return Ok(());
            }
        }
        match request {
            Request::RequestGrant {
                request_id,
                requested_scope,
                budget,
                depth,
                expiry,
            } => {
                self.on_request_grant(
                    agent,
                    corr,
                    RequestId::from_raw(request_id),
                    digest,
                    requested_scope,
                    budget,
                    depth,
                    expiry,
                );
                Ok(())
            }
            Request::Consume {
                request_id,
                cap_id,
                operation,
            } => self.on_consume(
                agent,
                corr,
                RequestId::from_raw(request_id),
                digest,
                CapabilityId::from_raw(cap_id),
                operation,
            ),
            Request::Delegate {
                request_id,
                cap_id,
                recipient,
                child_scope,
                child_budget,
                child_depth,
                child_expiry,
            } => {
                let rid = RequestId::from_raw(request_id);
                let cap = CapabilityId::from_raw(cap_id);
                let Some(recipient) = cv::agent_from_wire(recipient) else {
                    self.deny_agent(
                        agent,
                        corr,
                        kind,
                        Some(rid),
                        Some(digest),
                        Some(cap),
                        ErrorCode::InvalidRecipient,
                        "recipient epoch out of range",
                    );
                    return Ok(());
                };
                let Some(terms) = self.child_terms(
                    agent,
                    cap,
                    child_scope,
                    child_budget,
                    child_depth,
                    child_expiry,
                ) else {
                    self.deny_agent(
                        agent,
                        corr,
                        kind,
                        Some(rid),
                        Some(digest),
                        Some(cap),
                        ErrorCode::UnknownCapability,
                        "UnknownCapability",
                    );
                    return Ok(());
                };
                self.agent_tx(
                    agent,
                    corr,
                    rid,
                    digest,
                    cap,
                    AgentCommand::Delegate {
                        capability: cap,
                        recipient,
                        terms,
                    },
                )
            }
            Request::Attenuate {
                request_id,
                cap_id,
                reduced_scope,
                budget,
                depth,
                expiry,
            } => {
                let rid = RequestId::from_raw(request_id);
                let cap = CapabilityId::from_raw(cap_id);
                let Some(terms) =
                    self.child_terms(agent, cap, reduced_scope, budget, depth, expiry)
                else {
                    self.deny_agent(
                        agent,
                        corr,
                        kind,
                        Some(rid),
                        Some(digest),
                        Some(cap),
                        ErrorCode::UnknownCapability,
                        "UnknownCapability",
                    );
                    return Ok(());
                };
                self.agent_tx(
                    agent,
                    corr,
                    rid,
                    digest,
                    cap,
                    AgentCommand::Attenuate {
                        capability: cap,
                        terms,
                    },
                )
            }
            Request::Transfer {
                request_id,
                cap_id,
                recipient,
            } => {
                let rid = RequestId::from_raw(request_id);
                let cap = CapabilityId::from_raw(cap_id);
                let Some(recipient) = cv::agent_from_wire(recipient) else {
                    self.deny_agent(
                        agent,
                        corr,
                        kind,
                        Some(rid),
                        Some(digest),
                        Some(cap),
                        ErrorCode::InvalidRecipient,
                        "recipient epoch out of range",
                    );
                    return Ok(());
                };
                self.agent_tx(
                    agent,
                    corr,
                    rid,
                    digest,
                    cap,
                    AgentCommand::Transfer {
                        capability: cap,
                        recipient,
                    },
                )
            }
            Request::Drop { request_id, cap_id } => {
                let cap = CapabilityId::from_raw(cap_id);
                self.agent_tx(
                    agent,
                    corr,
                    RequestId::from_raw(request_id),
                    digest,
                    cap,
                    AgentCommand::Drop { capability: cap },
                )
            }
            Request::Revoke { request_id, cap_id } => {
                // Agents may revoke a capability they own or a descendant of
                // one they own (core rule; ADR-0014 as amended).
                let cap = CapabilityId::from_raw(cap_id);
                self.agent_tx(
                    agent,
                    corr,
                    RequestId::from_raw(request_id),
                    digest,
                    cap,
                    AgentCommand::Revoke { capability: cap },
                )
            }
            Request::Inspect { cap_id } => {
                let cap = CapabilityId::from_raw(cap_id);
                let now = self.clock.now();
                match self.state.capability(cap) {
                    Some(c) if c.owner() == agent => {
                        let status = match self.state.live(cap, now) {
                            Ok(_) => WireCapStatus::Live,
                            Err(n) => match cv::denial_code(Denial::NotLive(n)) {
                                ErrorCode::Expired => WireCapStatus::Expired,
                                _ if c.status() == tessera_capability_core::Status::Dropped => {
                                    WireCapStatus::Dropped
                                }
                                _ => WireCapStatus::Revoked,
                            },
                        };
                        let view = WireCapabilityView {
                            cap_id: cap.to_raw(),
                            root_id: c.root().to_raw(),
                            parent: c.parent().map(|p| p.to_raw()),
                            owner: cv::agent_to_wire(c.owner()),
                            scope: cv::scope_to_wire(&c.scope()),
                            budget_remaining: cv::budget_to_wire(c.budget()),
                            depth: cv::depth_to_wire(c.depth()),
                            expires_in_millis: match c.expiry() {
                                Expiry::Never => None,
                                Expiry::At(t) => Some(t.to_raw().saturating_sub(now.to_raw())),
                            },
                            status,
                        };
                        self.reply(agent, corr, Response::Inspected(view));
                    }
                    _ => self.deny_agent(
                        agent,
                        corr,
                        kind,
                        None,
                        Some(digest),
                        Some(cap),
                        ErrorCode::UnknownCapability,
                        "UnknownCapability",
                    ),
                }
                Ok(())
            }
            Request::Spawn { request_id, .. } => {
                self.deny_agent(
                    agent,
                    corr,
                    kind,
                    Some(RequestId::from_raw(request_id)),
                    Some(digest),
                    None,
                    ErrorCode::InvalidProfile,
                    "agent-initiated spawn is not enabled in the MVP",
                );
                Ok(())
            }
        }
    }

    /// Build child / attenuated terms; `None` if the caller does not own
    /// `cap` (reported as unknown to avoid an oracle) or terms are invalid.
    fn child_terms(
        &self,
        agent: AgentId,
        cap: CapabilityId,
        scope: tessera_protocol::WireScope,
        budget: tessera_protocol::WireBudget,
        depth: tessera_protocol::WireDepth,
        expiry: tessera_protocol::WireExpiry,
    ) -> Option<tessera_capability_core::Terms> {
        let c = self.state.capability(cap).filter(|c| c.owner() == agent)?;
        Some(tessera_capability_core::Terms {
            // An empty scope is passed through as the parent's kind with no
            // rights; the core denies it as InvalidScope.
            scope: cv::scope_from_wire(&scope).unwrap_or(match c.scope() {
                Scope::File { object, .. } => Scope::File {
                    object,
                    rights: tessera_capability_core::FileRights::empty(),
                },
                Scope::Https { endpoint, .. } => Scope::Https {
                    endpoint,
                    methods: tessera_capability_core::MethodSet::empty(),
                    max_body_bytes: 0,
                },
            }),
            budget: cv::budget_from_wire(budget),
            depth: cv::depth_from_wire(depth),
            expiry: cv::expiry_from_wire(expiry, self.clock.now(), c.expiry())?,
        })
    }

    /// Generic journaled agent transaction (delegate/attenuate/transfer/
    /// drop/revoke).
    fn agent_tx(
        &mut self,
        agent: AgentId,
        corr: u64,
        rid: RequestId,
        digest: [u8; 32],
        cap: CapabilityId,
        command: AgentCommand,
    ) -> Flow {
        let kind = agent_kind(&command);
        let before = self.budget_of(cap);
        let binding = Binding {
            agent,
            request_id: rid,
            digest,
        };
        let r = self.commit(
            AuthenticatedCommand::agent(agent, command),
            Some(binding),
            None,
        )?;
        match r {
            Ok((eff, jseq)) => {
                let mut ev = AuditEvent {
                    principal: agent_str(agent),
                    kind: kind.into(),
                    journal_seq: Some(jseq),
                    request_id: Some(format!("{:x}", rid.to_raw())),
                    request_digest: Some(hex(&digest)),
                    budget_before: before,
                    budget_after: self.budget_of(cap),
                    outcome: "ok".into(),
                    ..self.ev()
                };
                self.cap_audit(&mut ev, cap);
                let resp = match BindingResult::of(&eff) {
                    Some(r) => {
                        if let BindingResult::Delegated(child) = r {
                            ev.child = Some(child.to_raw());
                            if let tessera_capability_core::Effect::Derived { owner, .. } = &eff {
                                ev.detail = Some(format!(
                                    "child owner {} budget {}",
                                    agent_str(*owner),
                                    self.budget_of(child).unwrap_or_default()
                                ));
                            }
                        }
                        self.prior_response(rid, r)
                    }
                    None => error(Some(rid.to_raw()), ErrorCode::Internal, "unexpected effect"),
                };
                self.record(ev);
                self.reply(agent, corr, resp);
            }
            Err(d) => self.deny_agent(
                agent,
                corr,
                kind,
                Some(rid),
                Some(digest),
                Some(cap),
                cv::denial_code(d),
                &format!("{d:?}"),
            ),
        }
        Ok(())
    }

    fn on_consume(
        &mut self,
        agent: AgentId,
        corr: u64,
        rid: RequestId,
        digest: [u8; 32],
        cap: CapabilityId,
        operation: WireOperation,
    ) -> Flow {
        // Look up the capability only to learn its resource; a copied id of
        // another principal is reported exactly like an unknown id.
        let Some(c) = self.state.capability(cap).filter(|c| c.owner() == agent) else {
            let reason = if self.state.capability(cap).is_some() {
                "NotOwner"
            } else {
                "UnknownCapability"
            };
            self.deny_agent(
                agent,
                corr,
                "consume",
                Some(rid),
                Some(digest),
                Some(cap),
                ErrorCode::UnknownCapability,
                reason,
            );
            return Ok(());
        };
        let (op, job_op) = match (c.scope(), operation) {
            (Scope::File { object, .. }, WireOperation::FileReadSnapshot { max_bytes }) => (
                Operation::File {
                    object,
                    right: FileRight::Read,
                },
                JobOperation::FileRead {
                    object,
                    max_bytes: max_bytes.min(MAX_INLINE_CONTENT),
                },
            ),
            (Scope::File { object, .. }, WireOperation::FileReplaceContent { bytes }) => {
                if bytes.len() as u64 > MAX_INLINE_CONTENT {
                    self.deny_agent(
                        agent,
                        corr,
                        "consume",
                        Some(rid),
                        Some(digest),
                        Some(cap),
                        ErrorCode::LimitExceeded,
                        "replacement too large",
                    );
                    return Ok(());
                }
                (
                    Operation::File {
                        object,
                        right: FileRight::Replace,
                    },
                    JobOperation::FileReplace {
                        object,
                        bytes: bytes.into_inner(),
                    },
                )
            }
            (Scope::Https { endpoint, .. }, WireOperation::Https(req)) => (
                Operation::Https {
                    endpoint,
                    method: core_method(req.method),
                    body_bytes: req.body.len() as u64,
                },
                JobOperation::Https {
                    endpoint,
                    request: req,
                },
            ),
            _ => {
                self.deny_agent(
                    agent,
                    corr,
                    "consume",
                    Some(rid),
                    Some(digest),
                    Some(cap),
                    ErrorCode::ScopeViolation,
                    "operation kind does not match capability",
                );
                return Ok(());
            }
        };
        let before = self.budget_of(cap);
        self.fault(FaultPoint::BeforeConsumeCommit)?;
        let r = self.commit(
            AuthenticatedCommand::agent(
                agent,
                AgentCommand::Consume {
                    request_id: rid,
                    capability: cap,
                    operation: op,
                },
            ),
            Some(Binding {
                agent,
                request_id: rid,
                digest,
            }),
            None,
        )?;
        match r {
            Ok((tessera_capability_core::Effect::Reserved(reservation), jseq)) => {
                let res_id = reservation.id();
                let mut ev = AuditEvent {
                    principal: agent_str(agent),
                    kind: "consume".into(),
                    journal_seq: Some(jseq),
                    request_id: Some(format!("{:x}", rid.to_raw())),
                    request_digest: Some(hex(&digest)),
                    reservation: Some(res_id.to_raw()),
                    budget_before: before,
                    budget_after: self.budget_of(cap),
                    outcome: "ok".into(),
                    effect: Some("reserved".into()),
                    detail: Some(format!("{job_op:?}")),
                    ..self.ev()
                };
                self.cap_audit(&mut ev, cap);
                let root = reservation.root().to_raw();
                self.record(ev);
                self.fault(FaultPoint::AfterConsumeCommit)?;
                // Durable dispatch-started marker, then hand off.
                self.journal
                    .append(
                        &Entry::Dispatched {
                            reservation: res_id,
                        }
                        .encode(),
                    )
                    .map_err(journal_err)?;
                self.dispatched.insert(res_id);
                self.fault(FaultPoint::AfterDispatchMarker)?;
                self.pending_dispatch.insert(
                    res_id,
                    PendingDispatch {
                        agent,
                        correlation: corr,
                        request_id: rid,
                        capability: cap,
                        root,
                    },
                );
                let job = DispatchJob {
                    reservation,
                    operation: job_op,
                };
                if let Some(j) = &self.jobs {
                    let _ = j.send(job);
                }
            }
            Ok((other, _)) => {
                // A duplicate cannot reach here (bindings are checked first).
                let resp = match BindingResult::of(&other) {
                    Some(r) => self.prior_response(rid, r),
                    None => error(Some(rid.to_raw()), ErrorCode::Internal, "unexpected effect"),
                };
                self.reply(agent, corr, resp);
            }
            Err(d) => self.deny_agent(
                agent,
                corr,
                "consume",
                Some(rid),
                Some(digest),
                Some(cap),
                cv::denial_code(d),
                &format!("{d:?}"),
            ),
        }
        Ok(())
    }

    fn on_dispatched(&mut self, reservation: ReservationId, result: ExecResult) -> Flow {
        self.fault(FaultPoint::AfterDispatchBeforeOutcome)?;
        let pending = self.pending_dispatch.remove(&reservation);
        let (outcome, effect, fid) = match &result {
            ExecResult::Completed { new_identity, .. } => {
                (Outcome::Completed, "completed", *new_identity)
            }
            ExecResult::Failed { .. } => (Outcome::Failed, "failed", None),
            ExecResult::Unknown { .. } => (Outcome::Unknown, "unknown", None),
        };
        let summary = match &result {
            ExecResult::Completed { summary, .. }
            | ExecResult::Failed { summary, .. }
            | ExecResult::Unknown { summary } => summary.clone(),
        };
        let r = self.commit(
            AuthenticatedCommand::operator(AdminCommand::RecordOutcome {
                reservation,
                outcome,
            }),
            None,
            fid,
        )?;
        let (outcome_str, jseq) = match &r {
            Ok((_, j)) => ("ok".to_string(), Some(*j)),
            Err(d) => (format!("not-recorded:{d:?}"), None),
        };
        if r.is_ok()
            && let Some((obj, id)) = fid
            && let Some(f) = self.files.get_mut(&obj)
        {
            f.identity = id;
        }
        let mut ev = AuditEvent {
            principal: pending
                .as_ref()
                .map(|p| agent_str(p.agent))
                .unwrap_or_else(|| "broker".into()),
            kind: "effect".into(),
            journal_seq: jseq,
            reservation: Some(reservation.to_raw()),
            outcome: outcome_str,
            effect: Some(effect.into()),
            detail: Some(summary),
            ..self.ev()
        };
        if let Some(p) = &pending {
            ev.request_id = Some(format!("{:x}", p.request_id.to_raw()));
            ev.capability = Some(p.capability.to_raw());
            ev.root = Some(p.root);
        }
        self.record(ev);
        self.fault(FaultPoint::AfterOutcomeBeforeResponse)?;
        let Some(p) = pending else { return Ok(()) };
        let rid = p.request_id.to_raw();
        let resp = if r.is_err() {
            // The reservation was abandoned meanwhile (emergency stop).
            error(Some(rid), ErrorCode::EffectUnknown, "reservation abandoned")
        } else {
            match result {
                ExecResult::Completed { result, .. } => Response::Consumed {
                    request_id: rid,
                    reservation_id: u128::from(reservation.to_raw()),
                    result,
                },
                ExecResult::Failed { code, .. } => {
                    error(Some(rid), code, "adapter failed; budget is not refunded")
                }
                ExecResult::Unknown { .. } => error(
                    Some(rid),
                    ErrorCode::EffectUnknown,
                    "outcome unknown; it will not be retried",
                ),
            }
        };
        self.reply(p.agent, p.correlation, resp);
        Ok(())
    }

    // ------------------------------------------------------------------
    // Grant requests and approvals
    // ------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn on_request_grant(
        &mut self,
        agent: AgentId,
        corr: u64,
        rid: RequestId,
        digest: [u8; 32],
        scope: tessera_protocol::WireScope,
        budget: tessera_protocol::WireBudget,
        depth: tessera_protocol::WireDepth,
        expiry: tessera_protocol::WireExpiry,
    ) {
        let deny = |s: &mut Self, code, why: &str| {
            s.deny_agent(
                agent,
                corr,
                "request-grant",
                Some(rid),
                Some(digest),
                None,
                code,
                why,
            )
        };
        // A repeated id while approval is pending attaches to the pending
        // request (never a second prompt); different content conflicts.
        if let Some(p) = self
            .active
            .iter_mut()
            .chain(self.queue.iter_mut())
            .find(|p| p.agent == agent && p.request_id == rid)
        {
            if p.digest != digest {
                return deny(self, ErrorCode::RequestIdConflict, "RequestIdConflict");
            }
            if p.waiters.len() < 16 {
                p.waiters.push(corr);
                return;
            }
            return deny(
                self,
                ErrorCode::RateLimited,
                "too many retries of a pending request",
            );
        }
        let (Some(enrollment), true) = (self.enrollment.clone(), self.session.is_some()) else {
            return deny(
                self,
                ErrorCode::Unavailable,
                "no approval credential enrolled",
            );
        };
        let Some(core_scope) = cv::scope_from_wire(&scope) else {
            return deny(self, ErrorCode::ScopeViolation, "empty scope");
        };
        let registered = match core_scope {
            Scope::File { object, .. } => self.file_ok.contains(&object),
            Scope::Https { endpoint, .. } => self.endpoints.contains(&endpoint),
        };
        if !registered {
            return deny(
                self,
                ErrorCode::ScopeViolation,
                "object or endpoint not registered",
            );
        }
        let core_budget = cv::budget_from_wire(budget);
        if core_budget == Budget::Finite(0) {
            return deny(self, ErrorCode::InsufficientBudget, "zero budget");
        }
        let now = self.clock.now();
        let ttl = match expiry {
            tessera_protocol::WireExpiry::Inherit => self.cfg.default_grant_ttl_ms,
            tessera_protocol::WireExpiry::WithinMillis(ms) => ms.min(self.cfg.max_grant_ttl_ms),
        };
        let (Some(grant_exp), Some(req_exp)) = (
            now.to_raw().checked_add(ttl.max(1)),
            now.to_raw()
                .checked_add(self.cfg.approval_timeout_ms.max(1)),
        ) else {
            return deny(self, ErrorCode::LimitExceeded, "expiry overflow");
        };
        let Some(ap_scope) = cv::scope_to_approval(&core_scope) else {
            return deny(self, ErrorCode::ScopeViolation, "scope not representable");
        };
        let nonce = match ap::Nonce::random() {
            Ok(n) => n,
            Err(_) => return deny(self, ErrorCode::Internal, "no randomness"),
        };
        let fields = ap::GrantRequestFields {
            protocol_version: ap::request::SUPPORTED_PROTOCOL_VERSION,
            installation: ap::InstallationId(self.installation),
            authority_epoch: ap::AuthorityEpoch(self.state.epoch()),
            operator: enrollment.operator(),
            recipient: cv::agent_to_approval(agent),
            scope: ap_scope,
            budget: cv::budget_to_approval(core_budget),
            depth: cv::depth_to_approval(cv::depth_from_wire(depth)),
            grant_expires_at: ap::Tick(grant_exp),
            nonce,
            request_expires_at: ap::Tick(req_exp),
        };
        let request = match ap::GrantRequest::new(fields) {
            Ok(r) => r,
            Err(e) => return deny(self, ErrorCode::Malformed, &e.to_string()),
        };
        if self.queue.len() >= self.cfg.approval_queue {
            return deny(self, ErrorCode::RateLimited, "approval queue full");
        }
        let ticket = self.next_ticket;
        self.next_ticket += 1;
        let ev = AuditEvent {
            principal: agent_str(agent),
            kind: "request-grant".into(),
            request_id: Some(format!("{:x}", rid.to_raw())),
            request_digest: Some(hex(&digest)),
            scope: Some(cv::scope_summary(&core_scope)),
            budget_after: Some(cv::budget_summary(core_budget)),
            outcome: "pending-approval".into(),
            detail: Some(format!(
                "ticket={ticket} approval_digest={}",
                hex(&request.digest().0)
            )),
            ..self.ev()
        };
        self.record(ev);
        self.queue.push_back(PendingGrant {
            ticket,
            agent,
            correlation: corr,
            waiters: Vec::new(),
            request_id: rid,
            digest,
            request,
        });
        self.activate_next();
    }

    fn activate_next(&mut self) {
        while self.active.is_none() {
            let Some(pg) = self.queue.pop_front() else {
                return;
            };
            let now = ap::Tick(self.clock.now().to_raw());
            let Some(session) = self.session.as_mut() else {
                self.fail_grant(pg, ErrorCode::Unavailable, "no approval credential");
                continue;
            };
            match session.begin(pg.request.clone(), now) {
                Ok(_) => self.active = Some(pg),
                Err(ap::SessionError::RateLimited) => {
                    self.fail_grant(pg, ErrorCode::RateLimited, "approval requests rate-limited")
                }
                Err(e) => self.fail_grant(pg, ErrorCode::ApprovalDenied, &e.to_string()),
            }
        }
    }

    fn fail_grant(&mut self, pg: PendingGrant, code: ErrorCode, why: &str) {
        self.deny_agent(
            pg.agent,
            pg.correlation,
            "request-grant",
            Some(pg.request_id),
            Some(pg.digest),
            None,
            code,
            why,
        );
        for c in pg.waiters {
            self.reply(pg.agent, c, error(Some(pg.request_id.to_raw()), code, why));
        }
    }

    fn poll_approvals(&mut self) {
        let now = ap::Tick(self.clock.now().to_raw());
        if let Some(s) = self.session.as_mut()
            && s.poll(now).is_some()
            && let Some(pg) = self.active.take()
        {
            self.fail_grant(pg, ErrorCode::ApprovalTimeout, "approval timed out");
        }
        if self.active.is_some()
            && self.session.as_ref().is_some_and(|s| s.pending().is_none())
            && let Some(pg) = self.active.take()
        {
            self.fail_grant(pg, ErrorCode::ApprovalTimeout, "approval closed");
        }
        // Queued requests that expired while waiting.
        let mut expired = Vec::new();
        self.queue.retain(|p| {
            let keep = p.request.fields().request_expires_at > now;
            if !keep {
                expired.push(p.ticket);
            }
            keep
        });
        let _ = expired;
        self.activate_next();
    }

    fn active_ticket(&self, ticket: u64) -> bool {
        self.active.as_ref().is_some_and(|p| p.ticket == ticket)
    }

    fn on_approve(&mut self, ticket: u64, assertion: ap::Assertion) -> Result<AdminResponse, Stop> {
        if !self.active_ticket(ticket) {
            return Ok(AdminResponse::Error(format!(
                "ticket {ticket} is not awaiting a touch"
            )));
        }
        let now = ap::Tick(self.clock.now().to_raw());
        let Some(session) = self.session.as_mut() else {
            return Ok(AdminResponse::Error("no session".into()));
        };
        // The pending request is consumed whatever the outcome.
        let verified = session.complete(&assertion, now);
        let Some(pg) = self.active.take() else {
            return Ok(AdminResponse::Error("no active request".into()));
        };
        let verified = match verified {
            Ok(v) => v,
            Err(e) => {
                let why = format!("assertion rejected: {e}");
                let ev = AuditEvent {
                    principal: "operator".into(),
                    kind: "mint".into(),
                    request_id: Some(format!("{:x}", pg.request_id.to_raw())),
                    outcome: format!("denied:{why}"),
                    detail: Some(format!("ticket={ticket} recipient={}", agent_str(pg.agent))),
                    ..self.ev()
                };
                self.record(ev);
                self.fail_grant(pg, ErrorCode::ApprovalDenied, "approval not verified");
                self.activate_next();
                return Ok(AdminResponse::Error(why));
            }
        };
        let resp = self.mint(pg, &verified)?;
        self.activate_next();
        Ok(resp)
    }

    fn mint(&mut self, pg: PendingGrant, v: &ap::VerifiedApproval) -> Result<AdminResponse, Stop> {
        let approval = match cv::core_approval(v) {
            Some(a) if a.request().recipient == pg.agent => a,
            _ => {
                self.fail_grant(
                    pg,
                    ErrorCode::ApprovalDenied,
                    "approval does not map to a grant",
                );
                return Ok(AdminResponse::Error(
                    "approval does not map to a grant".into(),
                ));
            }
        };
        self.fault(FaultPoint::BeforeMintCommit)?;
        let r = self.commit(
            AuthenticatedCommand::operator(AdminCommand::Mint { approval }),
            Some(Binding {
                agent: pg.agent,
                request_id: pg.request_id,
                digest: pg.digest,
            }),
            None,
        )?;
        match r {
            Ok((
                tessera_capability_core::Effect::RootCreated {
                    root, capability, ..
                },
                jseq,
            )) => {
                let mut ev = AuditEvent {
                    principal: "operator".into(),
                    kind: "mint".into(),
                    journal_seq: Some(jseq),
                    request_id: Some(format!("{:x}", pg.request_id.to_raw())),
                    request_digest: Some(hex(&pg.digest)),
                    budget_after: self.budget_of(capability),
                    outcome: "ok".into(),
                    detail: Some(format!(
                        "recipient={} approval_digest={} evidence={} uv={} narrowed={}",
                        agent_str(pg.agent),
                        hex(&v.request_digest().0),
                        hex(v.evidence_digest()),
                        v.user_verified(),
                        v.request() != &pg.request
                    )),
                    ..self.ev()
                };
                self.cap_audit(&mut ev, capability);
                ev.root = Some(root.to_raw());
                self.record(ev);
                self.fault(FaultPoint::AfterMintCommit)?;
                for c in pg.correlations() {
                    self.reply(
                        pg.agent,
                        c,
                        Response::GrantIssued {
                            request_id: pg.request_id.to_raw(),
                            cap_id: capability.to_raw(),
                        },
                    );
                }
                Ok(AdminResponse::Capability(capability.to_raw()))
            }
            Ok(_) => Ok(AdminResponse::Error("unexpected effect".into())),
            Err(d) => {
                self.fail_grant(pg, cv::denial_code(d), &format!("{d:?}"));
                Ok(AdminResponse::Error(format!("mint denied: {d:?}")))
            }
        }
    }

    // ------------------------------------------------------------------
    // Channels / principals
    // ------------------------------------------------------------------

    fn attach_channel(&mut self, agent: AgentId, fd: OwnedFd) -> Result<(), String> {
        let conn = self.next_conn;
        self.next_conn += 1;
        // SO_PEERCRED of a launcher socketpair names the process that created
        // it (this broker), so it is recorded for audit only; identity is the
        // channel itself (ADR-0022).
        let cred = tessera_protocol::unix::peer_credentials(&fd)
            .map(|c| format!("peercred pid={} uid={}", c.pid, c.uid))
            .unwrap_or_else(|_| "peercred unavailable".into());
        let h = conn::attach(
            agent,
            conn,
            fd,
            self.inbox_tx.clone(),
            self.cfg.agent_max_frame,
        )
        .map_err(|e| e.to_string())?;
        self.channels.insert(agent, h);
        let ev = AuditEvent {
            principal: agent_str(agent),
            kind: "channel-attached".into(),
            outcome: "ok".into(),
            detail: Some(cred),
            ..self.ev()
        };
        self.record(ev);
        Ok(())
    }

    fn create_principal(&mut self) -> Result<Result<AgentId, String>, Stop> {
        match self.commit(
            AuthenticatedCommand::operator(AdminCommand::CreatePrincipal),
            None,
            None,
        )? {
            Ok((tessera_capability_core::Effect::PrincipalCreated { agent }, jseq)) => {
                let ev = AuditEvent {
                    principal: "operator".into(),
                    kind: "create-principal".into(),
                    journal_seq: Some(jseq),
                    outcome: "ok".into(),
                    detail: Some(agent_str(agent)),
                    ..self.ev()
                };
                self.record(ev);
                Ok(Ok(agent))
            }
            Ok(_) => Ok(Err("unexpected effect".into())),
            Err(d) => Ok(Err(format!("{d:?}"))),
        }
    }

    fn attach_in_process(&mut self) -> Result<Result<(AgentId, OwnedFd), String>, Stop> {
        let agent = match self.create_principal()? {
            Ok(a) => a,
            Err(e) => return Ok(Err(e)),
        };
        let (mine, theirs) = match tessera_protocol::unix::seqpacket_pair() {
            Ok(p) => p,
            Err(e) => {
                let _ = self.terminate(agent, "socketpair failed")?;
                return Ok(Err(e.to_string()));
            }
        };
        if let Err(e) = self.attach_channel(agent, mine) {
            let _ = self.terminate(agent, "attach failed")?;
            return Ok(Err(e));
        }
        conn::size_buffers(&theirs);
        Ok(Ok((agent, theirs)))
    }

    fn on_spawned(
        &mut self,
        agent: AgentId,
        result: Result<OwnedFd, String>,
        reply: Sender<AdminResponse>,
    ) -> Flow {
        let resp = match result {
            Ok(fd) if self.state.is_active(agent) => match self.attach_channel(agent, fd) {
                Ok(()) => AdminResponse::Agent(agent),
                Err(e) => {
                    let _ = self.terminate(agent, "attach failed")?;
                    AdminResponse::Error(e)
                }
            },
            Ok(_) => AdminResponse::Error("principal no longer active".into()),
            Err(e) => {
                let _ = self.terminate(agent, "spawn failed")?;
                AdminResponse::Error(format!("spawn failed: {e}"))
            }
        };
        let _ = reply.send(resp);
        Ok(())
    }

    /// Terminate a principal: journal, close channel, stop sandbox, fail its
    /// pending grant requests.
    fn terminate(&mut self, agent: AgentId, why: &str) -> Result<Result<(), Denial>, Stop> {
        let r = if self.state.principal(agent) == Some(PrincipalStatus::Active) {
            self.commit(
                AuthenticatedCommand::operator(AdminCommand::TerminatePrincipal { agent }),
                None,
                None,
            )?
            .map(|(_, j)| Some(j))
        } else {
            Ok(None)
        };
        if let Some(ch) = self.channels.remove(&agent) {
            ch.close();
        }
        if let Some(sp) = &self.spawner {
            sp.send(SpawnerMsg::Stop(agent));
        }
        if self.active.as_ref().is_some_and(|p| p.agent == agent) {
            self.active = None;
            // Drop the outstanding touch request; a fresh one is needed.
            self.reset_session();
        }
        self.queue.retain(|p| p.agent != agent);
        let ev = AuditEvent {
            principal: agent_str(agent),
            kind: "terminate-principal".into(),
            journal_seq: r.as_ref().ok().copied().flatten(),
            outcome: match &r {
                Ok(_) => "ok".into(),
                Err(d) => format!("denied:{d:?}"),
            },
            detail: Some(why.into()),
            ..self.ev()
        };
        self.record(ev);
        Ok(r.map(|_| ()))
    }

    fn reset_session(&mut self) {
        if let Some(e) = self.enrollment.clone() {
            self.install_enrollment(e);
        }
    }

    fn on_closed(&mut self, agent: AgentId, conn: u64, violation: Option<String>) -> Flow {
        if !self.channels.get(&agent).is_some_and(|c| c.conn == conn) {
            return Ok(());
        }
        // The channel *is* the principal's identity; once it is gone the
        // principal can never act again, so it is terminated (fail closed).
        let why = match &violation {
            Some(v) => format!("channel violation: {v}"),
            None => "channel closed".into(),
        };
        let _ = self.terminate(agent, &why)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Admin endpoint
    // ------------------------------------------------------------------

    fn on_admin(
        &mut self,
        req: AdminRequest,
        reply: &Sender<AdminResponse>,
    ) -> Result<Option<AdminResponse>, Stop> {
        let now = self.clock.now();
        Ok(Some(match req {
            AdminRequest::Status => AdminResponse::Status(StatusView {
                installation: format!("{:032x}", self.installation),
                epoch: self.state.epoch(),
                sequence: self.state.sequence(),
                tick: now.to_raw(),
                principals: self
                    .principals
                    .iter()
                    .filter(|a| self.state.is_active(**a))
                    .count() as u64,
                capabilities: self.state.capabilities().count() as u64,
                enrolled: self.enrollment.is_some(),
                pending_approvals: self.active.iter().count() as u64 + self.queue.len() as u64,
                uncertain_reservations: self
                    .reservation_views(true)
                    .iter()
                    .filter(|r| r.status.starts_with("unknown"))
                    .count() as u64,
            }),
            AdminRequest::Enroll { enrollment } => match ap::Enrollment::decode(&enrollment) {
                Ok(e) => {
                    self.journal
                        .append(&Entry::Enrolled { enrollment }.encode())
                        .map_err(journal_err)?;
                    if let Some(pg) = self.active.take() {
                        self.fail_grant(pg, ErrorCode::Unavailable, "credential rotated");
                    }
                    let ev = AuditEvent {
                        principal: "operator".into(),
                        kind: "enroll".into(),
                        outcome: "ok".into(),
                        detail: Some(format!(
                            "operator={:032x} rp_id={} credential={} alg={:?}",
                            e.operator().0,
                            e.rp_id(),
                            hex(e.credential_id()),
                            e.algorithm()
                        )),
                        ..self.ev()
                    };
                    self.record(ev);
                    self.install_enrollment(e);
                    self.activate_next();
                    AdminResponse::Ok
                }
                Err(e) => AdminResponse::Error(format!("bad enrollment: {e:?}")),
            },
            AdminRequest::RegisterFile {
                name,
                max_read_bytes,
                max_write_bytes,
            } => {
                let object = ObjectId::from_raw(
                    self.files.keys().map(|o| o.to_raw()).max().unwrap_or(0) + 1,
                );
                match self.executor.register_file(
                    object,
                    &name,
                    max_read_bytes,
                    max_write_bytes,
                    None,
                ) {
                    Ok(identity) => {
                        let rec = FileSlotRec {
                            object,
                            name: name.clone(),
                            max_read_bytes,
                            max_write_bytes,
                            identity,
                        };
                        self.journal
                            .append(&Entry::FileRegistered(rec.clone()).encode())
                            .map_err(journal_err)?;
                        self.files.insert(object, rec);
                        self.file_ok.insert(object);
                        let ev = AuditEvent {
                            principal: "operator".into(),
                            kind: "register-file".into(),
                            outcome: "ok".into(),
                            detail: Some(format!("object={} name={name}", object.to_raw())),
                            ..self.ev()
                        };
                        self.record(ev);
                        AdminResponse::Object(object.to_raw())
                    }
                    Err(e) => AdminResponse::Error(e),
                }
            }
            AdminRequest::RegisterEndpoint { id, spec } => {
                let eid = EndpointId::from_raw(id);
                if self.endpoints.contains(&eid) {
                    AdminResponse::Error(format!("endpoint {id} already registered"))
                } else {
                    match self.executor.register_endpoint(eid, &spec, None) {
                        Ok(()) => {
                            self.journal
                                .append(
                                    &Entry::EndpointRegistered {
                                        id: eid,
                                        spec: spec.clone(),
                                    }
                                    .encode(),
                                )
                                .map_err(journal_err)?;
                            self.endpoints.insert(eid);
                            let ev = AuditEvent {
                                principal: "operator".into(),
                                kind: "register-endpoint".into(),
                                outcome: "ok".into(),
                                detail: Some(format!(
                                    "endpoint={id} host={}:{} prefix={}",
                                    spec.host, spec.port, spec.path_prefix
                                )),
                                ..self.ev()
                            };
                            self.record(ev);
                            AdminResponse::Object(id)
                        }
                        Err(e) => AdminResponse::Error(e),
                    }
                }
            }
            AdminRequest::CreatePrincipal { profile } => {
                if self.spawner.is_none() {
                    AdminResponse::Error("no sandbox launcher configured".into())
                } else {
                    let agent = match self.create_principal()? {
                        Ok(a) => a,
                        Err(e) => return Ok(Some(AdminResponse::Error(e))),
                    };
                    let tx = self.inbox_tx.clone();
                    let reply = reply.clone();
                    if let Some(sp) = &self.spawner {
                        sp.send(SpawnerMsg::Spawn {
                            agent,
                            profile,
                            done: Box::new(move |result| {
                                let _ = tx.send(Inbox::SpawnDone {
                                    agent,
                                    result,
                                    reply,
                                });
                            }),
                        });
                    }
                    return Ok(None);
                }
            }
            AdminRequest::TerminatePrincipal { agent } => {
                match self.terminate(agent, "operator")? {
                    Ok(()) => AdminResponse::Ok,
                    Err(d) => AdminResponse::Error(format!("{d:?}")),
                }
            }
            AdminRequest::ListPrincipals => AdminResponse::Principals(
                self.principals
                    .iter()
                    .filter(|a| a.epoch() == self.state.epoch())
                    .map(|a| PrincipalView {
                        agent: *a,
                        status: if self.state.is_active(*a) {
                            "active".into()
                        } else {
                            "terminated".into()
                        },
                        connected: self.channels.contains_key(a),
                    })
                    .collect(),
            ),
            AdminRequest::InstallBaseline {
                agent,
                scope,
                budget,
                depth,
                expiry_ms,
            } => {
                let Some(scope) = cv::scope_from_wire(&scope) else {
                    return Ok(Some(AdminResponse::Error("empty scope".into())));
                };
                let expiry = match expiry_ms {
                    None => Expiry::Never,
                    Some(ms) => match now.to_raw().checked_add(ms) {
                        Some(t) => Expiry::At(Tick::from_raw(t)),
                        None => return Ok(Some(AdminResponse::Error("expiry overflow".into()))),
                    },
                };
                let terms = tessera_capability_core::Terms {
                    scope,
                    budget: cv::budget_from_wire(budget),
                    depth: cv::depth_from_wire(depth),
                    expiry,
                };
                match self.commit(
                    AuthenticatedCommand::operator(AdminCommand::InstallBaseline {
                        recipient: agent,
                        terms,
                    }),
                    None,
                    None,
                )? {
                    Ok((tessera_capability_core::Effect::RootCreated { capability, .. }, j)) => {
                        let mut ev = AuditEvent {
                            principal: "operator".into(),
                            kind: "install-baseline".into(),
                            journal_seq: Some(j),
                            outcome: "ok".into(),
                            budget_after: self.budget_of(capability),
                            detail: Some(format!("recipient={}", agent_str(agent))),
                            ..self.ev()
                        };
                        self.cap_audit(&mut ev, capability);
                        self.record(ev);
                        AdminResponse::Capability(capability.to_raw())
                    }
                    Ok(_) => AdminResponse::Error("unexpected effect".into()),
                    Err(d) => AdminResponse::Error(format!("denied: {d:?}")),
                }
            }
            AdminRequest::ListPending => AdminResponse::Pending(self.pending_views()),
            AdminRequest::Narrow { ticket, request } => {
                if !self.active_ticket(ticket) {
                    AdminResponse::Error(format!("ticket {ticket} is not active"))
                } else {
                    match ap::GrantRequest::decode(&request) {
                        Err(e) => AdminResponse::Error(format!("bad request encoding: {e:?}")),
                        Ok(n) => {
                            let t = ap::Tick(now.to_raw());
                            match self.session.as_mut().map(|s| s.narrow(n, t).map(|_| ())) {
                                Some(Ok(())) => {
                                    let ev = AuditEvent {
                                        principal: "operator".into(),
                                        kind: "narrow".into(),
                                        outcome: "ok".into(),
                                        detail: Some(format!("ticket={ticket}")),
                                        ..self.ev()
                                    };
                                    self.record(ev);
                                    AdminResponse::Ok
                                }
                                Some(Err(e)) => AdminResponse::Error(e.to_string()),
                                None => AdminResponse::Error("no session".into()),
                            }
                        }
                    }
                }
            }
            AdminRequest::Challenge { ticket } => {
                if !self.active_ticket(ticket) {
                    AdminResponse::Error(format!("ticket {ticket} is not active"))
                } else {
                    let t = ap::Tick(now.to_raw());
                    let s = self.session.as_mut();
                    match s.map(|s| {
                        let cur = s.pending().map(|p| p.current().encode());
                        (s.assertion_request(t), cur)
                    }) {
                        Some((Ok(a), Some(cur))) => AdminResponse::Challenge(ChallengeView {
                            rp_id: a.rp_id,
                            client_data_hash: a.client_data_hash,
                            credential_id: a.credential_id,
                            require_user_verification: a.require_user_verification,
                            request: cur,
                        }),
                        Some((Err(e), _)) => AdminResponse::Error(e.to_string()),
                        _ => AdminResponse::Error("no pending request".into()),
                    }
                }
            }
            AdminRequest::Approve {
                ticket,
                credential_id,
                authenticator_data,
                signature,
            } => self.on_approve(
                ticket,
                ap::Assertion {
                    credential_id,
                    authenticator_data,
                    signature,
                },
            )?,
            AdminRequest::Deny { ticket } => {
                let t = ap::Tick(now.to_raw());
                if self.active_ticket(ticket) {
                    if let Some(s) = self.session.as_mut() {
                        let _ = s.deny(t);
                    }
                    if let Some(pg) = self.active.take() {
                        self.fail_grant(pg, ErrorCode::ApprovalDenied, "operator denied");
                    }
                    self.activate_next();
                    AdminResponse::Ok
                } else if let Some(i) = self.queue.iter().position(|p| p.ticket == ticket) {
                    if let Some(pg) = self.queue.remove(i) {
                        self.fail_grant(pg, ErrorCode::ApprovalDenied, "operator denied");
                    }
                    AdminResponse::Ok
                } else {
                    AdminResponse::Error(format!("no ticket {ticket}"))
                }
            }
            AdminRequest::Revoke { capability } => {
                let cap = CapabilityId::from_raw(capability);
                let before = self.budget_of(cap);
                match self.commit(
                    AuthenticatedCommand::operator(AdminCommand::Revoke { capability: cap }),
                    None,
                    None,
                )? {
                    Ok((_, j)) => {
                        let mut ev = AuditEvent {
                            principal: "operator".into(),
                            kind: "revoke".into(),
                            journal_seq: Some(j),
                            budget_before: before,
                            outcome: "ok".into(),
                            detail: Some(format!(
                                "authorizations before journal seq {j} stand; subtree denied after"
                            )),
                            ..self.ev()
                        };
                        self.cap_audit(&mut ev, cap);
                        self.record(ev);
                        AdminResponse::Ok
                    }
                    Err(d) => AdminResponse::Error(format!("denied: {d:?}")),
                }
            }
            AdminRequest::Inspect { capability } => AdminResponse::Caps(
                self.cap_view(CapabilityId::from_raw(capability))
                    .into_iter()
                    .collect(),
            ),
            AdminRequest::Lineage { capability } => {
                let id = CapabilityId::from_raw(capability);
                let mut ids: Vec<CapabilityId> = self.state.lineage(id);
                ids.reverse();
                // Subtree (descendants), breadth-first in id order.
                let mut frontier = vec![id];
                while let Some(p) = frontier.pop() {
                    for c in self.state.capabilities().filter(|c| c.parent() == Some(p)) {
                        ids.push(c.id());
                        frontier.push(c.id());
                    }
                }
                AdminResponse::Caps(ids.into_iter().filter_map(|i| self.cap_view(i)).collect())
            }
            AdminRequest::Tree => AdminResponse::Caps(
                self.state
                    .capabilities()
                    .map(|c| c.id())
                    .collect::<Vec<_>>()
                    .into_iter()
                    .filter_map(|i| self.cap_view(i))
                    .collect(),
            ),
            AdminRequest::Accounts => AdminResponse::Accounts(
                self.state
                    .accounts_at(now)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|a| AccountView {
                        pool: a.pool.to_raw(),
                        root: a.root.to_raw(),
                        anchor: a.anchor.to_raw(),
                        initial: a.initial,
                        consumed: a.consumed,
                        live: a.live,
                        discarded: a.discarded(),
                    })
                    .collect(),
            ),
            AdminRequest::Reservations { only_uncertain } => {
                AdminResponse::Reservations(self.reservation_views(only_uncertain))
            }
            AdminRequest::Audit { since, limit } => {
                AdminResponse::Audit(self.audit.since(since, limit.min(10_000) as usize))
            }
            AdminRequest::EmergencyStop => {
                self.emergency_stop()?;
                AdminResponse::Ok
            }
            AdminRequest::Checkpoint => {
                let cp = self.journal.checkpoint();
                AdminResponse::Checkpoint {
                    records: cp.records,
                    head: hex(&cp.hash),
                }
            }
        }))
    }

    fn emergency_stop(&mut self) -> Flow {
        self.journal.begin_new_epoch().map_err(journal_err)?;
        self.clock.reset();
        step(
            &mut self.state,
            AuthenticatedCommand::operator(AdminCommand::BumpEpoch),
            Tick::ZERO,
        )
        .map_err(|d| Stop::Inconsistent(format!("epoch bump: {d:?}")))?;
        if self.journal.current_epoch() != self.state.epoch() {
            return Err(Stop::Inconsistent("journal/ledger epoch mismatch".into()));
        }
        let agents: Vec<AgentId> = self.channels.keys().copied().collect();
        self.channels.clear();
        if let Some(sp) = &self.spawner {
            for a in agents {
                sp.send(SpawnerMsg::Stop(a));
            }
        }
        self.active = None;
        self.queue.clear();
        let epoch = self.state.epoch();
        self.bindings.retain(|(a, _), _| a.epoch() == epoch);
        self.reset_session();
        let ev = AuditEvent {
            principal: "operator".into(),
            kind: "emergency-stop".into(),
            outcome: "ok".into(),
            detail: Some("epoch bumped; all grants invalid; all sandboxes stopped".into()),
            ..self.ev()
        };
        self.record(ev);
        Ok(())
    }

    fn pending_views(&self) -> Vec<PendingView> {
        let ctx = ap::RenderContext {
            now: ap::Tick(self.clock.now().to_raw()),
            ticks_per_second: NonZeroU64::new(1000),
        };
        let mut v = Vec::new();
        if let Some(pg) = &self.active {
            let cur = self
                .session
                .as_ref()
                .and_then(|s| s.pending())
                .map(|p| p.current().clone())
                .unwrap_or_else(|| pg.request.clone());
            v.push(PendingView {
                ticket: pg.ticket,
                agent: pg.agent,
                active: true,
                rendered: ap::render_request(&cur, None, &ctx),
                request: cur.encode(),
            });
        }
        for pg in &self.queue {
            v.push(PendingView {
                ticket: pg.ticket,
                agent: pg.agent,
                active: false,
                rendered: ap::render_request(&pg.request, None, &ctx),
                request: pg.request.encode(),
            });
        }
        v
    }

    fn cap_view(&self, id: CapabilityId) -> Option<CapView> {
        let c = self.state.capability(id)?;
        let now = self.clock.now();
        Some(CapView {
            id: id.to_raw(),
            root: c.root().to_raw(),
            parent: c.parent().map(|p| p.to_raw()),
            owner: c.owner(),
            scope: cv::scope_summary(&c.scope()),
            budget: cv::budget_summary(c.budget()),
            depth: match c.depth() {
                tessera_capability_core::Depth::Finite(d) => d.to_string(),
                tessera_capability_core::Depth::Unlimited => "unlimited".into(),
            },
            expiry: match c.expiry() {
                Expiry::Never => "never".into(),
                Expiry::At(t) => format!("tick {}", t.to_raw()),
            },
            status: match self.state.live(id, now) {
                Ok(_) => "live".into(),
                Err(n) => format!("{n:?}"),
            },
            root_kind: match self.state.root(c.root()).map(|r| r.kind()) {
                Some(RootKind::Approved { .. }) => "approved".into(),
                Some(RootKind::Baseline) => "baseline".into(),
                None => "?".into(),
            },
            generation: c.generation(),
        })
    }

    fn reservation_views(&self, only_uncertain: bool) -> Vec<ReservationView> {
        (0u64..)
            .map(ReservationId::from_raw)
            .map_while(|id| self.state.reservation(id))
            .filter_map(|r| {
                let id = r.id();
                let status = match r.status() {
                    ReservationStatus::Reserved if self.dispatched.contains(&id) => "dispatched",
                    ReservationStatus::Reserved => "reserved",
                    ReservationStatus::Completed => "completed",
                    ReservationStatus::Failed => "failed",
                    ReservationStatus::Unknown => "unknown",
                    ReservationStatus::Abandoned if self.dispatched.contains(&id) => {
                        "unknown-dispatched-before-restart"
                    }
                    ReservationStatus::Abandoned => "abandoned-not-dispatched",
                };
                if only_uncertain && matches!(status, "completed" | "failed") {
                    return None;
                }
                Some(ReservationView {
                    id: id.to_raw(),
                    owner: r.owner(),
                    capability: r.capability().to_raw(),
                    root: r.root().to_raw(),
                    status: status.into(),
                    operation: format!("{:?}", r.operation()),
                })
            })
            .collect()
    }
}

pub(crate) fn agent_str(a: AgentId) -> String {
    format!("agent:{}", cv::agent_label(a))
}

fn core_method(m: tessera_protocol::HttpMethod) -> tessera_capability_core::HttpMethod {
    use tessera_capability_core::HttpMethod as C;
    use tessera_protocol::HttpMethod as W;
    match m {
        W::Get => C::Get,
        W::Head => C::Head,
        W::Post => C::Post,
        W::Put => C::Put,
        W::Patch => C::Patch,
        W::Delete => C::Delete,
    }
}

fn request_kind(r: &Request) -> &'static str {
    match r {
        Request::RequestGrant { .. } => "request-grant",
        Request::Consume { .. } => "consume",
        Request::Delegate { .. } => "delegate",
        Request::Attenuate { .. } => "attenuate",
        Request::Transfer { .. } => "transfer",
        Request::Drop { .. } => "drop",
        Request::Inspect { .. } => "inspect",
        Request::Spawn { .. } => "spawn",
        Request::Revoke { .. } => "revoke",
    }
}

fn agent_kind(c: &AgentCommand) -> &'static str {
    match c {
        AgentCommand::Consume { .. } => "consume",
        AgentCommand::Split { .. } => "split",
        AgentCommand::Delegate { .. } => "delegate",
        AgentCommand::Attenuate { .. } => "attenuate",
        AgentCommand::Transfer { .. } => "transfer",
        AgentCommand::Revoke { .. } => "revoke",
        AgentCommand::Drop { .. } => "drop",
    }
}
