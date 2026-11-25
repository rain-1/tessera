//! # tessera-broker
//!
//! The trusted broker of spec §3, §5.2, §9 and §11 (WP3): it authenticates
//! agent IPC by channel, serializes every authority transition through one
//! writer, commits each one to the hash-chained journal before releasing
//! anything, dispatches adapter effects at most once, runs the human
//! approval flow, and serves a separate operator endpoint.
//!
//! ## Architecture
//!
//! ```text
//!  sandbox A ──seqpacket──▶ reader A ─┐                    ┌─▶ dispatch workers
//!  sandbox B ──seqpacket──▶ reader B ─┼─▶ inbox ─▶ WRITER ─┤    (file / https
//!  admin socket ─▶ admin conn ────────┤   (mpsc)  (State,  │     adapters)
//!  dispatch workers (outcomes) ───────┘           Journal, └─▶ writer A/B ─▶ sandboxes
//!                                                 approvals)
//! ```
//!
//! * **Identity = channel.** Each sandbox has its own socketpair; the reader
//!   thread is created knowing the AgentId the channel was bound to at spawn
//!   and stamps every request with it. Payload fields never name the caller
//!   ([`crate::conn`]). `SO_PEERCRED` on a launcher pair names the process
//!   that created the pair, so it is recorded but is not a cross-check
//!   (ADR-0022).
//! * **Single writer** ([`crate::reactor`]): validate → append + fdatasync
//!   → `step` → release. Not pipelined (ADR-0001).
//! * **Dispatch** happens after the durable `Consume` record *and* a durable
//!   `Dispatched` marker; the outcome is journaled before the agent sees the
//!   result. No refunds, no retries (ADR-0012).
//! * **Restart** replays the journal through the core, then bumps the epoch:
//!   every earlier grant and principal is invalid, spent nonces and history
//!   are kept, unresolved reservations are reported (`abandoned` if never
//!   dispatched, `unknown` if dispatched) and never re-dispatched
//!   (ADR-0003). The operator's emergency stop does the same in place.
//! * **Approval**: `RequestGrant` → canonical `GrantRequest` with a fresh
//!   nonce and the current epoch → `ApprovalSession` (one outstanding touch,
//!   rate-limited, queued behind) → operator approves / narrows / denies on
//!   the admin socket → assertion verified → `Mint` journaled with the nonce
//!   redemption in one record → capability id to the agent.
//!
//! See `docs/adr/0022-broker.md` for decisions and known gaps.

#![forbid(unsafe_code)]

pub mod admin;
pub mod audit;
mod broker;
pub mod clock;
pub mod config;
pub(crate) mod conn;
pub mod convert;
pub mod entry;
pub mod executor;
pub mod reactor;
pub mod softkey;
pub mod spawner;

pub use admin::{AdminClient, AdminRequest, AdminResponse};
pub use audit::{AuditCheckpoint, AuditEvent, AuditLog, AuditSync};
pub use broker::Broker;
pub use clock::{ManualClock, MonotonicClock, TickSource};
pub use entry::EndpointSpec;
pub use executor::{
    AdapterExecutor, DispatchJob, ExecResult, Executor, JobOperation, MAX_INLINE_CONTENT,
};
pub use reactor::{BrokerConfig, FaultHook, FaultPoint, Services, StartError, StopReason};
pub use spawner::{AgentSpawnProfile, BaselineGrant, LauncherSpawner, ProfileSpec, SandboxSpawner};
