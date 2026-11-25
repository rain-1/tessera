//! Broker handle: starts the reactor thread and offers in-process access.

use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;

use tessera_capability_core::AgentId;
use tessera_journal::{Journal, Storage};

use crate::admin::{self, AdminRequest, AdminResponse};
use crate::reactor::{BrokerConfig, Inbox, Reactor, Services, StartError, StopReason};

/// Depth of the single writer's inbox.
const INBOX: usize = 4096;

/// A running broker.
pub struct Broker {
    tx: mpsc::SyncSender<Inbox>,
    join: Option<thread::JoinHandle<StopReason>>,
}

impl Broker {
    /// Recover from `journal` (replay, then a fail-closed epoch bump) and
    /// start the single writer.
    pub fn start<S: Storage + Send + 'static>(
        journal: Journal<S>,
        config: BrokerConfig,
        services: Services,
    ) -> Result<Broker, StartError> {
        let (tx, rx) = mpsc::sync_channel(INBOX);
        let reactor = Reactor::open(journal, config, services, tx.clone())?;
        let join = thread::Builder::new()
            .name("tessera-writer".into())
            .spawn(move || reactor.run(rx))
            .map_err(|e| StartError::Config(e.to_string()))?;
        Ok(Broker {
            tx,
            join: Some(join),
        })
    }

    /// Execute an operator request in process (the admin socket uses the
    /// same path). `Error("broker unavailable")` once the writer stopped.
    pub fn admin(&self, req: AdminRequest) -> AdminResponse {
        admin::call_via(&self.tx, req)
            .unwrap_or_else(|| AdminResponse::Error("broker unavailable".into()))
    }

    /// Serve the operator socket at `path` (see [`crate::admin`]).
    pub fn serve_admin(&self, path: &Path) -> std::io::Result<()> {
        let tx = self.tx.clone();
        let submit: admin::AdminSubmit = Arc::new(move |req| admin::call_via(&tx, req));
        admin::serve(path, submit).map(|_| ())
    }

    /// Create a principal bound to a fresh in-process `SOCK_SEQPACKET` pair
    /// (tests, or a trusted embedding without the launcher). Returns the
    /// principal and the *client* end of its channel.
    pub fn attach_principal(&self) -> Result<(AgentId, OwnedFd), String> {
        let (rtx, rrx) = mpsc::channel();
        self.tx
            .send(Inbox::Attach { reply: rtx })
            .map_err(|_| "broker unavailable".to_string())?;
        rrx.recv().map_err(|_| "broker unavailable".to_string())?
    }

    /// Whether the writer thread is still running.
    pub fn is_running(&self) -> bool {
        self.join.as_ref().is_some_and(|j| !j.is_finished())
    }

    /// Ask the writer to stop and wait for it.
    pub fn shutdown(mut self) -> StopReason {
        let _ = self.tx.send(Inbox::Shutdown);
        self.join_inner()
    }

    /// Wait for the writer to stop on its own (e.g. a fault-injected kill).
    pub fn wait(mut self) -> StopReason {
        self.join_inner()
    }

    fn join_inner(&mut self) -> StopReason {
        match self.join.take().map(|j| j.join()) {
            Some(Ok(r)) => r,
            _ => StopReason::Inconsistent("writer thread panicked".into()),
        }
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        if self.join.is_some() {
            let _ = self.tx.send(Inbox::Shutdown);
            let _ = self.join_inner();
        }
    }
}
