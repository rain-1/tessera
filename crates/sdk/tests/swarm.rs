//! Drives the `swarm_demo` example flow (spec §12.2) against a small mock
//! ledger with four separate channels (A, B, C, D). Each channel is bound
//! to one principal, as the launcher binds one channel per sandbox. Checks
//! conservation and revocation from the agents' side.

mod common;

#[allow(dead_code)]
#[path = "../examples/swarm_demo.rs"]
mod swarm_demo;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use common::{Kind, Reply, detail, fast_config, serve};
use tessera_protocol::bounded::{BoundedBytes, BoundedVec};
use tessera_protocol::unix::seqpacket_pair;
use tessera_protocol::{
    ClientMessage, ErrorCode, Request, Response, WireAgentId, WireBudget, WireCapStatus,
    WireCapabilityView, WireDepth, WireOperation, WireOperationResult, WireScope,
};
use tessera_sdk::{AgentId, Client, ErrorCode as SdkCode};

const EPOCH: u128 = 1;

struct Cap {
    owner: u64,
    parent: Option<u128>,
    root: u128,
    scope: WireScope,
    budget: u64,
    depth: u32,
    revoked: bool,
}

#[derive(Default)]
struct Ledger {
    caps: HashMap<u128, Cap>,
    next: u128,
    dispatches: u32,
}

impl Ledger {
    fn live(&self, id: u128) -> bool {
        let mut cur = Some(id);
        while let Some(c) = cur {
            let cap = &self.caps[&c];
            if cap.revoked {
                return false;
            }
            cur = cap.parent;
        }
        true
    }

    fn total_remaining(&self) -> u64 {
        self.caps.values().map(|c| c.budget).sum()
    }

    fn handle(&mut self, me: u64, req: &Request) -> Response {
        let err = |code| Response::Error {
            request_id: req.request_id(),
            code,
            detail: detail("denied"),
        };
        // Owner check: unknown and not-yours look the same.
        let owned = |l: &Ledger, id: u128| l.caps.get(&id).is_some_and(|c| c.owner == me);
        match req.clone() {
            Request::RequestGrant {
                request_id,
                requested_scope,
                budget: WireBudget::Finite(n),
                depth: WireDepth::Finite(d),
                ..
            } => {
                self.next += 1;
                let id = self.next;
                self.caps.insert(
                    id,
                    Cap {
                        owner: me,
                        parent: None,
                        root: id,
                        scope: requested_scope,
                        budget: n,
                        depth: d,
                        revoked: false,
                    },
                );
                Response::GrantIssued {
                    request_id,
                    cap_id: id,
                }
            }
            Request::Delegate {
                request_id,
                cap_id,
                recipient,
                child_scope,
                child_budget: WireBudget::Finite(n),
                child_depth: WireDepth::Finite(d),
                ..
            } => {
                if !owned(self, cap_id) {
                    return err(ErrorCode::UnknownCapability);
                }
                if !self.live(cap_id) {
                    return err(ErrorCode::Revoked);
                }
                let p = self.caps.get_mut(&cap_id).unwrap();
                if p.depth == 0 || d >= p.depth {
                    return err(ErrorCode::DepthExhausted);
                }
                if n > p.budget {
                    return err(ErrorCode::InsufficientBudget);
                }
                p.budget -= n;
                let root = p.root;
                self.next += 1;
                let id = self.next;
                self.caps.insert(
                    id,
                    Cap {
                        owner: recipient.serial,
                        parent: Some(cap_id),
                        root,
                        scope: child_scope,
                        budget: n,
                        depth: d,
                        revoked: false,
                    },
                );
                Response::Delegated {
                    request_id,
                    child_cap_id: id,
                }
            }
            Request::Consume {
                request_id,
                cap_id,
                operation: WireOperation::Https(_),
            } => {
                if !owned(self, cap_id) {
                    return err(ErrorCode::UnknownCapability);
                }
                if !self.live(cap_id) {
                    return err(ErrorCode::Revoked);
                }
                let c = self.caps.get_mut(&cap_id).unwrap();
                if c.budget == 0 {
                    return err(ErrorCode::InsufficientBudget);
                }
                c.budget -= 1;
                self.dispatches += 1;
                Response::Consumed {
                    request_id,
                    reservation_id: u128::from(self.dispatches),
                    result: WireOperationResult::Https {
                        status: 200,
                        headers: BoundedVec::default(),
                        body: BoundedBytes::default(),
                        truncated: false,
                    },
                }
            }
            Request::Inspect { cap_id } => {
                if !owned(self, cap_id) {
                    return err(ErrorCode::UnknownCapability);
                }
                let live = self.live(cap_id);
                let c = &self.caps[&cap_id];
                Response::Inspected(WireCapabilityView {
                    cap_id,
                    root_id: c.root,
                    parent: c.parent,
                    owner: WireAgentId {
                        epoch: EPOCH,
                        serial: c.owner,
                    },
                    scope: c.scope,
                    budget_remaining: WireBudget::Finite(c.budget),
                    depth: WireDepth::Finite(c.depth),
                    expires_in_millis: None,
                    status: if live {
                        WireCapStatus::Live
                    } else {
                        WireCapStatus::Revoked
                    },
                })
            }
            _ => err(ErrorCode::PermissionDenied),
        }
    }
}

fn connect(ledger: &Arc<Mutex<Ledger>>, serial: u64) -> Client {
    let (client_fd, server_fd) = seqpacket_pair().unwrap();
    let l = ledger.clone();
    // The principal is fixed by the channel, never by message content.
    serve(
        server_fd,
        Kind::Seqpacket,
        Arc::default(),
        move |m: &ClientMessage| vec![Reply::Respond(l.lock().unwrap().handle(serial, &m.request))],
    );
    Client::from_fd_with(client_fd, fast_config()).unwrap()
}

#[test]
fn research_swarm_conserves_budget_and_revocation_is_subtree_local() {
    let ledger = Arc::new(Mutex::new(Ledger::default()));
    let id = |s| AgentId::new(EPOCH, s);
    let (a, b, c, d) = (
        connect(&ledger, 1),
        connect(&ledger, 2),
        connect(&ledger, 3),
        connect(&ledger, 4),
    );

    let alloc = swarm_demo::coordinator(&a, 7, id(2), id(3)).unwrap();
    assert_eq!(swarm_demo::log_balance("A", &a, alloc.root).unwrap(), 50);
    let cap_d = swarm_demo::worker_delegate("B", &b, alloc.b, id(4), 10).unwrap();
    assert_eq!(swarm_demo::log_balance("B", &b, alloc.b).unwrap(), 20);
    assert_eq!(swarm_demo::log_balance("C", &c, alloc.c).unwrap(), 20);
    assert_eq!(ledger.lock().unwrap().total_remaining(), 100);

    assert_eq!(swarm_demo::worker_use("D", &d, cap_d, 3, "/q").unwrap(), 3);
    assert_eq!(swarm_demo::log_balance("D", &d, cap_d).unwrap(), 7);
    assert_eq!(ledger.lock().unwrap().total_remaining(), 97);

    // Copied ids authorize nothing: C cannot use D's capability.
    let e = c
        .https_request(cap_d, tessera_sdk::HttpsRequest::get("/"))
        .unwrap_err();
    assert_eq!(e.code(), Some(SdkCode::UnknownCapability));
    // D's depth is 0: it cannot delegate further.
    let e = swarm_demo::worker_delegate("D", &d, cap_d, id(3), 1).unwrap_err();
    assert_eq!(e.code(), Some(SdkCode::DepthExhausted));

    // Operator revokes B (admin channel, not agent IPC).
    ledger
        .lock()
        .unwrap()
        .caps
        .get_mut(&alloc.b)
        .unwrap()
        .revoked = true;
    let e = swarm_demo::worker_use("D", &d, cap_d, 1, "/q").unwrap_err();
    assert_eq!(e.code(), Some(SdkCode::Revoked));
    assert_eq!(
        swarm_demo::worker_use("C", &c, alloc.c, 1, "/q").unwrap(),
        1
    );
    assert_eq!(ledger.lock().unwrap().dispatches, 4);
}
