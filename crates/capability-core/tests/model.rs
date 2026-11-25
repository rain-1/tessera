//! Property test: random command sequences against a deliberately naive
//! reference model.
//!
//! After every step we assert:
//! * the core and the model agree on accept/deny;
//! * `check_invariant` holds;
//! * a denial (or duplicate request) leaves the state byte-for-byte equal;
//! * every capability's owner, scope, budget, depth, expiry, status and
//!   liveness agree with the model;
//! * an independently maintained global conservation identity
//!   (Σ initial = Σ consumed + Σ explicitly discarded + Σ balances) agrees
//!   with the core's pool accounts;
//! * liveness is monotone (a capability observed dead never becomes live).

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::copy_state;
use proptest::prelude::*;
use tessera_capability_core::*;

// ---------------------------------------------------------------------------
// Reference model
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MStatus {
    Live,
    Dropped,
    Revoked,
}

#[derive(Clone, Debug)]
struct MCap {
    owner: AgentId,
    parent: Option<u128>,
    generation: u32,
    scope: Scope,
    budget: Budget,
    depth: Depth,
    expiry: Expiry,
    origin_expiry: Expiry,
    status: MStatus,
}

#[derive(Clone, Debug)]
struct Model {
    limits: Limits,
    epoch: u64,
    clock: u64,
    next_serial: u64,
    principals: BTreeMap<AgentId, bool>,
    caps: BTreeMap<u128, MCap>,
    roots: u64,
    nonces: BTreeSet<Nonce>,
    requests: BTreeMap<(AgentId, RequestId), (u128, Operation, u64)>,
    reservations: Vec<ReservationStatus>,
    // Global conservation counters, maintained independently of pools.
    total_initial: u128,
    total_consumed: u128,
    total_discarded: u128,
}

impl Model {
    fn new(limits: Limits) -> Self {
        Model {
            limits,
            epoch: 0,
            clock: 0,
            next_serial: 0,
            principals: BTreeMap::new(),
            caps: BTreeMap::new(),
            roots: 0,
            nonces: BTreeSet::new(),
            requests: BTreeMap::new(),
            reservations: Vec::new(),
            total_initial: 0,
            total_consumed: 0,
            total_discarded: 0,
        }
    }

    fn active(&self, a: AgentId) -> bool {
        a.epoch() == self.epoch && self.principals.get(&a) == Some(&true)
    }

    fn expired(e: Expiry, now: u64) -> bool {
        match e {
            Expiry::Never => false,
            Expiry::At(t) => now >= t.to_raw(),
        }
    }

    fn live(&self, id: u128, now: u64) -> bool {
        let Some(c) = self.caps.get(&id) else {
            return false;
        };
        if c.status != MStatus::Live || Self::expired(c.expiry, now) || !self.active(c.owner) {
            return false;
        }
        let mut p = c.parent;
        while let Some(pid) = p {
            let pc = &self.caps[&pid];
            if pc.status == MStatus::Revoked || Self::expired(pc.origin_expiry, now) {
                return false;
            }
            p = pc.parent;
        }
        true
    }

    fn issuable(t: &Terms, now: u64) -> bool {
        t.scope.is_well_formed() && !Self::expired(t.expiry, now) && t.budget != Budget::Finite(0)
    }

    fn full(len: usize, max: u64) -> bool {
        len as u64 >= max
    }

    fn new_cap(&mut self, owner: AgentId, parent: Option<u128>, generation: u32, t: Terms) {
        let id = self.caps.len() as u128;
        self.caps.insert(
            id,
            MCap {
                owner,
                parent,
                generation,
                scope: t.scope,
                budget: t.budget,
                depth: t.depth,
                expiry: t.expiry,
                origin_expiry: t.expiry,
                status: MStatus::Live,
            },
        );
    }

    fn owned_live(&self, caller: AgentId, id: u128, now: u64) -> bool {
        self.caps.get(&id).is_some_and(|c| c.owner == caller) && self.live(id, now)
    }

    /// Returns true iff the command is accepted; mutates only on accept.
    fn step(&mut self, cmd: &AuthenticatedCommand, now: u64) -> bool {
        let is_bump = matches!(cmd, AuthenticatedCommand::Operator(AdminCommand::BumpEpoch));
        if !is_bump && now < self.clock {
            return false;
        }
        // A repeated consume request id with identical content is accepted
        // without any state change (not even the clock).
        if let AuthenticatedCommand::Agent {
            caller,
            command:
                AgentCommand::Consume {
                    request_id,
                    capability,
                    operation,
                },
        } = *cmd
            && self.active(caller)
            && let Some((c, op, _)) = self.requests.get(&(caller, request_id))
        {
            return *c == capability.to_raw() && *op == operation;
        }
        let ok = match *cmd {
            AuthenticatedCommand::Operator(ref a) => self.admin(a, now),
            AuthenticatedCommand::Agent { caller, command } => {
                self.active(caller) && self.agent(caller, &command, now)
            }
        };
        if ok {
            self.clock = now;
        }
        ok
    }

    fn root(&mut self, recipient: AgentId, t: Terms, now: u64) -> bool {
        if !self.active(recipient)
            || !Self::issuable(&t, now)
            || Self::full(self.caps.len(), self.limits.max_capabilities)
            || Self::full(self.roots as usize, self.limits.max_roots)
        {
            return false;
        }
        if let Budget::Finite(n) = t.budget {
            self.total_initial += n as u128;
        }
        self.roots += 1;
        self.new_cap(recipient, None, 0, t);
        true
    }

    fn admin(&mut self, a: &AdminCommand, now: u64) -> bool {
        match *a {
            AdminCommand::CreatePrincipal => {
                if Self::full(self.principals.len(), self.limits.max_principals) {
                    return false;
                }
                self.principals
                    .insert(AgentId::new(self.epoch, self.next_serial), true);
                self.next_serial += 1;
                true
            }
            AdminCommand::TerminatePrincipal { agent } => match self.principals.get_mut(&agent) {
                Some(st @ true) => {
                    *st = false;
                    true
                }
                _ => false,
            },
            AdminCommand::AdvanceClock => true,
            AdminCommand::BumpEpoch => {
                self.epoch += 1;
                for v in self.principals.values_mut() {
                    *v = false;
                }
                for r in &mut self.reservations {
                    if *r == ReservationStatus::Reserved {
                        *r = ReservationStatus::Abandoned;
                    }
                }
                true
            }
            AdminCommand::Mint { approval } => {
                let req = approval.request();
                if self.nonces.contains(&approval.nonce())
                    || req.epoch != self.epoch
                    || now >= req.request_expires.to_raw()
                {
                    return false;
                }
                if self.root(req.recipient, req.terms, now) {
                    self.nonces.insert(approval.nonce());
                    true
                } else {
                    false
                }
            }
            AdminCommand::InstallBaseline { recipient, terms } => self.root(recipient, terms, now),
            AdminCommand::Revoke { capability } => self.revoke(capability.to_raw()),
            AdminCommand::RecordOutcome {
                reservation,
                outcome,
            } => match self.reservations.get_mut(reservation.to_raw() as usize) {
                Some(r @ ReservationStatus::Reserved) => {
                    *r = match outcome {
                        Outcome::Completed => ReservationStatus::Completed,
                        Outcome::Failed => ReservationStatus::Failed,
                        Outcome::Unknown => ReservationStatus::Unknown,
                    };
                    true
                }
                _ => false,
            },
        }
    }

    fn revoke(&mut self, id: u128) -> bool {
        match self.caps.get_mut(&id) {
            Some(c) if c.status != MStatus::Revoked => {
                c.status = MStatus::Revoked;
                true
            }
            _ => false,
        }
    }

    fn derive(&mut self, caller: AgentId, pid: u128, owner: AgentId, t: Terms, now: u64) -> bool {
        if !self.owned_live(caller, pid, now) {
            return false;
        }
        let p = self.caps[&pid].clone();
        let depth_ok = match (p.depth, t.depth) {
            (Depth::Finite(0), _) => false,
            (Depth::Unlimited, _) => true,
            (Depth::Finite(_), Depth::Unlimited) => false,
            (Depth::Finite(a), Depth::Finite(b)) => b < a,
        };
        let new_parent_budget = match (p.budget, t.budget) {
            (_, Budget::Finite(0)) => None,
            (Budget::Finite(b), Budget::Finite(q)) if q <= b => Some(Budget::Finite(b - q)),
            (Budget::Finite(_), _) => None,
            (Budget::Unlimited, _) => Some(Budget::Unlimited),
        };
        if !depth_ok
            || !t.scope.is_well_formed()
            || !is_subset(&t.scope, &p.scope)
            || !t.expiry.within(p.expiry)
            || !Self::issuable(&t, now)
            || p.generation + 1 > self.limits.max_lineage_length
            || Self::full(self.caps.len(), self.limits.max_capabilities)
        {
            return false;
        }
        let Some(nb) = new_parent_budget else {
            return false;
        };
        if let (Budget::Unlimited, Budget::Finite(q)) = (p.budget, t.budget) {
            self.total_initial += q as u128;
        }
        self.caps.get_mut(&pid).unwrap().budget = nb;
        self.new_cap(owner, Some(pid), p.generation + 1, t);
        true
    }

    fn agent(&mut self, caller: AgentId, cmd: &AgentCommand, now: u64) -> bool {
        match *cmd {
            AgentCommand::Consume {
                request_id,
                capability,
                operation,
            } => {
                let id = capability.to_raw();
                if let Some((c, op, _)) = self.requests.get(&(caller, request_id)) {
                    // Duplicate (accepted, no change) or conflict.
                    return *c == id && *op == operation;
                }
                if !self.owned_live(caller, id, now) {
                    return false;
                }
                let c = self.caps.get_mut(&id).unwrap();
                if !permits(&c.scope, &operation) {
                    return false;
                }
                if Self::full(self.reservations.len(), self.limits.max_reservations) {
                    return false;
                }
                match c.budget {
                    Budget::Finite(0) => return false,
                    Budget::Finite(b) => {
                        c.budget = Budget::Finite(b - 1);
                        self.total_consumed += 1;
                    }
                    Budget::Unlimited => {}
                }
                self.requests.insert(
                    (caller, request_id),
                    (id, operation, self.reservations.len() as u64),
                );
                self.reservations.push(ReservationStatus::Reserved);
                true
            }
            AgentCommand::Split { capability, terms } => {
                self.derive(caller, capability.to_raw(), caller, terms, now)
            }
            AgentCommand::Delegate {
                capability,
                recipient,
                terms,
            } => {
                self.active(recipient)
                    && self.derive(caller, capability.to_raw(), recipient, terms, now)
            }
            AgentCommand::Attenuate {
                capability,
                terms: t,
            } => {
                let id = capability.to_raw();
                if !self.owned_live(caller, id, now) {
                    return false;
                }
                let c = self.caps.get_mut(&id).unwrap();
                let budget_ok = match (c.budget, t.budget) {
                    (Budget::Finite(b), Budget::Finite(n)) => n <= b,
                    (Budget::Finite(_), Budget::Unlimited) => false,
                    (Budget::Unlimited, _) => true,
                };
                if !budget_ok
                    || !t.scope.is_well_formed()
                    || !is_subset(&t.scope, &c.scope)
                    || !t.depth.within(c.depth)
                    || !t.expiry.within(c.expiry)
                    || Self::expired(t.expiry, now)
                {
                    return false;
                }
                match (c.budget, t.budget) {
                    (Budget::Finite(b), Budget::Finite(n)) => {
                        self.total_discarded += (b - n) as u128
                    }
                    (Budget::Unlimited, Budget::Finite(n)) => self.total_initial += n as u128,
                    _ => {}
                }
                c.scope = t.scope;
                c.budget = t.budget;
                c.depth = t.depth;
                c.expiry = t.expiry;
                true
            }
            AgentCommand::Transfer {
                capability,
                recipient,
            } => {
                let id = capability.to_raw();
                if !self.owned_live(caller, id, now)
                    || !self.active(recipient)
                    || recipient == caller
                {
                    return false;
                }
                let c = self.caps.get_mut(&id).unwrap();
                c.depth = match c.depth {
                    Depth::Finite(0) => return false,
                    Depth::Finite(d) => Depth::Finite(d - 1),
                    Depth::Unlimited => Depth::Unlimited,
                };
                c.owner = recipient;
                true
            }
            AgentCommand::Revoke { capability } => {
                let id = capability.to_raw();
                let mut cur = Some(id);
                let mut authorized = false;
                while let Some(c) = cur {
                    let Some(rec) = self.caps.get(&c) else { break };
                    if rec.owner == caller {
                        authorized = true;
                        break;
                    }
                    cur = rec.parent;
                }
                authorized && self.revoke(id)
            }
            AgentCommand::Drop { capability } => {
                let id = capability.to_raw();
                if !self.owned_live(caller, id, now) {
                    return false;
                }
                let c = self.caps.get_mut(&id).unwrap();
                if let Budget::Finite(b) = c.budget {
                    self.total_discarded += b as u128;
                    c.budget = Budget::Finite(0);
                }
                c.status = MStatus::Dropped;
                true
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Symbolic command generation (resolved against the current state)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum Who {
    Serial(u8),
    OwnerOf,
    Stale(u8),
}

#[derive(Clone, Debug)]
struct STerms {
    scope: Option<Scope>,       // None: copy the source's current scope
    budget: Option<Budget>,     // None: about half of the source's finite balance
    depth: Option<Depth>,       // None: one generation below the source
    expiry: Option<Option<u8>>, // None: copy source; Some(None): Never; Some(Some(k)): now + k
}

#[derive(Clone, Debug)]
enum Sym {
    /// Re-issue the previous resolved command verbatim.
    RepeatLast,
    Create,
    Terminate(Who),
    Advance,
    Bump(u64),
    Mint {
        nonce: u8,
        wrong_epoch: bool,
        req_exp: u8,
        recipient: Who,
        terms: STerms,
    },
    Baseline {
        recipient: Who,
        terms: STerms,
    },
    AdminRevoke(u8),
    Outcome(u8, Outcome),
    Consume {
        caller: Who,
        rid: u8,
        cap: u8,
        op: Option<Operation>,
    }, // None: an op the cap's scope permits
    Split {
        caller: Who,
        cap: u8,
        terms: STerms,
    },
    Delegate {
        caller: Who,
        cap: u8,
        recipient: Who,
        terms: STerms,
    },
    Attenuate {
        caller: Who,
        cap: u8,
        terms: STerms,
    },
    Transfer {
        caller: Who,
        cap: u8,
        recipient: Who,
    },
    Revoke {
        caller: Who,
        cap: u8,
    },
    Drop {
        caller: Who,
        cap: u8,
    },
}

const METHODS: [HttpMethod; 3] = [HttpMethod::Get, HttpMethod::Post, HttpMethod::Delete];

fn arb_scope() -> impl Strategy<Value = Scope> {
    prop_oneof![
        (0..2u64, 0..4u8).prop_map(|(o, b)| Scope::File {
            object: ObjectId::from_raw(o),
            rights: FileRights::from_bits(b).unwrap()
        }),
        (0..2u64, 0..8u8, 0..4u64).prop_map(|(e, b, m)| Scope::Https {
            endpoint: EndpointId::from_raw(e),
            methods: MethodSet::from_bits(b & 0b101 | (b & 0b010) << 1)
                .unwrap_or(MethodSet::empty()),
            max_body_bytes: m
        }),
    ]
}

fn arb_op() -> impl Strategy<Value = Operation> {
    prop_oneof![
        (0..2u64, any::<bool>()).prop_map(|(o, r)| Operation::File {
            object: ObjectId::from_raw(o),
            right: if r {
                FileRight::Read
            } else {
                FileRight::Replace
            }
        }),
        (0..2u64, 0..3usize, 0..5u64).prop_map(|(e, m, b)| Operation::Https {
            endpoint: EndpointId::from_raw(e),
            method: METHODS[m],
            body_bytes: b
        }),
    ]
}

fn arb_who() -> impl Strategy<Value = Who> {
    prop_oneof![
        6 => Just(Who::OwnerOf),
        3 => (0..5u8).prop_map(Who::Serial),
        1 => (0..5u8).prop_map(Who::Stale),
    ]
}

fn arb_recipient() -> impl Strategy<Value = Who> {
    prop_oneof![8 => (0..5u8).prop_map(Who::Serial), 1 => (0..5u8).prop_map(Who::Stale)]
}

fn arb_terms() -> impl Strategy<Value = STerms> {
    (
        prop::option::weighted(0.3, arb_scope()),
        prop::option::weighted(
            0.6,
            prop_oneof![6 => (0..6u64).prop_map(Budget::Finite), 1 => Just(Budget::Unlimited)],
        ),
        prop::option::weighted(
            0.6,
            prop_oneof![4 => (0..4u32).prop_map(Depth::Finite), 1 => Just(Depth::Unlimited)],
        ),
        prop::option::weighted(0.4, prop::option::weighted(0.7, 0..25u8)),
    )
        .prop_map(|(scope, budget, depth, expiry)| STerms {
            scope,
            budget,
            depth,
            expiry,
        })
}

fn arb_sym() -> impl Strategy<Value = Sym> {
    prop_oneof![
        6 => Just(Sym::RepeatLast),
        6 => Just(Sym::Create),
        2 => arb_who().prop_map(Sym::Terminate),
        2 => Just(Sym::Advance),
        1 => (0..60u64).prop_map(Sym::Bump),
        8 => (0..6u8, prop::bool::weighted(0.1), 0..6u8, arb_recipient(), arb_terms())
            .prop_map(|(nonce, wrong_epoch, req_exp, recipient, terms)| Sym::Mint { nonce, wrong_epoch, req_exp, recipient, terms }),
        2 => (arb_recipient(), arb_terms()).prop_map(|(recipient, terms)| Sym::Baseline { recipient, terms }),
        1 => any::<u8>().prop_map(Sym::AdminRevoke),
        1 => (0..20u8, prop_oneof![Just(Outcome::Completed), Just(Outcome::Failed), Just(Outcome::Unknown)])
            .prop_map(|(r, o)| Sym::Outcome(r, o)),
        16 => (arb_who(), 0..6u8, any::<u8>(), prop::option::weighted(0.4, arb_op())).prop_map(|(caller, rid, cap, op)| Sym::Consume { caller, rid, cap, op }),
        8 => (arb_who(), any::<u8>(), arb_terms()).prop_map(|(caller, cap, terms)| Sym::Split { caller, cap, terms }),
        10 => (arb_who(), any::<u8>(), arb_recipient(), arb_terms())
            .prop_map(|(caller, cap, recipient, terms)| Sym::Delegate { caller, cap, recipient, terms }),
        4 => (arb_who(), any::<u8>(), arb_terms()).prop_map(|(caller, cap, terms)| Sym::Attenuate { caller, cap, terms }),
        4 => (arb_who(), any::<u8>(), arb_recipient()).prop_map(|(caller, cap, recipient)| Sym::Transfer { caller, cap, recipient }),
        2 => (arb_who(), any::<u8>()).prop_map(|(caller, cap)| Sym::Revoke { caller, cap }),
        2 => (arb_who(), any::<u8>()).prop_map(|(caller, cap)| Sym::Drop { caller, cap }),
    ]
}

struct Ctx<'a> {
    s: &'a State,
    now: u64,
}

impl Ctx<'_> {
    fn cap(&self, n: u8) -> CapabilityId {
        let count = self.s.capabilities().count() as u128;
        CapabilityId::from_raw(n as u128 % (count + 1))
    }
    fn who(&self, w: &Who, cap: Option<CapabilityId>) -> AgentId {
        let e = self.s.epoch();
        match w {
            Who::Serial(n) => self.serial(e, *n),
            Who::Stale(n) => self.serial(e.saturating_sub(1), *n),
            Who::OwnerOf => cap
                .and_then(|c| self.s.capability(c))
                .map(|c| AgentId::new(e, c.owner().serial()))
                .unwrap_or(self.serial(e, 0)),
        }
    }
    fn serial(&self, epoch: u64, n: u8) -> AgentId {
        // Map to existing principals of that epoch when possible.
        let in_epoch: Vec<AgentId> = (0..64)
            .map(|s| AgentId::new(epoch, s))
            .filter(|a| self.s.principal(*a).is_some())
            .collect();
        if in_epoch.is_empty() {
            AgentId::new(epoch, n as u64)
        } else {
            in_epoch[n as usize % in_epoch.len()]
        }
    }
    fn terms(&self, t: &STerms, src: Option<CapabilityId>) -> Terms {
        let src = src.and_then(|c| self.s.capability(c));
        let scope = t.scope.or(src.map(|c| c.scope())).unwrap_or(Scope::File {
            object: ObjectId::from_raw(0),
            rights: FileRights::READ,
        });
        let expiry = match t.expiry {
            None => src.map(|c| c.expiry()).unwrap_or(Expiry::Never),
            Some(None) => Expiry::Never,
            Some(Some(k)) => Expiry::At(Tick::from_raw(self.now + k as u64)),
        };
        let budget = t.budget.unwrap_or(match src.map(|c| c.budget()) {
            Some(Budget::Finite(b)) => Budget::Finite(b.div_ceil(2)),
            Some(Budget::Unlimited) => Budget::Finite(3),
            None => Budget::Finite(4),
        });
        let depth = t.depth.unwrap_or(match src.map(|c| c.depth()) {
            Some(Depth::Finite(d)) => Depth::Finite(d.saturating_sub(1)),
            Some(Depth::Unlimited) => Depth::Unlimited,
            None => Depth::Finite(2),
        });
        Terms {
            scope,
            budget,
            depth,
            expiry,
        }
    }
    fn permitted_op(&self, c: CapabilityId) -> Operation {
        match self.s.capability(c).map(|c| c.scope()) {
            Some(Scope::File { object, rights }) => Operation::File {
                object,
                right: if rights.has(FileRight::Read) {
                    FileRight::Read
                } else {
                    FileRight::Replace
                },
            },
            Some(Scope::Https {
                endpoint,
                methods,
                max_body_bytes,
            }) => Operation::Https {
                endpoint,
                method: METHODS
                    .iter()
                    .copied()
                    .find(|m| methods.has(*m))
                    .unwrap_or(HttpMethod::Get),
                body_bytes: max_body_bytes,
            },
            None => Operation::File {
                object: ObjectId::from_raw(0),
                right: FileRight::Read,
            },
        }
    }
    fn resolve(&self, sym: &Sym) -> AuthenticatedCommand {
        use AdminCommand as A;
        use AgentCommand as G;
        let op = AuthenticatedCommand::operator;
        let ag = AuthenticatedCommand::agent;
        match sym {
            Sym::RepeatLast => unreachable!("resolved by the runner"),
            Sym::Create => op(A::CreatePrincipal),
            Sym::Terminate(w) => op(A::TerminatePrincipal {
                agent: self.who(w, None),
            }),
            Sym::Advance => op(A::AdvanceClock),
            Sym::Bump(_) => op(A::BumpEpoch),
            Sym::Mint {
                nonce,
                wrong_epoch,
                req_exp,
                recipient,
                terms,
            } => {
                let req = GrantRequest {
                    epoch: self.s.epoch() + *wrong_epoch as u64,
                    recipient: self.who(recipient, None),
                    terms: self.terms(terms, None),
                    request_expires: Tick::from_raw(self.now + *req_exp as u64),
                };
                op(A::Mint {
                    approval: VerifiedApproval::new(Nonce::from_bytes([*nonce; 32]), req),
                })
            }
            Sym::Baseline { recipient, terms } => op(A::InstallBaseline {
                recipient: self.who(recipient, None),
                terms: self.terms(terms, None),
            }),
            Sym::AdminRevoke(c) => op(A::Revoke {
                capability: self.cap(*c),
            }),
            Sym::Outcome(r, o) => op(A::RecordOutcome {
                reservation: ReservationId::from_raw(*r as u64),
                outcome: *o,
            }),
            Sym::Consume {
                caller,
                rid,
                cap,
                op: o,
            } => {
                let c = self.cap(*cap);
                let operation = o.unwrap_or_else(|| self.permitted_op(c));
                ag(
                    self.who(caller, Some(c)),
                    G::Consume {
                        request_id: RequestId::from_raw(*rid as u128),
                        capability: c,
                        operation,
                    },
                )
            }
            Sym::Split { caller, cap, terms } => {
                let c = self.cap(*cap);
                ag(
                    self.who(caller, Some(c)),
                    G::Split {
                        capability: c,
                        terms: self.terms(terms, Some(c)),
                    },
                )
            }
            Sym::Delegate {
                caller,
                cap,
                recipient,
                terms,
            } => {
                let c = self.cap(*cap);
                ag(
                    self.who(caller, Some(c)),
                    G::Delegate {
                        capability: c,
                        recipient: self.who(recipient, None),
                        terms: self.terms(terms, Some(c)),
                    },
                )
            }
            Sym::Attenuate { caller, cap, terms } => {
                let c = self.cap(*cap);
                ag(
                    self.who(caller, Some(c)),
                    G::Attenuate {
                        capability: c,
                        terms: self.terms(terms, Some(c)),
                    },
                )
            }
            Sym::Transfer {
                caller,
                cap,
                recipient,
            } => {
                let c = self.cap(*cap);
                ag(
                    self.who(caller, Some(c)),
                    G::Transfer {
                        capability: c,
                        recipient: self.who(recipient, None),
                    },
                )
            }
            Sym::Revoke { caller, cap } => {
                let c = self.cap(*cap);
                ag(self.who(caller, Some(c)), G::Revoke { capability: c })
            }
            Sym::Drop { caller, cap } => {
                let c = self.cap(*cap);
                ag(self.who(caller, Some(c)), G::Drop { capability: c })
            }
        }
    }
}

fn status_of(s: Status) -> MStatus {
    match s {
        Status::Live => MStatus::Live,
        Status::Dropped => MStatus::Dropped,
        Status::Revoked => MStatus::Revoked,
    }
}

fn compare(s: &State, m: &Model, now: u64) -> Result<(), TestCaseError> {
    prop_assert_eq!(s.capabilities().count(), m.caps.len());
    prop_assert_eq!(s.epoch(), m.epoch);
    prop_assert_eq!(s.clock().to_raw(), m.clock);
    for (id, mc) in &m.caps {
        let c = s
            .capability(CapabilityId::from_raw(*id))
            .expect("cap exists");
        prop_assert_eq!(c.owner(), mc.owner);
        prop_assert_eq!(c.parent().map(|p| p.to_raw()), mc.parent);
        prop_assert_eq!(c.scope(), mc.scope);
        prop_assert_eq!(c.budget(), mc.budget);
        prop_assert_eq!(c.depth(), mc.depth);
        prop_assert_eq!(c.expiry(), mc.expiry);
        prop_assert_eq!(status_of(c.status()), mc.status);
        prop_assert_eq!(
            s.is_live(c.id(), Tick::from_raw(now)),
            m.live(*id, now),
            "liveness of {}",
            id
        );
    }
    for (i, st) in m.reservations.iter().enumerate() {
        prop_assert_eq!(
            s.reservation(ReservationId::from_raw(i as u64))
                .map(|r| r.status()),
            Some(*st)
        );
    }
    // Independent global conservation vs. the core's pools.
    let accts = s.accounts_at(Tick::from_raw(now)).expect("accounts");
    let sum = |f: fn(&PoolAccount) -> u64| accts.iter().map(|a| f(a) as u128).sum::<u128>();
    let balances: u128 = m
        .caps
        .values()
        .map(|c| match c.budget {
            Budget::Finite(b) => b as u128,
            Budget::Unlimited => 0,
        })
        .sum();
    prop_assert_eq!(sum(|a| a.initial), m.total_initial);
    prop_assert_eq!(sum(|a| a.consumed), m.total_consumed);
    prop_assert_eq!(sum(|a| a.discarded_explicit), m.total_discarded);
    prop_assert_eq!(
        m.total_initial,
        m.total_consumed + m.total_discarded + balances
    );
    prop_assert_eq!(sum(|a| a.live) + sum(|a| a.discarded_stranded), balances);
    for a in &accts {
        prop_assert_eq!(
            a.initial as u128,
            a.consumed as u128
                + a.live as u128
                + a.discarded_explicit as u128
                + a.discarded_stranded as u128
        );
    }
    Ok(())
}

fn run(limits: Limits, cmds: Vec<(Sym, u8, bool)>) -> Result<(), TestCaseError> {
    let mut s = State::new(limits);
    let mut m = Model::new(limits);
    let mut dead: BTreeSet<CapabilityId> = BTreeSet::new();
    let mut last = AuthenticatedCommand::operator(AdminCommand::AdvanceClock);
    for (sym, dt, regress) in cmds {
        let clock = s.clock().to_raw();
        let now = match sym {
            Sym::Bump(t) => t,
            _ if regress && clock > 0 => clock - 1,
            _ => clock + dt as u64,
        };
        let cmd = match sym {
            Sym::RepeatLast => last,
            _ => Ctx { s: &s, now }.resolve(&sym),
        };
        last = cmd;
        let before = copy_state(&s);
        let real = step(&mut s, cmd, Tick::from_raw(now));
        let model_ok = m.step(&cmd, now);
        prop_assert_eq!(
            real.is_ok(),
            model_ok,
            "disagreement on {:?} at {}: core {:?}",
            cmd,
            now,
            real
        );
        if let Err(_) | Ok(Effect::AlreadyReserved { .. }) = &real {
            prop_assert!(s == before, "denial or duplicate mutated state: {:?}", real);
        }
        check_invariant(&s)
            .map_err(|v| TestCaseError::fail(format!("invariant {v:?} after {cmd:?}")))?;
        compare(&s, &m, now)?;
        // Liveness monotonicity, at the committed clock (a denied
        // clock-regression request must not count as time going backwards).
        let t = s.clock();
        for c in s.capabilities() {
            if s.is_live(c.id(), t) {
                prop_assert!(
                    !dead.contains(&c.id()),
                    "capability {:?} resurrected",
                    c.id()
                );
            } else {
                dead.insert(c.id());
            }
        }
    }
    Ok(())
}

proptest! {
    // 512 cases by default; override with PROPTEST_CASES for soak runs.
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(512),
        ..ProptestConfig::default()
    })]

    #[test]
    fn core_refines_reference_model(
        cmds in prop::collection::vec((arb_sym(), 0..3u8, prop::bool::weighted(0.05)), 1..80)
    ) {
        run(Limits::default(), cmds)?;
    }

    #[test]
    fn core_refines_reference_model_tight_limits(
        cmds in prop::collection::vec((arb_sym(), 0..3u8, prop::bool::weighted(0.05)), 1..80)
    ) {
        let limits = Limits {
            max_capabilities: 8,
            max_principals: 4,
            max_roots: 3,
            max_reservations: 6,
            max_lineage_length: 2,
        };
        run(limits, cmds)?;
    }
}

/// Sanity check that the generator exercises the interesting transitions
/// (guards against a vacuous property test).
#[test]
fn generator_reaches_successful_transitions() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    let mut runner = TestRunner::deterministic();
    let strat = prop::collection::vec((arb_sym(), 0..3u8, Just(false)), 60..80);
    let mut kinds: BTreeMap<&'static str, usize> = BTreeMap::new();
    for _ in 0..200 {
        let cmds = strat.new_tree(&mut runner).unwrap().current();
        let mut s = State::new(Limits::default());
        let mut last = AuthenticatedCommand::operator(AdminCommand::AdvanceClock);
        for (sym, dt, _) in cmds {
            let now = match sym {
                Sym::Bump(t) => t,
                _ => s.clock().to_raw() + dt as u64,
            };
            let cmd = match sym {
                Sym::RepeatLast => last,
                _ => Ctx { s: &s, now }.resolve(&sym),
            };
            last = cmd;
            if let Ok(e) = step(&mut s, cmd, Tick::from_raw(now)) {
                let k = match (&cmd, e) {
                    (_, Effect::Reserved(_)) => "consume",
                    (_, Effect::AlreadyReserved { .. }) => "duplicate",
                    (
                        AuthenticatedCommand::Agent {
                            command: AgentCommand::Split { .. },
                            ..
                        },
                        _,
                    ) => "split",
                    (
                        AuthenticatedCommand::Agent {
                            command: AgentCommand::Delegate { .. },
                            ..
                        },
                        _,
                    ) => "delegate",
                    (_, Effect::Attenuated { .. }) => "attenuate",
                    (_, Effect::Transferred { .. }) => "transfer",
                    (_, Effect::Revoked { .. }) => "revoke",
                    (_, Effect::Dropped { .. }) => "drop",
                    (_, Effect::RootCreated { .. }) => "root",
                    (_, Effect::EpochAdvanced { .. }) => "epoch",
                    _ => "other",
                };
                *kinds.entry(k).or_default() += 1;
            }
        }
    }
    for k in [
        "consume",
        "duplicate",
        "split",
        "delegate",
        "attenuate",
        "transfer",
        "revoke",
        "drop",
        "root",
        "epoch",
    ] {
        assert!(
            kinds.get(k).copied().unwrap_or(0) >= 20,
            "generator rarely reaches {k}: {kinds:?}"
        );
    }
    eprintln!("successful transitions by kind: {kinds:?}");
}
