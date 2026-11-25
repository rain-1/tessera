//! Symbolic command generator shared by `tests/model.rs` and the Verus
//! differential test (`proofs/tests/differential.rs`, which includes this
//! file by path). Symbols are resolved against the current core state so
//! that most generated commands reference existing principals/capabilities.
#![allow(dead_code)]

use proptest::prelude::*;
use tessera_capability_core::*;
// ---------------------------------------------------------------------------
// Symbolic command generation (resolved against the current state)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum Who {
    Serial(u8),
    OwnerOf,
    Stale(u8),
}

#[derive(Clone, Debug)]
pub struct STerms {
    scope: Option<Scope>,       // None: copy the source's current scope
    budget: Option<Budget>,     // None: about half of the source's finite balance
    depth: Option<Depth>,       // None: one generation below the source
    expiry: Option<Option<u8>>, // None: copy source; Some(None): Never; Some(Some(k)): now + k
}

#[derive(Clone, Debug)]
pub enum Sym {
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

pub const METHODS: [HttpMethod; 3] = [HttpMethod::Get, HttpMethod::Post, HttpMethod::Delete];

pub fn arb_scope() -> impl Strategy<Value = Scope> {
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

pub fn arb_op() -> impl Strategy<Value = Operation> {
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

pub fn arb_who() -> impl Strategy<Value = Who> {
    prop_oneof![
        6 => Just(Who::OwnerOf),
        3 => (0..5u8).prop_map(Who::Serial),
        1 => (0..5u8).prop_map(Who::Stale),
    ]
}

pub fn arb_recipient() -> impl Strategy<Value = Who> {
    prop_oneof![8 => (0..5u8).prop_map(Who::Serial), 1 => (0..5u8).prop_map(Who::Stale)]
}

pub fn arb_terms() -> impl Strategy<Value = STerms> {
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

pub fn arb_sym() -> impl Strategy<Value = Sym> {
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

pub struct Ctx<'a> {
    pub s: &'a State,
    pub now: u64,
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
    pub fn resolve(&self, sym: &Sym) -> AuthenticatedCommand {
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
