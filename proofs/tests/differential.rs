//! Differential test: the Verus-verified model (`tessera_proofs::ledger`,
//! compiled here with ghost code erased) against the production core
//! (`tessera_capability_core`).
//!
//! Random command sequences (the same generator as the core's
//! `tests/model.rs`) are fed to both. After every step we require:
//! * identical results: the same `Denial` (including `NotLive` detail and
//!   `CapacityExceeded` resource) or the same `Effect`;
//! * identical observable state: epoch, sequence, clock, every principal,
//!   every capability record (all fields), every root record, every pool's
//!   `initial`/`consumed`/`discarded`, every reservation record, the spent
//!   nonce set, and `live` (with the same `NotLive` reason) for every
//!   capability.
//!
//! This is what keeps the proved model from drifting away from the code
//! that actually runs: any behavioural change to `crates/capability-core`
//! that is not mirrored in `proofs/src` fails this test.

#[path = "../../crates/capability-core/tests/common/sym.rs"]
mod sym;

use proptest::prelude::*;
use sym::*;
use tessera_capability_core as core;
use tessera_proofs::ledger as m;
use tessera_proofs::quantity as mq;
use tessera_proofs::scope as ms;

// ---------------------------------------------------------------------------
// core -> model conversions (injective on every field)
// ---------------------------------------------------------------------------

fn agent(a: core::AgentId) -> m::AgentId {
    m::AgentId {
        epoch: a.epoch(),
        serial: a.serial(),
    }
}

fn nonce(n: core::Nonce) -> m::Nonce {
    let b = n.as_bytes();
    m::Nonce {
        hi: u128::from_be_bytes(b[..16].try_into().unwrap()),
        lo: u128::from_be_bytes(b[16..].try_into().unwrap()),
    }
}

fn tick(t: core::Tick) -> mq::Tick {
    mq::Tick(t.to_raw())
}

fn budget(b: core::Budget) -> mq::Budget {
    match b {
        core::Budget::Finite(n) => mq::Budget::Finite(n),
        core::Budget::Unlimited => mq::Budget::Unlimited,
    }
}

fn depth(d: core::Depth) -> mq::Depth {
    match d {
        core::Depth::Finite(n) => mq::Depth::Finite(n),
        core::Depth::Unlimited => mq::Depth::Unlimited,
    }
}

fn expiry(e: core::Expiry) -> mq::Expiry {
    match e {
        core::Expiry::At(t) => mq::Expiry::At(tick(t)),
        core::Expiry::Never => mq::Expiry::Never,
    }
}

fn scope(s: core::Scope) -> ms::Scope {
    match s {
        core::Scope::File { object, rights } => ms::Scope::File {
            object: ms::ObjectId(object.to_raw()),
            rights: ms::FileRights(rights.bits()),
        },
        core::Scope::Https {
            endpoint,
            methods,
            max_body_bytes,
        } => ms::Scope::Https {
            endpoint: ms::EndpointId(endpoint.to_raw()),
            methods: ms::MethodSet(methods.bits()),
            max_body_bytes,
        },
    }
}

fn method(h: core::HttpMethod) -> ms::HttpMethod {
    match h {
        core::HttpMethod::Get => ms::HttpMethod::Get,
        core::HttpMethod::Head => ms::HttpMethod::Head,
        core::HttpMethod::Post => ms::HttpMethod::Post,
        core::HttpMethod::Put => ms::HttpMethod::Put,
        core::HttpMethod::Patch => ms::HttpMethod::Patch,
        core::HttpMethod::Delete => ms::HttpMethod::Delete,
    }
}

fn operation(o: core::Operation) -> ms::Operation {
    match o {
        core::Operation::File { object, right } => ms::Operation::File {
            object: ms::ObjectId(object.to_raw()),
            right: match right {
                core::FileRight::Read => ms::FileRight::Read,
                core::FileRight::Replace => ms::FileRight::Replace,
            },
        },
        core::Operation::Https {
            endpoint,
            method: h,
            body_bytes,
        } => ms::Operation::Https {
            endpoint: ms::EndpointId(endpoint.to_raw()),
            method: method(h),
            body_bytes,
        },
    }
}

fn terms(t: core::Terms) -> m::Terms {
    m::Terms {
        scope: scope(t.scope),
        budget: budget(t.budget),
        depth: depth(t.depth),
        expiry: expiry(t.expiry),
    }
}

fn limits(l: core::Limits) -> m::Limits {
    m::Limits {
        max_capabilities: l.max_capabilities,
        max_principals: l.max_principals,
        max_roots: l.max_roots,
        max_reservations: l.max_reservations,
        max_lineage_length: l.max_lineage_length,
    }
}

fn outcome(o: core::Outcome) -> m::Outcome {
    match o {
        core::Outcome::Completed => m::Outcome::Completed,
        core::Outcome::Failed => m::Outcome::Failed,
        core::Outcome::Unknown => m::Outcome::Unknown,
    }
}

fn command(c: core::AuthenticatedCommand) -> m::AuthenticatedCommand {
    use core::AdminCommand as A;
    use core::AgentCommand as G;
    match c {
        core::AuthenticatedCommand::Operator(a) => m::AuthenticatedCommand::Operator(match a {
            A::CreatePrincipal => m::AdminCommand::CreatePrincipal,
            A::TerminatePrincipal { agent: a } => {
                m::AdminCommand::TerminatePrincipal { agent: agent(a) }
            }
            A::AdvanceClock => m::AdminCommand::AdvanceClock,
            A::BumpEpoch => m::AdminCommand::BumpEpoch,
            // ADR-0031: compaction renumbers nothing but leaves sparse ids,
            // which the mirror's index-as-id representation cannot express.
            // The generator used here (`arb_sym`) never emits it; it is
            // covered by the production model test instead.
            A::CompactEpoch => unreachable!("CompactEpoch is outside the mirrored command set"),
            A::Mint { approval } => {
                let r = approval.request();
                m::AdminCommand::Mint {
                    approval: m::VerifiedApproval {
                        nonce: nonce(approval.nonce()),
                        request: m::GrantRequest {
                            epoch: r.epoch,
                            recipient: agent(r.recipient),
                            terms: terms(r.terms),
                            request_expires: tick(r.request_expires),
                        },
                    },
                }
            }
            A::InstallBaseline {
                recipient,
                terms: t,
            } => m::AdminCommand::InstallBaseline {
                recipient: agent(recipient),
                terms: terms(t),
            },
            A::Revoke { capability } => m::AdminCommand::Revoke {
                capability: capability.to_raw(),
            },
            A::RecordOutcome {
                reservation,
                outcome: o,
            } => m::AdminCommand::RecordOutcome {
                reservation: reservation.to_raw(),
                outcome: outcome(o),
            },
        }),
        core::AuthenticatedCommand::Agent { caller, command } => m::AuthenticatedCommand::Agent {
            caller: agent(caller),
            command: match command {
                G::Consume {
                    request_id,
                    capability,
                    operation: o,
                } => m::AgentCommand::Consume {
                    request_id: request_id.to_raw(),
                    capability: capability.to_raw(),
                    operation: operation(o),
                },
                G::Split {
                    capability,
                    terms: t,
                } => m::AgentCommand::Split {
                    capability: capability.to_raw(),
                    terms: terms(t),
                },
                G::Delegate {
                    capability,
                    recipient,
                    terms: t,
                } => m::AgentCommand::Delegate {
                    capability: capability.to_raw(),
                    recipient: agent(recipient),
                    terms: terms(t),
                },
                G::Attenuate {
                    capability,
                    terms: t,
                } => m::AgentCommand::Attenuate {
                    capability: capability.to_raw(),
                    terms: terms(t),
                },
                G::Transfer {
                    capability,
                    recipient,
                } => m::AgentCommand::Transfer {
                    capability: capability.to_raw(),
                    recipient: agent(recipient),
                },
                G::Revoke { capability } => m::AgentCommand::Revoke {
                    capability: capability.to_raw(),
                },
                G::Drop { capability } => m::AgentCommand::Drop {
                    capability: capability.to_raw(),
                },
            },
        },
    }
}

fn not_live(n: core::NotLive) -> m::NotLive {
    use core::NotLive as N;
    match n {
        N::Unknown => m::NotLive::Unknown,
        N::Revoked => m::NotLive::Revoked,
        N::Dropped => m::NotLive::Dropped,
        N::Expired => m::NotLive::Expired,
        N::AncestorRevoked(c) => m::NotLive::AncestorRevoked(c.to_raw()),
        N::AncestorExpired(c) => m::NotLive::AncestorExpired(c.to_raw()),
        N::OwnerTerminated => m::NotLive::OwnerTerminated,
        N::OwnerUnknown => m::NotLive::OwnerUnknown,
        N::StaleEpoch => m::NotLive::StaleEpoch,
        N::LineageCorrupt => m::NotLive::LineageCorrupt,
    }
}

fn denial(d: core::Denial) -> m::Denial {
    use core::Denial as D;
    match d {
        D::ClockRegression => m::Denial::ClockRegression,
        D::StaleEpoch => m::Denial::StaleEpoch,
        D::UnknownPrincipal => m::Denial::UnknownPrincipal,
        D::PrincipalTerminated => m::Denial::PrincipalTerminated,
        D::UnknownCapability => m::Denial::UnknownCapability,
        D::NotOwner => m::Denial::NotOwner,
        D::NotLive(n) => m::Denial::NotLive(not_live(n)),
        D::OperationNotPermitted => m::Denial::OperationNotPermitted,
        D::InsufficientBudget => m::Denial::InsufficientBudget,
        D::NotDelegatable => m::Denial::NotDelegatable,
        D::InvalidScope => m::Denial::InvalidScope,
        D::ScopeNotAttenuated => m::Denial::ScopeNotAttenuated,
        D::BudgetNotAttenuated => m::Denial::BudgetNotAttenuated,
        D::DepthNotAttenuated => m::Denial::DepthNotAttenuated,
        D::ExpiryNotAttenuated => m::Denial::ExpiryNotAttenuated,
        D::AlreadyExpired => m::Denial::AlreadyExpired,
        D::ZeroAllocation => m::Denial::ZeroAllocation,
        D::SelfTransfer => m::Denial::SelfTransfer,
        D::NotAuthorizedToRevoke => m::Denial::NotAuthorizedToRevoke,
        D::AlreadyRevoked => m::Denial::AlreadyRevoked,
        D::AlreadyTerminated => m::Denial::AlreadyTerminated,
        D::NonceReused => m::Denial::NonceReused,
        D::ApprovalEpochMismatch => m::Denial::ApprovalEpochMismatch,
        D::ApprovalExpired => m::Denial::ApprovalExpired,
        D::RequestIdConflict => m::Denial::RequestIdConflict,
        D::UnknownReservation => m::Denial::UnknownReservation,
        D::ReservationAlreadyResolved => m::Denial::ReservationAlreadyResolved,
        D::CapacityExceeded(r) => m::Denial::CapacityExceeded(match r {
            core::Resource::Capabilities => m::Resource::Capabilities,
            core::Resource::Principals => m::Resource::Principals,
            core::Resource::Roots => m::Resource::Roots,
            core::Resource::Reservations => m::Resource::Reservations,
        }),
        D::LineageTooLong => m::Denial::LineageTooLong,
        D::ArithmeticOverflow => m::Denial::ArithmeticOverflow,
    }
}

fn res_status(s: core::ReservationStatus) -> m::ReservationStatus {
    match s {
        core::ReservationStatus::Reserved => m::ReservationStatus::Reserved,
        core::ReservationStatus::Completed => m::ReservationStatus::Completed,
        core::ReservationStatus::Failed => m::ReservationStatus::Failed,
        core::ReservationStatus::Unknown => m::ReservationStatus::Unknown,
        core::ReservationStatus::Abandoned => m::ReservationStatus::Abandoned,
    }
}

fn root_kind(k: core::RootKind) -> m::RootKind {
    match k {
        core::RootKind::Approved { nonce: n } => m::RootKind::Approved { nonce: nonce(n) },
        core::RootKind::Baseline => m::RootKind::Baseline,
    }
}

fn effect(e: &core::Effect) -> m::Effect {
    use core::Effect as E;
    match e {
        E::PrincipalCreated { agent: a } => m::Effect::PrincipalCreated { agent: agent(*a) },
        E::PrincipalTerminated { agent: a } => m::Effect::PrincipalTerminated { agent: agent(*a) },
        E::ClockAdvanced { now } => m::Effect::ClockAdvanced { now: tick(*now) },
        E::EpochAdvanced {
            epoch,
            terminated_principals,
            abandoned_reservations,
        } => m::Effect::EpochAdvanced {
            epoch: *epoch,
            terminated_principals: *terminated_principals,
            abandoned_reservations: *abandoned_reservations,
        },
        E::EpochCompacted { .. } => unreachable!("CompactEpoch is never generated here"),
        E::RootCreated {
            root,
            capability,
            kind,
        } => m::Effect::RootCreated {
            root: root.to_raw(),
            capability: capability.to_raw(),
            kind: root_kind(*kind),
        },
        E::Reserved(r) => m::Effect::Reserved {
            reservation: r.id().to_raw(),
        },
        E::AlreadyReserved {
            reservation,
            status,
        } => m::Effect::AlreadyReserved {
            reservation: reservation.to_raw(),
            status: res_status(*status),
        },
        E::Derived {
            parent,
            child,
            owner,
        } => m::Effect::Derived {
            parent: parent.to_raw(),
            child: child.to_raw(),
            owner: agent(*owner),
        },
        E::Attenuated {
            capability,
            discarded,
        } => m::Effect::Attenuated {
            capability: capability.to_raw(),
            discarded: *discarded,
        },
        E::Transferred {
            capability,
            from,
            to,
        } => m::Effect::Transferred {
            capability: capability.to_raw(),
            from: agent(*from),
            to: agent(*to),
        },
        E::Revoked { capability } => m::Effect::Revoked {
            capability: capability.to_raw(),
        },
        E::Dropped {
            capability,
            discarded,
        } => m::Effect::Dropped {
            capability: capability.to_raw(),
            discarded: *discarded,
        },
        E::OutcomeRecorded {
            reservation,
            status,
        } => m::Effect::OutcomeRecorded {
            reservation: reservation.to_raw(),
            status: res_status(*status),
        },
    }
}

fn status(s: core::Status) -> m::Status {
    match s {
        core::Status::Live => m::Status::Live,
        core::Status::Dropped => m::Status::Dropped,
        core::Status::Revoked => m::Status::Revoked,
    }
}

// ---------------------------------------------------------------------------
// State comparison
// ---------------------------------------------------------------------------

fn compare(s: &core::State, ms_: &m::State, now: u64) -> Result<(), TestCaseError> {
    prop_assert_eq!(limits(s.limits()), ms_.limits);
    prop_assert_eq!(s.epoch(), ms_.epoch);
    prop_assert_eq!(s.sequence(), ms_.sequence);
    prop_assert_eq!(s.clock().to_raw(), ms_.clock.0);

    // Principals: dense by serial, keyed by (epoch, serial) in the core.
    for (serial, p) in ms_.principals.iter().enumerate() {
        let a = core::AgentId::new(p.epoch, serial as u64);
        let st = s.principal(a);
        prop_assert_eq!(
            st.map(|x| matches!(x, core::PrincipalStatus::Active)),
            Some(matches!(p.status, m::PrincipalStatus::Active)),
            "principal {:?}",
            a
        );
    }
    // No principal exists in the core beyond the model's serial range.
    let n = ms_.principals.len() as u64;
    for e in 0..=s.epoch() {
        prop_assert!(s.principal(core::AgentId::new(e, n)).is_none());
    }

    // Capabilities: every field.
    prop_assert_eq!(s.capabilities().count(), ms_.capabilities.len());
    for (i, mc) in ms_.capabilities.iter().enumerate() {
        let id = core::CapabilityId::from_raw(i as u128);
        let c = s.capability(id).expect("capability present in core");
        prop_assert_eq!(c.root().to_raw(), mc.root);
        prop_assert_eq!(c.parent().map(|p| p.to_raw()), mc.parent);
        prop_assert_eq!(agent(c.owner()), mc.owner);
        prop_assert_eq!(terms(c.origin()), mc.origin);
        prop_assert_eq!(scope(c.scope()), mc.scope);
        prop_assert_eq!(budget(c.budget()), mc.budget);
        prop_assert_eq!(depth(c.depth()), mc.depth);
        prop_assert_eq!(expiry(c.expiry()), mc.expiry);
        prop_assert_eq!(c.pool().map(|p| p.to_raw()), mc.pool);
        prop_assert_eq!(c.generation(), mc.generation);
        prop_assert_eq!(status(c.status()), mc.status);
        // Liveness, with the exact reason.
        let t = core::Tick::from_raw(now);
        let core_live = s.live(id, t).map(|_| ()).map_err(not_live);
        let model_live = ms_.live(i as u128, mq::Tick(now)).map(|_| ());
        prop_assert_eq!(core_live, model_live, "live({}) at {}", i, now);
    }

    // Roots.
    prop_assert_eq!(s.roots().count(), ms_.roots.len());
    for (i, mr) in ms_.roots.iter().enumerate() {
        let r = s
            .root(core::RootId::from_raw(i as u128))
            .expect("root present in core");
        prop_assert_eq!(r.capability().to_raw(), mr.capability);
        prop_assert_eq!(root_kind(r.kind()), mr.kind);
        prop_assert_eq!(agent(r.recipient()), mr.recipient);
        prop_assert_eq!(terms(r.terms()), mr.terms);
        prop_assert_eq!(r.epoch(), mr.epoch);
        prop_assert_eq!(r.issued_at().to_raw(), mr.issued_at.0);
    }

    // Pools (via the core's public accounting view).
    let accts = s.accounts_at(core::Tick::from_raw(now)).expect("accounts");
    prop_assert_eq!(accts.len(), ms_.pools.len());
    for a in &accts {
        let mp = &ms_.pools[a.pool.to_raw() as usize];
        prop_assert_eq!(a.root.to_raw(), mp.root);
        prop_assert_eq!(a.anchor.to_raw(), mp.anchor);
        prop_assert_eq!(a.initial, mp.initial);
        prop_assert_eq!(a.consumed, mp.consumed);
        prop_assert_eq!(a.discarded_explicit, mp.discarded);
    }

    // Spent nonces: the model's entries are exactly the core's set (the
    // core's map is in bijection with approved roots, see check_invariant).
    let approved = s
        .roots()
        .filter(|r| matches!(r.kind(), core::RootKind::Approved { .. }))
        .count();
    prop_assert_eq!(approved, ms_.spent_nonces.len());
    for sn in &ms_.spent_nonces {
        let r = s.root(core::RootId::from_raw(sn.root)).expect("nonce root");
        match r.kind() {
            core::RootKind::Approved { nonce: n } => {
                prop_assert_eq!(nonce(n), sn.nonce);
                prop_assert!(s.is_nonce_spent(&n));
            }
            core::RootKind::Baseline => prop_assert!(false, "nonce for baseline root"),
        }
    }

    // Reservations.
    for (i, mr) in ms_.reservations.iter().enumerate() {
        let r = s
            .reservation(core::ReservationId::from_raw(i as u64))
            .expect("reservation present in core");
        prop_assert_eq!(agent(r.owner()), mr.owner);
        prop_assert_eq!(r.request_id().to_raw(), mr.request_id);
        prop_assert_eq!(r.capability().to_raw(), mr.capability);
        prop_assert_eq!(r.root().to_raw(), mr.root);
        prop_assert_eq!(r.pool().map(|p| p.to_raw()), mr.pool);
        prop_assert_eq!(operation(r.operation()), mr.operation);
        prop_assert_eq!(res_status(r.status()), mr.status);
        prop_assert_eq!(r.reserved_at().to_raw(), mr.reserved_at.0);
        // Request-id index agrees.
        let via = s
            .reservation_for_request(r.owner(), r.request_id())
            .map(|x| x.id().to_raw());
        prop_assert_eq!(via, Some(i as u64));
    }
    prop_assert!(s
        .reservation(core::ReservationId::from_raw(ms_.reservations.len() as u64))
        .is_none());
    Ok(())
}

fn run(l: core::Limits, cmds: Vec<(Sym, u8, bool)>) -> Result<(), TestCaseError> {
    let mut s = core::State::new(l);
    let mut model = m::State::new(limits(l));
    let mut last = core::AuthenticatedCommand::operator(core::AdminCommand::AdvanceClock);
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
        let real = core::step(&mut s, cmd, core::Tick::from_raw(now));
        let mine = model.step(command(cmd), mq::Tick(now));
        let real_conv = real.as_ref().map(effect).map_err(|d| denial(*d));
        prop_assert_eq!(real_conv, mine, "result of {:?} at {}", cmd, now);
        compare(&s, &model, now)?;
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(512),
        ..ProptestConfig::default()
    })]

    #[test]
    fn verified_model_agrees_with_core(
        cmds in prop::collection::vec((arb_sym(), 0..3u8, prop::bool::weighted(0.05)), 1..80)
    ) {
        run(core::Limits::default(), cmds)?;
    }

    #[test]
    fn verified_model_agrees_with_core_tight_limits(
        cmds in prop::collection::vec((arb_sym(), 0..3u8, prop::bool::weighted(0.05)), 1..80)
    ) {
        let l = core::Limits {
            max_capabilities: 8,
            max_principals: 4,
            max_roots: 3,
            max_reservations: 6,
            max_lineage_length: 2,
        };
        run(l, cmds)?;
    }

    /// Pure functions on arbitrary inputs (not only generator-reachable ones).
    #[test]
    fn scope_and_quantity_functions_agree(
        cb in any::<u8>(), pb in any::<u8>(), o1 in 0..3u64, o2 in 0..3u64,
        x in any::<u64>(), y in any::<u64>(), d1 in any::<u32>(), d2 in any::<u32>(),
        right in any::<bool>(), mi in 0..6usize, unl in any::<(bool, bool)>(),
    ) {
        // Bitset decoding.
        prop_assert_eq!(core::FileRights::from_bits(cb).map(|r| r.bits()), ms::FileRights::from_bits(cb).map(|r| r.0));
        prop_assert_eq!(core::MethodSet::from_bits(cb).map(|r| r.bits()), ms::MethodSet::from_bits(cb).map(|r| r.0));
        let methods = [core::HttpMethod::Get, core::HttpMethod::Head, core::HttpMethod::Post,
                       core::HttpMethod::Put, core::HttpMethod::Patch, core::HttpMethod::Delete];
        if let (Some(cr), Some(pr)) = (core::FileRights::from_bits(cb & 3), core::FileRights::from_bits(pb & 3)) {
            let c = core::Scope::File { object: core::ObjectId::from_raw(o1), rights: cr };
            let p = core::Scope::File { object: core::ObjectId::from_raw(o2), rights: pr };
            let op = core::Operation::File { object: core::ObjectId::from_raw(o1),
                right: if right { core::FileRight::Read } else { core::FileRight::Replace } };
            prop_assert_eq!(core::is_subset(&c, &p), ms::is_subset(&scope(c), &scope(p)));
            prop_assert_eq!(core::permits(&c, &op), ms::permits(&scope(c), &operation(op)));
            prop_assert_eq!(c.is_well_formed(), scope(c).is_well_formed());
        }
        if let (Some(cm), Some(pm)) = (core::MethodSet::from_bits(cb & 63), core::MethodSet::from_bits(pb & 63)) {
            let c = core::Scope::Https { endpoint: core::EndpointId::from_raw(o1), methods: cm, max_body_bytes: x };
            let p = core::Scope::Https { endpoint: core::EndpointId::from_raw(o2), methods: pm, max_body_bytes: y };
            let op = core::Operation::Https { endpoint: core::EndpointId::from_raw(o2), method: methods[mi], body_bytes: y };
            prop_assert_eq!(core::is_subset(&c, &p), ms::is_subset(&scope(c), &scope(p)));
            prop_assert_eq!(core::permits(&p, &op), ms::permits(&scope(p), &operation(op)));
            prop_assert_eq!(core::permits(&c, &op), ms::permits(&scope(c), &operation(op)));
        }
        // Budget / Depth / Expiry orders and depth arithmetic.
        let b = |u: bool, v: u64| if u { core::Budget::Unlimited } else { core::Budget::Finite(v) };
        let (b1, b2) = (b(unl.0, x), b(unl.1, y));
        prop_assert_eq!(b1.within(b2), budget(b1).within(budget(b2)));
        prop_assert_eq!(b1.is_finite(), budget(b1).is_finite());
        let d = |u: bool, v: u32| if u { core::Depth::Unlimited } else { core::Depth::Finite(v % 4) };
        let (e1, e2) = (d(unl.0, d1), d(unl.1, d2));
        prop_assert_eq!(e1.within(e2), depth(e1).within(depth(e2)));
        prop_assert_eq!(e1.can_delegate(), depth(e1).can_delegate());
        prop_assert_eq!(e1.admits_child(e2), depth(e1).admits_child(depth(e2)));
        prop_assert_eq!(e1.decrement().map(depth), depth(e1).decrement());
        let ex = |u: bool, v: u64| if u { core::Expiry::Never } else { core::Expiry::At(core::Tick::from_raw(v)) };
        let (x1, x2) = (ex(unl.0, x % 8), ex(unl.1, y % 8));
        prop_assert_eq!(x1.within(x2), expiry(x1).within(expiry(x2)));
        let t = core::Tick::from_raw(y % 8);
        prop_assert_eq!(x1.is_expired_at(t), expiry(x1).is_expired_at(tick(t)));
    }
}

/// Deterministic boundary scenario: maximal budgets, a nonce that differs
/// only in its second half, and depth exhaustion.
#[test]
fn boundary_scenario_agrees() {
    use core::{AdminCommand as A, AgentCommand as G, AuthenticatedCommand as C};
    let l = core::Limits::default();
    let mut s = core::State::new(l);
    let mut model = m::State::new(limits(l));
    let go = |s: &mut core::State, model: &mut m::State, cmd: C, now: u64| {
        let real = core::step(s, cmd, core::Tick::from_raw(now));
        let mine = model.step(command(cmd), mq::Tick(now));
        assert_eq!(
            real.as_ref().map(effect).map_err(|d| denial(*d)),
            mine,
            "{cmd:?}"
        );
        compare(s, model, now).unwrap();
        real.ok()
    };
    let Some(core::Effect::PrincipalCreated { agent: a }) =
        go(&mut s, &mut model, C::operator(A::CreatePrincipal), 0)
    else {
        panic!()
    };
    let Some(core::Effect::PrincipalCreated { agent: b }) =
        go(&mut s, &mut model, C::operator(A::CreatePrincipal), 0)
    else {
        panic!()
    };
    let t = core::Terms {
        scope: core::Scope::File {
            object: core::ObjectId::from_raw(1),
            rights: core::FileRights::READ.union(core::FileRights::REPLACE),
        },
        budget: core::Budget::Finite(u64::MAX),
        depth: core::Depth::Finite(1),
        expiry: core::Expiry::Never,
    };
    let mut n1 = [7u8; 32];
    let req = core::GrantRequest {
        epoch: s.epoch(),
        recipient: a,
        terms: t,
        request_expires: core::Tick::from_raw(10),
    };
    go(
        &mut s,
        &mut model,
        C::operator(A::Mint {
            approval: core::VerifiedApproval::new(core::Nonce::from_bytes(n1), req),
        }),
        1,
    );
    // Same first half, different second half: a fresh nonce.
    n1[31] = 8;
    go(
        &mut s,
        &mut model,
        C::operator(A::Mint {
            approval: core::VerifiedApproval::new(core::Nonce::from_bytes(n1), req),
        }),
        1,
    );
    // Replay of the first nonce is denied.
    n1[31] = 7;
    go(
        &mut s,
        &mut model,
        C::operator(A::Mint {
            approval: core::VerifiedApproval::new(core::Nonce::from_bytes(n1), req),
        }),
        1,
    );
    let c0 = core::CapabilityId::from_raw(0);
    let half = core::Terms {
        budget: core::Budget::Finite(u64::MAX / 2),
        depth: core::Depth::Finite(0),
        ..t
    };
    go(
        &mut s,
        &mut model,
        C::agent(
            a,
            G::Delegate {
                capability: c0,
                recipient: b,
                terms: half,
            },
        ),
        2,
    );
    let c2 = core::CapabilityId::from_raw(2);
    // Depth zero: no further delegation or transfer.
    go(
        &mut s,
        &mut model,
        C::agent(
            b,
            G::Split {
                capability: c2,
                terms: core::Terms {
                    budget: core::Budget::Finite(1),
                    ..half
                },
            },
        ),
        3,
    );
    go(
        &mut s,
        &mut model,
        C::agent(
            b,
            G::Transfer {
                capability: c2,
                recipient: a,
            },
        ),
        3,
    );
    // Unlimited child from finite parent is denied.
    go(
        &mut s,
        &mut model,
        C::agent(
            a,
            G::Split {
                capability: c0,
                terms: core::Terms {
                    budget: core::Budget::Unlimited,
                    depth: core::Depth::Finite(0),
                    ..t
                },
            },
        ),
        3,
    );
    let read = core::Operation::File {
        object: core::ObjectId::from_raw(1),
        right: core::FileRight::Read,
    };
    go(
        &mut s,
        &mut model,
        C::agent(
            b,
            G::Consume {
                request_id: core::RequestId::from_raw(1),
                capability: c2,
                operation: read,
            },
        ),
        4,
    );
    go(
        &mut s,
        &mut model,
        C::agent(
            b,
            G::Consume {
                request_id: core::RequestId::from_raw(1),
                capability: c2,
                operation: read,
            },
        ),
        4,
    );
    go(
        &mut s,
        &mut model,
        C::agent(
            a,
            G::Attenuate {
                capability: c0,
                terms: core::Terms {
                    budget: core::Budget::Finite(3),
                    ..t
                },
            },
        ),
        5,
    );
    go(
        &mut s,
        &mut model,
        C::agent(a, G::Revoke { capability: c2 }),
        6,
    );
    go(
        &mut s,
        &mut model,
        C::agent(
            b,
            G::Consume {
                request_id: core::RequestId::from_raw(2),
                capability: c2,
                operation: read,
            },
        ),
        6,
    );
    go(
        &mut s,
        &mut model,
        C::agent(a, G::Drop { capability: c0 }),
        7,
    );
    go(&mut s, &mut model, C::operator(A::BumpEpoch), 0);
    go(&mut s, &mut model, C::operator(A::BumpEpoch), 0);
}

/// Semantic decision 2 (proof register): ancestors are checked against
/// their creation-time expiry, so attenuating a parent's expiry later does
/// not shorten existing children. Random generation rarely reaches this.
#[test]
fn attenuated_ancestor_expiry_agrees() {
    use core::{AdminCommand as A, AgentCommand as G, AuthenticatedCommand as C};
    let l = core::Limits::default();
    let mut s = core::State::new(l);
    let mut model = m::State::new(limits(l));
    let go = |s: &mut core::State, model: &mut m::State, cmd: C, now: u64| {
        let real = core::step(s, cmd, core::Tick::from_raw(now));
        let mine = model.step(command(cmd), mq::Tick(now));
        assert_eq!(
            real.as_ref().map(effect).map_err(|d| denial(*d)),
            mine,
            "{cmd:?}"
        );
        compare(s, model, now).unwrap();
    };
    go(&mut s, &mut model, C::operator(A::CreatePrincipal), 0);
    go(&mut s, &mut model, C::operator(A::CreatePrincipal), 0);
    let (a, b) = (core::AgentId::new(0, 0), core::AgentId::new(0, 1));
    let t = core::Terms {
        scope: core::Scope::File {
            object: core::ObjectId::from_raw(1),
            rights: core::FileRights::READ,
        },
        budget: core::Budget::Unlimited,
        depth: core::Depth::Unlimited,
        expiry: core::Expiry::Never,
    };
    go(
        &mut s,
        &mut model,
        C::operator(A::InstallBaseline {
            recipient: a,
            terms: t,
        }),
        0,
    );
    let c0 = core::CapabilityId::from_raw(0);
    go(
        &mut s,
        &mut model,
        C::agent(
            a,
            G::Delegate {
                capability: c0,
                recipient: b,
                terms: t,
            },
        ),
        1,
    );
    let short = core::Terms {
        expiry: core::Expiry::At(core::Tick::from_raw(5)),
        ..t
    };
    go(
        &mut s,
        &mut model,
        C::agent(
            a,
            G::Attenuate {
                capability: c0,
                terms: short,
            },
        ),
        2,
    );
    let read = core::Operation::File {
        object: core::ObjectId::from_raw(1),
        right: core::FileRight::Read,
    };
    let c1 = core::CapabilityId::from_raw(1);
    // At t = 9 the parent's current expiry has passed but the child lives.
    go(
        &mut s,
        &mut model,
        C::agent(
            b,
            G::Consume {
                request_id: core::RequestId::from_raw(1),
                capability: c1,
                operation: read,
            },
        ),
        9,
    );
    assert!(s.is_live(c1, core::Tick::from_raw(9)));
}
