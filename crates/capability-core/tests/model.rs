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
use common::sym::*;
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
