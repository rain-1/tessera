//! Shared test harness: every step is checked for (a) invariant
//! preservation and (b) denial-without-mutation.
#![allow(dead_code)]

use tessera_capability_core::*;

pub fn copy_state(s: &State) -> State {
    serde_json::from_str(&serde_json::to_string(s).expect("serialize")).expect("deserialize")
}

pub fn file(object: u64, rights: FileRights) -> Scope {
    Scope::File {
        object: ObjectId::from_raw(object),
        rights,
    }
}

pub fn https(endpoint: u64, methods: MethodSet, max_body_bytes: u64) -> Scope {
    Scope::Https {
        endpoint: EndpointId::from_raw(endpoint),
        methods,
        max_body_bytes,
    }
}

pub fn read(object: u64) -> Operation {
    Operation::File {
        object: ObjectId::from_raw(object),
        right: FileRight::Read,
    }
}

pub fn get(endpoint: u64) -> Operation {
    Operation::Https {
        endpoint: EndpointId::from_raw(endpoint),
        method: HttpMethod::Get,
        body_bytes: 0,
    }
}

pub fn terms(scope: Scope, budget: Budget, depth: Depth, expiry: Expiry) -> Terms {
    Terms {
        scope,
        budget,
        depth,
        expiry,
    }
}

pub fn at(t: u64) -> Expiry {
    Expiry::At(Tick::from_raw(t))
}

pub struct H {
    pub s: State,
    pub now: u64,
    next_nonce: u8,
    next_request: u128,
}

impl Default for H {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

impl H {
    pub fn new(limits: Limits) -> Self {
        H {
            s: State::new(limits),
            now: 0,
            next_nonce: 0,
            next_request: 0,
        }
    }

    pub fn t(&self) -> Tick {
        Tick::from_raw(self.now)
    }

    /// Run one command, asserting the core's contract around it.
    pub fn run(&mut self, cmd: AuthenticatedCommand) -> Result<Effect, Denial> {
        let before = copy_state(&self.s);
        let now = self.t();
        let r = step(&mut self.s, cmd, now);
        match &r {
            Err(_) | Ok(Effect::AlreadyReserved { .. }) => {
                assert_eq!(self.s, before, "denial/duplicate mutated state: {r:?}")
            }
            Ok(_) => {}
        }
        check_invariant(&self.s).unwrap_or_else(|v| panic!("invariant {v:?} after {cmd:?}"));
        r
    }

    pub fn admin(&mut self, cmd: AdminCommand) -> Result<Effect, Denial> {
        self.run(AuthenticatedCommand::operator(cmd))
    }

    pub fn agent_cmd(&mut self, caller: AgentId, cmd: AgentCommand) -> Result<Effect, Denial> {
        self.run(AuthenticatedCommand::agent(caller, cmd))
    }

    pub fn principal(&mut self) -> AgentId {
        match self.admin(AdminCommand::CreatePrincipal) {
            Ok(Effect::PrincipalCreated { agent }) => agent,
            other => panic!("{other:?}"),
        }
    }

    pub fn fresh_nonce(&mut self) -> Nonce {
        self.next_nonce += 1;
        Nonce::from_bytes([self.next_nonce; 32])
    }

    pub fn approval(&mut self, recipient: AgentId, t: Terms) -> VerifiedApproval {
        let nonce = self.fresh_nonce();
        VerifiedApproval::new(
            nonce,
            GrantRequest {
                epoch: self.s.epoch(),
                recipient,
                terms: t,
                request_expires: Tick::from_raw(self.now + 1000),
            },
        )
    }

    pub fn try_mint(&mut self, recipient: AgentId, t: Terms) -> Result<CapabilityId, Denial> {
        let approval = self.approval(recipient, t);
        match self.admin(AdminCommand::Mint { approval })? {
            Effect::RootCreated { capability, .. } => Ok(capability),
            other => panic!("{other:?}"),
        }
    }

    pub fn mint(&mut self, recipient: AgentId, t: Terms) -> CapabilityId {
        self.try_mint(recipient, t).expect("mint")
    }

    pub fn consume(
        &mut self,
        caller: AgentId,
        cap: CapabilityId,
        op: Operation,
    ) -> Result<Effect, Denial> {
        self.next_request += 1;
        let request_id = RequestId::from_raw(self.next_request);
        self.agent_cmd(
            caller,
            AgentCommand::Consume {
                request_id,
                capability: cap,
                operation: op,
            },
        )
    }

    pub fn consume_ok(&mut self, caller: AgentId, cap: CapabilityId, op: Operation) {
        match self.consume(caller, cap, op) {
            Ok(Effect::Reserved(_)) => {}
            other => panic!("expected reservation, got {other:?}"),
        }
    }

    fn derived(r: Result<Effect, Denial>) -> Result<CapabilityId, Denial> {
        match r? {
            Effect::Derived { child, .. } => Ok(child),
            other => panic!("{other:?}"),
        }
    }

    pub fn split(
        &mut self,
        caller: AgentId,
        cap: CapabilityId,
        t: Terms,
    ) -> Result<CapabilityId, Denial> {
        let r = self.agent_cmd(
            caller,
            AgentCommand::Split {
                capability: cap,
                terms: t,
            },
        );
        Self::derived(r)
    }

    pub fn delegate(
        &mut self,
        caller: AgentId,
        cap: CapabilityId,
        recipient: AgentId,
        t: Terms,
    ) -> Result<CapabilityId, Denial> {
        let r = self.agent_cmd(
            caller,
            AgentCommand::Delegate {
                capability: cap,
                recipient,
                terms: t,
            },
        );
        Self::derived(r)
    }

    pub fn budget(&self, cap: CapabilityId) -> Budget {
        self.s.capability(cap).expect("cap").budget()
    }

    /// Sum of N, U, L, D over all pools under `root_cap`'s root, at now.
    pub fn account_of(&self, root_cap: CapabilityId) -> PoolAccount {
        let root = self.s.capability(root_cap).unwrap().root();
        let accts = self.s.accounts_at(self.t()).unwrap();
        let a: Vec<_> = accts.into_iter().filter(|a| a.root == root).collect();
        assert_eq!(a.len(), 1, "expected a single pool for root");
        a[0]
    }
}
