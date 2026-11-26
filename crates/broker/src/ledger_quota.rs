//! Epoch-scoped admission limits for records created by agent commands.

use std::collections::HashMap;

use serde::Deserialize;
use tessera_capability_core::{
    AgentCommand, AgentId, AuthenticatedCommand, Denial, Resource, RootId, State,
};

/// Broker limits on the number of records an agent, a delegation tree or an
/// orchestration domain may allocate per epoch.
///
/// The per-domain limits bound what one operator-created principal and
/// everything it spawned can take together, so a spawn tree cannot exhaust
/// the global record caps (`Limits::max_capabilities`,
/// `Limits::max_reservations`) within an epoch (ADR-0033). With the
/// defaults one domain can use at most about 2% of either global cap.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LedgerQuotas {
    /// Derived capability records allocated by one principal per epoch.
    pub derived_per_principal: u64,
    /// Derived capability records allocated under one root, across owners.
    pub derived_per_root: u64,
    /// Reservations created by one principal per epoch.
    pub reservations_per_principal: u64,
    /// Reservations charged to one root, across owners.
    pub reservations_per_root: u64,
    /// Derived capability records allocated by all principals of one
    /// orchestration domain per epoch.
    pub derived_per_domain: u64,
    /// Reservations created by all principals of one orchestration domain
    /// per epoch.
    pub reservations_per_domain: u64,
}

impl Default for LedgerQuotas {
    fn default() -> Self {
        Self {
            derived_per_principal: 256,
            derived_per_root: 1_024,
            reservations_per_principal: 4_096,
            reservations_per_root: 16_384,
            derived_per_domain: 2_048,
            reservations_per_domain: 16_384,
        }
    }
}

#[derive(Clone, Copy)]
enum Allocation {
    Derived,
    Reservation,
}

pub(crate) struct Charge {
    allocation: Allocation,
    caller: AgentId,
    domain: AgentId,
    root: RootId,
}

#[derive(Default)]
struct Counts {
    principals: HashMap<AgentId, u64>,
    domains: HashMap<AgentId, u64>,
    roots: HashMap<RootId, u64>,
}

#[derive(Default)]
pub(crate) struct LedgerUsage {
    derived: Counts,
    reservations: Counts,
}

impl LedgerUsage {
    /// The core has already accepted the command for validation. In particular,
    /// a denied request cannot probe a different owner's quota. `domain_of`
    /// maps a principal to its orchestration domain.
    pub(crate) fn admit(
        &self,
        limits: LedgerQuotas,
        state: &State,
        command: AuthenticatedCommand,
        domain_of: impl Fn(AgentId) -> AgentId,
    ) -> Result<Option<Charge>, Denial> {
        let AuthenticatedCommand::Agent { caller, command } = command else {
            return Ok(None);
        };
        let (allocation, capability, counts, per_principal, per_domain, per_root, resource) =
            match command {
                AgentCommand::Split { capability, .. }
                | AgentCommand::Delegate { capability, .. } => (
                    Allocation::Derived,
                    capability,
                    &self.derived,
                    limits.derived_per_principal,
                    limits.derived_per_domain,
                    limits.derived_per_root,
                    Resource::Capabilities,
                ),
                AgentCommand::Consume {
                    capability,
                    request_id,
                    ..
                } => {
                    if state.reservation_for_request(caller, request_id).is_some() {
                        return Ok(None);
                    }
                    (
                        Allocation::Reservation,
                        capability,
                        &self.reservations,
                        limits.reservations_per_principal,
                        limits.reservations_per_domain,
                        limits.reservations_per_root,
                        Resource::Reservations,
                    )
                }
                _ => return Ok(None),
            };
        let root = state
            .capability(capability)
            .ok_or(Denial::UnknownCapability)?
            .root();
        let domain = domain_of(caller);
        if counts.principals.get(&caller).copied().unwrap_or(0) >= per_principal
            || counts.domains.get(&domain).copied().unwrap_or(0) >= per_domain
            || counts.roots.get(&root).copied().unwrap_or(0) >= per_root
        {
            return Err(Denial::CapacityExceeded(resource));
        }
        Ok(Some(Charge {
            allocation,
            caller,
            domain,
            root,
        }))
    }

    /// Record an allocation only after its journal append and core transition.
    pub(crate) fn charge(&mut self, charge: Charge) {
        let counts = match charge.allocation {
            Allocation::Derived => &mut self.derived,
            Allocation::Reservation => &mut self.reservations,
        };
        *counts.principals.entry(charge.caller).or_default() += 1;
        *counts.domains.entry(charge.domain).or_default() += 1;
        *counts.roots.entry(charge.root).or_default() += 1;
    }
}
