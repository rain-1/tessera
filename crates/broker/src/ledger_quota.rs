//! Epoch-scoped admission limits for records created by agent commands.

use std::collections::HashMap;

use serde::Deserialize;
use tessera_capability_core::{
    AgentCommand, AgentId, AuthenticatedCommand, Denial, Resource, RootId, State,
};

/// Broker limits on the number of records an agent or delegation tree may allocate.
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
}

impl Default for LedgerQuotas {
    fn default() -> Self {
        Self {
            derived_per_principal: 256,
            derived_per_root: 1_024,
            reservations_per_principal: 4_096,
            reservations_per_root: 16_384,
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
    root: RootId,
}

#[derive(Default)]
struct Counts {
    principals: HashMap<AgentId, u64>,
    roots: HashMap<RootId, u64>,
}

#[derive(Default)]
pub(crate) struct LedgerUsage {
    derived: Counts,
    reservations: Counts,
}

impl LedgerUsage {
    /// The core has already accepted the command for validation. In particular,
    /// a denied request cannot probe a different owner's quota.
    pub(crate) fn admit(
        &self,
        limits: LedgerQuotas,
        state: &State,
        command: AuthenticatedCommand,
    ) -> Result<Option<Charge>, Denial> {
        let AuthenticatedCommand::Agent { caller, command } = command else {
            return Ok(None);
        };
        let (allocation, capability, counts, per_principal, per_root, resource) = match command {
            AgentCommand::Split { capability, .. } | AgentCommand::Delegate { capability, .. } => (
                Allocation::Derived,
                capability,
                &self.derived,
                limits.derived_per_principal,
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
        if counts.principals.get(&caller).copied().unwrap_or(0) >= per_principal
            || counts.roots.get(&root).copied().unwrap_or(0) >= per_root
        {
            return Err(Denial::CapacityExceeded(resource));
        }
        Ok(Some(Charge {
            allocation,
            caller,
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
        *counts.roots.entry(charge.root).or_default() += 1;
    }
}
