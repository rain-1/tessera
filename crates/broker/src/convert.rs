//! Conversions at the broker boundary between the three id/scope
//! vocabularies: the untrusted wire schema (`tessera-protocol`), the approval
//! payload (`tessera-approval`) and the authority core.
//!
//! # Id width mapping (ADR-0022)
//!
//! | Quantity | wire | approval | core | adapters |
//! |---|---|---|---|---|
//! | agent epoch | `u128` | `u128` | `u64` | — |
//! | object id | `u64` | `u128` | `u64` | `u128` |
//! | endpoint id | `u64` | `u128` | `u64` | `u128` |
//! | reservation id | `u128` | — | `u64` | `u128` |
//! | capability / root id | `u128` | — | `u128` | — |
//!
//! The core's width is authoritative. Core → other direction always widens
//! (lossless). Other → core direction is a *checked* narrowing: a value that
//! does not fit is denied (it cannot name anything the core issued), never
//! truncated.

use tessera_approval as ap;
use tessera_capability_core as cc;
use tessera_protocol as wire;

use cc::{AgentId, Budget, Depth, Expiry, FileRights, MethodSet, Scope, Tick};

/// Wire principal id → core, `None` if the epoch does not fit.
pub fn agent_from_wire(a: wire::WireAgentId) -> Option<AgentId> {
    Some(AgentId::new(u64::try_from(a.epoch).ok()?, a.serial))
}

/// Core principal id → wire.
pub fn agent_to_wire(a: AgentId) -> wire::WireAgentId {
    wire::WireAgentId {
        epoch: u128::from(a.epoch()),
        serial: a.serial(),
    }
}

/// Core principal id → approval payload.
pub fn agent_to_approval(a: AgentId) -> ap::AgentId {
    ap::AgentId {
        epoch: u128::from(a.epoch()),
        serial: a.serial(),
    }
}

/// Approval principal id → core, `None` on overflow.
pub fn agent_from_approval(a: ap::AgentId) -> Option<AgentId> {
    Some(AgentId::new(u64::try_from(a.epoch).ok()?, a.serial))
}

/// Text form `e<epoch>.s<serial>`, also used as the launcher label.
pub fn agent_label(a: AgentId) -> String {
    format!("e{}.s{}", a.epoch(), a.serial())
}

/// Parse `e<epoch>.s<serial>` (or `<epoch>/<serial>`).
pub fn parse_agent(s: &str) -> Option<AgentId> {
    let (e, sr) = if let Some(rest) = s.strip_prefix('e') {
        rest.split_once(".s")?
    } else {
        s.split_once('/')?
    };
    Some(AgentId::new(e.parse().ok()?, sr.parse().ok()?))
}

/// Wire scope → core scope. Rights/method sets are rebuilt from explicit
/// booleans, so no undefined bit can be smuggled in. Returns `None` for an
/// empty (ill-formed) scope.
pub fn scope_from_wire(s: &wire::WireScope) -> Option<Scope> {
    let scope = match *s {
        wire::WireScope::File { object_id, rights } => {
            let mut r = FileRights::empty();
            if rights.read_snapshot {
                r = r.union(FileRights::READ);
            }
            if rights.replace_content {
                r = r.union(FileRights::REPLACE);
            }
            Scope::File {
                object: cc::ObjectId::from_raw(object_id),
                rights: r,
            }
        }
        wire::WireScope::Https {
            endpoint_id,
            methods,
            max_body_bytes,
        } => {
            let mut m = MethodSet::empty();
            for (on, meth) in [
                (methods.get, cc::HttpMethod::Get),
                (methods.head, cc::HttpMethod::Head),
                (methods.post, cc::HttpMethod::Post),
                (methods.put, cc::HttpMethod::Put),
                (methods.patch, cc::HttpMethod::Patch),
                (methods.delete, cc::HttpMethod::Delete),
            ] {
                if on {
                    m = m.with(meth);
                }
            }
            Scope::Https {
                endpoint: cc::EndpointId::from_raw(endpoint_id),
                methods: m,
                max_body_bytes,
            }
        }
    };
    scope.is_well_formed().then_some(scope)
}

/// Core scope → wire scope.
pub fn scope_to_wire(s: &Scope) -> wire::WireScope {
    match *s {
        Scope::File { object, rights } => wire::WireScope::File {
            object_id: object.to_raw(),
            rights: wire::WireFileRights {
                read_snapshot: rights.contains_all(FileRights::READ),
                replace_content: rights.contains_all(FileRights::REPLACE),
            },
        },
        Scope::Https {
            endpoint,
            methods,
            max_body_bytes,
        } => wire::WireScope::Https {
            endpoint_id: endpoint.to_raw(),
            methods: wire::WireMethodSet {
                get: methods.has(cc::HttpMethod::Get),
                head: methods.has(cc::HttpMethod::Head),
                post: methods.has(cc::HttpMethod::Post),
                put: methods.has(cc::HttpMethod::Put),
                patch: methods.has(cc::HttpMethod::Patch),
                delete: methods.has(cc::HttpMethod::Delete),
            },
            max_body_bytes,
        },
    }
}

/// Short, content-free scope summary for audit records and displays.
pub fn scope_summary(s: &Scope) -> String {
    match *s {
        Scope::File { object, rights } => {
            let mut r = Vec::new();
            if rights.contains_all(FileRights::READ) {
                r.push("read");
            }
            if rights.contains_all(FileRights::REPLACE) {
                r.push("replace");
            }
            format!("file:{}[{}]", object.to_raw(), r.join(","))
        }
        Scope::Https {
            endpoint,
            methods,
            max_body_bytes,
        } => {
            let names: Vec<&str> = [
                (cc::HttpMethod::Get, "GET"),
                (cc::HttpMethod::Head, "HEAD"),
                (cc::HttpMethod::Post, "POST"),
                (cc::HttpMethod::Put, "PUT"),
                (cc::HttpMethod::Patch, "PATCH"),
                (cc::HttpMethod::Delete, "DELETE"),
            ]
            .into_iter()
            .filter(|(m, _)| methods.has(*m))
            .map(|(_, n)| n)
            .collect();
            format!(
                "https:{}[{}] body<={}",
                endpoint.to_raw(),
                names.join(","),
                max_body_bytes
            )
        }
    }
}

/// Wire budget → core.
pub fn budget_from_wire(b: wire::WireBudget) -> Budget {
    match b {
        wire::WireBudget::Finite(n) => Budget::Finite(n),
        wire::WireBudget::Unlimited => Budget::Unlimited,
    }
}

/// Core budget → wire.
pub fn budget_to_wire(b: Budget) -> wire::WireBudget {
    match b {
        Budget::Finite(n) => wire::WireBudget::Finite(n),
        Budget::Unlimited => wire::WireBudget::Unlimited,
    }
}

/// Display form of a budget.
pub fn budget_summary(b: Budget) -> String {
    match b {
        Budget::Finite(n) => n.to_string(),
        Budget::Unlimited => "unlimited".into(),
    }
}

/// Wire depth → core.
pub fn depth_from_wire(d: wire::WireDepth) -> Depth {
    match d {
        wire::WireDepth::Finite(n) => Depth::Finite(n),
        wire::WireDepth::Unlimited => Depth::Unlimited,
    }
}

/// Core depth → wire.
pub fn depth_to_wire(d: Depth) -> wire::WireDepth {
    match d {
        Depth::Finite(n) => wire::WireDepth::Finite(n),
        Depth::Unlimited => wire::WireDepth::Unlimited,
    }
}

/// Resolve a relative wire expiry against trusted time. `inherit` is used
/// for [`wire::WireExpiry::Inherit`]. `None` on arithmetic overflow.
pub fn expiry_from_wire(e: wire::WireExpiry, now: Tick, inherit: Expiry) -> Option<Expiry> {
    match e {
        wire::WireExpiry::Inherit => Some(inherit),
        wire::WireExpiry::WithinMillis(ms) => {
            Some(Expiry::At(Tick::from_raw(now.to_raw().checked_add(ms)?)))
        }
    }
}

// ---------------------------------------------------------------------------
// Approval payload <-> core
// ---------------------------------------------------------------------------

/// Core scope → approval scope (widening ids). Bit layouts agree for the
/// rights the core knows (READ = 1, REPLACE = 2; GET..DELETE = 1..32).
pub fn scope_to_approval(s: &Scope) -> Option<ap::Scope> {
    Some(match *s {
        Scope::File { object, rights } => ap::Scope::File {
            object: ap::ObjectId(u128::from(object.to_raw())),
            rights: ap::FileRights::new(rights.bits())?,
        },
        Scope::Https {
            endpoint,
            methods,
            max_body_bytes,
        } => ap::Scope::Https {
            endpoint: ap::EndpointId(u128::from(endpoint.to_raw())),
            methods: ap::MethodSet::new(u16::from(methods.bits()))?,
            max_body_bytes,
        },
    })
}

/// Approval scope → core scope (checked narrowing). Rights the core does not
/// implement (APPEND, METADATA, OPTIONS) make the conversion fail: an
/// approval can never be turned into a broader or different grant.
pub fn scope_from_approval(s: &ap::Scope) -> Option<Scope> {
    let scope = match *s {
        ap::Scope::File { object, rights } => Scope::File {
            object: cc::ObjectId::from_raw(u64::try_from(object.0).ok()?),
            rights: FileRights::from_bits(rights.bits())?,
        },
        ap::Scope::Https {
            endpoint,
            methods,
            max_body_bytes,
        } => Scope::Https {
            endpoint: cc::EndpointId::from_raw(u64::try_from(endpoint.0).ok()?),
            methods: MethodSet::from_bits(u8::try_from(methods.bits()).ok()?)?,
            max_body_bytes,
        },
    };
    scope.is_well_formed().then_some(scope)
}

/// Core budget → approval budget (unit: one operation attempt).
pub fn budget_to_approval(b: Budget) -> ap::Budget {
    ap::Budget {
        amount: match b {
            Budget::Finite(n) => ap::BudgetAmount::Finite(n),
            Budget::Unlimited => ap::BudgetAmount::Unlimited,
        },
        unit: ap::BudgetUnit::Operations,
    }
}

/// Approval budget → core; only the MVP unit is accepted.
pub fn budget_from_approval(b: &ap::Budget) -> Option<Budget> {
    if b.unit != ap::BudgetUnit::Operations {
        return None;
    }
    Some(match b.amount {
        ap::BudgetAmount::Finite(n) => Budget::Finite(n),
        ap::BudgetAmount::Unlimited => Budget::Unlimited,
    })
}

/// Core depth → approval depth.
pub fn depth_to_approval(d: Depth) -> ap::Depth {
    match d {
        Depth::Finite(n) => ap::Depth::Finite(n),
        Depth::Unlimited => ap::Depth::Unlimited,
    }
}

/// Approval depth → core depth.
pub fn depth_from_approval(d: ap::Depth) -> Depth {
    match d {
        ap::Depth::Finite(n) => Depth::Finite(n),
        ap::Depth::Unlimited => Depth::Unlimited,
    }
}

/// Turn a *verified* approval into the core's evidence type. Every field of
/// the minted grant comes from the signed request; the conversion only
/// narrows integer widths and fails closed if anything does not map.
pub fn core_approval(v: &ap::VerifiedApproval) -> Option<cc::VerifiedApproval> {
    let f = v.request().fields();
    let terms = cc::Terms {
        scope: scope_from_approval(&f.scope)?,
        budget: budget_from_approval(&f.budget)?,
        depth: depth_from_approval(f.depth),
        expiry: Expiry::At(Tick::from_raw(f.grant_expires_at.0)),
    };
    Some(cc::VerifiedApproval::new(
        cc::Nonce::from_bytes(v.nonce().0),
        cc::GrantRequest {
            epoch: f.authority_epoch.0,
            recipient: agent_from_approval(f.recipient)?,
            terms,
            request_expires: Tick::from_raw(f.request_expires_at.0),
        },
    ))
}

/// Map a core denial to the coarse wire error code (§9.2). "Unknown" and
/// "not yours" collapse to `UnknownCapability` so a non-owner learns nothing.
pub fn denial_code(d: cc::Denial) -> wire::ErrorCode {
    use cc::{Denial as D, NotLive as N};
    use wire::ErrorCode as E;
    match d {
        D::UnknownCapability | D::NotOwner => E::UnknownCapability,
        D::NotLive(n) => match n {
            N::Expired | N::AncestorExpired(_) => E::Expired,
            N::Revoked | N::AncestorRevoked(_) | N::Dropped => E::Revoked,
            N::Unknown => E::UnknownCapability,
            N::StaleEpoch => E::StaleEpoch,
            N::OwnerTerminated | N::OwnerUnknown | N::LineageCorrupt => E::Revoked,
        },
        D::OperationNotPermitted => E::ScopeViolation,
        D::InsufficientBudget | D::ZeroAllocation => E::InsufficientBudget,
        D::NotDelegatable | D::DepthNotAttenuated => E::DepthExhausted,
        D::InvalidScope | D::ScopeNotAttenuated | D::BudgetNotAttenuated => E::NotSubset,
        D::ExpiryNotAttenuated | D::AlreadyExpired => E::ExpiryTooLate,
        D::StaleEpoch => E::StaleEpoch,
        D::UnknownPrincipal | D::PrincipalTerminated | D::SelfTransfer => E::InvalidRecipient,
        D::NotAuthorizedToRevoke => E::UnknownCapability,
        D::AlreadyRevoked => E::Revoked,
        D::RequestIdConflict => E::RequestIdConflict,
        D::CapacityExceeded(_) | D::LineageTooLong => E::LimitExceeded,
        D::NonceReused
        | D::ApprovalEpochMismatch
        | D::ApprovalExpired
        | D::AlreadyTerminated
        | D::UnknownReservation
        | D::ReservationAlreadyResolved
        | D::ClockRegression
        | D::ArithmeticOverflow => E::PermissionDenied,
    }
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_epoch_overflow_is_rejected_not_truncated() {
        let w = wire::WireAgentId {
            epoch: u128::from(u64::MAX) + 1,
            serial: 3,
        };
        assert_eq!(agent_from_wire(w), None);
        let ok = wire::WireAgentId {
            epoch: 7,
            serial: 3,
        };
        assert_eq!(agent_from_wire(ok), Some(AgentId::new(7, 3)));
        assert_eq!(parse_agent("e7.s3"), Some(AgentId::new(7, 3)));
        assert_eq!(
            parse_agent(&agent_label(AgentId::new(9, 1))),
            Some(AgentId::new(9, 1))
        );
    }

    #[test]
    fn approval_scope_roundtrip_and_overflow() {
        let s = Scope::File {
            object: cc::ObjectId::from_raw(5),
            rights: FileRights::READ,
        };
        assert_eq!(
            scope_from_approval(&scope_to_approval(&s).unwrap()),
            Some(s)
        );
        let big = ap::Scope::File {
            object: ap::ObjectId(u128::from(u64::MAX) + 1),
            rights: ap::FileRights::new(1).unwrap(),
        };
        assert_eq!(scope_from_approval(&big), None);
        // APPEND is not a core right: refuse rather than drop the bit.
        let append = ap::Scope::File {
            object: ap::ObjectId(1),
            rights: ap::FileRights::new(ap::FileRights::APPEND).unwrap(),
        };
        assert_eq!(scope_from_approval(&append), None);
    }

    #[test]
    fn empty_wire_scope_rejected() {
        let s = wire::WireScope::File {
            object_id: 1,
            rights: wire::WireFileRights::default(),
        };
        assert_eq!(scope_from_wire(&s), None);
    }
}
