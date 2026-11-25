//! Unit tests for every core-level rule of spec §15, §5 and §12.
//! Every command goes through `H::run`, which asserts invariant
//! preservation and that denials leave the state unchanged.

mod common;

use common::*;
use tessera_capability_core::*;

fn one_read(obj: u64) -> Terms {
    terms(
        file(obj, FileRights::READ),
        Budget::Finite(1),
        Depth::Finite(0),
        at(300),
    )
}

fn get_scope(ep: u64) -> Scope {
    https(ep, MethodSet::only(HttpMethod::Get), 1024)
}

// ---------------------------------------------------------------------------
// §12.1 / §15: budget one
// ---------------------------------------------------------------------------

#[test]
fn budget_one_thousand_attempts_yield_one_reservation() {
    let mut h = H::default();
    let a = h.principal();
    let cap = h.mint(a, one_read(1));
    let mut reserved = 0;
    for _ in 0..1000 {
        match h.consume(a, cap, read(1)) {
            Ok(Effect::Reserved(_)) => reserved += 1,
            Err(Denial::InsufficientBudget) => {}
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(reserved, 1);
    let acct = h.account_of(cap);
    assert_eq!(
        (acct.initial, acct.consumed, acct.live, acct.discarded()),
        (1, 1, 0, 0)
    );
}

#[test]
fn failed_dispatch_does_not_refund() {
    let mut h = H::default();
    let a = h.principal();
    let cap = h.mint(a, one_read(1));
    let Ok(Effect::Reserved(r)) = h.consume(a, cap, read(1)) else {
        panic!()
    };
    h.admin(AdminCommand::RecordOutcome {
        reservation: r.id(),
        outcome: Outcome::Failed,
    })
    .unwrap();
    assert_eq!(h.consume(a, cap, read(1)), Err(Denial::InsufficientBudget));
    assert_eq!(
        h.admin(AdminCommand::RecordOutcome {
            reservation: r.id(),
            outcome: Outcome::Completed
        }),
        Err(Denial::ReservationAlreadyResolved)
    );
    assert_eq!(
        h.s.reservation(r.id()).unwrap().status(),
        ReservationStatus::Failed
    );
}

#[test]
fn repeated_request_id_returns_previous_status_without_new_reservation() {
    let mut h = H::default();
    let a = h.principal();
    let cap = h.mint(
        a,
        terms(
            file(1, FileRights::READ),
            Budget::Finite(5),
            Depth::Finite(0),
            at(300),
        ),
    );
    let rid = RequestId::from_raw(42);
    let c = AgentCommand::Consume {
        request_id: rid,
        capability: cap,
        operation: read(1),
    };
    let Ok(Effect::Reserved(r)) = h.agent_cmd(a, c) else {
        panic!()
    };
    for _ in 0..10 {
        assert_eq!(
            h.agent_cmd(a, c),
            Ok(Effect::AlreadyReserved {
                reservation: r.id(),
                status: ReservationStatus::Reserved
            })
        );
    }
    assert_eq!(h.budget(cap), Budget::Finite(4));
    h.admin(AdminCommand::RecordOutcome {
        reservation: r.id(),
        outcome: Outcome::Unknown,
    })
    .unwrap();
    assert_eq!(
        h.agent_cmd(a, c),
        Ok(Effect::AlreadyReserved {
            reservation: r.id(),
            status: ReservationStatus::Unknown
        })
    );
    // Same request id, different operation: conflict.
    let other_op = Operation::File {
        object: ObjectId::from_raw(1),
        right: FileRight::Replace,
    };
    let c2 = AgentCommand::Consume {
        request_id: rid,
        capability: cap,
        operation: other_op,
    };
    assert_eq!(h.agent_cmd(a, c2), Err(Denial::RequestIdConflict));
    // Request ids are scoped per principal: B may use the same id (on its own cap).
    let b = h.principal();
    let cb = h.mint(b, one_read(1));
    let c3 = AgentCommand::Consume {
        request_id: rid,
        capability: cb,
        operation: read(1),
    };
    assert!(matches!(h.agent_cmd(b, c3), Ok(Effect::Reserved(_))));
}

// ---------------------------------------------------------------------------
// Conservation under splitting
// ---------------------------------------------------------------------------

#[test]
fn repeated_splits_conserve_budget() {
    let mut h = H::default();
    let a = h.principal();
    let root = h.mint(
        a,
        terms(
            get_scope(1),
            Budget::Finite(1000),
            Depth::Unlimited,
            Expiry::Never,
        ),
    );
    let mut frontier = vec![root];
    for i in 0..200u64 {
        let parent = frontier[(i as usize * 7) % frontier.len()];
        if let Budget::Finite(b) = h.budget(parent)
            && b >= 2
        {
            let child = h
                .split(
                    a,
                    parent,
                    terms(
                        get_scope(1),
                        Budget::Finite(b / 2),
                        Depth::Unlimited,
                        Expiry::Never,
                    ),
                )
                .unwrap();
            frontier.push(child);
        }
        if i % 5 == 0 {
            let c = frontier[i as usize % frontier.len()];
            let _ = h.consume(a, c, get(1));
        }
        let acct = h.account_of(root);
        assert_eq!(acct.consumed + acct.live + acct.discarded(), 1000);
    }
    let total_live: u64 = frontier
        .iter()
        .map(|c| match h.budget(*c) {
            Budget::Finite(b) => b,
            Budget::Unlimited => unreachable!(),
        })
        .sum();
    let acct = h.account_of(root);
    assert_eq!(total_live, acct.live);
}

#[test]
fn unlimited_root_allocates_conserved_finite_children() {
    let mut h = H::default();
    let a = h.principal();
    let b = h.principal();
    let root = h.mint(
        a,
        terms(
            get_scope(1),
            Budget::Unlimited,
            Depth::Unlimited,
            Expiry::Never,
        ),
    );
    // Unlimited remains unlimited after use.
    h.consume_ok(a, root, get(1));
    assert_eq!(h.budget(root), Budget::Unlimited);
    let c = h
        .delegate(
            a,
            root,
            b,
            terms(
                get_scope(1),
                Budget::Finite(10),
                Depth::Finite(3),
                Expiry::Never,
            ),
        )
        .unwrap();
    assert_eq!(h.budget(root), Budget::Unlimited);
    let gc = h
        .split(
            b,
            c,
            terms(
                get_scope(1),
                Budget::Finite(4),
                Depth::Finite(1),
                Expiry::Never,
            ),
        )
        .unwrap();
    // Finite children cannot produce unlimited grandchildren.
    assert_eq!(
        h.split(
            b,
            c,
            terms(
                get_scope(1),
                Budget::Unlimited,
                Depth::Finite(1),
                Expiry::Never
            )
        ),
        Err(Denial::BudgetNotAttenuated)
    );
    h.consume_ok(b, gc, get(1));
    let accts = h.s.accounts().unwrap();
    assert_eq!(accts.len(), 1);
    let p = accts[0];
    assert_eq!(p.anchor, c);
    assert_eq!(
        (p.initial, p.consumed, p.live, p.discarded()),
        (10, 1, 9, 0)
    );
}

// ---------------------------------------------------------------------------
// Attenuation on delegation (T2/T4)
// ---------------------------------------------------------------------------

#[test]
fn broader_delegation_is_denied_and_authority_unchanged() {
    let mut h = H::default();
    let a = h.principal();
    let b = h.principal();
    let parent_scope = https(
        1,
        MethodSet::only(HttpMethod::Get).with(HttpMethod::Head),
        100,
    );
    let cap = h.mint(
        a,
        terms(parent_scope, Budget::Finite(10), Depth::Finite(2), at(100)),
    );
    let ok = terms(
        https(1, MethodSet::only(HttpMethod::Get), 50),
        Budget::Finite(3),
        Depth::Finite(1),
        at(100),
    );

    let cases = [
        // broader methods
        (
            Terms {
                scope: https(1, MethodSet::only(HttpMethod::Post), 50),
                ..ok
            },
            Denial::ScopeNotAttenuated,
        ),
        // larger body bound
        (
            Terms {
                scope: https(1, MethodSet::only(HttpMethod::Get), 101),
                ..ok
            },
            Denial::ScopeNotAttenuated,
        ),
        // other endpoint
        (
            Terms {
                scope: https(2, MethodSet::only(HttpMethod::Get), 50),
                ..ok
            },
            Denial::ScopeNotAttenuated,
        ),
        // other resource kind
        (
            Terms {
                scope: file(1, FileRights::READ),
                ..ok
            },
            Denial::ScopeNotAttenuated,
        ),
        // empty scope
        (
            Terms {
                scope: https(1, MethodSet::empty(), 50),
                ..ok
            },
            Denial::InvalidScope,
        ),
        // longer expiry
        (
            Terms {
                expiry: at(101),
                ..ok
            },
            Denial::ExpiryNotAttenuated,
        ),
        (
            Terms {
                expiry: Expiry::Never,
                ..ok
            },
            Denial::ExpiryNotAttenuated,
        ),
        // equal depth (must be strictly lower)
        (
            Terms {
                depth: Depth::Finite(2),
                ..ok
            },
            Denial::DepthNotAttenuated,
        ),
        (
            Terms {
                depth: Depth::Unlimited,
                ..ok
            },
            Denial::DepthNotAttenuated,
        ),
        // more budget than balance
        (
            Terms {
                budget: Budget::Finite(11),
                ..ok
            },
            Denial::InsufficientBudget,
        ),
        (
            Terms {
                budget: Budget::Unlimited,
                ..ok
            },
            Denial::BudgetNotAttenuated,
        ),
        (
            Terms {
                budget: Budget::Finite(0),
                ..ok
            },
            Denial::ZeroAllocation,
        ),
    ];
    for (t, want) in cases {
        assert_eq!(h.delegate(a, cap, b, t), Err(want), "{t:?}");
        assert_eq!(h.split(a, cap, t), Err(want), "{t:?}");
    }
    // Control: the attenuated request succeeds.
    let child = h.delegate(a, cap, b, ok).unwrap();
    assert_eq!(h.s.capability(child).unwrap().owner(), b);
    assert_eq!(h.budget(cap), Budget::Finite(7));
}

#[test]
fn already_expired_child_terms_denied() {
    let mut h = H::default();
    let a = h.principal();
    let cap = h.mint(
        a,
        terms(get_scope(1), Budget::Finite(5), Depth::Finite(2), at(100)),
    );
    h.now = 50;
    assert_eq!(
        h.split(
            a,
            cap,
            terms(get_scope(1), Budget::Finite(1), Depth::Finite(1), at(50))
        ),
        Err(Denial::AlreadyExpired)
    );
}

#[test]
fn copied_capability_id_by_other_principal_denied() {
    let mut h = H::default();
    let a = h.principal();
    let b = h.principal();
    let cap = h.mint(
        a,
        terms(get_scope(1), Budget::Finite(5), Depth::Finite(2), at(100)),
    );
    let t = terms(get_scope(1), Budget::Finite(1), Depth::Finite(0), at(100));
    assert_eq!(h.consume(b, cap, get(1)), Err(Denial::NotOwner));
    assert_eq!(h.split(b, cap, t), Err(Denial::NotOwner));
    assert_eq!(h.delegate(b, cap, b, t), Err(Denial::NotOwner));
    assert_eq!(
        h.agent_cmd(
            b,
            AgentCommand::Transfer {
                capability: cap,
                recipient: b
            }
        ),
        Err(Denial::NotOwner)
    );
    assert_eq!(
        h.agent_cmd(
            b,
            AgentCommand::Attenuate {
                capability: cap,
                terms: t
            }
        ),
        Err(Denial::NotOwner)
    );
    assert_eq!(
        h.agent_cmd(b, AgentCommand::Drop { capability: cap }),
        Err(Denial::NotOwner)
    );
    assert_eq!(
        h.agent_cmd(b, AgentCommand::Revoke { capability: cap }),
        Err(Denial::NotAuthorizedToRevoke)
    );
    // Unknown / forged ids.
    let forged = CapabilityId::from_raw(999);
    assert_eq!(h.consume(a, forged, get(1)), Err(Denial::UnknownCapability));
    // Unknown and stale callers.
    let ghost = AgentId::new(0, 77);
    assert_eq!(h.consume(ghost, cap, get(1)), Err(Denial::UnknownPrincipal));
    let stale = AgentId::new(5, a.serial());
    assert_eq!(h.consume(stale, cap, get(1)), Err(Denial::StaleEpoch));

    let revoke = AgentCommand::Revoke { capability: cap };
    assert_eq!(
        h.agent_cmd(a, revoke),
        Ok(Effect::Revoked { capability: cap })
    );
    assert_eq!(h.agent_cmd(b, revoke), Err(Denial::NotAuthorizedToRevoke));
    assert_eq!(h.agent_cmd(a, revoke), Err(Denial::AlreadyRevoked));
}

#[test]
fn non_delegatable_split_transfer_delegate_denied() {
    let mut h = H::default();
    let a = h.principal();
    let b = h.principal();
    let cap = h.mint(
        a,
        terms(
            get_scope(1),
            Budget::Unlimited,
            Depth::Finite(0),
            Expiry::Never,
        ),
    );
    let t = terms(
        get_scope(1),
        Budget::Finite(1),
        Depth::Finite(0),
        Expiry::Never,
    );
    assert_eq!(h.split(a, cap, t), Err(Denial::NotDelegatable));
    assert_eq!(h.delegate(a, cap, b, t), Err(Denial::NotDelegatable));
    assert_eq!(
        h.agent_cmd(
            a,
            AgentCommand::Transfer {
                capability: cap,
                recipient: b
            }
        ),
        Err(Denial::NotDelegatable)
    );
    // Still usable (unlimited, non-delegatable).
    h.consume_ok(a, cap, get(1));
    h.consume_ok(a, cap, get(1));
}

#[test]
fn delegate_consumes_one_generation_split_then_transfer_two() {
    let mut h = H::default();
    let a = h.principal();
    let b = h.principal();
    let root = h.mint(
        a,
        terms(
            get_scope(1),
            Budget::Finite(10),
            Depth::Finite(2),
            Expiry::Never,
        ),
    );
    // Atomic delegate: child may have depth 1.
    let d = h
        .delegate(
            a,
            root,
            b,
            terms(
                get_scope(1),
                Budget::Finite(2),
                Depth::Finite(1),
                Expiry::Never,
            ),
        )
        .unwrap();
    assert_eq!(h.s.capability(d).unwrap().depth(), Depth::Finite(1));
    // Split (depth 1) then transfer (depth 0).
    let s = h
        .split(
            a,
            root,
            terms(
                get_scope(1),
                Budget::Finite(2),
                Depth::Finite(1),
                Expiry::Never,
            ),
        )
        .unwrap();
    let e = h
        .agent_cmd(
            a,
            AgentCommand::Transfer {
                capability: s,
                recipient: b,
            },
        )
        .unwrap();
    assert_eq!(
        e,
        Effect::Transferred {
            capability: s,
            from: a,
            to: b
        }
    );
    let rec = h.s.capability(s).unwrap();
    assert_eq!(
        (rec.owner(), rec.depth(), rec.parent()),
        (b, Depth::Finite(0), Some(root))
    );
    // b cannot pass it on.
    assert_eq!(
        h.agent_cmd(
            b,
            AgentCommand::Transfer {
                capability: s,
                recipient: a
            }
        ),
        Err(Denial::NotDelegatable)
    );
    // a no longer owns it.
    assert_eq!(h.consume(a, s, get(1)), Err(Denial::NotOwner));
    h.consume_ok(b, s, get(1));
}

#[test]
fn transfer_preserves_identity_and_rejects_self_and_inactive() {
    let mut h = H::default();
    let a = h.principal();
    let b = h.principal();
    let c = h.principal();
    let cap = h.mint(
        a,
        terms(
            get_scope(1),
            Budget::Finite(3),
            Depth::Unlimited,
            Expiry::Never,
        ),
    );
    assert_eq!(
        h.agent_cmd(
            a,
            AgentCommand::Transfer {
                capability: cap,
                recipient: a
            }
        ),
        Err(Denial::SelfTransfer)
    );
    h.admin(AdminCommand::TerminatePrincipal { agent: c })
        .unwrap();
    assert_eq!(
        h.agent_cmd(
            a,
            AgentCommand::Transfer {
                capability: cap,
                recipient: c
            }
        ),
        Err(Denial::PrincipalTerminated)
    );
    h.agent_cmd(
        a,
        AgentCommand::Transfer {
            capability: cap,
            recipient: b,
        },
    )
    .unwrap();
    let rec = h.s.capability(cap).unwrap();
    assert_eq!(
        (rec.owner(), rec.depth(), rec.budget()),
        (b, Depth::Unlimited, Budget::Finite(3))
    );
    // Provenance unchanged: still the root of its lineage.
    assert_eq!(h.s.lineage(cap), vec![cap]);
}

// ---------------------------------------------------------------------------
// Revocation (T5)
// ---------------------------------------------------------------------------

#[test]
fn revoke_zero_balance_ancestor_kills_descendants() {
    let mut h = H::default();
    let a = h.principal();
    let b = h.principal();
    let c = h.principal();
    let root = h.mint(
        a,
        terms(
            get_scope(1),
            Budget::Finite(2),
            Depth::Finite(3),
            Expiry::Never,
        ),
    );
    let cb = h
        .delegate(
            a,
            root,
            b,
            terms(
                get_scope(1),
                Budget::Finite(2),
                Depth::Finite(2),
                Expiry::Never,
            ),
        )
        .unwrap();
    let cc = h
        .delegate(
            b,
            cb,
            c,
            terms(
                get_scope(1),
                Budget::Finite(1),
                Depth::Finite(0),
                Expiry::Never,
            ),
        )
        .unwrap();
    // Zero-balance ancestors are still live (exhaustion is not revocation).
    assert_eq!(h.budget(root), Budget::Finite(0));
    assert!(h.s.is_live(root, h.t()));
    h.consume_ok(c, cc, get(1));
    // Revoke the zero-balance root.
    assert_eq!(
        h.admin(AdminCommand::Revoke { capability: root }),
        Ok(Effect::Revoked { capability: root })
    );
    assert_eq!(
        h.consume(b, cb, get(1)),
        Err(Denial::NotLive(NotLive::AncestorRevoked(root)))
    );
    assert_eq!(
        h.s.live(cc, h.t()).err(),
        Some(NotLive::AncestorRevoked(root))
    );
    assert_eq!(
        h.split(
            b,
            cb,
            terms(
                get_scope(1),
                Budget::Finite(1),
                Depth::Finite(0),
                Expiry::Never
            )
        ),
        Err(Denial::NotLive(NotLive::AncestorRevoked(root)))
    );
    assert_eq!(
        h.admin(AdminCommand::Revoke { capability: root }),
        Err(Denial::AlreadyRevoked)
    );
    // Stranded balances are counted in D, not L.
    let acct = h.account_of(root);
    assert_eq!(
        (acct.consumed, acct.live, acct.discarded_stranded),
        (1, 0, 1)
    );
}

#[test]
fn revoke_is_prospective_and_scoped_to_subtree() {
    let mut h = H::default();
    let a = h.principal();
    let b = h.principal();
    let c = h.principal();
    let root = h.mint(
        a,
        terms(
            get_scope(1),
            Budget::Finite(10),
            Depth::Finite(2),
            Expiry::Never,
        ),
    );
    let cb = h
        .delegate(
            a,
            root,
            b,
            terms(
                get_scope(1),
                Budget::Finite(3),
                Depth::Finite(0),
                Expiry::Never,
            ),
        )
        .unwrap();
    let cc = h
        .delegate(
            a,
            root,
            c,
            terms(
                get_scope(1),
                Budget::Finite(3),
                Depth::Finite(0),
                Expiry::Never,
            ),
        )
        .unwrap();
    let Ok(Effect::Reserved(r)) = h.consume(b, cb, get(1)) else {
        panic!()
    };
    // b cannot revoke its sibling or its ancestor.
    assert_eq!(
        h.agent_cmd(b, AgentCommand::Revoke { capability: cc }),
        Err(Denial::NotAuthorizedToRevoke)
    );
    assert_eq!(
        h.agent_cmd(b, AgentCommand::Revoke { capability: root }),
        Err(Denial::NotAuthorizedToRevoke)
    );
    // a (owner of an ancestor) can revoke b's grant.
    h.agent_cmd(a, AgentCommand::Revoke { capability: cb })
        .unwrap();
    assert_eq!(
        h.consume(b, cb, get(1)),
        Err(Denial::NotLive(NotLive::Revoked))
    );
    // Already issued reservation is unaffected (in-flight semantics, §5.2).
    assert_eq!(
        h.s.reservation(r.id()).unwrap().status(),
        ReservationStatus::Reserved
    );
    h.admin(AdminCommand::RecordOutcome {
        reservation: r.id(),
        outcome: Outcome::Completed,
    })
    .unwrap();
    // Sibling and parent unaffected.
    h.consume_ok(c, cc, get(1));
    h.consume_ok(a, root, get(1));
}

// ---------------------------------------------------------------------------
// Expiry, termination, epoch (T6)
// ---------------------------------------------------------------------------

#[test]
fn expiry_boundary() {
    let mut h = H::default();
    let a = h.principal();
    let cap = h.mint(
        a,
        terms(get_scope(1), Budget::Finite(5), Depth::Finite(0), at(10)),
    );
    h.now = 9;
    h.consume_ok(a, cap, get(1));
    h.now = 10;
    assert_eq!(
        h.consume(a, cap, get(1)),
        Err(Denial::NotLive(NotLive::Expired))
    );
    // Remaining balance is stranded (D), not live.
    h.admin(AdminCommand::AdvanceClock).unwrap();
    let acct = h.account_of(cap);
    assert_eq!(
        (acct.consumed, acct.live, acct.discarded_stranded),
        (1, 0, 4)
    );
    // Minting already-expired terms is denied.
    assert_eq!(
        h.try_mint(
            a,
            terms(get_scope(1), Budget::Finite(1), Depth::Finite(0), at(10))
        ),
        Err(Denial::AlreadyExpired)
    );
}

#[test]
fn clock_regression_denied() {
    let mut h = H::default();
    let a = h.principal();
    h.now = 10;
    h.admin(AdminCommand::AdvanceClock).unwrap();
    h.now = 9;
    assert_eq!(
        h.admin(AdminCommand::CreatePrincipal),
        Err(Denial::ClockRegression)
    );
    assert_eq!(
        h.consume(a, CapabilityId::from_raw(0), get(1)),
        Err(Denial::ClockRegression)
    );
}

#[test]
fn termination_stops_owner_but_not_delegated_children() {
    let mut h = H::default();
    let a = h.principal();
    let b = h.principal();
    let root = h.mint(
        a,
        terms(
            get_scope(1),
            Budget::Finite(10),
            Depth::Finite(1),
            Expiry::Never,
        ),
    );
    let cb = h
        .delegate(
            a,
            root,
            b,
            terms(
                get_scope(1),
                Budget::Finite(4),
                Depth::Finite(0),
                Expiry::Never,
            ),
        )
        .unwrap();
    h.admin(AdminCommand::TerminatePrincipal { agent: a })
        .unwrap();
    assert_eq!(h.consume(a, root, get(1)), Err(Denial::PrincipalTerminated));
    assert_eq!(h.s.live(root, h.t()).err(), Some(NotLive::OwnerTerminated));
    // Documented choice: parent-owner termination does not revoke children.
    h.consume_ok(b, cb, get(1));
    assert_eq!(
        h.admin(AdminCommand::TerminatePrincipal { agent: a }),
        Err(Denial::AlreadyTerminated)
    );
    // Cannot delegate to / mint for a terminated principal.
    let c = h.principal();
    let cc = h.mint(
        c,
        terms(
            get_scope(1),
            Budget::Finite(1),
            Depth::Finite(1),
            Expiry::Never,
        ),
    );
    assert_eq!(
        h.delegate(
            c,
            cc,
            a,
            terms(
                get_scope(1),
                Budget::Finite(1),
                Depth::Finite(0),
                Expiry::Never
            )
        ),
        Err(Denial::PrincipalTerminated)
    );
    assert_eq!(h.try_mint(a, one_read(1)), Err(Denial::PrincipalTerminated));
    // Accounting: root's 6 remaining units are stranded; b's 3 live.
    let acct = h.account_of(root);
    assert_eq!(
        (acct.consumed, acct.live, acct.discarded_stranded),
        (1, 3, 6)
    );
}

#[test]
fn epoch_bump_invalidates_everything_and_preserves_nonces() {
    let mut h = H::default();
    let a = h.principal();
    let t = terms(
        get_scope(1),
        Budget::Finite(3),
        Depth::Finite(0),
        Expiry::Never,
    );
    let approval = h.approval(a, t);
    let Ok(Effect::RootCreated {
        capability: cap, ..
    }) = h.admin(AdminCommand::Mint { approval })
    else {
        panic!()
    };
    let Ok(Effect::Reserved(r)) = h.consume(a, cap, get(1)) else {
        panic!()
    };
    h.now = 1000;
    h.admin(AdminCommand::AdvanceClock).unwrap();
    // Restart with a fresh monotonic clock that is *behind* the old one.
    h.now = 5;
    let e = h.admin(AdminCommand::BumpEpoch).unwrap();
    assert_eq!(
        e,
        Effect::EpochAdvanced {
            epoch: 1,
            terminated_principals: 1,
            abandoned_reservations: 1
        }
    );
    assert_eq!(h.s.clock(), Tick::from_raw(5));
    assert_eq!(
        h.s.reservation(r.id()).unwrap().status(),
        ReservationStatus::Abandoned
    );
    assert_eq!(h.consume(a, cap, get(1)), Err(Denial::StaleEpoch));
    assert_eq!(h.s.live(cap, h.t()).err(), Some(NotLive::StaleEpoch));
    // New principal in the new epoch cannot use the old grant.
    let a2 = h.principal();
    assert_eq!(a2.epoch(), 1);
    assert_eq!(h.consume(a2, cap, get(1)), Err(Denial::NotOwner));
    // Old approval: nonce already spent (and wrong epoch anyway).
    assert_eq!(
        h.admin(AdminCommand::Mint { approval }),
        Err(Denial::NonceReused)
    );
    assert!(h.s.is_nonce_spent(&approval.nonce()));
    // New approval in new epoch works.
    let c2 = h.mint(a2, t);
    h.consume_ok(a2, c2, get(1));
    // Stranded old balance.
    let acct = h.account_of(cap);
    assert_eq!(
        (acct.consumed, acct.live, acct.discarded_stranded),
        (1, 0, 2)
    );
}

// ---------------------------------------------------------------------------
// MINT / approval evidence (T7) and baseline (R2)
// ---------------------------------------------------------------------------

#[test]
fn nonce_reuse_and_binding() {
    let mut h = H::default();
    let a = h.principal();
    let b = h.principal();
    let t = one_read(1);
    let approval = h.approval(a, t);
    let Ok(Effect::RootCreated {
        root,
        capability,
        kind,
    }) = h.admin(AdminCommand::Mint { approval })
    else {
        panic!()
    };
    assert_eq!(
        kind,
        RootKind::Approved {
            nonce: approval.nonce()
        }
    );
    let rr = h.s.root(root).unwrap();
    assert_eq!(
        (rr.terms(), rr.recipient(), rr.capability()),
        (t, a, capability)
    );
    // Exact reuse.
    assert_eq!(
        h.admin(AdminCommand::Mint { approval }),
        Err(Denial::NonceReused)
    );
    // Same nonce, mutated payload (different recipient / budget): still the nonce.
    let mutated = VerifiedApproval::new(
        approval.nonce(),
        GrantRequest {
            recipient: b,
            terms: Terms {
                budget: Budget::Finite(100),
                ..t
            },
            ..*approval.request()
        },
    );
    assert_eq!(
        h.admin(AdminCommand::Mint { approval: mutated }),
        Err(Denial::NonceReused)
    );
    assert_eq!(h.s.roots().count(), 1);
}

#[test]
fn mint_rejects_wrong_epoch_expired_request_and_bad_terms() {
    let mut h = H::default();
    let a = h.principal();
    let t = one_read(1);
    let mk = |nonce: u8, epoch: u64, exp: u64, terms: Terms| {
        VerifiedApproval::new(
            Nonce::from_bytes([nonce; 32]),
            GrantRequest {
                epoch,
                recipient: a,
                terms,
                request_expires: Tick::from_raw(exp),
            },
        )
    };
    h.now = 50;
    assert_eq!(
        h.admin(AdminCommand::Mint {
            approval: mk(200, 1, 100, t)
        }),
        Err(Denial::ApprovalEpochMismatch)
    );
    assert_eq!(
        h.admin(AdminCommand::Mint {
            approval: mk(201, 0, 50, t)
        }),
        Err(Denial::ApprovalExpired)
    );
    let empty = Terms {
        scope: file(1, FileRights::empty()),
        ..t
    };
    assert_eq!(
        h.admin(AdminCommand::Mint {
            approval: mk(202, 0, 100, empty)
        }),
        Err(Denial::InvalidScope)
    );
    let zero = Terms {
        budget: Budget::Finite(0),
        ..t
    };
    assert_eq!(
        h.admin(AdminCommand::Mint {
            approval: mk(203, 0, 100, zero)
        }),
        Err(Denial::ZeroAllocation)
    );
    // Denied mints do not spend the nonce.
    assert!(!h.s.is_nonce_spent(&Nonce::from_bytes([203; 32])));
    assert!(
        h.admin(AdminCommand::Mint {
            approval: mk(203, 0, 100, t)
        })
        .is_ok()
    );
}

#[test]
fn baseline_grants_are_recorded_separately() {
    let mut h = H::default();
    let a = h.principal();
    let t = terms(
        file(9, FileRights::READ),
        Budget::Unlimited,
        Depth::Finite(0),
        Expiry::Never,
    );
    let Ok(Effect::RootCreated {
        root,
        capability,
        kind,
    }) = h.admin(AdminCommand::InstallBaseline {
        recipient: a,
        terms: t,
    })
    else {
        panic!()
    };
    assert_eq!(kind, RootKind::Baseline);
    assert_eq!(h.s.root(root).unwrap().kind(), RootKind::Baseline);
    assert!(h.s.roots().all(|r| r.kind() == RootKind::Baseline));
    h.consume_ok(a, capability, read(9));
}

// ---------------------------------------------------------------------------
// ATTENUATE and DROP
// ---------------------------------------------------------------------------

#[test]
fn attenuate_only_decreases_and_accounts_discard() {
    let mut h = H::default();
    let a = h.principal();
    let b = h.principal();
    let rw = FileRights::READ.union(FileRights::REPLACE);
    let cap = h.mint(
        a,
        terms(file(1, rw), Budget::Finite(10), Depth::Finite(2), at(100)),
    );
    let child = h
        .delegate(
            a,
            cap,
            b,
            terms(file(1, rw), Budget::Finite(4), Depth::Finite(1), at(100)),
        )
        .unwrap();
    let base = terms(file(1, rw), Budget::Finite(6), Depth::Finite(2), at(100));
    let att = |h: &mut H, t: Terms| {
        h.agent_cmd(
            a,
            AgentCommand::Attenuate {
                capability: cap,
                terms: t,
            },
        )
    };
    assert_eq!(
        att(
            &mut h,
            Terms {
                budget: Budget::Finite(7),
                ..base
            }
        ),
        Err(Denial::BudgetNotAttenuated)
    );
    assert_eq!(
        att(
            &mut h,
            Terms {
                budget: Budget::Unlimited,
                ..base
            }
        ),
        Err(Denial::BudgetNotAttenuated)
    );
    assert_eq!(
        att(
            &mut h,
            Terms {
                depth: Depth::Finite(3),
                ..base
            }
        ),
        Err(Denial::DepthNotAttenuated)
    );
    assert_eq!(
        att(
            &mut h,
            Terms {
                expiry: at(101),
                ..base
            }
        ),
        Err(Denial::ExpiryNotAttenuated)
    );
    assert_eq!(
        att(
            &mut h,
            Terms {
                scope: file(2, FileRights::READ),
                ..base
            }
        ),
        Err(Denial::ScopeNotAttenuated)
    );
    // Narrow everything; same-owner attenuation can reduce depth to zero.
    let narrow = terms(
        file(1, FileRights::READ),
        Budget::Finite(2),
        Depth::Finite(0),
        at(50),
    );
    assert_eq!(
        att(&mut h, narrow),
        Ok(Effect::Attenuated {
            capability: cap,
            discarded: 4
        })
    );
    let rec = h.s.capability(cap).unwrap();
    assert_eq!(
        (rec.scope(), rec.budget(), rec.depth(), rec.expiry()),
        (narrow.scope, narrow.budget, narrow.depth, narrow.expiry)
    );
    assert_eq!(rec.origin().budget, Budget::Finite(10));
    let acct = h.account_of(cap);
    assert_eq!(
        (acct.initial, acct.live, acct.discarded_explicit),
        (10, 6, 4)
    );
    // Not retroactive: the child keeps REPLACE and its own expiry.
    let replace = Operation::File {
        object: ObjectId::from_raw(1),
        right: FileRight::Replace,
    };
    h.consume_ok(b, child, replace);
    assert_eq!(
        h.consume(a, cap, replace),
        Err(Denial::OperationNotPermitted)
    );
    h.now = 60;
    assert_eq!(
        h.consume(a, cap, read(1)),
        Err(Denial::NotLive(NotLive::Expired))
    );
    h.consume_ok(b, child, read(1));
}

#[test]
fn attenuate_unlimited_to_finite_creates_boundary() {
    let mut h = H::default();
    let a = h.principal();
    let cap = h.mint(
        a,
        terms(
            get_scope(1),
            Budget::Unlimited,
            Depth::Unlimited,
            Expiry::Never,
        ),
    );
    let child = h
        .split(
            a,
            cap,
            terms(
                get_scope(1),
                Budget::Finite(5),
                Depth::Unlimited,
                Expiry::Never,
            ),
        )
        .unwrap();
    h.agent_cmd(
        a,
        AgentCommand::Attenuate {
            capability: cap,
            terms: terms(
                get_scope(1),
                Budget::Finite(3),
                Depth::Unlimited,
                Expiry::Never,
            ),
        },
    )
    .unwrap();
    let accts = h.s.accounts().unwrap();
    assert_eq!(accts.len(), 2);
    assert!(accts.iter().any(|p| p.anchor == child && p.initial == 5));
    assert!(accts.iter().any(|p| p.anchor == cap && p.initial == 3));
    // New children of `cap` now draw from its finite pool.
    let gc = h
        .split(
            a,
            cap,
            terms(
                get_scope(1),
                Budget::Finite(2),
                Depth::Unlimited,
                Expiry::Never,
            ),
        )
        .unwrap();
    assert_eq!(
        h.s.capability(gc).unwrap().pool(),
        h.s.capability(cap).unwrap().pool()
    );
    assert_eq!(h.budget(cap), Budget::Finite(1));
}

#[test]
fn drop_discards_balance_but_keeps_descendants() {
    let mut h = H::default();
    let a = h.principal();
    let b = h.principal();
    let cap = h.mint(
        a,
        terms(
            get_scope(1),
            Budget::Finite(10),
            Depth::Finite(1),
            Expiry::Never,
        ),
    );
    let child = h
        .delegate(
            a,
            cap,
            b,
            terms(
                get_scope(1),
                Budget::Finite(4),
                Depth::Finite(0),
                Expiry::Never,
            ),
        )
        .unwrap();
    assert_eq!(
        h.agent_cmd(a, AgentCommand::Drop { capability: cap }),
        Ok(Effect::Dropped {
            capability: cap,
            discarded: 6
        })
    );
    assert_eq!(
        h.consume(a, cap, get(1)),
        Err(Denial::NotLive(NotLive::Dropped))
    );
    h.consume_ok(b, child, get(1));
    let acct = h.account_of(cap);
    assert_eq!(
        (
            acct.consumed,
            acct.live,
            acct.discarded_explicit,
            acct.discarded_stranded
        ),
        (1, 3, 6, 0)
    );
    // A dropped capability's owner can still revoke what it delegated.
    h.agent_cmd(a, AgentCommand::Revoke { capability: child })
        .unwrap();
    assert_eq!(
        h.consume(b, child, get(1)),
        Err(Denial::NotLive(NotLive::Revoked))
    );
}

// ---------------------------------------------------------------------------
// Bounds and overflow (T8)
// ---------------------------------------------------------------------------

#[test]
fn capacity_and_lineage_bounds_deny() {
    let limits = Limits {
        max_capabilities: 3,
        max_lineage_length: 1,
        max_principals: 2,
        ..Limits::default()
    };
    let mut h = H::new(limits);
    let a = h.principal();
    let _b = h.principal();
    assert_eq!(
        h.admin(AdminCommand::CreatePrincipal),
        Err(Denial::CapacityExceeded(Resource::Principals))
    );
    let root = h.mint(
        a,
        terms(
            get_scope(1),
            Budget::Finite(10),
            Depth::Unlimited,
            Expiry::Never,
        ),
    );
    let t = terms(
        get_scope(1),
        Budget::Finite(1),
        Depth::Unlimited,
        Expiry::Never,
    );
    let c1 = h.split(a, root, t).unwrap();
    assert_eq!(h.split(a, c1, t), Err(Denial::LineageTooLong));
    let _c2 = h.split(a, root, t).unwrap();
    assert_eq!(
        h.split(a, root, t),
        Err(Denial::CapacityExceeded(Resource::Capabilities))
    );
}

#[test]
fn maximal_budgets_do_not_overflow() {
    let mut h = H::default();
    let a = h.principal();
    let root = h.mint(
        a,
        terms(
            get_scope(1),
            Budget::Unlimited,
            Depth::Unlimited,
            Expiry::Never,
        ),
    );
    let big = terms(
        get_scope(1),
        Budget::Finite(u64::MAX),
        Depth::Unlimited,
        Expiry::Never,
    );
    let c1 = h.split(a, root, big).unwrap();
    let _c2 = h.split(a, root, big).unwrap();
    let gc = h.split(a, c1, big).unwrap();
    assert_eq!(h.budget(c1), Budget::Finite(0));
    h.consume_ok(a, gc, get(1));
    assert_eq!(h.split(a, gc, big), Err(Denial::InsufficientBudget));
    let max_expiry = terms(
        get_scope(1),
        Budget::Finite(1),
        Depth::Unlimited,
        Expiry::At(Tick::from_raw(u64::MAX)),
    );
    let _ = h.split(a, gc, max_expiry).unwrap();
}

fn patch_json(s: &State, field: &str, value: &str) -> String {
    let json = serde_json::to_string(s).unwrap();
    let key = format!("\"{field}\":");
    let start = json.find(&key).unwrap() + key.len();
    let end = start + json[start..].find([',', '}']).unwrap();
    format!("{}{}{}", &json[..start], value, &json[end..])
}

#[test]
fn exhausted_counters_deny_without_mutation() {
    let mut h = H::default();
    let a = h.principal();
    let root = h.mint(
        a,
        terms(
            get_scope(1),
            Budget::Finite(10),
            Depth::Unlimited,
            Expiry::Never,
        ),
    );
    let t = terms(
        get_scope(1),
        Budget::Finite(1),
        Depth::Unlimited,
        Expiry::Never,
    );

    h.s = serde_json::from_str(&patch_json(&h.s, "sequence", &u64::MAX.to_string())).unwrap();
    assert_eq!(h.consume(a, root, get(1)), Err(Denial::ArithmeticOverflow));
    assert_eq!(h.budget(root), Budget::Finite(10));

    let mut h2 = H::default();
    let a2 = h2.principal();
    let r2 = h2.mint(
        a2,
        terms(
            get_scope(1),
            Budget::Finite(10),
            Depth::Unlimited,
            Expiry::Never,
        ),
    );
    h2.s = serde_json::from_str(&patch_json(
        &h2.s,
        "next_capability",
        &u128::MAX.to_string(),
    ))
    .unwrap();
    assert_eq!(h2.split(a2, r2, t), Err(Denial::ArithmeticOverflow));
    assert_eq!(h2.budget(r2), Budget::Finite(10));
}

// ---------------------------------------------------------------------------
// Snapshots and replay (rebuild from journal)
// ---------------------------------------------------------------------------

#[test]
fn corrupt_snapshot_is_rejected() {
    let mut h = H::default();
    let a = h.principal();
    let _ = h.mint(
        a,
        terms(
            get_scope(1),
            Budget::Finite(10),
            Depth::Unlimited,
            Expiry::Never,
        ),
    );
    let good = serde_json::to_string(&h.s).unwrap();
    assert!(serde_json::from_str::<State>(&good).is_ok());
    // Inflate the root balance: conservation must fail.
    let bad = good.replace("\"budget\":{\"Finite\":10}", "\"budget\":{\"Finite\":11}");
    assert_ne!(bad, good);
    let err = serde_json::from_str::<State>(&bad).unwrap_err().to_string();
    assert!(err.contains("invariant"), "{err}");
    // Clear the spent nonce table: nonce invariant must fail.
    let json = serde_json::to_string(&h.s).unwrap();
    let start = json.find("\"spent_nonces\":").unwrap();
    let end = start + json[start..].find(",\"reservations\"").unwrap();
    let bad2 = format!("{}\"spent_nonces\":[]{}", &json[..start], &json[end..]);
    assert!(serde_json::from_str::<State>(&bad2).is_err());
}

#[test]
fn replay_rebuilds_identical_state() {
    let mut log = Vec::new();
    let mut s = State::new(Limits::default());
    let mut run = |s: &mut State, cmd: AuthenticatedCommand, t: u64| {
        let r = step(s, cmd, Tick::from_raw(t));
        if r.is_ok() {
            log.push((cmd, Tick::from_raw(t)));
        }
        r
    };
    let Ok(Effect::PrincipalCreated { agent: a }) = run(
        &mut s,
        AuthenticatedCommand::operator(AdminCommand::CreatePrincipal),
        0,
    ) else {
        panic!()
    };
    let t = terms(
        get_scope(1),
        Budget::Finite(5),
        Depth::Finite(1),
        Expiry::Never,
    );
    let approval = VerifiedApproval::new(
        Nonce::from_bytes([9; 32]),
        GrantRequest {
            epoch: 0,
            recipient: a,
            terms: t,
            request_expires: Tick::from_raw(10),
        },
    );
    let Ok(Effect::RootCreated { capability, .. }) = run(
        &mut s,
        AuthenticatedCommand::operator(AdminCommand::Mint { approval }),
        1,
    ) else {
        panic!()
    };
    let consume = AgentCommand::Consume {
        request_id: RequestId::from_raw(1),
        capability,
        operation: get(1),
    };
    run(&mut s, AuthenticatedCommand::agent(a, consume), 2).unwrap();
    run(
        &mut s,
        AuthenticatedCommand::operator(AdminCommand::BumpEpoch),
        0,
    )
    .unwrap();
    let rebuilt = State::replay(Limits::default(), log.clone()).unwrap();
    assert_eq!(rebuilt, s);
    // A log entry that is denied on replay is reported.
    let mut bad = log;
    bad.push((AuthenticatedCommand::agent(a, consume), Tick::from_raw(3)));
    assert!(matches!(
        State::replay(Limits::default(), bad),
        Err(ReplayError::Denied {
            index: 4,
            denial: Denial::StaleEpoch
        })
    ));
}

// ---------------------------------------------------------------------------
// §12.2 multi-agent research swarm
// ---------------------------------------------------------------------------

#[test]
fn swarm_example_12_2() {
    let mut h = H::default();
    let a = h.principal();
    let b = h.principal();
    let c = h.principal();
    let d = h.principal();
    let e = get_scope(1);
    let t = |n: u64, depth: u32| terms(e, Budget::Finite(n), Depth::Finite(depth), Expiry::Never);

    // Operator grants A 100 HTTPS requests to endpoint E, depth two.
    let approval = h.approval(a, t(100, 2));
    let Ok(Effect::RootCreated {
        root,
        capability: ca,
        ..
    }) = h.admin(AdminCommand::Mint { approval })
    else {
        panic!()
    };
    // A delegates 30 to B and 20 to C, retaining 50.
    let cb = h.delegate(a, ca, b, t(30, 1)).unwrap();
    let cc = h.delegate(a, ca, c, t(20, 1)).unwrap();
    assert_eq!(h.budget(ca), Budget::Finite(50));
    // B delegates 10 of its 30 to D with depth zero, retaining 20.
    let cd = h.delegate(b, cb, d, t(10, 0)).unwrap();
    assert_eq!(h.budget(cb), Budget::Finite(20));
    // D cannot delegate further.
    assert_eq!(h.delegate(d, cd, a, t(1, 0)), Err(Denial::NotDelegatable));
    // Across A, B, C and D the finite budget remains 100.
    let acct = h.account_of(ca);
    assert_eq!(
        (acct.initial, acct.live, acct.consumed, acct.discarded()),
        (100, 100, 0, 0)
    );
    // After D uses 3, remaining balance is 97.
    let mut reservations = Vec::new();
    for _ in 0..3 {
        let Ok(Effect::Reserved(r)) = h.consume(d, cd, get(1)) else {
            panic!()
        };
        reservations.push(r);
    }
    let acct = h.account_of(ca);
    assert_eq!((acct.live, acct.consumed), (97, 3));
    // Revoking B invalidates the remaining B and D balances, without affecting C.
    h.admin(AdminCommand::Revoke { capability: cb }).unwrap();
    assert_eq!(
        h.consume(b, cb, get(1)),
        Err(Denial::NotLive(NotLive::Revoked))
    );
    assert_eq!(
        h.consume(d, cd, get(1)),
        Err(Denial::NotLive(NotLive::AncestorRevoked(cb)))
    );
    h.consume_ok(c, cc, get(1));
    h.consume_ok(a, ca, get(1));
    let acct = h.account_of(ca);
    // live: A 49 + C 19; consumed: 3 + 2; stranded: B 20 + D 7.
    assert_eq!(
        (
            acct.live,
            acct.consumed,
            acct.discarded_stranded,
            acct.discarded_explicit
        ),
        (68, 5, 27, 0)
    );
    assert_eq!(acct.live + acct.consumed + acct.discarded(), 100);
    // The audit identifies the root approval for each attempt.
    for r in &reservations {
        assert_eq!(r.root(), root);
        assert_eq!(h.s.lineage(r.capability()), vec![cd, cb, ca]);
        assert!(matches!(
            h.s.root(r.root()).unwrap().kind(),
            RootKind::Approved { .. }
        ));
    }
}

// ---------------------------------------------------------------------------
// ADR-0031: compaction at the epoch boundary (security review finding 3)
// ---------------------------------------------------------------------------

/// An attacker that fills the record capacity in one epoch cannot deny
/// service in the next: `CompactEpoch` prunes the dead epoch, frees every
/// bounded table, keeps the spent nonces and accounts for the pruned pools.
#[test]
fn compaction_frees_capacity_filled_by_a_previous_epoch() {
    let limits = Limits {
        max_capabilities: 6,
        max_principals: 3,
        max_roots: 2,
        max_reservations: 2,
        max_lineage_length: 8,
    };
    let mut h = H::new(limits);
    let attacker = h.principal();
    let wide = terms(
        get_scope(1),
        Budget::Finite(20),
        Depth::Unlimited,
        Expiry::Never,
    );
    let root = h.mint(attacker, wide);
    let second = h.approval(attacker, wide);
    assert!(matches!(
        h.admin(AdminCommand::Mint { approval: second }),
        Ok(Effect::RootCreated { .. })
    ));
    let piece = terms(
        get_scope(1),
        Budget::Finite(1),
        Depth::Unlimited,
        Expiry::Never,
    );
    while h.split(attacker, root, piece).is_ok() {}
    h.consume_ok(attacker, root, get(1));
    h.consume_ok(attacker, root, get(1));
    let _ = h.principal();
    let _ = h.principal();
    assert_eq!(
        h.split(attacker, root, piece),
        Err(Denial::CapacityExceeded(Resource::Capabilities))
    );
    assert_eq!(
        h.admin(AdminCommand::CreatePrincipal),
        Err(Denial::CapacityExceeded(Resource::Principals))
    );

    // Restart: the epoch bump alone frees nothing.
    h.now = 0;
    h.admin(AdminCommand::BumpEpoch).unwrap();
    assert_eq!(
        h.admin(AdminCommand::CreatePrincipal),
        Err(Denial::CapacityExceeded(Resource::Principals))
    );
    let (initial_before, consumed_before) =
        h.s.accounts()
            .unwrap()
            .iter()
            .fold((0u128, 0u128), |(i, c), a| {
                (i + a.initial as u128, c + a.consumed as u128)
            });
    let Ok(Effect::EpochCompacted {
        principals,
        capabilities,
        roots,
        pools,
        reservations,
        initial,
        consumed,
        discarded,
    }) = h.admin(AdminCommand::CompactEpoch)
    else {
        panic!("compaction failed")
    };
    assert_eq!(
        (principals, capabilities, roots, pools, reservations),
        (3, 6, 2, 2, 2)
    );
    assert_eq!((initial, consumed), (initial_before, consumed_before));
    assert_eq!(initial, consumed + discarded);
    assert_eq!(h.s.retired().initial, initial);
    assert_eq!(h.s.capabilities().count(), 0);
    assert_eq!(h.s.reservations().count(), 0);
    assert_eq!(h.s.capability(root), None);

    // A fresh principal is served again.
    let victim = h.principal();
    let cap = h.mint(victim, one_read(1));
    h.consume_ok(victim, cap, read(1));
    // Ids are never reused, and every earlier nonce stays spent.
    assert!(cap > root);
    assert!(h.s.is_nonce_spent(&Nonce::from_bytes([1; 32])));
    assert!(h.s.is_nonce_spent(&Nonce::from_bytes([2; 32])));
    let stale = VerifiedApproval::new(
        Nonce::from_bytes([1; 32]),
        GrantRequest {
            epoch: h.s.epoch(),
            recipient: victim,
            terms: one_read(1),
            request_expires: Tick::from_raw(h.now + 10),
        },
    );
    assert_eq!(
        h.admin(AdminCommand::Mint { approval: stale }),
        Err(Denial::NonceReused)
    );
    // A pruned capability id is simply unknown now.
    assert_eq!(
        h.consume(victim, root, get(1)),
        Err(Denial::UnknownCapability)
    );
}

/// Compaction only removes earlier epochs and is idempotent; current
/// records, their liveness and their request-id bindings are untouched.
#[test]
fn compaction_keeps_the_current_epoch() {
    let mut h = H::default();
    let old = h.principal();
    let _ = h.mint(old, one_read(1));
    h.now = 0;
    h.admin(AdminCommand::BumpEpoch).unwrap();
    let a = h.principal();
    let b = h.principal();
    let cap = h.mint(
        a,
        terms(
            file(1, FileRights::READ),
            Budget::Finite(4),
            Depth::Finite(1),
            Expiry::Never,
        ),
    );
    let child = h.delegate(a, cap, b, one_read(1)).unwrap();
    let rid = h.consume(a, cap, read(1)).unwrap();
    let before_caps: Vec<CapabilityId> = h.s.capabilities().map(|c| c.id()).collect();
    assert!(matches!(
        h.admin(AdminCommand::CompactEpoch),
        Ok(Effect::EpochCompacted {
            capabilities: 1,
            roots: 1,
            principals: 1,
            ..
        })
    ));
    let after_caps: Vec<CapabilityId> = h.s.capabilities().map(|c| c.id()).collect();
    assert_eq!(after_caps, before_caps[1..].to_vec());
    assert!(h.s.is_live(child, h.t()));
    let Effect::Reserved(r) = rid else { panic!() };
    // The same request id is still recognised as a duplicate.
    assert!(matches!(
        h.agent_cmd(
            a,
            AgentCommand::Consume {
                request_id: r.request_id(),
                capability: cap,
                operation: read(1)
            }
        ),
        Ok(Effect::AlreadyReserved { .. })
    ));
    // Nothing left to prune: a second compaction changes no record.
    assert!(matches!(
        h.admin(AdminCommand::CompactEpoch),
        Ok(Effect::EpochCompacted {
            capabilities: 0,
            roots: 0,
            principals: 0,
            pools: 0,
            reservations: 0,
            ..
        })
    ));
}

/// A compacted ledger round-trips through a snapshot, and a snapshot whose
/// retired totals or pruned-root floor were tampered with is rejected.
#[test]
fn compacted_snapshot_is_checked() {
    let mut h = H::default();
    let a = h.principal();
    let _ = h.mint(a, one_read(1));
    h.now = 0;
    h.admin(AdminCommand::BumpEpoch).unwrap();
    h.admin(AdminCommand::CompactEpoch).unwrap();
    let good = serde_json::to_string(&h.s).unwrap();
    let back: State = serde_json::from_str(&good).unwrap();
    assert_eq!(back, h.s);
    // The nonce now names a pruned root: lowering the floor exposes it.
    assert!(serde_json::from_str::<State>(&patch_json(&h.s, "retired_roots_below", "0")).is_err());
    let inflated = good.replace("\"initial\":1,", "\"initial\":2,");
    assert_ne!(inflated, good);
    assert!(serde_json::from_str::<State>(&inflated).is_err());
}
