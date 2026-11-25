#!/usr/bin/env python3
"""Explicit-state model of the BPF LSM direct-grant generation protocol (WP7).

Python 3 standard library only.  Run with:

    python3 -I models/bpf_generation_model.py            # correct protocol + every bug variant
    python3 -I models/bpf_generation_model.py --no-bugs --crashes 2
    python3 -I models/bpf_generation_model.py --bug no-barrier

It models docs/bpf-lsm.md section 6 and the Rust state machine in
enforcement/ebpf/manager/src/manager.rs (spec section 10.3).  It does not
model the BPF program's hook coverage: that is the hook matrix's job.

Actors and state
----------------
* Broker: issues desired generations 1..len(SCRIPT) in order; generation g
  grants the object set SCRIPT[g-1] to one sandbox.  It receives
  "installed(g)" reports with revocation acknowledgements.  It may go down
  once (then nobody renews the lease).
* Manager: performs one transition at a time, G -> D = latest issued, as small kernel
  steps: reconcile, stage each entry, freeze (barrier), activate, thaw,
  delete each retired entry, verify + report.  A freeze can time out (the
  transition aborts and leaves staged entries behind).  The manager can crash
  at any step; pinned maps survive.  A restarted manager first expires the
  lease, then deletes every entry and thaws.
* Kernel: active generation, grant entries (obj, gen_from, gen_until), frozen
  flag, lease (ticks left).  A check passes for obj o iff the lease is live,
  the cgroup is not frozen, and an entry for o is valid at the active
  generation.
* Workload: a hook is two steps.  CHECK reads the maps and passes or fails;
  COMPLETE performs the access (the syscall returns data).  At most one hook
  is in flight.  A frozen cgroup neither starts nor completes hooks, and
  freezing waits until no hook is in flight (cgroup.freeze semantics).
* Time: TICK decrements the lease.  The manager renews it only while alive,
  idle and connected to a live broker.

Invariants
----------
  KernelWithinActiveGeneration  whenever a check could pass, the entries
                                valid at the active generation are a subset of
                                the broker's set for that generation (no stale
                                or partially installed generation is usable)
  NoUseAfterRevocationAck       no access to o completes after the broker got a
                                revocation ack for o at generation r, unless it
                                was authorised by a later generation that
                                grants o again
  AckAfterRemoval               when a revocation of o at r is acknowledged, no
                                entry for o is valid at any generation <= r
  ManagerFailureFailsClosed     once the manager or broker has been down for
                                more than LEASE ticks, no check passes
  RestartFailsClosed            after a manager restart, no check passes on a
                                generation installed before the restart; only a
                                fresh generation installed by the restarted
                                manager is usable
  ActiveNeverAheadOfDesired     the kernel's active generation was issued by
                                the broker

Bug variants (--bug NAME) each break one rule:
  ack-before-removal      report (and ack revocations) right after activation
  no-barrier              skip the freeze barrier
  activate-before-stage   activate before staging removals
  no-reconcile            do not clean up leftovers of an aborted transition
  no-lease                the BPF program ignores the lease
  restart-trusts-maps     a restarted manager keeps installed entries and lease
"""

import argparse
import sys
from collections import deque

OBJS = ("a", "b")
# Generation g (1-based) grants SCRIPT[g-1].  Gen 2 revokes a and grants b,
# gen 3 revokes b and re-grants a, gen 4 grants both.
SCRIPT = (frozenset("a"), frozenset("b"), frozenset("a"), frozenset("ab"))
LEASE = 2
INF = 99
BUGS = (
    "ack-before-removal",
    "no-barrier",
    "activate-before-stage",
    "no-reconcile",
    "no-lease",
    "restart-trusts-maps",
)

# State is a tuple of these fields (in order).
FIELDS = (
    "issued",        # highest generation the broker has issued
    "broker_up",
    "broker_downs",  # how many times the broker went down (bounded)
    "m_alive",
    "m_pc",          # manager program counter, see manager_steps()
    "m_todo",        # frozenset of pending entry ops in this phase
    "m_target",      # target generation D of the current transition
    "m_revoking",    # objects this transition removes (acked at report)
    "restart_floor", # ghost: active generation when the manager last restarted (-1: never)
    "crashes",
    "aborts",
    "active",        # kernel active generation
    "entries",       # frozenset of (obj, gen_from, gen_until)
    "frozen",
    "lease",         # ticks left
    "down_ticks",    # ghost: ticks since manager/broker failure (capped)
    "inflight",      # None or (obj, gen at check)
    "acked",         # frozenset of (obj, gen) revocation acks received by broker
)
IDX = {f: i for i, f in enumerate(FIELDS)}


def g(s, k):
    return s[IDX[k]]


def upd(s, **kw):
    s = list(s)
    for k, v in kw.items():
        s[IDX[k]] = v
    return tuple(s)


def initial():
    return tuple({
        "issued": 0, "broker_up": True, "broker_downs": 0, "m_alive": True,
        "m_pc": "idle", "m_todo": frozenset(), "m_target": 0, "m_revoking": frozenset(),
        "restart_floor": -1, "crashes": 0,
        "aborts": 0, "active": 0, "entries": frozenset(), "frozen": False,
        "lease": LEASE, "down_ticks": 0, "inflight": None, "acked": frozenset()
    }[f] for f in FIELDS)


def desired(gen):
    return SCRIPT[gen - 1] if gen >= 1 else frozenset()


def valid(entry, gen):
    _, lo, hi = entry
    return lo <= gen < hi


def valid_objs(entries, gen):
    return frozenset(o for (o, lo, hi) in entries if lo <= gen < hi)


def check_passes(s, o, bug):
    if g(s, "frozen"):
        return False
    if g(s, "lease") == 0 and bug != "no-lease":
        return False
    return o in valid_objs(g(s, "entries"), g(s, "active"))


def manager_steps(s, cfg, bug):
    """Successors from the manager's current program counter."""
    pc = g(s, "m_pc")
    G = g(s, "active")
    D = g(s, "m_target")
    ents = g(s, "entries")
    out = []
    if pc == "idle":
        # Like the Rust manager, jump straight to the latest desired generation.
        if g(s, "issued") > G:
            D = g(s, "issued")
            if bug == "no-reconcile":
                todo = frozenset()
            else:
                todo = frozenset(e for e in ents if not (e[1] <= G and e[2] == INF))
            out.append((f"begin {G}->{D}", upd(s, m_pc="reconcile", m_todo=todo, m_target=D)))
        return out
    if pc == "reconcile":
        todo = g(s, "m_todo")
        if todo:
            for e in sorted(todo):
                o, lo, hi = e
                ne = ents - {e}
                if lo <= G < hi:          # aborted removal: re-open
                    ne = ne | {(o, lo, INF)}
                out.append((f"reconcile {e}", upd(s, entries=ne, m_todo=todo - {e})))
            return out
        installed = valid_objs(ents, G)
        revoking = installed - desired(D)
        ops = frozenset(("add", o) for o in desired(D) - installed) | \
            frozenset(("rem", o) for o in revoking)
        if bug == "activate-before-stage":
            return [("plan", upd(s, m_pc="activate", m_todo=ops, m_revoking=revoking))]
        return [("plan", upd(s, m_pc="stage", m_todo=ops, m_revoking=revoking))]
    if pc in ("stage", "late-stage"):
        todo = g(s, "m_todo")
        if todo:
            for op in sorted(todo):
                kind, o = op
                if kind == "add":
                    ne = ents | {(o, D, INF)}
                else:
                    old = next(e for e in ents if e[0] == o and valid(e, G))
                    ne = (ents - {old}) | {(o, old[1], D)}
                out.append((f"stage {kind} {o}@{D}", upd(s, entries=ne, m_todo=todo - {op})))
            return out
        if pc == "late-stage":
            return [("to-thaw", upd(s, m_pc="thaw"))]
        if g(s, "m_revoking") and bug != "no-barrier":
            return [("to-freeze", upd(s, m_pc="freeze"))]
        return [("to-activate", upd(s, m_pc="activate"))]
    if pc == "freeze":
        # cgroup.freeze completes only when no hook is in flight.
        if g(s, "inflight") is None:
            out.append(("freeze", upd(s, frozen=True, m_pc="activate")))
        if g(s, "aborts") < cfg["aborts"]:
            out.append(("freeze-timeout (abort)", upd(s, m_pc="idle", m_todo=frozenset(),
                                                      m_revoking=frozenset(),
                                                      aborts=g(s, "aborts") + 1)))
        return out
    if pc == "activate":
        if bug == "activate-before-stage":
            return [(f"activate {D}", upd(s, active=D, m_pc="late-stage"))]
        return [(f"activate {D}", upd(s, active=D, m_pc="thaw"))]
    if pc == "thaw":
        retired = frozenset(e for e in ents if e[2] <= G)
        nxt = upd(s, frozen=False, m_pc="cleanup", m_todo=retired)
        if bug == "ack-before-removal":
            nxt = upd(report(nxt), m_pc="cleanup", m_todo=retired)
        return [("thaw", nxt)]
    if pc == "cleanup":
        todo = g(s, "m_todo")
        if todo:
            for e in sorted(todo):
                out.append((f"delete {e}", upd(s, entries=ents - {e}, m_todo=todo - {e})))
            return out
        if bug == "ack-before-removal":
            return [("done", upd(s, m_pc="idle", m_revoking=frozenset()))]
        return [("verify+report", report(s))]
    raise AssertionError(pc)


def report(s):
    """Manager reports installed(active) to the broker, acking revocations.

    Verification (read back active == target, valid set == desired, no
    retired entries) is folded into this step; the correct protocol only
    reaches it when verification would succeed."""
    G = g(s, "active")
    acks = g(s, "acked") | frozenset((o, G) for o in g(s, "m_revoking"))
    return upd(s, acked=acks, m_pc="idle", m_todo=frozenset(), m_revoking=frozenset())


def successors(s, cfg, bug):
    out = []
    # Broker issues the next generation.
    if g(s, "broker_up") and g(s, "issued") < len(SCRIPT):
        out.append((f"issue {g(s, 'issued') + 1}", upd(s, issued=g(s, "issued") + 1)))
    if g(s, "broker_up") and g(s, "broker_downs") < cfg["broker_downs"]:
        out.append(("broker down", upd(s, broker_up=False, broker_downs=g(s, "broker_downs") + 1)))
    # Manager.
    if g(s, "m_alive"):
        out.extend(manager_steps(s, cfg, bug))
        if g(s, "crashes") < cfg["crashes"]:
            out.append(("manager crash", upd(s, m_alive=False, m_pc="dead", m_todo=frozenset(),
                                             m_revoking=frozenset(),
                                             crashes=g(s, "crashes") + 1)))
        if g(s, "m_pc") == "idle" and g(s, "broker_up") and g(s, "lease") < LEASE:
            out.append(("renew", upd(s, lease=LEASE)))
    else:
        dt = 0 if g(s, "broker_up") else g(s, "down_ticks")
        if bug == "restart-trusts-maps":
            r = upd(s, m_alive=True, m_pc="idle", restart_floor=g(s, "active"),
                    down_ticks=dt)
        else:
            # Expire the lease first, then wipe entries and thaw.
            r = upd(s, m_alive=True, m_pc="idle", lease=0, entries=frozenset(), frozen=False,
                    restart_floor=g(s, "active"), down_ticks=dt)
        out.append(("manager restart", r))
    # Time.
    failed = (not g(s, "m_alive")) or (not g(s, "broker_up"))
    if g(s, "lease") > 0 or (failed and g(s, "down_ticks") <= LEASE):
        dt = min(g(s, "down_ticks") + 1, LEASE + 1) if failed else 0
        out.append(("tick", upd(s, lease=max(0, g(s, "lease") - 1), down_ticks=dt)))
    # Workload hooks.
    if not g(s, "frozen"):
        if g(s, "inflight") is None:
            for o in OBJS:
                if check_passes(s, o, bug):
                    out.append((f"check {o} passes@{g(s, 'active')}",
                                upd(s, inflight=(o, g(s, "active")))))
        else:
            out.append((f"complete {g(s, 'inflight')[0]}", upd(s, inflight=None)))
    return out


# ---------------------------------------------------------------- invariants

def inv_kernel_within_active(s, prev, label):
    if g(s, "frozen"):
        return None  # no hook can run
    act = g(s, "active")
    v = valid_objs(g(s, "entries"), act)
    if v - desired(act):
        return (f"objects {sorted(v - desired(act))} usable at generation {act}, "
                f"which grants {sorted(desired(act))}")
    return None


def inv_no_use_after_ack(s, prev, label):
    if prev is None or not label.startswith("complete"):
        return None
    o, gen = g(prev, "inflight")
    for (ao, ag) in g(s, "acked"):
        if ao == o and gen < ag:
            return f"access to {o} authorised at generation {gen} completed after revocation ack at {ag}"
    return None


def inv_ack_after_removal(s, prev, label):
    if prev is None:
        return None
    for (o, r) in g(s, "acked") - g(prev, "acked"):
        left = [e for e in g(s, "entries") if e[0] == o]
        if left:
            return f"revocation of {o} at generation {r} acked while entries {left} remain"
    return None


def inv_failure_fails_closed(s, prev, label):
    if prev is None or not label.startswith("check"):
        return None
    if g(prev, "down_ticks") > LEASE:
        return f"check passed {g(prev, 'down_ticks')} ticks after manager/broker failure (lease {LEASE})"
    return None


def inv_restart_fails_closed(s, prev, label):
    if prev is None or not label.startswith("check"):
        return None
    if g(prev, "active") <= g(prev, "restart_floor"):
        return (f"check passed at generation {g(prev, 'active')} after a manager restart "
                f"(only generations > {g(prev, 'restart_floor')} may be used)")
    return None


def inv_active_issued(s, prev, label):
    if g(s, "active") > g(s, "issued"):
        return f"active generation {g(s, 'active')} > issued {g(s, 'issued')}"
    return None


INVARIANTS = (
    ("KernelWithinActiveGeneration", inv_kernel_within_active),
    ("NoUseAfterRevocationAck", inv_no_use_after_ack),
    ("AckAfterRemoval", inv_ack_after_removal),
    ("ManagerFailureFailsClosed", inv_failure_fails_closed),
    ("RestartFailsClosed", inv_restart_fails_closed),
    ("ActiveNeverAheadOfDesired", inv_active_issued),
)


def check(cfg, bug=None, max_states=None):
    s0 = initial()
    parent = {s0: (None, None)}
    q = deque([s0])
    found = {}
    transitions = 0
    depth = {s0: 0}
    capped = False
    while q:
        s = q.popleft()
        for label, t in successors(s, cfg, bug):
            transitions += 1
            for name, inv in INVARIANTS:
                if name in found:
                    continue
                msg = inv(t, s, label)
                if msg:
                    found[name] = (msg, trace(parent, s) + [label])
            if t not in parent:
                parent[t] = (s, label)
                depth[t] = depth[s] + 1
                q.append(t)
        if max_states and len(parent) >= max_states and found:
            capped = True
            break
    return {"states": len(parent), "transitions": transitions,
            "depth": max(depth.values()), "found": found, "capped": capped}


def trace(parent, s):
    out = []
    while parent[s][0] is not None:
        p, label = parent[s]
        out.append(label)
        s = p
    return list(reversed(out))


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--crashes", type=int, default=1)
    ap.add_argument("--aborts", type=int, default=1)
    ap.add_argument("--broker-downs", type=int, default=1)
    ap.add_argument("--bug", choices=BUGS, action="append")
    ap.add_argument("--no-bugs", action="store_true")
    args = ap.parse_args(argv)
    cfg = {"crashes": args.crashes, "aborts": args.aborts, "broker_downs": args.broker_downs}
    bounds = (f"crashes={cfg['crashes']} aborts={cfg['aborts']} broker_downs={cfg['broker_downs']} "
              f"objects={len(OBJS)} generations={len(SCRIPT)} lease={LEASE}")
    ok = True
    if not args.bug:
        r = check(cfg)
        print(f"[correct] {bounds}: {r['states']} states, {r['transitions']} transitions, "
              f"depth {r['depth']} (exhaustive)")
        for name, _ in INVARIANTS:
            if name in r["found"]:
                ok = False
                msg, tr = r["found"][name]
                print(f"    {name}: VIOLATED: {msg}\n      trace: {' ; '.join(tr)}")
            else:
                print(f"    {name}: holds")
    if not args.no_bugs:
        for bug in args.bug or BUGS:
            r = check(cfg, bug, max_states=300_000)
            how = "stopped at cap" if r["capped"] else "exhaustive"
            print(f"[bug: {bug}] {bounds}: {r['states']} states, depth {r['depth']} ({how})")
            if not r["found"]:
                ok = False
                print("    BUG NOT DETECTED")
            for name, (msg, tr) in r["found"].items():
                print(f"    {name} violated in {len(tr)} steps: {msg}\n      trace: {' ; '.join(tr)}")
    print("RESULT: " + ("as expected (correct protocol safe, every bug variant caught)"
                        if ok else "UNEXPECTED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
