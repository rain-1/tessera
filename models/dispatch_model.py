#!/usr/bin/env python3
"""Explicit-state model checker for the Tessera commit/dispatch/revoke/crash protocol.

Self-contained, Python 3 standard library only.  Run with:

    python3 -I models/dispatch_model.py            # correct protocol + every bug variant
    python3 -I models/dispatch_model.py --budget 2 --crashes 1
    python3 -I models/dispatch_model.py --bug refund-on-failure

This is a *model* of the protocol in docs/specification.md sections 5.2, 6.1
(T1, T5, T7, T9, T10, T11), 10.3 and 11, and of the decisions in docs/adr/.  It is
not the Rust implementation; it abstracts it.  The TLA+ twin is models/Dispatch.tla.

Abstraction
-----------
* One trusted single-writer broker.  A command is *accepted* (authenticated,
  validated against current committed state, staged) and later *committed*
  (appended to the hash-chained WAL and fsynced).  Only commit is a
  linearization point.  A crash between the two loses the staged command.
* Untrusted agents A and B submit any command at any time (bounded by
  MSGS per agent): CONSUME / DELEGATE with any request id and any capability
  id (forged ids, wrong owner, duplicate request ids included).
* The approval service delivers one FIDO2 mint evidence (nonce n1, bound to
  epoch 0, recipient A, budget N); the attacker may replay it MINT_REPLAYS times.
* The operator may revoke R (the root) or K (the delegated child) once.
* A reservation committed by CONSUME is queued to the adapter, which performs
  the external effect (ghost-counted) and later reports ok / fail, which is
  committed as an outcome record.
* The broker may crash at any point (CRASHES times).  Recovery replays the
  durable WAL, bumps the authority epoch, invalidates every live grant
  (balance moves to D), marks unresolved reservations UNKNOWN and never
  re-dispatches them.  Sandboxes are killed on restart, so in-transit agent
  messages vanish with their channels; agents are relaunched in the new
  epoch and may keep submitting stale ids.

Bug variants (--bug NAME) deliberately break one protocol rule each:
  refund-on-failure     failed dispatch refunds the unit (violates R4)
  replay-after-crash    recovery re-queues unresolved reservations (violates 5.2/T10)
  dispatch-before-commit adapter fires at accept time, before WAL fsync (violates 11)
  no-dedup              request ids not checked for duplicates (violates 5.2)
  no-epoch-bump         restart restores live grants instead of invalidating (violates 11/ADR-0003)
  stale-validation      writer pipelines: validates against committed state while
                        another command is staged, applies without re-check (violates T9)
  volatile-nonces       redeemed approval nonces kept only in memory (violates T7/R9)
"""

import argparse
import sys
from collections import deque

AGENTS = ("A", "B")
CAPS = ("R", "K")           # R = root minted for A, K = child delegated A -> B
RIDS = (1, 2)
BUGS = (
    "refund-on-failure",
    "replay-after-crash",
    "dispatch-before-commit",
    "no-dedup",
    "no-epoch-bump",
    "stale-validation",
    "volatile-nonces",
)

# ---------------------------------------------------------------------------
# State encoding.  Everything is an immutable tuple so states hash.
#
# State = (
#   epoch, up, crashes_left, msgs_left(A,B), mint_left, revoke_left, next_id,
#   pending,            tuple of staged txns (volatile)
#   caps,               durable: tuple of (id, root, parent, owner, bal, status, epoch)
#   roots,              durable: tuple of (root_id, N, U, D)
#   nonces,             durable: frozenset of redeemed nonces
#   vnonces,            volatile: frozenset of nonces the running broker treats as redeemed
#   reqlog,             durable: tuple of (agent, epoch, rid, resid-or-None)
#   resv,               durable: tuple of (resid, cap, root, agent, epoch, rid, seq, status)
#   revseq,             durable: tuple of (cap, seq)
#   seq,                durable: commit sequence number
#   queue,              volatile: frozenset of resids waiting for the adapter
#   inflight,           volatile: frozenset of resids dispatched, outcome not yet committed
#   ghost_eff,          ghost: tuple of (resid, dispatch_epoch, durable_at_dispatch, ok_order)
#   ghost_mints,        ghost: number of roots ever created from nonce n1
#   ghost_nonces,       ghost: frozenset of nonces ever committed as redeemed
#   ghost_reqs,         ghost: frozenset of request keys ever committed
#   ghost_maxU,         ghost: max U ever observed for root R
#   ghost_recovered,    ghost: True once a recovery happened in this run
# )
# ---------------------------------------------------------------------------

F = {name: i for i, name in enumerate((
    "epoch", "up", "crashes_left", "msgs_left", "mint_left", "revoke_left", "next_id",
    "pending", "caps", "roots", "nonces", "vnonces", "reqlog", "resv", "revseq", "seq",
    "queue", "inflight", "ghost_eff", "ghost_mints", "ghost_nonces", "ghost_reqs",
    "ghost_maxU", "ghost_recovered",
))}


def upd(s, **kw):
    lst = list(s)
    for k, v in kw.items():
        lst[F[k]] = v
    return tuple(lst)


def g(s, k):
    return s[F[k]]


def caps_d(s):
    return {c[0]: list(c[1:]) for c in g(s, "caps")}


def caps_t(d):
    return tuple(sorted((k,) + tuple(v) for k, v in d.items()))


def roots_d(s):
    return {r[0]: list(r[1:]) for r in g(s, "roots")}


def roots_t(d):
    return tuple(sorted((k,) + tuple(v) for k, v in d.items()))


def resv_d(s):
    return {r[0]: list(r[1:]) for r in g(s, "resv")}


def resv_t(d):
    return tuple(sorted((k,) + tuple(v) for k, v in d.items()))


# cap fields: root, parent, owner, bal, status, epoch
C_ROOT, C_PARENT, C_OWNER, C_BAL, C_STATUS, C_EPOCH = range(6)
# reservation fields: cap, root, agent, epoch, rid, seq, status
X_CAP, X_ROOT, X_AGENT, X_EPOCH, X_RID, X_SEQ, X_STATUS = range(7)
# root fields: N, U, D
R_N, R_U, R_D = range(3)


def ancestors(caps, cid):
    out = []
    while cid is not None and cid in caps:
        out.append(cid)
        cid = caps[cid][C_PARENT]
    return out


def is_live(caps, cid, epoch):
    """Live(c): exists, this epoch, neither it nor an ancestor is revoked/invalid."""
    if cid not in caps:
        return False
    for a in ancestors(caps, cid):
        if caps[a][C_STATUS] != "live" or caps[a][C_EPOCH] != epoch:
            return False
    return True


def initial(cfg):
    return (
        0, True, cfg.crashes, (cfg.msgs, cfg.msgs), cfg.mint_replays, 1, 0,
        (), (), (), frozenset(), frozenset(), (), (), (), 0,
        frozenset(), frozenset(), (), 0, frozenset(), frozenset(), 0, False,
    )


# ---------------------------------------------------------------------------
# Validation (pure, against *committed* state) -> staged txn or None (deny).
# ---------------------------------------------------------------------------

def validate(s, cmd, cfg, bug):
    epoch = g(s, "epoch")
    caps = caps_d(s)
    kind = cmd[0]
    if kind == "mint":
        _, nonce, bound_epoch = cmd
        if nonce in g(s, "vnonces"):
            return None                       # replayed evidence
        if bound_epoch != epoch:
            return None                       # challenge bound to another epoch
        if "R" in caps:
            return None                       # fresh id required (one root in model)
        return ("mint", nonce)
    if kind == "revoke":
        _, cid = cmd
        if cid not in caps or caps[cid][C_STATUS] != "live":
            return None
        return ("revoke", cid)
    # agent commands
    agent, rid = cmd[1], cmd[2]
    key = (agent, epoch, rid)
    if bug != "no-dedup":
        if any(r[:3] == key for r in g(s, "reqlog")):
            return None                       # duplicate: return prior status, no new effect
    if kind == "consume":
        cid = cmd[3]
        if not is_live(caps, cid, epoch) or caps[cid][C_OWNER] != agent:
            return None
        if caps[cid][C_BAL] < 1:
            return None
        return ("consume", agent, epoch, rid, cid)
    if kind == "delegate":
        cid, to = cmd[3], cmd[4]
        if cid != "R" or "K" in caps:
            return None                       # model: only R may delegate, one child
        if not is_live(caps, cid, epoch) or caps[cid][C_OWNER] != agent or to == agent:
            return None
        if caps[cid][C_BAL] < 1:
            return None
        return ("delegate", agent, epoch, rid, cid, to)
    raise AssertionError(cmd)


# ---------------------------------------------------------------------------
# Commit: append to WAL + fsync, i.e. the linearization point.
# In the correct protocol the txn was validated against exactly this state
# (single writer, nothing else committed in between).  stale-validation
# applies blindly without re-check, as a pipelining writer would.
# ---------------------------------------------------------------------------

def commit(s, txn, cfg, bug):
    caps = caps_d(s)
    roots = roots_d(s)
    resv = resv_d(s)
    seq = g(s, "seq") + 1
    epoch = g(s, "epoch")
    kind = txn[0]
    queue = g(s, "queue")
    reqlog = g(s, "reqlog")
    ghost_reqs = g(s, "ghost_reqs")
    out = dict(seq=seq)
    if kind == "mint":
        nonce = txn[1]
        if "R" not in caps:
            # A second mint (only reachable under stale-validation) would create a
            # second root with a fresh id; the model only tracks that it happened.
            caps["R"] = ["R", None, "A", cfg.budget, "live", epoch]
            roots["R"] = [cfg.budget, 0, 0]
        if bug != "volatile-nonces":
            out["nonces"] = g(s, "nonces") | {nonce}
        out["vnonces"] = g(s, "vnonces") | {nonce}
        out["ghost_nonces"] = g(s, "ghost_nonces") | {nonce}
        out["ghost_mints"] = g(s, "ghost_mints") + 1
    elif kind == "revoke":
        cid = txn[1]
        # Revoke cid and (transitively) its descendants: move balances to D.
        for c, v in caps.items():
            if cid in ancestors(caps, c) and v[C_STATUS] == "live":
                roots[v[C_ROOT]][R_D] += v[C_BAL]
                v[C_BAL] = 0
                v[C_STATUS] = "revoked"
        out["revseq"] = g(s, "revseq") + ((cid, seq),)
    elif kind == "consume":
        _, agent, ep, rid, cid, resid = txn
        cap = caps[cid]
        cap[C_BAL] -= 1                      # stale-validation may drive this < 0
        roots[cap[C_ROOT]][R_U] += 1
        resv[resid] = [cid, cap[C_ROOT], agent, ep, rid, seq, "reserved"]
        reqlog = reqlog + ((agent, ep, rid, resid),)
        ghost_reqs = ghost_reqs | {(agent, ep, rid)}
        if bug != "dispatch-before-commit":
            queue = queue | {resid}
    elif kind == "delegate":
        _, agent, ep, rid, cid, to = txn
        caps[cid][C_BAL] -= 1
        caps["K"] = [caps[cid][C_ROOT], cid, to, 1, "live", epoch]
        reqlog = reqlog + ((agent, ep, rid, None),)
        ghost_reqs = ghost_reqs | {(agent, ep, rid)}
    else:
        raise AssertionError(txn)
    maxU = max(g(s, "ghost_maxU"), roots.get("R", [0, 0, 0])[R_U])
    return upd(s, caps=caps_t(caps), roots=roots_t(roots), resv=resv_t(resv),
               queue=queue, reqlog=tuple(sorted(reqlog, key=repr)), ghost_reqs=ghost_reqs,
               ghost_maxU=maxU, **out)


def record_effect(s, resid):
    durable = resid in resv_d(s)
    eff = g(s, "ghost_eff") + ((resid, g(s, "epoch"), durable),)
    return upd(s, ghost_eff=tuple(sorted(eff)), inflight=g(s, "inflight") | {resid})


# ---------------------------------------------------------------------------
# Successor relation.
# ---------------------------------------------------------------------------

def agent_commands(s):
    epoch = g(s, "epoch")
    for i, a in enumerate(AGENTS):
        if g(s, "msgs_left")[i] == 0:
            continue
        for rid in RIDS:
            for cid in CAPS:
                yield i, ("consume", a, rid, cid)
            if a == "A":
                yield i, ("delegate", a, rid, "R", "B")


def successors(s, cfg, bug):
    if not g(s, "up"):
        yield ("recover",), recover(s, cfg, bug)
        return

    pending = g(s, "pending")
    max_pending = 2 if bug == "stale-validation" else 1

    # --- accept (validate + stage) ----------------------------------------
    if len(pending) < max_pending:
        cmds = []
        if g(s, "mint_left") > 0:
            cmds.append((None, ("mint", "n1", 0)))
        if g(s, "revoke_left") > 0:
            for cid in CAPS:
                cmds.append((None, ("revoke", cid)))
        cmds.extend(agent_commands(s))
        for who, cmd in cmds:
            t = s
            if cmd[0] == "mint":
                t = upd(t, mint_left=g(t, "mint_left") - 1)
            elif cmd[0] == "revoke":
                t = upd(t, revoke_left=0)
            else:
                ml = list(g(t, "msgs_left"))
                ml[who] -= 1
                t = upd(t, msgs_left=tuple(ml))
            txn = validate(s, cmd, cfg, bug)
            if txn is None:
                # Denied: no authority change.  (Audit event not modelled.)
                # Collapse revoke denial so the operator can still revoke later.
                if cmd[0] == "revoke":
                    continue
                yield ("deny",) + cmd, t
                continue
            if txn[0] == "consume":
                resid = g(t, "next_id")
                t = upd(t, next_id=resid + 1)
                txn = txn + (resid,)
                if bug == "dispatch-before-commit":
                    t = record_effect(t, resid)
            yield ("accept",) + cmd, upd(t, pending=pending + (txn,))

    # --- commit (WAL append + fsync): linearization point -------------------
    for i, txn in enumerate(pending):
        if bug != "stale-validation" and i > 0:
            break
        rest = pending[:i] + pending[i + 1:]
        yield ("commit",) + txn, commit(upd(s, pending=rest), txn, cfg, bug)

    # --- adapter dispatch ---------------------------------------------------
    for resid in sorted(g(s, "queue")):
        t = upd(s, queue=g(s, "queue") - {resid})
        yield ("dispatch", resid), record_effect(t, resid)

    # --- adapter outcome, committed by the writer --------------------------
    if not pending:
        for resid in sorted(g(s, "inflight")):
            resv = resv_d(s)
            if resid not in resv:
                continue                     # outcome needs a durable reservation
            for ok in (True, False):
                r2 = {k: list(v) for k, v in resv.items()}
                r2[resid][X_STATUS] = "ok" if ok else "failed"
                t = upd(s, inflight=g(s, "inflight") - {resid}, resv=resv_t(r2),
                        seq=g(s, "seq") + 1)
                if not ok and bug == "refund-on-failure":
                    caps = caps_d(t)
                    roots = roots_d(t)
                    cid = r2[resid][X_CAP]
                    if caps[cid][C_STATUS] == "live":
                        caps[cid][C_BAL] += 1
                        roots[caps[cid][C_ROOT]][R_U] -= 1
                        t = upd(t, caps=caps_t(caps), roots=roots_t(roots))
                yield ("outcome", resid, "ok" if ok else "failed"), t

    # --- crash anywhere ----------------------------------------------------
    if g(s, "crashes_left") > 0:
        yield ("crash",), upd(s, up=False, crashes_left=g(s, "crashes_left") - 1,
                              pending=(), queue=frozenset(), inflight=frozenset(),
                              vnonces=frozenset())


def recover(s, cfg, bug):
    """Replay the durable WAL; fail closed (ADR-0003)."""
    caps = caps_d(s)
    roots = roots_d(s)
    resv = resv_d(s)
    queue = frozenset()
    epoch = g(s, "epoch")
    if bug != "no-epoch-bump":
        epoch += 1
        for v in caps.values():
            if v[C_STATUS] == "live":
                roots[v[C_ROOT]][R_D] += v[C_BAL]
                v[C_BAL] = 0
                v[C_STATUS] = "invalid"
    for k, v in resv.items():
        if v[X_STATUS] == "reserved":
            if bug == "replay-after-crash":
                queue = queue | {k}
            else:
                v[X_STATUS] = "unknown"      # reported, never replayed
    return upd(s, up=True, epoch=epoch, caps=caps_t(caps), roots=roots_t(roots),
               resv=resv_t(resv), queue=queue, vnonces=g(s, "nonces"),
               ghost_recovered=True)


# ---------------------------------------------------------------------------
# Invariants.  Each returns None or a message.
# ---------------------------------------------------------------------------

def inv_no_overspend(s, cfg):
    """T1/R4: N = U + L + D for every root, all non-negative, and the number of
    external attempts never exceeds N; U never decreases (no refunds)."""
    caps = caps_d(s)
    for rid, (n, u, d) in roots_d(s).items():
        live = sum(v[C_BAL] for v in caps.values() if v[C_ROOT] == rid and v[C_STATUS] == "live")
        bals = [v[C_BAL] for v in caps.values() if v[C_ROOT] == rid]
        if any(b < 0 for b in bals) or u < 0 or d < 0:
            return f"negative balance/counter in root {rid}: bals={bals} U={u} D={d}"
        if n != u + live + d:
            return f"conservation broken for {rid}: N={n} U={u} L={live} D={d}"
        if rid == "R" and u < g(s, "ghost_maxU"):
            return f"U decreased for {rid}: U={u} < previously {g(s, 'ghost_maxU')} (refund)"
    attempts = len(g(s, "ghost_eff"))
    if g(s, "roots"):
        n = roots_d(s)["R"][R_N]
        if attempts > n:
            return f"{attempts} external attempts > budget N={n}"
    elif attempts:
        return "attempt without any root"
    return None


def inv_one_dispatch_per_reservation(s, cfg):
    seen = {}
    for resid, _, _ in g(s, "ghost_eff"):
        seen[resid] = seen.get(resid, 0) + 1
        if seen[resid] > 1:
            return f"reservation {resid} dispatched {seen[resid]} times"
    return None


def inv_revoke_order(s, cfg):
    """T5/5.2: no reservation is committed after a revoke of the capability or an
    ancestor linearized first (dispatches of earlier reservations may finish)."""
    caps = caps_d(s)
    revseq = dict(g(s, "revseq"))
    for resid, v in resv_d(s).items():
        for a in ancestors(caps, v[X_CAP]):
            if a in revseq and revseq[a] < v[X_SEQ]:
                return (f"reservation {resid} on {v[X_CAP]} committed at seq {v[X_SEQ]} "
                        f"after revoke of {a} at seq {revseq[a]}")
    return None


def inv_no_replay_after_crash(s, cfg):
    """T10: an effect is only ever dispatched in the epoch its reservation was made."""
    resv = resv_d(s)
    for resid, ep, durable in g(s, "ghost_eff"):
        if resid in resv and resv[resid][X_EPOCH] != ep:
            return f"reservation {resid} from epoch {resv[resid][X_EPOCH]} dispatched in epoch {ep}"
    return None


def inv_dispatch_needs_durable_reservation(s, cfg):
    """Sec. 11 / T11: an effect is released only after its reservation is durable."""
    for resid, ep, durable in g(s, "ghost_eff"):
        if not durable:
            return f"effect for {resid} dispatched before its reservation was durable"
    return None


def inv_no_resurrection(s, cfg):
    """R9/T7: redeemed nonces and used request ids stay consumed across crashes;
    each nonce mints at most one root."""
    if g(s, "ghost_mints") > 1:
        return f"nonce n1 minted {g(s, 'ghost_mints')} roots"
    if not g(s, "ghost_nonces") <= g(s, "nonces"):
        return f"redeemed nonces {set(g(s, 'ghost_nonces'))} not all durable {set(g(s, 'nonces'))}"
    keys = {r[:3] for r in g(s, "reqlog")}
    if not g(s, "ghost_reqs") <= keys:
        return "a committed request id disappeared from the durable log"
    return None


def inv_restart_invalidates(s, cfg):
    """ADR-0003: after restart no grant from an earlier epoch is live, and the epoch
    advanced past every grant's epoch."""
    if not g(s, "up") or not g(s, "ghost_recovered"):
        return None
    for cid, v in caps_d(s).items():
        if v[C_STATUS] == "live" and v[C_EPOCH] < g(s, "epoch"):
            return f"grant {cid} from epoch {v[C_EPOCH]} live in epoch {g(s, 'epoch')}"
    if g(s, "epoch") == 0:
        return "restart did not advance the authority epoch; pre-crash grants still live" \
            if any(v[C_STATUS] == "live" for v in caps_d(s).values()) else None
    return None


def inv_dedup(s, cfg):
    """5.2: a repeated request id never creates a second reservation."""
    keys = [(v[X_AGENT], v[X_EPOCH], v[X_RID]) for v in resv_d(s).values()]
    keys += [(r[0], r[1], r[2]) for r in g(s, "reqlog") if r[3] is None]
    dup = {k for k in keys if keys.count(k) > 1}
    if dup:
        return f"request id(s) {sorted(dup)} produced more than one reservation"
    return None


INVARIANTS = (
    ("NoOverspend", inv_no_overspend),
    ("AtMostOneDispatchPerReservation", inv_one_dispatch_per_reservation),
    ("RevokeLinearization", inv_revoke_order),
    ("NoReplayAfterCrash", inv_no_replay_after_crash),
    ("DispatchAfterDurableCommit", inv_dispatch_needs_durable_reservation),
    ("NoResurrection", inv_no_resurrection),
    ("RestartInvalidatesGrants", inv_restart_invalidates),
    ("RequestIdDedup", inv_dedup),
)


# ---------------------------------------------------------------------------
# BFS.
# ---------------------------------------------------------------------------

def check(cfg, bug=None, max_states=None):
    init = initial(cfg)
    parent = {init: None}
    frontier = deque([init])
    violations = {}
    transitions = 0
    max_depth = 0
    depth = {init: 0}
    exhaustive = True
    while frontier:
        s = frontier.popleft()
        for name, fn in INVARIANTS:
            if name in violations:
                continue
            msg = fn(s, cfg)
            if msg:
                violations[name] = (msg, s)
        if max_states is not None and len(parent) >= max_states and violations:
            exhaustive = False
            break
        for label, t in successors(s, cfg, bug):
            transitions += 1
            if t not in parent:
                parent[t] = (s, label)
                depth[t] = depth[s] + 1
                max_depth = max(max_depth, depth[t])
                frontier.append(t)
    return dict(states=len(parent), transitions=transitions, depth=max_depth,
                violations=violations, parent=parent, exhaustive=exhaustive)


def trace(parent, s):
    steps = []
    while parent[s] is not None:
        prev, label = parent[s]
        steps.append(label)
        s = prev
    return list(reversed(steps))


def fmt_label(label):
    return " ".join(str(x) for x in label)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--budget", type=int, nargs="*", default=[1, 2])
    ap.add_argument("--crashes", type=int, default=1)
    ap.add_argument("--msgs", type=int, default=3, help="commands per agent")
    ap.add_argument("--mint-replays", type=int, default=2)
    ap.add_argument("--bug", choices=BUGS, action="append")
    ap.add_argument("--no-bugs", action="store_true", help="check only the correct protocol")
    ap.add_argument("--max-states", type=int, default=200000,
                    help="state cap for bug variants once a violation is known")
    args = ap.parse_args(argv)

    class Cfg:
        pass

    def mkcfg(budget):
        cfg = Cfg()
        cfg.budget, cfg.crashes, cfg.msgs, cfg.mint_replays = (
            budget, args.crashes, args.msgs, args.mint_replays)
        return cfg

    def bounds(cfg):
        return (f"budget={cfg.budget} crashes={cfg.crashes} msgs/agent={cfg.msgs} "
                f"mint_replays={cfg.mint_replays} agents=2 rids=2")

    def report(r):
        for inv, (msg, s) in r["violations"].items():
            tr = trace(r["parent"], s)
            print(f"    {inv} violated in {len(tr)} steps: {msg}")
            print("      trace: " + " ; ".join(fmt_label(x) for x in tr))

    ok = True
    if not args.bug:
        for budget in args.budget:
            cfg = mkcfg(budget)
            r = check(cfg, None)
            print(f"[correct] {bounds(cfg)}: {r['states']} states, "
                  f"{r['transitions']} transitions, depth {r['depth']} (exhaustive)")
            for inv, _ in INVARIANTS:
                print(f"    {inv}: {'VIOLATED' if inv in r['violations'] else 'holds'}")
            if r["violations"]:
                ok = False
                report(r)
            sys.stdout.flush()
    if not args.no_bugs:
        for bug in args.bug or BUGS:
            caught = False
            for budget in args.budget:
                cfg = mkcfg(budget)
                r = check(cfg, bug, max_states=args.max_states)
                how = "exhaustive" if r["exhaustive"] else f"stopped at {args.max_states}-state cap"
                print(f"[bug: {bug}] {bounds(cfg)}: {r['states']} states, depth {r['depth']} ({how})")
                if r["violations"]:
                    caught = True
                    report(r)
                    break
                print("    no counterexample at this bound")
                sys.stdout.flush()
            if not caught:
                ok = False
                print("    BUG NOT DETECTED at any bound")
            sys.stdout.flush()
    print("RESULT:", "as expected (correct protocol safe, every bug variant caught)"
          if ok else "UNEXPECTED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
