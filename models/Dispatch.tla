------------------------------- MODULE Dispatch -------------------------------
(***************************************************************************)
(* Tessera commit / dispatch / revoke / crash protocol.                    *)
(*                                                                         *)
(* Twin of models/dispatch_model.py (same state, actions, invariants and   *)
(* bug flags).  Covers docs/specification.md sec. 5.2, 6.1 (T1, T5, T7,    *)
(* T9, T10, T11), 10.3 and 11, and ADR-0002/0003.                          *)
(*                                                                         *)
(* STATUS: written for TLC but NOT yet machine-checked: no TLA+ tools are  *)
(* installed in the project environment.  The Python checker is the       *)
(* evidence of record until TLC runs in CI (see models/README.md).         *)
(*                                                                         *)
(* Abstraction: a single-writer broker ACCEPTS a command (authenticate,    *)
(* validate against committed state, stage) and later COMMITS it (WAL      *)
(* append + fsync = linearization point).  A crash loses staged commands,  *)
(* the adapter queue and in-flight bookkeeping.  Recovery replays the WAL, *)
(* bumps the epoch, invalidates every live grant (balance to D), marks     *)
(* unresolved reservations UNKNOWN and never re-dispatches them.  Agent    *)
(* channels die with their sandboxes, so there is no message buffer:       *)
(* "agent submits X" and "broker accepts X" are one step.                  *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Budget,          \* N of the single root R (1 or 2)
    MaxCrashes,      \* crashes allowed in one behaviour
    MaxMsgs,         \* commands each agent may submit
    MaxMintReplays,  \* times the approval evidence may be (re)submitted
    BUG              \* "none" or one of the bug variant names below

Agents   == {"A", "B"}
Rids     == {1, 2}
CapIds   == {"R", "K"}           \* R = root minted for A; K = child delegated A -> B
ResIds   == 0 .. (2 * MaxMsgs)   \* bound on reservation ids
NoParent == "none"

Bugs == {"none", "refund-on-failure", "replay-after-crash", "dispatch-before-commit",
         "no-dedup", "no-epoch-bump", "stale-validation", "volatile-nonces"}
ASSUME BUG \in Bugs /\ Budget \in 1..3

MaxPending == IF BUG = "stale-validation" THEN 2 ELSE 1

NoCap == [status |-> "none", root |-> "R", parent |-> NoParent, owner |-> "A",
          bal |-> 0, ep |-> 0]
NoRes == [status |-> "none", cap |-> "R", agent |-> "A", ep |-> 0, rid |-> 1, seq |-> 0]

VARIABLES
    epoch, up, crashesLeft, msgsLeft, mintLeft, revokeLeft, nextId,
    pending,                       \* volatile: staged txns
    caps, U, D,                    \* durable ledger (single root R: N = Budget)
    nonces, vnonces,               \* durable / in-memory redeemed nonces
    reqlog,                        \* durable: set of [agent, ep, rid, seq]
    resv,                          \* durable: ResIds -> reservation
    revseq,                        \* durable: CapIds -> seq of revoke (0 = never)
    seq,                           \* durable commit sequence
    queue, inflight,               \* volatile adapter state
    effs,                          \* ghost: Seq of [res, ep, durable]
    mints, ghostNonces, ghostReqs, maxU, recovered   \* ghost

vars == <<epoch, up, crashesLeft, msgsLeft, mintLeft, revokeLeft, nextId, pending,
          caps, U, D, nonces, vnonces, reqlog, resv, revseq, seq, queue, inflight,
          effs, mints, ghostNonces, ghostReqs, maxU, recovered>>

Anc(c) == IF c = "K" THEN {"K", "R"} ELSE {"R"}

Live(c) == \A a \in Anc(c) : caps[a].status = "live" /\ caps[a].ep = epoch

Init ==
    /\ epoch = 0 /\ up = TRUE /\ crashesLeft = MaxCrashes
    /\ msgsLeft = [a \in Agents |-> MaxMsgs] /\ mintLeft = MaxMintReplays
    /\ revokeLeft = 1 /\ nextId = 0 /\ pending = <<>>
    /\ caps = [c \in CapIds |-> NoCap] /\ U = 0 /\ D = 0
    /\ nonces = {} /\ vnonces = {} /\ reqlog = {}
    /\ resv = [r \in ResIds |-> NoRes] /\ revseq = [c \in CapIds |-> 0] /\ seq = 0
    /\ queue = {} /\ inflight = {} /\ effs = <<>>
    /\ mints = 0 /\ ghostNonces = {} /\ ghostReqs = {} /\ maxU = 0 /\ recovered = FALSE

Durable(r) == resv[r].status # "none"

RecordEffect(r) ==
    /\ effs' = Append(effs, [res |-> r, ep |-> epoch, durable |-> Durable(r)])
    /\ inflight' = inflight \cup {r}

Seen(a, rid) == \E x \in reqlog : x.agent = a /\ x.ep = epoch /\ x.rid = rid
Dedup(a, rid) == BUG = "no-dedup" \/ ~Seen(a, rid)

Stage(t) == pending' = Append(pending, t)

(* ---------------------------- accept ---------------------------------- *)

AcceptMint ==
    /\ up /\ mintLeft > 0 /\ Len(pending) < MaxPending
    /\ mintLeft' = mintLeft - 1
    /\ IF "n1" \notin vnonces /\ epoch = 0 /\ caps["R"].status = "none"
         THEN Stage([kind |-> "mint"])
         ELSE UNCHANGED pending
    /\ UNCHANGED <<epoch, up, crashesLeft, msgsLeft, revokeLeft, nextId, caps, U, D,
                   nonces, vnonces, reqlog, resv, revseq, seq, queue, inflight, effs,
                   mints, ghostNonces, ghostReqs, maxU, recovered>>

AcceptRevoke(c) ==
    /\ up /\ revokeLeft > 0 /\ Len(pending) < MaxPending
    /\ caps[c].status = "live"
    /\ revokeLeft' = 0
    /\ Stage([kind |-> "revoke", cap |-> c])
    /\ UNCHANGED <<epoch, up, crashesLeft, msgsLeft, mintLeft, nextId, caps, U, D,
                   nonces, vnonces, reqlog, resv, revseq, seq, queue, inflight, effs,
                   mints, ghostNonces, ghostReqs, maxU, recovered>>

AcceptConsume(a, rid, c) ==
    /\ up /\ msgsLeft[a] > 0 /\ Len(pending) < MaxPending
    /\ msgsLeft' = [msgsLeft EXCEPT ![a] = @ - 1]
    /\ IF Dedup(a, rid) /\ Live(c) /\ caps[c].owner = a /\ caps[c].bal >= 1
         THEN /\ nextId' = nextId + 1
              /\ Stage([kind |-> "consume", agent |-> a, ep |-> epoch, rid |-> rid,
                        cap |-> c, res |-> nextId])
              /\ IF BUG = "dispatch-before-commit"
                   THEN RecordEffect(nextId)
                   ELSE UNCHANGED <<effs, inflight>>
         ELSE UNCHANGED <<nextId, pending, effs, inflight>>   \* deny
    /\ UNCHANGED <<epoch, up, crashesLeft, mintLeft, revokeLeft, caps, U, D, nonces,
                   vnonces, reqlog, resv, revseq, seq, queue, mints, ghostNonces,
                   ghostReqs, maxU, recovered>>

AcceptDelegate(rid) ==
    /\ up /\ msgsLeft["A"] > 0 /\ Len(pending) < MaxPending
    /\ msgsLeft' = [msgsLeft EXCEPT !["A"] = @ - 1]
    /\ IF Dedup("A", rid) /\ Live("R") /\ caps["R"].owner = "A"
          /\ caps["R"].bal >= 1 /\ caps["K"].status = "none"
         THEN Stage([kind |-> "delegate", agent |-> "A", ep |-> epoch, rid |-> rid])
         ELSE UNCHANGED pending
    /\ UNCHANGED <<epoch, up, crashesLeft, mintLeft, revokeLeft, nextId, caps, U, D,
                   nonces, vnonces, reqlog, resv, revseq, seq, queue, inflight, effs,
                   mints, ghostNonces, ghostReqs, maxU, recovered>>

(* Agent B's attempts to use R, to delegate, or forged ids are all denials *)
(* that only spend msgsLeft; AcceptConsume already generates them.        *)

(* ---------------------------- commit ---------------------------------- *)
(* Linearization point.  Without stale-validation only the head commits and *)
(* nothing else was committed since it was validated.  With                *)
(* stale-validation any staged txn commits and is applied without re-check. *)

RemoveAt(s, i) == [j \in 1 .. (Len(s) - 1) |-> IF j < i THEN s[j] ELSE s[j + 1]]

CommitTxn(t) ==
    LET s1 == seq + 1 IN
    /\ seq' = s1
    /\ CASE t.kind = "mint" ->
              /\ caps' = IF caps["R"].status = "none"
                           THEN [caps EXCEPT !["R"] = [status |-> "live", root |-> "R",
                                   parent |-> NoParent, owner |-> "A", bal |-> Budget,
                                   ep |-> epoch]]
                           ELSE caps
              /\ nonces' = IF BUG = "volatile-nonces" THEN nonces ELSE nonces \cup {"n1"}
              /\ vnonces' = vnonces \cup {"n1"}
              /\ ghostNonces' = ghostNonces \cup {"n1"}
              /\ mints' = mints + 1
              /\ UNCHANGED <<U, D, reqlog, resv, revseq, queue, ghostReqs, maxU>>
         [] t.kind = "revoke" ->
              LET hit == {c \in CapIds : t.cap \in Anc(c) /\ caps[c].status = "live"}
              IN /\ D' = D + (IF "R" \in hit THEN caps["R"].bal ELSE 0)
                           + (IF "K" \in hit THEN caps["K"].bal ELSE 0)
                 /\ caps' = [c \in CapIds |-> IF c \in hit
                                THEN [caps[c] EXCEPT !.bal = 0, !.status = "revoked"]
                                ELSE caps[c]]
                 /\ revseq' = [revseq EXCEPT ![t.cap] = s1]
                 /\ UNCHANGED <<U, nonces, vnonces, reqlog, resv, queue, mints,
                                ghostNonces, ghostReqs, maxU>>
         [] t.kind = "consume" ->
              /\ caps' = [caps EXCEPT ![t.cap].bal = @ - 1]   \* may go < 0 only if stale
              /\ U' = U + 1
              /\ maxU' = IF U + 1 > maxU THEN U + 1 ELSE maxU
              /\ resv' = [resv EXCEPT ![t.res] = [status |-> "reserved", cap |-> t.cap,
                            agent |-> t.agent, ep |-> t.ep, rid |-> t.rid, seq |-> s1]]
              /\ reqlog' = reqlog \cup {[agent |-> t.agent, ep |-> t.ep, rid |-> t.rid, seq |-> s1]}
              /\ ghostReqs' = ghostReqs \cup {<<t.agent, t.ep, t.rid>>}
              /\ queue' = IF BUG = "dispatch-before-commit" THEN queue ELSE queue \cup {t.res}
              /\ UNCHANGED <<D, nonces, vnonces, revseq, mints, ghostNonces>>
         [] t.kind = "delegate" ->
              /\ caps' = [caps EXCEPT !["R"].bal = @ - 1,
                                      !["K"] = [status |-> "live", root |-> "R",
                                                parent |-> "R", owner |-> "B", bal |-> 1,
                                                ep |-> epoch]]
              /\ reqlog' = reqlog \cup {[agent |-> t.agent, ep |-> t.ep, rid |-> t.rid, seq |-> s1]}
              /\ ghostReqs' = ghostReqs \cup {<<t.agent, t.ep, t.rid>>}
              /\ UNCHANGED <<U, D, nonces, vnonces, resv, revseq, queue, mints,
                             ghostNonces, maxU>>

Commit ==
    /\ up /\ pending # <<>>
    /\ \E i \in 1 .. Len(pending) :
         /\ (i = 1 \/ BUG = "stale-validation")
         /\ pending' = RemoveAt(pending, i)
         /\ CommitTxn(pending[i])
    /\ UNCHANGED <<epoch, up, crashesLeft, msgsLeft, mintLeft, revokeLeft, nextId,
                   inflight, effs, recovered>>

(* ---------------------------- adapter --------------------------------- *)

Dispatch(r) ==
    /\ up /\ r \in queue
    /\ queue' = queue \ {r}
    /\ RecordEffect(r)
    /\ UNCHANGED <<epoch, up, crashesLeft, msgsLeft, mintLeft, revokeLeft, nextId,
                   pending, caps, U, D, nonces, vnonces, reqlog, resv, revseq, seq,
                   mints, ghostNonces, ghostReqs, maxU, recovered>>

Outcome(r, ok) ==
    /\ up /\ r \in inflight /\ Durable(r) /\ pending = <<>>
    /\ inflight' = inflight \ {r}
    /\ seq' = seq + 1
    /\ resv' = [resv EXCEPT ![r].status = IF ok THEN "ok" ELSE "failed"]
    /\ IF ~ok /\ BUG = "refund-on-failure" /\ caps[resv[r].cap].status = "live"
         THEN /\ caps' = [caps EXCEPT ![resv[r].cap].bal = @ + 1]
              /\ U' = U - 1
         ELSE UNCHANGED <<caps, U>>
    /\ UNCHANGED <<epoch, up, crashesLeft, msgsLeft, mintLeft, revokeLeft, nextId,
                   pending, D, nonces, vnonces, reqlog, revseq, queue, effs, mints,
                   ghostNonces, ghostReqs, maxU, recovered>>

(* ---------------------------- crash / recover ------------------------- *)

Crash ==
    /\ up /\ crashesLeft > 0
    /\ up' = FALSE /\ crashesLeft' = crashesLeft - 1
    /\ pending' = <<>> /\ queue' = {} /\ inflight' = {} /\ vnonces' = {}
    /\ UNCHANGED <<epoch, msgsLeft, mintLeft, revokeLeft, nextId, caps, U, D, nonces,
                   reqlog, resv, revseq, seq, effs, mints, ghostNonces, ghostReqs, maxU,
                   recovered>>

Recover ==
    /\ ~up
    /\ up' = TRUE /\ recovered' = TRUE /\ vnonces' = nonces
    /\ IF BUG = "no-epoch-bump"
         THEN UNCHANGED <<epoch, caps, D>>
         ELSE /\ epoch' = epoch + 1
              /\ D' = D + caps["R"].bal * (IF caps["R"].status = "live" THEN 1 ELSE 0)
                        + caps["K"].bal * (IF caps["K"].status = "live" THEN 1 ELSE 0)
              /\ caps' = [c \in CapIds |-> IF caps[c].status = "live"
                            THEN [caps[c] EXCEPT !.bal = 0, !.status = "invalid"]
                            ELSE caps[c]]
    /\ IF BUG = "replay-after-crash"
         THEN /\ queue' = {r \in ResIds : resv[r].status = "reserved"}
              /\ UNCHANGED resv
         ELSE /\ queue' = {}
              /\ resv' = [r \in ResIds |-> IF resv[r].status = "reserved"
                            THEN [resv[r] EXCEPT !.status = "unknown"] ELSE resv[r]]
    /\ UNCHANGED <<crashesLeft, msgsLeft, mintLeft, revokeLeft, nextId, pending, U,
                   nonces, reqlog, revseq, seq, inflight, effs, mints, ghostNonces,
                   ghostReqs, maxU>>

Next ==
    \/ AcceptMint
    \/ \E c \in CapIds : AcceptRevoke(c)
    \/ \E a \in Agents, rid \in Rids, c \in CapIds : AcceptConsume(a, rid, c)
    \/ \E rid \in Rids : AcceptDelegate(rid)
    \/ Commit
    \/ \E r \in ResIds : Dispatch(r)
    \/ \E r \in ResIds, ok \in BOOLEAN : Outcome(r, ok)
    \/ Crash
    \/ Recover

Spec == Init /\ [][Next]_vars

(* ---------------------------- invariants ------------------------------ *)

TypeOK ==
    /\ epoch \in Nat /\ up \in BOOLEAN /\ seq \in Nat
    /\ \A c \in CapIds : caps[c].status \in {"none", "live", "revoked", "invalid"}
    /\ \A r \in ResIds : resv[r].status \in {"none", "reserved", "ok", "failed", "unknown"}

LiveBal == (IF caps["R"].status = "live" THEN caps["R"].bal ELSE 0)
         + (IF caps["K"].status = "live" THEN caps["K"].bal ELSE 0)

Minted == caps["R"].status # "none"

\* T1 / R4
NoOverspend ==
    /\ \A c \in CapIds : caps[c].bal >= 0
    /\ Minted => Budget = U + LiveBal + D
    /\ U >= maxU
    /\ Len(effs) <= (IF Minted THEN Budget ELSE 0)

\* sec. 5.2
AtMostOneDispatchPerReservation ==
    \A i, j \in 1 .. Len(effs) : i # j => effs[i].res # effs[j].res

\* T5 / sec. 5.2: revoke that linearized first denies
RevokeLinearization ==
    \A r \in ResIds : Durable(r) =>
        \A a \in Anc(resv[r].cap) : revseq[a] = 0 \/ revseq[a] > resv[r].seq

\* T10
NoReplayAfterCrash ==
    \A i \in 1 .. Len(effs) : Durable(effs[i].res) => resv[effs[i].res].ep = effs[i].ep

\* sec. 11 / T11
DispatchAfterDurableCommit ==
    \A i \in 1 .. Len(effs) : effs[i].durable

\* R9 / T7
NoResurrection ==
    /\ mints <= 1
    /\ ghostNonces \subseteq nonces
    /\ ghostReqs \subseteq {<<x.agent, x.ep, x.rid>> : x \in reqlog}

\* ADR-0003
RestartInvalidatesGrants ==
    (up /\ recovered) =>
        /\ epoch > 0
        /\ \A c \in CapIds : caps[c].status = "live" => caps[c].ep = epoch

\* sec. 5.2
RequestIdDedup ==
    \A x, y \in reqlog : (x.agent = y.agent /\ x.ep = y.ep /\ x.rid = y.rid) => x = y

Safety ==
    /\ NoOverspend /\ AtMostOneDispatchPerReservation /\ RevokeLinearization
    /\ NoReplayAfterCrash /\ DispatchAfterDurableCommit /\ NoResurrection
    /\ RestartInvalidatesGrants /\ RequestIdDedup
=============================================================================
