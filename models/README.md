# Protocol models

Models of the broker's external protocol: commit, dispatch, revoke, crash and
restart (specification sections 5.2, 6.1 T1/T5/T7/T9/T10/T11, 10.3 and 11;
ADR-0002 and ADR-0003). They check the protocol design. They do not check the
Rust code. Matching the Rust code to the model is a separate obligation, to be
covered by journal fault-injection tests (WP3) and the proof register.

| File | What | Status |
|---|---|---|
| `dispatch_model.py` | Explicit-state BFS checker, Python 3 stdlib only | **Run; results below** |
| `Dispatch.tla` / `Dispatch.cfg` | TLA+ version of the same model (same actions, invariants, `BUG` flag) | **Written, not yet checked with TLC or parsed with SANY** (no TLA+ tools installed). Treat it as a draft until CI runs TLC. |
| `bpf_generation_model.py` | BPF LSM direct-grant generation/revocation/lease protocol (WP7, spec §10.3), Python 3 stdlib only | **Run; results in "BPF generation model" below** |

## Running

```sh
python3 -I models/dispatch_model.py                       # correct protocol (budget 1, 2) + every bug variant
python3 -I models/dispatch_model.py --no-bugs --crashes 2 # deeper crash bound
python3 -I models/dispatch_model.py --bug no-dedup        # one variant
```

Exit status 0 means the correct protocol satisfies every invariant and every
bug variant produces at least one counterexample.

## What is modelled

* **Single-writer broker.** A command is *accepted* (the caller is
  authenticated, the command is validated against committed state and staged)
  and later *committed* (hash-chained WAL append + fsync). The commit is the
  linearization point. Only one command is staged at a time.
* **Untrusted agents A and B.** Each submits up to 3 commands in any order:
  CONSUME or DELEGATE with any request id in {1,2} and any capability id in
  {R, K}. This covers forged and wrong-owner ids, duplicate request ids and
  stale ids after restart.
* **Approval evidence.** One FIDO2 mint evidence (nonce `n1`, bound to epoch
  0, recipient A, budget N). An attacker may submit it twice (replay).
* **Delegation.** A delegates 1 unit of R to B as child K (depth 1 → 0).
* **Revocation.** The operator revokes R or K once, at any point. This races
  with consume.
* **Adapter.** A committed reservation is queued. The adapter dispatches it
  once (the external effect is counted in ghost state), then reports `ok` or
  `failed`. The writer commits that outcome.
* **Crash and restart.** A crash can happen at any step. It loses staged
  commands, the adapter queue, in-flight bookkeeping and the in-memory nonce
  cache. Recovery replays the WAL, bumps the epoch and invalidates every live
  grant (its balance moves to D). Reservations still `reserved` become
  `unknown` and are never re-dispatched. Sandboxes are killed, so messages
  still in transit die with their channels.

Not modelled: expiry and clock (T6), principal termination, ATTENUATE,
TRANSFER, SPLIT as a separate primitive, multi-level delegation, approval UI
behaviour, torn or partial WAL writes (the WAL is treated as atomic per
record after fsync; torn-tail handling is a journal unit-test obligation), and
storage that lies about fsync (outside the threat model, see ADR-0002).

## Invariants

| Invariant | Meaning | Spec |
|---|---|---|
| NoOverspend | `N = U + L + D`. No negative balance. U never decreases (no refund). External attempts ≤ N | T1, R4 |
| AtMostOneDispatchPerReservation | Each reservation causes at most one external effect | 5.2 |
| RevokeLinearization | No reservation commits after a revoke of its capability or an ancestor that linearized earlier. A reservation committed before the revoke may still dispatch | T5, 5.2 |
| NoReplayAfterCrash | An effect is dispatched only in the epoch its reservation was committed | T10 |
| DispatchAfterDurableCommit | No effect is dispatched before its reservation is durable | §11, T11 |
| NoResurrection | A nonce mints at most once. Redeemed nonces and used request ids stay in the durable log across crashes | R9, T7 |
| RestartInvalidatesGrants | After restart the epoch has advanced and no grant from an earlier epoch is live | ADR-0003, §11 |
| RequestIdDedup | A repeated (agent, epoch, request id) never creates a second reservation | 5.2 |

## Bug variants

| Flag | Rule it breaks |
|---|---|
| `refund-on-failure` | A failed dispatch gives the unit back (R4) |
| `replay-after-crash` | Recovery re-queues unresolved reservations (5.2, T10) |
| `dispatch-before-commit` | The adapter fires when the command is accepted, before the WAL fsync (§11) |
| `no-dedup` | Request ids are not checked for duplicates (5.2) |
| `no-epoch-bump` | Restart keeps live grants and the epoch (§11, ADR-0003) |
| `stale-validation` | A pipelined writer validates while another command is staged, then applies without re-checking (T9) |
| `volatile-nonces` | Redeemed nonces are kept only in memory (T7, R9) |

## Results (recorded 2026-11-25, Python 3.13.5)

Bounds: 2 agents, 2 request ids, 3 commands per agent, 2 mint submissions, 1
revoke, 2 capability ids. Bug variants use BFS, so each trace shown is a
shortest counterexample for that invariant. A bug-variant search stops at a
200,000-state cap only after a violation has already been found.

```text
$ python3 -I models/dispatch_model.py
[correct] budget=1 crashes=1 msgs/agent=3 mint_replays=2 agents=2 rids=2: 7936 states, 40514 transitions, depth 17 (exhaustive)
    NoOverspend: holds
    AtMostOneDispatchPerReservation: holds
    RevokeLinearization: holds
    NoReplayAfterCrash: holds
    DispatchAfterDurableCommit: holds
    NoResurrection: holds
    RestartInvalidatesGrants: holds
    RequestIdDedup: holds
[correct] budget=2 crashes=1 msgs/agent=3 mint_replays=2 agents=2 rids=2: 90928 states, 433798 transitions, depth 20 (exhaustive)
    NoOverspend: holds
    AtMostOneDispatchPerReservation: holds
    RevokeLinearization: holds
    NoReplayAfterCrash: holds
    DispatchAfterDurableCommit: holds
    NoResurrection: holds
    RestartInvalidatesGrants: holds
    RequestIdDedup: holds
[bug: refund-on-failure] budget=1 crashes=1 msgs/agent=3 mint_replays=2 agents=2 rids=2: 18352 states, depth 23 (exhaustive)
    NoOverspend violated in 6 steps: U decreased for R: U=0 < previously 1 (refund)
      trace: accept mint n1 0 ; commit mint n1 ; accept consume A 1 R ; commit consume A 0 1 R 0 ; dispatch 0 ; outcome 0 failed
[bug: replay-after-crash] budget=1 crashes=1 msgs/agent=3 mint_replays=2 agents=2 rids=2: 10528 states, depth 18 (exhaustive)
    NoReplayAfterCrash violated in 7 steps: reservation 0 from epoch 0 dispatched in epoch 1
      trace: accept mint n1 0 ; commit mint n1 ; accept consume A 1 R ; commit consume A 0 1 R 0 ; crash ; recover ; dispatch 0
    NoOverspend violated in 8 steps: 2 external attempts > budget N=1
      trace: accept mint n1 0 ; commit mint n1 ; accept consume A 1 R ; commit consume A 0 1 R 0 ; dispatch 0 ; crash ; recover ; dispatch 0
    AtMostOneDispatchPerReservation violated in 8 steps: reservation 0 dispatched 2 times
      trace: accept mint n1 0 ; commit mint n1 ; accept consume A 1 R ; commit consume A 0 1 R 0 ; dispatch 0 ; crash ; recover ; dispatch 0
[bug: dispatch-before-commit] budget=1 crashes=1 msgs/agent=3 mint_replays=2 agents=2 rids=2: 6568 states, depth 16 (exhaustive)
    DispatchAfterDurableCommit violated in 3 steps: effect for 0 dispatched before its reservation was durable
      trace: accept mint n1 0 ; commit mint n1 ; accept consume A 1 R
[bug: no-dedup] budget=1 crashes=1 msgs/agent=3 mint_replays=2 agents=2 rids=2: 7936 states, depth 17 (exhaustive)
    no counterexample at this bound
[bug: no-dedup] budget=2 crashes=1 msgs/agent=3 mint_replays=2 agents=2 rids=2: 172624 states, depth 20 (exhaustive)
    RequestIdDedup violated in 6 steps: request id(s) [('A', 0, 1)] produced more than one reservation
      trace: accept mint n1 0 ; commit mint n1 ; accept consume A 1 R ; commit consume A 0 1 R 0 ; accept consume A 1 R ; commit consume A 0 1 R 1
[bug: no-epoch-bump] budget=1 crashes=1 msgs/agent=3 mint_replays=2 agents=2 rids=2: 12776 states, depth 17 (exhaustive)
    RestartInvalidatesGrants violated in 4 steps: restart did not advance the authority epoch; pre-crash grants still live
      trace: accept mint n1 0 ; commit mint n1 ; crash ; recover
[bug: stale-validation] budget=1 crashes=1 msgs/agent=3 mint_replays=2 agents=2 rids=2: 200000 states, depth 14 (stopped at 200000-state cap)
    NoResurrection violated in 4 steps: nonce n1 minted 2 roots
      trace: accept mint n1 0 ; accept mint n1 0 ; commit mint n1 ; commit mint n1
    NoOverspend violated in 6 steps: negative balance/counter in root R: bals=[-1] U=1 D=1
      trace: accept mint n1 0 ; commit mint n1 ; accept revoke R ; accept consume A 1 R ; commit revoke R ; commit consume A 0 1 R 0
    RevokeLinearization violated in 6 steps: reservation 0 on R committed at seq 3 after revoke of R at seq 2
      trace: accept mint n1 0 ; commit mint n1 ; accept revoke R ; accept consume A 1 R ; commit revoke R ; commit consume A 0 1 R 0
    RequestIdDedup violated in 6 steps: request id(s) [('A', 0, 1)] produced more than one reservation
      trace: accept mint n1 0 ; commit mint n1 ; accept consume A 1 R ; accept consume A 1 R ; commit consume A 0 1 R 0 ; commit consume A 0 1 R 1
[bug: volatile-nonces] budget=1 crashes=1 msgs/agent=3 mint_replays=2 agents=2 rids=2: 7936 states, depth 17 (exhaustive)
    NoResurrection violated in 2 steps: redeemed nonces {'n1'} not all durable set()
      trace: accept mint n1 0 ; commit mint n1
RESULT: as expected (correct protocol safe, every bug variant caught)

$ python3 -I models/dispatch_model.py --no-bugs --crashes 2   (invariant lines omitted: all hold)
[correct] budget=1 crashes=2 msgs/agent=3 mint_replays=2 agents=2 rids=2: 12952 states, 63928 transitions, depth 19 (exhaustive)
[correct] budget=2 crashes=2 msgs/agent=3 mint_replays=2 agents=2 rids=2: 148568 states, 673608 transitions, depth 22 (exhaustive)
RESULT: as expected (correct protocol safe, every bug variant caught)
```

### Summary

| Configuration | States | Transitions | Result |
|---|---|---|---|
| correct, budget 1, 1 crash | 7,936 | 40,514 | all 8 invariants hold (exhaustive) |
| correct, budget 2, 1 crash | 90,928 | 433,798 | all 8 invariants hold (exhaustive) |
| correct, budget 1, 2 crashes | 12,952 | 63,928 | all 8 invariants hold (exhaustive) |
| correct, budget 2, 2 crashes | 148,568 | 673,608 | all 8 invariants hold (exhaustive) |
| `refund-on-failure` | 18,352 | – | NoOverspend: 6-step counterexample (U goes from 1 back to 0 after a failed dispatch). There is also a 9-step trace with 2 external attempts on a budget of 1: fail, refund, consume rid 2, dispatch. This was confirmed by searching the same state space |
| `replay-after-crash` | 10,528 | – | NoReplayAfterCrash (7 steps), NoOverspend and AtMostOneDispatchPerReservation (8 steps: dispatch, crash, recover, dispatch again) |
| `dispatch-before-commit` | 6,568 | – | DispatchAfterDurableCommit (3 steps) |
| `no-dedup` | 172,624 (budget 2) | – | No violation at budget 1, because the second consume is refused for lack of budget. At budget 2: RequestIdDedup, 6 steps (the same request id reserves twice) |
| `no-epoch-bump` | 12,776 | – | RestartInvalidatesGrants (4 steps: mint, crash, recover) |
| `stale-validation` | 200,000 (cap) | – | NoResurrection (double mint from one nonce, 4 steps), NoOverspend (negative balance, 6 steps), RevokeLinearization (consume commits after a revoke that linearized first, 6 steps), RequestIdDedup (6 steps) |
| `volatile-nonces` | 7,936 | – | NoResurrection (2 steps: nonce redeemed but not durable) |

### Observations

* **Duplicate request ids.** At budget 1, `no-dedup` is masked: the budget
  check refuses the duplicate. Tests for request-id deduplication must use a
  budget of at least 2, or the test passes even when deduplication is broken.
  Record this in the WP3 test plan.
* **Two independent replay defences.** Under `volatile-nonces`, the replayed
  evidence never mints a second root, even after a crash. The approval
  challenge is bound to epoch 0 and recovery bumps the epoch. Nonce durability
  and epoch binding are therefore two independent defences. The invariant
  flags the durability gap directly so that nothing silently depends on the
  epoch binding alone.
* **Single writer (T9).** `stale-validation` breaks four invariants at once.
  This is the model-level argument for the single-writer decision (ADR-0001).
  Any later pipelining must re-validate at commit time.
* **Revoke versus consume.** In the correct model there are reachable states
  in which a reservation committed *before* a revoke is dispatched *after* it.
  This is allowed by 5.2. The audit log must show such effects as "authorized
  before revocation" so that they are not mistaken for a bypass.

## TLC results (TLA+ spec)

Checked with TLC v1.7.4 (`models/run_tlc.sh`, jar pinned by SHA-256) on 2026-11-25.
Bounds as in `Dispatch.cfg` (Budget=2, MaxCrashes=1, MaxMsgs=3, MaxMintReplays=2).
`CHECK_DEADLOCK FALSE` because the bounded model has terminal states by design.

| Variant | Result |
|---|---|
| none (correct protocol) | No error; 621,239 states generated, 130,352 distinct, depth 21 |
| refund-on-failure | `NoOverspend` violated |
| replay-after-crash | `NoReplayAfterCrash` violated |
| dispatch-before-commit | `DispatchAfterDurableCommit` violated |
| no-epoch-bump | `RestartInvalidatesGrants` violated |

The Python checker and TLC agree on every variant checked.

## BPF generation model

`bpf_generation_model.py` models the direct-grant update protocol in
`docs/bpf-lsm.md` §6. That protocol is implemented as a pure state machine
in `enforcement/ebpf/manager`. Direct grants are not part of the MVP
(ADR-0023), so this model is design evidence for P6.

### What is modelled

* **Broker.** It issues generations 1–4 for one sandbox:
  * {a};
  * {b} (revokes a);
  * {a} (revokes b, grants a again);
  * {a, b}.

  It may go down once, and then stops lease renewal.
* **Manager.** It jumps to the latest issued generation. Each transition
  runs reconcile, stage (one entry per step), freeze barrier, activate,
  thaw, delete (one entry per step), then verify and report. A freeze may
  time out, which aborts the transition and leaves staged entries behind.
  The manager may crash at any step, and pinned maps survive the crash. On
  restart it expires the lease, wipes all entries and thaws.
* **Kernel.** It holds the active generation, the grant entries with
  `[gen_from, gen_until)`, a frozen flag and a lease counted in ticks.
* **Workload hooks.** A hook is a CHECK step followed by a COMPLETE step,
  with at most one hook in flight. A frozen cgroup does neither step, and
  a freeze completes only when no hook is in flight.

Not modelled:
* BPF hook coverage (see the hook matrix in `docs/bpf-lsm.md` §4);
* several sandboxes;
* map capacity;
* broker recovery;
* `ALLOW_MMAP` grants, whose revocation is non-strict by definition.

### Invariants

| Invariant | Meaning |
|---|---|
| KernelWithinActiveGeneration | While hooks can run, the entries valid at the active generation are a subset of what that generation grants. No stale or partial generation is usable |
| NoUseAfterRevocationAck | No access completes after its revocation was acknowledged, unless a later generation grants the object again |
| AckAfterRemoval | When a revocation is acknowledged, no entry for that object remains |
| ManagerFailureFailsClosed | No check passes more than LEASE ticks after the manager or broker failed |
| RestartFailsClosed | After a manager restart, nothing installed before the restart is usable |
| ActiveNeverAheadOfDesired | The active generation was issued by the broker |

Bug variants:
* `ack-before-removal`;
* `no-barrier`;
* `activate-before-stage`;
* `no-reconcile`;
* `no-lease`;
* `restart-trusts-maps`.

### Results (recorded 2026-11-25, Python 3.13.5)

```text
$ python3 -I models/bpf_generation_model.py
[correct] crashes=1 aborts=1 broker_downs=1 objects=2 generations=4 lease=2: 33806 states, 107890 transitions, depth 55 (exhaustive)
    KernelWithinActiveGeneration: holds
    NoUseAfterRevocationAck: holds
    AckAfterRemoval: holds
    ManagerFailureFailsClosed: holds
    RestartFailsClosed: holds
    ActiveNeverAheadOfDesired: holds
[bug: ack-before-removal] crashes=1 aborts=1 broker_downs=1 objects=2 generations=4 lease=2: 33304 states, depth 54 (exhaustive)
    AckAfterRemoval violated in 17 steps: revocation of a at generation 2 acked while entries [('a', 1, 2)] remain
      trace: issue 1 ; begin 0->1 ; issue 2 ; plan ; stage add a@1 ; to-activate ; activate 1 ; thaw ; done ; begin 1->2 ; plan ; stage add b@2 ; stage rem a@2 ; to-freeze ; freeze ; activate 2 ; thaw
[bug: no-barrier] crashes=1 aborts=1 broker_downs=1 objects=2 generations=4 lease=2: 21082 states, depth 45 (exhaustive)
    NoUseAfterRevocationAck violated in 20 steps: access to a authorised at generation 1 completed after revocation ack at 2
      trace: issue 1 ; begin 0->1 ; issue 2 ; plan ; stage add a@1 ; to-activate ; activate 1 ; thaw ; verify+report ; begin 1->2 ; plan ; stage add b@2 ; stage rem a@2 ; to-activate ; check a passes@1 ; activate 2 ; thaw ; delete ('a', 1, 2) ; verify+report ; complete a
[bug: activate-before-stage] crashes=1 aborts=1 broker_downs=1 objects=2 generations=4 lease=2: 27366 states, depth 45 (exhaustive)
    KernelWithinActiveGeneration violated in 12 steps: objects ['a'] usable at generation 2, which grants ['b']
      trace: issue 1 ; begin 0->1 ; issue 2 ; plan ; activate 1 ; stage add a@1 ; to-thaw ; thaw ; verify+report ; begin 1->2 ; plan ; activate 2
    NoUseAfterRevocationAck violated in 20 steps: access to a authorised at generation 1 completed after revocation ack at 2
      trace: issue 1 ; begin 0->1 ; issue 2 ; plan ; activate 1 ; stage add a@1 ; to-thaw ; thaw ; verify+report ; begin 1->2 ; plan ; check a passes@1 ; activate 2 ; stage add b@2 ; stage rem a@2 ; to-thaw ; thaw ; delete ('a', 1, 2) ; verify+report ; complete a
[bug: no-reconcile] crashes=1 aborts=1 broker_downs=1 objects=2 generations=4 lease=2: 33302 states, depth 53 (exhaustive)
    KernelWithinActiveGeneration violated in 20 steps: objects ['b'] usable at generation 3, which grants ['a']
      trace: issue 1 ; begin 0->1 ; issue 2 ; plan ; stage add a@1 ; to-activate ; activate 1 ; thaw ; verify+report ; begin 1->2 ; issue 3 ; plan ; stage add b@2 ; stage rem a@2 ; to-freeze ; freeze-timeout (abort) ; begin 1->3 ; plan ; to-activate ; activate 3
[bug: no-lease] crashes=1 aborts=1 broker_downs=1 objects=2 generations=4 lease=2: 33806 states, depth 54 (exhaustive)
    ManagerFailureFailsClosed violated in 11 steps: check passed 3 ticks after manager/broker failure (lease 2)
      trace: issue 1 ; broker down ; begin 0->1 ; plan ; stage add a@1 ; to-activate ; activate 1 ; tick ; tick ; tick ; check a passes@1
[bug: restart-trusts-maps] crashes=1 aborts=1 broker_downs=1 objects=2 generations=4 lease=2: 39726 states, depth 53 (exhaustive)
    RestartFailsClosed violated in 9 steps: check passed at generation 1 after a manager restart (only generations > 1 may be used)
      trace: issue 1 ; begin 0->1 ; plan ; stage add a@1 ; to-activate ; activate 1 ; manager crash ; manager restart ; check a passes@1
RESULT: as expected (correct protocol safe, every bug variant caught)

$ python3 -I models/bpf_generation_model.py --no-bugs --crashes 2 --aborts 2   (invariant lines omitted: all hold)
[correct] crashes=2 aborts=2 broker_downs=1 objects=2 generations=4 lease=2: 103244 states, 351739 transitions, depth 65 (exhaustive)
RESULT: as expected (correct protocol safe, every bug variant caught)
```

`no-reconcile` is the subtle case. A transition 1→2 stages "add b at 2"
and then aborts at the freeze. The broker has meanwhile issued 3 = {a}, and
the next transition jumps 1→3. Without reconcile, the leftover entry
`(b, 2, ∞)` becomes valid at 3. The Rust test
`without_reconcile_leftover_becomes_usable` reproduces this: the manager's
read-back verification catches it and expires the lease (fails closed).
