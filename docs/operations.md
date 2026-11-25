# Operating Tessera

This is how to run `tesserad`, approve grants, revoke, stop everything and
recover. Every command below is run by `scripts/demo.sh` against a real
broker and a real sandbox, except where marked otherwise. Installation is
covered in [install.md](install.md).

All `tessera-admin` commands talk to the admin socket
(`--socket PATH`, `$TESSERA_ADMIN_SOCKET`, default `/run/tessera/admin.sock`)
and must run as the broker's uid.

## 1. Running the daemon

```sh
tesserad --config /etc/tessera/tesserad.json
# stderr: tesserad: serving operator socket /run/tessera/admin.sock
tessera-admin status
```

At startup `tesserad`:

1. opens `state_dir/journal` and verifies the whole hash chain. **Any
   corruption refuses startup** (strict tail policy; see §7);
2. replays every record through the authority core and checks the global
   invariant;
3. **starts a new authority epoch** (journaled). Every grant from earlier
   epochs is dead, and every earlier principal is gone;
4. reports reservations left unresolved by the previous run (§6);
5. re-checks registered files and endpoints and restores the enrollment;
6. probes the launcher if profiles are configured, and refuses to start if
   a mandatory sandbox control is missing;
7. serves the admin socket.

`tesserad` runs in the foreground and logs to stderr. When the broker stops
(a fatal journal error or an inconsistency) it exits non-zero with
`broker stopped: <reason>`.

## 2. Principals and sandboxes

```sh
tessera-admin create-principal agent    # profile name from the config; prints: agent e<epoch>.s<serial>
tessera-admin principals
tessera-admin terminate e3.s0           # closes its channel, stops its sandbox, kills its grants' use
```

Identity is the channel the launcher created (ADR-0022). Agents cannot
create principals: agent `spawn` is denied. If a channel closes for any
reason, the principal is terminated, and it cannot reconnect.

Inside the sandbox, the agent uses the `tessera` CLI or SDK on fd 3
([sdk.md](sdk.md)):

```sh
tessera --json request --file 1 --rights read --budget 1 --depth 0   # blocks until approved/denied
tessera --json read --cap <CAP>
```

## 3. Approval flow

1. An agent sends `request`. The broker builds the canonical grant request:
   installation, epoch, enrolled operator, recipient (the caller), scope of
   a *registered* object, budget, depth, finite expiry, fresh nonce and
   approval deadline. It then queues the request. Only one request waits
   for a touch at a time; the others queue (16 at most), and at most 30
   approvals are handled per minute.
2. The operator reviews it:

   ```sh
   tessera-admin pending
   # ticket 1 (awaiting touch) from e1.s0
   # Recipient : agent .../0   Target : file object ...1   Actions : read
   # Quantity  : 1 operation attempt   Delegation : none   Grant expiry : ...
   # Consequences : - can read the full contents of this file ...
   ```

   Only broker-normalized fields are shown. Agent text is never shown
   (`RequestGrant` has no description field yet).
3. Approve, narrow, or deny:

   ```sh
   tessera-admin approve 1 --fido2 /dev/hidraw0          # hardware (untested), touch the key
   tessera-admin approve 1 --key operator.key            # software key, DEVELOPMENT ONLY
   tessera-admin approve 1 --key operator.key --budget 1 --depth 0   # narrow first (never widen)
   tessera-admin deny 1
   ```

   `approve` fetches the challenge, decodes the request it is about to
   show, recomputes its digest locally and **refuses if the digest does not
   match the challenge**. It then asks you to type `yes` (`--yes` skips
   this, for scripts) and gets the assertion. The broker verifies the
   assertion, redeems the nonce and mints in one journal record, and the
   agent's `request` returns `cap_id`.
4. If nobody approves within 2 minutes, the request is denied. A reused
   assertion, or one over a mutated request, is rejected (T7).

Baseline grants (`tessera-admin baseline AGENT --file OBJ --budget N`) skip
the touch. They are recorded as operator baseline roots (R2), separately
from approved roots.

## 4. Inspecting authority

```sh
tessera-admin tree                 # every capability, as a delegation forest
tessera-admin inspect CAP          # one capability
tessera-admin lineage CAP          # its ancestors
tessera-admin accounts             # per-root pools: initial = consumed + live + discarded
tessera-admin reservations [--uncertain]
```

`accounts` shows the conservation invariant N = U + L + D directly.

## 5. Revocation and emergency stop

```sh
tessera-admin revoke CAP           # recursive: CAP and all descendants
tessera-admin emergency-stop
```

* **Revoke** works going forward (ADR-0014). It linearizes in the single
  writer, and no later authorization succeeds for the subtree. A
  reservation committed *before* the revoke may still dispatch (residual
  risk R-7). The audit log shows this ordering. Data that was already read
  cannot be revoked.
* **Emergency stop** does in place what a restart does. It journals a new
  epoch, which makes every grant invalid. It closes every agent channel,
  stops every sandbox, clears the approval queue and drops pending
  bindings. The daemon keeps running. Registered files, endpoints and the
  enrollment are kept. New principals must be created afterwards.

## 6. Restart semantics

A restart (crash, `kill`, `systemctl restart`, or emergency stop) is
**fail-closed** (ADR-0003):

* The epoch increases by one. All earlier grants become non-live. Their
  remaining balance is accounted as discarded, never refunded or carried
  over.
* All sandboxes die with the broker (`--die-with-parent`). There is no
  explicit cgroup sweep of an earlier run's leaves yet (ADR-0022 gap).
* A reservation that was committed but not resolved is **never
  re-dispatched**. At startup it is audited as `kind: "recovery"` with
  `effect` set to one of:
  * `abandoned-not-dispatched`: no dispatch marker, so the effect did not
    happen.
  * `unknown-dispatched-before-restart`: the dispatch marker is durable
    but the outcome is not. The external effect **may or may not** have
    happened (R-8). Check it out of band.
  `tessera-admin reservations --uncertain` lists them. `status` counts
  them in `uncertain_reservations`.
* File slots with an interrupted replacement are restored only if the
  occupant matches a journaled identity and passes the adapter's checks.
  Restoring a slot does not change the old reservation's uncertain status.
* Request-id bindings from earlier epochs are dropped. Agents in a new
  epoch are new principals.

## 7. Journal, audit and recovery

* `state_dir/journal` is the only source of truth: an append-only,
  hash-chained WAL with an fsync before any result is released.
* `state_dir/audit.jsonl` holds JSON lines, flushed but **not fsynced and
  not hash-chained**. It is evidence, not authority. A crash can lose the
  tail of the audit log but never a committed transition.
  `tessera-admin audit [--since N] [--limit N]` reads the in-memory ring.
  Contents and secrets are never recorded, only sizes and SHA-256 digests.
* **Checkpoints.** `tessera-admin checkpoint` prints `records` and `head`
  (the chain hash). Record it **outside the host** at regular intervals.
  The chain detects tampering and corruption only relative to a checkpoint
  kept somewhere else (R-4). Root on the host can rewrite the whole chain.
  There is no admin command to verify an old checkpoint yet. Compare by
  hand: `records` must not decrease. To verify a specific head, use
  `Journal::verify_checkpoint` offline on a copy of the journal.

### Recovering from a refused start

If `tesserad` exits with a journal error (`Corrupt { offset, expected_seq,
kind }`):

1. **Stop and copy** `state_dir` before changing anything.
2. If the damage is a torn final record after a power loss, the journal
   crate supports an operator override
   (`TailPolicy::TruncateUnverifiableFinalRecord`) that truncates only an
   unverifiable *final* record. `tesserad` does not expose it yet. Using
   it means opening a copy of the journal with that option offline (a small
   Rust program against `tessera-journal`), and **it can discard an
   acknowledged record** if the damage was really media corruption.
3. Any other corruption (bad header, sequence gap, hash mismatch in the
   middle) cannot be recovered in place. The authority state cannot be
   trusted. Start a fresh `state_dir`. This gives a new installation id,
   all grants are gone, and you must enroll and register everything again.
   Keep the old directory for investigation.

`tesserad` also refuses to start on a replay mismatch (a journaled command
that the core now denies) or an epoch mismatch. Both mean either a core
regression or tampering. Do not work around them.

## 8. Known residual risks (operator view)

From [threat-model.md §8](threat-model.md). These are **not** mitigated:

| Risk | What it means for operators |
|---|---|
| R-1 confused deputy | A non-delegatable grant stops *transfer*, not an agent acting on another's behalf through allowed channels |
| R-2 information flow | Do not give one principal both protected reads and network/model access unless disclosure is acceptable |
| R-3 kernel in TCB | A kernel bug defeats confinement. Keep the kernel patched; use a VM for high-risk work |
| R-4 root on the host | Root can rewrite the journal or binaries. Keep checkpoints off-host |
| R-5 presence, not consent | The key has no display. Read `pending` carefully; approval fatigue is real |
| R-7 in-flight after revoke | Effects reserved before a revoke can still happen |
| R-8 not exactly-once | `unknown` reservations need out-of-band reconciliation |
| R-10 lying storage | Run the state directory on storage that honours fsync |
| R-12 DoS | Agents can fill the approval queue; restarts kill every sandbox |

Gaps specific to this implementation:

* The **software authenticator** (`--key`) proves nothing about physical
  presence. Use it for development only.
* The `fido2-cli` hardware path has not been tested with a real token.
* The audit log is not tamper-evident (no hash chain, no fsync).
* Unknown configuration keys are silently ignored.
* There is no per-principal request rate limit beyond bounded queues.
