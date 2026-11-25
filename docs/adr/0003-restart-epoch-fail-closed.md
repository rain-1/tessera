# ADR-0003: Restart bumps the authority epoch and fails closed

- Status: Accepted (design). Protocol is model-checked. Not implemented.
- Spec: §11, §16 "Restart", R9, T6, T10

## Context
Restoring live grants after a crash would need a recovery proof and a
trusted-clock policy. Neither exists. Replaying a reservation whose outcome
is uncertain could cause a second external effect.

## Decision
On every broker start after the first:

1. Replay the journal (ADR-0002). Refuse to start if it is corrupt.
2. Kill every sandbox tree from the previous epoch. The launcher kills the
   whole cgroup with `cgroup.kill` and confirms it is empty. Every agent
   channel from that epoch is gone.
3. Append and fsync an `EpochBump{old, new}` record. Then, in the same
   record, invalidate every live capability: its remaining finite balance
   moves to D. After this, no capability from an earlier epoch is live
   (T6).
4. Mark every reservation that has no committed outcome as `unknown`. Never
   re-dispatch it. Report it to the operator as an uncertain effect.
5. Keep spent nonces, the request-id log and all history.
6. Approval challenges carry the epoch, so evidence produced before the bump
   is rejected, even if nonce durability were broken.
7. Baseline (operator-installed) policy is re-applied from the
   administrative configuration when the launcher relaunches sandboxes. It is
   recorded as a separate `BaselineInstalled` event. No FIDO2-minted grant
   survives a restart.

If the monotonic clock source is invalid (suspend handling or
`CLOCK_BOOTTIME` anomalies), treat it like a restart: bump the epoch and
fail closed.

## Consequences
- Live work is lost on restart. This is accepted (§16).
- Model evidence: RestartInvalidatesGrants, NoReplayAfterCrash and
  NoResurrection hold with up to 2 crashes. Variants `no-epoch-bump` and
  `replay-after-crash` are caught.
- Request IDs are scoped by (principal, epoch). After a restart the principal
  is new, so old request ids cannot collide with new ones.
- Capability IDs and AgentIds include the epoch, so audit lineage stays
  unambiguous across restarts.
