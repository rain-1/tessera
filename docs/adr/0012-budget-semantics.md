# ADR-0012: Budget = authorization to attempt; no refunds; duplicate request ids never dispatch

- Status: Accepted (spec §16). The protocol is model-checked. Not implemented.
- Spec: §4.2, §5.2, R4, T1, T10

## Decision
- Budgets are `Finite(u64) | Unlimited`. In the MVP every operation costs
  1. One unit buys one *attempt* at one exact canonical operation.
- CONSUME deducts the unit and creates a reservation bound to
  (principal, epoch, request id, canonical operation digest). This is one
  journal record. Dispatch happens after the fsync and at most once.
- A failed or uncertain outcome never refunds. There is no automatic retry.
- Resubmitting the same request id **with the same canonical content**
  returns the status of the existing reservation. Resubmitting the same
  request id **with different content** is denied with
  `RequestIdConflict`. Neither case creates an effect. (The spec does not
  cover the different-content case. This ADR decides it.)

## Consequences
- The model variant `refund-on-failure` shows that a refund lets an agent
  make 2 attempts on a budget of 1. The variant `no-dedup` shows that the
  same request id reserves twice. The model also shows that this second bug
  only appears when the budget is at least 2, so dedup tests must use
  budget ≥ 2.
