# ADR-0013: Delegation: single owner, split and transfer, bounded depth

- Status: Accepted (spec §16). Not implemented.
- Spec: §4.3, §5, §5.1, R5, T2, T4

## Decision
Each capability has one owner. Each non-root capability has one immutable
parent. The public transactions are DELEGATE, SPLIT, TRANSFER, ATTENUATE
and DROP. DELEGATE is a single atomic transaction: it creates a child owned
by the recipient and uses one depth generation. Every derivation that
narrows authority checks: child scope ⊆ parent scope; child expiry ≤ parent
expiry; finite child depth < parent depth. A finite parent cannot produce an
unlimited child budget. A non-delegatable capability (depth 0) cannot be
split, delegated or transferred. Shared balances across owners are deferred.

Note: §5 says "seven authority primitives", but §5.1 and §9.2 add DELEGATE
as a public command. DELEGATE is the eighth public transaction. It is built
from the internal SPLIT logic and the ownership-update logic.

## Consequences
- The non-delegation claim covers *direct transfer only*. It does not
  prevent an agent acting as a deputy for another (threat model residual
  risk R-1).
