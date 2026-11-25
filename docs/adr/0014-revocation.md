# ADR-0014: Revocation: recursive and prospective, through the admin endpoint in the MVP

- Status: Accepted (spec §16). The protocol is model-checked. Implemented in
  `crates/capability-core` and `crates/broker` (amended by ADR-0022).
- Spec: §5, §5.2, §9.2, R6, T5

## Decision
REVOKE marks a node as revoked. Liveness checks every ancestor, so all
descendants stop authorizing new uses. Their remaining finite balances move
to D in the same journal record. REVOKE orders against CONSUME by commit
sequence:

- If the revoke committed first, the consume is denied.
- If the consume committed first, the reservation may still be dispatched.

The audit log labels such an effect "authorized before revocation at seq
N".

The operator may revoke any capability through the administrative
endpoint. **Amended (ADR-0022):** the agent `Revoke` message is also
accepted, but only for a capability the caller currently owns or a
descendant of one it currently owns (the authority core's rule). An agent
can therefore always cut off what it delegated, and nothing else. A
non-owner's attempt is reported as `UnknownCapability`. There is still no
designated-revoker role for capabilities outside the caller's own subtree.

## Consequences
- Model: RevokeLinearization holds. The pipelined-writer variant violates it.
- No cancellation of in-flight effects. Data already released stays
  released.
