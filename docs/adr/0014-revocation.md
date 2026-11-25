# ADR-0014: Revocation: recursive and prospective, through the admin endpoint in the MVP

- Status: Accepted (spec §16). The protocol is model-checked. Not implemented.
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

In the MVP, REVOKE is accepted only on the administrative endpoint. The
`Revoke` message in the agent protocol (§9.2, "admin or designated revoker")
is rejected on agent channels until there is a designated-revoker design with
its own ADR. The spec lists Revoke in the agent protocol and also requires a
separate admin endpoint. This ADR settles that tension in favour of the admin
endpoint.

## Consequences
- Model: RevokeLinearization holds. The pipelined-writer variant violates it.
- No cancellation of in-flight effects. Data already released stays
  released.
