# ADR-0001: Single-writer ledger

- Status: Accepted (design). Not implemented.
- Spec: §16 "Concurrency", §5, T9, WP3

## Context
Many sandboxes send authority commands at the same time. Every authority
transition (MINT, CONSUME, SPLIT/DELEGATE, ATTENUATE, TRANSFER, REVOKE, DROP,
and the lifecycle and epoch transitions) must be atomic and must linearize
into one serial order. T9 requires that concurrent execution refines a serial
trace and never double-spends.

## Decision
The broker has exactly one writer task. That task owns the in-memory ledger
and the journal handle. The design is a bounded MPSC queue feeding one task.
The writer handles one command at a time:

1. authenticate (the caller identity comes from the channel, ADR-0004)
2. validate the command against the current committed state
3. call the pure `capability_core::step`
4. append to the journal and fsync (ADR-0002)
5. apply the change to memory
6. only then release the reservation, grant or response

Step 4 is the linearization point. The writer does not pipeline: no command
is validated while another is staged and not yet committed. Parsing and
size-limiting of untrusted frames happen before the queue, in per-connection
tasks. Those tasks never touch ledger state.

## Consequences
- Linearization is easy to reason about and to verify. The model
  (`models/`) shows that the pipelining variant (`stale-validation`) breaks
  four invariants: double mint, negative balance, consume after revoke, and a
  duplicate request id.
- Throughput is limited by fsync latency. If this matters, group commit (one
  fsync for several staged records) is allowed only if every command in the
  group is validated against the state that includes the earlier commands in
  the group, and nothing is released before the shared fsync. That change
  needs a new ADR and a model update.
- The adapter runs outside the writer. A slow remote call does not block
  authority transitions.
