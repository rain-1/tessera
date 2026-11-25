# ADR-0002: Persistence: append-only, hash-chained WAL with fsync

- Status: Accepted (design). Not implemented. The durability assumptions are
  not yet validated by fault injection.
- Spec: §11, R8, R9, T7, T10, WP3. Resolves the open question "persistence
  backend and durability assumptions".

## Context
§11 allows either a database with correctly configured durability or an
append-only WAL. Before releasing any grant, reservation or response, the
broker must commit the state change and the request identity. A hash chain
helps detect accidental corruption, and tampering relative to an external
checkpoint.

## Decision
`crates/journal` implements one append-only log file per installation, in a
broker-owned directory that is not mounted into any sandbox.

- Record = `len | version | epoch | seq | prev_hash | kind | canonical body | hash`.
  The hash is SHA-256 over a domain-separated encoding
  (`"tessera/journal/v1"`) of everything before it. Records hold digests,
  never secret content.
- Commit = `write_all` the record, then `fsync` the file (`fdatasync` is
  allowed only after the file size is preallocated). On first creation, also
  `fsync` the directory. The writer (ADR-0001) acknowledges nothing until
  fsync returns success.
- If fsync fails, the broker treats the journal as poisoned. It stops the
  writer, halts and fails closed (ADR-0003). It never retries an fsync after
  a failure, because the "fsyncgate" behaviour means a retried fsync can
  report success after data was lost.
- Recovery reads records in order and checks the length, hash chain and
  sequence. A torn last record (short or with a bad hash at the tail) is
  truncated and logged. A bad record in the middle is fatal: the broker
  refuses to start until the operator intervenes.
- Snapshots (later): a checkpoint record holds the hash of a full ledger
  snapshot. Replay = snapshot + suffix. Not needed for the MVP.
- The state replayed into the ledger is: spent nonces, request-id log,
  consumption ledger (U), discarded (D), lineage, reservations and their
  outcomes, the epoch counter and the sequence number.

## Consequences
- The design has no database dependency and an auditable format. Audit and
  durability use the same artifact.
- Assumptions (not verified; listed in the proof register): the filesystem
  and device honour fsync (no volatile write cache that lies), and the host
  does not roll storage back. Rollback and a hostile administrator are out of
  scope (§11, threat model). An external checkpoint of the head hash is
  recommended but not required in the MVP.
- Model evidence: `models/dispatch_model.py` invariants
  DispatchAfterDurableCommit and NoResurrection. Variants
  `dispatch-before-commit` and `volatile-nonces` are caught.
- WP3 must inject failures before and after write, before and after fsync,
  and with a torn tail.
