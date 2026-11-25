# ADR-0015: Attenuation does not narrow existing descendants

- Status: Accepted (spec §16). Not implemented.
- Spec: §5 ATTENUATE, §6.1 T2 note

## Decision
ATTENUATE narrows only the target node. Budget it gives up moves to D.
Children derived earlier keep their scope from the time of derivation. To
change a whole subtree, revoke it and reissue. A cascading-attenuation
primitive may come later.

## Consequences
- Derivation semantics are immutable and simple. Operators must be told,
  in the CLI lineage view, that attenuating a parent does not narrow its
  children.
