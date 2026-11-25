# ADR-0011: Scope language: a small, typed, exact-resource language

- Status: Accepted (spec §16). Not implemented.
- Spec: §4.1, §7, §9.3, §9.4, T2, WP1

## Decision
The MVP has exactly two scope forms:
`File { object: ObjectId, rights ⊆ {ReadSnapshot, Replace} }` and
`Https { endpoint: EndpointId, methods: MethodSet, max_body_bytes }`.
`ObjectId` and `EndpointId` are operator-registered handles, never paths or
URLs. `is_subset` is conservative. Scopes with different resource kinds or
different objects or endpoints are never subsets of each other. Rights,
method sets and byte limits are compared component-wise. There are no globs,
path prefixes or regexes.

## Consequences
- Subset soundness (`subset ∧ permits(C,o) ⇒ permits(P,o)`) is a small proof
  obligation.
- There is no wildcard authority. Each object or endpoint needs its own
  grant. A later extension needs its own ADR and its own soundness proof.
