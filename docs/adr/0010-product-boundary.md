# ADR-0010: Product boundary: an external platform, not a trusted harness

- Status: Accepted (spec §16).
- Spec: §0, §3.1, §16 "Product boundary", R1, R12

## Decision
Tessera runs harnesses (Claude Code, Codex, shells, swarms) as untrusted
clients inside external confinement. It is not an agent harness. A harness's
own permission settings can only add restrictions. They never grant an
escape. Compatibility mode needs no harness changes. Native mode uses the
untrusted SDK.

## Consequences
- A compromised harness does not relax confinement (WP6 escape-toggle test).
- Rich semantic permissions need adapters or SDK support (R12 is a SHOULD).
- The broker and launcher are new privileged attack surface (§12.4). This is
  a recorded residual risk.
