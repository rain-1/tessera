# ADR-0016: Finite authority only through brokered adapters; BPF LSM direct grants deferred

- Status: Accepted (spec §16). BPF LSM is Deferred to P6. Refined by
  ADR-0023 (WP7 evaluation: still no direct grants in the MVP; toolchain
  libbpf-rs proposed for P6).
- Spec: §3, §10.2, §10.3, §16 "Finite enforcement" and "Direct enforcement".
  Resolves the open question "choice of BPF toolchain" by deferring it.

## Decision
In the MVP, every finite protected operation goes through a broker adapter.
The kernel enforces only static, deny-by-default baseline confinement
(ADR-0005). No dynamic direct grant exists. Choosing between Aya and
libbpf-rs is deferred to WP7. That choice requires a hook matrix, a pinned
kernel with BPF LSM enabled, and a modelled generation and update protocol
(§10.3).

## Consequences
- No finite counters live in BPF. No split-brain is possible between BPF and
  the ledger.
- The broker-only profile is the supported secure profile. It must not
  depend on BPF LSM being present.
