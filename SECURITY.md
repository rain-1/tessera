# Security policy

## Status

Tessera is **pre-release research software** (spec v0.1). It has not had
an independent security review (ADR-0021). The software authenticator is
for development only, and the hardware FIDO2 path has not been tested with
a real token. Do not use Tessera to protect anything whose compromise you
cannot accept. The README's status table lists what is implemented,
tested, model-checked or proved.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**:

* Use GitHub's "Report a vulnerability" (private security advisory) on this
  repository, or
* contact the maintainers privately through the channel listed on the
  project page.

Please do not open public issues for vulnerabilities. Include:

* the affected component (core, approval, journal, broker, launcher,
  adapters, SDK/CLI) and commit;
* a minimal reproducer, preferably one that does not need an LLM (a
  `tessera` CLI script, a fuzz input or a Rust test);
* which property breaks (e.g. budget conservation T1, attenuation T2/T4,
  revocation T5, replay T7, crash safety T10, confinement T11).

We aim to acknowledge reports within 7 days. We will agree on a disclosure
date with you, normally within 90 days.

## In scope

* Authority bypass: using, minting, widening, resurrecting or keeping
  authority contrary to the specification (§4–§7).
* Approval binding: getting a mint that the operator's assertion does not
  cover exactly.
* Broker: parser crashes or resource exhaustion from agent input,
  identity confusion between principals, at-most-once dispatch
  violations.
* Journal: acknowledged records lost or resurrected under the documented
  storage assumptions.
* Sandbox escape or access to protected effects outside the adapters
  (`docs/protected-effects.md`).

## Out of scope / accepted residual risks

See [`docs/threat-model.md` §8](docs/threat-model.md). In particular:
kernel bugs (R-3), a hostile root user (R-4), covert/timing channels
(R-6), storage that lies about fsync (R-10), and information disclosed
through authority that was legitimately granted (R-2). Reports that one of
these is *worse than documented* are welcome.

## Known open advisories

| Advisory | Status |
|---|---|
| RUSTSEC-2026-0387 (`crypto-bigint 0.5`, via `p256 0.13`) | Fixed: upgraded to `p256` 0.14 (`crypto-bigint` ≥ 0.7.6); no ignore entries remain |
