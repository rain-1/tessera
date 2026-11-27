# Release gates that need a human or hardware

Two P7 gates (spec §13, WP4, WP8) can't be met by automation on the
development host:

1. A physical FIDO2 key must mint exactly the reviewed grant.
2. An independent human review must be done.

This page says how to complete each one and where to record the result.
Until the open checks and the human review are recorded below, Tessera is
**not release-ready**. The rest of
the evidence is in the [README](../README.md#what-has-been-verified) and
[release engineering](release.md).

## Gate H1: hardware approval (WP4)

**Status: core flow PASSED on 2026-11-27. Two manual checks are still open: a second unenrolled key, and user verification (PIN) on hardware (see below).**

Run on the development host, with the operator present and touching the key:

- **Key:** YubiKey 5 (FIDO+CCID), firmware 5.7.4, AAGUID `d7781e5d-e353-46aa-afe2-3ca49f13332a`
- **libfido2:** 1.15.0 (Debian `fido2-tools`)
- **Command:** `FIDO2_DEVICE=/dev/hidraw7 scripts/demo.sh`, with `tessera-admin` built with `--features fido2-cli`

| Check | Result |
|---|---|
| Enroll through `fido2-cred` with a physical touch | **Pass.** The audit log records `enroll … alg=Es256` |
| An agent in a real sandbox requests a one-use read; the approval screen shows exactly that request (`file:1[read]`, budget 1, depth 0); touching the key mints it | **Pass.** The audit log records `mint … evidence=54d834e5… uv=false narrowed=false` |
| The agent's first read succeeds and its second is denied | **Pass.** First read returns 17 bytes; second returns `InsufficientBudget` |
| Revoke, emergency stop and restart after a hardware-minted grant | **Pass.** Epoch went 1 → 2 → 3, and the grant is dead |
| No touch within the key's presence window (about 28 s), at enroll and at approve | **Pass.** `FIDO_ERR_OPERATION_DENIED` from the key; no enrollment and no mint (seen on four earlier runs) |
| Inside a sandbox, the key is not present | **Pass.** No `/dev/hidraw*` and no `/sys` |
| Approve with a second key that wasn't enrolled | **Open.** No second key was available |
| Re-run `approve` on a ticket that was already approved | **Pass** (2026-11-27, hardware). `tessera-admin: ticket 1 is not active`; the key isn't asked for a touch; `tessera-admin tree` shows exactly one approved root. `scripts/demo.sh` now checks this on every run |
| `require_user_verification: true` without a PIN | **Open** on hardware. It needs the operator to type the PIN in a terminal: `FIDO2_DEVICE=/dev/hidrawN REQUIRE_UV=true scripts/demo.sh` (expect `uv=true` on the mint), then rerun and give no PIN (expect no mint). Covered by the software-authenticator tests (UV required but absent → reject) |

Prerequisites:

- libfido2's `fido2-token`, `fido2-cred` and `fido2-assert` (Debian package `fido2-tools`)
- a FIDO2 key, e.g. a YubiKey 5
- read and write access to its `/dev/hidraw*` node

```sh
fido2-token -L                                 # find the device, e.g. /dev/hidraw3
FIDO2_DEVICE=/dev/hidraw3 scripts/demo.sh      # touch the key at enroll and at approve
```

The demo builds `tessera-admin` with `--features fido2-cli` and enrolls a
credential on the key. An agent in a real sandbox then asks for a one-use
read grant. The approval screen shows that request, and touching the key mints
it. The agent's first read succeeds and its second is denied.

To pass, also check by hand:

| Check | Expected |
|---|---|
| Approve, but don't touch the key before the timeout | No mint; the agent is told `ApprovalTimeout` |
| Approve with a second key that wasn't enrolled | Verification fails; no mint |
| Re-run `approve` on a ticket already approved | Refused; no second root (`tessera-admin tree` shows one) |
| With `require_user_verification: true`, approve without a PIN | Refused (UV absent) |
| Inside the sandbox, `ls /dev/hidraw*` and access to the key | Not present |

Record further results here: date, key model and firmware, libfido2
version, outcome, and the operator's name.

## Gate H2: independent security review (WP8)

**Status: NOT DONE by a human reviewer.** Model-assisted reviews ran on
2026-11-25 and 2026-11-26. Every finding is fixed with a regression test
([review](security-review-2026-11-25.md),
[model-proxy review](security-review-2026-11-26-model-proxy.md)). They don't
replace an independent review.

Suggested scope, from most to least security-critical:

1. **Broker glue**: `crates/broker/src/reactor.rs`, `convert.rs`, `spawner.rs`.
   Covers identity binding, request-ID binding, quotas, journal-first
   ordering, recovery.
2. **Approval binding**: `crates/approval`. Covers the canonical encoding,
   assertion verification and narrowing.
3. **Launcher**: `crates/launcher`. Covers the bwrap arguments, the seccomp
   filters (including the ENOSYS guard for syscalls above 470), Landlock rules
   and cgroups.
4. **Adapters and proxy**: `adapters/file`, `adapters/https`,
   `crates/model-proxy`.
5. **Proof assumptions**: `docs/proof-register.md`. The Verus proofs cover a
   mirror that the differential test checks against production.
6. **The one `unsafe` block**: `crates/sdk/src/env_fd.rs`, assumption A14.

Material for the reviewer:

- [threat model](threat-model.md)
- [protected effects](protected-effects.md)
- [ADRs](adr/README.md), including the spec inconsistencies they resolve
- [traceability](traceability.md)
- `make test lint adversarial models tlc verus`

Record the result here: reviewer, scope, date, the commit reviewed, and a
link to the findings. Releasing also requires that no critical finding is
left unresolved.
