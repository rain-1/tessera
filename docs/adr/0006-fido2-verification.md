# ADR-0006: FIDO2: pure-Rust (RustCrypto) assertion verification, libfido2 for device transport only

- Status: Accepted (design). This **changes spec §8.1 and WP4**, which say
  "use libfido2 … reviewed bindings" for verification as well. Not
  implemented.
- Spec: §8, R2, T7, WP4

## Context
The spec says to use libfido2 rather than custom cryptography. libfido2 is a
C library. Its assertion-verification path (`fido_assert_verify`) would put C
parsing and cryptography inside the broker's verification decision. RustCrypto
provides reviewed, constant-time ECDSA P-256 (`p256`) and Ed25519
(`ed25519-dalek`) verification in safe Rust. That is not custom cryptography.
It is a different, memory-safe library.

## Decision
- **Transport.** The approval service (a separate process from the broker,
  ADR-0017) uses libfido2 through a small FFI module to talk to the
  authenticator (CTAP2 over hidraw) and obtain the assertion: authenticator
  data, signature and credential id. All `unsafe` code stays in that module.
- **Verification** happens in the broker (or `crates/approval`, linked into
  the broker) in pure Rust:
  1. `clientDataHash = SHA-256(domain_sep || canonical_grant_payload)`,
     computed by the broker. The challenge is never taken from the UI.
  2. Check `rpIdHash == SHA-256(rp_id)`.
  3. Check flags: UP is set. UV is set when the policy requires it.
  4. Verify the signature over `authData || clientDataHash` with the
     enrolled COSE public key. Supported algorithms: ES256 and EdDSA. Any
     other algorithm is denied.
  5. The challenge must be unexpired, match the current epoch and carry an
     unredeemed nonce. Nonce redemption and root creation happen in one
     journal record (ADR-0002).
  6. The signature counter is recorded as evidence only. It is never the
     replay defence.
- Enrolment stores the COSE key, credential id, algorithm, RP id and the
  operator. It runs only through the admin endpoint.

## Consequences
- libfido2 stays in the TCB for *availability and UI honesty* (it talks to
  the device). It is no longer in the TCB for *acceptance*: a malformed
  response from libfido2 or the device can, at worst, make verification
  fail.
- RustCrypto crates must be pinned and recorded in the proof register as
  cryptographic assumptions (T7).
- Real-YubiKey tests (WP4) remain mandatory. Software-authenticator test
  vectors (generated with an EC key) cover tamper and replay cases in CI.
