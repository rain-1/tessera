<p align="center"><img src="docs/brand/tessera-lockup.svg" alt="Tessera" width="420"></p>

# Tessera

A capability platform for running untrusted autonomous agents. Authority is an explicit,
countable, delegable and revocable resource, minted only by a human with a hardware key,
and enforced outside the agent harness so that a compromised agent cannot relax it.

> Status: early implementation of `docs/specification.md` (v0.1). Nothing here is
> verified or security-certified yet; see the spec's completion status.

## The mark

A *tessera hospitalis* was a Roman token of trust, broken and shared between parties.
The logo is a 2×2 mosaic tile (root authority) with one piece moved out (a delegated,
attenuated child). The dashed outline shows the piece is still accounted for, so
the conservation invariant **N = U + L + D** holds.
