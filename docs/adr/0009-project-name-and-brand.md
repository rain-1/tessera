# ADR-0009: Project name and brand: Tessera

- Status: Accepted.
- Spec: none (product identity)

## Context
The specification is titled generically. The project needs a short name for
the crates, the CLI and the documentation.

## Decision
The name is **Tessera**. A *tessera hospitalis* was a Roman token of trust:
a tile broken between two parties, each keeping one part. Matching the parts
proved the relationship. That is a good fit for a capability that is split
and handed on while its provenance is kept.

The mark (`docs/brand/tessera-mark.svg`, `-dark.svg`, lockup and PNG
renders) is a 2×2 mosaic tile, standing for the root authority. One piece is
moved out of the tile (a delegated, attenuated child). A dashed outline
remains where the piece was: the delegated authority is still accounted for,
so the conservation identity `N = U + L + D` holds.

## Consequences
- The crates and the CLI use `tessera`. The spec's `capsandbox run` example
  becomes `tessera run`.
- The mark promises conservation and accounted delegation. It must not be
  used to suggest the system is verified or certified.
