#!/usr/bin/env bash
# Verify the Tessera authority-core proofs with a pinned, checksum-verified
# Verus binary release. No root required: everything lives under
# ${XDG_DATA_HOME:-~/.local/share}/tessera/verus-$VER and rustup's home.
# Two runs:
#   1. the mirror, proofs/src (ledger, quantities, scopes);
#   2. the production crate crates/capability-core itself: Verus compiles the
#      real crate with cfg(verus_keep_ghost) and verifies the leaf functions
#      annotated with cfg_attr(verus_keep_ghost, verus_spec(..)) in
#      budget.rs, scope.rs and ids.rs (specs in *_verus.rs); everything else
#      in the crate is compiled but not verified. --no-cheating rejects any
#      assume/admit/external_body in the verified code.
# Usage: proofs/run_verus.sh [extra verus args...]   (passed to both runs)
set -euo pipefail
VER=0.2026.11.02.8bf68ee
SHA=f3a0119292df8855e4435da8130bee1873b0e6a60c306accf81a08ea687bba3c
ZIP="verus-$VER-x86-linux.zip"
URL="https://github.com/verus-lang/verus/releases/download/release/$VER/$ZIP"
here="$(cd "$(dirname "$0")" && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
dest="${XDG_DATA_HOME:-$HOME/.local/share}/tessera/verus-$VER"
if [ ! -x "$dest/verus" ]; then
  [ "$(uname -sm)" = "Linux x86_64" ] || { echo "only x86_64 Linux is pinned" >&2; exit 2; }
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  curl -sSfL -o "$tmp/$ZIP" "$URL"
  echo "$SHA  $tmp/$ZIP" | sha256sum -c --quiet
  (cd "$tmp" && unzip -q "$ZIP")
  inner="$(dirname "$(find "$tmp" -maxdepth 3 -name verus -type f | head -1)")"
  mkdir -p "$(dirname "$dest")" && rm -rf "$dest" && mv "$inner" "$dest"
  rm -rf "$tmp"; trap - EXIT
fi
# Verus needs the exact rustc it was built against.
tc="$(sed -n 's/.*"toolchain": *"\([^ "]*\).*/\1/p' "$dest/version.json" | head -1)"
if [ -n "$tc" ] && ! rustup toolchain list | grep -q "^$tc"; then
  rustup toolchain install --profile minimal "$tc"
fi
echo "== mirror (proofs/src)"
"$dest/verus" "$here/src/lib.rs" --crate-type=lib "$@"

echo "== production (crates/capability-core)"
[ -n "$tc" ] || { echo "cannot read the Rust toolchain from $dest/version.json" >&2; exit 2; }
root="$(dirname "$here")"
# serde (and its proc-macro) must be compiled by the rustc Verus uses.
deps_dir="$here/target/verus-deps"
RUSTUP_TOOLCHAIN="$tc" cargo build -q --locked --manifest-path "$root/Cargo.toml" -p serde --target-dir "$deps_dir"
deps="$deps_dir/debug/deps"
serde="$(ls -t "$deps"/libserde-*.rlib | head -1)"
exec "$dest/verus" "$root/crates/capability-core/src/lib.rs" --crate-type=lib --edition=2024 \
  --crate-name tessera_capability_core -L "$deps" --extern serde="$serde" --no-cheating "$@"
