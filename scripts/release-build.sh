#!/usr/bin/env bash
# Reproducible release build of the Tessera binaries (docs/release.md).
#
#   scripts/release-build.sh [OUT_DIR]
#
# Pins: the toolchain (TESSERA_TOOLCHAIN, default below), the dependency
# graph (--locked against the committed Cargo.lock), the timestamp
# (SOURCE_DATE_EPOCH = last commit time) and every build path (remapped, so
# the checkout location and $CARGO_HOME do not leak into the binaries).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
toolchain="${TESSERA_TOOLCHAIN:-1.100.0}"
target="${TESSERA_TARGET:-x86_64-unknown-linux-gnu}"
out="${1:-$root/dist}"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
export PATH="$cargo_home/bin:$PATH"

rustup toolchain list | grep -q "^$toolchain" ||
    rustup toolchain install --profile minimal "$toolchain"

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
export TZ=UTC LC_ALL=C
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target/release-repro}"
export RUSTFLAGS="--remap-path-prefix=$root=/build/tessera --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$rustup_home=/rustup"
# C code built by build scripts (ring): same remapping for debug info/__FILE__.
export CFLAGS="-ffile-prefix-map=$root=/build/tessera -ffile-prefix-map=$cargo_home=/cargo"

cargo "+$toolchain" build --release --locked --target "$target" \
    -p tessera-broker -p tessera-cli -p tessera-launcher --bins

mkdir -p "$out"
bins=(tesserad tessera-admin tessera tessera-sandbox-init tessera-launch-run tessera-launch-probe)
for b in "${bins[@]}"; do
    install -m 0755 "$CARGO_TARGET_DIR/$target/release/$b" "$out/$b"
done
(cd "$out" && sha256sum "${bins[@]}" > SHA256SUMS)
echo "toolchain $toolchain, target $target, SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
cat "$out/SHA256SUMS"
