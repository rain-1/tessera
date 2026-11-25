#!/usr/bin/env bash
# Regenerate the CycloneDX SBOMs in docs/sbom/ (one per workspace crate).
#
# Requires: cargo install cargo-cyclonedx --locked
# Uses the last commit time as SOURCE_DATE_EPOCH so the timestamp is stable.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
command -v cargo-cyclonedx >/dev/null || {
    echo "cargo-cyclonedx not found: cargo install cargo-cyclonedx --locked" >&2
    exit 2
}
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
out="$root/docs/sbom"
mkdir -p "$out"
rm -f "$out"/*.cdx.json
cargo cyclonedx --format json --spec-version 1.5 --all-features \
    --target x86_64-unknown-linux-gnu --override-filename sbom.cdx -q
for m in crates/*/Cargo.toml adapters/*/Cargo.toml; do
    d="$(dirname "$m")"
    name="$(sed -n 's/^name *= *"\(.*\)"/\1/p' "$m" | head -1)"
    # Strip the absolute checkout path from bom-refs (machine-independent,
    # and no local user names in committed files).
    sed "s#path+file://$root/#path+file://./#g" "$d/sbom.cdx.json" > "$out/$name.cdx.json"
    rm "$d/sbom.cdx.json"
done
echo "SBOMs written to $out (SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"
