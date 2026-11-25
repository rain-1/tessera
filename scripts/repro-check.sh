#!/usr/bin/env bash
# Reproducibility check: build the release binaries from two independent
# checkouts of HEAD (different paths, different target dirs) and compare
# SHA-256 sums. Exit 0 only if every binary is bit-identical.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/tessera-repro.XXXXXX")"
trap 'rm -rf "$work"' EXIT
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}"
for i in a b; do
    mkdir -p "$work/$i/src"
    git -C "$root" archive HEAD | tar -x -C "$work/$i/src"
    CARGO_TARGET_DIR="$work/$i/target" \
        "$work/$i/src/scripts/release-build.sh" "$work/$i/dist" >/dev/null
done
if diff "$work/a/dist/SHA256SUMS" "$work/b/dist/SHA256SUMS"; then
    echo "REPRODUCIBLE: all binaries bit-identical"
    cat "$work/a/dist/SHA256SUMS"
else
    echo "NOT REPRODUCIBLE (see diff above)" >&2
    exit 1
fi
