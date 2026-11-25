#!/usr/bin/env bash
# Run TLC on Dispatch.tla with a pinned, checksum-verified tla2tools.jar.
# Usage: models/run_tlc.sh [BUG]   (BUG defaults to "none")
set -euo pipefail
VER=v1.7.4
SHA=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
here="$(cd "$(dirname "$0")" && pwd)"
cache="${XDG_CACHE_HOME:-$HOME/.cache}/tessera"; mkdir -p "$cache"
jar="$cache/tla2tools-$VER.jar"
if [ ! -f "$jar" ]; then
  curl -sSfL -o "$jar.tmp" "https://github.com/tlaplus/tlaplus/releases/download/$VER/tla2tools.jar"
  echo "$SHA  $jar.tmp" | sha256sum -c --quiet && mv "$jar.tmp" "$jar"
fi
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
cp "$here/Dispatch.tla" "$work/"
sed "s/BUG = \"none\"/BUG = \"${1:-none}\"/" "$here/Dispatch.cfg" > "$work/Dispatch.cfg"
cd "$work" && java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers auto -config Dispatch.cfg Dispatch.tla
