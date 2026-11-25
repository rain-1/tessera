#!/bin/sh
# Compile-check the BPF policy program. Needs only clang with the BPF target.
# Produces an object for inspection; loading it needs root and libbpf (not done here).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-"$here/tessera_direct_read.bpf.o"}
clang -target bpf -O2 -g -Wall -Werror -c "$here/tessera_direct_read.bpf.c" -o "$out"
echo "built $out (NOT loaded / NOT verifier-checked)"
