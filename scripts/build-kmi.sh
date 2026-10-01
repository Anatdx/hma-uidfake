#!/usr/bin/env bash
# Shared by CMake and CI; all Kbuild output stays in this KMI's staging directory.
# Usage: build-kmi.sh KMI DDK_CLANG STAGE OUTPUT_KO [DEBUG=0]
set -euo pipefail
if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
  echo "usage: $0 KMI DDK_CLANG STAGE OUTPUT_KO [DEBUG=0]" >&2
  exit 2
fi
repo=$(cd "$(dirname "$0")/.." && pwd)
kmi=$1
compiler=$2
stage=$3
output=$4
debug=${5:-0}
ddk=${DDK_ROOT:-/opt/ddk}
kdir="$ddk/kdir/$kmi"
clang_bin="$ddk/clang/$compiler/bin"
test -f "$kdir/Makefile" || { echo "missing kernel tree: $kdir" >&2; exit 1; }
test -x "$clang_bin/clang" || { echo "missing DDK compiler: $clang_bin/clang" >&2; exit 1; }
test -x "$clang_bin/llvm-strip" || { echo "missing DDK strip: $clang_bin/llvm-strip" >&2; exit 1; }
mkdir -p "$stage" "$(dirname "$output")"
stage=$(cd "$stage" && pwd)
for item in "$repo"/src/*; do
  ln -sfn "$item" "$stage/$(basename "$item")"
done
args=(-C "$kdir" ARCH=arm64 LLVM=1 CROSS_COMPILE=aarch64-linux-gnu- "M=$stage")
# New Kbuild can inherit KBUILD_EXTMOD_OUTPUT; explicitly keep 6.18 output local.
if [ "$kmi" = android17-6.18 ]; then
  args+=("MO=$stage")
fi
if [ "$debug" = 1 ]; then
  args+=(KCFLAGS=-DUF_DEBUG_ALWAYS=1)
fi
if [ -n "${UG_KBUILD_JOBS:-}" ]; then
  args+=("-j$UG_KBUILD_JOBS")
fi
PATH="$clang_bin:$PATH" "${UG_KBUILD_MAKE:-make}" "${args[@]}" modules
"$clang_bin/llvm-strip" -d "$stage/hma_uidfake.ko"
cp "$stage/hma_uidfake.ko" "$output"
