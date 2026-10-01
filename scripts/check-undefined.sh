#!/usr/bin/env bash
# Fail if the module needs a symbol the kernel does not export.
#
# The authority is the DDK's per-KMI Module.symvers -- the same table kbuild itself uses.
# One lookup per symbol, no source-tree scans (the first version grepped ten kernel trees per
# symbol, which was slow and wrong about macros like EXPORT_SYMBOL_NS).
#
# This class of mistake is real: __builtin___clear_cache() lowered to __clear_cache(), which
# is not exported, and the module then refused to load on the device with
#   "Unknown symbol __clear_cache (-2)"
#
#   scripts/check-undefined.sh [module.ko ...]
set -euo pipefail
cd "$(dirname "$0")/.."
nm_tool=${NM:-llvm-nm}
ddk=${DDK_ROOT:-/opt/ddk}
command -v "$nm_tool" >/dev/null || { echo "missing symbol reader: $nm_tool" >&2; exit 1; }
KOS=("$@")
[ ${#KOS[@]} -eq 0 ] && KOS=(build/ko/*.ko)

fail=0
for ko in "${KOS[@]}"; do
  kmi=$(basename "$ko" _arm64_hma_uidfake.ko)
  symvers="$ddk/kdir/$kmi/Module.symvers"
  if [ ! -f "$symvers" ]; then
    echo "FAIL $kmi: no $symvers"
    fail=1
    continue
  fi
  syms=$("$nm_tool" -u "$ko" | awk '{print $NF}' | sort -u)
  bad=0
  for s in $syms; do
    if ! awk -v n="$s" '$2 == n { found = 1; exit } END { exit !found }' "$symvers"; then
      echo "FAIL $kmi: $s is not exported by this kernel"
      bad=1
      fail=1
    fi
  done
  [ "$bad" = 0 ] && echo "ok   $kmi: $(echo "$syms" | wc -w) undefined symbol(s), all exported"
done
exit $fail
