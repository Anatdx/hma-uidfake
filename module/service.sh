#!/system/bin/sh
# Load the module if post-fs-data did not, then start sync-tool: it watches HMA's config,
# evaluates it and pushes the resulting policy over netlink, forever.
MODDIR=${0%/*}
LOG="$MODDIR/state/sync.log"
mkdir -p "$MODDIR/state"
. "$MODDIR/load.sh"
uidfake_load "$MODDIR" >>"$LOG" 2>&1

[ -x "$MODDIR/sync-tool" ] && "$MODDIR/sync-tool" >>"$LOG" 2>&1 &
