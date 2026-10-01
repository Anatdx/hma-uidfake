#!/system/bin/sh
# Install hooks before the framework starts. Policies and APK paths are sent by
# Owner's sync-tool from service.sh once their source files are available.
MODDIR=${0%/*}
LOG="$MODDIR/state/sync.log"
mkdir -p "$MODDIR/state"
. "$MODDIR/load.sh"
uidfake_load "$MODDIR" >>"$LOG" 2>&1
