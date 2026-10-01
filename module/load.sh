#!/system/bin/sh
# Shared by the two boot stages. An inline module stays loaded until reboot;
# never unload or stack a replacement over an existing instance.
uidfake_load() {
  local moddir="$1"
  local ko="$moddir/ko/hma_uidfake.ko"
  local loader rc

  [ -f "$ko" ] || { echo "[load] no selected kernel module"; return 1; }
  if lsmod | grep -q '^hma_uidfake '; then
    echo "[load] already loaded; replacing the module requires a reboot"
    return 0
  fi

  # Use the installed KernelSU loader when available. The bundled loader keeps
  # Owner's Magisk/non-KernelSU path; a failed ksud load is not retried through
  # another loader. No shell-evaluated parameter file is involved.
  if [ -x /data/adb/ksud ]; then
    loader=ksud
    /data/adb/ksud insmod "$ko"
    rc=$?
  elif [ -x "$moddir/lkmloader" ]; then
    loader=lkmloader
    "$moddir/lkmloader" "$ko"
    rc=$?
  else
    echo "[load] no ksud or bundled lkmloader"
    return 1
  fi
  echo "[load] $loader rc=$rc $(date '+%m-%d %H:%M:%S')"
  if ! lsmod | grep -q '^hma_uidfake '; then
    echo "[load] module not loaded; see the loader error above"
    return 1
  fi
  return 0
}
