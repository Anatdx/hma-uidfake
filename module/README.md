# HMA UID Fake

Makes a hidden uid look like it does not exist:

```
getpriority(PRIO_USER, uid)       -> -ESRCH
ioprio_get(IOPRIO_WHO_USER, uid)  -> -ESRCH
setpriority / ioprio_set         -> -ESRCH when the request reaches USER lookup
```

The rules come from the app a process was born from, so an isolated child or anything that called
`setuid()` cannot choose which of them apply. The repository README has the rest.

`customize.sh` picks the `ko/` entry matching `uname -r`, renames it to `ko/hma_uidfake.ko` and
removes the rest. With nothing for your kernel it leaves the closest build as
`ko/hma_uidfake.ko.try` and explains the unsupported KMI. Kernel release/vermagic
text need not match exactly: the loader handles supported differences, but it
cannot make another KMI's structure layouts compatible.

`post-fs-data.sh` loads early and `service.sh` retries before starting the existing
rule-sync process. Loading prefers `/data/adb/ksud insmod` when available and uses
the bundled `lkmloader` otherwise; results go to `state/sync.log`.

Successful inline tiers leave syscall tables untouched; unsupported kernels can
fall back to LSM/syscall hooks. The module status shows the selected mechanisms.
Published inline hooks stay loaded until reboot; reboot after updating the package.
