# HMA UID Fake

KernelSU module that makes the uid of an app hidden by HMA (or HMA-OSS) answer as if it did
not exist:

```
getpriority(PRIO_USER, uid)       -> -ESRCH
ioprio_get(IOPRIO_WHO_USER, uid)  -> -ESRCH
setpriority / ioprio_set         -> -ESRCH when the request reaches USER lookup
```

Which rules apply follows the app a process was born from, not the uid it holds when it calls, so an
isolated child or anything that called `setuid()` answers the same way.

The preferred path hooks `find_user` and the setuid capability callback using
the running kernel's entry instructions, leaving both syscall tables untouched.
Unsupported kernels can fall back to LSM/syscall hooks; module status identifies
the mechanism installed.

Install the module zip with KernelSU. Boot loading prefers `/data/adb/ksud insmod`
when available, otherwise the bundled loader. A published inline hook remains
loaded until reboot.

See [design](docs/design.md) for hook behavior and compatibility limits,
and [build instructions](docs/build.md) for packaging and loading.

GPL-2.0, see [LICENSE](LICENSE).
