# Build

Use Linux with CMake 3.22+, GNU make, Python 3, an Android NDK, and the matching
DDK kernel tree/compiler for each KMI. Install `nlohmann-json3-dev` and `zlib1g-dev`
for the userspace helper. Initialize the pinned loader before configuring:

```sh
git submodule update --init --recursive
```

Each KMI builds with its DDK compiler so that Clang CFI and shadow call stack
instrumentation match. Kbuild links the module and writes its objects into
`build/kmi/<KMI>`, a directory holding symlinks to `src/`.

## Package build

With all default DDKs under `/opt/ddk`:

```sh
export ANDROID_NDK_HOME=/absolute/path/to/android-ndk
cmake -S . -B build -DUG_NDK="$ANDROID_NDK_HOME" -DDDK_ROOT=/opt/ddk
cmake --build build -j8
```

The default KMIs are android14-6.1, android15-6.6, android16-6.12 and android17-6.18.
`-DUG_ENABLE_5X=ON` adds the four legacy 5.x KMIs when their DDK trees are present.
Modules go to `build/ko`; the installable zip goes to `build/dist`. The package
also contains `sync-tool`, the pinned `external/lkmloader`, and the boot scripts.

Version metadata comes from git, falling back to `module/module.prop` for source
exports. `-DUG_VERSION_OVERRIDE=0.4.0-dev+local -DUG_VERSION_CODE_OVERRIDE=4000`
sets explicit metadata without changing tags or module attribution.

## Separate KMI builds

For environments with one DDK each, CMake and CI share `scripts/build-kmi.sh`:

| KMI | DDK compiler |
| --- | --- |
| android14-6.1 | clang-r487747c |
| android15-6.6 | clang-r510928 |
| android16-6.12 | clang-r536225 |
| android17-6.18 | clang-r584948c |

For example, run this inside the 6.1 build environment:

```sh
UG_KBUILD_JOBS=8 bash scripts/build-kmi.sh \
  android14-6.1 clang-r487747c \
  build/kmi/android14-6.1 build/ko/android14-6.1_arm64_hma_uidfake.ko
```

Collect the desired modules in `build/ko`, then package them with the NDK:

```sh
cmake -S . -B build -DUG_NDK="$ANDROID_NDK_HOME" -DUG_USE_PREBUILT_KO=ON
cmake --build build -j8
```

Prebuilt mode packages the files present in `build/ko`; keep that directory limited
to the intended candidate. `UG_DEBUG=ON` enables permanent kernel diagnostics.
Normal packages leave it off; the `debug=1` module parameter enables them for 60 seconds.

## Loading

Install the zip through KernelSU and reboot. `customize.sh` selects the matching
KMI. `post-fs-data.sh` loads early; `service.sh` retries if needed and starts
`sync-tool`. Both prefer `/data/adb/ksud insmod` and use the bundled loader only
when ksud is absent. Logs are in the installed module's `state/sync.log`.

For manual loading from a root shell on a boot without this module active:

```sh
/data/adb/ksud insmod /data/local/tmp/hma_uidfake.ko 'uid_tier=inline setuid_tier=inline'
```

Forcing the inline tiers disables fallback for that attempt. Normal package loading
uses automatic selection; check module status for the installed mechanisms and
errors. Published inline hooks remain loaded until reboot, so updating package
files does not replace the running module. A vermagic release-string difference
alone does not establish incompatibility, but the loader cannot repair incompatible
KMI structure layouts.

## uidbench

This optional measurement tool is not a package component. Cross-compile it and
run as an app uid with hiding rules:

```sh
"$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang" \
  -O2 -static -o uidbench src/tools/uidbench.c
```

It samples hidden, absent and unhooked cases in one round. Compare latency on a
controlled device workload; functional success alone does not establish a speedup.
