# Design

## Layout

One file per mechanism, so that what can be swapped is a swap of a file and not of an `if`:

```
inline_hooks.c    find_user / cap_task_fix_setuid hooks, one-instruction entry publication,
                  policy/identity handling, and permanent module references
table_hooks.c     the two mechanisms that rewrite sys_call_table entries, one for the uid
                  queries and one for the id setters, plus that table plumbing itself
inode_hook.c      the apk side: registered application APKs have ->open replaced
lsm.c             the task_fix_setuid LSM fallback, before the credential commit
inline_entry.c    a short original-call trampoline, returning to the native function body
inline_alloc.c    private near-island pages, runtime allocation and RW/NX to RO/X sealing
inline.c          the relocator and branch encoder
tiers.c           the walk: try a family's mechanisms in order, remember what won
tag.c status.c    the identity record, and what the module reports about itself
policy.c          the rules, and the query the hooks ask
hooks.c           the two families and their order
```

## Mechanisms and their order

There are two questions, and more than one mechanism can answer each of them. Which one works
depends on the kernel it was not built for, so each mechanism is a struct with the order it wants to
be tried in, one definition in its own file, and one line in the table in `tiers.c`. The runner walks
a family in that order until one installs; a mechanism that fails says so and the next one is tried.

| family | order | mechanism | answers from |
| --- | --- | --- | --- |
| uid queries | 10 | `inline find_user` | an entry hook plus the original `find_user` body |
| uid queries | 20 | `syscall tables` | the four entries in `sys_call_table` (and their 32-bit numbers) |
| setuid | 10 | `inline cap_task_fix_setuid` | an entry hook plus the original capability callback |
| setuid | 20 | `lsm task_fix_setuid` | the LSM hook itself, taken by replacing its pointer or static call |
| setuid | 30 | `syscall setters` | the six setters in both syscall tables |

The order is data: moving a mechanism is one number. A mechanism can also be forced, which is how
the table above is checked on a device -- a forced run tries only what it names, so that a failure
is reported rather than quietly replaced:

```
/data/adb/ksud insmod /data/local/tmp/hma_uidfake.ko 'uid_tier=inline setuid_tier=inline'
```

With both inline tiers selected successfully, neither family changes syscall table entries. Auto
selection still permits the fallbacks above; forcing both tiers prevents that fallback, but a loaded
module alone does not prove either tier installed. Check the reported mechanisms and errors.

The inline implementation copies one or two entry instructions from the running function into a
short trampoline, then branches back to the native body. Including its synthetic `BTI c`, the
trampoline occupies at most 16 bytes. Internal branches, alternatives and exception-table addresses
in the remainder keep their original locations; whole-function relocation is not used.

The live patch is one aligned four-byte `B`. A leading `BTI c/jc` or `PACIASP/PACIBSP` remains in
place, with the following instruction patched instead. When entry PAC has already signed LR, the
matching assembly stub authenticates it at the original SP before entering C. The original-call
trampoline replays the displaced prefix with its own call's LR, then resumes the native body.
The direct path's trampolines and stubs live in executable, non-writable module text.

If either direct branch exceeds A64's approximately ±128 MiB range, a private page near the
kernel target holds an entry veneer and the original-prefix trampoline. A single `B` reaches the
island; its LDR/BR veneer enters the module stub. The module's original-call alias uses another
LDR/BR to reach the island trampoline, whose final B resumes the native body. Both veneers use
ABI scratch x16 and preserve LR, SP, NZCV and arguments. The island is filled RW/NX and sealed
RO/X before publication; an unpublished page can be freed, but a published page stays pinned.
The entire kernel image is excluded from allocation. Missing nearby space or required permission,
cache or allocation helpers causes refusal.

Missing symbols or patch helpers, unrecognized entry instructions, unsafe branches/address-taking
into the displaced prefix, and unresolvable indirect control flow cause refusal. The scanner requires a complete
symbol-bounded snapshot of at most 1024 bytes and assumes normal compiler function-entry calls;
it cannot discover arbitrary external jumps into a function's interior. This adapts to runtime code
without a firmware profile, but it is not a universal KMI contract. The internal symbols and accepted
instruction shapes can differ between vendor kernels.

When neither family installs, initialization skips task identity priming. Module load success
still means its status endpoint is available, not that a hook necessarily installed.

The registry remains an explicit table: module linker sections cannot rely on Kbuild with LTO
providing `__start_`/`__stop_` symbols.

## Queries

The USER branches of `getpriority`, `setpriority`, `ioprio_get`, and `ioprio_set` use `find_user()`
to look up an existing `user_struct`. The inline hook first calls `policy_query`, then selects either
the requested UID or its policy replacement and calls the native lookup through the trampoline.
Hidden targets normally take a native miss without first acquiring the hidden user's reference.
An absent UID also reaches `policy_query`, closing a pending identity window on this path.

Replacement UIDs are selected at policy-apply time from an unassigned range, aiming for the target's
native hash bucket. For `hash_32`, multiplication is truncated to 32 bits before the high bits are
extracted, matching the kernel's arithmetic. If a replacement becomes live later, the hook releases
that unrelated result and returns `NULL`; it never returns the replacement user's object. This guard
adds work on a collision. Hash detection, bucket contents, cache state, and contention still affect
latency, so neither equal cost nor timing indistinguishability is guaranteed.

PROCESS/PGRP paths avoid the new hook. Self/zero targets and some invalid ioprio requests can also
bypass `find_user`, so pending-window closure is not identical to observing every syscall invocation.
Other kernel callers of `find_user` do enter the policy hook; this implementation has no caller
whitelist. There is no permanent kprobe or syscall tracepoint on these paths. Symbol resolution uses
temporary initialization probes, which are immediately unregistered.

The table fallback instead substitutes the UID argument in its wrapper before calling the original
syscall. Both mechanisms use the birth tag for caller identity. The inline mechanism receives an
ordinary `kuid_t` argument and leaves the syscall's `pt_regs` untouched.

A slot is patched only when the value in it is one this module resolved: the entry's own symbol, the
64-bit implementation, the compat wrapper under either of its names, in both the plain and the
jump-table spelling. The number a syscall has is a hint for the first comparison, never the thing
that decides -- a wrong number would otherwise be a hook on someone else's syscall, which is what a
32-bit getpriority used to be before this was a comparison.

## Naming an isolated child

An isolated process gets its uid at birth and nothing else says which app it came from:

1. **Birth.** The preferred hook wraps `cap_task_fix_setuid`, which receives both old and proposed
   credentials, including calls originating from 32-bit userspace. After the original callback
   succeeds, the hook records eligible identity transitions. This is before `commit_creds`; another
   LSM can still reject the change later. When the framework gives an app uid to a
   fresh process, or `app_zygote` gives an isolated uid to one, the app id goes into bits 40..53 of
   `thread_info.flags` (zero = untagged) and an isolated child also gets a pending bit above that
   field. A task that is named already is left alone: its name came from the one transition that
   gave it its identity.
2. **Fallbacks.** If inline installation is refused in auto mode, the LSM pointer/static-call tier
   is tried, then wrappers around the id setters. The LSM fallback also sees proposed credentials
   before the commit; setter wrappers sample the two ends of the syscall. Status identifies which
   mechanism installed. Neither callback-based tier is a post-commit notification.
3. **The first file of its code it opens.** The pending bit says a child is waiting. Registered
   application APKs have their `->open` replaced with a copy of the inode's
   `file_operations` that differs in that one member, and the record behind the copy is the app id:
   the first open of that file names the whole thread group, with no lookup and no walk. The inode is
   held while its fields are read and only for that -- a path resolves to a dentry, not to a committed
   inode, and the package manager frees the one it is replacing while the helper is still sending the
   new one. Nothing is stored about the inode: a record keeps the numbers it was made for and the
   table to put back, is never handed to another file, and carries this module as the owner of its
   table -- so an open file keeps the module loaded and the table cannot be given back while one is
   still using it. At unload each file is found again from the path it was registered with. The app
   id is taken from inside the uid (`uid % 100000`), because a user id is the high part of it: read
   as a whole number, an app of a secondary user looks like an isolated uid and would never be named.
4. **Before the module loads.** `uidfake_tag_prime()` derives the same tag for every running task
   from its uid. A successful inline installation stays loaded until reboot.

## Policy and APK synchronization

`sync-tool` watches HMA/HMA-OSS configuration, APK paths, PackageManager commits and Android user
changes before its first synchronization attempt. It expands rules for the current packages and
users and sends them through staged netlink. A readable empty configuration clears policy; a
missing or unreadable configuration preserves it and schedules a retry. Direct system-APK paths
and directories containing `base.apk` are supported. APK registration includes applications without
rules so their isolated children can be identified; policy callers take priority at the size limit.

APK messages are deltas. A device/inode ledger records each entry as `Adding`, `Confirmed` or
`Dropping`, accounting for operations whose replies may be lost. Removals and same-inode UID
changes must be acknowledged before replacement adds. An add batch is confirmed only when status
reports the expected count and zero failures; uncertain additions are retried individually. This
keeps a partial failure from repeatedly retiring successful replacements. An unreachable peer
arms a retry. `sync-tool --once` fails when policy or APK synchronization remains incomplete.

The ledger is not persistent or a kernel inventory: a daemon restart cannot recover every installed
record. Userspace `stat()` can race the kernel's path resolution during package replacement, and
status describes the latest apply, so reconciliation assumes one writer. Retired inode shadows
remain allocated until reboot on the pinned inline path.

## Patch writes

`patch.c` uses the running kernel's `aarch64_insn_patch_text_nosync` helper for native fixmap geometry,
locking and instruction-cache maintenance. Trampolines are populated and checked before publication;
a failure leaves only unreachable scratch code. This path does not walk `init_mm` using the
module's structure layout.

Entry publication uses `uidfake_patch_insn`: validate the aligned kernel-text address, stop all
online CPUs, compare the expected instruction, and write exactly one replacement word through the
native helper. Cache maintenance finishes while CPUs remain stopped, and every participating CPU
executes ISB before resuming. In the checked ARM64 ACK implementations the helper's four-byte
nofault write is one aligned `STR W`; an error leaves that instruction unchanged. A missing helper
or mismatched instruction refuses publication without attempting a multibyte entry patch.

The module takes a reference before publishing either entry and retains it permanently on success.
Normal unload is therefore unavailable until reboot. Restoring the entry alone would not drain
threads preempted inside a setuid hook or trampoline. Tier teardown keeps its registry while any
inline hook is active, and module initialization must not return an error after publication.

The legacy alias writer remains for LSM/syscall data-slot fallbacks. It checks the kernel/module
range, calibrates its page-table walk only when that path is first needed, and finishes cache
maintenance inside the stopped phase. Its bulk-write error can still mean a changed prefix; it is
not the single-instruction transaction API and must not be used for inline entry publication.

## Diagnostics

Diagnostics sit behind a static key (jump label): with the key off the branch is a NOP.

```
/data/adb/ksud insmod /data/local/tmp/hma_uidfake.ko debug=1
```

What the module is doing is also readable where a user looks: `KAUX_CMD_STATUS` answers with the
entry counts for both tables, how many apk inodes are held and how many of an apply failed, whether
the setuid hook was taken and from which implementation, the geometry this module was built for, and
the last failure. `sync-tool` reads it and writes the one-line summary into the module description,
which is where KernelSU and Magisk show a module's state, and compares the module's geometry against
the running kernel's config (`/proc/config.gz`).

## Invariants

- Hidden targets normally redirect to a native lookup miss. A live replacement is released and
  rejected rather than being returned as the target's user object.
- Replacement selection aims for the target's bucket using the detected UID hash. The inherited
  detector has a default formula when detection fails; this is not proof of bucket equivalence on
  every vendor kernel.
- The policy table fixes its target-probe count when a layout is built. Its UID-hash layout uses
  the detected bucket to select a line and slot; caller masks are interned rather than repeated for
  each target. Replacement selection uses `csel`, reducing branches on the hiding decision.
  Caller lookup, identity handling, and the native UID lookup still have their own control flow.
  `scripts/lookup_model.py` models policy table accesses, not total kernel execution time.
- Replacements come from 20001..24096 and are checked for absence when the policy is applied.
  That check is a snapshot, so the inline path must retain its live-replacement collision guard.
- The inline entry accepts a normal function argument and does not rewrite syscall `pt_regs`.
- The kernel only compares numbers; whatever needs a path, a package name or JSON happens in
  `sync-tool`, and what arrives is checked for shape and size.
- A rejected update changes nothing: a policy that does not fit, a caller that is not an app uid, a
  group larger than the tables -- each is logged and the previous policy stays in force, because
  half a policy is the state that leaks.

## Trust

- The netlink family is `GENL_ADMIN_PERM`: only root can push a policy, both blobs are
  length-checked before they are parsed, and nothing is copied back out except the status.
- HMA's `config.json` decides who is hidden and belongs to HMA's uid; `sync-tool` reads nothing an
  app can write.
- The tag still uses bits 40..53 of `thread_info.flags` and pending bit 55. Removing syscall hooks
  does not remove this shared-field dependency or reserve these bits against other kernel modules.
- The hooked syscalls take at most three arguments, which is what the register object they receive
  covers.
- Normal runs print no addresses; the two init lines that do are behind the debug key.
- Timing indistinguishability is not guaranteed; measure with `uidbench` on the running kernel.

## Protocol

Little endian, defined once in `include/kaux.h`, which the module and the tool both include. The
family version is 3 and the kernel rejects a request that does not carry it, so a helper and a
module of different versions cannot read each other's command ids. Version 3 has not been published
before 0.3.0, so it is the layout as it stands.

```
KAUX_CMD_PING         (1)  no payload, ACK only
KAUX_CMD_STAGE_BEGIN  (2)  blob: struct kaux_begin {u32 kind, u32 bytes, u32 crc32}
KAUX_CMD_STAGE_CHUNK  (3)  blob: u32 offset, u32 len, then len bytes
KAUX_CMD_STAGE_COMMIT (4)  no payload: byte count and CRC are checked, then applied
KAUX_CMD_STATUS       (5)  reply: KAUX_ATTR_STATUS = struct kaux_status
```

Family `kaux`, all commands `GENL_ADMIN_PERM`; a blob over 32 KiB is rejected before it is parsed.
A blob goes up in chunks and only becomes live when the commit matches what was announced, so a
half-uploaded policy never takes effect. `struct kaux_status` carries magic, size and version, so a
reader that is not looking at the structure it was built for says so instead of misreading it.

| limit | value |
|---|---|
| `(caller, target)` pairs | 65536 |
| callers | 4096 |
| code dirs (`UF_APK_MAX`) | 10000 |
| netlink blob (`KAUX_STAGED_BYTES`) | 2 MiB |
| netlink message (`MAX_BLOB_BYTES`) | 32 KiB |
