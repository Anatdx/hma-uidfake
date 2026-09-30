# Design

## Layout

One file per mechanism, so that what can be swapped is a swap of a file and not of an `if`:

```
inline_hooks.c    the two mechanisms that run a copy of a kernel function (find_user,
                  cap_task_fix_setuid): the copy is built by inline.c and entered through a
                  twelve byte patch at the function's own entry
table_hooks.c     the two mechanisms that rewrite sys_call_table entries, one for the uid
                  queries and one for the id setters, plus that table plumbing itself
inode_hook.c      the apk side: the base.apk of an app with rules has ->open replaced
lsm.c             the LSM hook the kernel hands both creds to at the commit (task_fix_setuid)
inline.c          the relocator: whole function, PC-relative operands rewritten or refused
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
| uid queries | 10 | `inline find_user` | a relocated copy of `find_user`, entered at its own entry |
| uid queries | 20 | `syscall tables` | the four entries in `sys_call_table` (and their 32-bit numbers) |
| setuid | 10 | `inline cap_task_fix_setuid` | a relocated copy of what implements the LSM hook |
| setuid | 20 | `lsm task_fix_setuid` | the LSM hook itself, taken by replacing its pointer or static call |
| setuid | 30 | `syscall setters` | the six setters in both syscall tables |

The order is data: moving a mechanism is one number. A mechanism can also be forced, which is how
the table above is checked on a device -- a forced run tries only what it names, so that a failure
is reported rather than quietly replaced:

```
lkmloader hma_uidfake.ko setuid_tier=inline     # or lsm, or setters
lkmloader hma_uidfake.ko uid_tier=tables        # or inline
```

An inline mechanism never guesses: the copy is built from the function's own bytes and every operand
that leaves the function is rewritten into an absolute form (see `include/inline.h`); an encoding
the relocator does not know is a refusal, and the refusal is what the next mechanism is for. The
entry patch is twelve bytes -- `adrp`/`add`/`br x17` -- and no literal pool, because a module sits
further from the kernel's text than a literal load can reach; the stub it jumps to is written in asm,
so that the section holding the copies is executable and not writable at once, which a kernel with
`STRICT_MODULE_RWX` insists on.

The registry is an explicit table and not a linker-collected section. A section would need
`__start_`/`__stop_` symbols, and this toolchain (kbuild with LTO, on every KMI compiled here) does
not synthesise them for a module: the symbols come out undefined and the module would not load. That
was measured on all six KMIs, not assumed.

## Queries

The four syscalls a uid scanner uses reach `find_user()`, the one place that decides whether a uid
has processes at all. The first mechanism answers them there, from a relocated copy of that function:
the real answer is computed and then dropped, so a hidden uid answers exactly like a uid with no
processes, on the same code path and at the same cost -- measured at 0.3 to 0.5 ns of difference,
below the spread between two uids that do not exist. The mechanism behind it redirects the entries in
`sys_call_table` (and the AArch32 numbers in `compat_sys_call_table`) instead: the hook substitutes
the uid argument and calls the original, which takes its own "no such uid" branch. The caller side comes
from the birth tag rather than from the current uid -- one table load and a `csel` -- so changing
uid cannot move a process into another set of rules. `/proc` and ptrace see the argument as the
caller wrote it, and there is nothing to restore.

A slot is patched only when the value in it is one this module resolved: the entry's own symbol, the
64-bit implementation, the compat wrapper under either of its names, in both the plain and the
jump-table spelling. The number a syscall has is a hint for the first comparison, never the thing
that decides -- a wrong number would otherwise be a hook on someone else's syscall, which is what a
32-bit getpriority used to be before this was a comparison.

## Naming an isolated child

An isolated process gets its uid at birth and nothing else says which app it came from:

1. **Birth.** The id change is watched where the kernel commits it: `task_fix_setuid` is taken over
   in the LSM hook list, chained into the implementation that was there (commoncap's on every kernel
   this is built for). It is called for every uid change, 32-bit callers included, and hands over
   both creds, so nothing has to be sampled around a call. When the framework gives an app uid to a
   fresh process, or `app_zygote` gives an isolated uid to one, the app id goes into bits 40..53 of
   `thread_info.flags` (zero = untagged) and an isolated child also gets a pending bit above that
   field. A task that is named already is left alone: its name came from the one transition that
   gave it its identity.
2. **Where the id change is watched.** The LSM hook at the commit is the one that sees both creds
   at once; when the kernel cannot give it to us (no exported way to move a 6.12 static call, which
   is what a kernel that trims unused ksyms looks like), the id setters in both syscall tables are
   hooked instead, exactly as KernelSU does, and the two ends are read around the call. The status
   says which of the two is in place.
3. **The first file of its code it opens.** The pending bit says a child is waiting. The base.apk of
   every app that has rules has its `->open` replaced with a copy of the inode's
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
3. **Before the module loads.** `uidfake_tag_prime()` derives the same tag for every running task
   from its uid. Without it a manual `rmmod`/`insmod` would lose the identity of every running app.

## Patch writes

The kernel text and rodata this touches are read-only, and nothing that makes them writable is
exported to modules. The physical address of the target is translated with the image offset
(`va - kimage_voffset`), the page is mapped through the kernel's own fixmap window, and the write
goes through a nofault copy.

- Every target is inside `[_stext, _end)`; anything else is refused before a byte is written.
- The fixmap address depends on the VA size the kernel was built with, which is not always the one
  this module was built with. Two candidates are tried, this build's and the one derived from the
  kernel's own `vmemmap` (`FIXADDR_TOP = VMEMMAP_START - SZ_32M`), and each is proved before use:
  the bytes at the alias have to be the bytes at the target. Neither proved means nothing is written.
- An inline hook is two writes: the whole function, relocated into this module's own text, and the
  twelve byte entry patch that sends callers there. Both go through the same alias path, both are read
  back, and the bytes the entry patch replaced are kept verbatim so the unload can put them back.
- The page table walk is a second opinion and is calibrated against the image offset once at load. A
  kernel whose `struct mm_struct` or geometry is not this module's makes the walk answer with a
  different page; the offset is the one that does not care, and it is what the write needs.
- What was written is read back, and a hook that is no longer this module's is left alone on unload
  rather than overwritten.

## Diagnostics

Diagnostics sit behind a static key (jump label): with the key off the branch is a NOP.

```
lkmloader hma_uidfake.ko debug=1     # for 60 seconds, then off again
```

What the module is doing is also readable where a user looks: `KAUX_CMD_STATUS` answers with the
entry counts for both tables, how many apk inodes are held and how many of an apply failed, whether
the setuid hook was taken and from which implementation, the geometry this module was built for, and
the last failure. `sync-tool` reads it and writes the one-line summary into the module description,
which is where KernelSU and Magisk show a module's state, and compares the module's geometry against
the running kernel's config (`/proc/config.gz`).

## Invariants

- Never take the `find_user()` hit path: it walks every process at ~1000x the cost of a miss, which
  timing shows. The argument is rewritten instead and the kernel takes its own miss branch.
- The replacement uid hashes into the same bucket as the target (`__uidhashfn(uid) = ((uid >> 7) +
  uid) & 127`), or the chain length would differ from a genuinely absent uid.
- The lookup does constant work: one hash of the target with the kernel's own uid hash (read back
  from `find_user()` when a policy is applied) gives the bucket line and the starting slot; the line
   contents; the probe count is fixed when the policy is laid out (1, 2 or 4), each probe
   reads one slot -- the target's own slot of its own line, then the same slot of the lines
   that follow, which is where the layout puts a target whose line is full -- and one word
   of that slot's mask, the one the caller's own id selects. Which words those are follows
   from the caller and the target and never from the answer; indices are masked, never
   branched on; `cmp`+`csel` picks the bit and the replacement, and the select is a `csel`
   rather than a branch on purpose (a predictor can learn a branch on the answer). Probing
   across lines is what keeps the table the size of the target count rather than of the
   worst collision on one line: 24000 targets need 8192 lines (512 KB) instead of 32768
   (2 MB). The masks are interned, one entry per distinct set of callers, so a policy of
   tens of thousands of pairs keeps a few hundred of them instead of one copy per slot.

   The replacement a hidden target answers with is chosen once, at apply time, from a low
   unassigned range (20001..24096) carrying the target's own uidhash bucket, so a syscall
   that resolves a uid through `find_user()` walks the chain it would for the target. It is
   low because the kernel rejects a small uid several nanoseconds faster than a large one,
   which any caller can measure (`uidbench`, which is why the select is a `csel` too). What
   is left after both is the kernel's own per-value cost variation, the same for these
   values as for any other uid that does not exist. A query touches a function of `(caller, target)` alone --
  `scripts/lookup_model.py` states that function.
- Never touch the syscall's `pt_regs`: the probe sits on `find_user()`, the first place a uid is a
  plain argument register. (arm64 has no in-register syscall entry to hook: no `__do_sys_`/
  `__se_sys_` symbol.)
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
- The tag lives in bits 40..53 of `thread_info.flags` and the pending bit in bit 55; both are only
  read-modify-written with those bits masked out. KernelSU's own marker is the standard
  `TIF_SYSCALL_TRACEPOINT` bit, so the two do not share a field.
- The hooked syscalls take at most three arguments, which is what the register object they receive
  covers.
- Normal runs print no addresses; the two init lines that do are behind the debug key.
- The timing a hidden uid still costs is measured, not assumed away: `src/tools/uidbench.c` samples
  the hidden, absent and unhooked cases in one round and reports paired deltas.

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
| `(caller, target)` pairs | 8192 |
| callers | 8192 |
| code dirs (`UF_APK_MAX`) | 10000 |
| netlink blob (`KAUX_STAGED_BYTES`) | 4 MiB |
| netlink message (`MAX_BLOB_BYTES`) | 32 KiB |
