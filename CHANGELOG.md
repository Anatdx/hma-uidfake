# Changelog

## 0.3.3

- The tool reads the package database whichever form it is written in. Android 12 introduced the
  binary one (ABX) and `Xml.resolveSerializer()` picks between the two by the system property
  `persist.sys.binary_xml`, while reading sniffs the header -- so a device can carry either, and a
  device whose database is text used to get no rules at all, which is nothing hidden for anyone. One
  entry header hands out the same events for both forms, the readers live in their own units, and a
  file that is neither form is refused with the first bytes in the log rather than guessed at. Two
  things the text form needed besides a parser: the system flag, which that writer spells
  `publicFlags` where the binary one writes `flags`, and the shared user id, which was never read
  from a `<shared-user>` element at all.

- The manager hides itself under the xposed preset again. HMA-OSS writes itself into that preset in
  code and exports only the scanned half to its cache, and the generated table of written-in names
  had xposed empty: the generator collected quoted strings only, so the bare
  `BuildConfig.APP_PACKAGE_NAME` was dropped without a word. On a device that has run the app, where
  the cache answers, every caller that applies the preset saw the manager, while a scan of the same
  packages hid it. The generator resolves that name from the app's build script now and refuses to
  write a table at all when it meets an identifier it cannot resolve.

- A preset cache that cannot be parsed falls back to the older file instead of leaving the device
  with no presets and a full rescan of every installed apk, and a package that joins a shared user
  gets its app id back.

## 0.3.2

- A kernel where the setuid hook cannot be taken still learns who changes ids: the setters in both
  syscall tables are watched instead, which is the mechanism KernelSU uses for the same purpose.
  That is the state a vendor kernel with `CONFIG_TRIM_UNUSED_KSYMS=y` puts us in -- the symbol that
  moves a 6.12 LSM static call is not exported by any KMI this is built for, and a kernel that trims
  unused ksyms does not even have it in its image -- and the module used to say so and then hide
  nothing at all, because a process it never names has no rules. The status line says which of the
  two is in place (`setuid=<implementation>` or `setuid=syscall setters`), and the entry counts it
  reports include the setters, so that line reads ten of ten rather than four of four.

- The 6.12 LSM path takes the static call table's real size from kallsyms instead of trusting this
  build's `MAX_LSM_COUNT`, and enables the slot's own static key after taking it over; both are what
  KernelSU does as well.

## 0.3.1

- A hidden uid no longer answers measurably differently from a uid that does not exist. The lookup
  picked the replacement with a branch on the answer -- a predictor can learn that and a clock can
  see it -- and the value it picked was one the kernel takes several nanoseconds longer to reject
  than an ordinary uid. Both are fixed, and `uidbench` now judges its verdict against a control
  class (the same hidden uid measured twice) instead of the spread between two absent uids, which
  had been calling a real 13 ns difference not exploitable.

## 0.3.0

- An isolated child is named from the apk it opens, instead of from the openat hook that used to walk
  the dentry chain of every file it opened. Every app that has rules has its base.apk's `->open`
  replaced with a copy of the inode's `file_operations` that differs in that one member and carries
  the app id behind it, so the first open of its own code names the whole thread group. `openat` is
  gone from both syscall tables; nothing is looked up on the open path, no reference to the inode is
  taken, and the tables are put back at unload by finding each file again from its path.

- The id change is watched where the kernel commits it. The six setter wrappers in each syscall
  table are gone -- twelve entries, plus the compat numbers they were written with -- and
  `task_fix_setuid` is taken in the LSM hook list instead, chained into the implementation that was
  there (commoncap's on every kernel this is built for; SAFETY: SELinux does not implement it).
  Both creds are handed over, so nothing is sampled around a call, and 32-bit callers go through it
  too. A task that is named already is left alone, which is also what stops a process that changes
  ids repeatedly from being reported each time. The syscall tables keep the four uid lookup entries,
  native and compat, and nothing else.

- A 32-bit caller is no longer a way around the hiding. The compat entries are matched by the
  function that is in them -- the 64-bit implementation, or the compat wrapper under either of its
  names, in both spellings -- where the number used to decide, and the number this module carried
  for getpriority was 141 while the 32-bit table numbers it 96: the old code was patching getdents
  and _llseek. An entry that cannot be found is not hooked and says so.

- Text is written through the kernel's own fixmap window with a nofault copy, the way KernelSU's
  patcher does, instead of mapping the page again with vmap: the kernel builds the mapping, so no
  page protection has to be guessed. The write is proved before it happens -- the alias has to show
  the bytes that are at the target -- and the alias is derived from the kernel's own `vmemmap`, so a
  kernel whose VA size is not the one this module was built with is used rather than only refused.

- The physical address comes from the image offset first and the page table walk second. On a vendor
  kernel whose `struct mm_struct` is not the tree's, the walk answers with the wrong page; it is
  calibrated against the offset once at load and dropped if the two disagree.

- The protocol is defined once, in `include/kaux.h`, which the module and the tool both include. The
  retired apk command is gone, the staged commands are named for what they do, and
  `KAUX_CMD_STATUS` answers with what the module hooked: entry counts for both tables, apk inodes
  held and failures, whether the setuid hook was taken and from which implementation, the geometry
  the module was built for, and the last failure. The tool reads the running kernel's config to
  compare the geometry, and writes the summary into the module description -- the line KernelSU and
  Magisk show -- so a hook that is not installed is visible without a dmesg.

- The apk inode limit is 10000, the same as a user's app id space, and the staging buffers are 4 MiB
  and allocated on first use rather than at load. The tag and the wait bit are in separate bits now:
  the pending bit sat inside the tag field, which would have read as "still waiting" for a tag with
  the top bit set.

  a work profile queried its own user's uid and matched nothing. The helper reads
  /data/system/users and writes every pair once per user, each with the replacement its own bucket
  needs.

- A hidden target and one that was never configured now read the same addresses the same number of
  times, and read far less: the lookup takes the target's line and, from the mask of each probed
  slot, one word -- the caller's own. It used to read every word of every probed mask, ten loads per
  slot for a policy with six hundred callers. The masks are interned as well, one entry per distinct
  set of callers, so twenty-four thousand pairs keep a few hundred of them instead of one copy per
  slot. The same host benchmark over a sweep of four thousand targets went from 16.0 to 5.1 ns per
  query at that size; building the policy pays about a millisecond more for the interning.

- A name is never taken away by the code that marks a child as waiting or that closes the window:
  both move the flag with a compare-and-swap that leaves the tag field alone. A task that was named
  while either was in flight kept answering as one with no rules of its own before this. Kernel
  addresses also left the unconditional log lines -- they need the debug switch, which is what the
  module's own comment about dmesg asked for.

- The apk shadow is one table per file, never handed to another file, and the copy names this module
  as its owner. A table used to be given to the next replacement while the inode it was made for could
  still be read: that inode then dispatched into another filesystem's operations, an apk that came
  back after being dropped chained to this module's own open and called itself until the stack was
  gone, and a record was installed even when its path could not be stored, leaving a file that no
  unload could find again. The owner also makes an open file count against unload, so no file can
  still be holding a table when the module is given back.

- The inode whose open is replaced is held for as long as it is read, and only for that. A path
  resolves to a dentry, not to a committed inode: the package manager frees the inode it is replacing
  while the helper is still sending the new one, and reading its fields after that was a
  use-after-free -- on an uninstall, which is exactly when that happens.

- The app id is read from inside the uid, not from the whole number. An app of a secondary user
  (100000 + app) was compared against the isolated range as a whole uid, so it looked isolated and was
  never tagged: every app of that user was hidden from nothing, while the policy itself carried its
  pairs. A caller-0 pair ("hide from everyone") is honoured for a caller with no rules of its own as
  well -- the lookup used to answer zero for those before it ever read the target's line -- and the
  identity word is moved with a compare-and-swap, so a TIF_* bit the kernel sets in the same word is
  never lost.

- An apply is serialised: two uploads at once used to copy into the buffer while it was being parsed.
  The status line counts the apk inodes that are held from the table itself instead of adding deltas,
  so a drop for an entry this kernel never had can no longer take the number below zero, and a setuid
  hook whose slot could not be put back at unload says so instead of leaving a pointer into this
  module behind.

- The target table follows the number of targets instead of the worst collision on one line: a target
  goes into its own slot of its own line or of the lines that follow, so twenty-four thousand
  targets need 8192 lines (512 KB) where they needed 32768 (2 MB). A query reads one slot from
  each probed line and one word of its mask either way, which measures the same as before, and
  building the policy is slightly faster because the buffers a layout is built in are kept
  between applies. The staging buffers the kernel holds for an upload are 2 MiB rather than 4 --
  a policy cannot be larger than 512 KiB and an apk set than about 800 KiB -- so six megabytes
  of kernel memory are no longer held for nothing. The tool compares the apk set through hash
  sets instead of scanning the published list for every entry, which was up to a second of work
  on a device at the ten thousand apk limit, on every package event.

- The user ids are read on their own terms: the directory names under /data/system/users went
  through the parser written for uids, and that one rejects 0, so a device with a work profile
  wrote the work profile's pairs and dropped the primary user's -- the case above, still open.
  A listing that cannot be opened, stops half way or comes back empty is not a user set either:
  the previous policy is kept and the sync retries until it reads one (/data may still be
  encrypted at boot), and --once reports the failure instead of a success. A regression test
  covers user 0 beside a secondary user.

- The policy is published without a lock: the spinlock that was taken with interrupts off around it
  guarded a single pointer assignment, which is an atomic exchange by itself.
- The staged upload takes one, on the other hand: three commands write the same buffer and nothing
  serialised them. A second sender could only produce a policy whose CRC does not check out -- refused
  rather than half applied -- but a mutex keeps them from fighting over it.


- The presets a config applies follow the app line for line. The rules its own code computes
  (`canBeAddedIntoPreset`) were only partly copied here, so a package the app hides could be one this
  side did not count -- a uid hidden in userspace and still answered by the kernel. `sus_apps` by
  `com.termux` and the apk editor assets, `root_apps` by the viper, busybox, magisk and apatch names,
  the kernel manager libraries and the old `ACCESS_SUPERUSER` permission, `accessibility_apps` by its
  permission and never for a system app, `shizuku` by the provider it declares, `xposed` by the entry
  it carries or by being the app itself, `custom_rom` by the full overlay prefix list. A binary
  manifest keeps its strings in UTF-16, so one search looks for both forms: two checks that looked
  for bytes could never have matched on a device.
- Permissions are read from `/data/system/packages.xml` (`<perms>`) as well, and either source is
  enough.
- A regression test holds 25 cases, each naming the line of the app it stands for, and runs with the
  host tests in both rounds (plain and under ASan).

## 0.2.1

- A policy is uploaded in pages and only becomes live when its last page and its CRC check out, so a
  config with thousands of pairs is applied as one piece instead of being refused as too large.
- The netlink command ids moved with that, and the family version is 2: a helper and a module of
  different versions refuse each other instead of reading each other's commands.

## 0.2.0

- HMA and HMA-OSS each have their own config format and their own rules: the source that exists
  decides which one is in use, and each file is read by the parser written for it.
- HMA-OSS works as well as HMA: its config is read from
  /data/misc/hide_my_applist_*/config.json, and the preset cache it writes beside it says what each
  preset contains, so presets (which only the app can work out on the device) are applied too.
- The rule decision is the one HMA-OSS makes: the extra list, the opposite list, the applied
  templates, the applied presets, then whitelist mode. Rules from both tools are applied together.

## 0.1.3

- Config changes are noticed again. An event on a watched directory was taken for an install event
  and dropped, so a changed config was only picked up by the periodic pass -- and that pass is gone.

## 0.1.2

- The policy and the caller code table are sent to the kernel only when they changed, and only
  events for config.json itself count as a config change: an idle module no longer re-sends the
  same tables every few seconds.
- The sync runs on events, not on a timer. Watches that could not be created before the unlock are
  applied when it happens, and a push that did not land asks for one retry.
- The update record the module manager shows is text instead of the release page.

## 0.1.1

- The helper reads /data/system/packages.xml itself instead of asking "pm list packages -f -U"
  and walking /data/app, and installs arrive as inotify events on the first level of /data/app.
- The system flag comes from what that file records instead of MIUI's partition marker, so an
  updated preinstalled app stays a system app.

## 0.1.0

- First release. The module answers the app id (uid) of the packages HMA hides with the id of a
  real, unrelated, installed app, and the kernel refuses an id that a hidden package would be the
  only owner of.
