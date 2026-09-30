// SPDX-License-Identifier: GPL-2.0
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/ioprio.h>
#include <linux/kernel.h>
#include <linux/version.h>

#include <linux/module.h>
#include <linux/resource.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/uidgid.h>
#include <linux/user.h>

#include "uidfake.h"
#include "kaux.h"

/*
 * What the module tells userspace about itself (include/kaux.h). The tool reads
 * it and puts it in the module description, which is where KernelSU and Magisk
 * show a module's state -- so a hook that was not taken is something a user can
 * see without a dmesg.
 */
static struct kaux_status g_status = {
	.magic = KAUX_STATUS_MAGIC,
	.version = KAUX_FAMILY_VERSION,
	/* what this build assumes; the tool checks it against the running kernel */
	.va_bits = CONFIG_ARM64_VA_BITS,
	.page_shift = PAGE_SHIFT,
};

void uidfake_status_get(struct kaux_status *out)
{
	*out = g_status;
	/* The reader checks these before it believes anything else, so they are set
	 * here and not left to whoever filled the rest in. */
	out->magic = KAUX_STATUS_MAGIC;
	out->size = sizeof(*out);
	out->version = KAUX_FAMILY_VERSION;
}

void uidfake_status_set_hooks(unsigned int native, unsigned int compat)
{
	g_status.native = native;
	g_status.compat = compat;
	if (native == g_status.native_expected)
		g_status.flags |= KAUX_F_NATIVE;
	if (compat == g_status.compat_expected)
		g_status.flags |= KAUX_F_COMPAT;
}

void uidfake_status_set_lsm(int state, int error, const char *target)
{
	g_status.lsm_state = state;
	g_status.lsm_error = error;
	if (state == KAUX_LSM_TAKEN || state == KAUX_LSM_FALLBACK)
		g_status.flags |= KAUX_F_SETUID;
	if (target)
		strscpy(g_status.lsm_target, target,
			sizeof(g_status.lsm_target));
}

void uidfake_status_set_apks(unsigned int inodes, unsigned int expected,
			     unsigned int failed)
{
	g_status.apk_inodes = inodes;
	g_status.apk_offered = expected;
	g_status.apk_failed = failed;
	/*
	 * An inode that could not be put in place is worth keeping: the next apply
	 * that goes well would otherwise report no failures at all, and a hook that
	 * is missing on one file is not something a later success undoes.
	 */
	g_status.apk_failed_total += failed;
	g_status.apk_updates++;
	if (failed == 0)
		g_status.flags |= KAUX_F_APKS;
}

void uidfake_status_note(int error)
{
	g_status.last_error = error;
}

/* The window is closed from the query path too (see uidfake_close_pending). */
void uidfake_tag_close(void);

/* one translation unit with the policy: its query is on the hot path and the
 * compiler can then inline it into the syscall wrappers instead of paying a
 * call for every query */
#include "policy.c"

#define ARG_UID 0 /* find_user(kuid_t uid): uid in x0 */
#define ARG_WHO \
	1 /* getpriority/setpriority/ioprio_get/ioprio_set: (which, who, ...) */

/* syscall_fn_t is not declared for every KMI the module builds against */
typedef long (*uidfake_syscall_t)(const struct pt_regs *);

/*
 * nr is where the entry is expected to be, and is replaced by where it really is
 * once the slot has been found. A table is searched for the wrapper that is
 * supposed to be in it -- the same thing KernelSU does to find a free slot for
 * its dispatcher -- so the number itself is a shortcut and not the thing that
 * decides what gets patched. On a kernel whose numbering, 32-bit ABI or vendor
 * syscalls differ from the tree this module was built against, the constant
 * would point at the wrong entry and the patch that followed would be a hook on
 * someone else's syscall; looking the wrapper up instead cannot do that, and an
 * entry that cannot be found is simply not hooked.
 */
struct hook_entry { // NOLINT(clang-analyzer-optin.performance.Padding)
	unsigned int nr;
	uidfake_syscall_t ours;
	uidfake_syscall_t orig;
	const char *sym;
	/*
	 * The table entry of the other (64-bit) table this one has to hold the same
	 * function as, or -1 to resolve sym instead. The 32-bit ABI calls the same
	 * implementations for the syscalls this module cares about -- unistd32.h maps
	 * getpriority to sys_getpriority and so on -- but through its own table, so
	 * the value to look for is the address the 64-bit table held, not a name and
	 * not a number. Names are what this replaced: the numbers this module used to
	 * carry (141 for getpriority) were not even the 32-bit ones (96), and on a
	 * device where the 32-bit table has no such entry at all there is nothing to
	 * find and nothing is hooked.
	 */
	int native;
	/*
	 * The other way a 32-bit table names the same syscall: some kernels wrap
	 * compat syscalls in __arm64_compat_sys_<name> and put that in the table,
	 * where others put the 64-bit implementation itself. Both are accepted --
	 * the value found in the table is what decides, and the device decides which
	 * of the two its kernel has.
	 */
	const char *sym32;
	/* the 64-bit sibling of a fallback entry, when native is -1 */
	struct hook_entry *ally;
};

/*
 * Only data is patched, never an instruction: the syscall table entries are
 * indirect calls, so there is no branch range to worry about (a module region
 * is farther from the image than a bl can reach), no BTI landing pad and no PAC
 * prologue. A wrapper never touches the task's pt_regs either -- it copies it,
 * substitutes the uid in the copy and runs the real wrapper with that, so
 * find_user() fails exactly like for a uid that does not exist while
 * /proc/<tid>/syscall, ptrace and the syscall-exit stop keep seeing the
 * original argument.
 *
 * This is the mechanism KernelSU uses. Fallback: if the table cannot be
 * resolved or patched, the verified sys_call_table patch is the only hook.
 */

asmlinkage long uidfake_getpriority(const struct pt_regs *regs);
asmlinkage long uidfake_setpriority(const struct pt_regs *regs);
asmlinkage long uidfake_ioprio_get(const struct pt_regs *regs);
asmlinkage long uidfake_ioprio_set(const struct pt_regs *regs);

/* The fallback: only installed when the LSM hook cannot be taken (see below). */
asmlinkage long uidfake_setuid(const struct pt_regs *regs);
asmlinkage long uidfake_setreuid(const struct pt_regs *regs);
asmlinkage long uidfake_setresuid(const struct pt_regs *regs);
asmlinkage long uidfake_setgid(const struct pt_regs *regs);
asmlinkage long uidfake_setregid(const struct pt_regs *regs);
asmlinkage long uidfake_setresgid(const struct pt_regs *regs);
#ifdef CONFIG_COMPAT
asmlinkage long uidfake32_setuid(const struct pt_regs *regs);
asmlinkage long uidfake32_setreuid(const struct pt_regs *regs);
asmlinkage long uidfake32_setresuid(const struct pt_regs *regs);
asmlinkage long uidfake32_setgid(const struct pt_regs *regs);
asmlinkage long uidfake32_setregid(const struct pt_regs *regs);
asmlinkage long uidfake32_setresgid(const struct pt_regs *regs);
#endif

static struct hook_entry g_hook[] = {
	{ __NR_getpriority, uidfake_getpriority, NULL,
	  "__arm64_sys_getpriority", -1, NULL, NULL },
	{ __NR_setpriority, uidfake_setpriority, NULL,
	  "__arm64_sys_setpriority", -1, NULL, NULL },
	{ __NR_ioprio_get, uidfake_ioprio_get, NULL, "__arm64_sys_ioprio_get",
	  -1, NULL, NULL },
	{ __NR_ioprio_set, uidfake_ioprio_set, NULL, "__arm64_sys_ioprio_set",
	  -1, NULL, NULL },
};

/*
 * AArch32 binaries go through compat_sys_call_table with the ARM (EABI)
 * numbers. They are stable ABI constants: getpriority/setpriority are 141/140
 * in both tables, ioprio is not (314/315 here against 31/30 in the 64-bit
 * generic table).
 */
#ifdef CONFIG_COMPAT
/* The 32-bit (EABI) numbers of the same four: a hint for the first comparison,
 * the value found in the table is what decides. */
#define NR32_GETPRIORITY 96
#define NR32_SETPRIORITY 97
#define NR32_IOPRIO_SET 314
#define NR32_IOPRIO_GET 315

asmlinkage long uidfake32_getpriority(const struct pt_regs *regs);
asmlinkage long uidfake32_setpriority(const struct pt_regs *regs);
asmlinkage long uidfake32_ioprio_get(const struct pt_regs *regs);
asmlinkage long uidfake32_ioprio_set(const struct pt_regs *regs);

static struct hook_entry g_chook[] = {
	{ NR32_GETPRIORITY, uidfake32_getpriority, NULL, NULL, 0,
	  "__arm64_compat_sys_getpriority", NULL },
	{ NR32_SETPRIORITY, uidfake32_setpriority, NULL, NULL, 1,
	  "__arm64_compat_sys_setpriority", NULL },
	{ NR32_IOPRIO_GET, uidfake32_ioprio_get, NULL, NULL, 2,
	  "__arm64_compat_sys_ioprio_get", NULL },
	{ NR32_IOPRIO_SET, uidfake32_ioprio_set, NULL, NULL, 3,
	  "__arm64_compat_sys_ioprio_set", NULL },
};

static struct hook_entry g_set[] = {
	{ __NR_setuid, uidfake_setuid, NULL, "__arm64_sys_setuid", -1, NULL,
	  NULL },
	{ __NR_setreuid, uidfake_setreuid, NULL, "__arm64_sys_setreuid", -1,
	  NULL, NULL },
	{ __NR_setresuid, uidfake_setresuid, NULL, "__arm64_sys_setresuid", -1,
	  NULL, NULL },
	{ __NR_setgid, uidfake_setgid, NULL, "__arm64_sys_setgid", -1, NULL,
	  NULL },
	{ __NR_setregid, uidfake_setregid, NULL, "__arm64_sys_setregid", -1,
	  NULL, NULL },
	{ __NR_setresgid, uidfake_setresgid, NULL, "__arm64_sys_setresgid", -1,
	  NULL, NULL },
};

#ifdef CONFIG_COMPAT
#define UF_NR32_SETUID 213
#define UF_NR32_SETGID 214
#define UF_NR32_SETREUID 203
#define UF_NR32_SETREGID 204
#define UF_NR32_SETRESUID 208
#define UF_NR32_SETRESGID 210

static struct hook_entry g_cset[] = {
	{ UF_NR32_SETUID, uidfake32_setuid, NULL, NULL, -1,
	  "__arm64_compat_sys_setuid", &g_set[0] },
	{ UF_NR32_SETREUID, uidfake32_setreuid, NULL, NULL, -1,
	  "__arm64_compat_sys_setreuid", &g_set[1] },
	{ UF_NR32_SETRESUID, uidfake32_setresuid, NULL, NULL, -1,
	  "__arm64_compat_sys_setresuid", &g_set[2] },
	{ UF_NR32_SETGID, uidfake32_setgid, NULL, NULL, -1,
	  "__arm64_compat_sys_setgid", &g_set[3] },
	{ UF_NR32_SETREGID, uidfake32_setregid, NULL, NULL, -1,
	  "__arm64_compat_sys_setregid", &g_set[4] },
	{ UF_NR32_SETRESGID, uidfake32_setresgid, NULL, NULL, -1,
	  "__arm64_compat_sys_setresgid", &g_set[5] },
};
#endif

#endif

/*
 * Substitute the uid argument when the policy hides it, then run the real
 * wrapper.
 *
 * Only the argument registers are copied: the generated __arm64_sys_* wrappers
 * read exactly regs[0..2] (which/who/prio) and never pass the pt_regs on, so
 * the rest of the copy is never touched. The copy is unconditional and the
 * substituted value is selected with csel, so a hidden uid and a uid that does
 * not exist execute the same instruction stream -- only the register value
 * differs. The task's own pt_regs is never modified, so /proc/<tid>/syscall,
 * ptrace and the syscall-exit stop keep seeing the original argument.
 */
/*
 * The ten syscalls hooked here take three arguments at most, and the generated
 * __arm64_sys_* wrappers read exactly those argument registers -- so the
 * substituted call is handed a three register object instead of a whole
 * pt_regs. The full struct made the compiler zero 312 bytes on every hooked
 * call (a memset call, not three stores), and it pushed the frame over the size
 * that turns the stack canary on. The copy stays unconditional, so a hidden uid
 * and a uid that does not exist still execute the same instruction stream.
 */
struct uidfake_args {
	u64 regs[3];
};

/*
 * The original syscall is reached through a pointer this module stored, and a
 * pre-kCFI kernel checks such calls against the callee's jump table; the functions
 * that make them are marked __nocfi, as KernelSU's dispatcher is.
 */
static asmlinkage long __nocfi uid_hook(const struct pt_regs *regs,
					unsigned int which_user,
					uidfake_syscall_t orig)
{
	struct uidfake_args args;
	u64 who;
	u32 repl;

	args.regs[0] = regs->regs[0];
	args.regs[1] = regs->regs[1];
	args.regs[2] = regs->regs[2];
	if ((u32)regs->regs[0] != which_user)
		return orig(regs);

	/*
	 * The argument is read and the replacement is selected unconditionally: the same
	 * instructions either way, so there is no branch for a predictor to learn and no
	 * difference between a target that is hidden and one that does not exist.
	 */
	who = regs->regs[ARG_WHO];
	repl = policy_query((u32)who);
	args.regs[ARG_WHO] = uf_select((u64)repl, who, repl);
	return orig((const struct pt_regs *)&args);
}

asmlinkage long uidfake_getpriority(const struct pt_regs *regs)
{
	return uid_hook(regs, PRIO_USER, g_hook[0].orig);
}

asmlinkage long uidfake_setpriority(const struct pt_regs *regs)
{
	return uid_hook(regs, PRIO_USER, g_hook[1].orig);
}

asmlinkage long uidfake_ioprio_get(const struct pt_regs *regs)
{
	return uid_hook(regs, IOPRIO_WHO_USER, g_hook[2].orig);
}

asmlinkage long uidfake_ioprio_set(const struct pt_regs *regs)
{
	return uid_hook(regs, IOPRIO_WHO_USER, g_hook[3].orig);
}

#ifdef CONFIG_COMPAT
asmlinkage long uidfake32_getpriority(const struct pt_regs *regs)
{
	return uid_hook(regs, PRIO_USER, g_chook[0].orig);
}

asmlinkage long uidfake32_setpriority(const struct pt_regs *regs)
{
	return uid_hook(regs, PRIO_USER, g_chook[1].orig);
}

asmlinkage long uidfake32_ioprio_get(const struct pt_regs *regs)
{
	return uid_hook(regs, IOPRIO_WHO_USER, g_chook[2].orig);
}

asmlinkage long uidfake32_ioprio_set(const struct pt_regs *regs)
{
	return uid_hook(regs, IOPRIO_WHO_USER, g_chook[3].orig);
}
#endif

/* the fallback: the id setters, only installed when the LSM hook cannot be taken */
static asmlinkage long uid_change_hook(const struct pt_regs *regs,
				       uidfake_syscall_t orig)
{
	const u32 before = (u32)__kuid_val(current_fsuid());
	const bool interesting = before == 0 ||
				 (before % 100000u) >= UF_APP_MIN;
	long ret;

	if (interesting && uidfake_tag_isset())
		return orig(regs);

	ret = orig(regs);
	if (ret == 0 && interesting) {
		const u32 after = (u32)__kuid_val(current_fsuid());

		if ((after % 100000u) >= UF_APP_MIN) {
			uidfake_tag_adopt(before, after);
			uidfake_tag_note(0, 0, before, after);
		}
	}
	return ret;
}

asmlinkage long uidfake_setuid(const struct pt_regs *regs)
{
	return uid_change_hook(regs, g_set[0].orig);
}

asmlinkage long uidfake_setreuid(const struct pt_regs *regs)
{
	return uid_change_hook(regs, g_set[1].orig);
}

asmlinkage long uidfake_setresuid(const struct pt_regs *regs)
{
	return uid_change_hook(regs, g_set[2].orig);
}

asmlinkage long uidfake_setgid(const struct pt_regs *regs)
{
	return uid_change_hook(regs, g_set[3].orig);
}

asmlinkage long uidfake_setregid(const struct pt_regs *regs)
{
	return uid_change_hook(regs, g_set[4].orig);
}

asmlinkage long uidfake_setresgid(const struct pt_regs *regs)
{
	return uid_change_hook(regs, g_set[5].orig);
}

#ifdef CONFIG_COMPAT
asmlinkage long uidfake32_setuid(const struct pt_regs *regs)
{
	return uid_change_hook(regs, g_cset[0].orig);
}

asmlinkage long uidfake32_setreuid(const struct pt_regs *regs)
{
	return uid_change_hook(regs, g_cset[1].orig);
}

asmlinkage long uidfake32_setresuid(const struct pt_regs *regs)
{
	return uid_change_hook(regs, g_cset[2].orig);
}

asmlinkage long uidfake32_setgid(const struct pt_regs *regs)
{
	return uid_change_hook(regs, g_cset[3].orig);
}

asmlinkage long uidfake32_setregid(const struct pt_regs *regs)
{
	return uid_change_hook(regs, g_cset[4].orig);
}

asmlinkage long uidfake32_setresgid(const struct pt_regs *regs)
{
	return uid_change_hook(regs, g_cset[5].orig);
}
#endif

/* ---- naming an isolated child from the apk it opens ---- */

static bool uidfake_tag_pending(void)
{
	return (READ_ONCE(task_thread_info(current)->flags) & UF_TAG_PENDING) !=
	       0;
}

/*
 * The identity belongs to the process, not to the thread that happened to open
 * the apk: every thread carries its own thread_info, and a sibling thread is
 * exactly where a later query comes from. Threads created afterwards inherit
 * the tag from whoever created them.
 */
static noinline void uidfake_tag_group(u32 tag)
{
	struct task_struct *t;

	rcu_read_lock();
	for_each_thread(current, t) {
		const unsigned long flags =
			READ_ONCE(task_thread_info(t)->flags);
		const unsigned long next =
			(flags &
			 ~((UF_TAG_MASK << UF_TAG_SHIFT) | UF_TAG_PENDING)) |
			((unsigned long)tag << UF_TAG_SHIFT);

		if (next != flags)
			WRITE_ONCE(task_thread_info(t)->flags, next);
	}
	rcu_read_unlock();
}

static noinline void uidfake_tag_verify(u32 tag)
{
	if (!uidfake_tag_pending())
		return;
	uidfake_tag_group(tag);
	pr_info("uidfake: iso uid %u belongs to app %u, from the apk it opened\n",
		(u32)__kuid_val(current_fsuid()), (u32)tag - 1u + UF_APP_MIN);
}

/*
 * The name a waiting isolated child gets from the base.apk it opens. The write
 * is the one the syscall path used; nothing here is reachable by user code,
 * because only a task the framework is still setting up is pending.
 */
void uidfake_tag_name(u32 app)
{
	uidfake_tag_verify(app + 1u);
}

/*
 * The window is over and no apk named this one: it is an app without rules and
 * it answers as one. Saying so once is enough -- this is a normal outcome, not
 * a failure.
 */
/*
 * Take the mark off, and only the mark: the tag field is not touched. A name set
 * while this was in flight is the answer this close was racing, and taking it away
 * would leave the process answering as one with no rules at all -- which is the exact
 * failure this path exists to be the end of.
 */
static noinline void uidfake_tag_unmark(void)
{
	struct task_struct *t;

	rcu_read_lock();
	for_each_thread(current, t) {
		unsigned long *p = (unsigned long *)&task_thread_info(t)->flags;
		unsigned long old;

		do {
			old = READ_ONCE(*p);
			if ((old & UF_TAG_PENDING) == 0)
				break;
		} while (cmpxchg(p, old, old & ~UF_TAG_PENDING) != old);
	}
	rcu_read_unlock();
}

noinline void uidfake_tag_close(void)
{
	static unsigned int logged;

	uidfake_tag_unmark();
	if (logged < 4 && UF_DEBUG_ON()) {
		logged++;
		pr_info("uidfake: iso uid %u reached its own code, no rule names it\n",
			(u32)__kuid_val(current_fsuid()));
	}
}

/*
 * The app's code directory is what the helper registers, so an open of anything
 * inside it -- the apk, a vdex, an odex, a library -- names the app as soon as
 * the directory is reached. The walk is one or two levels (the same for every
 * artifact) and only runs while a child is still unnamed. Nothing that may or
 * may not exist has to be listed, and the first file of the app's own code that
 * is opened ends the wait either way: a hit names the app, no hit means it has
 * no rules.
 */
#define UF_DIR_DEPTH 4

/* ---- table patching ---- */

static uidfake_syscall_t *main_table;
/* The LSM hook could not be taken, so the syscall setters stand in for it. */
static bool g_lsm_failed;
static int g_lsm_err;
#ifdef CONFIG_COMPAT
static uidfake_syscall_t *compat_table;
#endif

/*
 * The slot that holds the wrapper this entry is for, or NULL. The number is
 * tried first, and the table is searched for the wrapper when that does not
 * match it. Both spellings are accepted, because a pre-kCFI kernel puts the
 * jump-table address of a function in its table.
 */
#define UF_TABLE_SCAN \
	512 /* the largest arm64 table, 64-bit or 32-bit, is ~450 */

static uidfake_syscall_t *find_slot(uidfake_syscall_t *table,
				    struct hook_entry *e)
{
	/* uidfake_lookup() gives the spelling a table holds -- the jump-table entry
	 * before 6.1 and the plain symbol from there on, which is the rule KernelSU
	 * resolves a functable hook with; the other spelling is accepted too. */
	/*
	 * Every way the same syscall can be named in a table: the 64-bit
	 * implementation, the entry's own symbol in both spellings, and the compat
	 * wrapper under both of its names in both spellings. KernelSU and its forks
	 * do not cover 32-bit callers at all -- they return early for a compat task
	 * and never touch compat_sys_call_table -- so there is no method to follow
	 * here; what is left is to accept everything a kernel might have put there
	 * and patch the one that is actually in the table.
	 */
	unsigned long want[8];
	unsigned int nwant = 0, i;
	bool found = false;

	if (e->native >= 0 && g_hook[e->native].orig) {
		/* the implementation the 64-bit table had for this syscall: what some
		 * kernels put in the 32-bit table as well */
		want[nwant++] = (unsigned long)g_hook[e->native].orig;
	}
	if (e->ally && e->ally->orig) {
		/* a fallback entry: the implementation the 64-bit table holds for the
		 * same syscall, which some kernels put in the 32-bit table as well */
		want[nwant++] = (unsigned long)e->ally->orig;
	}
	if (e->sym) {
		want[nwant++] = uidfake_lookup(e->sym);
		want[nwant++] = uidfake_lookup_raw(e->sym);
	}
	if (e->sym32) {
		/* or the compat wrapper of its own, on kernels that have one: the
		 * jump-table spelling first, the plain symbol after it. Some trees name
		 * it compat_sys_<name> rather than __arm64_compat_sys_<name>, so that
		 * spelling is added as well when the name carries the prefix. */
		const char *pfx = strstr(e->sym32, "__arm64_");
		const char *alt = pfx ? pfx + strlen("__arm64_") : NULL;

		want[nwant++] = uidfake_lookup(e->sym32);
		want[nwant++] = uidfake_lookup_raw(e->sym32);
		if (alt) {
			want[nwant++] = uidfake_lookup(alt);
			want[nwant++] = uidfake_lookup_raw(alt);
		}
	}
	for (i = 0; i < nwant; i++)
		if (want[i])
			found = true;
	if (!found)
		return NULL;

	/* the number is only the first guess, and only when it agrees */
	if (e->nr < UF_TABLE_SCAN) {
		for (i = 0; i < nwant; i++) {
			if (want[i] &&
			    table[e->nr] == (uidfake_syscall_t)want[i])
				return &table[e->nr];
		}
	}

	for (i = 0; i < UF_TABLE_SCAN; i++) {
		unsigned int k;

		for (k = 0; k < nwant; k++) {
			if (want[k] && table[i] == (uidfake_syscall_t)want[k]) {
				e->nr = i;
				return &table[i];
			}
		}
	}
	return NULL;
}

static unsigned int patch_entries(uidfake_syscall_t *table,
				  struct hook_entry *e, unsigned int n,
				  bool required)
{
	unsigned int i, done = 0;

	for (i = 0; i < n; i++) {
		uidfake_syscall_t *slot = find_slot(table, &e[i]);
		uidfake_syscall_t orig;

		if (!slot) {
			pr_warn("uidfake: no slot held for %s; not hooked\n",
				e[i].sym ? e[i].sym : "a 32-bit entry");
			e[i].orig = NULL;
			if (required) {
				uidfake_status_note(-ENOENT);
				return done;
			}
			continue;
		}
		done++;
		orig = slot[0];
		if (uidfake_patch_text(slot, &e[i].ours,
				       sizeof(uidfake_syscall_t), true) ||
		    slot[0] != e[i].ours) {
			pr_warn("uidfake: patching syscall %u failed\n",
				e[i].nr);
			e[i].orig = NULL;
			uidfake_status_note(-EIO);
			return required ? i : done - 1;
		}
		e[i].orig = orig;
	}
	return done;
}

static void unpatch_entries(uidfake_syscall_t *table, struct hook_entry *e,
			    unsigned int n)
{
	unsigned int i;

	if (!table)
		return;
	for (i = 0; i < n; i++) {
		/*
		 * Only when the entry is still this module's, and only the value that
		 * was there when it was taken. Another patcher may have replaced it
		 * since -- its hook is the live one then, and undoing it here would
		 * silently remove work that is not ours; and what was saved may be an
		 * address inside a module that has already gone, which is a call to
		 * nothing once it is written back.
		 */
		if (!e[i].orig) {
			continue;
		} else if (table[e[i].nr] != e[i].ours) {
			pr_warn("uidfake: syscall %u is no longer ours; leaving it alone\n",
				e[i].nr);
		} else {
			uidfake_patch_text(&table[e[i].nr],
					   (const void *)&e[i].orig,
					   sizeof(uidfake_syscall_t), true);
		}
		e[i].orig = NULL;
	}
}

static int patch_tables(void)
{
	unsigned long table = uidfake_lookup("sys_call_table");
	unsigned int n;

	if (!table)
		return -ENOENT;
	/* Real addresses go behind the debug key: dmesg is readable on plenty of devices. */
	if (UF_DEBUG_ON())
		pr_info("uidfake: sys_call_table=%px locator check: find_user=%px linked=%px\n",
			(void *)table, (void *)uidfake_lookup("find_user"),
			(void *)find_user);

	g_status.native_expected = ARRAY_SIZE(g_hook);
#ifdef CONFIG_COMPAT
	g_status.compat_expected = ARRAY_SIZE(g_chook);
#endif

	main_table = (uidfake_syscall_t *)table;
	n = patch_entries(main_table, g_hook, ARRAY_SIZE(g_hook), true);
	if (n != ARRAY_SIZE(g_hook)) {
		unpatch_entries(main_table, g_hook, n);
		return -EIO;
	}
	pr_info("uidfake: %u uid syscall(s) hooked in sys_call_table\n", n);
	uidfake_status_set_hooks(n, 0);
	/*
   * Off by default: the probe exercises the sid->context call, and if the call
   * shape were ever
   */

#ifdef CONFIG_COMPAT
	table = uidfake_lookup("compat_sys_call_table");
	if (table) {
		compat_table = (uidfake_syscall_t *)table;
		n = patch_entries(compat_table, g_chook, ARRAY_SIZE(g_chook),
				  false);
		if (n != ARRAY_SIZE(g_chook))
			pr_warn("uidfake: %u of %u 32-bit entr(ies) hooked; the rest are not in this kernel's 32-bit table\n",
				n, (unsigned)ARRAY_SIZE(g_chook));
		pr_info("uidfake: %u uid syscall(s) hooked in compat_sys_call_table\n",
			n);
		uidfake_status_set_hooks(g_status.native, n);
	}
#endif

	if (g_lsm_failed) {
		unsigned int set_done, cset_done = 0;

		set_done = patch_entries(main_table, g_set, ARRAY_SIZE(g_set),
					 true);
		if (set_done != ARRAY_SIZE(g_set)) {
			unpatch_entries(main_table, g_set, set_done);
			pr_err("uidfake: could not hook the id setters either; identity changes are NOT watched\n");
			return -EIO;
		}
		pr_warn("uidfake: LSM hook unavailable (%d); id changes are watched in the syscall tables\n",
			g_lsm_err);
#ifdef CONFIG_COMPAT
		if (compat_table) {
			cset_done = patch_entries(compat_table, g_cset,
						  ARRAY_SIZE(g_cset), false);
			pr_info("uidfake: %u of %u 32-bit id setter(s) hooked\n",
				cset_done, (unsigned)ARRAY_SIZE(g_cset));
		}
#endif
		/* the counts a user reads are what is hooked: ten of ten here */
		g_status.native_expected += ARRAY_SIZE(g_set);
#ifdef CONFIG_COMPAT
		if (compat_table)
			g_status.compat_expected += ARRAY_SIZE(g_cset);
#endif
		uidfake_status_set_hooks(g_status.native + set_done,
					 g_status.compat + cset_done);
		uidfake_status_set_lsm(KAUX_LSM_FALLBACK, g_lsm_err,
				       "syscall setters");
	}
	return 0;
}

int hooks_install(void)
{
	if (uidfake_patch_init())
		return 0;

	/*
	 * Where the kernel hands both creds over at the commit, that hook is what the
	 * id setters used to be. Taken before the tables are patched, so a hook that
	 * cannot be taken is known before anything else is installed.
	 */
	/*
	 * The change of identity is watched where the kernel commits it, and there is
	 * no second mechanism behind this one: a kernel where the hook cannot be taken
	 * gets a module that hides callers but never learns about new ones, and says
	 * so loudly, instead of quietly hooking the syscalls the id setters use.
	 */
	{
		const int lsm = uidfake_lsm_install();

		if (lsm) {
			pr_warn("uidfake: setuid hook not taken (%d); falling back to the syscall setters\n",
				lsm);
			g_lsm_err = lsm;
			g_lsm_failed = true;
		} else {
			pr_info("uidfake: id changes are watched at the commit\n");
		}
	}

	if (!patch_tables()) {
		/*
     * The vendor hook covers every open path, not just openat, and keeps
     * sys_call_table down to the uid syscalls.
     */
		uidfake_tag_prime(); /* give the processes that already run their tag */
		return 1;
	}

	pr_warn("uidfake: could not hook sys_call_table, no hook installed\n");
	return 0;
}

void hooks_remove(void)
{
	/* The apk inodes are ours whatever the table did: put them back first. */
	uidfake_apk_remove();

	/* nothing was patched means nothing to tear down: there is no fallback */
	if (!main_table)
		return;

	unpatch_entries(main_table, g_hook, ARRAY_SIZE(g_hook));
	if (g_lsm_failed) {
#ifdef CONFIG_COMPAT
		unpatch_entries(compat_table, g_cset, ARRAY_SIZE(g_cset));
#endif
		unpatch_entries(main_table, g_set, ARRAY_SIZE(g_set));
	}
#ifdef CONFIG_COMPAT
	unpatch_entries(compat_table, g_chook, ARRAY_SIZE(g_chook));
	compat_table = NULL;
#endif
	main_table = NULL;

	/* the identity changes stay covered until the last moment */
	uidfake_lsm_remove();
}
