// SPDX-License-Identifier: GPL-2.0
/*
 * table_hooks.c - the mechanisms that answer from a syscall table.
 *
 * Both questions can be answered by replacing entries in sys_call_table and its
 * 32-bit twin: the four uid queries (getpriority, setpriority, ioprio_get,
 * ioprio_set) and the six id setters. This is what a kernel falls back to when
 * a function cannot be copied, and it is the same work KernelSU does.
 *
 * The table plumbing lives here too, because there is one way to do it: find an
 * entry by number without trusting the table's address, and write it through the
 * kernel's own fixmap, keeping a verbatim copy of what was there so the write can
 * prove it worked and the unload can put it back.
 */
#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/uidgid.h>
#include <linux/user.h>
#include <linux/version.h>

#include "uidfake.h"
#include "kaux.h"
#include "tier.h"

#define ARG_UID 0 /* find_user(kuid_t uid): uid in x0 */
#define ARG_WHO \
	1 /* getpriority/setpriority/ioprio_get/ioprio_set: (which, who, ...) */

#define NR32_GETPRIORITY 96
#define NR32_SETPRIORITY 97
#define NR32_IOPRIO_SET 314
#define NR32_IOPRIO_GET 315

#define UF_NR32_SETUID 213
#define UF_NR32_SETGID 214
#define UF_NR32_SETREUID 203
#define UF_NR32_SETREGID 204
#define UF_NR32_SETRESUID 208
#define UF_NR32_SETRESGID 210

struct uidfake_args {
	u64 regs[3];
};
#define UF_TABLE_SCAN \
	512 /* the largest arm64 table, 64-bit or 32-bit, is ~450 */

static uidfake_syscall_t *main_table;
static uidfake_syscall_t *compat_table;

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
 * The tables themselves are defined further down, next to the hooks they point
 * at; find_slot below names them, so they are declared here. A tentative
 * definition of an array of unknown size is what lets a later one carry the
 * initialiser.
 */
static struct hook_entry g_hook[];
static struct hook_entry g_set[];
#ifdef CONFIG_COMPAT
static struct hook_entry g_chook[];
static struct hook_entry g_cset[];
#endif

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
asmlinkage long uidfake_getpriority(const struct pt_regs *regs);
asmlinkage long uidfake_setpriority(const struct pt_regs *regs);
asmlinkage long uidfake_ioprio_get(const struct pt_regs *regs);
asmlinkage long uidfake_ioprio_set(const struct pt_regs *regs);
asmlinkage long uidfake32_getpriority(const struct pt_regs *regs);
asmlinkage long uidfake32_setpriority(const struct pt_regs *regs);
asmlinkage long uidfake32_ioprio_get(const struct pt_regs *regs);
asmlinkage long uidfake32_ioprio_set(const struct pt_regs *regs);
asmlinkage long uidfake_setuid(const struct pt_regs *regs);
asmlinkage long uidfake_setreuid(const struct pt_regs *regs);
asmlinkage long uidfake_setresuid(const struct pt_regs *regs);
asmlinkage long uidfake_setgid(const struct pt_regs *regs);
asmlinkage long uidfake_setregid(const struct pt_regs *regs);
asmlinkage long uidfake_setresgid(const struct pt_regs *regs);
asmlinkage long uidfake32_setuid(const struct pt_regs *regs);
asmlinkage long uidfake32_setreuid(const struct pt_regs *regs);
asmlinkage long uidfake32_setresuid(const struct pt_regs *regs);
asmlinkage long uidfake32_setgid(const struct pt_regs *regs);
asmlinkage long uidfake32_setregid(const struct pt_regs *regs);
asmlinkage long uidfake32_setresgid(const struct pt_regs *regs);

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
#ifdef CONFIG_COMPAT
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
#endif
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
static int uid_tables_install(void)
{
	unsigned long table = uidfake_lookup("sys_call_table");
	unsigned int n, n_compat = 0;

	if (!table)
		return -ENOENT;
	/* Real addresses go behind the debug key: dmesg is readable on plenty of
	 * devices. */
	if (UF_DEBUG_ON())
		pr_info("uidfake: sys_call_table=%px locator check: find_user=%px linked=%px\n",
			(void *)table, (void *)uidfake_lookup("find_user"),
			(void *)find_user);

	uidfake_status_add_flags(KAUX_F_PRIO_TABLES);
	uidfake_status_set_hooks_expected(ARRAY_SIZE(g_hook),
#ifdef CONFIG_COMPAT
					  ARRAY_SIZE(g_chook)
#else
					  0
#endif
	);

	main_table = (uidfake_syscall_t *)table;
	n = patch_entries(main_table, g_hook, ARRAY_SIZE(g_hook), true);
	if (n != ARRAY_SIZE(g_hook)) {
		unpatch_entries(main_table, g_hook, n);
		return -EIO;
	}
	pr_info("uidfake: %u uid syscall(s) hooked in sys_call_table\n", n);
	uidfake_status_set_hooks(n, 0);

#ifdef CONFIG_COMPAT
	table = uidfake_lookup("compat_sys_call_table");
	if (table) {
		compat_table = (uidfake_syscall_t *)table;
		n_compat = patch_entries(compat_table, g_chook,
					 ARRAY_SIZE(g_chook), false);
		if (n_compat != ARRAY_SIZE(g_chook))
			n = n_compat;
		pr_warn("uidfake: %u of %u 32-bit entr(ies) hooked; the rest are not in this kernel's 32-bit table\n",
			n, (unsigned)ARRAY_SIZE(g_chook));
		pr_info("uidfake: %u uid syscall(s) hooked in compat_sys_call_table\n",
			n);
		uidfake_status_set_hooks(n, n_compat);
	}
#endif
	return 0;
}
static void uid_tables_remove(void)
{
	if (!main_table)
		return;
	unpatch_entries(main_table, g_hook, ARRAY_SIZE(g_hook));
#ifdef CONFIG_COMPAT
	if (compat_table)
		unpatch_entries(compat_table, g_chook, ARRAY_SIZE(g_chook));
#endif
}
static int setuid_tables_install(void)
{
	unsigned long table = uidfake_lookup("sys_call_table");
	unsigned int n, c = 0;

	if (!table)
		return -ENOENT;
	if (!main_table)
		main_table = (uidfake_syscall_t *)table;

	n = patch_entries(main_table, g_set, ARRAY_SIZE(g_set), true);
	if (n != ARRAY_SIZE(g_set)) {
		unpatch_entries(main_table, g_set, n);
		pr_err("uidfake: could not hook the id setters either; identity changes are NOT watched\n");
		return -EIO;
	}
	pr_warn("uidfake: id changes are watched in the syscall tables (%u setter(s))\n",
		n);

#ifdef CONFIG_COMPAT
	table = uidfake_lookup("compat_sys_call_table");
	if (table) {
		compat_table = (uidfake_syscall_t *)table;
		c = patch_entries(compat_table, g_cset, ARRAY_SIZE(g_cset),
				  false);
		pr_info("uidfake: %u of %u 32-bit id setter(s) hooked\n", c,
			(unsigned)ARRAY_SIZE(g_cset));
	}
#endif
	/* the counts a user reads are what is hooked: ten of ten here */
	uidfake_status_add_hooks_expected(ARRAY_SIZE(g_set),
#ifdef CONFIG_COMPAT
					  compat_table ? ARRAY_SIZE(g_cset) : 0
#else
					  0
#endif
	);
	uidfake_status_add_hooks(n, c);
	uidfake_status_set_lsm(KAUX_LSM_FALLBACK, 0, "syscall setters");
	return 0;
}
static void setuid_tables_remove(void)
{
	if (!main_table)
		return;
	unpatch_entries(main_table, g_set, ARRAY_SIZE(g_set));
#ifdef CONFIG_COMPAT
	if (compat_table)
		unpatch_entries(compat_table, g_cset, ARRAY_SIZE(g_cset));
#endif
}

/* The two table mechanisms in the order (tiers.c): behind the inline copies, and
 * the setters behind nothing -- watching an id change in the table is the last
 * way there is. */
UF_TIER(uf_tier_uid_tables, UF_TIER_UID, "tables", "syscall tables", 20,
	uid_tables_install, uid_tables_remove);
UF_TIER(uf_tier_setuid_setters, UF_TIER_SETUID, "setters", "syscall setters",
	30, setuid_tables_install, setuid_tables_remove);
