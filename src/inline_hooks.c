// SPDX-License-Identifier: GPL-2.0
/*
 * inline_hooks.c - the two mechanisms that answer by running a copy of a kernel
 * function.
 *
 * One copy of find_user answers all four uid queries, and one copy of
 * cap_task_fix_setuid sees every identity change where the kernel commits it.
 * Both are built at load time by inline.c (whole function, relocated) and
 * entered through a twelve byte patch at the function's own entry, so the live
 * copy is what runs and the tables are not touched at all.
 *
 * These are the mechanisms that are tried first, for both families: they depend
 * on nothing but the symbol being where the kernel says it is.
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
#include "inline.h"
#include "tier.h"

extern struct user_struct *uf_find_user_stub(kuid_t uid);
struct user_struct *
uf_find_user_hook(kuid_t uid); /* the asm above calls this */

/*
 * The copy and the stub both live in one section that is executable and not
 * writable. It is written in asm for that reason: a C array put under a .text
 * name gets data flags from the compiler and ends up W+X, which a kernel with
 * STRICT_MODULE_RWX refuses to load (it did, on the first try).
 */
/* Declared here and defined with the setuid hook below: the debug dump is
 * shared by both hooks. */
#define UF_FIND_USER_COPY_SIZE 512u
extern u8 g_find_user_copy[]; /* defined in the asm below */
static unsigned long g_find_user_addr;
static u8 g_find_user_saved[UF_INLINE_ENTRY];
static bool g_find_user_hooked;

/* The stub the entry patch jumps to. bti jc because that jump is indirect. */
asm(".pushsection \".text.uf_inline\",\"ax\"\n"
    ".balign 16\n"
    ".global g_find_user_copy\n"
    ".type g_find_user_copy, %object\n"
    "g_find_user_copy:\n"
    "\t.space 512, 0\n"
    ".size g_find_user_copy, . - g_find_user_copy\n"
    ".balign 4\n"
    ".global uf_find_user_stub\n"
    ".type uf_find_user_stub, %function\n"
    "uf_find_user_stub:\n"
    "\tbti jc\n"
    "\tb uf_find_user_hook\n"
    ".size uf_find_user_stub, . - uf_find_user_stub\n"
    ".popsection\n");

/*
 * Runs exactly where find_user would have run, with the same arguments and the
 * same stack. The real answer is always computed first, so an answer that is
 * about to be hidden costs what an answer that names a uid with no processes
 * costs; only the result is dropped.
 */
noinline struct user_struct *uf_find_user_hook(kuid_t uid)
{
	struct user_struct *real =
		((struct user_struct * (*)(kuid_t)) g_find_user_copy)(uid);

	if (real == NULL)
		return NULL;

	/* Two things decide: the caller has to be an app with rules of its own, and
	 * the uid asked about has to be one those rules hide. policy_query answers
	 * both - it is the same gate the syscall wrappers use. */
	if (policy_query((u32)__kuid_val(uid)) == 0)
		return real;

	/* A hidden uid answers like one that has no processes: the reference the
	 * copy took is given back here, where the kernel would have given it back. */
	free_uid(real);
	return NULL;
}

static int find_user_hook_install(void)
{
	static u8 scratch[UF_FIND_USER_COPY_SIZE];
	u32 patch[UF_INLINE_ENTRY / 4];
	unsigned long size = 0, written = 0;
	int rc;

	if (g_find_user_hooked)
		return 0;
	if (!uidfake_symbol_range("find_user", &g_find_user_addr, &size)) {
		pr_warn("uidfake: find_user is not in this kernel's symbols\n");
		uidfake_status_note(-ENOENT);
		return -ENOENT;
	}
	if (size == 0 || size > sizeof(scratch)) {
		pr_warn("uidfake: find_user is %lu bytes, past the copy\n",
			size);
		uidfake_status_note(-E2BIG);
		return -E2BIG;
	}
	uidfake_debug_dump("find_user", g_find_user_addr, size);

	rc = uf_inline_relocate(scratch, sizeof(scratch),
				(const void *)g_find_user_addr,
				g_find_user_addr,
				(unsigned long)g_find_user_copy, size,
				&written);
	if (rc != UF_INLINE_OK) {
		pr_warn("uidfake: cannot copy find_user (%d); its code is not one this handles\n",
			rc);
		uidfake_status_note(rc);
		return rc;
	}

	/* The copy and the stub live in this module's text, which is read-only: both
	 * are written through the same alias path the kernel image uses. */
	rc = uidfake_patch_text(g_find_user_copy, scratch, written, true);
	if (rc != 0) {
		pr_warn("uidfake: cannot place the find_user copy (%d)\n", rc);
		uidfake_status_note(rc);
		return rc;
	}

	rc = uf_inline_entry(patch, sizeof(patch), g_find_user_addr,
			     (unsigned long)uf_find_user_stub);
	if (rc != (int)UF_INLINE_ENTRY) {
		pr_warn("uidfake: the jump to the hook does not fit (%d)\n",
			rc);
		uidfake_status_note(rc);
		return rc;
	}

	memcpy(g_find_user_saved, (const void *)g_find_user_addr,
	       UF_INLINE_ENTRY);
	rc = uidfake_patch_text((void *)g_find_user_addr, patch,
				UF_INLINE_ENTRY, true);
	if (rc != 0 || memcmp((const void *)g_find_user_addr, patch,
			      UF_INLINE_ENTRY) != 0) {
		pr_warn("uidfake: the entry patch did not take (%d)\n", rc);
		uidfake_patch_text((void *)g_find_user_addr, g_find_user_saved,
				   UF_INLINE_ENTRY, true);
		uidfake_status_note(-EIO);
		return -EIO;
	}

	g_find_user_hooked = true;
	pr_info("uidfake: uid queries are answered from a copy of find_user (%lu bytes copied)\n",
		written);
	return 0;
}
static void find_user_hook_remove(void)
{
	if (!g_find_user_hooked)
		return;
	if (uidfake_patch_text((void *)g_find_user_addr, g_find_user_saved,
			       UF_INLINE_ENTRY, true) == 0 &&
	    memcmp((const void *)g_find_user_addr, g_find_user_saved,
		   UF_INLINE_ENTRY) == 0)
		g_find_user_hooked = false;
	else
		pr_warn("uidfake: could not put find_user back\n");
}
extern int uf_setuid_stub(struct cred *new, const struct cred *old, int flags);
int uf_setuid_inline_hook(struct cred *new, const struct cred *old, int flags);

#define UF_SETUID_COPY_SIZE 512u
extern u8 g_setuid_copy[]; /* defined in the asm below */
static unsigned long g_setuid_addr;
static const char *g_setuid_name;
static u8 g_setuid_saved[UF_INLINE_ENTRY];
static bool g_setuid_hooked;

/* The same section and the same reason as the find_user copy above: one ax
 * section holds both copies and both stubs. */
asm(".pushsection \".text.uf_inline\",\"ax\"\n"
    ".balign 16\n"
    ".global g_setuid_copy\n"
    ".type g_setuid_copy, %object\n"
    "g_setuid_copy:\n"
    "\t.space 512, 0\n"
    ".size g_setuid_copy, . - g_setuid_copy\n"
    ".balign 4\n"
    ".global uf_setuid_stub\n"
    ".type uf_setuid_stub, %function\n"
    "uf_setuid_stub:\n"
    "\tbti jc\n"
    "\tb uf_setuid_inline_hook\n"
    ".size uf_setuid_stub, . - uf_setuid_stub\n"
    ".popsection\n");

typedef int (*uf_setid_fn)(struct cred *new, const struct cred *old, int flags);

/*
 * The call into the copy comes from a function that may itself be reached
 * through an indirect call, and the copy is in no jump table, so on a kernel
 * with CFI this is marked the way KernelSU marks its dispatcher.
 */
static noinline int __nocfi uf_setuid_orig(struct cred *new,
					   const struct cred *old, int flags)
{
	return ((uf_setid_fn)g_setuid_copy)(new, old, flags);
}

/*
 * Runs where cap_task_fix_setuid would have run, with the same arguments and the
 * same stack. The bookkeeping is the same code the LSM hook runs: a task that is
 * named already is left alone, because its name came from the one transition
 * that gave it its identity, and only a change that lands on an app uid says
 * anything.
 */
noinline int uf_setuid_inline_hook(struct cred *new, const struct cred *old,
				   int flags)
{
	const u32 before = (u32)__kuid_val(old->fsuid);
	const u32 after = (u32)__kuid_val(new->fsuid);
	const bool interesting = before == 0 ||
				 (before % 100000u) >= UF_APP_MIN;
	int ret;

	if (uidfake_tag_isset())
		return uf_setuid_orig(new, old, flags);

	ret = uf_setuid_orig(new, old, flags);
	if (ret == 0 && interesting && (after % 100000u) >= UF_APP_MIN) {
		uidfake_tag_adopt(before, after);
		uidfake_tag_note(0, 0, before, after);
	}
	return ret;
}

/*
 * Debug aid: the first bytes of a function about to be copied. Reading them
 * through the nofault copy is what makes a device's own code available for a
 * host test, and what tells a reader which encoding the last refusal was about.
 */
/*
 * The plain symbol, not the jump-table spelling: a call site reaches the
 * function directly (the static call on 6.12 and later) or through its
 * jump-table entry, and that entry branches to the plain function, so patching
 * the plain one catches both.
 */

static int setuid_inline_install(void)
{
	static const char *const names[] = {
		"cap_task_fix_setuid",
		"safesetid_task_fix_setuid",
	};
	static u8 scratch[UF_SETUID_COPY_SIZE];
	u32 patch[UF_INLINE_ENTRY / 4];
	unsigned long addr = 0, size = 0, written = 0;
	const char *name = NULL;
	unsigned int i;
	int rc;

	if (g_setuid_hooked)
		return 0;

	for (i = 0; i < ARRAY_SIZE(names); i++) {
		unsigned long a = 0, n = 0;

		if (uidfake_symbol_range(names[i], &a, &n)) {
			addr = a;
			size = n;
			name = names[i];
			break;
		}
	}
	if (addr == 0) {
		pr_warn("uidfake: neither %s nor %s is in this kernel's symbols\n",
			names[0], names[1]);
		uidfake_status_note(-ENOENT);
		return -ENOENT;
	}
	if (size == 0 || size > sizeof(scratch)) {
		pr_warn("uidfake: %s is %lu bytes, past the copy\n", name,
			size);
		uidfake_status_note(-E2BIG);
		return -E2BIG;
	}
	uidfake_debug_dump(name, addr, size);

	rc = uf_inline_relocate(scratch, sizeof(scratch), (const void *)addr,
				addr, (unsigned long)g_setuid_copy, size,
				&written);
	if (rc != UF_INLINE_OK) {
		pr_warn("uidfake: cannot copy %s (%d); its code is not one this handles\n",
			name, rc);
		uidfake_status_note(rc);
		return rc;
	}

	/* The copy is placed by the write path the kernel image uses: this module's
	 * text is mapped read-only, so the write goes through the alias. */
	rc = uidfake_patch_text(g_setuid_copy, scratch, written, true);
	if (rc != 0) {
		pr_warn("uidfake: cannot place the %s copy (%d)\n", name, rc);
		uidfake_status_note(rc);
		return rc;
	}

	rc = uf_inline_entry(patch, sizeof(patch), addr,
			     (unsigned long)uf_setuid_stub);
	if (rc != (int)UF_INLINE_ENTRY) {
		pr_warn("uidfake: the jump to the setuid hook does not fit (%d)\n",
			rc);
		uidfake_status_note(rc);
		return rc;
	}

	memcpy(g_setuid_saved, (const void *)addr, UF_INLINE_ENTRY);
	rc = uidfake_patch_text((void *)addr, patch, UF_INLINE_ENTRY, true);
	if (rc != 0 ||
	    memcmp((const void *)addr, patch, UF_INLINE_ENTRY) != 0) {
		pr_warn("uidfake: the entry patch on %s did not take (%d)\n",
			name, rc);
		uidfake_status_note(rc != 0 ? rc : -EIO);
		return rc != 0 ? rc : -EIO;
	}

	g_setuid_addr = addr;
	g_setuid_name = name;
	g_setuid_hooked = true;
	uidfake_status_set_lsm(KAUX_LSM_TAKEN, 0, "inline cap_task_fix_setuid");
	pr_info("uidfake: id changes are watched from a copy of %s (%lu bytes copied)\n",
		name, written);
	return 0;
}
static void setuid_inline_remove(void)
{
	if (!g_setuid_hooked)
		return;
	if (uidfake_patch_text((void *)g_setuid_addr, g_setuid_saved,
			       UF_INLINE_ENTRY, true) == 0 &&
	    memcmp((const void *)g_setuid_addr, g_setuid_saved,
		   UF_INLINE_ENTRY) == 0)
		g_setuid_hooked = false;
	else
		pr_warn("uidfake: could not put %s back\n",
			g_setuid_name ? g_setuid_name : "cap_task_fix_setuid");
}

/*
 * The uid mechanism on top of the copy: the copy itself installs, and what is
 * left here is what the module reports about it -- one write point, so nothing
 * is counted in the tables.
 */
static int uid_inline_install(void)
{
	const int rc = find_user_hook_install();

	if (rc == 0) {
		uidfake_status_set_hooks_expected(0, 0);
		uidfake_status_add_flags(KAUX_F_PRIO_INLINE);
	}
	return rc;
}

static void uid_inline_remove(void)
{
	find_user_hook_remove();
}

UF_TIER(uf_tier_uid_inline, UF_TIER_UID, "inline", "inline find_user", 10,
	uid_inline_install, uid_inline_remove);
UF_TIER(uf_tier_setuid_inline, UF_TIER_SETUID, "inline",
	"inline cap_task_fix_setuid", 10, setuid_inline_install,
	setuid_inline_remove);
