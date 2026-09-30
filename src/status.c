// SPDX-License-Identifier: GPL-2.0
/*
 * status.c - what the module tells userspace about itself.
 *
 * One struct, filled in by whichever mechanism ends up in place and read out
 * over netlink (KAUX_CMD_STATUS). Fixed size with a magic, so a mismatch
 * between the two ends is a checked error and not a misread (include/kaux.h).
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
/*
 * The three a mechanism needs, since the struct itself is private to this file:
 * which one is in place, how many entries it expects to have hooked, and how
 * many it has just hooked.
 */
void uidfake_status_add_flags(unsigned int flags)
{
	g_status.flags |= flags;
}

void uidfake_status_set_hooks_expected(unsigned int native, unsigned int compat)
{
	g_status.native_expected = native;
	g_status.compat_expected = compat;
}

void uidfake_status_add_hooks(unsigned int native, unsigned int compat)
{
	g_status.native += native;
	g_status.compat += compat;
	uidfake_status_set_hooks(g_status.native, g_status.compat);
}

void uidfake_status_add_hooks_expected(unsigned int native, unsigned int compat)
{
	g_status.native_expected += native;
	g_status.compat_expected += compat;
}
