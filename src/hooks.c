// SPDX-License-Identifier: GPL-2.0
/*
 * hooks.c - the two questions, and the order the mechanisms are tried in.
 *
 * How a uid with no processes is reported, and where an identity change is seen:
 * each has a family of mechanisms that can answer it, each mechanism registers
 * itself with the order it wants (tiers.c reads the registry), and this file is
 * what starts the walk, names the winner in the log, and takes everything back
 * at unload. The mechanisms live in the files named after them:
 *
 *   inline_hooks.c   a copy of find_user / cap_task_fix_setuid
 *   table_hooks.c    the uid queries / the id setters in sys_call_table
 *   lsm.c            the LSM hook the kernel hands both creds to
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

static char *uf_uid_tier = "";
static char *uf_setuid_tier = "";
module_param_named(uid_tier, uf_uid_tier, charp, 0644);
MODULE_PARM_DESC(uid_tier,
		 "force a mechanism for the uid queries: inline, tables");
module_param_named(setuid_tier, uf_setuid_tier, charp, 0644);
MODULE_PARM_DESC(
	setuid_tier,
	"force a mechanism for the identity change: inline, lsm, setters");

int hooks_install(void)
{
	int uid, setuid;

	if (uidfake_patch_init())
		return 0;

	/*
	 * The uid queries come first: they are the question every one of those
	 * syscalls asks before it does anything, and answering it costs one copy of
	 * find_user instead of eight table entries.
	 */
	uid = uf_tier_install(UF_TIER_UID, uf_uid_tier);
	if (uid)
		pr_err("uidfake: no mechanism on this kernel can answer the uid queries\n");
	else
		pr_info("uidfake: uid queries are answered by %s\n",
			uf_tier_name(UF_TIER_UID));

	/*
	 * Then the identity changes. A kernel where nothing can watch them gets a
	 * module that hides callers but never learns about new ones, and says so
	 * loudly.
	 */
	setuid = uf_tier_install(UF_TIER_SETUID, uf_setuid_tier);
	if (setuid) {
		pr_err("uidfake: identity changes are NOT watched on this kernel\n");
		uidfake_status_set_lsm(KAUX_LSM_FAILED, -ENODEV, "");
	} else {
		pr_info("uidfake: id changes are watched by %s\n",
			uf_tier_name(UF_TIER_SETUID));
	}

	uidfake_tag_prime(); /* give the processes that already run their tag */
	return (uid == 0 || setuid == 0) ? 1 : 0;
}

void hooks_remove(void)
{
	/*
	 * The entry patches go back first: a jump left pointing into this module
	 * would be a wild branch the moment the module leaves. Then the apk inodes,
	 * which are ours whatever the tables did, and then the rest of the setuid
	 * family (the LSM slot or the setters behind it).
	 */
	uf_tier_revert(UF_TIER_UID);
	uidfake_apk_remove();
	uf_tier_revert(UF_TIER_SETUID);
}
