// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/workqueue.h>

#include "uidfake.h"

struct static_key_false uidfake_debug_key;

/* Diagnostics switch themselves off, so a run that enabled them leaves nothing
 * behind. */
static void uidfake_debug_off(struct work_struct *work);
static DECLARE_DELAYED_WORK(uidfake_debug_work, uidfake_debug_off);

/* The parameter is a one-shot: it arms the key and the work item disarms it a
 * minute later. */
#ifdef UF_DEBUG_ALWAYS
static bool uidfake_debug = true;
#else
static bool uidfake_debug;
#endif
module_param_named(debug, uidfake_debug, bool, 0644);
MODULE_PARM_DESC(debug,
		 "log the isolated-child naming for 60 seconds after load");

static void uidfake_debug_off(struct work_struct *work)
{
	(void)work;
	if (static_key_enabled(&uidfake_debug_key)) {
		static_branch_disable(&uidfake_debug_key);
		pr_info("uidfake: diagnostics off\n");
	}
}

void uidfake_debug_init(bool on)
{
	if (!on)
		return;
	static_branch_enable(&uidfake_debug_key);
#ifdef UF_DEBUG_ALWAYS
	pr_info("uidfake: diagnostics on (compiled in, they never turn off)");
	return;
#else
	pr_info("uidfake: diagnostics on for 60 s\n");
	schedule_delayed_work(&uidfake_debug_work, 60UL * HZ);
#endif
}

static int __init uidfake_init(void)
{
	if (policy_init())
		return -ENOMEM;

	uidfake_debug_init(uidfake_debug);

	netlink_init();
	/* An inline tier may pin this module and publish a kernel entry below.
	 * Module-loader failure frees even pinned modules: no error return after
	 * this point. Individual unsupported tiers report their own status. */
	pr_info("uidfake: ready (%d hook(s))\n", hooks_install());
	return 0;
}

static void __exit uidfake_exit(void)
{
	cancel_delayed_work_sync(&uidfake_debug_work);
	netlink_exit();
	hooks_remove();
	policy_free();
	pr_info("uidfake: unloaded\n");
}

module_init(uidfake_init);
module_exit(uidfake_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("local");
MODULE_DESCRIPTION(
	"uidfake - kernel-side uid existence guard (netlink-injected policy)");
