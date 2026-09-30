// SPDX-License-Identifier: GPL-2.0
/*
 * tag.c - the identity of a process, learned from the apk it opens.
 *
 * The first file of its own code that an isolated child opens names it (the
 * inode hook in inode_hook.c does the naming); this is the record behind that
 * name: the pending bit, the app id, and the ids the task changed between. Both
 * of the id-change mechanisms, the apk side and the query all ask it questions.
 *
 * The tag and the window bit live in the high bits of thread_info.flags, in the
 * same word as the TIF_* bits the rest of the kernel updates with set_bit() and
 * clear_bit(): so the word is moved with a compare-and-swap and only those bits
 * are touched, which is what the helpers at the top are.
 */
/*
 * On the host the test compiles this file right after policy.c, which has
 * already pulled the shims in; including them again here would double-define
 * the statics in the sched shim. So the host build includes nothing.
 */
#ifndef UIDFAKE_HOST_TEST
#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/uidgid.h>
#include <linux/user.h>
#include <linux/version.h>
#endif

#include "uidfake.h"

#define UF_TAG_CLEAR ((UF_TAG_MASK << UF_TAG_SHIFT) | UF_TAG_PENDING)
#define UF_TAG_SET(v) (((unsigned long)(v)) << UF_TAG_SHIFT)

static void uf_ti_flags_rmw(struct task_struct *t, unsigned long clear,
			    unsigned long set)
{
	unsigned long *p = (unsigned long *)&task_thread_info(t)->flags;
	unsigned long old, new;

	do {
		old = READ_ONCE(*p);
		new = (old & ~clear) | set;
		if (new == old)
			return;
	} while (cmpxchg(p, old, new) != old);
}

static bool uf_ti_mark_pending(struct task_struct *t)
{
	unsigned long *p = (unsigned long *)&task_thread_info(t)->flags;
	unsigned long old;

	do {
		old = READ_ONCE(*p);
		if (old & (UF_TAG_MASK << UF_TAG_SHIFT))
			return false;
	} while (cmpxchg(p, old, old | UF_TAG_PENDING) != old);
	return true;
}

static u32 uf_ti_tag(struct task_struct *t)
{
	return (u32)((READ_ONCE(task_thread_info(t)->flags) >> UF_TAG_SHIFT) &
		     UF_TAG_MASK);
}

void uidfake_tag_prime(void)
{
	struct task_struct *task, *thread;
	u32 primed = 0;

	rcu_read_lock();
	for_each_process(task) {
		for_each_thread(task, thread) {
			const struct cred *cred = get_task_cred(thread);
			u32 id;

			if (!cred)
				continue;
			id = (u32)__kuid_val(cred->fsuid) % 100000u;
			if (id >= UF_APP_MIN && id < UF_ISOLATED_START) {
				if (uf_ti_tag(thread) == 0) {
					uf_ti_flags_rmw(thread, UF_TAG_CLEAR,
							UF_TAG_SET(id -
								   UF_APP_MIN +
								   1u));
					primed++;
				}
			}
			put_cred(cred);
		}
	}
	rcu_read_unlock();
	pr_info("uidfake: %u task(s) primed from the running system\n", primed);
}

bool uidfake_tag_isset(void)
{
	const unsigned long flags = READ_ONCE(task_thread_info(current)->flags);

	return ((flags >> UF_TAG_SHIFT) & UF_TAG_MASK) != 0;
}

void uidfake_tag_note(u32 before_sid, u32 after_sid, u32 old_uid, u32 new_uid)
{
	(void)before_sid;
	(void)after_sid;

	if ((new_uid % 100000u) >= UF_ISOLATED_START) {
		/*
     * An isolated child. Nothing in its own state names the app it belongs to:
     * the context is shared, the supplementary groups are the pool's and its
     * parent is the zygote. It is marked here so the first file it opens can
     * name it; until one does it answers as a process with no rules of its own.
     */
		/* The mark, and nothing else: a name that arrives while this is in
		 * flight is the answer this was racing, and it is never taken away. */
		if (uf_ti_mark_pending(current))
			pr_info("uidfake: iso birth uid %u marked, awaiting the apk it opens\n",
				new_uid);
		return;
	}

	if ((old_uid % 100000u) < UF_APP_MIN &&
	    (new_uid % 100000u) >= UF_APP_MIN &&
	    (new_uid % 100000u) < UF_ISOLATED_START) {
		const u32 app = (new_uid % 100000u) - UF_APP_MIN;

		if (app < UF_APP_SPAN)
			pr_info("uidfake: app birth uid %u -> app %u\n",
				new_uid, app);
	}
}

u32 uidfake_tag_app(void)
{
	return (u32)((task_thread_info(current)->flags >> UF_TAG_SHIFT) &
		     UF_TAG_MASK);
}

void uidfake_tag_adopt(u32 old_uid, u32 new_uid)
{
	u32 app;

	/* One shot, one transition: init/zygote giving an app uid to a fresh process.
   */
	if (uf_ti_tag(current) != 0)
		return;
	/*
	 * Every comparison is on the app id inside the uid, never on the whole uid: a
	 * user id is the high part of it, so a secondary user's app (100000 + app) is
	 * past UF_ISOLATED_START as a number -- read raw, every app of that user would
	 * look like an isolated child and never be named at all, and a system uid of
	 * that user (100000 + 1000) would be tagged as an app.
	 */
	if ((old_uid % 100000u) >= UF_APP_MIN)
		return;
	if ((new_uid % 100000u) < UF_APP_MIN ||
	    (new_uid % 100000u) >= UF_ISOLATED_START)
		return;

	app = (new_uid % 100000u) - UF_APP_MIN;
	if (app >= UF_APP_SPAN)
		return;
	uf_ti_flags_rmw(current, UF_TAG_CLEAR, UF_TAG_SET(app + 1u));
}

bool uidfake_tag_pending_here(void)
{
	return (READ_ONCE(task_thread_info(current)->flags) & UF_TAG_PENDING) !=
	       0;
}

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
