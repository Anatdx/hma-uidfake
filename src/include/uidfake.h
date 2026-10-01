/* SPDX-License-Identifier: GPL-2.0 */
/* uidfake: kernel-side uid existence guard (userspace-resolved policy). */
#ifndef UIDFAKE_H
#define UIDFAKE_H

#include <linux/jump_label.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/uidgid.h>

#define POLICY_MAX_PAIRS \
	65536 /* 23k+ pairs appeared in the field: see the host test */

/*
 * Two tables. The target table is read on every query and is indexed like the
 * kernel's own uidhash (8 bucket pointers per line), with the masks of a whole
 * line read either way; the caller table is matched by uid and its cost may
 * differ between callers. A target's mask is a bitmap over dense hider ids, so
 * a target can be hidden from any subset of the policy's callers and the caller
 * count is limited only by POLICY_MAX_CALLERS.
 */

#define POLICY_WAY 8 /* target slots per 64-byte line */
/* How many lines one target may be placed after its own. Probing across lines rather
 * than across the slots of a single line is what keeps the table small: the line count
 * then follows the number of targets instead of the worst collision on one line, which
 * is what needed 32768 lines (2 MB) for 24000 targets where 4096 (256 KB) do. */
#define POLICY_PROBE_MAX 4
#define POLICY_CLINE_WAY 8 /* caller slots per 64-byte line */
#define POLICY_MIN_LINES 16
#define POLICY_MAX_LINES \
	32768 /* 8 slots a line, so this covers ~260k targets */
#define POLICY_MAX_CALLERS 4096
#define POLICY_REPL_BITS 12
/*
 * The first uid a hidden target may be replaced with. Two properties matter, and the
 * second is about what a caller can measure: the value has to hash into the same
 * uidhash bucket as the target, so the syscalls that go through find_user() walk the
 * chain they would for the target itself, and it has to be a value the kernel rejects
 * as cheaply as any ordinary uid that does not exist. The window is low for the second
 * one: on a device, getpriority(PRIO_USER, x) costs about 10 ns more to answer for
 * x = 0x40000000 than for x = 10500, and that difference is exactly the timing signal
 * between "hidden" and "no such uid" that uidbench measures. 20001..24096 (the window
 * is POLICY_REPL_MAX wide) is not inside any uid range Android hands out -- apps are
 * 10000..19999 per user, isolated children 90000..98999 -- and make_replace() still
 * refuses any candidate find_user() says exists.
 */
#define POLICY_REPL_BASE 20001u
#define POLICY_REPL_MAX (1u << POLICY_REPL_BITS)
#define POLICY_ID_NONE 0xffffffffu
#define POLICY_APP_ID_MIN 10000u /* app uids: 10000 + appid + user * 100000 */
#define POLICY_APP_ID_SPAN 10000u
#define POLICY_WILD_FLAG (1u << 15) /* slot flag: "hide from any caller" */

/*
 * The uid hash is not hardcoded here on purpose: policy.c reads the formula the
 * running kernel actually uses back from find_user() at policy-apply time.
 */

struct uid_pair { /* 8 bytes: POLICY_WAY of them fill one cache line */
	u32 target;
	u16 repl_k;
	/* Which of the interned caller masks this slot uses. The same set of callers
	 * hides target after target, so the mask a slot needs is shared rather than
	 * stored per slot; zero is the empty mask. */
	u16 mask_id;
};

void policy_apply(const u32 *pairs, u32 npairs);

/*
 * Diagnostics sit behind a static key: when it is off the branch is patched to
 * a NOP, so a release build carries none of it. The module parameter turns it
 * on at load and the work item below turns it off again, so a diagnostic run
 * pays for itself only while it is running.
 */
extern struct static_key_false uidfake_debug_key;
#define UF_DEBUG_ON() static_branch_unlikely(&uidfake_debug_key)
void uidfake_debug_init(bool on);
/* 0 = not hidden; otherwise the same-bucket replacement uid */
/* Explicit identity: the self-check in policy_apply() and the host test. */
u32 policy_lookup_as(uid_t caller, uid_t target);

/*
 * Identity tag: the app id a process was born with, kept in the free high bits
 * of thread_info.flags (bits 40..55, zero = untagged). It is written at the two
 * moments an identity is created - zygote handing an app uid to a fresh
 * process, and app_zygote handing an isolated uid to one - and never rewritten
 * or cleared afterwards, while fork copies it, so an isolated or app_zygote
 * child keeps answering as the app it came from. That is what makes the caller
 * identity unforgeable: setuid() can no longer pick which hiding rules apply.
 * Only the app id is stored, because the policy is keyed by app id anyway.
 */
/*
 * The name a task carries sits in bits 40..53: an app id is below 10000, so
 * fourteen bits hold one plus its offset. The window bit is above that field,
 * not inside it -- a tag with the top bit set would read back as "still
 * waiting" and the task would be renamed on every file it opened.
 */
#define UF_TAG_SHIFT 40
#define UF_TAG_MASK 0x3fffUL
#define UF_APP_MIN POLICY_APP_ID_MIN
#define UF_APP_SPAN POLICY_APP_ID_SPAN
#define UF_ISOLATED_START \
	90000u /* KernelSU: app_zygote children are 90000-98999 too */

/*
 * Isolated children are marked before they can be named: the flag sits above
 * the identity inside the same field so the hot path tests it with a single
 * AND, without shifting the field out first (an app id plus one never reaches
 * bit 55).
 */
#define UF_TAG_PENDING (1UL << 55)

#define UF_APK_MAX \
	10000 /* app apks whose open is replaced. Android allows 10000 app ids per \
	      * user; real devices stay well under this. */

u32 uidfake_tag_app(void); /* app id + 1, or 0 when untagged */

/* The name a waiting child gets from the apk it opened, and the end of its window. */
void uidfake_tag_name(u32 app);
void uidfake_tag_close(void);
bool uidfake_tag_pending_here(void);

/*
 * The gate the hooks ask: does @target get hidden from whoever is calling? 0 when
 * it does not, or when the caller is not an app with rules of its own.
 */
struct pt_regs;

typedef long (*uidfake_syscall_t)(const struct pt_regs *);

u32 policy_query(uid_t target);

/* The status the mechanisms fill in (status.c). */
void uidfake_status_add_flags(unsigned int flags);
void uidfake_status_set_hooks_expected(unsigned int native,
				       unsigned int compat);
void uidfake_status_add_hooks(unsigned int native, unsigned int compat);
void uidfake_status_add_hooks_expected(unsigned int native,
				       unsigned int compat);

/* The first bytes of a symbol about to be copied, when the debug key is on. */
void uidfake_debug_dump(const char *name, unsigned long addr,
			unsigned long size);

static __always_inline u64 uf_select(u64 when_true, u64 when_false, u32 nonzero)
{
#if defined(__aarch64__)
	u64 out;

	asm("cmp\t%w3, #0\n\tcsel\t%0, %1, %2, ne"
	    : "=r"(out)
	    : "r"(when_true), "r"(when_false), "r"(nonzero)
	    : "cc");
	return out;
#else
	/* The host test and the userspace model compile this file too. A real branch is fine
	 * there: nothing is timed, and x86 is not the target. */
	return nonzero ? when_true : when_false;
#endif
}

int uidfake_apk_apply(const u32 *blob,
		      u32 n); /* n * (st_dev, ino_lo, ino_hi, uid) */
/*
 * blob: u32 n, then n * (action, uid, off, len), then the paths those offsets
 * point into. action 0 replaces the open of the base.apk at that path, 1 puts
 * it back, so the helper can send only what changed. A replaced inode names a
 * waiting isolated child from the app the apk belongs to.
 */
int uidfake_apk_apply(const u32 *blob, u32 len);
void uidfake_apk_remove(void); /* put every inode back (module exit) */
void uidfake_tag_adopt(u32 old_uid, u32 new_uid);
void uidfake_tag_prime(void);
bool uidfake_tag_isset(void);
void uidfake_tag_note(u32 before_sid, u32 after_sid, u32 old_uid, u32 new_uid);

/*
 * The setuid hook (see lsm.c): where the kernel hands both creds over at the
 * commit, the syscall table is not touched for the id setters at all. Returns
 * non-zero when the syscall table has to keep them.
 */
int uidfake_lsm_install(void);
void uidfake_lsm_remove(void);

/*
 * The status the tool reads over netlink (include/kaux.h). hooks.c owns it,
 * lsm.c and the hook table fill it in as they go.
 */
struct kaux_status;
void uidfake_status_get(struct kaux_status *out);
void uidfake_status_set_hooks(unsigned int native, unsigned int compat);
void uidfake_status_set_lsm(int state, int error, const char *target);
void uidfake_status_set_apks(unsigned int inodes, unsigned int expected,
			     unsigned int failed);
void uidfake_status_note(int error);

int policy_init(void);
void policy_free(void);

int hooks_install(void);
void hooks_remove(void);

/* Bulk writes for unpublished clones and legacy data slots, not live entry
 * instructions. A failed bulk write can have changed a prefix. */
int uidfake_patch_text(void *dst, const void *src, size_t len, bool sync);
/* Compare and publish one aligned kernel instruction while CPUs are stopped.
 * A nonzero return means this operation did not change the instruction. */
int uidfake_patch_insn(void *dst, u32 expected, u32 replacement);
bool uidfake_inline_active(void);

/* Read kernel text through the nofault copy, for diagnostics only. */
bool uidfake_read(const void *src, void *dst, size_t len);
int uidfake_patch_init(void);
unsigned long uidfake_lookup(const char *name);

/*
 * A symbol's address and its extent: the following symbol bounds it, which is
 * what copying a whole function needs to know.
 */
bool uidfake_symbol_range(const char *name, unsigned long *addr,
			  unsigned long *size);

/*
 * The address just past that symbol: the end of its body in kallsyms, which is
 * what a scan for a call site inside it has to stay within. Zero when the symbol
 * or its follower is unknown.
 */
unsigned long uidfake_lookup_raw(const char *name);

/*
 * aarch64 branch helpers, kept inline so the host test can check the encoder: a
 * direct branch is 26 bits of word offset, i.e. +/-128 MB, which is exactly the
 * reach that decides whether a module can call into the kernel image.
 */
#define ARM64_B 0x14000000u
#define ARM64_BL 0x94000000u

static inline bool arm64_is_bl(u32 insn)
{
	return (insn & 0xFC000000u) == ARM64_BL;
}

static inline u32 arm64_branch(u32 op, unsigned long from, unsigned long to)
{
	long off = (long)(to - from);

	if ((off & 3) || off < -(1L << 27) || off >= (1L << 27))
		return 0;
	return op | (((u32)(off >> 2)) & 0x03FFFFFFu);
}

static inline unsigned long arm64_bl_target(unsigned long pc, u32 insn)
{
	long off = (long)(insn & 0x03FFFFFFu) << 2;

	return (unsigned long)((long)pc + ((off ^ (1L << 27)) - (1L << 27)));
}

int netlink_init(void);
void netlink_exit(void);

#endif /* UIDFAKE_H */
