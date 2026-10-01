// SPDX-License-Identifier: GPL-2.0
/*
 * Runtime entry trampolines for find_user and the setuid LSM callback.
 * A single direct B publishes each hook. No syscall table entry is touched by
 * these tiers, and no kernel image profile or permanent probe is needed.
 *
 * Successful publication pins the module until reboot. Restoring an entry is
 * not enough to drain preempted module frames, especially the setuid path.
 */
#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/uidgid.h>
#include <linux/user.h>

#include "uidfake.h"
#include "kaux.h"
#include "inline.h"
#include "inline_entry.h"
#include "inline_alloc.h"
#include "tier.h"

#define UF_INLINE_STORAGE_SIZE 16
#define UF_BTI_C 0xd503245fu
#define UF_BTI_JC 0xd50324dfu
#define UF_PACIASP 0xd503233fu
#define UF_PACIBSP 0xd503237fu

/* Assembly objects have instruction alignment, not unsigned-long alignment. */
extern u32 g_find_user_copy[], g_setuid_copy[];
/* Typed function aliases at the same RX addresses: direct calls need no CFI
 * bypass or extra C bridge frame. The object aliases are only for text writes.
 */
extern struct user_struct *uf_find_user_orig(kuid_t uid);
extern int uf_setuid_orig(struct cred *new, const struct cred *old, int flags);
extern struct user_struct *uf_find_user_stub(kuid_t uid);
extern struct user_struct *uf_find_user_pacia_stub(kuid_t uid);
extern struct user_struct *uf_find_user_pacib_stub(kuid_t uid);
extern int uf_setuid_stub(struct cred *, const struct cred *, int);
extern int uf_setuid_pacia_stub(struct cred *, const struct cred *, int);
extern int uf_setuid_pacib_stub(struct cred *, const struct cred *, int);
struct user_struct *uf_find_user_hook(kuid_t uid);
int uf_setuid_inline_hook(struct cred *, const struct cred *, int);

/* RX storage avoids STRICT_MODULE_RWX rejecting writable executable arrays. */
#define UF_ASM_STUB(name, auth, hook)                                   \
	".balign 4\n.global " name "\n.type " name ", %function\n" name \
	":\n\tbti jc\n" auth "\tb " hook "\n"                           \
	".size " name ", . - " name "\n"
#define UF_ASM_COPY(name, original)                                           \
	".balign 16\n.global " name "\n.type " name ", %object\n"             \
	".global " original "\n.type " original ", %function\n" name          \
	":\n" original                                                        \
	":\n\t.space " __stringify(UF_INLINE_STORAGE_SIZE) ", 0\n"            \
							   ".size " name      \
							   ", . - " name "\n" \
							   ".size " original  \
							   ", . - " original  \
							   "\n"
asm(".pushsection \".text.uf_inline\",\"ax\"\n" UF_ASM_COPY(
	"g_find_user_copy",
	"uf_find_user_orig") UF_ASM_STUB("uf_find_user_stub", "",
					 "uf_find_user_hook")
	    UF_ASM_STUB(
		    "uf_find_user_pacia_stub", "\tautiasp\n",
		    "uf_find_user_hook") UF_ASM_STUB("uf_find_user_pacib_stub",
						     "\tautibsp\n",
						     "uf_find_user_hook")
		    UF_ASM_COPY("g_setuid_copy", "uf_setuid_orig") UF_ASM_STUB(
			    "uf_setuid_stub", "", "uf_setuid_inline_hook")
			    UF_ASM_STUB("uf_setuid_pacia_stub", "\tautiasp\n",
					"uf_setuid_inline_hook")
				    UF_ASM_STUB(
					    "uf_setuid_pacib_stub",
					    "\tautibsp\n",
					    "uf_setuid_inline_hook") ".popsection\n");

noinline struct user_struct *uf_find_user_hook(kuid_t uid)
{
	const u32 replacement = policy_query((u32)__kuid_val(uid));
	const u32 query =
		(u32)uf_select(replacement, __kuid_val(uid), replacement);
	struct user_struct *real = uf_find_user_orig(KUIDT_INIT(query));
	struct user_struct *drop =
		(struct user_struct *)(unsigned long)uf_select(
			(unsigned long)real, 0, replacement);

	/* A hidden target normally does one native miss in its own hash bucket,
	 * without incrementing and then dropping the real target's reference.
	 * A replacement UID may have become live since policy_apply: never return
	 * that unrelated user or leak its reference. This is not a constant-time
	 * guarantee; hash detection and bucket population still matter. */
	if (unlikely(drop)) {
		free_uid(drop);
		return NULL;
	}
	return real;
}

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
	/* This observes the capability/LSM callback, before commit_creds. It
	 * preserves the upstream tagging contract, not a post-commit guarantee. */
	if (ret == 0 && interesting && (after % 100000u) >= UF_APP_MIN) {
		uidfake_tag_adopt(before, after);
		uidfake_tag_note(0, 0, before, after);
	}
	return ret;
}

struct uf_inline_hook {
	const char *name;
	u32 *copy;
	unsigned long stub, pacia_stub, pacib_stub;
	unsigned long site;
	u32 saved;
	bool installed;
	struct uf_inline_region region;
};

static struct uf_inline_hook g_find_user = {
	.name = "find_user",
	.copy = g_find_user_copy,
	.stub = (unsigned long)uf_find_user_stub,
	.pacia_stub = (unsigned long)uf_find_user_pacia_stub,
	.pacib_stub = (unsigned long)uf_find_user_pacib_stub,
};
static struct uf_inline_hook g_setuid = {
	.name = "cap_task_fix_setuid",
	.copy = g_setuid_copy,
	.stub = (unsigned long)uf_setuid_stub,
	.pacia_stub = (unsigned long)uf_setuid_pacia_stub,
	.pacib_stub = (unsigned long)uf_setuid_pacib_stub,
};

bool uidfake_inline_active(void)
{
	return g_find_user.installed || g_setuid.installed;
}

static int inline_errno(int rc)
{
	switch (rc) {
	case UF_INLINE_ESIZE:
		return -E2BIG;
	case UF_INLINE_EINSN:
		return -EOPNOTSUPP;
	case UF_INLINE_ERANGE:
		return -ERANGE;
	default:
		return -EINVAL;
	}
}

/* Called only during serialized module initialization. Nothing can enter the
 * scratch/trampoline while it is being constructed. Only the displaced entry
 * instructions are copied; the rest runs at its original kernel address. */
static int inline_install(struct uf_inline_hook *hook)
{
	static u32 source[UF_INLINE_MAX_SOURCE / UF_INLINE_INSN];
	static u32 scratch[UF_INLINE_STORAGE_SIZE / UF_INLINE_INSN];
	unsigned long addr = 0, size = 0, stub = hook->stub;
	size_t written = 0, skip = 0;
	u32 patch;
	bool distant = false;
	int rc;

	BUILD_BUG_ON(UF_INLINE_TRAMPOLINE_MAX + UF_INLINE_INSN >
		     UF_INLINE_STORAGE_SIZE);
	BUILD_BUG_ON(UF_INLINE_VENEER_SIZE > UF_INLINE_STORAGE_SIZE);
	if (hook->installed)
		return 0;
	if (!uidfake_symbol_range(hook->name, &addr, &size))
		return -ENOENT;
	if ((addr & 3) || (size & 3) || size < UF_INLINE_INSN ||
	    size > sizeof(source))
		return -E2BIG;
	if (!uidfake_read((const void *)addr, source, size))
		return -EFAULT;
	uidfake_debug_dump(hook->name, addr, size);

	/* Preserve explicit BTI landing pads. PAC*SP is also a landing pad: if
	 * first, leave it in place and undo precisely that signing in the stub,
	 * before a C prologue changes SP or signs its own return address. */
	if ((source[0] & 0xffffff3fu) == 0xd503241fu) {
		skip = UF_INLINE_INSN;
	} else if (source[0] == UF_PACIASP || source[0] == UF_PACIBSP) {
		skip = UF_INLINE_INSN;
		stub = source[0] == UF_PACIASP ? hook->pacia_stub :
						 hook->pacib_stub;
	}
	if (size < skip + UF_INLINE_INSN)
		return -EINVAL;
	rc = uf_inline_entry(&patch, sizeof(patch), addr + skip, stub);
	if (rc != UF_INLINE_ENTRY && rc != UF_INLINE_ERANGE)
		return inline_errno(rc);
	distant = rc == UF_INLINE_ERANGE;

	/* The original may only be directly called and have no BTI of its own.
	 * The helper can call this copy indirectly, so give it a known landing. */
	scratch[0] = UF_BTI_C;
	if (!distant) {
		rc = uf_inline_trampoline(scratch + 1,
					  sizeof(scratch) - UF_INLINE_INSN,
					  source, addr,
					  (unsigned long)(hook->copy + 1), size,
					  skip, &written);
		if (rc != UF_INLINE_OK && rc != UF_INLINE_ERANGE)
			return inline_errno(rc);
		distant = rc == UF_INLINE_ERANGE;
		written += UF_INLINE_INSN;
	}
	if (distant) {
		u32 *entry, *original;
		size_t original_len;

		/* Keep the kernel entry a single B. Only a private allocation holds
		 * long veneers; no extra live instructions are overwritten. Each
		 * hook owns its page, retained forever once the entry is published.
		 */
		rc = uidfake_inline_alloc(&hook->region, addr);
		if (rc)
			return rc;
		entry = hook->region.addr;
		original = entry + UF_INLINE_ISLAND_TRAMPOLINE / UF_INLINE_INSN;
		rc = uf_inline_entry(&patch, sizeof(patch), addr + skip,
				     (unsigned long)entry);
		if (rc != UF_INLINE_ENTRY) {
			rc = inline_errno(rc);
			goto free_region;
		}
		original[0] = UF_BTI_JC;
		rc = uf_inline_trampoline(
			original + 1, UF_INLINE_STORAGE_SIZE - UF_INLINE_INSN,
			source, addr, (unsigned long)(original + 1), size, skip,
			&original_len);
		if (rc != UF_INLINE_OK) {
			rc = inline_errno(rc);
			goto free_region;
		}
		rc = uf_inline_veneer(entry, UF_INLINE_ISLAND_TRAMPOLINE, stub,
				      1);
		if (rc != UF_INLINE_LANDING_VENEER_SIZE) {
			rc = inline_errno(rc);
			goto free_region;
		}
		/* The typed alias is still reached by a direct BL. Its private
		 * veneer preserves LR, arguments, NZCV and SCS; IP0 is ABI scratch.
		 * The island original trampoline resumes the body with a direct B.
		 */
		rc = uf_inline_veneer(scratch, sizeof(scratch),
				      (unsigned long)original, 0);
		if (rc != UF_INLINE_VENEER_SIZE) {
			rc = inline_errno(rc);
			goto free_region;
		}
		written = UF_INLINE_VENEER_SIZE;
		rc = uidfake_inline_seal(&hook->region);
		if (rc)
			goto free_region;
	}
	rc = uidfake_patch_text(hook->copy, scratch, written, true);
	if (rc)
		goto free_region;
	if (memcmp(hook->copy, scratch, written)) {
		rc = -EIO;
		goto free_region;
	}
	if (memcmp((const void *)addr, source, size)) {
		rc = -EBUSY;
		goto free_region;
	}

	hook->site = addr + skip;
	hook->saved = source[skip / UF_INLINE_INSN];
	/* Hold a real module reference BEFORE the kernel can branch into us.
	 * uidfake_init must never return an error after a successful publication:
	 * module-loader init failure frees even a module with outstanding refs. */
	if (!try_module_get(THIS_MODULE)) {
		rc = -ENODEV;
		goto free_region;
	}
	rc = uidfake_patch_insn((void *)hook->site, hook->saved, patch);
	if (rc) {
		/* The single-word patch API guarantees failure leaves it unchanged. */
		module_put(THIS_MODULE);
		goto free_region;
	}
	hook->installed = true;
	if (distant)
		hook->region.published = true;
	if (distant)
		pr_info("uidfake: inline %s near island at %px, %zu bytes RO/X\n",
			hook->name, hook->region.addr, hook->region.size);
	pr_info("uidfake: inline %s: %zu-byte %s, one B, pinned until reboot\n",
		hook->name, written,
		distant ? "original-call veneer via near island" :
			  "entry trampoline");
	return 0;

free_region:
	uidfake_inline_free(&hook->region);
	return rc;
}

static int find_user_hook_install(void)
{
	int rc = inline_install(&g_find_user);

	if (rc)
		uidfake_status_note(rc);
	return rc;
}

static int setuid_inline_install(void)
{
	int rc = inline_install(&g_setuid);

	/* Preserve the upstream symbol fallback when capability's body is absent. */
	if (rc == -ENOENT && !strcmp(g_setuid.name, "cap_task_fix_setuid")) {
		g_setuid.name = "safesetid_task_fix_setuid";
		rc = inline_install(&g_setuid);
	}
	if (rc) {
		uidfake_status_note(rc);
		return rc;
	}
	uidfake_status_set_lsm(KAUX_LSM_TAKEN, 0, g_setuid.name);
	return 0;
}

static int uid_inline_install(void)
{
	int rc = find_user_hook_install();

	if (!rc) {
		uidfake_status_set_hooks_expected(0, 0);
		uidfake_status_add_flags(KAUX_F_PRIO_INLINE);
	}
	return rc;
}

static void inline_remove(void)
{
	/* Normally unreachable: successful publication retains a module ref.
	 * Tier teardown also refuses while either permanent inline tier is live. */
	WARN_ON_ONCE(uidfake_inline_active());
}

UF_TIER(uf_tier_uid_inline, UF_TIER_UID, "inline", "inline find_user", 10,
	uid_inline_install, inline_remove);
UF_TIER(uf_tier_setuid_inline, UF_TIER_SETUID, "inline",
	"inline cap_task_fix_setuid", 10, setuid_inline_install, inline_remove);
