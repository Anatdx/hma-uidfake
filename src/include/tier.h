/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#ifdef __KERNEL__

/*
 * tier.h - the fallback chains, as a registry.
 *
 * Two questions this module answers on kernels it was not built for: how a uid
 * with no processes is reported, and where an identity change is seen. More than
 * one mechanism can answer each of them, and which one works depends on the
 * kernel -- whether a symbol is copyable, whether an LSM hook can be taken,
 * whether the tables are where they were.
 *
 * So each mechanism is a struct with the order it wants to be tried in, and the
 * runner walks the family in that order until one installs. A mechanism is one
 * definition (UF_TIER below) in its own file and one line in the table in
 * tiers.c; the order is data, so moving a mechanism is a number.
 *
 * The table is explicit rather than a linker-collected section on purpose: a
 * section would need __start_/__stop_ symbols, and this toolchain (kbuild with
 * LTO, on every KMI) does not synthesise them for a module -- the symbols come
 * out undefined and the module would not load. That was measured, not assumed.
 */
struct uf_tier {
	const char *family;
	const char *key; /* what a module parameter names it by */
	const char *name; /* what the status line shows when this one wins */
	int order; /* lower is tried first */
	int (*install)(void);
	void (*remove)(void);
};

#define UF_TIER_UID "uid queries"
#define UF_TIER_SETUID "setuid"

#define UF_TIER(_sym, _family, _key, _name, _order, _install, _remove) \
	const struct uf_tier _sym = {                                  \
		.family = (_family),                                   \
		.key = (_key),                                         \
		.name = (_name),                                       \
		.order = (_order),                                     \
		.install = (_install),                                 \
		.remove = (_remove),                                   \
	}

/*
 * Install the first mechanism of @family that works. @force names a mechanism by
 * key (a module parameter); when it is set, only that one is tried, so that a
 * forced run reports why it failed instead of quietly using another.
 */
int uf_tier_install(const char *family, const char *force);

/* Take back what is installed, most recent first. */
void uf_tier_revert(const char *family);
void uf_tier_revert_all(void);

/* The name of the mechanism in place for @family, or NULL. */
const char *uf_tier_name(const char *family);

#endif /* __KERNEL__ */
