// SPDX-License-Identifier: GPL-2.0
/*
 * tiers.c - walk a family of mechanisms in order, and remember what won.
 *
 * The mechanisms themselves are defined in the files named after them (see
 * tier.h for why the table below is explicit); this is the table and the walk.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#ifdef UIDFAKE_HOST_TEST
#include <string.h> /* the host test compiles this file against its own shims */
#else
#include <linux/string.h>
#endif

#include "uidfake.h"
#include "tier.h"

/* One line per mechanism, in no particular order: the order field decides. */
extern const struct uf_tier uf_tier_uid_inline;
extern const struct uf_tier uf_tier_uid_tables;
extern const struct uf_tier uf_tier_setuid_inline;
extern const struct uf_tier uf_tier_setuid_lsm;
extern const struct uf_tier uf_tier_setuid_setters;

#ifdef UIDFAKE_HOST_TEST
/*
 * The host test supplies its own mechanisms. The kernel's table is fixed, so
 * this is compiled in only for the test, and the two accessors below are the
 * only place the choice shows.
 */
static const struct uf_tier *const *g_test_tiers;
static unsigned int g_test_tiers_n;

void uf_tier_set_table(const struct uf_tier *const *tiers, unsigned int n)
{
	g_test_tiers = tiers;
	g_test_tiers_n = n;
}
#endif

#ifndef UIDFAKE_HOST_TEST
static const struct uf_tier *const g_tiers[] = {
	&uf_tier_uid_inline, &uf_tier_uid_tables,     &uf_tier_setuid_inline,
	&uf_tier_setuid_lsm, &uf_tier_setuid_setters,
};
#else
/* empty: the host test always sets its own table with uf_tier_set_table() */
static const struct uf_tier *const g_tiers[] = { NULL };
#endif

static const struct uf_tier *tier_at(unsigned int i)
{
#ifdef UIDFAKE_HOST_TEST
	if (g_test_tiers)
		return g_test_tiers[i];
#endif
	return g_tiers[i];
}

static unsigned int tier_count(void)
{
#ifdef UIDFAKE_HOST_TEST
	if (g_test_tiers)
		return g_test_tiers_n;
#endif
	return (unsigned int)ARRAY_SIZE(g_tiers);
}

#define UF_TIER_MAX 8
static const struct uf_tier *g_installed[UF_TIER_MAX];
static int g_installed_n;
static const struct uf_tier *g_tried[16];
static int g_tried_n;

static bool already_tried(const struct uf_tier *t)
{
	int i;

	for (i = 0; i < g_tried_n; i++)
		if (g_tried[i] == t)
			return true;
	return false;
}

int uf_tier_install(const char *family, const char *force)
{
	const struct uf_tier *t, *best;
	bool forced = force && *force && strcmp(force, "auto");
	unsigned int i;

	g_tried_n = 0;
	if (forced) {
		/*
		 * One mechanism, named: a forced run has to show that one's answer,
		 * including a failure, and not quietly fall through to another.
		 */
		for (i = 0; i < tier_count(); i++) {
			int rc;

			t = tier_at(i);
			if (strcmp(t->family, family) != 0 ||
			    strcmp(t->key, force) != 0)
				continue;
			rc = t->install();
			if (rc) {
				pr_err("uidfake: %s: %s was asked for and did not install (%d)\n",
				       family, t->name, rc);
				return rc;
			}
			if (g_installed_n < UF_TIER_MAX)
				g_installed[g_installed_n++] = t;
			return 0;
		}
		pr_err("uidfake: %s: no mechanism named '%s'\n", family, force);
		return -ENOENT;
	}

	for (;;) {
		best = NULL;
		for (i = 0; i < tier_count(); i++) {
			t = tier_at(i);
			if (strcmp(t->family, family) != 0 || already_tried(t))
				continue;
			if (!best || t->order < best->order)
				best = t;
		}
		if (!best)
			break;
		if (g_tried_n < (int)ARRAY_SIZE(g_tried))
			g_tried[g_tried_n++] = best;

		if (best->install() == 0) {
			if (g_installed_n < UF_TIER_MAX)
				g_installed[g_installed_n++] = best;
			return 0;
		}
		pr_warn("uidfake: %s: %s did not install, trying the next\n",
			family, best->name);
	}
	return -ENODEV;
}

static void forget(int i)
{
	memmove(&g_installed[i], &g_installed[i + 1],
		(size_t)(g_installed_n - i - 1) * sizeof(g_installed[0]));
	g_installed_n--;
}

void uf_tier_revert(const char *family)
{
	int i;

	if (uidfake_inline_active()) {
		pr_warn("uidfake: inline tiers are permanent until reboot; keeping the registry\n");
		return;
	}

	for (i = g_installed_n - 1; i >= 0; i--) {
		if (strcmp(g_installed[i]->family, family) != 0)
			continue;
		g_installed[i]->remove();
		forget(i);
	}
}

void uf_tier_revert_all(void)
{
	if (uidfake_inline_active()) {
		pr_warn("uidfake: inline tiers are permanent until reboot; keeping the registry\n");
		return;
	}
	while (g_installed_n > 0) {
		g_installed[g_installed_n - 1]->remove();
		g_installed_n--;
	}
}

const char *uf_tier_name(const char *family)
{
	int i;

	for (i = g_installed_n - 1; i >= 0; i--)
		if (strcmp(g_installed[i]->family, family) == 0)
			return g_installed[i]->name;
	return NULL;
}
