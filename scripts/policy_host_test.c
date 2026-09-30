/* Host test: compile the real policy.c against the scripts/hosttest shims and
 * check that the table reproduces its own policy exactly, at small and large
 * scale.
 */
#include "policy.c"
#include "tag.c" /* the tag record moved out of policy.c; this test covers both */
#include <stdio.h>

/* the host never logs anything, but the key has to exist for the linker */
struct static_key_false uidfake_debug_key;

/* the host has no isolated windows to close */

static u32 g_fail;
static u32 t_pairs[400 * 200 * 2];
static u32 t_np;
static u32 t_callers[400];
static u32 t_nc;

static int is_cfg(u32 c, u32 t)
{
	u32 k;

	for (k = 0; k < t_np; k += 2)
		if (t_pairs[k] == c && t_pairs[k + 1] == t)
			return 1;
	return 0;
}

static void check_sweep(const char *tag, u32 *pairs, u32 np, u32 *callers,
			u32 nc, u32 tlo, u32 thi)
{
	u32 i, j, unhidden = 0, fp = 0, cells = 0;

	policy_init();
	policy_apply(pairs, np / 2);
	for (i = 0; i < np; i += 2)
		if (pairs[i] &&
		    !policy_lookup_as((uid_t)pairs[i], (uid_t)pairs[i + 1]))
			unhidden++;
	for (i = 0; i < nc; i++) {
		for (j = tlo; j <= thi; j++) {
			int cfg = 0;
			u32 k2;

			for (k2 = 0; k2 < np; k2 += 2)
				if (pairs[k2] == callers[i] &&
				    pairs[k2 + 1] == j)
					cfg = 1;
			cells++;
			if (!cfg &&
			    policy_lookup_as((uid_t)callers[i], (uid_t)j))
				fp++;
		}
	}
	printf("%-22s pairs=%-5u callers=%-4u cells=%-7u unhidden=%u "
	       "false_positive=%u\n",
	       tag, np / 2, nc, cells, unhidden, fp);
	if (unhidden || fp)
		g_fail = 1;
}

/*
 * The identity the hot path uses is the tag, and the tag is written from the app
 * id inside the uid: a user id is the high part of a uid, so an app of a secondary
 * user (100000 + app) must be named like any other -- read as a whole number it is
 * past UF_ISOLATED_START and would never be tagged at all, which is a user whose
 * apps are hidden by nothing. A caller==0 pair hides the target from every caller,
 * including one that has no rules of its own.
 */
static void check_tag_path(void)
{
	static u32 pairs[] = { 10123, 10456, 110123, 110456 };
	static u32 wild[] = { 0, 10456 };
	u32 tag, hidden;

	policy_init();
	policy_apply(pairs, 2);

	fake_current.thread_info.flags = 0;
	uidfake_tag_adopt(0, 10123);
	tag = uidfake_tag_app();
	hidden = policy_query(10456);
	printf("%-22s tag=%-4u hidden=%u\n", "tag: owner", tag, hidden);
	if (tag != 124 || !hidden)
		g_fail = 1;

	fake_current.thread_info.flags = 0;
	uidfake_tag_adopt(0, 110123);
	tag = uidfake_tag_app();
	hidden = policy_query(110456);
	printf("%-22s tag=%-4u hidden=%u\n", "tag: secondary user", tag,
	       hidden);
	if (tag != 124 || !hidden)
		g_fail = 1;

	/* A system uid of a secondary user (100000 + 1000) is not an app, and an
	 * isolated uid is not one either. */
	fake_current.thread_info.flags = 0;
	uidfake_tag_adopt(0, 101000);
	if (uidfake_tag_app() != 0) {
		printf("%-22s tagged as an app\n", "tag: user system uid");
		g_fail = 1;
	}
	fake_current.thread_info.flags = 0;
	uidfake_tag_adopt(0, 90042);
	if (uidfake_tag_app() != 0) {
		printf("%-22s tagged as an app\n", "tag: isolated uid");
		g_fail = 1;
	}

	policy_apply(wild, 1);
	fake_current.thread_info.flags = 0;
	uidfake_tag_adopt(0, 10376);
	tag = uidfake_tag_app();
	hidden = policy_query(10456);
	printf("%-22s tag=%-4u hidden=%u\n", "tag: wildcard caller", tag,
	       hidden);
	if (tag != 377 || !hidden || policy_query(10457))
		g_fail = 1;

	fake_current.thread_info.flags = 0;
}

int main(void)
{
	u32 callers[7] = { 10376, 10377, 10378, 10379, 10380, 10381, 10382 };
	u32 targets[19];
	static u32 pairs[7 * 19 * 2];
	u32 i, j, w = 0;
	static u32 big[4000 * 2];
	/* A policy from the field: more pairs than the old 4096 ceiling. */
	static u32 kHugePairs = 24000;
	static u32 huge[24000 * 2];
	static u32 hugec[600];
	static u32 bigc[400];
	u32 bw = 0, bc = 0, hw = 0;

	for (i = 0; i < 19; i++)
		targets[i] = 10400 + i;
	for (i = 0; i < 19; i++)
		for (j = 0; j < 7; j++) {
			pairs[2 * w] = callers[j];
			pairs[2 * w + 1] = targets[i];
			w++;
		}
	check_sweep("device-like", pairs, w * 2, callers, 7, 10000, 14000);

	for (i = 0; i < 400; i++)
		bigc[bc++] = 10000 + i * 3; /* app uids live in 10000..19999 */
	for (i = 0; i < 100 && bw < 4000; i++)
		for (j = 0; j < 400 && bw < 4000; j++)
			if (((i * 7 + j * 13) % 40) ==
			    0) { /* ~10 of 400 callers per target */
				big[2 * bw] = bigc[j];
				big[2 * bw + 1] = 30000 + i;
				bw++;
			}
	check_sweep("uid-scale callers", big, bw * 2, bigc, bc, 30000, 30010);

	/* 24000 pairs over 600 callers: every one of them has to come back hidden. */
	for (i = 0; i < 600; i++)
		hugec[i] = 10000 + i * 3;
	for (i = 0, hw = 0; i < kHugePairs; i++) {
		huge[2 * hw] = hugec[i % 600];
		huge[2 * hw + 1] = 30000 + (i * 7) % 20000;
		hw++;
	}
	check_sweep("field-sized", huge, hw * 2, hugec, 600, 30000, 30009);

	/* The same policy for two users, the way expand_users() hands it over: the
	 * hider table is keyed by app id, so both users' pairs have to be found. */
	for (i = 0, hw = 0; i < 200; i++) {
		huge[2 * hw] = 10452;
		huge[2 * hw + 1] = 10700 + i;
		hw++;
	}
	for (i = 0; i < 200; i++) {
		huge[2 * hw] = 110452;
		huge[2 * hw + 1] = 110700 + i;
		hw++;
	}
	check_sweep("two users", huge, hw * 2, hugec, 0, 30000, 30000);

	check_tag_path();

	printf("%s\n", g_fail ? "FAIL" : "PASS");
	return g_fail;
}
