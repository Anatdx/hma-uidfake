/*
 * Host test for the tier framework: which mechanism a family picks, what a forced
 * run does, and what a revert takes back.
 *
 * The runner is the real src/tiers.c, compiled against the shims with its table
 * replaced by fakes that record what was called (uf_tier_set_table is compiled in
 * only for the host). The cases are about the framework, not about any mechanism:
 * order, family isolation, forcing (which tries only what it names), and that a
 * revert takes back everything that was installed -- the order that keeps a
 * mechanism from being left behind when two families share a piece of state, which
 * is how the table mechanisms used to be able to leave six entries patched.
 */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif
#include <errno.h> /* tiers.c returns -ENOENT and -ENODEV */
#include "tiers.c"

#include <stdio.h>
#include <string.h>

static char g_log[64];
static unsigned int g_log_n;
static unsigned int g_case_fail;
static unsigned int g_total_fail;

static void log_add(char c)
{
	if (g_log_n < sizeof(g_log) - 1)
		g_log[g_log_n++] = c;
	g_log[g_log_n] = 0;
}

static void want(bool cond, const char *what)
{
	if (!cond) {
		fprintf(stderr, "tiers: FAILED: %s (log '%s')\n", what, g_log);
		g_case_fail++;
	}
}

static void want_log(const char *expect)
{
	want(strcmp(g_log, expect) == 0, expect);
}

/* A family with nothing installed has no name; comparing that is not a crash. */
static void want_name(const char *family, const char *expect)
{
	const char *got = uf_tier_name(family);

	if (!expect) {
		want(got == NULL, "no mechanism is in place");
		return;
	}
	want(got != NULL && strcmp(got, expect) == 0, expect);
}

static void end_case(const char *name)
{
	printf("tiers: %s %s\n", name, g_case_fail ? "FAIL" : "PASS");
	g_total_fail += g_case_fail;
	g_case_fail = 0;
	/* clear after the revert, or the removes it runs land in the next case */
	uf_tier_revert_all();
	g_log_n = 0;
	g_log[0] = 0;
}

struct fake {
	int rc;
	int removes;
};

static struct fake g_fa, g_fb, g_fc, g_fd, g_fe, g_ff, g_fg, g_fh;

static int inst_a(void)
{
	log_add('a');
	return g_fa.rc;
}
static void rem_a(void)
{
	log_add('A');
	g_fa.removes++;
}
static int inst_b(void)
{
	log_add('b');
	return g_fb.rc;
}
static void rem_b(void)
{
	log_add('B');
	g_fb.removes++;
}
static int inst_c(void)
{
	log_add('c');
	return g_fc.rc;
}
static void rem_c(void)
{
	log_add('C');
	g_fc.removes++;
}
static int inst_d(void)
{
	log_add('d');
	return g_fd.rc;
}
static void rem_d(void)
{
	log_add('D');
	g_fd.removes++;
}
static int inst_e(void)
{
	log_add('e');
	return g_fe.rc;
}
static void rem_e(void)
{
	log_add('E');
	g_fe.removes++;
}
static int inst_f(void)
{
	log_add('f');
	return g_ff.rc;
}
static void rem_f(void)
{
	log_add('F');
	g_ff.removes++;
}
static int inst_g(void)
{
	log_add('g');
	return g_fg.rc;
}
static void rem_g(void)
{
	log_add('G');
	g_fg.removes++;
}
static int inst_h(void)
{
	log_add('h');
	return g_fh.rc;
}
static void rem_h(void)
{
	log_add('H');
	g_fh.removes++;
}

/* uid family: a and b fail, c works; g exists for the revert-all case. */
static const struct uf_tier t_a = { UF_TIER_UID, "a",	 "fake a",
				    10,		 inst_a, rem_a };
static const struct uf_tier t_b = { UF_TIER_UID, "b",	 "fake b",
				    20,		 inst_b, rem_b };
static const struct uf_tier t_c = { UF_TIER_UID, "c",	 "fake c",
				    30,		 inst_c, rem_c };
/* setuid family: d works, e fails, f is the one behind it (a forced run is how
 * the ones behind a working mechanism are reached). */
static const struct uf_tier t_d = { UF_TIER_SETUID, "d",  "fake d", 10,
				    inst_d,	    rem_d };
static const struct uf_tier t_e = { UF_TIER_SETUID, "e",  "fake e", 20,
				    inst_e,	    rem_e };
static const struct uf_tier t_f = { UF_TIER_SETUID, "f",  "fake f", 30,
				    inst_f,	    rem_f };
/* the revert-all pair: orders past everything else, so they change no other case */
static const struct uf_tier t_g = { UF_TIER_UID, "g",	 "fake g",
				    40,		 inst_g, rem_g };
static const struct uf_tier t_h = { UF_TIER_SETUID, "h",  "fake h", 40,
				    inst_h,	    rem_h };

static const struct uf_tier *const g_table[] = {
	&t_a, &t_b, &t_c, &t_d, &t_e, &t_f, &t_g, &t_h,
};

static void reset_fakes(void)
{
	static const struct fake zero;

	g_fa = g_fb = g_fc = g_fd = g_fe = g_ff = g_fg = g_fh = zero;
	g_fa.rc = -ENOENT;
	g_fb.rc = -EINVAL;
	g_fd.rc = 0;
	g_fe.rc = -EOPNOTSUPP;
	g_fg.rc = 0;
	g_fh.rc = 0;
}

int main(void)
{
	uf_tier_set_table(g_table, ARRAY_SIZE(g_table));

	/* 1. The lowest order that installs wins, after the ones before it failed. */
	reset_fakes();
	g_fa.rc = -ENOENT;
	g_fb.rc = -EINVAL;
	want(uf_tier_install(UF_TIER_UID, NULL) == 0, "install returns 0");
	want_name(UF_TIER_UID, "fake c");
	want_log("abc");
	end_case("order");

	/* 2. A family install never touches another family's mechanisms. */
	reset_fakes();
	want(uf_tier_install(UF_TIER_UID, NULL) == 0, "install uid");
	want(uf_tier_install(UF_TIER_SETUID, NULL) == 0, "install setuid");
	want_log("abcd");
	end_case("isolation");

	/* 3. Forced: only the mechanism named by key is tried. */
	reset_fakes();
	g_fb.rc = 0; /* b is the one this case asks for, so it has to work */
	want(uf_tier_install(UF_TIER_UID, "b") == 0, "forced b installs");
	want_log("b");
	want_name(UF_TIER_UID, "fake b");
	end_case("forced");

	/* 4. A forced mechanism that fails is reported, not replaced: that is what
	 *    makes a device run say why the mechanism asked for is not there. */
	reset_fakes();
	want(uf_tier_install(UF_TIER_UID, "a") != 0,
	     "forced failure is returned");
	want_log("a");
	want_name(UF_TIER_UID, NULL);
	end_case("forced-failure");

	/* 5. A key no mechanism has is refused without calling anything. */
	reset_fakes();
	want(uf_tier_install(UF_TIER_UID, "nope") != 0, "unknown key refused");
	want_log("");
	want_name(UF_TIER_UID, NULL);
	end_case("forced-unknown");

	/* 5b. A setuid run passes a failing mechanism and lands on the one behind it. */
	reset_fakes();
	g_fd.rc = -EOPNOTSUPP;
	want(uf_tier_install(UF_TIER_SETUID, NULL) == 0, "install");
	want_log("def");
	want_name(UF_TIER_SETUID, "fake f");
	end_case("fallthrough");

	/* 6. Revert takes back only what one family installed. */
	reset_fakes();
	want(uf_tier_install(UF_TIER_UID, NULL) == 0, "install uid");
	want(uf_tier_install(UF_TIER_SETUID, NULL) == 0, "install setuid");
	g_log_n = 0;
	g_log[0] = 0;
	uf_tier_revert(UF_TIER_UID);
	want_log("C");
	want(g_fc.removes == 1 && g_fd.removes == 0,
	     "only the uid one came back");
	uf_tier_revert(UF_TIER_SETUID);
	want_log("CD");
	want(g_fd.removes == 1, "the setuid one came back");
	end_case("revert");

	/* 7. Everything installed comes back, most recent first -- the order that
	 *    keeps a mechanism from being left behind when two share state. */
	reset_fakes();
	want(uf_tier_install(UF_TIER_UID, "g") == 0, "install g");
	want(uf_tier_install(UF_TIER_SETUID, "h") == 0, "install h");
	g_log_n = 0;
	g_log[0] = 0;
	uf_tier_revert_all();
	want_log("HG");
	want(g_fg.removes == 1 && g_fh.removes == 1, "both came back");
	g_log_n = 0;
	g_log[0] = 0;
	uf_tier_revert_all(); /* nothing installed: a no-op, not a second remove */
	want_log("");
	end_case("revert-all");

	/* 8. A family nobody answers stays unanswered and says so. */
	reset_fakes();
	want(uf_tier_install("nope", NULL) != 0, "unknown family refused");
	want_log("");
	want_name("nope", NULL);
	end_case("unknown-family");

	printf("tiers: %u case(s) failed\n", g_total_fail);
	return g_total_fail != 0;
}
