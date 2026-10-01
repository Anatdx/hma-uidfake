// SPDX-License-Identifier: GPL-2.0
/*
 * Host test for the runtime relocator and short entry trampoline. Real machine
 * code of find_user() exercises PAC, SCS, ADRP+ADD, calls and internal branches.
 * Synthetic entries cover short trampoline prefixes and refusal paths.
 */
#include "include/inline.h"
#include "include/inline_entry.h"

#ifdef UF_INLINE_DEBUG
extern unsigned int uf_inline_dbg_insn;
extern unsigned int uf_inline_dbg_index;
extern unsigned int uf_inline_dbg_stage;
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "find_user_sample.h"

#define FROM_VA 0x17986cUL
#define TO_VA 0x8000000UL
#define LEN 248u

static int failures;

static void check(int ok, const char *what)
{
	if (!ok) {
		printf("FAIL: %s\n", what);
		failures++;
	}
}

/* Decode the relocated ADRP+ADD pairs and direct calls at their new PCs. */
static int holds_const(const unsigned char *code, size_t len, unsigned int reg,
		       unsigned long value)
{
	unsigned long page = 0;
	int have_page = 0;
	size_t i;

	for (i = 0; i + 4 <= len; i += 4) {
		unsigned int word;
		long offset;

		memcpy(&word, code + i, 4);
		if ((word & 0x9f00001fu) == (0x90000000u | reg)) {
			offset = ((word >> 29) & 3u) |
				 (((word >> 5) & 0x7ffffu) << 2);
			if (offset & (1L << 20))
				offset -= 1L << 21;
			page = ((TO_VA + i) & ~0xfffUL) +
			       (unsigned long)(offset * 4096);
			have_page = 1;
		} else if (have_page &&
			   (word & 0xffc003ffu) ==
				   (0x91000000u | reg << 5 | reg) &&
			   page + ((word >> 10) & 0xfffu) == value) {
			return 1;
		}
	}
	return 0;
}

static int calls_target(const unsigned char *code, size_t len,
			unsigned long target)
{
	size_t i;

	for (i = 0; i + 4 <= len; i += 4) {
		unsigned int word;
		long offset;

		memcpy(&word, code + i, 4);
		if ((word & 0xfc000000u) != 0x94000000u)
			continue;
		offset = word & 0x03ffffffu;
		if (offset & (1L << 25))
			offset -= 1L << 26;
		if (TO_VA + i + (unsigned long)(offset * 4) == target)
			return 1;
	}
	return 0;
}

static int contains_word(const unsigned char *code, size_t len,
			 unsigned int insn)
{
	size_t i;

	for (i = 0; i + 4 <= len; i += 4) {
		unsigned int w;

		memcpy(&w, code + i, 4);
		if (w == insn)
			return 1;
	}
	return 0;
}

static unsigned long branch_target(unsigned int word, unsigned long pc)
{
	long displacement = word & 0x03ffffffu;

	if (displacement & (1L << 25))
		displacement -= 1L << 26;
	return pc + (unsigned long)(displacement * 4);
}

static void trampoline_refused(const unsigned int *source, size_t len,
			       size_t skip, unsigned long to, size_t capacity,
			       int expected, const char *what)
{
	unsigned int output[4], before[4];
	size_t written = 999;

	memset(output, 0xa5, sizeof(output));
	memcpy(before, output, sizeof(before));
	check(uf_inline_trampoline(output, capacity, source, FROM_VA, to, len,
				   skip, &written) == expected,
	      what);
	check(written == 0 && !memcmp(output, before, sizeof(output)),
	      "trampoline refusal clears length and leaves output untouched");
}

static void trampoline_tests(void)
{
	static const struct {
		unsigned int first, second;
		size_t skip;
	} entries[] = {
		{ 0x51000448, 0x7100091f, 0 }, /* SUB; CMP, plain entry */
		{ 0xd503233f, 0xa9bd7bfd, 4 }, /* PACIASP; STP frame */
		{ 0xd503237f, 0xf800865e, 4 }, /* PACIBSP; SCS push */
		{ 0xd503245f, 0x51000448, 4 }, /* BTI c; SUB */
		{ 0xd50324df, 0xd503233f, 4 }, /* BTI jc; PACIASP */
	};
	/* At source[2], each PC-relative target below reaches source[1]. */
	static const unsigned int reentries[] = {
		0x17ffffff, 0x97ffffff, 0x54ffffe0, /* B, BL, B.eq */
		0x34ffffe0, 0x3607ffe0, 0x10ffffe0, /* CBZ, TBZ, ADR */
		0x90000000, /* ADRP: the entry's page */
		0xd61f0100, 0xd63f0100, /* BR/BLR: unresolved target */
	};
	unsigned int source[4], output[4];
	size_t i, written;

	for (i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
		const size_t prefix = entries[i].skip + 4;
		const size_t branch = prefix / 4;

		source[0] = entries[i].first;
		source[1] = entries[i].second;
		source[2] = 0x14000000; /* Body-only loop stays native. */
		source[3] = 0xd65f03c0;
		memset(output, 0xa5, sizeof(output));
		written = 999;
		check(uf_inline_trampoline(output, sizeof(output), source,
					   FROM_VA, TO_VA, sizeof(source),
					   entries[i].skip, &written) == 0,
		      "plain and BTI/PAC entries build a short trampoline");
		/* This checks PAC instruction preservation, not hardware authentication. */
		check(written == prefix + 4 && !memcmp(output, source, prefix),
		      "original-call trampoline replays the complete entry prefix");
		check((output[branch] & 0xfc000000u) == 0x14000000u &&
			      branch_target(output[branch], TO_VA + prefix) ==
				      FROM_VA + prefix,
		      "direct return branch resumes after the overwritten instruction");
		check(output[branch + 1] == 0xa5a5a5a5,
		      "trampoline does not copy the native body");
		trampoline_refused(source, sizeof(source), entries[i].skip,
				   FROM_VA + (1UL << 28), sizeof(output),
				   UF_INLINE_ERANGE,
				   "out-of-range native resume is refused");
		trampoline_refused(
			source, sizeof(source), entries[i].skip, TO_VA, prefix,
			UF_INLINE_ESIZE,
			"output must fit the prefix and resume branch");
		trampoline_refused(source, sizeof(source), entries[i].skip ^ 4,
				   TO_VA, sizeof(output), UF_INLINE_EINSN,
				   "patch offset must match the entry landing");
	}
	source[0] = 0xd503245f; /* BTI c */
	source[1] = 0x51000448; /* SUB w8,w2,#1 */
	for (i = 0; i < sizeof(reentries) / sizeof(reentries[0]); i++) {
		source[2] = reentries[i];
		trampoline_refused(
			source, sizeof(source), 4, TO_VA, sizeof(output),
			UF_INLINE_EINSN,
			"prefix reentry or unresolved body branch is refused");
	}
	source[2] = 0xd503201f;
	source[1] = 0x14000000;
	trampoline_refused(source, sizeof(source), 4, TO_VA, sizeof(output),
			   UF_INLINE_EINSN,
			   "an existing branch at the patch site is refused");
	source[1] = 0x51000448;
	trampoline_refused(source, 8, 4, TO_VA, sizeof(output), UF_INLINE_ESIZE,
			   "a trampoline needs a native body to resume");
}

int main(void)
{
	_Alignas(4) unsigned char copy[1024];
	unsigned int source[LEN / 4];
	size_t out = 0;
	int rc;

	memset(copy, 0, sizeof copy);
	memcpy(source, kFindUser, LEN);
	rc = uf_inline_relocate(copy, sizeof copy, source, FROM_VA, TO_VA, LEN,
				&out);
	if (rc != 0) {
#ifdef UF_INLINE_DEBUG
		printf("  relocation returned %d (stage %u, index %u, insn 0x%08x)\n",
		       rc, uf_inline_dbg_stage, uf_inline_dbg_index,
		       uf_inline_dbg_insn);
#else
		printf("  relocation returned %d\n", rc);
#endif
	}
	check(rc == 0, "the real find_user relocates");
	check(out >= LEN, "the copy is at least as long as the original");

	{
		unsigned int first;

		memcpy(&first, copy, 4);
		check(first == 0xd503233fu, "the copy starts with paciasp");
		/* No hole: every word of the copy was written by the relocation. */
		{
			size_t k;
			int hole = 0;

			for (k = 0; k < out / 4; k++) {
				unsigned int w;

				memcpy(&w, copy + k * 4, 4);
				if (w == 0)
					hole = 1;
			}
			check(!hole, "the copy has no unwritten word");
		}
	}
	check(contains_word(copy, out, 0xd503233fu), "paciasp copied");
	check(contains_word(copy, out, 0xd50323bfu), "autiasp copied");
	check(contains_word(copy, out, 0xd65f03c0u), "ret copied");

	if (getenv("UF_DUMP")) {
		size_t k;

		for (k = 0; k < out / 4; k++) {
			unsigned int w;

			memcpy(&w, copy + k * 4, 4);
			printf("  %02zu: %08x\n", k, w);
		}
	}
	check(holds_const(copy, out, 0, 0x20cd860UL),
	      "uidhash_lock address kept (x0)");
	check(holds_const(copy, out, 9, 0x20cd868UL),
	      "uidhash_table address kept (x9)");

	check(calls_target(copy, out, 0x140a024UL), "call 1 target kept");
	check(calls_target(copy, out, 0x140a278UL), "call 2 target kept");
	check(calls_target(copy, out, 0x774b70UL), "call 3 target kept");
	check(!contains_word(copy, out, 0xd63f0220u), "calls remain direct");

	{
		static const unsigned int literal[2] = { 0x58000040u,
							 0xd65f03c0u };
		unsigned int buf[16];

		rc = uf_inline_relocate(buf, sizeof buf, literal, FROM_VA, 0, 8,
					&out);
		check(rc == UF_INLINE_EINSN, "a literal load is refused");
	}
	{
		static const unsigned int none[2] = { 0xd65f03c0u,
						      0xd65f03c0u };
		unsigned int buf[16];

		rc = uf_inline_relocate(buf, sizeof buf, none, FROM_VA, 0, 8,
					&out);
		check(rc == UF_INLINE_OK, "a plain function is accepted");
	}

	{
		unsigned int patch;
		long imm26;
		unsigned long site = 0xffffff8008000000UL + 0x17986cUL;
		unsigned long hook = site - (1UL << 26);

		rc = uf_inline_entry(&patch, sizeof patch, site, hook);
		check(rc == (int)UF_INLINE_ENTRY, "an entry patch is built");
		check((patch & 0xfc000000u) == 0x14000000u, "single B emitted");
		imm26 = patch & 0x03ffffffu;
		if (imm26 & (1L << 25))
			imm26 -= 1L << 26;
		check(site + (unsigned long)(imm26 * 4) == hook,
		      "B reaches the hook");
		rc = uf_inline_entry(&patch, sizeof patch, site,
				     site + (1UL << 27));
		check(rc == UF_INLINE_ERANGE,
		      "a hook out of branch range is refused");
	}

	trampoline_tests();
	if (failures == 0)
		printf("inline reloc: PASS\n");
	return failures == 0 ? 0 : 1;
}
