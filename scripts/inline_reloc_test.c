// SPDX-License-Identifier: GPL-2.0
/*
 * Host test for the runtime relocator in src/inline.c. The input is the real
 * machine code of find_user() from a device kernel image, so the encodings under
 * test are the ones a kernel actually emits: paciasp, a shadow-call-stack store,
 * two adrp+add pairs, three bl calls, and branches that stay inside the function.
 */
#include "include/inline.h"

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
#define LEN 248u

static int failures;

static void check(int ok, const char *what)
{
	if (!ok) {
		printf("FAIL: %s\n", what);
		failures++;
	}
}

/* Materialise the movz/movk runs in @code and report whether x@reg ever holds @value. */
static int holds_const(const unsigned char *code, size_t len, unsigned int reg,
		       unsigned long value)
{
	size_t i;

	for (i = 0; i + 4 <= len; i += 4) {
		unsigned long acc = 0;
		int started = 0;
		size_t j;

		for (j = i; j + 4 <= len; j += 4) {
			unsigned int insn;

			memcpy(&insn, code + j, 4);
			if ((insn & 0xff80001fu) == (0xd2800000u | reg)) {
				acc = (insn >> 5) & 0xffffu;
				started = 1;
				continue;
			}
			if ((insn & 0xff80001fu) == (0xf2800000u | reg) &&
			    started) {
				const unsigned int hw = (insn >> 21) & 0x3u;

				acc = (acc & ~(0xffffUL << (16 * hw))) |
				      (((insn >> 5) & 0xffffUL) << (16 * hw));
				continue;
			}
			break;
		}
		if (started && acc == value)
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

int main(void)
{
	unsigned char copy[1024];
	size_t out = 0;
	int rc;

	memset(copy, 0, sizeof copy);
	rc = uf_inline_relocate(copy, sizeof copy, kFindUser, FROM_VA,
				0xffff000000000000UL, LEN, &out);
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

	check(holds_const(copy, out, 17, 0x140a024UL), "call 1 target kept");
	check(holds_const(copy, out, 17, 0x140a278UL), "call 2 target kept");
	check(holds_const(copy, out, 17, 0x774b70UL), "call 3 target kept");
	check(contains_word(copy, out, 0xd63f0220u), "blr x17 emitted");

	{
		static const unsigned int literal[2] = { 0x58000040u,
							 0xd65f03c0u };
		unsigned char buf[64];

		rc = uf_inline_relocate(buf, sizeof buf, literal, FROM_VA, 0, 8,
					&out);
		check(rc == UF_INLINE_EINSN, "a literal load is refused");
	}
	{
		static const unsigned int none[2] = { 0xd65f03c0u,
						      0xd65f03c0u };
		unsigned char buf[64];

		rc = uf_inline_relocate(buf, sizeof buf, none, FROM_VA, 0, 8,
					&out);
		check(rc == UF_INLINE_OK, "a plain function is accepted");
	}

	{
		unsigned char patch[UF_INLINE_ENTRY];
		unsigned int w[3];
		long imm21;
		/* A VA39 kernel: the image is high, the module region a few tens of
		 * MB below it, which is what makes adrp reach and ldr literal not. */
		unsigned long site = 0xffffff8008000000UL + 0x17986cUL;
		unsigned long hook = 0xffffff8000001000UL;

		rc = uf_inline_entry(patch, sizeof patch, site, hook);
		check(rc == (int)UF_INLINE_ENTRY, "an entry patch is built");
		memcpy(w, patch, sizeof w);
		check((w[0] & 0x9f000000u) == 0x90000000u, "adrp first");
		check(w[2] == 0xd61f0220u, "br x17 last");
		imm21 = (long)(((w[0] >> 29) & 0x3u) |
			       (((w[0] >> 5) & 0x7ffffu) << 2));
		if (imm21 & (1L << 20))
			imm21 -= (1L << 21); /* the field is signed */
		check((unsigned long)(((long)(site & ~0xfffull) + imm21 * 4096) +
				      (long)((w[1] >> 10) & 0xfffu)) == hook,
		      "adrp+add reaches the hook");
		rc = uf_inline_entry(patch, sizeof patch, site,
				     site + (1UL << 33));
		check(rc == UF_INLINE_ERANGE,
		      "a hook out of adrp range is refused");
	}

	if (failures == 0)
		printf("inline reloc: PASS\n");
	return failures == 0 ? 0 : 1;
}
