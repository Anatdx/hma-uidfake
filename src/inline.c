// SPDX-License-Identifier: GPL-2.0
/*
 * inline.c - the runtime half of an inline hook; see inline.h for why a copy is
 * built instead of a jump-back trampoline.
 *
 * Two passes. The first decides how long each source instruction becomes in the
 * copy and where it lands; the second emits. The map is what lets a branch inside
 * the function keep pointing at the same instruction after the instructions
 * before it changed size.
 *
 * Relocation is narrow on purpose: an instruction whose target is inside the
 * function keeps its encoding (the copy is contiguous and in order), and only
 * the operands that leave the function - an adrp page, a bl target - are turned
 * into absolute form. Anything this file does not understand is a refusal, never
 * a guess: a silently mis-relocated copy would be worse than no hook.
 */
#include "include/inline.h"

/* Opcode patterns. */
#define UF_B 0x14000000u
#define UF_BL 0x94000000u
#define UF_CBZ 0x34000000u
#define UF_CBNZ 0x35000000u
#define UF_TBZ 0x36000000u
#define UF_TBNZ 0x37000000u
#define UF_BCOND 0x54000000u
#define UF_ADRP 0x90000000u
#define UF_ADR 0x10000000u
#define UF_ADD_IMM 0x11000000u /* sf and shift are operands, not opcode */
#define UF_SUB_IMM 0x51000000u
#define UF_LDR_U64 0xf9400000u
#define UF_LDR_U32 0xb9400000u
#define UF_LDRSW 0xb9800000u

#define UF_M_BRANCH 0xfc000000u /* b, bl (bit 31 tells them apart) */
#define UF_M_COND 0x7f000000u /* cbz, cbnz, tbz, tbnz (bit 31 is the width) */
#define UF_M_BCOND 0xff000010u /* b.<cond> */
#define UF_M_ADRP 0x9f000000u /* adrp and adr share this mask */
#define UF_M_ADDSUB 0x7f800000u
#define UF_M_LDR 0xffc00000u
#define UF_M_LITERAL 0xff000000u

#define UF_INSNS 128u
#define UF_LOOKAHEAD 4u
#define UF_MAX_OUT (UF_INSNS * 5u * UF_INLINE_INSN)

#define UF_X17 17u /* IP1: not an argument, and not x18 (shadow call stack) */

/* The host test turns these on to see which instruction was refused. */
#ifdef UF_INLINE_DEBUG
unsigned int uf_inline_dbg_insn;
unsigned int uf_inline_dbg_index;
unsigned int uf_inline_dbg_stage;
#endif

static int uf_sx(unsigned int value, unsigned int bits)
{
	const unsigned int sign = 1u << (bits - 1);

	return (int)((value ^ sign) - sign);
}

/* movz/movk sequence that materialises @value in x@rd; returns the word count. */
static unsigned int uf_mov_imm(unsigned int *out, unsigned int rd,
			       unsigned long value)
{
	unsigned int n = 0, k;

	for (k = 0; k < 4; k++) {
		const unsigned int half =
			(unsigned int)((value >> (16 * k)) & 0xffffu);

		if (k == 0)
			out[n++] = 0xd2800000u | (half << 5) | rd; /* movz */
		else if (half || (value >> (16 * k)) != 0)
			out[n++] = 0xf2800000u | (k << 21) | (half << 5) |
				   rd; /* movk */
	}
	return n;
}

/*
 * What an instruction reads and writes, for the classes that appear between an
 * adrp and its user. Returns 0 when the class is not understood, and the caller
 * then refuses: guessing about liveness is how a copy gets silently broken.
 */
static int uf_reads_writes(unsigned int insn, int *rd, int *rn)
{
	*rd = -1;
	*rn = -1;

	/* add/sub (immediate), logical (immediate): Rd, Rn */
	if ((insn & 0x1f000000u) == 0x11000000u ||
	    (insn & 0x1f000000u) == 0x12000000u) {
		*rd = (int)(insn & 0x1fu);
		*rn = (int)((insn >> 5) & 0x1fu);
		return 1;
	}
	/* add/sub (shifted register), logical (shifted register): Rd, Rn */
	if ((insn & 0x1f000000u) == 0x0b000000u ||
	    (insn & 0x1f000000u) == 0x0a000000u) {
		*rd = (int)(insn & 0x1fu);
		*rn = (int)((insn >> 5) & 0x1fu);
		return 1;
	}
	/* movz/movk/movn: Rd only */
	if ((insn & 0x1f800000u) == 0x12800000u) {
		*rd = (int)(insn & 0x1fu);
		return 1;
	}
	/* ldr/ldrsw (immediate, unsigned offset): Rt, Rn */
	if ((insn & UF_M_LDR) == UF_LDR_U64 ||
	    (insn & UF_M_LDR) == UF_LDR_U32 || (insn & UF_M_LDR) == UF_LDRSW) {
		*rd = (int)(insn & 0x1fu);
		*rn = (int)((insn >> 5) & 0x1fu);
		return 1;
	}
	return 0;
}

/* The instruction that uses the page an adrp computed. */
#define UF_PAIR_NONE (-1)
#define UF_PAIR_ADD 0
#define UF_PAIR_LOAD 1

static int uf_find_user(const unsigned int *src, unsigned int words,
			unsigned int i, unsigned int rd, unsigned int *out)
{
	unsigned int j;

	for (j = i + 1; j < words && j <= i + UF_LOOKAHEAD; j++) {
		int d = -1, n = -1;

		if (!uf_reads_writes(src[j], &d, &n))
			return UF_INLINE_EINSN;
		if (n == (int)rd) {
			*out = j;
			return UF_INLINE_OK;
		}
		if (d == (int)rd)
			return UF_INLINE_EINSN; /* the page is lost before it is used */
	}
	return UF_INLINE_EINSN;
}

static int uf_pair_kind(unsigned int insn, unsigned int rd)
{
	if ((insn & UF_M_ADDSUB) == UF_ADD_IMM ||
	    (insn & UF_M_ADDSUB) == UF_SUB_IMM) {
		if ((insn & 0x1fu) == rd && ((insn >> 5) & 0x1fu) == rd)
			return UF_PAIR_ADD;
		return UF_PAIR_NONE;
	}
	if ((insn & UF_M_LDR) == UF_LDR_U64 ||
	    (insn & UF_M_LDR) == UF_LDR_U32 || (insn & UF_M_LDR) == UF_LDRSW) {
		if (((insn >> 5) & 0x1fu) == rd)
			return UF_PAIR_LOAD;
		return UF_PAIR_NONE;
	}
	return UF_PAIR_NONE;
}

/* The page an adrp computes, as a value. */
static unsigned long uf_adrp_value(unsigned int insn, unsigned long insn_va)
{
	const unsigned long pc = insn_va & ~0xfffull;
	const long imm = (long)uf_sx(
		((insn >> 5) & 0x7ffffu) << 2 | ((insn >> 29) & 0x3u), 21);

	return (unsigned long)((long)pc + imm * 4096);
}

/* Is this a legal landing pad for an indirect call? */
static int uf_is_landing(unsigned int insn)
{
	if ((insn & ~0xe0u) == 0xd503241fu) /* bti c / j / jc */
		return 1;
	if ((insn & ~0xc0u) == 0xd503233fu) /* paciasp / pacibsp */
		return 1;
	return 0;
}

/* Where each source word lands in the copy; -1 when a pair consumed it. */
struct uf_layout {
	int out[UF_INSNS];
	unsigned int words;
	size_t size;
};

static int uf_plan(const unsigned int *src, unsigned int words,
		   unsigned long from_va, struct uf_layout *lay)
{
	unsigned int i;
	size_t at = 0;

	if (words == 0 || words > UF_INSNS)
		return UF_INLINE_ESIZE;
	lay->words = words;
	lay->size = 0;
	/* 0 means "not placed yet"; a pair marks its user -1 before the loop gets
	 * there, and the guard below is what keeps that word out of the copy. */
	for (i = 0; i < UF_INSNS; i++)
		lay->out[i] = 0;

	for (i = 0; i < words; i++) {
		const unsigned int insn = src[i];
		const unsigned long va =
			from_va + (unsigned long)i * UF_INLINE_INSN;

		if (lay->out[i] == -1)
			continue; /* consumed by the adrp pair before it */
		lay->out[i] = (int)(at / UF_INLINE_INSN);

		if ((insn & UF_M_BRANCH) == UF_B ||
		    (insn & UF_M_BRANCH) == UF_BL) {
			const long off =
				(long)uf_sx(insn & 0x03ffffffu, 26) * 4;
			const unsigned long target =
				(unsigned long)((long)va + off);
			const int internal =
				target >= from_va &&
				target < from_va + words * UF_INLINE_INSN;

			if (internal)
				at += UF_INLINE_INSN;
			else if ((insn & UF_M_BRANCH) == UF_BL)
				at += 5 *
				      UF_INLINE_INSN; /* movz/movk up to 4 + blr */
			else
				return UF_INLINE_ERANGE;
			continue;
		}

		if ((insn & UF_M_COND) == UF_CBZ ||
		    (insn & UF_M_COND) == UF_CBNZ ||
		    (insn & UF_M_COND) == UF_TBZ ||
		    (insn & UF_M_COND) == UF_TBNZ ||
		    (insn & UF_M_BCOND) == UF_BCOND) {
			const long off =
				(insn & UF_M_BCOND) == UF_BCOND ?
					(long)uf_sx((insn >> 5) & 0x7ffffu,
						    19) *
						4 :
				((insn & UF_M_COND) == UF_TBZ ||
				 (insn & UF_M_COND) == UF_TBNZ) ?
					(long)uf_sx((insn >> 5) & 0x3fffu, 14) *
						4 :
					(long)uf_sx((insn >> 5) & 0x7ffffu,
						    19) *
						4;
			const unsigned long target =
				(unsigned long)((long)va + off);

			if (target < from_va ||
			    target >= from_va + words * UF_INLINE_INSN)
				return UF_INLINE_ERANGE; /* no absolute form here */
			at += UF_INLINE_INSN;
			continue;
		}

		if ((insn & UF_M_ADRP) == UF_ADRP) {
			const unsigned int rd = insn & 0x1fu;
			unsigned int j;
			int kind;

			if (uf_find_user(src, words, i, rd, &j) != UF_INLINE_OK)
				return UF_INLINE_EINSN;
			kind = uf_pair_kind(src[j], rd);
			if (kind == UF_PAIR_NONE)
				return UF_INLINE_EINSN;

			/* The user is marked, and the words scheduled in between are left
			 * to the loop: they get their own slots after this reservation. */

			lay->out[j] = -1;
			at += (kind == UF_PAIR_LOAD ? 5 : 4) * UF_INLINE_INSN;
			continue;
		}

		/* PC-relative with no absolute form here: literal load, prfm
		 * literal, adr. Refusing is the point. */
		if ((insn & UF_M_LITERAL) == 0x58000000u ||
		    (insn & UF_M_LITERAL) == 0x98000000u ||
		    (insn & UF_M_LITERAL) == 0xd8000000u ||
		    (insn & UF_M_ADRP) == UF_ADR)
			return UF_INLINE_EINSN;

		at += UF_INLINE_INSN;
	}

	lay->size = at;
	return UF_INLINE_OK;
}

int uf_inline_entry(void *out, size_t out_size, unsigned long site_va,
		    unsigned long hook_va)
{
	unsigned int *dst = out;
	const long page_delta =
		(long)(hook_va & ~0xfffull) - (long)(site_va & ~0xfffull);
	const long imm21 = page_delta / 4096;

	if (out_size < UF_INLINE_ENTRY)
		return UF_INLINE_ESIZE;
	if (page_delta % 4096 || imm21 < -(1L << 20) || imm21 >= (1L << 20))
		return UF_INLINE_ERANGE; /* adrp reaches +-4 GB of pages */

	dst[0] = 0x90000000u | ((unsigned int)(imm21 & 0x3) << 29) |
		 ((unsigned int)((imm21 >> 2) & 0x7ffffu) << 5) | 17u;
	dst[1] = 0x91000000u | (((unsigned int)(hook_va & 0xfffu)) << 10) |
		 (17u << 5) | 17u;
	dst[2] = 0xd61f0220u; /* br x17 */
	return (int)UF_INLINE_ENTRY;
}

int uf_inline_relocate(void *to, size_t to_size, const void *from,
		       unsigned long from_va, unsigned long to_va, size_t len,
		       size_t *out_len)
{
	struct uf_layout lay;
	const unsigned int *src = from;
	unsigned int *dst = to;
	unsigned int words, i, prefix = 0;
	int rc;

	(void)to_va;
	if (len % UF_INLINE_INSN)
		return UF_INLINE_EINSN;
	words = (unsigned int)(len / UF_INLINE_INSN);
	rc = uf_plan(src, words, from_va, &lay);
	if (rc != UF_INLINE_OK)
		return rc;

	if (!uf_is_landing(src[0]))
		prefix = 1;
	if (lay.size + prefix * UF_INLINE_INSN > to_size ||
	    lay.size > UF_MAX_OUT)
		return UF_INLINE_ESIZE;
	if (prefix) {
		dst[0] =
			0xd503245fu; /* bti jc: both a call and a jump can land here */
		for (i = 0; i < words; i++)
			if (lay.out[i] >= 0)
				lay.out[i] += 1;
	}

	for (i = 0; i < words; i++) {
		const unsigned int insn = src[i];
		const unsigned long va =
			from_va + (unsigned long)i * UF_INLINE_INSN;
		const size_t at = (size_t)lay.out[i] * UF_INLINE_INSN;

		if (lay.out[i] < 0)
			continue;
#ifdef UF_INLINE_DEBUG
		uf_inline_dbg_insn = insn;
		uf_inline_dbg_index = i;
		uf_inline_dbg_stage = 2;
#endif

		if ((insn & UF_M_BRANCH) == UF_BL) {
			const long off =
				(long)uf_sx(insn & 0x03ffffffu, 26) * 4;
			const unsigned long target =
				(unsigned long)((long)va + off);

			if (target >= from_va &&
			    target < from_va + (unsigned long)words *
						       UF_INLINE_INSN) {
				const size_t to_word =
					(size_t)lay.out[(target - from_va) /
							UF_INLINE_INSN];
				const long new_off =
					(long)to_word * UF_INLINE_INSN -
					(long)at;

				if (new_off % 4 || new_off / 4 < -(1 << 25) ||
				    new_off / 4 >= (1 << 25))
					return UF_INLINE_ERANGE;
				dst[at / 4] = UF_BL |
					      ((new_off / 4) & 0x03ffffffu);
			} else {
				unsigned int tmp[4];
				unsigned int n =
					uf_mov_imm(tmp, UF_X17, target);
				unsigned int k;

				for (k = 0; k < n; k++)
					dst[at / 4 + k] = tmp[k];
				dst[at / 4 + n] = 0xd63f0220u; /* blr x17 */
				while (n + 1 < 5)
					dst[at / 4 + ++n] = 0xd503201fu;
			}
			continue;
		}

		if ((insn & UF_M_COND) == UF_CBZ ||
		    (insn & UF_M_COND) == UF_CBNZ ||
		    (insn & UF_M_COND) == UF_TBZ ||
		    (insn & UF_M_COND) == UF_TBNZ ||
		    (insn & UF_M_BCOND) == UF_BCOND) {
			const long off =
				(insn & UF_M_BCOND) == UF_BCOND ?
					(long)uf_sx((insn >> 5) & 0x7ffffu,
						    19) *
						4 :
				((insn & UF_M_COND) == UF_TBZ ||
				 (insn & UF_M_COND) == UF_TBNZ) ?
					(long)uf_sx((insn >> 5) & 0x3fffu, 14) *
						4 :
					(long)uf_sx((insn >> 5) & 0x7ffffu,
						    19) *
						4;
			const unsigned long target =
				(unsigned long)((long)va + off);
			const long to_word = (long)lay.out[(target - from_va) /
							   UF_INLINE_INSN];
			const long new_off =
				to_word * UF_INLINE_INSN - (long)at;
			const unsigned int bits =
				(insn & UF_M_BCOND) == UF_BCOND ? 19 :
				((insn & UF_M_COND) == UF_TBZ ||
				 (insn & UF_M_COND) == UF_TBNZ) ?
								  14 :
								  19;
			const long limit = 1L << (bits - 1);

			if (new_off % 4 || new_off / 4 < -limit ||
			    new_off / 4 >= limit)
				return UF_INLINE_ERANGE;
			dst[at / 4] = (insn & ~(((1u << bits) - 1u) << 5)) |
				      (((unsigned int)(new_off / 4) &
					((1u << bits) - 1u))
				       << 5);
			continue;
		}

		if ((insn & UF_M_ADRP) == UF_ADRP) {
			const unsigned int rd = insn & 0x1fu;
			unsigned int j, k, n;
			int kind;
			unsigned long value = uf_adrp_value(insn, va);
			unsigned int tmp[4];

			if (uf_find_user(src, words, i, rd, &j) != UF_INLINE_OK)
				return UF_INLINE_EINSN;
			kind = uf_pair_kind(src[j], rd);
			if (kind == UF_PAIR_LOAD) {
				const unsigned long size =
					((src[j] >> 30) & 0x1u) ? 8 : 4;

				value += ((src[j] >> 10) & 0xfffu) * size;
			} else {
				const unsigned long imm12 = (src[j] >> 10) &
							    0xfffu;
				const unsigned long shift =
					((src[j] >> 22) & 0x1u) ? 12 : 0;

				value = (src[j] & UF_M_ADDSUB) == UF_SUB_IMM ?
						value - (imm12 << shift) :
						value + (imm12 << shift);
			}

			n = uf_mov_imm(tmp, rd, value);
			for (k = 0; k < n; k++)
				dst[at / 4 + k] = tmp[k];
			while (n < 4)
				dst[at / 4 + n++] =
					0xd503201fu; /* keep the layout */
			if (kind == UF_PAIR_LOAD)
				dst[at / 4 + 4] = src[j] & ~(0xfffu << 10);
			continue;
		}

		dst[at / 4] = insn;
	}

	if (out_len)
		*out_len = lay.size + prefix * UF_INLINE_INSN;
	return UF_INLINE_OK;
}
