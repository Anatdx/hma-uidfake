// SPDX-License-Identifier: GPL-2.0
#include "inline_entry.h"

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

int uf_inline_veneer(void *out, size_t out_size, unsigned long target,
		     int landing)
{
	unsigned int words[UF_INLINE_LANDING_VENEER_SIZE / UF_INLINE_INSN];
	const size_t len = landing ? UF_INLINE_LANDING_VENEER_SIZE :
				     UF_INLINE_VENEER_SIZE;
	size_t literal;

	if (!out || out_size < len)
		return UF_INLINE_ESIZE;
	if (((unsigned long)out | target) & (UF_INLINE_INSN - 1))
		return UF_INLINE_EINSN;
	if (landing) {
		words[0] = 0xd50324dfu; /* BTI jc */
		words[1] = 0x58000070u; /* LDR x16, PC + 12 */
		words[2] = 0xd61f0200u; /* BR x16 */
		words[3] = 0xd503201fu; /* NOP, align the literal */
		literal = 4;
	} else {
		words[0] = 0x58000050u; /* LDR x16, PC + 8 */
		words[1] = 0xd61f0200u; /* BR x16 */
		literal = 2;
	}
	words[literal] = (unsigned int)target;
	words[literal + 1] = (unsigned int)(target >> 32);
	memcpy(out, words, len);
	return (int)len;
}

static long entry_sx(unsigned int value, unsigned int bits)
{
	return (value & (1u << (bits - 1))) ? (long)value - (1L << bits) :
					      (long)value;
}

static int entry_landing(unsigned int word)
{
	return word == 0xd503245fu || word == 0xd50324dfu ||
	       word == 0xd503233fu || word == 0xd503237fu;
}

static int entry_displaceable(unsigned int word)
{
	if (entry_landing(word) || word == 0xd503201fu)
		return 1;
	/* Compiler SCS push: STR x30, [x18], #8; no other arbitrary store. */
	if (word == 0xf800865eu)
		return 1;
	/* STP of two X registers relative to the kernel stack pointer. */
	if ((word & 0xfe4003e0u) == 0xa80003e0u)
		return 1;
	/* Integer add/subtract immediate, including ordinary stack allocation. */
	if ((word & 0x1f000000u) == 0x11000000u)
		return 1;
	/* Integer logical/add/subtract register operations and MOV aliases. */
	if ((word & 0x1f000000u) == 0x0a000000u ||
	    (word & 0x1f000000u) == 0x0b000000u)
		return 1;
	/* MOVN/MOVZ/MOVK immediates. */
	return (word & 0x1f800000u) == 0x12800000u;
}

static int entry_body_safe(const unsigned int *src, size_t len,
			   unsigned long from_va, size_t prefix)
{
	size_t offset;
	const unsigned long end = from_va + prefix;

	for (offset = prefix; offset < len; offset += UF_INLINE_INSN) {
		const unsigned int word = src[offset / UF_INLINE_INSN];
		const unsigned long pc = from_va + offset;
		unsigned long target;
		unsigned int bits = 0, field = 0;

		if ((word & 0x7c000000u) == 0x14000000u) {
			bits = 26;
			field = word & 0x03ffffffu;
		} else if ((word & 0xff000000u) == 0x54000000u ||
			   (word & 0x7e000000u) == 0x34000000u) {
			bits = 19;
			field = (word >> 5) & 0x7ffffu;
		} else if ((word & 0x7e000000u) == 0x36000000u) {
			bits = 14;
			field = (word >> 5) & 0x3fffu;
		}
		if (bits) {
			target =
				pc + (unsigned long)(entry_sx(field, bits) * 4);
			if (target >= from_va && target < end)
				return 0;
		}
		if ((word & 0x1f000000u) == 0x10000000u) {
			const unsigned int imm =
				((word >> 29) & 3u) |
				(((word >> 5) & 0x7ffffu) << 2);
			const long displacement = entry_sx(imm, 21);

			if (word & 0x80000000u) {
				target = (pc & ~0xfffUL) +
					 (unsigned long)(displacement * 4096);
				/* An ADRP could be followed by any within-page add. */
				if (target >= (from_va & ~0xfffUL) &&
				    target <= ((end - 1) & ~0xfffUL))
					return 0;
			} else {
				target = pc + (unsigned long)displacement;
				if (target >= from_va && target < end)
					return 0;
			}
		}
		/* Cannot establish targets of BR/BLR or authenticated variants. */
		if ((word & 0xfe000000u) == 0xd6000000u &&
		    word != 0xd65f03c0u && word != 0xd65f0bffu &&
		    word != 0xd65f0fffu)
			return 0;
	}
	return 1;
}

int uf_inline_trampoline(void *out, size_t out_size, const void *from,
			 unsigned long from_va, unsigned long to_va, size_t len,
			 size_t patch_offset, size_t *out_len)
{
	unsigned int scratch[UF_INLINE_TRAMPOLINE_MAX / UF_INLINE_INSN];
	const unsigned int *src = from;
	const size_t prefix = patch_offset + UF_INLINE_INSN;
	size_t written = 0, offset;
	int rc;

	if (out_len)
		*out_len = 0;
	if (!out || !from || !len || len > UF_INLINE_MAX_SOURCE ||
	    (patch_offset != 0 && patch_offset != UF_INLINE_INSN) ||
	    len <= prefix || out_size < prefix + UF_INLINE_INSN)
		return UF_INLINE_ESIZE;
	if ((((unsigned long)out | (unsigned long)from | from_va | to_va | len) &
	     (UF_INLINE_INSN - 1)) ||
	    from_va + len < from_va || to_va + UF_INLINE_TRAMPOLINE_MAX < to_va)
		return UF_INLINE_EINSN;
	if ((unsigned long)out < (unsigned long)from + len &&
	    (unsigned long)from < (unsigned long)out + prefix + UF_INLINE_INSN)
		return UF_INLINE_EINSN;
	if (entry_landing(src[0]) != (patch_offset == UF_INLINE_INSN))
		return UF_INLINE_EINSN;
	for (offset = 0; offset < prefix; offset += UF_INLINE_INSN)
		if (!entry_displaceable(src[offset / UF_INLINE_INSN]))
			return UF_INLINE_EINSN;
	if (!entry_body_safe(src, len, from_va, prefix))
		return UF_INLINE_EINSN;

	rc = uf_inline_relocate(scratch, sizeof(scratch), from, from_va, to_va,
				prefix, &written);
	if (rc)
		return rc;
	if (written != prefix)
		return UF_INLINE_EINSN;
	rc = uf_inline_entry(&scratch[written / UF_INLINE_INSN],
			     sizeof(scratch) - written, to_va + written,
			     from_va + prefix);
	if (rc != UF_INLINE_ENTRY)
		return rc < 0 ? rc : UF_INLINE_EINSN;
	written += UF_INLINE_INSN;
	memcpy(out, scratch, written);
	if (out_len)
		*out_len = written;
	return UF_INLINE_OK;
}
