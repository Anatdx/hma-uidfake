/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#include "inline.h"

/* One or two displaced instructions and a direct branch to the native body. */
#define UF_INLINE_TRAMPOLINE_MAX 12u

/* Private veneers entered at an ABI function boundary may clobber IP0/x16.
 * The 16-byte form is reached only by a direct BL. The 24-byte form has a
 * BTI jc landing; both keep the 64-bit target literal eight-byte aligned when
 * the caller places the veneer at an eight-byte-aligned address.
 */
#define UF_INLINE_VENEER_SIZE 16u
#define UF_INLINE_LANDING_VENEER_SIZE 24u
#define UF_INLINE_ISLAND_TRAMPOLINE 32u
#define UF_INLINE_ISLAND_SIZE 48u
int uf_inline_veneer(void *out, size_t out_size, unsigned long target,
		     int landing);

/*
 * Build an original-call trampoline from the running function. @len is its
 * complete symbol-sized snapshot, not just its prologue. @patch_offset is zero
 * or four; four is required for a leading BTI c/jc or PACIASP/PACIBSP, which
 * the installer preserves at the live entry. @to_va names the first displaced
 * instruction: the caller adds any synthetic BTI landing before that address.
 *
 * Only explicit non-PC-relative entry instruction classes are displaced.
 * Interior direct branches/address-taking into the prefix, indirect branches
 * and unknown prefix instructions are refused. The native remainder stays at
 * its original address, including its alternatives and exception-table PCs.
 * This assumes normal compiler function-entry calling conventions; it cannot
 * discover external callers that enter an interior address.
 *
 * Source/destination buffers must be disjoint and four-byte aligned. Output is
 * untouched on failure and @out_len is zero. All checks precede publication.
 */
int uf_inline_trampoline(void *out, size_t out_size, const void *from,
			 unsigned long from_va, unsigned long to_va, size_t len,
			 size_t patch_offset, size_t *out_len);
