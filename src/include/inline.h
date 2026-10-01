/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/stddef.h>
#else
#include <stddef.h>
#include <stdint.h>
#endif

/*
 * Runtime A64 function copies, derived from the running kernel's instructions.
 * Internal branches are remapped through the complete output layout. ADRP
 * preserves its original page value and leaves all consumers in place. External
 * branches remain direct; unsupported PC-relative forms or unreachable targets
 * are refused before writing output. This is not an arbitrary-code translator:
 * callers must supply a complete function without embedded data or external
 * fixups (such as exception-table entries).
 */
#define UF_INLINE_INSN 4u
#define UF_INLINE_MAX_SOURCE 1024u
#define UF_INLINE_MAX_COPY (UF_INLINE_MAX_SOURCE * 4u + UF_INLINE_INSN)

#define UF_INLINE_OK 0
#define UF_INLINE_ESIZE (-1) /* empty/oversize input or insufficient output */
#define UF_INLINE_EINSN (-2) /* unsupported encoding or unaligned input */
#define UF_INLINE_ERANGE (-3) /* a relative target cannot be represented */

/*
 * @from and @to must be disjoint, instruction-aligned buffers. Addresses denote
 * the runtime locations, which can differ from those buffers. No output bytes
 * are written on failure; @out_len is zero on failure if provided. The copy
 * begins with the original first instruction; an indirect caller must arrange
 * a BTI landing pad before it when required.
 */
int uf_inline_relocate(void *to, size_t to_size, const void *from,
		       unsigned long from_va, unsigned long to_va, size_t len,
		       size_t *out_len);

/*
 * One B instruction, with no scratch register or indirect landing-pad demand.
 * The live site must be aligned and the target within [-128 MiB, +128 MiB-4].
 * The installer must preserve an existing entry BTI instruction and select the
 * following instruction as @site_va. Publishing still needs an SMP instruction
 * synchronization protocol; this helper only builds the replacement word.
 */
#define UF_INLINE_ENTRY 4u
int uf_inline_entry(void *out, size_t out_size, unsigned long site_va,
		    unsigned long hook_va);
