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
 * inline.h - the runtime side of an inline hook: build a callable copy of a
 * kernel function, and the entry patch that sends callers to us instead.
 *
 * The copy exists because of the two things a module cannot do: it cannot jump
 * back into the middle of kernel text (the pages carry BTI, so an indirect branch
 * must land on a bti/paciasp instruction, which no function's middle is), and it
 * cannot place its own trampoline inside the kernel image the way an image
 * patcher does. Copying the whole function avoids both: the copy is entered at
 * its own beginning and returns normally, so nothing jumps into the middle of
 * anything.
 *
 * Relocation is deliberate and narrow. An instruction whose PC-relative operand
 * points inside the function keeps its encoding -- the copy is contiguous and in
 * order, so those distances are unchanged -- and only the ones that leave the
 * function (adrp/add pairs and bl targets) are rewritten into absolute form. Any
 * encoding this file does not know is a refusal (-ENOTSUP), never a guess: a
 * silently mis-relocated function would be worse than no hook at all.
 */

/* One instruction is 4 bytes; the longest rewritten form is 20 (movz/movk*4 + blr). */
#define UF_INLINE_INSN 4u

/* Why a relocation failed. */
#define UF_INLINE_OK 0
#define UF_INLINE_ESIZE (-1) /* the destination buffer is too small */
#define UF_INLINE_EINSN (-2) /* an instruction this file does not handle */
#define UF_INLINE_ERANGE (-3) /* a branch target outside the function */

/*
 * Copy the function that ran at @from_va (its bytes at @from, @len long) into
 * @to, where it will run at @to_va. Returns the length written in @out_len and
 * UF_INLINE_OK, or a UF_INLINE_E* code.
 */
int uf_inline_relocate(void *to, size_t to_size, const void *from,
		       unsigned long from_va, unsigned long to_va, size_t len,
		       size_t *out_len);

/*
 * The entry patch: three instructions and no literal pool. A literal load reaches
 * only 1 MB, and a module sits far from the kernel's text, so the jump has to be
 * built from adrp/add, which reach +-4 GB:
 *
 *     adrp x17, hook ; add x17, x17, #:lo12:hook ; br x17
 *
 * The hook has to start with a landing pad, because that br is an indirect jump.
 * Returns the byte count, or a UF_INLINE_E* code.
 */
#define UF_INLINE_ENTRY 12u
int uf_inline_entry(void *out, size_t out_size, unsigned long site_va,
		    unsigned long hook_va);
