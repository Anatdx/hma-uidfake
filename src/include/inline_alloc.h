/* SPDX-License-Identifier: GPL-2.0 */
#ifndef UIDFAKE_INLINE_ALLOC_H
#define UIDFAKE_INLINE_ALLOC_H

#include <linux/types.h>

/* Initialization-only ownership. Once published, the containing hook and its
 * module are pinned, and this page must survive until reboot as well. */
struct uf_inline_region {
	void *addr;
	size_t size;
	bool sealed;
	bool published;
};

int uidfake_inline_alloc(struct uf_inline_region *region, unsigned long target);
int uidfake_inline_seal(struct uf_inline_region *region);
void uidfake_inline_free(struct uf_inline_region *region);

#endif
