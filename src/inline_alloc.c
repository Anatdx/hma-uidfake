// SPDX-License-Identifier: GPL-2.0
/*
 * Allocate a branch island near the running kernel, without borrowing kernel
 * text or relying on its link address. The native vmap allocator owns the VA
 * reservation, page allocation and page tables. The private mapping starts
 * RW/NX and becomes RO/X before an entry branch can be published.
 */
#include <asm/pgtable.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include "uidfake.h"
#include "inline_alloc.h"

#define UF_BRANCH_REACH (128UL * 1024 * 1024)

typedef void *(*uf_vmalloc_range_t)(unsigned long, unsigned long, unsigned long,
				    unsigned long, gfp_t, pgprot_t,
				    unsigned long, int, const void *);
typedef int (*uf_change_mem_t)(unsigned long, int);
typedef void (*uf_flush_icache_t)(unsigned long, unsigned long);
typedef int (*uf_vmap_addr_t)(const void *);

/* Look up the running implementation. In particular, checking VAs through the
 * native predicate avoids importing the build kernel's VA_BITS assumptions. */
static uf_vmalloc_range_t g_alloc;
static uf_change_mem_t g_ro, g_x;
static uf_flush_icache_t g_flush;
static uf_vmap_addr_t g_is_vmap;

static int resolve_allocators(void)
{
	if (g_alloc)
		return 0;
	g_ro = (void *)uidfake_lookup("set_memory_ro");
	g_x = (void *)uidfake_lookup("set_memory_x");
	g_flush = (void *)uidfake_lookup("caches_clean_inval_pou");
	if (!g_flush)
		g_flush = (void *)uidfake_lookup("__flush_icache_range");
	g_is_vmap = (void *)uidfake_lookup("is_vmalloc_or_module_addr");
	if (!g_ro || !g_x || !g_flush || !g_is_vmap)
		return -EOPNOTSUPP;

	/* With software KASAN and no KASAN_VMALLOC, a module shadow allocation
	 * needs additional alignment and a separate lifetime. That is not a
	 * supported near-allocation configuration yet. HW_TAGS/KASAN_VMALLOC
	 * handle it within the native vmalloc path, as for module_alloc(). The
	 * out-of-line shadow helpers exist only in the unsupported case. */
	if (uidfake_lookup("kasan_alloc_module_shadow") ||
	    uidfake_lookup("kasan_module_alloc"))
		return -EOPNOTSUPP;

	g_alloc = (void *)uidfake_lookup("__vmalloc_node_range");
	if (!g_alloc)
		g_alloc = (void *)uidfake_lookup("__vmalloc_node_range_noprof");
	return g_alloc ? 0 : -EOPNOTSUPP;
}

static noinline bool __nocfi valid_vmap_range(unsigned long start,
					      unsigned long end)
{
	return start < end && g_is_vmap((void *)start) &&
	       g_is_vmap((void *)(end - 1));
}

static noinline void *__nocfi allocate_range(unsigned long start,
					     unsigned long end)
{
	/* Keep the allocator's trailing guard page. No huge mappings: native
	 * set_memory_* only accepts VM_ALLOC mappings made of individual PTEs.
	 * The reset flag lets vfree restore any read-only direct-map aliases. */
	return g_alloc(PAGE_SIZE, PAGE_SIZE, start, end,
		       GFP_KERNEL | __GFP_NOWARN, PAGE_KERNEL,
		       VM_FLUSH_RESET_PERMS, NUMA_NO_NODE,
		       __builtin_return_address(0));
}

static void *try_range(unsigned long start, unsigned long end)
{
	void *allocation;
	unsigned long addr;

	if (start >= end || end - start < 2 * PAGE_SIZE ||
	    !valid_vmap_range(start, end))
		return NULL;
	allocation = allocate_range(start, end);
	if (!allocation)
		return NULL;
	/* This follows arm64 module_alloc/execmem: code addresses and PC-relative
	 * literal loads use the kernel tag, not a random data allocation tag. */
	/* Do not use the build-configuration-dependent kasan_reset_tag macro:
	 * the running kernel may enable HW_TAGS when the DDK does not. For a
	 * kernel-half ARM64 VA, resetting bits 63:56 gives the kernel tag. */
	addr = (unsigned long)allocation | (0xffUL << 56);
	if (!IS_ALIGNED(addr, PAGE_SIZE) || addr < start ||
	    addr > end - 2 * PAGE_SIZE) {
		vfree(allocation);
		return NULL;
	}
	return (void *)addr;
}

int uidfake_inline_alloc(struct uf_inline_region *region, unsigned long target)
{
	unsigned long image_start, image_end, start, end;
	void *allocation;
	int rc;

	if (!region || region->addr || !target || (target & 3))
		return -EINVAL;
	rc = resolve_allocators();
	if (rc)
		return rc;
	image_start = uidfake_lookup_raw("_text");
	image_end = uidfake_lookup_raw("_end");
	if (!image_start || image_end <= image_start || target < image_start ||
	    target >= image_end || image_end > ULONG_MAX - 2 * PAGE_SIZE)
		return -ENOEXEC;
	if (target < UF_BRANCH_REACH || target > ULONG_MAX - UF_BRANCH_REACH)
		return -ERANGE;

	/* Leave a complete page of distance slack on each side. Both the entry
	 * and a return branch anywhere in this page then fit signed imm26. */
	start = ALIGN(target - UF_BRANCH_REACH + PAGE_SIZE, PAGE_SIZE);
	end = (target + UF_BRANCH_REACH - PAGE_SIZE) & PAGE_MASK;
	image_start &= PAGE_MASK;
	image_end = PAGE_ALIGN(image_end) + PAGE_SIZE;

	/* The kernel registers its mapped segments in the vmap tree. Excluding
	 * the entire image explicitly also protects unmapped padding and freed
	 * init sections from becoming an island by accident. */
	allocation = try_range(start, min(end, image_start));
	if (!allocation)
		allocation = try_range(max(start, image_end), end);
	if (!allocation)
		return -ENOMEM;
	region->addr = allocation;
	region->size = PAGE_SIZE;
	region->sealed = false;
	region->published = false;
	return 0;
}

static noinline int __nocfi seal_range(unsigned long addr, size_t size)
{
	int rc;

	/* The caller has finished all writes; no execution is possible yet.
	 * Publication performs a stop_machine ISB on every online CPU after
	 * cache maintenance, so no CPU may execute stale island instructions. */
	g_flush(addr, addr + size);
	rc = g_ro(addr, size / PAGE_SIZE);
	if (rc)
		return rc;
	return g_x(addr, size / PAGE_SIZE);
}

int uidfake_inline_seal(struct uf_inline_region *region)
{
	int rc;

	if (!region || !region->addr || region->size != PAGE_SIZE ||
	    region->sealed || region->published)
		return -EINVAL;
	rc = seal_range((unsigned long)region->addr, region->size);
	if (!rc)
		region->sealed = true;
	return rc;
}

void uidfake_inline_free(struct uf_inline_region *region)
{
	if (!region || !region->addr)
		return;
	if (WARN_ON_ONCE(region->published))
		return;
	vfree(region->addr);
	memset(region, 0, sizeof(*region));
}
