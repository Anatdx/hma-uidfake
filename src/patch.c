// SPDX-License-Identifier: GPL-2.0
/*
 * patch.c - write a few bytes into read-only kernel or module text.
 *
 * Kernel text is mapped read-only and the helpers that would normally make it
 * writable (set_memory_rw, text_poke) are not exported to modules. Instead the
 * physical address is translated through init_mm and the page is mapped again
 * writable through the kernel's own fixmap window -- the way the kernel itself
 * pokes text -- and a nofault copy does the write, so a translation that went
 * wrong is an error and not a fault. The caches are cleaned afterwards and the
 * synchronous path stops all other CPUs, because one of them can be executing
 * the very instruction being replaced.
 *
 * The technique is the one every out-of-tree patcher on arm64 ends up using;
 * this is an independent implementation.
 */
#include <asm/cacheflush.h>
#include <asm/fixmap.h>
#include <asm/pgtable.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/stop_machine.h>
#include <linux/string.h>

#include "uidfake.h"

static int probe_noop(struct kprobe *p, struct pt_regs *r)
{
	return 0;
}

/*
 * Symbol lookup, the way KernelSU does it on arm64: resolve a name through
 * kallsyms, accept the CFI jump-table variant of it as well (that is what a call
 * site reaches on a CFI kernel), and fall back to walking the whole kallsyms
 * table when kallsyms_lookup_name() cannot be had. Nothing here reads an offset
 * out of a function body.
 *
 * kallsyms_lookup_name() and kallsyms_on_each_symbol() are not exported to
 * modules, so their own addresses come from a probe registered on them -- kprobe
 * resolves .symbol_name through kallsyms internally -- unregistered immediately,
 * so nothing stays behind.
 */
/*
 * Pre-kCFI kernels (before 6.1) check an indirect call against the callee's jump
 * table, so the address a call has to carry is the .cfi_jt one; from 6.1 the check
 * is a type hash on the function itself and there is no jump table to prefer. The
 * split is the one KernelSU makes with USE_KCFI.
 */
#define UF_USE_KCFI (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))

static unsigned long lookup_exported(const char *symbol)
{
	struct kprobe kp = { .symbol_name = symbol, .pre_handler = probe_noop };
	unsigned long addr;

	if (register_kprobe(&kp))
		return 0;
	addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	return addr;
}

/*
 * The call goes to an address kallsyms handed us, and on a pre-kCFI kernel the
 * indirect-call check consults the callee's jump table: a function that reaches a
 * resolved address is marked __nocfi, the way KernelSU marks its dispatcher.
 */
static noinline unsigned long __nocfi lookup_name(const char *name)
{
	unsigned long (*fn)(const char *) =
		(void *)lookup_exported("kallsyms_lookup_name");

	return fn ? fn(name) : 0;
}

struct find_ctx {
	const char *name;
	unsigned long addr;
	unsigned long next; /* the following symbol: where the body ends */
};

/*
 * The walk has to see every symbol: the one after a match is the end of it, so it
 * cannot stop at the match itself.
 */
static int find_symbol_cb(void *data, const char *name, unsigned long addr)
{
	struct find_ctx *ctx = data;

	if (ctx->addr && addr > ctx->addr && (!ctx->next || addr < ctx->next))
		ctx->next = addr;
	if (!ctx->addr && name && strcmp(name, ctx->name) == 0)
		ctx->addr = addr;
#if !UF_USE_KCFI
	/* The jump-table variant is the one a call site can reach: prefer it, and
	 * stop looking once it is found. */
	{
		const size_t len = ctx->name ? strlen(ctx->name) : 0;
		const char *suffix = ".cfi_jt";

		if (name && len && strncmp(name, ctx->name, len) == 0 &&
		    strcmp(name + len, suffix) == 0) {
			ctx->addr = addr;
			return 1;
		}
	}
#endif
	return 0;
}

/* For kernels before 6.6 the callback carries the module a symbol came from: a
 * module may shadow a name, so those are skipped. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
static int find_symbol_cb_mod(void *data, const char *name, struct module *mod,
			      unsigned long addr)
{
	if (mod)
		return 0;
	return find_symbol_cb(data, name, addr);
}
#endif

static noinline void __nocfi find_symbol(const char *name, struct find_ctx *ctx)
{
	ctx->name = name;
	ctx->addr = 0;
	ctx->next = 0;
	/*
	 * The walk takes the callback first and its data second -- both signatures
	 * do, the one whose callback has the module argument and the one without.
	 * Passing them the other way round hands the kernel a stack address to jump
	 * to, which is a fault the moment it is reached.
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	{
		int (*walk)(int (*)(void *, const char *, unsigned long),
			    void *) =
			(void *)lookup_exported("kallsyms_on_each_symbol");

		if (walk)
			walk(find_symbol_cb, ctx);
	}
#else
	/*
	 * The older signature takes the callback with the module argument, so it is
	 * called through a small shim with the same shape.
	 */
	{
		int (*walk)(int (*)(void *, const char *, struct module *,
				    unsigned long),
			    void *) =
			(void *)lookup_exported("kallsyms_on_each_symbol");

		if (walk)
			walk(find_symbol_cb_mod, ctx);
	}
#endif
}

unsigned long uidfake_lookup(const char *name)
{
	unsigned long addr;

#if !UF_USE_KCFI
	char cfi[KSYM_NAME_LEN + 16];

	/*
	 * A call site on these kernels reaches the .cfi_jt variant, and the plain
	 * address fails its check: take the jump-table symbol when there is one.
	 * selinux_setprocattr becomes selinux_setprocattr.cfi_jt.
	 */
	if (!strchr(name, '.') &&
	    snprintf(cfi, sizeof(cfi), "%s.cfi_jt", name) < (int)sizeof(cfi)) {
		addr = lookup_name(cfi);
		if (addr)
			return addr;
	}
#endif

	addr = lookup_name(name);
	if (addr)
		return addr;

	{
		struct find_ctx ctx;

		find_symbol(name, &ctx);
		return ctx.addr;
	}
}

/*
 * The same lookup without preferring the jump-table variant. A table that holds
 * function addresses (an LSM hook list, for one) holds the plain symbol, so a
 * name has to be resolvable to exactly that to be matched against it.
 */
unsigned long uidfake_lookup_raw(const char *name)
{
	unsigned long addr = lookup_name(name);

	if (addr)
		return addr;

	{
		struct find_ctx ctx;

		find_symbol(name, &ctx);
		return ctx.addr;
	}
}

/*
 * A symbol's address and extent, for a caller that has to copy the function whole:
 * the following symbol bounds it, and the walk already computes that.
 */
bool uidfake_symbol_range(const char *name, unsigned long *addr,
			  unsigned long *size)
{
	struct find_ctx ctx;

	find_symbol(name, &ctx);
	if (!ctx.addr || ctx.next <= ctx.addr)
		return false;
	*addr = ctx.addr;
	*size = ctx.next - ctx.addr;
	return true;
}
/*
 * Symbols the patcher needs at run time. init_mm is not exported,
 * kimage_voffset/kallsyms are not either, so all of them go through the same
 * transient-probe resolver.
 */
static struct mm_struct *patch_mm;

/* defined below; the calibration at load asks both of them about _stext */
static phys_addr_t phys_from_virt(unsigned long addr);
static phys_addr_t image_phys(unsigned long addr);

/*
 * The ranges this module may write: the kernel image, and its own text, where the
 * copy of a hooked function and the stub that jumps into it live.
 */
static unsigned long g_mod_start;
static unsigned long g_mod_end;
static unsigned long g_text_start;
static unsigned long g_text_end;

static bool writable_range(unsigned long addr, size_t len)
{
	if (g_text_start && g_text_end && addr >= g_text_start &&
	    addr + len <= g_text_end)
		return true;
	if (g_mod_start && g_mod_end && addr >= g_mod_start &&
	    addr + len <= g_mod_end)
		return true;
	return false;
}

static unsigned long *g_kimage_voffset;
static unsigned long *g_memstart_addr;
static bool g_offset_warned;
/*
 * Whether the page table walk agrees with kimage_voffset on this kernel. The walk
 * uses this module's view of struct mm_struct and of the page table geometry, and
 * a kernel of the same version can be built with a different VA size; the image
 * offset does not care about either. So the walk is calibrated once against it
 * and ignored from there on if it disagrees -- the offset is the answer that holds
 * on every configuration, and it is the one the write depends on.
 */
static unsigned long g_vmemmap;
static bool g_walk_usable = true;
/*
 * FIXADDR_TOP as this kernel has it, worked out from the kernel's own vmemmap
 * pointer: memory.h defines it as VMEMMAP_START - SZ_32M, and vmemmap is that
 * region's base at run time. This module's compiled FIXADDR_TOP comes from the
 * config it was built with, so on a kernel whose VA size differs the two
 * disagree -- and then the slot this module thinks it mapped is not the one the
 * kernel made. The alias is proved before it is used either way, so this is how
 * such a kernel gets used at all rather than only refused. Zero when vmemmap is
 * not resolvable, which leaves the compiled value as the only candidate.
 */
static unsigned long g_fixmap_top;

/*
 * Neither __set_fixmap() nor copy_to_kernel_nofault() is exported to modules, so
 * both are resolved by name and reached through these. The fixmap window is the
 * kernel's own way in -- it builds the mapping, with attributes the image's own
 * read-only mapping does not have -- and the nofault copy turns a translation
 * that went wrong into an error instead of a fault.
 */
static unsigned long g_set_fixmap_addr;
static unsigned long g_copy_nofault_addr;
static unsigned long g_copy_from_nofault_addr;

typedef void (*uf_set_fixmap_t)(enum fixed_addresses idx, phys_addr_t phys,
				pgprot_t prot);
typedef long (*uf_copy_nofault_t)(void *dst, const void *src, size_t size);
typedef long (*uf_copy_from_nofault_t)(void *dst, const void *src, size_t size);

static noinline void __nocfi patch_set_fixmap(enum fixed_addresses idx,
					      phys_addr_t phys, pgprot_t prot)
{
	((uf_set_fixmap_t)g_set_fixmap_addr)(idx, phys, prot);
}

static noinline long __nocfi patch_copy_nofault(void *dst, const void *src,
						size_t size)
{
	return ((uf_copy_nofault_t)g_copy_nofault_addr)(dst, src, size);
}

/*
 * Read kernel text for a diagnostic. It is the same nofault copy the patcher
 * uses, exposed because the debug dump reads a symbol it is about to rewrite:
 * an ordinary load could fault on a page this context may not take.
 */
static noinline long __nocfi patch_copy_from_nofault(void *dst, const void *src,
						     size_t size);

/*
 * The first bytes of a symbol this module is about to copy, through the nofault
 * copy. It is what makes a device's own code available for a host test, and what
 * tells a reader which encoding a refusal was about.
 */
void uidfake_debug_dump(const char *name, unsigned long addr,
			unsigned long size)
{
	u8 buf[64];
	unsigned long n = size < sizeof(buf) ? size : sizeof(buf);
	unsigned long i;

	if (!UF_DEBUG_ON() || n == 0)
		return;
	if (!uidfake_read((const void *)addr, buf, n))
		return;
	pr_info("uidfake: %s at %#lx, %lu of %lu bytes:\n", name, addr, n,
		size);
	for (i = 0; i < n; i += 16)
		pr_info("uidfake:  %*phN\n", (int)(n - i < 16 ? n - i : 16),
			buf + i);
}

bool uidfake_read(const void *src, void *dst, size_t len)
{
	if (!g_copy_from_nofault_addr)
		return false;
	return patch_copy_from_nofault(dst, src, len) == 0;
}

static noinline long __nocfi patch_copy_from_nofault(void *dst, const void *src,
						     size_t size)
{
	return ((uf_copy_from_nofault_t)g_copy_from_nofault_addr)(dst, src,
								  size);
}

int uidfake_patch_init(void)
{
	/* The kernel's own extent: every patch target has to be inside it, or the
	 * write would land somewhere it has no business being. */
	g_text_start = uidfake_lookup("_stext");
	g_text_end = uidfake_lookup("_end");

	/*
	 * This module's own text: the copy of a hooked function and the stub that
	 * jumps into it are written there, so the patcher has to know the range.
	 * The layout field changed shape in 6.4 - module_layout gave way to an
	 * array of module_memory - so both spellings are read here.
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	g_mod_start = (unsigned long)THIS_MODULE->mem[MOD_TEXT].base;
	g_mod_end = g_mod_start + THIS_MODULE->mem[MOD_TEXT].size;
#else
	g_mod_start = (unsigned long)THIS_MODULE->core_layout.base;
	g_mod_end = g_mod_start + THIS_MODULE->core_layout.text_size;
#endif

	patch_mm = (struct mm_struct *)uidfake_lookup("init_mm");
	g_kimage_voffset = (unsigned long *)uidfake_lookup("kimage_voffset");
	g_memstart_addr = (unsigned long *)uidfake_lookup("memstart_addr");
	g_set_fixmap_addr = uidfake_lookup("__set_fixmap");
	g_copy_nofault_addr = uidfake_lookup("copy_to_kernel_nofault");
	if (!g_copy_nofault_addr)
		g_copy_nofault_addr =
			uidfake_lookup("__copy_to_kernel_nofault");
	g_copy_from_nofault_addr = uidfake_lookup("copy_from_kernel_nofault");
	if (!g_copy_from_nofault_addr)
		g_copy_from_nofault_addr =
			uidfake_lookup("__copy_from_kernel_nofault");
	if (UF_DEBUG_ON())
		pr_info("uidfake: init_mm=%px kimage_voffset=%px memstart_addr=%px set_fixmap=%px nofault=%px mod=%#lx-%#lx\n",
			(void *)patch_mm, (void *)g_kimage_voffset,
			(void *)g_memstart_addr, (void *)g_set_fixmap_addr,
			(void *)g_copy_nofault_addr, (unsigned long)g_mod_start,
			(unsigned long)g_mod_end);
	if (!patch_mm || !g_set_fixmap_addr)
		return -ENOENT;

	/*
	 * One calibration, at load: if the walk and the image offset disagree about
	 * where the kernel's own text is, the walk is the one that is wrong on this
	 * device -- it goes through this module's view of struct mm_struct and of the
	 * page table geometry, and a kernel of the same version can be built with a
	 * different VA size. It is the offset that holds on every configuration, and
	 * the offset is what the write needs, so the walk steps aside.
	 */
	g_vmemmap = uidfake_lookup_raw("vmemmap");
	if (g_vmemmap)
		g_fixmap_top = g_vmemmap - SZ_32M;
	if (UF_DEBUG_ON())
		pr_info("uidfake: vmemmap=%px fixmap_top=%#lx (this build's: %#lx)\n",
			(void *)g_vmemmap, g_fixmap_top,
			(unsigned long)__fix_to_virt(FIX_TEXT_POKE0) +
				((unsigned long)FIX_TEXT_POKE0 << PAGE_SHIFT));

	if (g_text_start) {
		phys_addr_t walk = phys_from_virt(g_text_start);
		phys_addr_t offset = image_phys(g_text_start);

		if (walk && offset && walk != offset) {
			g_walk_usable = false;
			pr_info("uidfake: page table walk disagrees with kimage_voffset (kernel geometry is not this module's); using the image offset alone\n");
		}
	}
	return 0;
}
struct patch_req {
	void *addr;
	const void *src;
	size_t len;
};

/*
 * Physical address of a kernel address, by walking init_mm the way KernelSU's
 * patcher does. Kernel .rodata (where sys_call_table lives) is often mapped as a
 * 2 MB block and the image as 1 GB blocks, so a block mapping is resolved to the
 * page inside it instead of being rejected. The page offset is part of the
 * result, which is what the fixmap copy wants.
 */
static phys_addr_t phys_from_virt(unsigned long addr)
{
	pgd_t *pgd = pgd_offset(patch_mm, addr);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return 0;
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return 0;
#if defined(p4d_leaf)
	if (p4d_leaf(*p4d))
		return (phys_addr_t)(p4d_val(*p4d) & ~(P4D_SIZE - 1)) +
		       (addr & (P4D_SIZE - 1));
#endif
	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud))
		return 0;
	if (pud_leaf(*pud))
		return (phys_addr_t)(pud_val(*pud) & ~(PUD_SIZE - 1)) +
		       (addr & (PUD_SIZE - 1));
	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return 0;
	if (pmd_leaf(*pmd))
		return (phys_addr_t)(pmd_val(*pmd) & ~(PMD_SIZE - 1)) +
		       (addr & (PMD_SIZE - 1));
	pte = pte_offset_kernel(pmd, addr);
	if (!pte || pte_none(*pte) || !pte_present(*pte))
		return 0;
	return (phys_addr_t)(pte_val(*pte) & PHYS_MASK & PAGE_MASK) +
	       (addr & ~PAGE_MASK);
}
/*
 * Cache maintenance inlined by hand: __builtin___clear_cache() lowers to a call
 * to
 * __clear_cache(), which the kernel does not export (the module would fail to
 * load with "Unknown symbol __clear_cache").
 */
static unsigned long cache_dline(void)
{
	unsigned long ctr;

	asm volatile("mrs %0, ctr_el0" : "=r"(ctr));
	return 4UL << ((ctr >> 16) & 0xf);
}

static unsigned long cache_iline(void)
{
	unsigned long ctr;

	asm volatile("mrs %0, ctr_el0" : "=r"(ctr));
	return 4UL << (ctr & 0xf);
}

static void cache_clean_inval(void *addr, size_t len)
{
	unsigned long start = (unsigned long)addr;
	unsigned long end = start + len;
	unsigned long dline = cache_dline();
	unsigned long iline = cache_iline();
	unsigned long p;

	for (p = start & ~(dline - 1); p < end; p += dline)
		asm volatile("dc cvau, %0" ::"r"(p) : "memory");
	dsb(ish);
	for (p = start & ~(iline - 1); p < end; p += iline)
		asm volatile("ic ivau, %0" ::"r"(p) : "memory");
	dsb(ish);
	isb();
}

/*
 * Physical address of a kernel image address without walking page tables: with
 * KASLR the image is offset by kimage_voffset, so pa = va - kimage_voffset.
 * Used when the walk cannot resolve the address, for instance because struct
 * mm_struct differs from the tree this module was built against.
 */
static phys_addr_t image_phys(unsigned long addr)
{
	phys_addr_t base, end, pa;
	unsigned long voff;

	if (g_kimage_voffset)
		voff = *g_kimage_voffset;
	else if (g_memstart_addr)
		voff = (unsigned long)(KIMAGE_VADDR - *g_memstart_addr);
	else
		return 0;

	pa = (phys_addr_t)(addr - voff);
	/*
	 * The offset has to put the target inside the image's own physical extent.
	 * When it does not -- a vendor kernel whose kimage_voffset this module did
	 * not read correctly, or an mm_struct that is not the tree's -- the write
	 * would land on an unrelated page, so it is refused instead.
	 */
	if (!g_text_start || !g_text_end)
		return 0;
	base = (phys_addr_t)(g_text_start - voff);
	end = (phys_addr_t)(g_text_end - voff);
	if (pa < base || pa >= end)
		return 0;
	return pa;
}

/*
 * The write itself: map the target's physical page into the kernel's own fixmap
 * window and copy through that. stop_machine holds every other CPU, so the one
 * fixmap slot cannot be claimed by anyone else while it is in use.
 */
static int patch_nosync(void *dst, const void *src, size_t len)
{
	unsigned long p = (unsigned long)dst;
	phys_addr_t walk = g_walk_usable ? phys_from_virt(p) : 0;
	phys_addr_t offset = image_phys(p);
	phys_addr_t phy;
	enum fixed_addresses idx = FIX_TEXT_POKE0;
	unsigned long aliases[2];
	unsigned int naliases = 0, a;
	bool checked;
	void *map;
	int ret;

	/*
	 * Every target is inside [_stext, _end) (checked in uidfake_patch_text), and
	 * the image is one contiguous block, so the image offset translates it
	 * exactly -- and it is the only translation that works on a vendor kernel
	 * whose struct mm_struct differs from the tree this module was built
	 * against, which is where the walk gives up. The walk is the second opinion
	 * then, and the fallback where the offset is not readable.
	 */
	/* A module address is not in the image, so the image offset cannot translate
	 * it: the page-table walk is the only source there. */
	if (g_mod_start && p >= g_mod_start && p < g_mod_end)
		offset = 0;

	if (offset) {
		if (walk && walk != offset) {
			pr_warn("uidfake: refusing to write: the walk and the image offset disagree\n");
			if (UF_DEBUG_ON())
				pr_info("uidfake:   %px walk=%pa image=%pa\n",
					dst, &walk, &offset);
			return -EFAULT;
		}
		phy = offset;
		checked = true;
	} else {
		if (!walk) {
			pr_warn("uidfake: no physical address for the target\n");
			if (UF_DEBUG_ON())
				pr_info("uidfake:   %px\n", dst);
			return -EFAULT;
		}
		if (!g_offset_warned) {
			g_offset_warned = true;
			pr_info("uidfake: kimage_voffset unusable; using the page table walk\n");
		}
		phy = walk;
		checked = false;
	}

	/*
	 * The slot shows up at FIXADDR_TOP - idx * PAGE_SIZE, and FIXADDR_TOP is not
	 * the same in every build: this module has the one its config gave it, and
	 * the kernel has its own. Two candidates are therefore tried -- what this
	 * build computes, and what the kernel's vmemmap pointer implies -- and each
	 * is proved before it is used: the bytes at the alias have to be the bytes at
	 * the target, or nothing is written. The reads are nofault, because a wrong
	 * address is exactly the case where a plain read would fault. With no proof
	 * available the compiled address is used, as before.
	 */
	aliases[naliases++] = __fix_to_virt(idx);
	if (g_fixmap_top)
		aliases[naliases++] =
			g_fixmap_top - ((unsigned long)idx << PAGE_SHIFT);

	for (a = 0; a < naliases; a++) {
		map = (void *)(aliases[a] + (phy & ~PAGE_MASK));
		patch_set_fixmap(idx, phy, PAGE_KERNEL);

		if (!g_copy_from_nofault_addr)
			break; /* nothing to prove it with: the first alias is used */
		{
			u8 seen[8], want[8];
			const size_t n = len < sizeof(seen) ? len :
							      sizeof(seen);
			const bool same =
				!patch_copy_from_nofault(seen, map, n) &&
				!patch_copy_from_nofault(want, dst, n) &&
				!memcmp(seen, want, n);

			patch_set_fixmap(idx, 0, __pgprot(0));
			if (same) {
				map = (void *)(aliases[a] + (phy & ~PAGE_MASK));
				patch_set_fixmap(idx, phy, PAGE_KERNEL);
				break;
			}
		}
	}
	if (a == naliases) {
		pr_warn("uidfake: no fixmap alias proved out; nothing written\n");
		if (UF_DEBUG_ON())
			pr_info("uidfake:   %px this build's %#lx, the kernel's %#lx\n",
				dst, aliases[0],
				naliases > 1 ? aliases[1] : 0UL);
		return -EFAULT;
	}

	if (g_copy_nofault_addr)
		ret = (int)patch_copy_nofault(map, src, len);
	else if (checked)
		ret = (memcpy(map, src, len), 0);
	else
		ret = -ENOSYS;
	patch_set_fixmap(idx, 0, __pgprot(0));

	if (ret)
		pr_warn("uidfake: the write failed: %d\n", ret);
	if (UF_DEBUG_ON())
		pr_info("uidfake:   %px\n", dst);
	return ret;
}

static int patch_do(void *arg)
{
	struct patch_req *r = arg;

	return patch_nosync(r->addr, r->src, r->len);
}

int uidfake_patch_text(void *dst, const void *src, size_t len, bool sync)
{
	struct patch_req req = { .addr = dst, .src = src, .len = len };
	int ret;

	if (!len || (unsigned long)dst & 3 || len & 3)
		return -EINVAL;
	/* Refuse anything outside the kernel image before a single byte is written:
	 * a wrong physical address used to be caught only by reading the target
	 * back, which is too late -- the stray write has already happened. */
	if (!writable_range((unsigned long)dst, len)) {
		pr_warn("uidfake: refusing to patch: neither the kernel image nor this module\n");
		if (UF_DEBUG_ON())
			pr_info("uidfake:   %px\n", dst);
		return -EPERM;
	}
	if (offset_in_page((unsigned long)dst) + len > PAGE_SIZE)
		return -EINVAL;

	ret = sync ? stop_machine(patch_do, &req, NULL) : patch_do(&req);
	if (ret)
		return ret;

	/* make the new instructions visible to every CPU */
	cache_clean_inval(dst, len);
	return 0;
}
