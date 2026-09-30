# kbuild fragment for the hma_uidfake module.
#
# Normally driven by CMake (which runs kbuild inside build/kmi/<kmi>/, a directory
# holding only symlinks to this source tree), but a manual build works too:
#   make -C <KDIR> ARCH=arm64 LLVM=1 CROSS_COMPILE=aarch64-linux-gnu- M=$PWD/src modules
#
# CROSS_COMPILE matters for the old trees: they take the target triple from it, and without it
# clang emits bitcode for the host, which the LTO link then refuses.

KDIR ?= /lib/modules/$(shell uname -r)/build

# abspath, not realpath: kbuild is invoked through a symlink staging directory, and
# realpath would resolve it back to the real source directory, writing objects there.
MDIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
ODIR := $(MDIR)

# Kernel tree: srctree is the reliable one for a direct make, KDIR for the DDK flow.
KSRC  ?= $(or $(srctree),$(KDIR))
KMI   := $(notdir $(patsubst %/,%,$(KSRC)))

# Old trees (android12-5.10) have a GCC style register-asm atomic_lse.h that clang
# cannot parse. -U on the command line is useless (clang handles -D/-U first, then
# -include, so autoconf.h redefines the macro), hence a compatibility header that is
# -included after autoconf.h and drops the macros -- the module then falls back to
# LL/SC atomics, which is semantically equivalent.
LSE_HDR := $(shell grep -l 'unsigned long x0 asm' $(KSRC)/arch/arm64/include/asm/atomic_lse.h 2>/dev/null)
# The stack pointer is a GCC style global register variable in the same trees, which clang also
# refuses; kmi_compat.h then provides the inline asm helper later kernels use.
SP_REG := $(shell grep -l 'register unsigned long current_stack_pointer' $(KSRC)/arch/arm64/include/asm/stack_pointer.h 2>/dev/null)
# asm/kgdb.h writes its breakpoint with a constraint clang does not accept for that value, and
# The instruction is rewritten with a plain immediate where that constraint is written that way
# (see kmi_compat.h); every tree here has it, and none of them needs the header itself.
KGDB_BRK := $(shell grep -l '"I" (KGDB_COMPILED_DBG_BRK_IMM)' $(KSRC)/arch/arm64/include/asm/kgdb.h 2>/dev/null)
$(info uidfake: KMI=$(KMI) lse-workaround=$(if $(LSE_HDR),on,off) sp-register=$(if $(SP_REG),on,off) kgdb-brk=$(if $(KGDB_BRK),on,off) lto-kernel=$(if $(CONFIG_LTO_CLANG),on,off))

ifeq ($(KMI),android17-6.18)
KBUILD_ARGS := M=$(MDIR) MO=$(ODIR)
else
KBUILD_ARGS := M=$(MDIR)
endif

obj-m += hma_uidfake.o
hma_uidfake-objs := main.o patch.o inline.o status.o tag.o inline_hooks.o \
	table_hooks.o inode_hook.o hooks.o policy.o lsm.o netlink.o tiers.o

ifeq ($(strip $(LSE_HDR)$(SP_REG)$(KGDB_BRK)),)
else
ccflags-y += -include $(MDIR)/include/kmi_compat.h
endif
ifneq ($(SP_REG),)
ccflags-y += -DUIDFAKE_SP_REGISTER
endif
ifneq ($(KGDB_BRK),)
ccflags-y += -DUIDFAKE_KGDB_BRK
endif
ccflags-y += -I$(MDIR)/include
ccflags-y += -I$(MDIR)
ccflags-y += -gz=none
