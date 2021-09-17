# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

# Makefile for out-of-tree building eBPF programs
#  similar to kernel/samples/bpf/
include ../Makefile.variable

TARGETS += intmd_tc_ksource
TARGETS += intmd_tc_uencap_ksource

# Linking with libbpf and libpcap
#TARGETS_PCAP += xdp_tcpdump

# Generate file name-scheme based on TARGETS
KERN_SOURCES = ${TARGETS:=.c}
KERN_OBJECTS = ${KERN_SOURCES:.c=.o}

ARCH ?= x86

CFLAGS := -g -O2 -Wall

# it's important to have include paths in right order. we search our own
# include first, then system headers
TC_INCLUDE := -I../../include
TC_INCLUDE += -I../common
TC_INCLUDE += -I/usr/include
TC_INCLUDE += -I/usr/include/x86_64-linux-gnu

LDFLAGS= -lelf -lbpf

# Allows pointing LLC/CLANG to another LLVM backend, redefine on cmdline:
#  make LLC=~/git/llvm/build/bin/llc CLANG=~/git/llvm/build/bin/clang

NOSTDINC_FLAGS := -nostdinc -isystem $(shell $(CC) -print-file-name=include)

BPF_EXTRA_CFLAGS = -Werror -fno-stack-protector

ifeq "$(SUPPORT_BOOTTIME)" "true"
BPF_EXTRA_CFLAGS += -DSUPPORT_BOOTTIME
endif

all: dependencies $(TARGETS_ALL) $(KERN_OBJECTS) $(CMDLINE_TOOLS)

.PHONY: dependencies clean verify_cmds verify_llvm_target_bpf $(CLANG) $(LLC)

debug: BPF_EXTRA_CFLAGS += -DEXTRA_DEBUG
debug: all

clean:
	@find . -type f \
		\( -name '*~' \
		-o -name '*.ll' \
		-o -name '*.bc' \
		-o -name 'core' \) \
		-exec rm -vf '{}' \;
	rm -f $(OBJECTS)
	rm -f $(KERN_OBJECTS)

dependencies: verify_llvm_target_bpf

verify_cmds: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if ! (which -- "$${TOOL}" > /dev/null 2>&1); then \
			echo "*** ERROR: Cannot find LLVM tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

verify_llvm_target_bpf: verify_cmds
	@if ! (${LLC} -march=bpf -mattr=help > /dev/null 2>&1); then \
		echo "*** ERROR: LLVM (${LLC}) does not support 'bpf' target" ;\
		echo "   NOTICE: LLVM version >= 3.7.1 required" ;\
		exit 2; \
	else true; fi

# Compiling of eBPF restricted-C code with LLVM
#  clang option -S generated output file with suffix .ll
#   which is the non-binary LLVM assembly language format
#   (normally LLVM bitcode format .bc is generated)
#
# Use -Wno-address-of-packed-member as eBPF verifier enforces
# unaligned access checks where necessary
#
# $(KERN_OBJECTS): %.o: %.c Makefile
# 	$(CLANG) -S $(NOSTDINC_FLAGS) $(TC_INCLUDE) $(BPF_EXTRA_CFLAGS) \
# 	    -D__ASM_SYSREG_H \
# 	    -D__BPF_TRACING__ \
# 	    -Wall \
# 	    -Wno-unused-value -Wno-pointer-sign \
# 	    -D__TARGET_ARCH_$(ARCH) \
# 	    -Wno-compare-distinct-pointer-types \
# 	    -Wno-gnu-variable-sized-type-not-at-end \
# 	    -Wno-tautological-compare \
# 	    -Wno-unknown-warning-option \
# 	    -Wno-address-of-packed-member \
# 	    -O2 -emit-llvm -c $< -o ${@:.o=.ll}
# 	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

$(KERN_OBJECTS): %.o: %.c Makefile
	$(Q)$(CLANG) $(NOSTDINC_FLAGS) $(TC_INCLUDE) $(BPF_EXTRA_CFLAGS) -I$(obj) \
		-D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
		-D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option $(CLANG_ARCH_ARGS) \
		-O2 -emit-llvm -c $< -o -| $(LLC) -march=bpf $(LLC_FLAGS) -filetype=obj -o $@

# Targets that links with libpcap
# $(TARGETS_PCAP): %: %_user.c $(OBJECTS) $(LIBBPF) Makefile bpf_util.h
# 	$(CC) $(CFLAGS) $(OBJECTS) $(LDFLAGS) -o $@ $<  $(LIBBPF) -lpcap

#$(CMDLINE_TOOLS): %: %.c $(OBJECTS) $(LIBBPF) Makefile $(COMMON_H) bpf_util.h
#	$(CC) -g $(CFLAGS) $(OBJECTS) $(LDFLAGS) -o $@ $<  $(LIBBPF)

install: all
	for obj in $(KERN_OBJECTS); do \
		install -m 0644 $$obj $(LIBDIR); \
	done
