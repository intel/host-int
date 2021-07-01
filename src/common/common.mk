# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

# Common Makefile parts for BPF-building with libbpf
# --------------------------------------------------
#
# This file should be included from your Makefile like:
#  COMMON_DIR = ../common/
#  include $(COMMON_DIR)/common.mk
#
# It is expected that you define the variables:
#  XDP_TARGETS and USER_TARGETS
# as a space-separated list
#
include ../Makefile.variable

XDP_C = ${XDP_TARGETS:=.c}
XDP_OBJ = ${XDP_C:.c=.o}
USER_C := ${USER_TARGETS:=.c}
USER_OBJ := ${USER_C:.c=.o}

# Expect this is defined by including Makefile, but define if not
COMMON_DIR ?= ../common/

# Extend if including Makefile already added some
COMMON_OBJS += $(COMMON_DIR)/common_params.o $(COMMON_DIR)/common_user_bpf_xdp.o $(COMMON_DIR)/common_report.o

# Create expansions for dependencies
COMMON_H := ${COMMON_OBJS:.o=.h}

EXTRA_DEPS +=

# BPF-prog kern and userspace shares struct via header file:
KERN_USER_H ?= $(wildcard common_kern_user.h)

# it's important to have include paths in right order. we search our own
# include first, then system headers
CFLAGS ?= -g -I../common -I../../include
# Extra include for Ubuntu issue #44
CFLAGS += -I/usr/include/x86_64-linux-gnu

LIBS = -lbpf -lelf $(USER_LIBS)

all: llvm-check $(USER_TARGETS) $(XDP_OBJ)

debug: CFLAGS += -DEXTRA_DEBUG -g
debug: llvm-check $(USER_TARGETS) $(XDP_OBJ)

ifeq "$(SUPPORT_BOOTTIME)" "true"
CFLAGS += -DSUPPORT_BOOTTIME
endif

.PHONY: clean $(CLANG) $(LLC)

clean:
	$(MAKE) -C $(COMMON_DIR) clean
	rm -f $(USER_TARGETS) $(XDP_OBJ) $(USER_OBJ)
	rm -f *.ll
	rm -f *~


# For build dependency on this file, if it gets updated
COMMON_MK = $(COMMON_DIR)/common.mk

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

# Create dependency: detect if C-file change and touch H-file, to trigger
# target $(COMMON_OBJS)
$(COMMON_H): %.h: %.c
	touch $@

# Detect if any of common obj changed and create dependency on .h-files
$(COMMON_OBJS): %.o: %.h
	make -C $(COMMON_DIR)

$(USER_TARGETS): %: %.c  Makefile $(COMMON_MK) $(COMMON_OBJS) $(KERN_USER_H) $(EXTRA_DEPS)
	$(CC) -Wall $(CFLAGS) $(LDFLAGS) -o $@ $(COMMON_OBJS) \
	 $< $(LIBS)

# use below for debug purpose that will generate .ll files
# (XDP_OBJ): %.o: %.c  Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS)
# 	$(CLANG) -S \
# 	    -target bpf \
# 	    -D __BPF_TRACING__ \
# 	    $(CFLAGS) \
# 	    -Wall \
# 	    -Wno-unused-value \
# 	    -Wno-pointer-sign \
# 	    -Wno-compare-distinct-pointer-types \
# 	    -Werror \
# 	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
# 	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

$(XDP_OBJ): %.o: %.c  Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS)
	$(CLANG) \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g $< -o -| $(LLC) -march=bpf -filetype=obj -o $@

install: all
	for t in $(USER_TARGETS); do \
		install -m 0755 $$t $(DESTDIR)$(SBINDIR); \
	done
	for t in $(XDP_OBJ); do \
		install -m 0644 $$t $(LIBDIR); \
	done
