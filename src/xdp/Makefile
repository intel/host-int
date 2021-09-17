# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

XDP_TARGETS += intmd_xdp_ksource
XDP_TARGETS += intmd_xdp_ksink
XDP_TARGETS += intmd_xdp_uencap_ksink
#XDP_TARGETS += intmd_xdp_ksink
USER_TARGETS += xdp_loader
USER_LIBS=-lpthread

COMMON_DIR = ../common/

include $(COMMON_DIR)/common.mk
COMMON_OBJS := $(COMMON_DIR)/common_params.o $(COMMON_DIR)/common_user_bpf_xdp.o
