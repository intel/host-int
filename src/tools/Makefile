# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

USER_TARGETS := hostintd
USER_TARGETS += hostintcol
USER_TARGETS += hostintcfg
USER_LIBS=-lpthread

COMMON_DIR = ../common/

include $(COMMON_DIR)/common.mk

install: service_install

service_install:
	install -m 0644 hostintd.cfg /etc
	install -m 0644 hostintd.service /lib/systemd/system
	install -m 0755 hostintctl $(DESTDIR)$(SBINDIR)