# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
include Makefile.variable

SUBDIRS=xdp tc tools

all:
	@for d in $(SUBDIRS); do \
		echo ""; echo $$d; \
		( cd $$d && $(MAKE) ); \
	done

debug:
	@for d in $(SUBDIRS); do \
		( cd $$d && $(MAKE) debug ); \
	done

clean:
	@for d in $(SUBDIRS); do \
		( cd $$d && $(MAKE) clean ); \
	done

install: all
	install -m 0755 -d $(DESTDIR)$(SBINDIR)
	install -m 0755 -d $(LIBDIR)
	@for d in $(SUBDIRS);  do \
		( cd $$d && $(MAKE) install ); \
	done
	setcap 'CAP_SYS_RESOURCE=+ep' $(DESTDIR)$(SBINDIR)/hostintd
