# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

CC := gcc

all: common_params.o common_user_bpf_xdp.o common_report.o

CFLAGS := -g -Wall
CFLAGS += -I../../include

common_params.o: common_params.c common_params.h
	$(CC) $(CFLAGS) -c -o $@ $<

common_report.o: common_report.c common_report.h
	$(CC) $(CFLAGS) -c -o $@ $<

common_user_bpf_xdp.o: common_user_bpf_xdp.c common_user_bpf_xdp.h
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	rm -f *.o
