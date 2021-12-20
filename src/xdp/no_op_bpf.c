/* Copyright (C) 2021 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_no_op(struct xdp_md *ctx) { return XDP_PASS; }

char _license[] SEC("license") = "GPL";
