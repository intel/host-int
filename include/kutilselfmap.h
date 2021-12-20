/* Copyright (C) 2021 Intel Corporation */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef __KUTILSELFMAP__
#define __KUTILSELFMAP__

#include <stddef.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include "intbpf.h"
#include "intmd_headers.h"

static __always_inline void update_stats_elf(__u32 stats_addr,
                                             struct bpf_elf_map *stats_map,
                                             __u16 pkt_len_bytes)
{
    __u64 pktlen = (__u64)pkt_len_bytes;
    struct packet_byte_counter *stats =
        bpf_map_lookup_elem(stats_map, &stats_addr);
    if (stats) {
        __sync_fetch_and_add(&stats->pkt_count, 1);
        __sync_fetch_and_add(&stats->byte_count, pktlen);
    }
}

#endif /* __KUTILSELFMAP__ */
