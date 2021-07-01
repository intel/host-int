/* Copyright (C) 2021 Intel Corporation */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef __KUTILS__
#define __KUTILS__

#include <stddef.h>
#include "intbpf.h"
#include "intmd_headers.h"

#define PKT_SAMPLE_SIZE 1024ul

#define FALSE 0
#define TRUE 1

static __always_inline __u64 e2e_latency_bucket(__u32 e2e_latency_ns) {
    if (e2e_latency_ns < 50 * MILLI_TO_NANO) {
        return 0;
    } else if (e2e_latency_ns < 100 * MILLI_TO_NANO) {
        return 50 * MILLI_TO_NANO;
    } else if (e2e_latency_ns < 225 * MILLI_TO_NANO) {
        return 100 * MILLI_TO_NANO;
    } else if (e2e_latency_ns < 500 * MILLI_TO_NANO) {
        return 225 * MILLI_TO_NANO;
    } else if (e2e_latency_ns < 750 * MILLI_TO_NANO) {
        return 500 * MILLI_TO_NANO;
    }
    return 750 * MILLI_TO_NANO;
}

static __always_inline void
update_flow_stats_gap_data(struct sink_flow_stats_datarec *fs,
                           __u32 pkt_seq_num, unsigned long curr_ts) {
    // Note that we ignore packets with seq_num less than the head
    if (pkt_seq_num > fs->gap_head_seq_num) {
        if (pkt_seq_num == fs->gap_head_seq_num + 1) { // update head
            fs->gap_head_ts_ns = curr_ts;
            fs->gap_head_seq_num = pkt_seq_num;
        } else if (fs->gap_tail_seq_num == 0) {
            // This is a new gap, add tail info
            fs->gap_tail_seq_num = pkt_seq_num;
            fs->gap_tail_ts_ns = curr_ts;
        } else if (pkt_seq_num < fs->gap_tail_seq_num) {
            // inside the existing gap
            if (pkt_seq_num == fs->gap_tail_seq_num - 1) {
                // update tail
                fs->gap_tail_seq_num = pkt_seq_num;
                fs->gap_tail_ts_ns = curr_ts;
            } else {
                fs->gap_pkt_count += 1;
            }
        } else if (pkt_seq_num > fs->gap_tail_seq_num) {
            if (pkt_seq_num == fs->gap_tail_seq_num + 1) {
                // update tail
                fs->gap_tail_seq_num = pkt_seq_num;
                fs->gap_tail_ts_ns = curr_ts;
                fs->gap_pkt_count += 1;
            } else {
                // second gap
                fs->gap_head_ts_ns = fs->gap_tail_ts_ns;
                fs->gap_tail_ts_ns = curr_ts;
                fs->gap_tail_seq_num = pkt_seq_num;
                fs->gap_pkt_count += 1;
            }
        }
    }
}

static __always_inline void send_packet_userspace(
    struct xdp_md *ctx, __u16 pkt_len, struct bpf_map_def *map,
    struct int_metadata_entry *intmdsink, struct flow_ds_md *fdsmd,
    __u32 *node_id, __u16 *domain_id) {
    __u64 flags = BPF_F_CURRENT_CPU;
    __u16 sample_size;
    struct packet_metadata metadata;

    metadata.s_meta.cookie = 0xdead;
    metadata.s_meta.pkt_len = pkt_len;
    metadata.intmdsink = *intmdsink;
    metadata.fdsmd = *fdsmd;
    if (node_id != NULL) {
        metadata.node_id = *node_id;
    }

    if (domain_id != NULL) {
        metadata.domain_id = *domain_id;
    }

    sample_size = metadata.s_meta.pkt_len;
    if (sample_size > PKT_SAMPLE_SIZE) {
        sample_size = PKT_SAMPLE_SIZE;
    }

    flags |= (__u64)sample_size << 32;

    int ret =
        bpf_perf_event_output(ctx, map, flags, &metadata, sizeof(metadata));
    if (ret) {
        bpf_printk("intmd_xdp_ksink bpf_perf_event_output with size=%d"
                   " failed: %d\n",
                   sample_size, ret);
    }
#ifdef EXTRA_DEBUG
    else {
        bpf_printk("intmd_xdp_ksink bpf_perf_event_output with size=%d"
                   " succeeded: %d\n",
                   sample_size, ret);
    }
#endif
}

#endif /* __KUTILS__ */
