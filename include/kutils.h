/* Copyright (C) 2021 Intel Corporation */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef __KUTILS__
#define __KUTILS__

#include <stddef.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include "intbpf.h"
#include "intmd_headers.h"

#define PKT_SAMPLE_SIZE 1024ul

#define FALSE 0
#define TRUE 1

static __always_inline __u64 e2e_latency_bucket(
    __u32 e2e_latency_ns, struct latency_bucket_entries *latency_bucket_value)
{
    int i = 0;

    if (e2e_latency_ns < latency_bucket_value->entries[0]) {
        return 0;
    } else {
        for (i = 1; i < LATENCYBUCKET_MAP_MAX_ENTRIES; i++) {
            if (e2e_latency_ns <= latency_bucket_value->entries[i]) {
                break;
            }
        }
        return latency_bucket_value->entries[i - 1];
    }
}

/* The packet loss detection logic as written now will probably _not_
 * work if the pkt_seq_num ever wraps around from 2^32-1 back to 0.
 * TODO: Consider changing it to handle such a scenario, for very
 * long-running flows.
 *
 * As written, this function will also not work correctly if packets
 * with the same pkt_seq_num are received multiple times, e.g. because
 * the packet is duplicated in the network.
 *
 * An alternative approach that might handle both of the above issues
 * gracefully would be something like the anti-replay attack detection
 * logic used by IPsec.
 *
 * Under the conditions that packet sequence numbers never wrap
 * around, and we never receive more than one packet with the same
 * packet sequence number, the following should describe the possible
 * states that can be reached.
 *
 * H is an abbreviation for gap_head_seq_num
 * T is an abbreviation for gap_tail_seq_num
 * S is an abbreviation for pkt_seq_num, the sequence number of the
 *     packet currently being processed.
 * G is an abbreviation for gap_pkts_not_rcvd
 *
 * The first packet processed will leave the state as H=S, T=0, G=0
 *
 * If all sequence numbers are received in order, with no gaps, then
 * the state will always be H=S, T=0, G=0, where S is the most
 * recently received pkt_seq_num.
 *
 * If in this state a packet is received with S > H+1, then the final
 * state will be H unchanged, T=S, G=(S-H-1).  T will now always be
 * the largest packet sequence number ever received, and G will count
 * the number of packets that have never been received with sequence
 * numbers that are greater than H, but less then T.
 *
 * If at any time G becomes equal to 0, then the state resets back to
 * H=S, T=0, G=0, where S is the largest packet sequence number
 * received so far. */

static __always_inline void
update_flow_stats_gap_data(struct sink_flow_stats_datarec *fs,
                           __u32 pkt_seq_num, unsigned long curr_ts)
{
    // Note that we ignore packets with seq_num less than the head
    if (pkt_seq_num > fs->gap_head_seq_num) {
        if (fs->gap_tail_seq_num == 0) {
            if (pkt_seq_num == fs->gap_head_seq_num + 1) { // update head
                fs->gap_head_seq_num = pkt_seq_num;
                fs->gap_head_ts_ns = curr_ts;
            } else {
                // This is a new gap, add tail info
                fs->gap_tail_seq_num = pkt_seq_num;
                fs->gap_tail_ts_ns = curr_ts;
                fs->gap_pkts_not_rcvd = pkt_seq_num - fs->gap_head_seq_num - 1;
            }
        } else if (pkt_seq_num < fs->gap_tail_seq_num) {
            // inside the existing gap
            fs->gap_pkts_not_rcvd -= 1;
            fs->gap_tail_ts_ns = curr_ts;
            if (fs->gap_pkts_not_rcvd == 0) {
                // the gap was completely filled
                fs->gap_head_seq_num = fs->gap_tail_seq_num;
                fs->gap_head_ts_ns = fs->gap_tail_ts_ns;
                fs->gap_tail_seq_num = 0;
                fs->gap_tail_ts_ns = 0;
            }
        } else if (pkt_seq_num > fs->gap_tail_seq_num) {
            if (pkt_seq_num == fs->gap_tail_seq_num + 1) {
                // update tail
                fs->gap_tail_seq_num = pkt_seq_num;
                fs->gap_tail_ts_ns = curr_ts;
            } else {
                // second gap
                fs->gap_pkts_not_rcvd += pkt_seq_num - fs->gap_tail_seq_num - 1;
                fs->gap_head_ts_ns = fs->gap_tail_ts_ns;
                fs->gap_tail_seq_num = pkt_seq_num;
                fs->gap_tail_ts_ns = curr_ts;
            }
        }
    }
}

static __always_inline void send_packet_userspace(
    struct xdp_md *ctx, __u16 pkt_len, struct bpf_map_def *map,
    struct int_metadata_entry *intmdsink, struct flow_ds_md *fdsmd,
    __u32 *node_id, __u16 *domain_id)
{
    __u64 flags = BPF_F_CURRENT_CPU;
    __u16 sample_size;
    struct packet_metadata metadata;

    metadata.s_meta.cookie = PACKET_METADATA_COOKIE;
    metadata.s_meta.pkt_len = pkt_len;
    if (intmdsink == NULL) {
        metadata.intmdsink.node_id = 0;
        metadata.intmdsink.ingress_port = 0;
        metadata.intmdsink.egress_port = 0;
        metadata.intmdsink.ingress_ts = 0;
        metadata.intmdsink.egress_ts = 0;
    } else {
        metadata.intmdsink = *intmdsink;
    }
    if (fdsmd == NULL) {
        metadata.fdsmd.src_node_id = 0;
        metadata.fdsmd.src_port = 0;
        metadata.fdsmd.sink_port = 0;
        metadata.fdsmd.src_timestamp = 0;
        metadata.fdsmd.sink_timestamp = 0;
    } else {
        metadata.fdsmd = *fdsmd;
    }
    if (node_id == NULL) {
        metadata.node_id = 0;
    } else {
        metadata.node_id = *node_id;
    }
    if (domain_id == NULL) {
        metadata.domain_id = 0;
    } else {
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

static __always_inline void sprintf_byte_hex(char *buf, __u8 byte)
{
    int digit;
    digit = (byte >> 4) & 0xf;
    if (digit > 9) {
        buf[0] = 'a' + digit - 10;
    } else {
        buf[0] = '0' + digit;
    }
    digit = byte & 0xf;
    if (digit > 9) {
        buf[1] = 'a' + digit - 10;
    } else {
        buf[1] = '0' + digit;
    }
}

/* When calling sprintf_flow_key_hex(), parameter buf must point to a
 * buffer of at least SPRINTF_FLOW_KEY_HEX_BUF_SIZE characters.  The
 * contents of the buffer will always be written to end with a null
 * string terminator, which will always fit within that size. */

#define SPRINTF_FLOW_KEY_HEX_BUF_SIZE 31

static __always_inline void sprintf_flow_key_hex(char *buf,
                                                 struct flow_key *key)
{
    __u8 *data;

    data = (__u8 *)&(key->saddr);
    sprintf_byte_hex(buf, data[0]);
    buf += 2;
    sprintf_byte_hex(buf, data[1]);
    buf += 2;
    sprintf_byte_hex(buf, data[2]);
    buf += 2;
    sprintf_byte_hex(buf, data[3]);
    buf += 2;

    *buf = ' ';
    buf++;

    data = (__u8 *)&(key->daddr);
    sprintf_byte_hex(buf, data[0]);
    buf += 2;
    sprintf_byte_hex(buf, data[1]);
    buf += 2;
    sprintf_byte_hex(buf, data[2]);
    buf += 2;
    sprintf_byte_hex(buf, data[3]);
    buf += 2;

    *buf = ' ';
    buf++;

    data = (__u8 *)&(key->sport);
    sprintf_byte_hex(buf, data[0]);
    buf += 2;
    sprintf_byte_hex(buf, data[1]);
    buf += 2;

    *buf = ' ';
    buf++;

    data = (__u8 *)&(key->dport);
    sprintf_byte_hex(buf, data[0]);
    buf += 2;
    sprintf_byte_hex(buf, data[1]);
    buf += 2;

    *buf = ' ';
    buf++;

    data = (__u8 *)&(key->proto);
    sprintf_byte_hex(buf, data[0]);
    buf += 2;
    *buf = '\0';
}

static __always_inline void debug_print_4_bytes_hex(__u8 *data)
{
    char buf[12];

    sprintf_byte_hex(&(buf[0]), data[0]);
    buf[2] = ' ';
    sprintf_byte_hex(&(buf[3]), data[1]);
    buf[5] = ' ';
    sprintf_byte_hex(&(buf[6]), data[2]);
    buf[8] = ' ';
    sprintf_byte_hex(&(buf[9]), data[3]);
    buf[11] = '\0';
    bpf_printk("%s\n", buf);
}

static __always_inline void debug_print_ipv4_header(struct iphdr *iph)
{
    __u8 *hdr = (__u8 *)iph;

    bpf_printk("IPv4:\n");
    debug_print_4_bytes_hex(&(hdr[0]));
    debug_print_4_bytes_hex(&(hdr[4]));
    debug_print_4_bytes_hex(&(hdr[8]));
    debug_print_4_bytes_hex(&(hdr[12]));
    debug_print_4_bytes_hex(&(hdr[16]));
    if (iph->ihl >= 6) {
        bpf_printk("IPv4 options not shown (%d bytes of options):\n",
                   (iph->ihl - 5) << 2);
        // debug_print_4_bytes_hex(&(hdr[20]));
    }
    // if (iph->ihl >= 7) debug_print_4_bytes_hex(&(hdr[24]));
    // if (iph->ihl >= 8) debug_print_4_bytes_hex(&(hdr[28]));
    // if (iph->ihl >= 9) debug_print_4_bytes_hex(&(hdr[32]));
    // if (iph->ihl >= 10) debug_print_4_bytes_hex(&(hdr[36]));
    // if (iph->ihl >= 11) debug_print_4_bytes_hex(&(hdr[40]));
    // if (iph->ihl >= 12) debug_print_4_bytes_hex(&(hdr[44]));
    // if (iph->ihl >= 13) debug_print_4_bytes_hex(&(hdr[48]));
    // if (iph->ihl >= 14) debug_print_4_bytes_hex(&(hdr[52]));
    // if (iph->ihl >= 15) debug_print_4_bytes_hex(&(hdr[56]));
}

static __always_inline void debug_print_tcp_header(struct tcphdr *tcph)
{
    __u8 *hdr = (__u8 *)tcph;
    int data_offset = (int)tcph->doff;

    bpf_printk("TCP:\n");
    debug_print_4_bytes_hex(&(hdr[0]));
    debug_print_4_bytes_hex(&(hdr[4]));
    debug_print_4_bytes_hex(&(hdr[8]));
    debug_print_4_bytes_hex(&(hdr[12]));
    debug_print_4_bytes_hex(&(hdr[16]));
    if (data_offset >= 6) {
        bpf_printk("TCP options not shown (%d bytes of options):\n",
                   (data_offset - 5) << 2);
        // debug_print_4_bytes_hex(&(hdr[20]));
    }
}

static __always_inline void debug_print_int_headers(void *int_hdrs,
                                                    void *data_end)
{
    __u8 *hdr = (__u8 *)int_hdrs;

    bpf_printk("INT:\n");
    debug_print_4_bytes_hex(&(hdr[0]));
    debug_print_4_bytes_hex(&(hdr[4]));
    debug_print_4_bytes_hex(&(hdr[8]));
    debug_print_4_bytes_hex(&(hdr[12]));
    debug_print_4_bytes_hex(&(hdr[16]));
    debug_print_4_bytes_hex(&(hdr[20]));
    debug_print_4_bytes_hex(&(hdr[24]));
    debug_print_4_bytes_hex(&(hdr[28]));
    debug_print_4_bytes_hex(&(hdr[32]));
    if (hdr + 48 > data_end)
        return;
    bpf_printk("12 bytes after INT headers:\n");
    debug_print_4_bytes_hex(&(hdr[36]));
    debug_print_4_bytes_hex(&(hdr[40]));
    debug_print_4_bytes_hex(&(hdr[44]));
}

#endif /* __KUTILS__ */
