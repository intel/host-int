/* Copyright (C) 2021 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

#define KBUILD_MODNAME "hostint"
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "intbpf.h"
#include "intmd_headers.h"
#include "kutils.h"

#include "parsing_helpers.h"
#include "rewrite_helpers.h"

struct bpf_map_def SEC("maps") sink_event_perf_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(__u32),
    .max_entries = MAX_CPUS,
};

struct bpf_map_def SEC("maps") sink_flow_stats_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct flow_key),
    .value_size = sizeof(struct sink_flow_stats_datarec),
    .max_entries = FLOW_MAP_MAX_ENTRIES,
};

struct bpf_map_def SEC("maps") sink_config_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u16),
    .value_size = sizeof(__u64),
    .max_entries = CONFIGURATION_MAP_MAX_ENTRIES,
};

SEC("xdp")
int sink_func(struct xdp_md *ctx) {
    int action = XDP_PASS;
    int eth_type, ip_type;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct udphdr *udph;
    struct tcphdr *tcph;

    struct int_shim_hdr *intshimh;
    struct int_metadata_hdr *intmdh;
    struct int_metadata_entry *intmdsrc;
    __u32 *seq_num;
    __u32 csum = 0;
    __u32 *extra_bytes;

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor nh = {.pos = data};
    unsigned long curr_ts = get_bpf_timestamp();
    __u16 time_offset_key = CONFIG_MAP_KEY_TIME_OFFSET;
    __u64 *time_offset =
        bpf_map_lookup_elem(&sink_config_map, &time_offset_key);
    if (time_offset != NULL) {
        curr_ts += *time_offset;
#ifdef EXTRA_DEBUG
        bpf_printk("Adjusted time with offset %lu\n", time_offset);
#endif
    }

    __u32 sink_ts_ns = bpf_htonl((__u32)curr_ts);
    __u16 ingress_port = (__u16)(ctx->ingress_ifindex);

    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type < 0) {
        bpf_printk("intmd_xdp_ksink Dropping received packet that did"
                   " not contain full Ethernet header"
                   " (data_end-data)=%d\n",
                   data_end - data);
        action = XDP_ABORTED;
        goto out;
    }

#ifdef EXTRA_DEBUG
    __u32 dbg_ts = (__u32)curr_ts;
    bpf_printk("%u: intmd_xdp_ksink dsz=(data_end-data)=%d"
               " eth proto=0x%x\n",
               dbg_ts, data_end - data, bpf_ntohs(eth_type));
#endif

    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iph);
        if (ip_type < 0) {
            bpf_printk("intmd_xdp_ksink Dropping received Ethernet"
                       " packet with proto=0x%x indicating IPv4,"
                       " but it did not contain full IPv4 header"
                       " (data_end-data)=%d\n",
                       bpf_ntohs(eth_type), data_end - data);
            action = XDP_ABORTED;
            goto out;
        }
    } else {
        // No bpf_printk here, since receiving non-IPv4
        // packets is perfectly normal in many networks.
        goto out;
    }

    __u16 dscp_val_key = CONFIG_MAP_KEY_DSCP_VAL;
    __u32 *dscp_val_ptr = bpf_map_lookup_elem(&sink_config_map, &dscp_val_key);
    __u16 dscp_mask_key = CONFIG_MAP_KEY_DSCP_MASK;
    __u32 *dscp_mask_ptr =
        bpf_map_lookup_elem(&sink_config_map, &dscp_mask_key);
    __u8 dscp_val = DEFAULT_INT_DSCP_VAL;
    __u8 dscp_mask = DEFAULT_INT_DSCP_MASK;
    if (dscp_val_ptr != NULL && dscp_mask_ptr != NULL) {
        dscp_val = *dscp_val_ptr;
        dscp_mask = *dscp_mask_ptr;
    }
    if ((iph->tos & dscp_mask) != (dscp_val & dscp_mask)) {
        // No bpf_printk here, since receiving IPv4 packets
        // with DSCP indicating no INT header is perfectly
        // normal if source host was configured not to add an
        // INT header to the packet.
        goto out;
    }

    struct flow_key key = {};
    key.saddr = bpf_ntohl(iph->saddr);
    key.daddr = bpf_ntohl(iph->daddr);
    key.proto = iph->protocol;

    /* First copy the original eth and ip headers */
    struct ethhdr eth_cpy;
    __builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

    struct iphdr iph_cpy;
    __builtin_memcpy(&iph_cpy, iph, sizeof(iph_cpy));

    struct udphdr udph_cpy = {};
    struct tcphdr tcph_cpy = {};

    __u32 sink_node_id = DEFAULT_SINK_NODE_ID;
    __u32 pkt_seq_num = 0;

    // read node id from config map
    // enum ConfigKey node_id_key = NODE_ID;
    __u16 node_id_key = CONFIG_MAP_KEY_NODE_ID;
    __u32 *node_id = bpf_map_lookup_elem(&sink_config_map, &node_id_key);
    if (node_id != NULL) {
        sink_node_id = *node_id;
    }

    if (ip_type == IPPROTO_UDP) {
        if (parse_udphdr(&nh, data_end, &udph) < 0) {
            bpf_printk("intmd_xdp_ksink Dropping received"
                       " Ethernet+IPv4 packet with proto=UDP, but"
                       " it was too short to contain a full UDP"
                       " header, or its UDP length was less than 8"
                       " (data_end-data)=%d\n",
                       data_end - data);
            action = XDP_ABORTED;
            goto out;
        }
        key.sport = bpf_ntohs(udph->source);
        key.dport = bpf_ntohs(udph->dest);

        if (parse_int_md_hdr(&nh, data_end, &intshimh, &intmdh, &intmdsrc,
                             &seq_num, &extra_bytes) < 0) {
            bpf_printk("intmd_xdp_ksink Dropping received"
                       " Ethernet+IPv4+UDP packet whose DSCP"
                       " indicated it should"
                       " contain INT headers, but it was too short"
                       " to contain INT headers"
                       " (data_end-data)=%d\n",
                       data_end - data);
            action = XDP_ABORTED;
            goto out;
        }

        __builtin_memcpy(&udph_cpy, udph, sizeof(udph_cpy));

        pkt_seq_num = bpf_ntohl(*seq_num);
        csum = (__u32)(~udph->check);
        void *int_data = (data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
                          sizeof(struct udphdr));
        if ((int_data + 32) > data_end) {
            goto out;
        }
        csum = bpf_csum_diff(int_data, 32, NULL, 0, csum);

    } else if (ip_type == IPPROTO_TCP) {
        if (parse_tcphdr(&nh, data_end, &tcph) < 0) {
            bpf_printk("intmd_xdp_ksink Dropping received"
                       " Ethernet+IPv4 packet with proto=TCP, but"
                       " it was too short to contain a full"
                       " TCP header"
                       " (data_end-data)=%d\n",
                       data_end - data);
            action = XDP_ABORTED;
            goto out;
        }
        key.sport = bpf_ntohs(tcph->source);
        key.dport = bpf_ntohs(tcph->dest);
        csum = (__u32)(~tcph->check);

        __builtin_memcpy(&tcph_cpy, tcph, sizeof(tcph_cpy));

        if (parse_int_md_hdr(&nh, data_end, &intshimh, &intmdh, &intmdsrc,
                             &seq_num, &extra_bytes) < 0) {
            bpf_printk("intmd_xdp_ksink Dropping received"
                       " Ethernet_IPv4+TCP"
                       " packet whose DSCP indicated it should"
                       " contain INT headers, but it was too short"
                       " to contain INT headers"
                       " (data_end-data)=%d\n",
                       data_end - data);
            action = XDP_ABORTED;
            goto out;
        }

        pkt_seq_num = bpf_ntohl(*seq_num);
        void *int_data = data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
                         sizeof(struct tcphdr);
        if ((int_data + 32) > data_end) {
            goto out;
        }
        csum = bpf_csum_diff(int_data, 32, NULL, 0, csum);
    } else {
        // No bpf_printk here, since receiving packets that
        // are neither TCP nor UDP is perfectly normal in many
        // networks.
        goto out;
    }

    __u32 e2e_latency_ns = ((__u32)curr_ts - bpf_ntohl(intmdsrc->ingress_ts));
#ifdef EXTRA_DEBUG
    bpf_printk("intmd_xdp_ksink e2e_latency_ns: %u\n", e2e_latency_ns);
#endif

    __u64 latency_bucket_ns = e2e_latency_bucket(e2e_latency_ns);

    struct sink_flow_stats_datarec *flow_stats_rec =
        bpf_map_lookup_elem(&sink_flow_stats_map, &key);
    int generate_int_report = FALSE;
    if (flow_stats_rec == NULL) {
        struct sink_flow_stats_datarec new_flow_stats_rec = {
            .src_node_id = bpf_ntohl(intmdsrc->node_id),
            .src_port = bpf_ntohs(intmdsrc->ingress_port),
            .sink_node_id = sink_node_id,
            .sink_port = ingress_port,
            .gap_head_ts_ns = curr_ts,
            .gap_head_seq_num = pkt_seq_num,
            .gap_tail_ts_ns = 0,
            .gap_tail_seq_num = 0,
            .gap_pkt_count = 0,
            .latency_bucket_ns = latency_bucket_ns};
        int ret = bpf_map_update_elem(&sink_flow_stats_map, &key,
                                      &new_flow_stats_rec, BPF_NOEXIST);
        if (ret < 0) {
            // See Note 1 in intmd_tc_ksource.c
            generate_int_report = FALSE;
        } else {
            generate_int_report = TRUE;
        }
    } else {
        if (flow_stats_rec->latency_bucket_ns != latency_bucket_ns) {
            generate_int_report = TRUE;
        }
        flow_stats_rec->latency_bucket_ns = latency_bucket_ns;
        update_flow_stats_gap_data(flow_stats_rec, pkt_seq_num, curr_ts);
        // TODO: Should there be a call to
        // bpf_map_update_elem() here to update the value
        // flow_stats_rec for the map entry that was matched?
    }
    if (generate_int_report) {
        struct flow_ds_md tmp_fdsmd = {0, 0, 0, 0, 0}; // dummy values
        __u32 tmp_node_id = 0;
        __u16 tmp_domain_id = 0;
        struct int_metadata_entry intmdsink;
        intmdsink.node_id = bpf_htonl(sink_node_id);
        ingress_port = bpf_htons(ingress_port);
        intmdsink.ingress_port = ingress_port;
        intmdsink.egress_port = ingress_port;
        intmdsink.ingress_ts = sink_ts_ns; // MID-12
        intmdsink.egress_ts = sink_ts_ns;
        // Update the length field in INT shim header to
        // include the extra data added by this sink node, but
        // remove the "reserved garbage data" that the source
        // currently adds at the end of the INT data just
        // before the TCP/UDP payload.
        intshimh->length += ((sizeof(intmdsink) - sizeof(__u32)) >> 2);
        // TODO: Right now the sink code assumes that the INT
        // headers it receives have intmdh->total_hop_count <
        // intmdh->max_hop_cnt, and thus the sink always adds
        // its metadata.  It would be better to check that
        // condition first, and _not_ add sink metadata if it
        // is false.  Implementing that would require some
        // changes to the user-space program that processes
        // these perf events, to handle the multiple cases.
        intmdh->total_hop_cnt += 1;
        send_packet_userspace(ctx, (__u16)(data_end - data),
                              &sink_event_perf_map, &intmdsink, &tmp_fdsmd,
                              &tmp_node_id, &tmp_domain_id);
    }

    // remove INT headers
    const __u16 int_hdrs_len =
        (sizeof(struct int_shim_hdr) + sizeof(struct int_metadata_hdr) +
         sizeof(struct int_metadata_entry) + sizeof(__u32) + sizeof(__u32));
    int ret = bpf_xdp_adjust_head(ctx, int_hdrs_len);
    if (ret < 0) {
        bpf_printk("intmd_xdp_ksink bpf_xdp_adjust_head by %d"
                   " failed (%d)\n",
                   int_hdrs_len, ret);
        action = XDP_ABORTED;
        goto out;
    }

    data_end = (void *)(long)ctx->data_end;
    data = (void *)(long)ctx->data;
    eth = data;
    if ((void *)(eth + 1) > data_end) {
        bpf_printk("intmd_xdp_ksink Dropping packet that parsed as"
                   " full packet before bpf_xdp_adjust_head"
                   " but did not contain complete Ethernet header"
                   " afterwards"
                   " (data_end-data)=%d\n",
                   data_end - data);
        action = XDP_ABORTED;
        goto out;
    }
    __builtin_memcpy(eth, &eth_cpy, sizeof(*eth));

    iph = (struct iphdr *)(void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        bpf_printk("intmd_xdp_ksink Dropping packet that parsed as"
                   " full packet before bpf_xdp_adjust_head"
                   " but did not contain complete IPv4 header"
                   " afterwards"
                   " (data_end-data)=%d\n",
                   data_end - data);
        action = XDP_ABORTED;
        goto out;
    }
    __builtin_memcpy(iph, &iph_cpy, sizeof(*iph));
    __u16 ip_oldlen = bpf_ntohs(iph->tot_len);
    __u16 ip_newlen = ip_oldlen - int_hdrs_len;
    iph->tot_len = bpf_htons(ip_newlen);
#ifdef EXTRA_DEBUG
    bpf_printk("old ip len: %d, new ip len: %d\n", ip_oldlen, ip_newlen);
#endif

    // Restore DSCP value.
    // TODO: Check whether INT source should be preserving the
    // original DSCP value in some INT header field, and here we
    // should be copying it from that field to the IPv4 header.
    iph->tos = iph->tos & ~dscp_mask;
    ipv4_csum(iph);

    __u32 payload_oldlen = (__u32)bpf_htons(ip_oldlen - sizeof(struct iphdr));
    __u32 payload_newlen = (__u32)bpf_htons(ip_newlen - sizeof(struct iphdr));
    if (ip_type == IPPROTO_UDP) {
        // update UDP len
        udph = (struct udphdr *)(void *)(iph + 1);
        if ((void *)(udph + 1) > data_end) {
            bpf_printk("intmd_xdp_ksink Dropping packet that parsed"
                       " as full packet before bpf_xdp_adjust_head"
                       " but did not contain complete UDP header"
                       " afterwards"
                       " (data_end-data)=%d\n",
                       data_end - data);
            action = XDP_ABORTED;
            goto out;
        }
        __builtin_memcpy(udph, &udph_cpy, sizeof(*udph));
        udph->len = payload_newlen;

        // Adjust UDP length once for UDP length in UDP
        // header, and another time for UDP length in UDP
        // pseudo-header.
        csum = bpf_csum_diff(&payload_oldlen, 4, NULL, 0, csum);
        csum = bpf_csum_diff(NULL, 0, &payload_newlen, 4, csum);
        csum = bpf_csum_diff(&payload_oldlen, 4, NULL, 0, csum);
        csum = bpf_csum_diff(NULL, 0, &payload_newlen, 4, csum);
        csum = csum_fold_helper(csum);
        udph->check = csum;
    } else if (ip_type == IPPROTO_TCP) {
        tcph = (struct tcphdr *)(void *)(iph + 1);
        if ((void *)(tcph + 1) > data_end) {
            bpf_printk("intmd_xdp_ksink Dropping packet that parsed"
                       " as full packet before bpf_xdp_adjust_head"
                       " but did not contain complete TCP header"
                       " afterwards"
                       " (data_end-data)=%d\n",
                       data_end - data);
            action = XDP_ABORTED;
            goto out;
        }
        __builtin_memcpy(tcph, &tcph_cpy, sizeof(*tcph));

        csum = bpf_csum_diff(&payload_oldlen, 4, NULL, 0, csum);
        csum = bpf_csum_diff(NULL, 0, &payload_newlen, 4, csum);
        csum = csum_fold_helper(csum);
        tcph->check = csum;
    }

out:
    return action;
}
char _license[] SEC("license") = "GPL";
