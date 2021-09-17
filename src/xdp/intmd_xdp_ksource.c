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

#define PROG_NAME "intmd_xdp_ksource"

struct bpf_map_def SEC("maps") src_flow_stats_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct flow_key),
    .value_size = sizeof(struct src_flow_stats_datarec),
    .max_entries = FLOW_MAP_MAX_ENTRIES,
};

struct bpf_map_def SEC("maps") src_config_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u16),
    .value_size = sizeof(__u64),
    .max_entries = CONFIGURATION_MAP_MAX_ENTRIES,
};

struct bpf_map_def SEC("maps") src_dest_ipv4_filter_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u16),
    .max_entries = DEST_FILTER_MAP_MAX_ENTRIES,
};

SEC("xdp")
int source_func(struct xdp_md *ctx)
{
    int action = XDP_PASS;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    unsigned long curr_ts = get_bpf_timestamp();
    __u16 time_offset_key = CONFIG_MAP_KEY_TIME_OFFSET;
    __u64 *time_offset = bpf_map_lookup_elem(&src_config_map, &time_offset_key);
    if (time_offset != NULL) {
        curr_ts += *time_offset;
#ifdef EXTRA_DEBUG
        bpf_printk(PROG_NAME " Adjusted time with offset %u\n", *time_offset);
#endif
    } else {
        bpf_printk(PROG_NAME " time_offset is NULL\n");
    }
    __u32 src_ts_ns = bpf_htonl((__u32)curr_ts);
    __u16 ingress_port = (__u16)(ctx->ingress_ifindex);
    const int int_hdr_len =
        (sizeof(struct int_shim_hdr) + sizeof(struct int_metadata_hdr) +
         sizeof(struct int_metadata_entry) + sizeof(__u32) +
         sizeof(struct int_tail_hdr));

    struct udphdr udph_cpy = {};
    struct tcphdr tcph_cpy = {};

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bpf_printk(PROG_NAME
                   " Dropping received packet that did not"
                   " contain full Ethernet header (data_end-data)=%d\n",
                   data_end - data);
        action = XDP_DROP;
        goto out;
    }

#ifdef EXTRA_DEBUG
    __u32 dbg_ts = (__u32)curr_ts;
    bpf_printk(PROG_NAME "%u: intmd_xdp_ksource dsz=(data_end-data)=%d"
                         " eth proto=0x%x\n",
               dbg_ts, data_end - data, bpf_ntohs(eth->h_proto));
#endif
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        // No bpf_printk here, since receiving non-IPv4 packets is
        // perfectly normal in many networks.
        goto out;
    }

    /* Get IP header */
    struct iphdr *iph = (struct iphdr *)(void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        bpf_printk(PROG_NAME " Dropping received Ethernet packet"
                             " with proto=0x%x indicating IPv4, but it"
                             " did not contain full IPv4 header"
                             " (data_end-data)=%d\n",
                   bpf_ntohs(eth->h_proto), data_end - data);
        action = XDP_DROP;
        goto out;
    }

    /* Determine whether receiving IPv4 address has been configured as
     * being prepared to receive packets with INT headers.  Note that
     * the key is the IPv4 address in network byte order. */
    __u32 ipv4_daddr_key = iph->daddr;
    __u16 *dest_ipv4_address_config =
        bpf_map_lookup_elem(&src_dest_ipv4_filter_map, &ipv4_daddr_key);
    if (dest_ipv4_address_config == NULL) {
        /* Do not add INT header to this packet. */
#ifdef EXTRA_DEBUG
        /* Only enable this tracing for extra debug, because it could
         * be most packets that take this branch. */
        bpf_printk(PROG_NAME " Dest IPv4 address 0x%x is not in"
                             " destination filter map\n",
                   bpf_ntohl(iph->daddr));
#endif
        goto out;
    }

    struct flow_key key;
    key.saddr = iph->saddr;
    key.daddr = iph->daddr;
    key.proto = iph->protocol;

    struct iphdr iph_cpy;
    __builtin_memcpy(&iph_cpy, iph, sizeof(iph_cpy));

    struct ethhdr eth_cpy;
    __builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

    int oldlen = bpf_htons(iph->tot_len);

    __u32 new_seq_num = 1;
    __u32 udp_length = 0;
    __u32 csum = 0;

#ifdef EXTRA_DEBUG
    {
        __u16 tot_len = bpf_ntohs(iph->tot_len);
        bpf_printk(PROG_NAME " %u: proto=%d ip_tot_len=%d\n", dbg_ts,
                   iph->protocol, tot_len);
        bpf_printk(PROG_NAME "%u: id=0x%x (eth+iplen)-dsz=%d\n", dbg_ts,
                   bpf_ntohs(iph->id),
                   (sizeof(struct ethhdr) + tot_len) - (data_end - data));
    }
#endif
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(void *)(iph + 1);
        if (tcph + 1 > data_end) {
            bpf_printk(PROG_NAME " Dropping received Ethernet+IPv4"
                                 " packet with proto=TCP, but it was too"
                                 " short to contain a full TCP header"
                                 " (data_end-data)=%d\n",
                       data_end - data);
            action = XDP_DROP;
            goto out;
        }
        __builtin_memcpy(&tcph_cpy, tcph, sizeof(*tcph));

        key.sport = tcph->source;
        key.dport = tcph->dest;
#ifdef EXTRA_DEBUG
        bpf_printk(PROG_NAME " [tcp]: %d->%d, %d\n", key.sport, key.dport,
                   new_seq_num);
#endif
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(void *)(iph + 1);
        if (udph + 1 > data_end) {
            bpf_printk(PROG_NAME " Dropping received Ethernet+IPv4"
                                 " packet with proto=UDP, but it was too"
                                 " short to contain a full UDP header"
                                 " (data_end-data)=%d\n",
                       data_end - data);
            action = XDP_DROP;
            goto out;
        }
        __builtin_memcpy(&udph_cpy, udph, sizeof(*udph));
        key.sport = udph->source;
        key.dport = udph->dest;
        udp_length = (__u32)(udph->len);
        csum = (__u32)(~udph->check);
#ifdef EXTRA_DEBUG
        bpf_printk(PROG_NAME " [udp]: %d->%d, %d\n", key.sport, key.dport,
                   new_seq_num);
#endif
    } else {
        // No bpf_printk here, since receiving packets that are
        // neither TCP nor UDP is perfectly normal in many networks.
        goto out;
    }

    struct src_flow_stats_datarec *fstatsrec =
        bpf_map_lookup_elem(&src_flow_stats_map, &key);
    if (fstatsrec != NULL) {
        fstatsrec->seqnum += 1;
        fstatsrec->ts_ns = curr_ts;
        new_seq_num = fstatsrec->seqnum;
        bpf_map_update_elem(&src_flow_stats_map, &key, fstatsrec, BPF_EXIST);
    } else {
        struct src_flow_stats_datarec new_fstatsrec = {
            .seqnum = new_seq_num, .ts_ns = curr_ts, .port = 0};
        int ret = bpf_map_update_elem(&src_flow_stats_map, &key, &new_fstatsrec,
                                      BPF_NOEXIST);
        if (ret < 0) {
            // TODO: See Note 1 in intmd_tc_ksource.c
            goto out;
        }
    }

    /* Then add space in front of the packet */

    int ret = bpf_xdp_adjust_head(ctx, 0 - int_hdr_len);
    if (ret) {
        bpf_printk(PROG_NAME " bpf_xdp_adjust_head by %d failed (%d)\n",
                   0 - int_hdr_len, ret);
        action = XDP_DROP;
        goto out;
    }
    data_end = (void *)(long)ctx->data_end;
    data = (void *)(long)ctx->data;

    eth = data;
    if ((void *)(eth + 1) > data_end) {
        bpf_printk(PROG_NAME " Dropping packet that parsed as"
                             " full packet before bpf_xdp_adjust_head"
                             " but did not contain complete Ethernet header"
                             " afterwards"
                             " (data_end-data)=%d\n",
                   data_end - data);
        action = XDP_DROP;
        goto out;
    }
    __builtin_memcpy(eth, &eth_cpy, sizeof(*eth));

    iph = (struct iphdr *)(void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        bpf_printk(PROG_NAME " Dropping packet that parsed as"
                             " full packet before bpf_xdp_adjust_head"
                             " but did not contain complete IPv4 header"
                             " afterwards"
                             " (data_end-data)=%d\n",
                   data_end - data);
        action = XDP_DROP;
        goto out;
    }
    __builtin_memcpy(iph, &iph_cpy, sizeof(*iph));

    struct int_shim_hdr *inthdr;

    if (iph_cpy.protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(void *)(iph + 1);
        if ((void *)(tcph + 1) > data_end) {
            bpf_printk(PROG_NAME " Dropping packet that parsed as"
                                 " full packet before bpf_xdp_adjust_head"
                                 " but did not contain complete TCP header"
                                 " afterwards"
                                 " (data_end-data)=%d\n",
                       data_end - data);
            action = XDP_DROP;
            goto out;
        }
        __builtin_memcpy(tcph, &tcph_cpy, sizeof(*tcph));

        inthdr = (struct int_shim_hdr *)(void *)(tcph + 1);
    } else {
        struct udphdr *udph = (struct udphdr *)(void *)(iph + 1);
        if ((void *)(udph + 1) > data_end) {
            bpf_printk(PROG_NAME " Dropping packet that parsed as"
                                 " full packet before bpf_xdp_adjust_head"
                                 " but did not contain complete UDP header"
                                 " afterwards"
                                 " (data_end-data)=%d\n",
                       data_end - data);
            action = XDP_DROP;
            goto out;
        }
        __builtin_memcpy(udph, &udph_cpy, sizeof(*udph));

        inthdr = (struct int_shim_hdr *)(void *)(udph + 1);
    }
    if ((void *)(inthdr + 1) > data_end) {
        bpf_printk(PROG_NAME " Dropping packet that does not have enough"
                             " space for inthdr after increasing its size using"
                             " bpf_xdp_adjust_head"
                             " (data_end-data)=%d\n",
                   data_end - data);
        action = XDP_DROP;
        goto out;
    }
    inthdr->type = INT_TYPE_NON_STANDARD_INCLUDES_SEQUENCE_NUMBER;
    inthdr->reserved_1 = 0;
    inthdr->length = int_hdr_len >> 2;
    inthdr->reserved_2 = 0;

    struct int_metadata_hdr *mdhdr;
    mdhdr = (struct int_metadata_hdr *)(void *)(inthdr + 1);
    if ((void *)(mdhdr + 1) > data_end) {
        bpf_printk(PROG_NAME " Dropping packet that does not have enough"
                             " space for mdhdr after increasing its size using"
                             " bpf_xdp_adjust_head"
                             " (data_end-data)=%d\n",
                   data_end - data);
        action = XDP_DROP;
        goto out;
    }
    mdhdr->ver = 0;
    mdhdr->rep = INT_REPLICATION_NONE;
    mdhdr->c = INT_COPY_ORIGINAL_PACKET;
    mdhdr->e = 0;
    mdhdr->reserved_1 = 0;
    mdhdr->ins_cnt = 4;
    mdhdr->max_hop_cnt = 2;
    mdhdr->total_hop_cnt = 1;
    mdhdr->ins_bitmap = bpf_htons(0xcc00);
    mdhdr->reserved_2 = 0;

    struct int_metadata_entry *mdentry;
    mdentry = (struct int_metadata_entry *)(void *)(mdhdr + 1);
    if ((void *)(mdentry + 1) > data_end) {
        bpf_printk(PROG_NAME
                   " Dropping packet that does not have enough"
                   " space for mdentry after increasing its size using"
                   " bpf_xdp_adjust_head"
                   " (data_end-data)=%d\n",
                   data_end - data);
        action = XDP_DROP;
        goto out;
    }

    // read node id from config map
    // enum ConfigKey node_id_key = NODE_ID;
    __u16 node_id_key = CONFIG_MAP_KEY_NODE_ID;
    __u32 *node_id = bpf_map_lookup_elem(&src_config_map, &node_id_key);
    if (node_id == NULL) {
        mdentry->node_id = bpf_htonl(DEFAULT_SOURCE_NODE_ID);
    } else {
        mdentry->node_id = bpf_htonl(*node_id);
    }

    ingress_port = bpf_htons(ingress_port);
    mdentry->ingress_port = ingress_port;
    mdentry->egress_port = ingress_port;
    mdentry->ingress_ts = src_ts_ns;
    mdentry->egress_ts = src_ts_ns;

    __u32 *seq_num = (__u32 *)(void *)(mdentry + 1);
    if ((void *)(seq_num + 1) > data_end) {
        bpf_printk(PROG_NAME
                   " Dropping packet that does not have enough"
                   " space for seq_num after increasing its size using"
                   " bpf_xdp_adjust_head"
                   " (data_end-data)=%d\n",
                   data_end - data);
        action = XDP_DROP;
        goto out;
    }
    new_seq_num = bpf_htonl(new_seq_num);
    __builtin_memcpy(seq_num, &new_seq_num, sizeof(__u32));

    struct int_tail_hdr *tailhdr;
    tailhdr = (struct int_tail_hdr *)(void *)(seq_num + 1);
    if ((void *)(tailhdr + 1) > data_end) {
        bpf_printk(PROG_NAME
                   " Dropping packet that does not have enough"
                   " space for e_bytes after increasing its size using"
                   " bpf_xdp_adjust_head"
                   " (data_end-data)=%d\n",
                   data_end - data);
        action = XDP_DROP;
        goto out;
    }
    tailhdr->proto = 0;
    tailhdr->dest_port_lo = 0;
    tailhdr->dest_port_hi = 0;
    tailhdr->reserved = 0;

    const __u16 int_hdr_minus_iphdr_len =
        (__u16)int_hdr_len - sizeof(struct iphdr);
    int iplen = oldlen + int_hdr_len;
    iph->tot_len = bpf_htons(iplen);

    __u16 dscp_val_key = CONFIG_MAP_KEY_DSCP_VAL;
    __u32 *dscp_val = bpf_map_lookup_elem(&src_config_map, &dscp_val_key);
    __u16 dscp_mask_key = CONFIG_MAP_KEY_DSCP_MASK;
    __u32 *dscp_mask = bpf_map_lookup_elem(&src_config_map, &dscp_mask_key);

    if (dscp_val == NULL || dscp_mask == NULL) {
        iph->tos = ((iph->tos) & ~DEFAULT_INT_DSCP_MASK) |
                   (DEFAULT_INT_DSCP_VAL & DEFAULT_INT_DSCP_MASK);
    } else {
        iph->tos = ((iph->tos) & ~(*dscp_mask)) | (*dscp_val & *dscp_mask);
    }

    ipv4_csum(iph);

    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(void *)(iph + 1);
        if (udph + 1 > data_end) {
            bpf_printk(PROG_NAME " Dropping packet that parsed as"
                                 " full packet before bpf_xdp_adjust_head"
                                 " but did not contain complete UDP header"
                                 " afterwards"
                                 " (data_end-data)=%d\n",
                       data_end - data);
            action = XDP_DROP;
            goto out;
        }
        udph->len = bpf_htons(iplen - sizeof(struct iphdr));
#ifdef EXTRA_DEBUG
        bpf_printk(PROG_NAME " %u: new udp len: %d\n", dbg_ts,
                   iplen - sizeof(struct iphdr));
#endif
        __u32 len = (__u32)(udph->len);
        void *int_data = (data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
                          sizeof(struct udphdr));

        if ((int_data + int_hdr_len) > data_end) {
            goto out;
        }
        csum = bpf_csum_diff(NULL, 0, int_data, int_hdr_len, csum);
        csum = bpf_csum_diff(&udp_length, 4, NULL, 0, csum);
        csum = bpf_csum_diff(&udp_length, 4, NULL, 0, csum);
        csum = bpf_csum_diff(NULL, 0, &len, 4, csum);
        csum = bpf_csum_diff(NULL, 0, &len, 4, csum);
        csum = csum_fold_helper(csum);
        udph->check = csum;

    } else {
        struct tcphdr *tcph = (struct tcphdr *)(void *)(iph + 1);
        if (tcph + 1 > data_end) {
            bpf_printk(PROG_NAME " Dropping packet that parsed as"
                                 " full packet before bpf_xdp_adjust_head"
                                 " but did not contain complete TCP header"
                                 " afterwards"
                                 " (data_end-data)=%d\n",
                       data_end - data);
            action = XDP_DROP;
            goto out;
        }
        tcph->check = 0;
        __u16 tcp_len = oldlen + int_hdr_minus_iphdr_len;
        __u32 tmp = 0;
        __u32 csum = bpf_csum_diff(0, 0, &iph->saddr, sizeof(__be32), 0);
        csum = bpf_csum_diff(0, 0, &iph->daddr, sizeof(__be32), csum);
        tmp = __builtin_bswap32((__u32)iph->protocol);
        csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), csum);
        tmp = __builtin_bswap32((__u32)tcp_len);
        csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), csum);
        ret = variable_length_csum_diff((__u8 *)tcph, tcp_len, data_end, &csum);
        if (ret < 0) {
            bpf_printk(PROG_NAME " failed (%d) variable_length_csum_diff"
                                 " starting at offset %d with length %d\n",
                       ret, (void *)tcph - data, tcp_len);
            action = XDP_DROP;
            goto out;
        }
        csum = csum_fold_helper(csum);
        tcph->check = csum;
    }

out:
    return action;
}
char _license[] SEC("license") = "GPL";
