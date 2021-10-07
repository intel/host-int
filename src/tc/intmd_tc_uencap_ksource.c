/* Copyright (C) 2021 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/types.h>
#define KBUILD_MODNAME "hostint"
#ifdef asm_volatile_goto
#undef asm_volatile_goto
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")
#endif
#define volatile(x...) volatile("")

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
// we are using tc to load in our ebpf program that will
// create maps for us and require structure bpf_elf_map
#include <iproute2/bpf_elf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "intbpf.h"

#include "parsing_helpers.h"
#include "rewrite_helpers.h"
#include "intmd_headers.h"
#include "kutils.h"

#define PROG_NAME "intmd_tc_uencap_ksource"

#define MAX_L4_HDR_LEN sizeof(struct tcphdr)
#undef TRY_ADDING_INT_TO_TCP_SUPERPACKETS
#undef FLOW_DEBUG

#define UDP_CSUM_OFF                                                           \
    (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check))

struct bpf_elf_map SEC("maps") src_flow_stats_map = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(struct flow_key),
    .size_value = sizeof(struct src_flow_stats_datarec),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = FLOW_MAP_MAX_ENTRIES,
};

struct bpf_elf_map SEC("maps") src_config_map = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(__u16),
    .size_value = sizeof(__u64),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = CONFIGURATION_MAP_MAX_ENTRIES,
};

struct bpf_elf_map SEC("maps") src_dest_ipv4_filter_map = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(__u32),
    .size_value = sizeof(__u16),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = DEST_FILTER_MAP_MAX_ENTRIES,
};

SEC("source_egress")
int source_egress_func(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    int rc = TC_ACT_OK;
    int ret;
    unsigned long curr_ts = get_bpf_timestamp();

    const __u16 int_hdr_len =
        (sizeof(struct int_shim_hdr) + sizeof(struct int_metadata_hdr) +
         sizeof(struct int_metadata_entry) + sizeof(__u32) +
         sizeof(struct int_tail_hdr));

    const __u16 total_int_len_with_int_udp =
        (sizeof(struct udphdr) + int_hdr_len);

    __u16 cfg_key;
    cfg_key = CONFIG_MAP_KEY_TIME_OFFSET;
    __u64 *time_offset = bpf_map_lookup_elem(&src_config_map, &cfg_key);
    if (time_offset != NULL) {
        curr_ts += *time_offset;
#ifdef EXTRA_DEBUG
        bpf_printk(PROG_NAME " Adjusted time with offset %lu\n", *time_offset);
#endif
    } else {
        bpf_printk(PROG_NAME " time_offset is NULL\n");
    }

    __u32 src_ts_ns = bpf_htonl((__u32)curr_ts);

#ifdef EXTRA_DEBUG
    __u32 dbg_ts = (__u32)curr_ts;
    bpf_printk(PROG_NAME "%u: dsz=(data_end-data)=%d\n", dbg_ts,
               data_end - data);
#endif

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bpf_printk(PROG_NAME " processed packet that did not"
                             " contain full Ethernet header"
                             " - forwarding packet with no modifications made"
                             " (data_end-data)=%d\n",
                   data_end - data);
        return rc;
    }

#ifdef EXTRA_DEBUG
    bpf_printk(PROG_NAME " %u: dsz=(data_end-data)=%d eth proto=0x%x\n", dbg_ts,
               data_end - data, bpf_ntohs(eth->h_proto));
#endif
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        // No bpf_printk here -- this can be a frequent path, e.g. for
        // IPv6 packets.
        return rc;
    }

    /* Get IP header */
    struct iphdr *iph = (struct iphdr *)(void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        bpf_printk(PROG_NAME " Processed Ethernet packet"
                             " with proto=0x%x indicating IPv4, but it"
                             " did not contain full IPv4 header"
                             " - forwarding packet with no modifications made"
                             " (data_end-data)=%d\n",
                   bpf_ntohs(eth->h_proto), data_end - data);
        return rc;
    }

    /* Determine whether receiving IPv4 address has been configured as
     * being prepared to receive packets with INT headers.  Note that
     * the key is the IPv4 address in network byte order. */
    __u32 ipv4_daddr_key = iph->daddr;

    __u16 oldlen = bpf_ntohs(iph->tot_len);

    __u16 *dest_ipv4_address_config =
        bpf_map_lookup_elem(&src_dest_ipv4_filter_map, &ipv4_daddr_key);
    if (dest_ipv4_address_config == NULL) {
        /* Do not add INT header to this packet. */
#ifdef EXTRA_DEBUG
        /* Only enable this tracing for extra debug, because it could
         * be most packets that take this branch. */
        bpf_printk(PROG_NAME
                   " dest IPv4 address 0x%x is not in destination filter map",
                   " - forwarding packet with no modifications made\n",
                   bpf_ntohl(iph->daddr));
#endif
        return rc;
    }

    if ((int)oldlen > (DEFAULT_MTU - total_int_len_with_int_udp)) {
#ifdef TRY_ADDING_INT_TO_TCP_SUPERPACKETS
        bpf_printk(PROG_NAME " IP length %d is larger than MTU-%d"
                             " - adding UDP + INT header anyway\n",
                   (int)oldlen, (int)total_int_len_with_int_udp);
#else
#ifdef EXTRA_DEBUG
        bpf_printk(PROG_NAME
                   " IP length too big ip_length=%d"
                   " - forwarding packet with no modifications made\n",
                   (int)oldlen);
#endif
        return rc;
#endif // TRY_ADDING_INT_TO_TCP_SUPERPACKETS
    }

    if ((bpf_ntohs(iph->frag_off) & IPV4_FRAG_OFFSET_MASK) != 0) {
#ifdef EXTRA_DEBUG
        bpf_printk(PROG_NAME " Not a first IPv4 fragment packet");
#endif
        return rc;
    }

#ifdef EXTRA_DEBUG
    ret = test_loading_data_after_data_end(skb, iph, dbg_ts);
    if (ret < 0) {
        return rc;
    }
#endif

    struct flow_key key;
    key.saddr = iph->saddr;
    key.daddr = iph->daddr;
    key.proto = iph->protocol;

    __u32 new_seq_num = 1;
    __u32 offset = sizeof(struct ethhdr) + sizeof(struct iphdr);

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(void *)(iph + 1);
        if (tcph + 1 > data_end) {
            bpf_printk(PROG_NAME
                       " Processed Ethernet+IPv4"
                       " packet with proto=TCP, but it was too"
                       " short to contain a full TCP header"
                       " - forwarding packet with no modifications made"
                       " (data_end-data)=%d\n",
                       data_end - data);
            return rc;
        }
        key.sport = tcph->source;
        key.dport = tcph->dest;
#ifdef EXTRA_DEBUG
        bpf_printk(PROG_NAME " %d->%d\n", key.sport, key.dport);
#endif
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(void *)(iph + 1);
        if (udph + 1 > data_end) {
            bpf_printk(PROG_NAME
                       " processed Ethernet+IPv4"
                       " packet with proto=UDP, but it was too"
                       " short to contain a full UDP header"
                       " - forwarding packet with no modifications made"
                       " (data_end-data)=%d\n",
                       data_end - data);
            return rc;
        }
        key.sport = udph->source;
        key.dport = udph->dest;
#ifdef EXTRA_DEBUG
        bpf_printk(PROG_NAME " %d->%d\n", key.sport, key.dport);
#endif
    } else {
        // No bpf_printk here, since this could be a commonly taken
        // code path, for any packets that are neither TCP nor UDP.
        return rc;
    }

#ifdef FLOW_DEBUG
    char buf[SPRINTF_FLOW_KEY_HEX_BUF_SIZE];
    sprintf_flow_key_hex(buf, &key);
#endif

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
        ret = bpf_map_update_elem(&src_flow_stats_map, &key, &new_fstatsrec,
                                  BPF_NOEXIST);
        if (ret < 0) {
            // See Note 1
#ifdef FLOW_DEBUG
            bpf_printk(PROG_NAME " failed (%d) adding new entry key=%s\n", ret,
                       buf);
#endif
            return rc;
        }
#ifdef FLOW_DEBUG
        bpf_printk(PROG_NAME " new entry key=%s\n", buf);
#endif
    }

    /*
     * Grow room for INT data in the packet associated to skb by length
     * BPF_ADJ_ROOM_NET: Adjust room at the network layer
     *  (new bytes are added just after the layer 3 header).
     */
    /*
    bpf_printk(PROG_NAME " Total length(UDP + INT headers) %u\n",
               total_int_len_with_int_udp);
    */
#ifdef EXTRA_DEBUG
    bpf_printk(PROG_NAME " ipv4.id %u len %u seqnum %u\n", bpf_ntohs(iph->id),
               bpf_ntohs(iph->tot_len), new_seq_num);
#endif
    ret = bpf_skb_adjust_room(skb, total_int_len_with_int_udp, BPF_ADJ_ROOM_NET,
                              BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 |
                                  BPF_F_ADJ_ROOM_ENCAP_L4_UDP);
    if (ret < 0) {
        bpf_printk(PROG_NAME " failed (%d) to bpf_skb_adjust_room by %d"
                             " - dropping packet\n",
                   ret, total_int_len_with_int_udp);
        // For any error conditions starting with the call to
        // bpf_skb_adjust_room, it seems best to drop the packet,
        // instead of letting it go through the kernel and perhaps
        // transmitted out of the host in some partially modified
        // state.
        rc = TC_ACT_SHOT;
        return rc;
    }

    /* Insert UDP header */
    cfg_key = CONFIG_MAP_KEY_INT_UDP_ENCAP_DEST_PORT;
    __u32 *cfg_val_ptr;
    __u16 udp_dest_port;
    cfg_val_ptr = bpf_map_lookup_elem(&src_config_map, &cfg_key);
    if (cfg_val_ptr != NULL) {
        /* For some extra EBPF program run-time efficiency, this
         * config value should be stored in the config map in network
         * byte order, in the least significant 16 bits of the 32-bit
         * value. */
        udp_dest_port = (__be16)*cfg_val_ptr;
    } else {
        udp_dest_port = bpf_htons(DEFAULT_INT_UDP_DEST_PORT);
    }
    /* out_udph.len is initialized below after the call to
     * bpf_skb_adjust_room. */
    struct udphdr out_udph = {
        .source = key.sport, .dest = udp_dest_port, .check = 0};

    /* Insert INT header */
    struct int_shim_hdr inthdr = {
        .type = INT_TYPE_NON_STANDARD_INCLUDES_SEQUENCE_NUMBER,
        .reserved_1 = 0,
        .length = int_hdr_len >> 2,
        .reserved_2 = 0};
    struct int_metadata_hdr mdhdr = {.ver = 0,
                                     .rep = INT_REPLICATION_NONE,
                                     .c = INT_COPY_ORIGINAL_PACKET,
                                     .e = 0,
                                     .ins_cnt = 4,
                                     .reserved_1 = 0,
                                     .max_hop_cnt = 2,
                                     .total_hop_cnt = 1,
                                     .ins_bitmap = bpf_htons(0xcc00),
                                     .reserved_2 = 0};

    cfg_key = CONFIG_MAP_KEY_NODE_ID;
    cfg_val_ptr = bpf_map_lookup_elem(&src_config_map, &cfg_key);
    int id = DEFAULT_SOURCE_NODE_ID;
    if (cfg_val_ptr != NULL) {
        id = *cfg_val_ptr;
    }

    struct int_metadata_entry mdentry = {.node_id = bpf_htonl(id),
                                         .ingress_port =
                                             bpf_htons(skb->ifindex),
                                         .egress_port = bpf_htons(skb->ifindex),
                                         .ingress_ts = src_ts_ns,
                                         .egress_ts = src_ts_ns};
    struct int_tail_hdr tail_hdr = {.proto = key.proto,
                                    .dest_port_hi = 0,
                                    .dest_port_lo = 0,
                                    .reserved = 0};
    // TODO: Consider making a minor optimization where all of the
    // data to be copied into the packet is copied in a single
    // bpf_skb_store_bytes call, instead of several.
    ret = bpf_skb_store_bytes(skb, offset, &out_udph, sizeof(struct udphdr), 0);
    if (ret < 0) {
        bpf_printk(PROG_NAME " failed (%d) to bpf_skb_store_bytes"
                             " with offset: %d"
                             " - dropping packet\n",
                   ret, offset);
        rc = TC_ACT_SHOT;
        return rc;
    }
    offset += sizeof(struct udphdr);
    ret = bpf_skb_store_bytes(skb, offset, &inthdr, sizeof(struct int_shim_hdr),
                              0);
    if (ret < 0) {
        bpf_printk(PROG_NAME
                   " Failed (%d) to bpf_skb_store_bytes with offset: %d"
                   " - dropping packet\n",
                   ret, offset);
        rc = TC_ACT_SHOT;
        return rc;
    }

    offset += sizeof(struct int_shim_hdr);
    ret = bpf_skb_store_bytes(skb, offset, &mdhdr,
                              sizeof(struct int_metadata_hdr), 0);
    if (ret < 0) {
        bpf_printk(PROG_NAME
                   " Failed (%d) to bpf_skb_store_bytes with offset: %d"
                   " - dropping packet\n",
                   ret, offset);
        rc = TC_ACT_SHOT;
        return rc;
    }

    offset += sizeof(struct int_metadata_hdr);
    ret = bpf_skb_store_bytes(skb, offset, &mdentry,
                              sizeof(struct int_metadata_entry), 0);
    if (ret < 0) {
        bpf_printk(PROG_NAME
                   " Failed (%d) to bpf_skb_store_bytes with offset: %d"
                   " - dropping packet\n",
                   ret, offset);
        rc = TC_ACT_SHOT;
        return rc;
    }

    offset += sizeof(struct int_metadata_entry);
    new_seq_num = bpf_htonl(new_seq_num);
    ret = bpf_skb_store_bytes(skb, offset, &new_seq_num, sizeof(__u32), 0);
    if (ret < 0) {
        bpf_printk(PROG_NAME
                   " Failed (%d) to bpf_skb_store_bytes with offset: %d"
                   " - dropping packet\n",
                   ret, offset);
        rc = TC_ACT_SHOT;
        return rc;
    }

    offset += sizeof(__u32);
    ret = bpf_skb_store_bytes(skb, offset, &tail_hdr,
                              sizeof(struct int_tail_hdr), 0);
    if (ret < 0) {
        bpf_printk(PROG_NAME
                   " Failed (%d) to bpf_skb_store_bytes with offset: %d"
                   " - dropping packet\n",
                   ret, offset);
        rc = TC_ACT_SHOT;
        return rc;
    }

    data_end = (void *)(long)skb->data_end;
    data = (void *)(long)skb->data;
    iph = (struct iphdr *)(data + sizeof(struct ethhdr));
    if ((void *)(iph + 1) > data_end) {
        bpf_printk(PROG_NAME
                   " Dropping packet that parsed as"
                   " full packet before bpf_skb_adjust_room"
                   " but did not contain complete IPv4 header afterwards"
                   " - dropping packet"
                   " (data_end-data)=%d\n",
                   data_end - data);
        rc = TC_ACT_SHOT;
        return rc;
    }

    __u16 iplen = oldlen + total_int_len_with_int_udp;
    iph->tot_len = bpf_htons(iplen);
    iph->protocol = IPPROTO_UDP;
    ipv4_csum(iph);

    struct udphdr *udph = (struct udphdr *)(void *)(iph + 1);
    if (udph + 1 > data_end) {
        bpf_printk(PROG_NAME
                   " Dropping packet that parsed as"
                   " full packet before bpf_skb_adjust_room"
                   " but did not contain complete UDP header afterwards"
                   " - dropping packet"
                   " (data_end-data)=%d\n",
                   data_end - data);
        rc = TC_ACT_SHOT;
        return rc;
    }
    udph->len = bpf_htons(iplen - sizeof(struct iphdr));

    return rc;
}

char _license[] SEC("license") = "GPL";
