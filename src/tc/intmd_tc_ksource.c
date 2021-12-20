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
#include "kutilselfmap.h"

#define PROG_NAME "intmd_tc_ksource"

#define MAX_L4_HDR_LEN sizeof(struct tcphdr)

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

struct bpf_elf_map SEC("maps") src_stats_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(__u32),
    .size_value = sizeof(struct packet_byte_counter),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = NUM_PACKET_BYTE_COUNTERS,
};

/* test_loading_data_after_data_end was written only to do a quick
 * test to verify that it was possible to load packet data that occurs
 * after skb->data_end using the bpf_skb_load_bytes helper function.
 * It is common with Linux kernel versions 5.4 and 5.8 at least
 * (probably many others) that TCP payload data is after
 * skb->data_end. */
static __always_inline int
test_loading_data_after_data_end(struct __sk_buff *skb, struct iphdr *iph,
                                 __u32 dbg_ts)
{
    int bytes_after_data_end;
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    __u16 tot_len = bpf_ntohs(iph->tot_len);
    bytes_after_data_end =
        ((sizeof(struct ethhdr) + tot_len) - (data_end - data));
    bpf_printk(PROG_NAME " %u: proto=%d ip_tot_len=%d\n", dbg_ts, iph->protocol,
               tot_len);
    bpf_printk(PROG_NAME " %u: id=0x%x (eth+iplen)-dsz=%d\n", dbg_ts,
               bpf_ntohs(iph->id), bytes_after_data_end);
    if (bytes_after_data_end >= 16) {
        __u8 buf[16];
        int ret = bpf_skb_load_bytes(skb, data_end - data, buf, 16);
        if (ret < 0) {
            bpf_printk(PROG_NAME " failed (%d) to bpf_skb_load_bytes by 16\n",
                       ret);
            return -1;
        }
        bpf_printk("%u: tc   first 16 bytes after data_end:\n", dbg_ts);
        bpf_printk("%u: tc  \n", dbg_ts);
        bpf_printk(" %x %x\n", buf[0], buf[1]);
        bpf_printk(" %x %x\n", buf[2], buf[3]);
        bpf_printk(" %x %x\n", buf[4], buf[5]);
        bpf_printk(" %x %x\n", buf[6], buf[7]);
        bpf_printk(" %x %x\n", buf[8], buf[9]);
        bpf_printk(" %x %x\n", buf[10], buf[11]);
        bpf_printk(" %x %x\n", buf[12], buf[13]);
        bpf_printk(" %x %x\n", buf[14], buf[15]);
    }
    return 0;
}

/* Note 1:
 *
 * In a source host, if all of the other conditions are right to add
 * an INT header to a packet, but the per-flow map is full, we would
 * not be able to send increasing sequence numbers on subsequent
 * packets in the same flow.  Thus we choose to send the packet from
 * the source without modifying it, i.e. no INT header is added, to
 * avoid adding misleading sequence numbers (all 1) into such an INT
 * header.
 *
 * In a sink host, if we receive a packet with an INT header, we
 * should always remove the INT header before passing the packet on to
 * the kernel, because neither the kernel nor a receiving application
 * are expecteing to see such data in the packet.  However, if the
 * per-flow map is full, there is no reasonable way to track
 * statistics for this packet's flow and generate reports under the
 * desired conditions (e.g. latency changes for packets within the
 * flow), so never generate a perf event to user space when a sink
 * EBPF program fails to create an entry for a packet in the per-flow
 * map.
 *
 * Consider whether it is worth doing anything special in the case
 * where attempting to add a new flow to src_flow_stats_map fails,
 * because the maximum number of map entries are already installed
 * before this packet arrived.  One possibility: Keep a count of how
 * many times this happens in some counter in a separate EBPF map.  It
 * would _not_ be a good idea performance-wise to create a perf event
 * every time this occurs, since once the map is full, every packet of
 * a flow that is not already in the map will cause this to happen
 * again, which could be a large fraction of packets processed. */

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
    __u8 tmp_l4_hdr[MAX_L4_HDR_LEN];

#ifdef EXTRA_DEBUG
    __u32 dbg_ts = (__u32)curr_ts;
    bpf_printk(PROG_NAME " %u: dsz=(data_end-data)=%d\n", dbg_ts,
               data_end - data);
#endif

    cfg_key = CONFIG_MAP_KEY_STATS_BASE_ADDRESS;
    __u64 *stats_base_addr_ptr = bpf_map_lookup_elem(&src_config_map, &cfg_key);
    __u32 stats_base_addr = 0;
    if (stats_base_addr_ptr != NULL) {
        stats_base_addr = (__u32)*stats_base_addr_ptr;
    }
    __u32 stats_offset = STATS_OTHER;
    __u16 pkt_len_for_stats = data_end - data;

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
        stats_offset = STATS_NOT_IPV4;
        goto out;
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
    pkt_len_for_stats = bpf_ntohs(iph->tot_len);

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
        stats_offset = STATS_IPV4_NO_INT_HEADER;
        goto out;
    }

    if ((int)oldlen > (DEFAULT_MTU - int_hdr_len)) {
#ifdef EXTRA_DEBUG
        bpf_printk(PROG_NAME
                   " IP length too big ip_length=%d"
                   " - forwarding packet with no modifications made\n",
                   (int)oldlen);
#endif
        if (iph->protocol == IPPROTO_TCP) {
            stats_offset = STATS_IPV4_TCP_TOO_LONG_TO_ADD_INT_HEADER;
        } else if (iph->protocol == IPPROTO_UDP) {
            stats_offset = STATS_IPV4_UDP_TOO_LONG_TO_ADD_INT_HEADER;
        } else {
            stats_offset =
                STATS_IPV4_NEITHER_TCP_NOR_UDP_TOO_LONG_TO_ADD_INT_HEADER;
        }
        goto out;
    }

    if ((bpf_ntohs(iph->frag_off) & IPV4_FRAG_OFFSET_MASK) != 0) {
#ifdef EXTRA_DEBUG
        bpf_printk(PROG_NAME " Not a first IPv4 fragment packet");
#endif
        if (iph->protocol == IPPROTO_TCP) {
            stats_offset = STATS_IPV4_TCP_NON_FIRST_FRAGMENT;
        } else if (iph->protocol == IPPROTO_UDP) {
            stats_offset = STATS_IPV4_UDP_NON_FIRST_FRAGMENT;
        } else {
            stats_offset = STATS_IPV4_NEITHER_TCP_NOR_UDP_NON_FIRST_FRAGMENT;
        }
        goto out;
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
    __u32 udp_length = 0;
    int l4hdrsize;
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
        l4hdrsize = sizeof(struct tcphdr);
        ret = bpf_skb_load_bytes(skb, offset, tmp_l4_hdr, l4hdrsize);
        if (ret < 0) {
            bpf_printk(PROG_NAME
                       " failed (%d) to bpf_skb_load_bytes"
                       " for TCP hdr with offset=%d len=%d"
                       " - forwarding packet with no modifications made\n",
                       ret, offset, l4hdrsize);
            return rc;
        }
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
        udp_length = (__u32)bpf_ntohs(udph->len);
#ifdef EXTRA_DEBUG
        bpf_printk(PROG_NAME " %d->%d\n", key.sport, key.dport);
#endif
        l4hdrsize = sizeof(struct udphdr);
        ret = bpf_skb_load_bytes(skb, offset, tmp_l4_hdr, l4hdrsize);
        if (ret < 0) {
            bpf_printk(PROG_NAME
                       " failed (%d) to bpf_skb_load_bytes"
                       " for TCP hdr with offset=%d len=%d"
                       " - forwarding packet with no modifications made\n",
                       ret, offset, l4hdrsize);
            return rc;
        }
    } else {
        // No bpf_printk here, since this could be a commonly taken
        // code path, for any packets that are neither TCP nor UDP.
        stats_offset = STATS_IPV4_NEITHER_TCP_NOR_UDP;
        goto out;
    }

#ifdef EXTRA_DEBUG
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
#ifdef EXTRA_DEBUG
            bpf_printk(PROG_NAME " failed (%d) adding new entry key=%s\n", ret,
                       buf);
#endif
            stats_offset = STATS_FLOW_STATS_MAP_FAILED_TO_ADD_ENTRY;
            goto out;
        }
#ifdef EXTRA_DEBUG
        bpf_printk(PROG_NAME " new entry key=%s\n", buf);
#endif
    }

    /*
     * Grow room for INT data in the packet associated to skb by length
     * BPF_ADJ_ROOM_NET: Adjust room at the network layer
     *  (new bytes are added just after the layer 3 header).
     */
    ret = bpf_skb_adjust_room(skb, int_hdr_len, BPF_ADJ_ROOM_NET, 0);
    if (ret < 0) {
        bpf_printk(PROG_NAME " failed (%d) to bpf_skb_adjust_room by %d"
                             " - dropping packet\n",
                   ret, int_hdr_len);
        // For any error conditions starting with the call to
        // bpf_skb_adjust_room, it seems best to drop the packet,
        // instead of letting it go through the kernel and perhaps
        // transmitted out of the host in some partially modified
        // state.
        rc = TC_ACT_SHOT;
        return rc;
    }

    // Copy L4 header to just after the IP header
    ret = bpf_skb_store_bytes(skb, offset, tmp_l4_hdr, l4hdrsize, 0);
    if (ret < 0) {
        bpf_printk(PROG_NAME " failed (%d) to bpf_skb_store_bytes"
                             " with offset: %d"
                             " - dropping packet\n",
                   ret, offset);
        rc = TC_ACT_SHOT;
        return rc;
    }

    // insert INT header
    struct int_shim_hdr inthdr = {
        .type = INT_TYPE_NON_STANDARD_INCLUDES_SEQUENCE_NUMBER,
        .reserved_1 = 0,
        .length = int_hdr_len >> 2,
        .reserved_2 = 0};
    // TODO: Is this code adding the INT tail header described in
    // [INT05] Section 5.3.1?  If it is not, should it?
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
    __u64 *cfg_val_ptr;
    cfg_val_ptr = bpf_map_lookup_elem(&src_config_map, &cfg_key);
    __be32 id = DEFAULT_SOURCE_NODE_ID;
    if (cfg_val_ptr != NULL) {
        id = (__be32)*cfg_val_ptr;
    }

    struct int_metadata_entry mdentry = {.node_id = bpf_htonl(id),
                                         .ingress_port =
                                             bpf_htons(skb->ifindex),
                                         .egress_port = bpf_htons(skb->ifindex),
                                         .ingress_ts = src_ts_ns,
                                         .egress_ts = src_ts_ns};

    // Intentionally filling the tail header with 0s, because at least for TCP
    // packets later Linux kernel code, or the NIC, usually overwrite several
    // of these bytes, so cannot rely on their values getting through to the
    // sink.
    struct int_tail_hdr tail_hdr = {
        .proto = 0, .dest_port_hi = 0, .dest_port_lo = 0, .reserved = 0};

    // TODO: Consider making a minor optimization where all of the
    // data to be copied into the packet is copied in a single
    // bpf_skb_store_bytes call, instead of several.
    offset += l4hdrsize;
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

    const __u16 int_hdr_minus_iphdr_len = int_hdr_len - sizeof(struct iphdr);
    __u16 iplen = oldlen + int_hdr_len;
    iph->tot_len = bpf_htons(iplen);

    cfg_key = CONFIG_MAP_KEY_DSCP_VAL;
    cfg_val_ptr = bpf_map_lookup_elem(&src_config_map, &cfg_key);
    __u8 dscp_val = DEFAULT_INT_DSCP_VAL << 2;
    if (cfg_val_ptr != NULL) {
        dscp_val = (__u8)*cfg_val_ptr;
    }
    cfg_key = CONFIG_MAP_KEY_DSCP_MASK;
    cfg_val_ptr = bpf_map_lookup_elem(&src_config_map, &cfg_key);
    __u8 dscp_mask = DEFAULT_INT_DSCP_MASK << 2;
    if (cfg_val_ptr != NULL) {
        dscp_mask = (__u8)*cfg_val_ptr;
    }
    iph->tos = (iph->tos & ~dscp_mask) | (dscp_val & dscp_mask);

    ipv4_csum(iph);

    if (iph->protocol == IPPROTO_UDP) {
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

        udph->len = bpf_htons(udp_length + int_hdr_len);
        __u32 len = (__u32)udph->len;
        void *int_data = ((void *)udph) + sizeof(struct udphdr);
        if ((int_data + int_hdr_len) > data_end) {
            return rc;
        }
        __u32 csum = bpf_csum_diff(NULL, 0, int_data, int_hdr_len,
                                   bpf_ntohs(udph->check));
        /* update checksum for INT header */
        ret = bpf_l4_csum_replace(skb, UDP_CSUM_OFF, bpf_ntohs(udph->check),
                                  csum, sizeof(csum));
        if (ret < 0) {
            bpf_printk(PROG_NAME " failed (%d) to replace checksum"
                                 " for added data"
                                 " - dropping packet\n",
                       ret);
            rc = TC_ACT_SHOT;
            return rc;
        }

        /* Update checksum for new length in udp header */
        ret = bpf_l4_csum_replace(
            skb, UDP_CSUM_OFF, (__u32)bpf_htons(udp_length), len, sizeof(len));
        if (ret < 0) {
            bpf_printk(PROG_NAME " failed (%d) to replace checksum"
                                 " for new udp len"
                                 " - dropping packet\n",
                       ret);
            rc = TC_ACT_SHOT;
            return rc;
        }

        /* Update checksum for new length in pseudo header */
        ret =
            bpf_l4_csum_replace(skb, UDP_CSUM_OFF, (__u32)bpf_htons(udp_length),
                                len, BPF_F_PSEUDO_HDR | sizeof(len));
        if (ret < 0) {
            bpf_printk(PROG_NAME " failed (%d) to replace pseudo header"
                                 " checksum"
                                 " - dropping packet\n",
                       ret);
            rc = TC_ACT_SHOT;
            return rc;
        }
        stats_offset = STATS_IPV4_UDP_INT_HEADER_ADDED;
    } else if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(void *)(iph + 1);
        if (tcph + 1 > data_end) {
            bpf_printk(PROG_NAME
                       " Dropping packet that parsed as"
                       " full packet before bpf_skb_adjust_room"
                       " but did not contain complete TCP header afterwards"
                       " - dropping packet"
                       " (data_end-data)=%d\n",
                       data_end - data);
            rc = TC_ACT_SHOT;
            return rc;
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
        ret = skb_variable_length_csum_diff(skb, (__u8 *)tcph, tcp_len, &csum);
        if (ret < 0) {
            bpf_printk(PROG_NAME " failed (%d) variable_length_csum_diff"
                                 " starting at offset %d with length %d"
                                 " - dropping packet\n",
                       ret, (void *)tcph - data, tcp_len);
            rc = TC_ACT_SHOT;
            return rc;
        }
        csum = csum_fold_helper(csum);
        tcph->check = csum;
        stats_offset = STATS_IPV4_TCP_INT_HEADER_ADDED;
    }

out:
    update_stats_elf(stats_base_addr + stats_offset, &src_stats_map,
                     pkt_len_for_stats);

    return rc;
}

char _license[] SEC("license") = "GPL";
