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

#define PROG_NAME "intmd_xdp_uencap_ksink"
#undef SEQNUM_DEBUG
struct temp_space_data_t {
    struct ethhdr eth_cpy;
    struct iphdr iph_cpy;
};

/* temp_space_map is only intended to temporarily store data while
 * processing a single packet that does not easily fit on the 512-byte
 * call stack.  The only possible reason to access it from a user
 * space program would be for debugging, but even then there would be
 * no way to get a consistent snapshot of the value 'between packets',
 * or at any other desired point in time, from a user space
 * program. */
struct bpf_map_def SEC("maps") temp_space_map = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct temp_space_data_t),
    .max_entries = 1,
};

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

struct bpf_map_def SEC("maps") latency_bucket_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u16),
    .value_size = sizeof(struct latency_bucket_entries),
    .max_entries = LATENCYBUCKET_MAP_MAX_ENTRIES,
};

SEC("xdp")
int sink_func(struct xdp_md *ctx)
{
    int action = XDP_PASS;
    int eth_type, ip_type;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct udphdr *udph;
    struct tcphdr *tcph;

    const __u16 int_hdr_len =
        (sizeof(struct int_shim_hdr) + sizeof(struct int_metadata_hdr) +
         sizeof(struct int_metadata_entry) + sizeof(__u32) +
         sizeof(struct int_tail_hdr));
    const __u16 total_int_len_with_int_udp =
        (sizeof(struct udphdr) + int_hdr_len);

    struct int_shim_hdr *intshimh;
    struct int_metadata_hdr *intmdh;
    struct int_metadata_entry *intmdsrc;
    struct int_tail_hdr *tail_hdr;
    __u32 *seq_num;

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor nh = {.pos = data};
    unsigned long curr_ts = get_bpf_timestamp();
    __u16 cfg_key;
    cfg_key = CONFIG_MAP_KEY_TIME_OFFSET;
    __u64 *time_offset = bpf_map_lookup_elem(&sink_config_map, &cfg_key);
    if (time_offset != NULL) {
        curr_ts += *time_offset;
#ifdef EXTRA_DEBUG
        bpf_printk(PROG_NAME " Adjusted time with offset %lu\n", *time_offset);
#endif
    } else {
        bpf_printk(PROG_NAME " time_offset is NULL\n");
    }

    __u32 sink_ts_ns = bpf_htonl((__u32)curr_ts);
    __u16 ingress_port = (__u16)(ctx->ingress_ifindex);

    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type < 0) {
        bpf_printk(PROG_NAME " Dropping received packet that did"
                             " not contain full Ethernet header"
                             " (data_end-data)=%d\n",
                   data_end - data);
        action = XDP_DROP;
        goto out;
    }

#ifdef EXTRA_DEBUG
    __u32 dbg_ts = (__u32)curr_ts;
    bpf_printk(PROG_NAME " %u: dsz=(data_end-data)=%d"
                         " eth proto=0x%x\n",
               dbg_ts, data_end - data, bpf_ntohs(eth_type));
#endif

    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iph);
        if (ip_type < 0) {
            bpf_printk(PROG_NAME " Dropping received Ethernet"
                                 " packet with proto=0x%x indicating IPv4,"
                                 " but it did not contain full IPv4 header"
                                 " (data_end-data)=%d\n",
                       bpf_ntohs(eth_type), data_end - data);
            action = XDP_DROP;
            goto out;
        }
    } else {
        // No bpf_printk here, since receiving non-IPv4
        // packets is perfectly normal in many networks.
        goto out;
    }

    if ((bpf_ntohs(iph->frag_off) & IPV4_FRAG_OFFSET_MASK) != 0) {
#ifdef EXTRA_DEBUG
        bpf_printk(PROG_NAME " Not a first IPv4 fragment packet");
#endif
        goto out;
    }

    if (ip_type != IPPROTO_UDP) {
        /* No bpf_printk here, since receiving packets with no INT
         * header is perfectly normal in many networks. */
#ifdef SEQNUM_DEBUG
        bpf_printk(PROG_NAME " proto %u ipv4.id %u len %u\n", iph->protocol,
                   bpf_ntohs(iph->id), bpf_ntohs(iph->tot_len));
#endif // SEQNUM_DEBUG
        goto out;
    }
    if (parse_udphdr(&nh, data_end, &udph) < 0) {
        bpf_printk(PROG_NAME " Dropping received"
                             " Ethernet+IPv4 packet with proto=UDP, but"
                             " it was too short to contain a full UDP"
                             " header, or its UDP length was less than 8"
                             " (data_end-data)=%d\n",
                   data_end - data);
        action = XDP_DROP;
        goto out;
    }
    /* Check if UDP dest port indicates that an INT header
     * follows. */
    cfg_key = CONFIG_MAP_KEY_INT_UDP_ENCAP_DEST_PORT;
    __u32 *cfg_val_ptr;
    __u16 int_udp_dest_port;
    cfg_val_ptr = bpf_map_lookup_elem(&sink_config_map, &cfg_key);
    if (cfg_val_ptr != NULL) {
        int_udp_dest_port = (__be16)*cfg_val_ptr;
    } else {
        int_udp_dest_port = bpf_htons(DEFAULT_INT_UDP_DEST_PORT);
    }
    if (udph->dest != int_udp_dest_port) {
        /* No INT header follows the UDP header.  Send the packet
         * onwards without modifying it. */
#ifdef SEQNUM_DEBUG
        bpf_printk(PROG_NAME " non-INT UDP ipv4.id %u len %u dport %u\n",
                   bpf_ntohs(iph->id), bpf_ntohs(iph->tot_len),
                   bpf_ntohs(udph->dest));
#endif // SEQNUM_DEBUG
        goto out;
    }

    struct flow_key key = {};
    key.saddr = iph->saddr;
    key.daddr = iph->daddr;

    __u32 temp_space_key = 0;
    struct temp_space_data_t *temp_space =
        bpf_map_lookup_elem(&temp_space_map, &temp_space_key);
    if (temp_space == NULL) {
        /* This is completely unexpected for an array map.  It should
         * never happen. */
        bpf_printk(PROG_NAME " Lookup of key 0 in temp space map returned NULL."
                             "  Dropping packet.\n");
        action = XDP_DROP;
        goto out;
    }
    /* First copy the original eth and ip headers */
    __builtin_memcpy(&(temp_space->eth_cpy), eth, sizeof(struct ethhdr));
    __builtin_memcpy(&(temp_space->iph_cpy), iph, sizeof(struct iphdr));

    __u32 sink_node_id = DEFAULT_SINK_NODE_ID;
    __u32 pkt_seq_num = 0;

    // read node id from config map
    // enum ConfigKey node_id_key = NODE_ID;
    cfg_key = CONFIG_MAP_KEY_NODE_ID;
    __u32 *node_id = bpf_map_lookup_elem(&sink_config_map, &cfg_key);
    if (node_id != NULL) {
        sink_node_id = *node_id;
    }

    if (parse_int_md_hdr(&nh, data_end, &intshimh, &intmdh, &intmdsrc, &seq_num,
                         &tail_hdr) < 0) {
        bpf_printk(PROG_NAME " Dropping received"
                             " Ethernet+IPv4+UDP packet too short"
                             " to contain INT headers"
                             " (data_end-data)=%d\n",
                   data_end - data);
        action = XDP_DROP;
        goto out;
    }
    key.proto = tail_hdr->proto;
    pkt_seq_num = bpf_ntohl(*seq_num);
    if (tail_hdr->proto == IPPROTO_UDP) {
        if (parse_udphdr(&nh, data_end, &udph) < 0) {
            bpf_printk(PROG_NAME
                       " Dropping received"
                       " Ethernet+IPv4+UDP packet with dest port %u"
                       " indicating INT header follows, original"
                       " IPv4 proto in INT tail header %u indicating UDP"
                       " follows, but it was too short to contain a full"
                       " UDP header, or its UDP length was less than 8"
                       " (data_end-data)=%d\n",
                       bpf_ntohs(udph->dest), tail_hdr->proto, data_end - data);
            action = XDP_DROP;
            goto out;
        }
        key.sport = udph->source;
        key.dport = udph->dest;
    } else if (tail_hdr->proto == IPPROTO_TCP) {
        if (parse_tcphdr(&nh, data_end, &tcph) < 0) {
            bpf_printk(PROG_NAME
                       " Dropping received"
                       " Ethernet+IPv4+UDP packet with dest port %u"
                       " indicating INT header follows, original"
                       " IPv4 proto in INT tail header %u indicating TCP"
                       " follows, but it was too short to contain a full"
                       " TCP header plus TCP options"
                       " (data_end-data)=%d\n",
                       bpf_ntohs(udph->dest), tail_hdr->proto, data_end - data);
            action = XDP_DROP;
            goto out;
        }
        key.sport = tcph->source;
        key.dport = tcph->dest;
    } else {
        bpf_printk(PROG_NAME " Dropping received"
                             " Ethernet+IPv4+UDP packet with dest port %u"
                             " indicating INT header follows, but original"
                             " IPv4 proto in INT tail header %u that is neither"
                             " TCP nor UDP\n",
                   bpf_ntohs(udph->dest), tail_hdr->proto);
        action = XDP_DROP;
        goto out;
    }

#define SIMULATE_NIC_RX_PACKET_DROPS
#ifdef SIMULATE_NIC_RX_PACKET_DROPS
    /* The only purpose of this code is to simulate the receiving
     * host's NIC dropping a fraction of packets on particular flows.
     * It is for demonstration purposes only. */
#define UDP_DEST_PORT_THAT_DROPS_SOME_PKTS 10001
    if ((tail_hdr->proto == IPPROTO_UDP) &&
        (key.dport == bpf_htons(UDP_DEST_PORT_THAT_DROPS_SOME_PKTS))) {
        /* Select approximately 10% of these packets to drop.  We
         * could do it by parsing the INT header and seeing if the
         * sequence number is a multiple of 10.  I am hoping that this
         * approach based upon the current time in the sink host
         * should also work reasonably. */
        __u32 tmp = (__u32)curr_ts;
        __u32 hash = ((tmp & 0x1f) ^ ((tmp >> 5) & 0x1f) ^
                      ((tmp >> 10) & 0x1f) ^ ((tmp >> 15) & 0x1f));
        if (hash < 3) {
            action = XDP_DROP;
            goto out;
        }
    }
#endif

    __u32 e2e_latency_ns = ((__u32)curr_ts - bpf_ntohl(intmdsrc->ingress_ts));
#ifdef EXTRA_DEBUG
    bpf_printk(PROG_NAME " e2e_latency_ns: %u\n", e2e_latency_ns);
#endif

    cfg_key = LATENCY_MAP_KEY_LATENCY_BUCKET;

    struct latency_bucket_entries *latency_bucket_value =
        bpf_map_lookup_elem(&latency_bucket_map, &cfg_key);

    if (latency_bucket_value == NULL) {
        bpf_printk(PROG_NAME " no latency bucket entry \n");
        goto out;
#ifdef EXTRA_DEBUG
    } else {
        bpf_printk(PROG_NAME " found latency bucket entry: %llu\n",
                   latency_bucket_value->entries[0]);
#endif
    }

    __u64 latency_bucket_ns =
        e2e_latency_bucket(e2e_latency_ns, latency_bucket_value);

#ifdef SEQNUM_DEBUG
    bpf_printk(PROG_NAME " INT UDP ipv4.id %u len %u seqnum %u\n",
               bpf_ntohs(iph->id), bpf_ntohs(iph->tot_len), pkt_seq_num);
#endif // SEQNUM_DEBUG

#undef FLOW_DEBUG
#ifdef FLOW_DEBUG
    char buf[SPRINTF_FLOW_KEY_HEX_BUF_SIZE];
    sprintf_flow_key_hex(buf, &key);
#endif

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
            .gap_pkts_not_rcvd = 0,
            .latency_bucket_ns = latency_bucket_ns,
            .last_int_latency_report_time_ns = curr_ts};
        int ret = bpf_map_update_elem(&sink_flow_stats_map, &key,
                                      &new_flow_stats_rec, BPF_NOEXIST);
        if (ret < 0) {
            // See Note 1 in intmd_tc_ksource.c
            generate_int_report = FALSE;
#ifdef FLOW_DEBUG
            bpf_printk(PROG_NAME " failed (%d) adding new entry key=%s\n", ret,
                       buf);
#endif
        } else {
            /* Generate INT latency report for first packet of
             * flow. */
            generate_int_report = TRUE;
#ifdef FLOW_DEBUG
            bpf_printk(PROG_NAME " new entry key=%s\n", buf);
#endif
        }
    } else {
        if (flow_stats_rec->latency_bucket_ns != latency_bucket_ns) {
            /* Generate INT latency report because latency of this
             * packet is significantly different than latency of
             * previous packet in the same flow. */
            generate_int_report = TRUE;
        } else {
            cfg_key = CONFIG_MAP_KEY_LATENCY_REPORT_PERIOD_NSEC;
            __u64 *latency_report_period_nsec_ptr =
                bpf_map_lookup_elem(&sink_config_map, &cfg_key);
            __u64 latency_report_period_nsec;
            if (latency_report_period_nsec_ptr == NULL) {
                latency_report_period_nsec = DEFAULT_LATENCY_REPORT_PERIOD_NSEC;
            } else {
                latency_report_period_nsec = *latency_report_period_nsec_ptr;
            }
            if (curr_ts >= (flow_stats_rec->last_int_latency_report_time_ns +
                            latency_report_period_nsec)) {
                /* Generate INT latency report because it has been at
                 * least latency_report_period_nsec since the last
                 * time an INT latency report was generated for this
                 * flow. */
                generate_int_report = TRUE;
            }
        }
        flow_stats_rec->latency_bucket_ns = latency_bucket_ns;
        if (generate_int_report) {
            flow_stats_rec->last_int_latency_report_time_ns = curr_ts;
        }
        update_flow_stats_gap_data(flow_stats_rec, pkt_seq_num, curr_ts);
        // TODO: Should there be a call to
        // bpf_map_update_elem() here to update the value
        // flow_stats_rec for the map entry that was matched?
    }
    if (generate_int_report) {
        struct int_metadata_entry intmdsink;
        intmdsink.node_id = bpf_htonl(sink_node_id);
        ingress_port = bpf_htons(ingress_port);
        intmdsink.ingress_port = ingress_port;
        intmdsink.egress_port = ingress_port;
        intmdsink.ingress_ts = sink_ts_ns; // MID-12
        intmdsink.egress_ts = sink_ts_ns;
        // Update the length field in INT shim header to
        // include the extra data added by this sink node, but
        // remove the "int_tail_hdr".
        intshimh->length +=
            ((sizeof(intmdsink) - sizeof(struct int_tail_hdr)) >> 2);
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
                              &sink_event_perf_map, &intmdsink, NULL, NULL,
                              NULL);
    }
    cfg_key = CONFIG_MAP_KEY_DROP_PACKET;
    char *sink_type = bpf_map_lookup_elem(&sink_config_map, &cfg_key);
    if (sink_type != NULL) {
        action = XDP_DROP;
        goto out;
    }
    // remove INT headers
    int ret = bpf_xdp_adjust_head(ctx, total_int_len_with_int_udp);
    if (ret < 0) {
        bpf_printk(PROG_NAME " bpf_xdp_adjust_head by %d"
                             " failed (%d)\n",
                   total_int_len_with_int_udp, ret);
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
    __builtin_memcpy(eth, &(temp_space->eth_cpy), sizeof(struct ethhdr));

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
    __builtin_memcpy(iph, &(temp_space->iph_cpy), sizeof(struct iphdr));
    __u16 ip_oldlen = bpf_ntohs(iph->tot_len);
    __u16 ip_newlen = ip_oldlen - total_int_len_with_int_udp;
    iph->tot_len = bpf_htons(ip_newlen);
    iph->protocol = key.proto;
    ipv4_csum(iph);

out:
    return action;
}
char _license[] SEC("license") = "GPL";
