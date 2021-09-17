/* Copyright (C) 2021 Intel Corporation */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef __INTBPF__
#define __INTBPF__

/* This file contains definitions used by EBPF programs, and also by
 * several user space programs that interact with the EBPF programs,
 * e.g. via EBPF maps and perf events. */

#include "intmd_headers.h"

#ifndef __packed
#define __packed __attribute__((packed))
#endif

// Maps common to both source and sink EBPF programs
#define CONFIGURATION_MAP_MAX_ENTRIES 16
#define LATENCYBUCKET_MAP_MAX_ENTRIES 16
#define FLOW_MAP_MAX_ENTRIES 65536

// Maps that are only accessed by source EBPF programs.
#define DEST_FILTER_MAP_MAX_ENTRIES 4096
#define IPV4_FRAG_OFFSET_MASK 0x1fff
// There are currently no EBPF maps that are only accessed by the sink
// EBPF program.

#define MAX_CPUS 256
#define DEFAULT_MTU 1500 // todo to get it dynamically
#define SAMPLE_SIZE 1024

// Source/sink EBPF programs use these IDs if it is not provided by
// configuration map.
#define DEFAULT_SOURCE_NODE_ID 2
#define DEFAULT_SINK_NODE_ID 3

// Default DSCP value/mask to use if not provided by configuration
// map.
#define DEFAULT_INT_DSCP_VAL 0x04
#define DEFAULT_INT_DSCP_MASK 0x04

// Default UDP destination port value to use, if one is not provided
// by the configuration map.
// According to the following IANA web page retreived on 2021-Jul-27,
// the UDP destination port range 33061-33122 is unassigned:
// https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?&page=130
#define DEFAULT_INT_UDP_DEST_PORT 33122

#define NANOSECS_PER_USEC 1000
#define USECS_PER_MSEC 1000
#define MSECS_PER_SEC 1000
#define MILLI_TO_NANO 1000000

// Default latency report period to use if not provided by
// configuration map.
#define DEFAULT_LATENCY_REPORT_PERIOD_NSEC (2 * MSECS_PER_SEC * MILLI_TO_NANO)

#define CONFIG_MAP_KEY_NODE_ID 1
#define CONFIG_MAP_KEY_DSCP_VAL 2
#define CONFIG_MAP_KEY_DSCP_MASK 3
#define CONFIG_MAP_KEY_DOMAIN_ID 4
#define CONFIG_MAP_KEY_INS_BITMAP 5
#define CONFIG_MAP_KEY_IDLE_TO 6
#define CONFIG_MAP_KEY_PKTLOSS_TO 7
#define CONFIG_MAP_KEY_TIME_OFFSET 8
#define CONFIG_MAP_KEY_INT_UDP_ENCAP_DEST_PORT 9
#define CONFIG_MAP_KEY_LATENCY_REPORT_PERIOD_NSEC 10
#define CONFIG_MAP_KEY_DROP_PACKET 11
#define LATENCY_MAP_KEY_LATENCY_BUCKET 0
#define U64_MAX_VALUE 0xFFFFFFFFFFFFFFFF

struct __attribute__((__packed__)) flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 proto;
};

struct __attribute__((__packed__)) sink_flow_stats_datarec {
    __u32 src_node_id;
    __u16 src_port;
    __u32 sink_node_id;
    __u16 sink_port;
    __u64 gap_head_ts_ns;
    __u32 gap_head_seq_num;
    __u64 gap_tail_ts_ns;
    __u32 gap_tail_seq_num;
    __u16 gap_pkts_not_rcvd;
    __u64 latency_bucket_ns;
    __u64 last_int_latency_report_time_ns;
};

struct __attribute__((__packed__)) src_flow_stats_datarec {
    __u32 seqnum;
    __u64 ts_ns;
    __u16 port;
};

struct src_pkt_meta {
    __u16 cookie;
    __u16 pkt_len;
};

#define PACKET_METADATA_COOKIE 0xdead

struct flow_ds_md { // 24 bytes
    __be32 src_node_id;
    __be16 src_port;
    __be16 sink_port;
    __be64 src_timestamp;
    __be64 sink_timestamp;
};

struct packet_metadata {
    struct int_metadata_entry intmdsink;
    struct src_pkt_meta s_meta;
    struct flow_ds_md fdsmd; // only used in INT MX
    __u32 node_id;           // only used in INT MX
    __u16 domain_id;         // only used in INT MX
} __packed;

struct latency_bucket_entries {
    __u64 entries[LATENCYBUCKET_MAP_MAX_ENTRIES];
};

#define get_timestamp(pts) clock_gettime(CLOCK_REALTIME, pts)

#ifdef SUPPORT_BOOTTIME
#define get_bpf_timestamp() bpf_ktime_get_boot_ns()
#else
#define get_bpf_timestamp() bpf_ktime_get_ns()
#endif

#endif /* __INTBPF__ */
