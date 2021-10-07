/* Copyright (C) 2021 Intel Corporation */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef __COMMON_DEFINES_H
#define __COMMON_DEFINES_H

#include <stdio.h>
#include <net/if.h>
#include <linux/types.h>
#include <stdbool.h>
#include "intbpf.h"

#define VERSION "0.1.1-alpha"

#define PT_SINK 1
#define PT_SOURCE 2
#define ENCAP_INT_05_OVER_TCP_UDP 1
#define ENCAP_INT_05_EXTENSION_UDP 2

struct config {
    __u32 xdp_flags;
    int ifindex;
    char *ifname;
    char ifname_buf[IF_NAMESIZE];
    int redirect_ifindex;
    char *redirect_ifname;
    char redirect_ifname_buf[IF_NAMESIZE];
    bool do_unload;
    bool reuse_maps;
    char pin_dir[512];
    char filename[512];
    char progsec[32];
    __u16 xsk_bind_flags;
    int xsk_if_queue;
    bool xsk_poll_mode;
    char filter_filename[512];
    int node_id;
    int dscp_val;
    int dscp_mask;
    int domain_specific_id;
    int ins_bitmap;
    int idle_flow_timeout_ms;
    int pkt_loss_timeout_ms;
    char server_hostname[512];
    int server_port;
    char report_file[512];
    int sender_collector_port;
    bool drop_packet;
    bool sw_id_after_report_hdr;
    int port;
    char bind_addr[16];
    int prog_type;
    struct latency_bucket_entries latency_entries;
    int num_latency_entries;
    int encap_type;
};

/* Defined in common_params.o */
extern int verbose;
#define VPRT(format, args...)                                                  \
    if (verbose) {                                                             \
        printf(format, ##args);                                                \
    }

#define EPRT(format, args...)                                                  \
    {                                                                          \
        fprintf(stderr, "Error - ");                                           \
        fprintf(stderr, format, ##args);                                       \
    }
#define WPRT(format, args...)                                                  \
    {                                                                          \
        fprintf(stderr, "Warning - ");                                         \
        fprintf(stderr, format, ##args);                                       \
    }

#ifdef EXTRA_DEBUG
#define DPRT(format, args...) fprintf(stderr, format, ##args)
#else
#define DPRT(format, args...)
#endif

/* Exit return codes */
#define EXIT_OK 0   /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL 1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION 2
#define EXIT_FAIL_XDP 30
#define EXIT_FAIL_BPF 40

#define COLLECTOR_HOSTNAME "127.0.0.1"
#define COLLECTOR_PORT 32766
#define MAX_IDLE_FLOW_TIMEOUT_MS 600000
#define MAX_PKT_LOSS_TIMEOUT_MS 600000

// Common params between source and sink
#define DEFAULT_IDLE_FLOW_TIMEOUT_MS 2000
#define PKT_LOSS_TIMEOUT_MS 200
// time update params
#define TU_INTERVAL_SEC 10
#define TU_THRESHOLD_NS 50

#define PIN_BASE_DIR "/sys/fs/bpf"
#define TC_PIN_GLOBAL_BASE "/sys/fs/bpf/tc/globals"
#define DEFAULT_HOSTINTD_REPORT_FILE "/var/log/hostintd_report.log"
#define DEFAULT_HOSTINTCOL_REPORT_FILE "/var/log/hostintcol_report.log"
#define DEFAULT_KSINK_FILE "intmd_xdp_ksink.o"

#define SINK_MAP_EVENT_PERF "sink_event_perf_map"
#define SINK_MAP_FLOW_STATS "sink_flow_stats_map"
#define SINK_MAP_CONFIG "sink_config_map"
#define SINK_MAP_LATENCY "latency_bucket_map"
#define SOURCE_MAP_EVENT_PERF "src_event_perf_map"
#define SOURCE_MAP_FLOW_STATS "src_flow_stats_map"
#define SOURCE_MAP_CONFIG "src_config_map"
#define SOURCE_MAP_FILTER "src_dest_ipv4_filter_map"

#endif /* __COMMON_DEFINES_H */
