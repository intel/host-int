/* Copyright (C) 2021 Intel Corporation */
/* SPDX-License-Identifier: BSD-3-Clause */

#include "common_params.h"
#include "common_report.h"
#include "common_user_bpf_xdp.h"
#include "intbpf.h"
#include "intmd_headers.h"
#include "periodic_timer.h"
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <inttypes.h>
#include <libgen.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/ip.h>
#include <linux/limits.h>
#include <linux/perf_event.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <time.h>
//#include "intmx_headers.h"
#include "uutils.h"

static pthread_mutex_t seq_num_lock;

static int done;
static void sig_handler(int signo)
{
    DPRT("Caught signal. Stop program...\n");
    done = 1;
}
static int sink_config_map_fd = -1;
static char collector_name[512];
static int collector_port = -1;
static int sender_collector_port = -1;
static FILE *report_file;
static int report_with_switch_id = false;
__u32 sink_node_id;
// can change when we reload cfg
static uint64_t sink_idle_flow_timeout_ns, sink_pkt_loss_timeout_ns;

static const char *__doc__ =
    "INT Edge-to-Edge User Space Program that loads in sink EBPF program, and\n"
    "maintains shared EBPF map for both sink and source EBPF programs.\n"
    "It unloads sink EBPF program on exit or interruption.\n";

static const struct option_wrapper long_options[] = {
    {{"help", no_argument, NULL, 'h'}, "Show help", false},

    {{"Version", no_argument, NULL, 'V'}, "Print version number", false},

    {{"dev", required_argument, NULL, 'd'},
     "Operate on device <ifname>",
     "<ifname>",
     true},

    {{"quiet", no_argument, NULL, 'q'}, "Quiet mode (no output)"},

    {{"node-id", required_argument, NULL, 'n'}, "Node ID"},

    {{"dscp-val", required_argument, NULL, 'v'}, "DSCP Value"},

    {{"dscp-mask", required_argument, NULL, 'm'}, "DSCP Mask"},

    {{"idle-flow-timeout-ms", required_argument, NULL, 't'},
     "Idle flow clear timeout (ms)"},

    {{"pkg-loss-timeout-ms", required_argument, NULL, 'l'},
     "Package loss timeout (ms)"},

    {{"latency-bucket", required_argument, NULL, 'B'},
     "Latency bucket entry (ms)"},

    {{"collector-server", required_argument, NULL, 'C'},
     "Collector server name. Default is an empty string that indicates do not "
     "report data to a collector."},

    {{"collector-port", required_argument, NULL, 'P'},
     "Collector port number."},

    {{"encap", required_argument, NULL, 'E'},
     "Encap type can be 'int_05_over_tcp_udp' or 'int_05_extension_udp'."},

    {{"drop-packet", no_argument, NULL, 'D'},
     "When this option is present, all packets with INT headers received by "
     "the UDP-encapsulation EBPF sink program will be dropped, and not sent "
     "onwards to the Linux kernel."},

    {{"no-sw-id-after-report-hdr", no_argument, NULL, 'Y'},
     "When this option is present latency reports will not have an additional"
     " copy of the sink host's node id inserted after the Telemetry Report "
     "Fixed Header, and before the IPv4 header."},

    {{"report-output", required_argument, NULL, 'o'},
     "Report output file. An empty string indicates do not report data to a "
     "file. Default is " DEFAULT_HOSTINTD_REPORT_FILE "."},

    {{"sender-collector-port", required_argument, NULL, 5},
     "Send report back to sender's UDP port"},

    {{"filename", required_argument, NULL, 1},
     "Load program from <file>",
     "<file>"},

    {{0, 0, NULL, 0}, NULL, false}};

void cleanup()
{
    DPRT("CLEANUP\n");
    if (report_file) {
        fclose(report_file);
    }
}

int get_next_report_seq_num(void)
{
    static int report_seq_num = 1;
    int ret;
    pthread_mutex_lock(&seq_num_lock);
    ret = report_seq_num;
    report_seq_num += 1;
    pthread_mutex_unlock(&seq_num_lock);
    return ret;
}

uint64_t get_time_offset()
{
    int i, ret1, ret2;
    struct timespec ts1, ts2;
    uint64_t ts1_ns, ts2_ns, delta, min_delta = 0;
    for (i = 0; i < 200; i++) {
#ifdef SUPPORT_BOOTTIME
        ret1 = clock_gettime(CLOCK_BOOTTIME, &ts1);
#else
        ret1 = clock_gettime(CLOCK_MONOTONIC, &ts1);
#endif
        ret2 = clock_gettime(CLOCK_REALTIME, &ts2);
        if (ret1 == 0 && ret2 == 0) {
            ts1_ns = ((uint64_t)ts1.tv_sec * NANOSECS_PER_USEC *
                      USECS_PER_MSEC * MSECS_PER_SEC) +
                     ts1.tv_nsec;
            ts2_ns = ((uint64_t)ts2.tv_sec * NANOSECS_PER_USEC *
                      USECS_PER_MSEC * MSECS_PER_SEC) +
                     ts2.tv_nsec;
            delta = ts2_ns - ts1_ns;
            if (delta < min_delta || min_delta == 0) {
                min_delta = delta;
            }
        }
    }
    return min_delta;
}

int update_time_offset_map(int map_fd, uint64_t time_offset, char *map_name)
{
    __u16 time_offset_key = CONFIG_MAP_KEY_TIME_OFFSET;
    int ret =
        bpf_map_update_elem(map_fd, &time_offset_key, &time_offset, BPF_ANY);
    if (ret < 0) {
        EPRT("Failed to update time offset (%lu) in %s err code: "
             "%i\n",
             time_offset, map_name, ret);
        return ret;
    }
    VPRT("Updated time offset in %s to %lu ns\n", map_name, time_offset);
    return 0;
}

void update_time_offset(size_t timer_id, void *params)
{
    static int source_config_map_fd = -1;
    static uint64_t time_offset = 0;
    uint64_t new_offset = get_time_offset();
    if (!new_offset) {
        return;
    }

    uint64_t delta = new_offset > time_offset ? new_offset - time_offset
                                              : time_offset - new_offset;
    bool to_update = delta >= TU_THRESHOLD_NS;
    // check source map file
    if (source_config_map_fd < 0) {
        struct bpf_map_info info = {0};
        source_config_map_fd = silent_open_bpf_map_file(
            TC_PIN_GLOBAL_BASE, SOURCE_MAP_CONFIG, &info);
        if (source_config_map_fd >= 0) {
            VPRT("Opened %s with id=%d\n", SOURCE_MAP_CONFIG, info.id);
            if (!to_update) {
                // first time, shall still update
                update_time_offset_map(source_config_map_fd, new_offset,
                                       SOURCE_MAP_CONFIG);
            }
        }
    }
    if (!to_update) {
        return;
    }

    int ret1 = 0;
    if (source_config_map_fd > 0) {
        ret1 = update_time_offset_map(source_config_map_fd, new_offset,
                                      SOURCE_MAP_CONFIG);
    }
    int ret2 =
        update_time_offset_map(sink_config_map_fd, new_offset, SINK_MAP_CONFIG);

    if (ret1 == 0 && ret2 == 0) {
        time_offset = new_offset;
    }
}

static int process_ebpf_perf_event_from_sink(void *data, int size)
{
    struct {
        struct packet_metadata meta;
        __u8 pkt_data[SAMPLE_SIZE];
    } __packed *e = data;
    struct timespec ts;
    struct flow_key key;
    int err;
    int report_seq_num;

    if (e->meta.s_meta.cookie != PACKET_METADATA_COOKIE) {
        EPRT("BUG expected cookie %x but found %x sized %d\n",
             PACKET_METADATA_COOKIE, e->meta.s_meta.cookie, size);
        return LIBBPF_PERF_EVENT_ERROR;
    }

    err = get_timestamp(&ts);
    if (err < 0) {
        EPRT("gettimeofday failed with code: %i\n", err);
        return LIBBPF_PERF_EVENT_ERROR;
    }

    /* In order to simplify the sink EBPF program, it does not insert
     * its metadata in the middle of the INT headers the way a normal
     * INT device would do.  Instead it puts the data that it _should_
     * insert into the middle of the INT header at the beginning of the
     * packet it sends as a perf event, and expects the hostintd process
     * to rearrange the data before sending an INT report. */
    struct int_metadata_entry intmdsink = e->meta.intmdsink;
    __u8 l4_hdr_size = 0;
    __u32 seq_num;

    /* Note: This code assumes that the Ethernet protocol is IPv4.  That
     * is the only kind of packet that sink EBPF program should ever
     * send in this version of the code. */
    int ipv4_offset_in_pkt_data = sizeof(struct ethhdr);
    struct iphdr *iph = (struct iphdr *)&(e->pkt_data[ipv4_offset_in_pkt_data]);

    __u8 ip_protocol = iph->protocol;
    __u32 saddr = iph->saddr;
    key.saddr = iph->saddr;
    key.daddr = iph->daddr;
    key.proto = iph->protocol;
    /* TODO: Another place to change if we ever need to support IPv4
     * options. */
    int off = ipv4_offset_in_pkt_data + sizeof(struct iphdr);

    if (ip_protocol == IPPROTO_UDP) {
        l4_hdr_size = sizeof(struct udphdr);
        struct udphdr *udph = (struct udphdr *)&(e->pkt_data[off]);
        key.sport = udph->source;
        key.dport = udph->dest;
    } else if (ip_protocol == IPPROTO_TCP) {
        l4_hdr_size = sizeof(struct tcphdr);
        struct tcphdr *tcph = (struct tcphdr *)&(e->pkt_data[off]);
        key.sport = tcph->source;
        key.dport = tcph->dest;
    } else {
        return LIBBPF_PERF_EVENT_ERROR;
    }

    /* TODO: Verify that the INT length field is one of the expected
     * values. */

    /* int_rpt_body is the part of the INT report that comes after the
     * header defined by 'struct int_report_hdr', containing some of the
     * bytes from the packet sent here by the sink EBPF program. */

    /* part1 begins just after the Ethernet header of the received
     * packet, and continues up to the TCP/UDP header, and after that up
     * to the end of the INT header defined by 'struct
     * int_metadata_hdr'. */
    int int_rpt_body_part1_offset = ipv4_offset_in_pkt_data;

    __u32 int_rpt_body_part1_len =
        (sizeof(struct iphdr) + l4_hdr_size + sizeof(struct int_shim_hdr) +
         sizeof(struct int_metadata_hdr));
    /* Part 2 is the data in the format of 'struct int_metadata_entry'
     * added by the sink EBPF program, which is right now in variable
     * intmdsink, not in e->pkt_data */
    __u32 int_rpt_body_part2_len = sizeof(struct int_metadata_entry);
    /* Part 3 is the data in the format of 'struct int_metadata_entry'
     * added by the source EBPF program, which is right now in
     * e->pkt_data starting at the part3 offset calculated below. */
    int int_rpt_body_part3_offset =
        (int_rpt_body_part1_offset + int_rpt_body_part1_len);
    __u32 int_rpt_body_part3_len =
        (sizeof(struct int_metadata_entry) + sizeof(seq_num));

    __u32 pkt_len = 0;
    /* populate buffer */
    if (report_with_switch_id == 1) {
        pkt_len = (int_rpt_body_part1_len + int_rpt_body_part2_len +
                   int_rpt_body_part3_len + sizeof(sink_node_id));
    } else {
        pkt_len = (int_rpt_body_part1_len + int_rpt_body_part2_len +
                   int_rpt_body_part3_len);
    }
    __u8 buffer[pkt_len];
    __u32 offset = 0;
    if (report_with_switch_id == 1) {
        memcpy(&buffer[offset], &intmdsink, sizeof(sink_node_id));
        offset += sizeof(sink_node_id);
    }
    memcpy(&buffer[offset], &(e->pkt_data[int_rpt_body_part1_offset]),
           int_rpt_body_part1_len);
    offset += int_rpt_body_part1_len;

    memcpy(&buffer[offset], &intmdsink, sizeof(struct int_metadata_entry));
    offset += sizeof(struct int_metadata_entry);

    memcpy(&buffer[offset], &(e->pkt_data[int_rpt_body_part3_offset]),
           int_rpt_body_part3_len);
    offset += int_rpt_body_part3_len;

    report_seq_num = get_next_report_seq_num();
    if (collector_port > 0) {
        // send the whole packet (excluding eth header) to the buffer
        err = send_latency_report(collector_name, 0, collector_port, pkt_len,
                                  buffer, report_seq_num, &ts);
        if (err) {
            EPRT("Failed to send report! (%i)\n", err);
            return LIBBPF_PERF_EVENT_ERROR;
        }
    }

    if (report_file) {
        print_latency_report(report_file,
                             (struct int_metadata_entry *)&(
                                 e->pkt_data[int_rpt_body_part3_offset]),
                             (struct int_metadata_entry *)&intmdsink,
                             report_seq_num, &ts, &key);
    }

    if (sender_collector_port > 0) {
        err = send_latency_report(NULL, saddr, sender_collector_port, pkt_len,
                                  buffer, report_seq_num, &ts);
        if (err) {
            EPRT("Failed to send back report to sender! (%i)\n", err);
            return LIBBPF_PERF_EVENT_ERROR;
        }
    }

#ifdef EXTRA_DEBUG
    int i;
    printf("pkt len: %-5d bytes. hdr: ", pkt_len);
    for (i = 0; i < pkt_len; i++)
        printf("%02x ", buffer[i]);
    printf("\n");
#endif
    return LIBBPF_PERF_EVENT_CONT;
}

static int process_ebpf_perf_event_from_sink_without_encap(void *data, int size)
{
    struct {
        struct packet_metadata meta;
        __u8 pkt_data[SAMPLE_SIZE];
    } __packed *e = data;
    struct timespec ts;
    struct flow_key key;
    int err;
    int report_seq_num;

    if (e->meta.s_meta.cookie != PACKET_METADATA_COOKIE) {
        EPRT("BUG expected cookie %x but found %x sized %d\n",
             PACKET_METADATA_COOKIE, e->meta.s_meta.cookie, size);
        return LIBBPF_PERF_EVENT_ERROR;
    }

    err = get_timestamp(&ts);
    if (err < 0) {
        EPRT("gettimeofday failed with code: %i\n", err);
        return LIBBPF_PERF_EVENT_ERROR;
    }

    /* In order to simplify the sink EBPF program, it does not insert
     * its metadata in the middle of the INT headers the way a normal
     * INT device would do.  Instead it puts the data that it _should_
     * insert into the middle of the INT header at the beginning of the
     * packet it sends as a perf event, and expects the hostintd process
     * to rearrange the data before sending an INT report. */
    struct int_metadata_entry intmdsink = e->meta.intmdsink;
    __u32 seq_num;
    /* Note: This code assumes that the Ethernet protocol is IPv4.  That
     * is the only kind of packet that sink EBPF program should ever
     * send in this version of the code. */
    int ipv4_offset_in_pkt_data = sizeof(struct ethhdr);
    struct iphdr *iph = (struct iphdr *)&(e->pkt_data[ipv4_offset_in_pkt_data]);
    __u32 saddr = iph->saddr;
    key.saddr = iph->saddr;
    key.daddr = iph->daddr;
    /* TODO: Another place to change if we ever need to support IPv4
     * options. */
    int int_rpt_body_part1_offset = ipv4_offset_in_pkt_data;
    __u32 int_rpt_body_part1_len = (sizeof(struct iphdr));

    __u32 int_rpt_body_part2_len = 0;
    int tail_offset = (ipv4_offset_in_pkt_data + sizeof(struct iphdr) +
                       sizeof(struct udphdr) + sizeof(struct int_shim_hdr) +
                       sizeof(struct int_metadata_hdr) + sizeof(seq_num) +
                       sizeof(struct int_metadata_entry));

    int int_rpt_body_part2_offset = (tail_offset + sizeof(struct int_tail_hdr));

    struct int_tail_hdr *tail_hdr =
        (struct int_tail_hdr *)&(e->pkt_data[tail_offset]);
    if (tail_hdr->proto == IPPROTO_UDP) {
        int_rpt_body_part2_len = sizeof(struct udphdr);
        struct udphdr *udph =
            (struct udphdr *)&(e->pkt_data[int_rpt_body_part2_offset]);
        key.sport = udph->source;
        key.dport = udph->dest;
    } else if (tail_hdr->proto == IPPROTO_TCP) {
        int_rpt_body_part2_len = sizeof(struct tcphdr);
        struct tcphdr *tcph =
            (struct tcphdr *)&(e->pkt_data[int_rpt_body_part2_offset]);
        key.sport = tcph->source;
        key.dport = tcph->dest;
    } else {
        EPRT("Not a supported protocol! (%i)\n", err);
        return LIBBPF_PERF_EVENT_ERROR;
    }

    /* TODO: Verify that the INT length field is one of the expected
     * values. */

    /* int_rpt_body is the part of the INT report that comes after the
     * header defined by 'struct int_report_hdr', containing some of the
     * bytes from the packet sent here by the sink EBPF program. */

    /* part1 begins just after the Ethernet header of the received
     * packet, and continues up to the TCP/UDP header, and after that up
     * to the end of the INT header defined by 'struct
     * int_metadata_hdr'. */
    int int_rpt_body_part3_offset =
        (ipv4_offset_in_pkt_data + sizeof(struct iphdr) +
         sizeof(struct udphdr));
    __u32 int_rpt_body_part3_len =
        (sizeof(struct int_shim_hdr) + sizeof(struct int_metadata_hdr));
    /* Part 4 is the data in the format of 'struct int_metadata_entry'
     * added by the sink EBPF program, which is right now in variable
     * intmdsink, not in e->pkt_data */
    __u32 int_rpt_body_part4_len = sizeof(struct int_metadata_entry);
    int int_rpt_body_part5_offset =
        (int_rpt_body_part3_offset + int_rpt_body_part3_len);
    __u32 int_rpt_body_part5_len =
        (sizeof(struct int_metadata_entry) + sizeof(seq_num));

    /* Part 5 is the data in the format of 'struct int_metadata_entry'
     * added by the source EBPF program, which is right now in
     * e->pkt_data starting at the part3 offset calculated below. */

    /* populate buffer */
    __u32 pkt_len;

    if (report_with_switch_id == 1) {
        pkt_len = (sizeof(sink_node_id) + int_rpt_body_part1_len +
                   int_rpt_body_part2_len + int_rpt_body_part3_len +
                   int_rpt_body_part4_len + int_rpt_body_part5_len);
    } else {
        pkt_len = (int_rpt_body_part1_len + int_rpt_body_part2_len +
                   int_rpt_body_part3_len + int_rpt_body_part4_len +
                   int_rpt_body_part5_len);
    }
    __u8 buffer[pkt_len];
    __u32 offset = 0;
    if (report_with_switch_id == 1) {
        memcpy(&buffer[offset], &intmdsink, sizeof(sink_node_id));
        offset += sizeof(sink_node_id);
    }
    memcpy(&buffer[offset], &(e->pkt_data[int_rpt_body_part1_offset]),
           int_rpt_body_part1_len);
    struct iphdr *iph2 = (struct iphdr *)&buffer[offset];
    iph2->protocol = tail_hdr->proto;
    key.proto = iph2->protocol;

    __u8 dscp_val = DEFAULT_INT_DSCP_VAL;
    __u8 dscp_mask = DEFAULT_INT_DSCP_MASK;
    iph2->tos = (iph2->tos & ~dscp_mask) | (dscp_val & dscp_mask);

    offset += int_rpt_body_part1_len;

    memcpy(&buffer[offset], &(e->pkt_data[int_rpt_body_part2_offset]),
           int_rpt_body_part2_len);
    offset += int_rpt_body_part2_len;

    memcpy(&buffer[offset], &(e->pkt_data[int_rpt_body_part3_offset]),
           int_rpt_body_part3_len);
    offset += int_rpt_body_part3_len;

    memcpy(&buffer[offset], &intmdsink, sizeof(struct int_metadata_entry));
    offset += sizeof(struct int_metadata_entry);

    memcpy(&buffer[offset], &(e->pkt_data[int_rpt_body_part5_offset]),
           int_rpt_body_part5_len);
    offset += int_rpt_body_part5_len;

    report_seq_num = get_next_report_seq_num();
    if (collector_port > 0) {
        // send the whole packet (excluding eth header) to the buffer
        err = send_latency_report(collector_name, 0, collector_port, pkt_len,
                                  buffer, report_seq_num, &ts);
        if (err) {
            EPRT("Failed to send report! (%i)\n", err);
            return LIBBPF_PERF_EVENT_ERROR;
        }
    }

    if (report_file) {
        print_latency_report(report_file,
                             (struct int_metadata_entry *)&(
                                 e->pkt_data[int_rpt_body_part5_offset]),
                             (struct int_metadata_entry *)&intmdsink,
                             report_seq_num, &ts, &key);
    }
    if (sender_collector_port > 0) {
        err = send_latency_report(NULL, saddr, sender_collector_port, pkt_len,
                                  buffer, report_seq_num, &ts);
        if (err) {
            EPRT("Failed to send back report to sender! (%i)\n", err);
            return LIBBPF_PERF_EVENT_ERROR;
        }
    }

#ifdef EXTRA_DEBUG
    int i;
    printf("pkt len: %-5d bytes. hdr: ", pkt_len);
    for (i = 0; i < pkt_len; i++)
        printf("%02x ", buffer[i]);
    printf("\n");
#endif
    return LIBBPF_PERF_EVENT_CONT;
}

static int send_drop_summary_report(struct flow_key *key,
                                    struct sink_flow_stats_datarec *value,
                                    struct timespec *ts)
{

    int err;
    __u16 len;
    __u8 buf[MAX_REPORT_PAYLOAD_LEN];
    int report_seq_num;

    // create drop summary report data
    struct int_drop_summary_data reportd;
    reportd.src_switch_id = htonl(value->src_node_id);
    reportd.dst_switch_id = htonl(value->sink_node_id);
    reportd.src_port = htons(value->src_port);
    reportd.dst_port = htons(value->sink_port);
    reportd.gap_timestamp = htonl(
        (uint32_t)(value->gap_head_ts_ns / ((uint32_t)NANOSECS_PER_USEC *
                                            USECS_PER_MSEC * MSECS_PER_SEC)));
    reportd.flow_seq_num = htonl(value->gap_head_seq_num);
    reportd.gap_count = htonl(value->gap_pkts_not_rcvd);
    const unsigned int max_report_size =
        (sizeof(struct int_drop_summary_data) + sizeof(struct iphdr) +
         sizeof(struct tcphdr));
    if (max_report_size > MAX_REPORT_PAYLOAD_LEN) {
        EPRT("Report size (%u) exceeds the max payload len\n", max_report_size);
        return -1;
    }
    memcpy(buf, &reportd, sizeof(reportd));
    len = sizeof(reportd);

    // create IP header
    struct iphdr iph = {.version = 4,
                        .ihl = 5,
                        .protocol = key->proto,
                        .saddr = key->saddr,
                        .daddr = key->daddr};
    memcpy(buf + len, &iph, sizeof(iph));
    len += sizeof(iph);

    int l4_hdr_size = 0;
    // create L4 header
    if (key->proto == IPPROTO_UDP) { // UDP
        struct udphdr udph = {
            .source = key->sport,
            .dest = key->dport,
            .len = htons(sizeof(udph)),
        };
        l4_hdr_size += sizeof(udph);
        memcpy(buf + len, &udph, sizeof(udph));
        len += sizeof(udph);
    } else if (key->proto == IPPROTO_TCP) { // TCP
        struct tcphdr tcph = {
            .source = key->sport,
            .dest = key->dport,
        };
        l4_hdr_size += sizeof(tcph);
        memcpy(buf + len, &tcph, sizeof(tcph));
        len += sizeof(tcph);
    }

    report_seq_num = get_next_report_seq_num();
    if (collector_port > 0) {
        err = send_drop_report(collector_name, 0, collector_port, len, buf,
                               report_seq_num, ts);
        if (err) {
            EPRT("Failed to send report! (%i)\n", err);
            return -1;
        }
    }

    if (report_file) {
        print_drop_report(report_file, &reportd, report_seq_num, ts, key);
    }

    if (sender_collector_port > 0) {
        err = send_drop_report(NULL, iph.saddr, sender_collector_port, len, buf,
                               report_seq_num, ts);
        if (err) {
            EPRT("Failed to send report! (%i)\n", err);
            return -1;
        }
    }
    return 0;
}

/* Note 3: wrap-around time of timestamps used
 *
 * The variable curr_ts_ns is an unsigned 64-bit integer that is the
 * number of nanoseconds since the Unix epoch, 1970-Jan-01.
 *
 * That value will not wrap around until 2^64 nanoseconds later, which
 * is:
 *
 * (2^64 nsec) / ((10^9 nsec/sec) * (3600 sec/hour) * (24 hours/day) *
 *                (365.25 days/year))
 * ~= 584.5 years
 *
 * which is some time during the year 2554 AD.  This software is
 * assumed to be end of life or updated to handle the Y2554 problem
 * before then.
 *
 * By contrast, 32-bit timestamps in units of nanoseconds wrap around every
 *
 * (2^32 nsec) / (10^9 nsec/sec)
 * ~= 4.295 sec
 *
 * so all arithmetic on 32-bit timestamps should be done with unsigned
 * arithmetic in C, which is defined to be modulo 2^32, and have
 * predictable results (C does not define the results of overflow for
 * signed arithmetic, only unsigned). */

void clear_source_idle_flows(size_t timer_id, void *params)
{
    uint64_t idle_flow_timeout_ns = sink_idle_flow_timeout_ns;
    static int source_flow_stats_map_fd = -1;
    // check map file
    if (source_flow_stats_map_fd < 0) {
        struct bpf_map_info info = {0};
        source_flow_stats_map_fd = silent_open_bpf_map_file(
            TC_PIN_GLOBAL_BASE, SOURCE_MAP_FLOW_STATS, &info);
        if (source_flow_stats_map_fd >= 0) {
            VPRT("Opened %s with id=%d\n", SOURCE_MAP_FLOW_STATS, info.id);
        } else {
            // nothing to do
            return;
        }
    }

    struct flow_key key;
    struct flow_key *prev_key = NULL;
    struct src_flow_stats_datarec value;
    struct flow_key to_delete[FLOW_MAP_MAX_ENTRIES];
    int to_delete_size = 0;
    struct timespec curr_ts;
    int err = get_timestamp(&curr_ts);
    if (err < 0) {
        EPRT("gettimeofday failed with code: %i\n", err);
        return;
    }

    uint64_t curr_ts_ns = ((uint64_t)curr_ts.tv_sec * NANOSECS_PER_USEC *
                           USECS_PER_MSEC * MSECS_PER_SEC) +
                          curr_ts.tv_nsec;
    // DPRT("source flow idle_flow_timeout_ns=%"PRIu64"\n",
    // idle_flow_timeout_ns);
    while (bpf_map_get_next_key(source_flow_stats_map_fd, prev_key, &key) ==
           0) {
        if (bpf_map_lookup_elem(source_flow_stats_map_fd, &key, &value) < 0) {
            EPRT("failed to fetch elem from source flow_stats_map_fd\n");
            source_flow_stats_map_fd = -1;
            break;
        }
        DPRT("curr_ts_ns: %" PRIu64 ", val.ts_ns: %llu\n", curr_ts_ns,
             value.ts_ns);
        /* It is possible that the source EBPF program has updated a
         * map entry after this function began running.  If so,
         * value.ts_ns can be greater than curr_ts_ns.  Do not perform
         * the entry age calculation in that case, since it will wrap
         * around, which for a type uint64_t it wraps around to a very
         * large positive value. */
        /* See Note 3*/
        if ((curr_ts_ns > value.ts_ns) &&
            ((curr_ts_ns - value.ts_ns) > idle_flow_timeout_ns)) {
            to_delete[to_delete_size++] = key;
            DPRT("Delete entry\n");
        }
        prev_key = &key;
    }
    if (errno != ENOENT) {
        source_flow_stats_map_fd = -1;
        return;
    }
    for (int i = 0; i < to_delete_size; i++) {
        key = to_delete[i];
        int res = bpf_map_delete_elem(source_flow_stats_map_fd, &key);
        if (res < 0) {
            EPRT("Failed to delete elem from flow_stats_map. err code: %i\n",
                 res);
            source_flow_stats_map_fd = -1;
        }
    }
}

void pkt_drop_stats_collect(size_t timer_id, void *params)
{
    uint64_t idle_flow_timeout_ns = sink_idle_flow_timeout_ns;
    uint64_t pkt_loss_timeout_ns = sink_pkt_loss_timeout_ns;
    int flow_stats_map_fd = *((int *)params);
    struct flow_key key;
    struct flow_key *prev_key = NULL;
    struct sink_flow_stats_datarec value;

    struct flow_key to_delete[FLOW_MAP_MAX_ENTRIES];
    int to_delete_size = 0;
    struct timespec curr_ts;
    int err = get_timestamp(&curr_ts);
    if (err < 0) {
        EPRT("gettimeofday failed with code: %i\n", err);
        return;
    }
    // DPRT("sink flow idle_flow_timeout_ns=%"PRIu64"\n", idle_flow_timeout_ns);
    // DPRT("sink flow pkt_loss_timeout_ns=%"PRIu64"\n", pkt_loss_timeout_ns);
    uint64_t curr_ts_ns = ((uint64_t)curr_ts.tv_sec * NANOSECS_PER_USEC *
                           USECS_PER_MSEC * MSECS_PER_SEC) +
                          curr_ts.tv_nsec;

    // while(bpf_map_get_next_key_and_delete(&flow_gap_map_fd, prev_key, &key,
    // &delete_previous) == 0) {
    while (bpf_map_get_next_key(flow_stats_map_fd, prev_key, &key) == 0) {
        if (bpf_map_lookup_elem(flow_stats_map_fd, &key, &value) < 0) {
            EPRT("failed to fetch elem from sink flow_stats_map_fd\n");
            break;
        }
        DPRT("curr_ts_ns: %" PRIu64
             ", val.gap_head_ts_ns: %llu, val.gap_head_seq_no: %u, "
             "val.gap_tail_ts_ns: %llu, val.gap_tail_seq_no: %u,"
             " val.gap_pkts_not_rcvd: %u\n",
             curr_ts_ns, value.gap_head_ts_ns, value.gap_head_seq_num,
             value.gap_tail_ts_ns, value.gap_tail_seq_num,
             value.gap_pkts_not_rcvd);
        /* The last time the entry was updated is the later of the
         * gap_head and gap_tail times. */
        uint64_t entry_ts_ns = value.gap_head_ts_ns;
        if (value.gap_tail_ts_ns > entry_ts_ns) {
            entry_ts_ns = value.gap_tail_ts_ns;
        }
        /* It is possible that the sink EBPF program has updated a map
         * entry after this function began running.  If so,
         * entry_ts_ns can be greater than curr_ts_ns.  Treat the
         * entry age as 0 in this case, since doing the subtraction
         * will wrap around, which for a type uint64_t it wraps around
         * to a very large positive value. */
        uint64_t entry_age_ns = 0;
        if (curr_ts_ns > entry_ts_ns) {
            entry_age_ns = curr_ts_ns - entry_ts_ns;
        }
        int delete_entry = 0;
        if (entry_age_ns > idle_flow_timeout_ns) {
            // Remove the gap entry from the map
            to_delete[to_delete_size++] = key;
            DPRT("Delete entry\n");
            delete_entry = 1;
        }
        uint64_t delta_ns = 0;
        if (curr_ts_ns > value.gap_head_ts_ns) {
            delta_ns = curr_ts_ns - value.gap_head_ts_ns;
        }
        if (delta_ns > pkt_loss_timeout_ns) {
            if (value.gap_pkts_not_rcvd != 0) {
                DPRT("Send drop summary report\n");
                send_drop_summary_report(&key, &value, &curr_ts);
            }
            if ((delete_entry == 0) && (value.gap_tail_seq_num != 0)) {
                value.gap_head_ts_ns = value.gap_tail_ts_ns;
                value.gap_tail_ts_ns = 0;
                value.gap_head_seq_num = value.gap_tail_seq_num;
                value.gap_tail_seq_num = 0;
                value.gap_pkts_not_rcvd = 0;
                int res = bpf_map_update_elem(flow_stats_map_fd, &key, &value,
                                              BPF_EXIST);
                if (res < 0) {
                    EPRT("Failed to update elem in sink flow_stats_map. err "
                         "code: %i\n",
                         res);
                }
            }
        }
        prev_key = &key;
    }
    for (int i = 0; i < to_delete_size; i++) {
        key = to_delete[i];
        int res = bpf_map_delete_elem(flow_stats_map_fd, &key);
        if (res < 0) {
            EPRT("Failed to delete elem from sink flow_stats_map. err code: "
                 "%i\n",
                 res);
        }
    }
}

int deploy_ebpf(struct config *cfg)
{
    int ret;
    char pin_filename[PATH_MAX];

    struct bpf_object *bpf_obj = load_bpf_and_xdp_attach(cfg);
    if (!bpf_obj) {
        return EXIT_FAIL_BPF;
    }
    VPRT("Success: Loaded BPF-object(%s) and used section(%s)\n", cfg->filename,
         cfg->progsec);
    VPRT(" - XDP prog attached on device:%s(ifindex:%d)\n", cfg->ifname,
         cfg->ifindex);

    /* Existing/previous XDP prog might not have cleaned up */
    ret = snprintf(pin_filename, PATH_MAX, "%s/%s", cfg->pin_dir,
                   SINK_MAP_CONFIG);
    if (ret < 0) {
        EPRT("Failed to create map filepath. err code: %i\n", ret);
        return EXIT_FAIL_OPTION;
    }
    if (access(pin_filename, F_OK) != -1) {
        VPRT("Unpinning existing maps in %s/\n", cfg->pin_dir);

        ret = bpf_object__unpin_maps(bpf_obj, cfg->pin_dir);
        if (ret) {
            EPRT("Failed to unpin maps in %s\n", cfg->pin_dir);
            return EXIT_FAIL_BPF;
        }
    }

    ret = bpf_object__pin_maps(bpf_obj, cfg->pin_dir);
    if (ret) {
        return EXIT_FAIL_BPF;
    }
    VPRT(" - Pinning maps in %s/\n", cfg->pin_dir);
    return EXIT_OK;
}

static void reload_handler()
{
    VPRT("Reloading configurations\n");
    __u16 key = CONFIG_MAP_KEY_IDLE_TO;
    __u32 val;

    int ret = bpf_map_lookup_elem(sink_config_map_fd, &key, &val);
    if (ret < 0) {
        EPRT("Failed to get idle flow timeout from %s\n", SINK_MAP_CONFIG);
    } else {
        if (val <= MAX_IDLE_FLOW_TIMEOUT_MS) {
            sink_idle_flow_timeout_ns = (uint64_t)val * MILLI_TO_NANO;
            VPRT("Updated sink idle flow timeout to %" PRIu64 " ns\n",
                 sink_idle_flow_timeout_ns);
        } else {
            EPRT("Value %d from the map is larger than the maximum "
                 "supported value of %d ms\n",
                 val, MAX_IDLE_FLOW_TIMEOUT_MS);
        }
    }

    key = CONFIG_MAP_KEY_PKTLOSS_TO;
    ret = bpf_map_lookup_elem(sink_config_map_fd, &key, &val);
    if (ret < 0) {
        EPRT("Failed to get packet loss timeout from %s\n", SINK_MAP_CONFIG);
    } else {
        if (val <= MAX_PKT_LOSS_TIMEOUT_MS) {
            sink_pkt_loss_timeout_ns = (uint64_t)val * MILLI_TO_NANO;
            VPRT("Updated sink packet loss timeout to %" PRIu64 " ns\n",
                 sink_pkt_loss_timeout_ns);
        } else {
            EPRT("Value %d from the map is larger than the maximum "
                 "supported value of %d ms\n",
                 val, MAX_PKT_LOSS_TIMEOUT_MS);
        }
    }
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    struct rlimit r_core;

    int perf_map_fd;
    int flow_stats_map_fd;
    int latency_bucket_map_fd;
    struct bpf_map_info info = {0};

    int ret, i, len;
    int numcpus = libbpf_num_possible_cpus();
    if (numcpus > MAX_CPUS) {
        // todo: need to revisit. If we suggest our user "update MAX_CPUS to
        // number of cpu's on your system", then we shall set MAX_CPUS to the
        // detected number of cpus. If not, we shall revise the message.
        printf("\n***Error***\n");
        printf("Numbers of cpu/cores on your system (%d) are more than %i.\n",
               numcpus, MAX_CPUS);
        printf("Please update MAX_CPUS to number of cpu's on your system.\n");
        return EXIT_FAIL;
    }

    struct config cfg = {
        .xdp_flags = XDP_FLAGS_SKB_MODE,
        .ifindex = -1,
        .node_id = -1,
        .dscp_val = -1,
        .dscp_mask = -1,
        .idle_flow_timeout_ms = DEFAULT_IDLE_FLOW_TIMEOUT_MS,
        .pkt_loss_timeout_ms = PKT_LOSS_TIMEOUT_MS,
        .server_hostname = "",
        .server_port = -1,
        .drop_packet = false,
        .sw_id_after_report_hdr = true,
        .sender_collector_port = -1,
        .num_latency_entries = 0,
        .encap_type = -1,
    };

    snprintf(cfg.report_file, sizeof(cfg.report_file), "%s",
             DEFAULT_HOSTINTD_REPORT_FILE);
    snprintf(cfg.filename, sizeof(cfg.filename), "%s", DEFAULT_KSINK_FILE);

    if (pthread_mutex_init(&seq_num_lock, NULL) != 0) {
        EPRT("Mutex init failed.\n");
        return EXIT_FAIL;
    }

    if (init_send_packet_lock() != 0) {
        EPRT("Mutex init failed.\n");
        return EXIT_FAIL;
    }

    /* Cmdline options can change these */
    parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

    /* Required option */
    if (cfg.ifindex == -1) {
        EPRT("Required option --dev missing\n");
        usage(argv[0], __doc__, long_options, (argc == 1));
        return EXIT_FAIL_OPTION;
    }

    if (cfg.dscp_val == -1 && cfg.dscp_mask != -1) {
        EPRT("dscp value is not specified\n");
        usage(argv[0], __doc__, long_options, (argc == 1));
        return EXIT_FAIL_OPTION;
    }

    if (cfg.dscp_val != -1 && cfg.dscp_mask == -1) {
        EPRT("dscp mask is not specified\n");
        usage(argv[0], __doc__, long_options, (argc == 1));
        return EXIT_FAIL_OPTION;
    }

    if (cfg.encap_type == -1) {
        EPRT("Encap type is not specified\n");
        usage(argv[0], __doc__, long_options, (argc == 1));
        return EXIT_FAIL_OPTION;
    }

    if (cfg.num_latency_entries == 0) {
        EPRT("Required option --latency-bucket missing\n");
        usage(argv[0], __doc__, long_options, (argc == 1));
        return EXIT_FAIL_OPTION;
    }

    if (cfg.idle_flow_timeout_ms <= MAX_IDLE_FLOW_TIMEOUT_MS) {
        sink_idle_flow_timeout_ns =
            (uint64_t)cfg.idle_flow_timeout_ms * MILLI_TO_NANO;
    }

    if (cfg.pkt_loss_timeout_ms <= MAX_PKT_LOSS_TIMEOUT_MS) {
        sink_pkt_loss_timeout_ns =
            (uint64_t)cfg.pkt_loss_timeout_ms * MILLI_TO_NANO;
    }

    if (cfg.server_hostname[0]) {
        snprintf(collector_name, sizeof(collector_name), "%s",
                 cfg.server_hostname);
        collector_port = cfg.server_port < 0 ? COLLECTOR_PORT : cfg.server_port;
        VPRT("Will send report to %s:%i\n", collector_name, collector_port);
    }

    if (cfg.report_file[0]) {
        report_file = fopen(cfg.report_file, "ab+");
        if (!report_file) {
            EPRT("Cannot open file '%s'. Report will not write into it.\n",
                 cfg.report_file);
        } else {
            VPRT("Will send report to file %s\n", cfg.report_file);
        }
    }

    if (cfg.sender_collector_port > 0) {
        sender_collector_port = cfg.sender_collector_port;
        VPRT("Will send report back to sender's UDP port %i\n",
             cfg.sender_collector_port);
    }

    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return EXIT_FAIL;
    }

    if (getrlimit(RLIMIT_CORE, &r_core)) {
        perror("getrlimit(RLIMIT_CORE)");
        return EXIT_FAIL;
    }
    VPRT("Max coredump file size soft:%lu hard:%lu\n", r_core.rlim_cur,
         r_core.rlim_max);

    r_core.rlim_cur = 100UL * 1024UL * 1024UL;
    r_core.rlim_max = 100UL * 1024UL * 1024UL;

    if (setrlimit(RLIMIT_CORE, &r_core)) {
        perror("setrlimit(RLIMIT_CORE)");
        return EXIT_FAIL;
    }

    if (getrlimit(RLIMIT_CORE, &r_core)) {
        perror("getrlimit(RLIMIT_CORE)");
        return EXIT_FAIL;
    }
    VPRT("Max coredump file size soft:%lu hard:%lu\n", r_core.rlim_cur,
         r_core.rlim_max);

    len = snprintf(cfg.pin_dir, sizeof(cfg.pin_dir), "%s/%s", PIN_BASE_DIR,
                   cfg.ifname);
    if (len < 0) {
        EPRT("Failed to create pin dirname. err code: %i\n", len);
        return EXIT_FAIL_OPTION;
    }

    atexit(cleanup);
    signal(SIGINT, sig_handler);
    signal(SIGHUP, reload_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGABRT, sig_handler);

    if (cfg.filename[0]) {
        ret = deploy_ebpf(&cfg);
        if (ret) {
            return ret;
        }
    } else {
        WPRT("No EBPF program specified. Continue by assuming it's already "
             "loaded "
             "into XDP.\n");
    }

    perf_map_fd = open_bpf_map_file(cfg.pin_dir, SINK_MAP_EVENT_PERF, &info);
    if (perf_map_fd < 0) {
        EPRT("Failed to open %s from %s\n", SINK_MAP_EVENT_PERF, cfg.pin_dir);
        return EXIT_FAIL_BPF;
    }
    VPRT("Opened %s with id=%i\n", SINK_MAP_EVENT_PERF, info.id);

    flow_stats_map_fd =
        open_bpf_map_file(cfg.pin_dir, SINK_MAP_FLOW_STATS, &info);
    if (flow_stats_map_fd < 0) {
        EPRT("Failed to open %s from %s\n", SINK_MAP_FLOW_STATS, cfg.pin_dir);
        return EXIT_FAIL_BPF;
    }
    VPRT("Opened %s with id=%i\n", SINK_MAP_FLOW_STATS, info.id);

    latency_bucket_map_fd =
        open_bpf_map_file(cfg.pin_dir, SINK_MAP_LATENCY, &info);
    if (latency_bucket_map_fd < 0) {
        EPRT("Failed to open %s from %s\n", SINK_MAP_LATENCY, cfg.pin_dir);
        return EXIT_FAIL_BPF;
    }
    VPRT("Opened %s with id=%i\n", SINK_MAP_LATENCY, info.id);

    __u16 latency_bucket_key = LATENCY_MAP_KEY_LATENCY_BUCKET;

    ret = bpf_map_update_elem(latency_bucket_map_fd, &latency_bucket_key,
                              &cfg.latency_entries, BPF_ANY);
    if (ret < 0) {
        EPRT("Failed to insert entry in latency bucket map. err code: %i\n",
             ret);
        return EXIT_FAIL_BPF;
    }

    sink_config_map_fd = open_bpf_map_file(cfg.pin_dir, SINK_MAP_CONFIG, &info);
    if (sink_config_map_fd < 0) {
        EPRT("Failed to open %s from %s\n", SINK_MAP_CONFIG, cfg.pin_dir);
        return EXIT_FAIL_BPF;
    }
    VPRT("Opened %s with id=%i\n", SINK_MAP_CONFIG, info.id);

    if (cfg.node_id != -1) {
        // enum ConfigKey node_id_key = NODE_ID;
        __u16 node_id_key = CONFIG_MAP_KEY_NODE_ID;
        ret = bpf_map_update_elem(sink_config_map_fd, &node_id_key,
                                  &cfg.node_id, BPF_ANY);
        if (ret < 0) {
            EPRT("Failed to insert node_id (%i) in sink config map. err code: "
                 "%i\n",
                 cfg.node_id, ret);
            return EXIT_FAIL_BPF;
        }
        VPRT("Set node_id (%i) in sink config map\n", cfg.node_id);
    }

    if (cfg.dscp_val != -1 && cfg.dscp_mask != -1) {
        __u16 dscp_val_key = CONFIG_MAP_KEY_DSCP_VAL;
        ret = bpf_map_update_elem(sink_config_map_fd, &dscp_val_key,
                                  &cfg.dscp_val, BPF_ANY);
        if (ret < 0) {
            EPRT("Failed to insert dscp_val in sink config map. err code: %i\n",
                 ret);
            return EXIT_FAIL_BPF;
        }
        __u16 dscp_mask_key = CONFIG_MAP_KEY_DSCP_MASK;
        ret = bpf_map_update_elem(sink_config_map_fd, &dscp_mask_key,
                                  &cfg.dscp_mask, BPF_ANY);
        if (ret < 0) {
            EPRT(
                "Failed to insert dscp_mask in sink config map. err code: %i\n",
                ret);
            return EXIT_FAIL_BPF;
        }
        VPRT(
            "Set dscp_val (0x%02x) and dscp_mask (0x%02x) in sink config map\n",
            cfg.dscp_val, cfg.dscp_mask);
    }

    __u16 idel_to_key = CONFIG_MAP_KEY_IDLE_TO;
    ret = bpf_map_update_elem(sink_config_map_fd, &idel_to_key,
                              &cfg.idle_flow_timeout_ms, BPF_ANY);
    if (ret < 0) {
        EPRT("Failed to insert idle flow timeout in sink config map. err code: "
             "%i\n",
             ret);
        return EXIT_FAIL_BPF;
    }
    VPRT("Set idle flow timeout to %i ms in sink config map\n",
         cfg.idle_flow_timeout_ms);

    __u16 pkt_loss_key = CONFIG_MAP_KEY_PKTLOSS_TO;
    ret = bpf_map_update_elem(sink_config_map_fd, &pkt_loss_key,
                              &cfg.pkt_loss_timeout_ms, BPF_ANY);
    if (ret < 0) {
        EPRT("Failed to insert packet loss timeout in sink config map. err "
             "code: "
             "%i\n",
             ret);
        return EXIT_FAIL_BPF;
    }
    VPRT("Set packet loss timeout to %i ms in sink config map\n",
         cfg.pkt_loss_timeout_ms);

    __u16 drop_packet_key = CONFIG_MAP_KEY_DROP_PACKET;
    if (cfg.drop_packet == 1) {
        ret = bpf_map_update_elem(sink_config_map_fd, &drop_packet_key,
                                  &cfg.drop_packet, BPF_ANY);
        if (ret < 0) {
            EPRT("Failed to insert drop packet (%i) in sink config map. err "
                 "code: "
                 "%i\n",
                 cfg.drop_packet, ret);
            return EXIT_FAIL_BPF;
        }
        VPRT("Set drop packet to (%i) in sink config map\n", cfg.drop_packet);
    }

    if (cfg.sw_id_after_report_hdr) {
        report_with_switch_id = 1;
    }

    test_bpf_perf_event(perf_map_fd, numcpus);

    for (i = 0; i < numcpus; i++) {
        if (perf_event_mmap_header(pmu_fds[i], &headers[i]) < 0) {
            return 1;
        }
    }

    size_t drop_detection_timer, source_clean_timer, time_offset_update_timer;
    init_timers();
    drop_detection_timer =
        start_timer(100, pkt_drop_stats_collect, &flow_stats_map_fd);
    source_clean_timer = start_timer(100, clear_source_idle_flows, NULL);
    time_offset_update_timer =
        start_timer(TU_INTERVAL_SEC * MSECS_PER_SEC, update_time_offset, NULL);

    if (cfg.encap_type == ENCAP_INT_05_OVER_TCP_UDP) {
        ret = perf_event_poller_multi(pmu_fds, headers, numcpus,
                                      process_ebpf_perf_event_from_sink, &done);
    } else if (cfg.encap_type == ENCAP_INT_05_EXTENSION_UDP) {
        ret = perf_event_poller_multi(
            pmu_fds, headers, numcpus,
            process_ebpf_perf_event_from_sink_without_encap, &done);
    } else {
        EPRT("Invalid encap type: %d\n", cfg.encap_type);
        return EXIT_FAIL_BPF;
    }
    stop_timer(drop_detection_timer);
    stop_timer(source_clean_timer);
    stop_timer(time_offset_update_timer);
    close_timers();
    pthread_mutex_destroy(&seq_num_lock);

    xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);

    return ret;
}
