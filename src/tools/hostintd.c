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

static int report_seq_num = 1;
static pthread_mutex_t seq_num_lock;

static int done;
static void sig_handler(int signo) {
    DPRT("Caught signal. Stop program...\n");
    done = 1;
}
static int source_config_map_fd = -1;
static int source_flow_stats_map_fd = -1;
static int sink_config_map_fd = -1;
static char collector_name[512];
static int collector_port = -1;
static int sender_collector_port = -1;
static FILE *report_file;
// can change when we reload cfg
static uint64_t sink_idle_flow_timeout_ns, sink_pkt_loss_timeout_ns;

static uint64_t time_offset;

static const char *__doc__ =
    "INT Edge-to-Edge User Space Program that loads in sink EBPF program, and\n"
    "maintains shared EBPF map for both sink and source EBPF programs.\n"
    "It unloads sink EBPF program on exit or interruption.\n";

static const struct option_wrapper long_options[] = {
    {{"help", no_argument, NULL, 'h'}, "Show help", false},

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

    {{"collector-server", required_argument, NULL, 'C'},
     "Collector server name. Default is an empty string that indicates do not "
     "report data to a collector."},

    {{"collector-port", required_argument, NULL, 'P'},
     "Collector port number."},

    {{"report-output", required_argument, NULL, 'o'},
     "Report output file. An empty string indicates do not report data to a "
     "file. Default is " DEFAULT_HOSTINTD_REPORT_FILE "."},

    {{"sender-collector-port", required_argument, NULL, 5},
     "Send report back to sender's UDP port"},

    {{"filename", required_argument, NULL, 1},
     "Load program from <file>",
     "<file>"},

    {{0, 0, NULL, 0}, NULL, false}};

void cleanup() {
    DPRT("CLEANUP\n");
    if (report_file) {
        fclose(report_file);
    }
}

uint64_t get_time_offset() {
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

int update_time_offset_map(int map_fd, uint64_t time_offset, char *map_name) {
    __u16 time_offset_key = CONFIG_MAP_KEY_TIME_OFFSET;
    int ret = bpf_map_update_elem(map_fd, &time_offset_key, &time_offset, BPF_ANY);
    if (ret < 0) {
        EPRT("Failed to update time offset (%lu) in %s err code: "
             "%i\n",
             time_offset, map_name, ret);
        return ret;
    }
    VPRT("Updated time offset in %s to %lu ns\n", map_name, time_offset);
    return 0;
}

void update_time_offset(size_t timer_id, void *params) {
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

static int print_bpf_output(void *data, int size) {
    struct {
        struct packet_metadata meta;
        __u8 pkt_data[SAMPLE_SIZE];
    } __packed *e = data;
    struct timespec ts;
    int err;

    if (e->meta.s_meta.cookie != 0xdead) {
        EPRT("BUG cookie %x sized %d\n", e->meta.s_meta.cookie, size);
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

    if (ip_protocol == IPPROTO_UDP) {
        l4_hdr_size = sizeof(struct udphdr);
    } else if (ip_protocol == IPPROTO_TCP) {
        l4_hdr_size = sizeof(struct tcphdr);
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

    /* populate buffer */
    __u32 pkt_len = (int_rpt_body_part1_len + int_rpt_body_part2_len +
                     int_rpt_body_part3_len);
    __u8 buffer[pkt_len];
    __u32 offset = 0;
    memcpy(&buffer[offset], &(e->pkt_data[int_rpt_body_part1_offset]),
           int_rpt_body_part1_len);
    offset += int_rpt_body_part1_len;

    memcpy(&buffer[offset], &intmdsink, sizeof(struct int_metadata_entry));
    offset += sizeof(struct int_metadata_entry);

    memcpy(&buffer[offset], &(e->pkt_data[int_rpt_body_part3_offset]),
           int_rpt_body_part3_len);
    offset += int_rpt_body_part3_len;

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
                             report_seq_num, &ts);
    }

    if (sender_collector_port > 0) {
        err = send_latency_report(NULL, saddr, sender_collector_port, pkt_len,
                                  buffer, report_seq_num, &ts);
        if (err) {
            EPRT("Failed to send back report to sender! (%i)\n", err);
            return LIBBPF_PERF_EVENT_ERROR;
        }
    }

    pthread_mutex_lock(&seq_num_lock);
    report_seq_num += 1;
    pthread_mutex_unlock(&seq_num_lock);

#ifdef EXTRA_DEBUG
    int i;
    printf("pkt len: %-5d bytes. hdr: ", pkt_len);
    for (i = 0; i < pkt_len; i++)
        printf("%02x ", buffer[i]);
    printf("\n");
#endif
    // pcap_dump((u_char *) pdumper, &h, e->pkt_data);
    // pcap_pkts++;
    return LIBBPF_PERF_EVENT_CONT;
}

static int send_drop_summary_report(struct flow_key *key,
                                    struct sink_flow_stats_datarec *value,
                                    struct timespec *ts) {

    int err;
    __u16 len;
    __u8 buf[MAX_REPORT_PAYLOAD_LEN];

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
    reportd.gap_count =
        htonl(value->gap_tail_seq_num - value->gap_head_seq_num - 1 -
              value->gap_pkt_count);
    memcpy(buf, &reportd, sizeof(reportd));
    len = sizeof(reportd);

    // create IP header
    struct iphdr iph = {
        .ihl = 5,
        .version = 4,
        .protocol = key->proto,
        .saddr = htonl(key->saddr),
        .daddr = htonl(key->daddr),
    };
    memcpy(buf + len, &iph, sizeof(iph));
    len += sizeof(iph);

    int l4_hdr_size = 0;
    // create L4 header
    if (key->proto == IPPROTO_UDP) { // UDP
        struct udphdr udph = {
            .source = htons(key->sport),
            .dest = htons(key->dport),
            .len = htons(sizeof(udph)),
        };
        l4_hdr_size += sizeof(udph);
        memcpy(buf + len, &udph, sizeof(udph));
        len += sizeof(udph);
    } else if (key->proto == IPPROTO_TCP) { // TCP
        struct tcphdr tcph = {
            .source = htons(key->sport),
            .dest = htons(key->dport),
        };
        l4_hdr_size += sizeof(tcph);
        memcpy(buf + len, &tcph, sizeof(tcph));
        len += sizeof(tcph);
    }

    if (collector_port > 0) {
        err = send_drop_report(collector_name, 0, collector_port, len, buf,
                               report_seq_num, ts);
        if (err) {
            EPRT("Failed to send report! (%i)\n", err);
            return -1;
        }
    }

    if (report_file) {
        print_drop_report(report_file, &reportd, report_seq_num, ts);
    }

    if (sender_collector_port > 0) {
        err = send_drop_report(NULL, iph.saddr, sender_collector_port, len, buf,
                               report_seq_num, ts);
        if (err) {
            EPRT("Failed to send report! (%i)\n", err);
            return -1;
        }
    }

    pthread_mutex_lock(&seq_num_lock);
    report_seq_num += 1;
    pthread_mutex_unlock(&seq_num_lock);
    return 0;
}

void clear_source_idle_flows(size_t timer_id, void *params) {
    uint64_t idle_flow_timeout_ns = sink_idle_flow_timeout_ns;
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
        if (curr_ts_ns - value.ts_ns > idle_flow_timeout_ns) {
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

void pkt_drop_stats_collect(size_t timer_id, void *params) {
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
    uint64_t delta_ns = 0;

    // while(bpf_map_get_next_key_and_delete(&flow_gap_map_fd, prev_key, &key,
    // &delete_previous) == 0) {
    while (bpf_map_get_next_key(flow_stats_map_fd, prev_key, &key) == 0) {
        if (bpf_map_lookup_elem(flow_stats_map_fd, &key, &value) < 0) {
            EPRT("failed to fetch elem from sink flow_stats_map_fd\n");
            break;
        }
        DPRT("curr_ts_ns: %" PRIu64
             ", val.gap_head_ts_ns: %llu, val.gap_head_seq_no: %u, "
             "val.gap_tail_ts_ns: %llu, val.gap_tail_seq_no: %u, count: %u\n",
             curr_ts_ns, value.gap_head_ts_ns, value.gap_head_seq_num,
             value.gap_tail_ts_ns, value.gap_tail_seq_num, value.gap_pkt_count);
        delta_ns = curr_ts_ns - value.gap_head_ts_ns;
        if (delta_ns > pkt_loss_timeout_ns) {
            if (value.gap_tail_seq_num != 0 &&
                value.gap_tail_seq_num - value.gap_head_seq_num - 1 >
                    value.gap_pkt_count) {
                DPRT("Send drop summary report\n");
                send_drop_summary_report(&key, &value, &curr_ts);
            }

            if (delta_ns > idle_flow_timeout_ns) {
                // Remove the gap entry from the map
                to_delete[to_delete_size++] = key;
                DPRT("Delete entry\n");
            } else if (value.gap_tail_seq_num != 0) {
                value.gap_head_ts_ns = value.gap_tail_ts_ns;
                value.gap_tail_ts_ns = 0;
                value.gap_head_seq_num = value.gap_tail_seq_num;
                value.gap_tail_seq_num = 0;
                value.gap_pkt_count = 0;
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

int deploy_ebpf(struct config *cfg) {
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

static void reload_handler() {
    VPRT("Reloading configurations\n");
    __u16 key = CONFIG_MAP_KEY_IDLE_TO;
    __u32 val;

    int ret = bpf_map_lookup_elem(sink_config_map_fd, &key, &val);
    if (ret < 0) {
        EPRT("Failed to get idle flow timeout from %s\n", SINK_MAP_CONFIG);
    } else {
        sink_idle_flow_timeout_ns = (uint64_t)val * MILLI_TO_NANO;
        VPRT("Updated sink idle flow timeout to %" PRIu64 " ns\n",
             sink_idle_flow_timeout_ns);
    }

    key = CONFIG_MAP_KEY_PKTLOSS_TO;
    ret = bpf_map_lookup_elem(sink_config_map_fd, &key, &val);
    if (ret < 0) {
        EPRT("Failed to get packet loss timeout from %s\n", SINK_MAP_CONFIG);
    } else {
        sink_pkt_loss_timeout_ns = (uint64_t)val * MILLI_TO_NANO;
        VPRT("Updated sink packet loss timeout to %" PRIu64 " ns\n",
             sink_pkt_loss_timeout_ns);
    }
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

    int perf_map_fd;
    int flow_stats_map_fd;
    struct bpf_map_info info = {0};
    // struct bpf_map *map;

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
        .sender_collector_port = -1,
    };
    strncpy(cfg.report_file, DEFAULT_HOSTINTD_REPORT_FILE,
            sizeof(cfg.report_file));
    strncpy(cfg.filename, DEFAULT_KSINK_FILE, sizeof(cfg.filename));

    if (pthread_mutex_init(&seq_num_lock, NULL) != 0) {
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

    sink_idle_flow_timeout_ns =
        (uint64_t)cfg.idle_flow_timeout_ms * MILLI_TO_NANO;

    sink_pkt_loss_timeout_ns =
        (uint64_t)cfg.pkt_loss_timeout_ms * MILLI_TO_NANO;

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

    ret = perf_event_poller_multi(pmu_fds, headers, numcpus, print_bpf_output,
                                  &done);

    stop_timer(drop_detection_timer);
    stop_timer(source_clean_timer);
    stop_timer(time_offset_update_timer);
    close_timers();
    pthread_mutex_destroy(&seq_num_lock);

    xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);

    return ret;
}
