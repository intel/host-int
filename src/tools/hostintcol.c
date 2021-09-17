/* Copyright (C) 2021 Intel Corporation */
/* SPDX-License-Identifier: BSD-3-Clause */

#include "common_defines.h"
#include "common_params.h"
#include "common_report.h"
#include "intbpf.h"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define DEFAULT_HOSTINTCOL_PORT 36166
#define MAX_PKT_SIZE 1152 // SAMPLE_SIZE(1024) + 128

static const int tcp_int_meta_offset =
    sizeof(struct int_report_hdr) + sizeof(struct iphdr) +
    sizeof(struct tcphdr) + sizeof(struct int_shim_hdr) +
    sizeof(struct int_metadata_hdr);
static const int udp_int_meta_offset =
    sizeof(struct int_report_hdr) + sizeof(struct iphdr) +
    sizeof(struct udphdr) + sizeof(struct int_shim_hdr) +
    sizeof(struct int_metadata_hdr);
static FILE *report_file;

static int done;
static void sig_handler(int signo)
{
    DPRT("Caught signal. Stop program...\n");
    done = 1;
}

static const char *__doc__ =
    "INT Edge-to-Edge Collector that collects INT Edge-to-Edge reports.\n"
    "Usually run with hostintctl to get reports sent back from receiver.\n";

static const struct option_wrapper long_options[] = {
    {{"help", no_argument, NULL, 'h'}, "Show help", false},

    {{"Version", no_argument, NULL, 'V'}, "Print version number", false},

    {{"quiet", no_argument, NULL, 'q'}, "Quiet mode (no output)"},

    {{"report-output", required_argument, NULL, 'o'},
     "Report output file. An empty string indicates do not print report data"
     "into file. Default is " DEFAULT_HOSTINTCOL_REPORT_FILE "."},

    {{"bind", required_argument, NULL, 'b'},
     "Bind IP address used to receive reports from hostintd"},

    {{"port", required_argument, NULL, 6},
     "Port number used to receive reports from hostintd"},

    {{0, 0, NULL, 0}, NULL, false}};

void cleanup()
{
    DPRT("CLEANUP\n");
    if (report_file) {
        fclose(report_file);
    }
}

int launch_udp_receiver(char *ip_addr, int port)
{
    int sockfd;
    struct sockaddr_in server_addr = {0};

    /* socket: create the socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        EPRT("Opening socket (%i) failed : %s\n", sockfd, strerror(errno));
        return -EXIT_FAIL;
    }

    server_addr.sin_family = AF_INET; // IPv4
    server_addr.sin_port = htons(port);
    if (ip_addr == NULL || ip_addr[0] == 0) {
        server_addr.sin_addr.s_addr = INADDR_ANY; // All available interfaces
        VPRT("Will bind to port %i on all available interfaces\n", port);
    } else {
        struct in_addr addr;
        if (inet_aton(ip_addr, &addr) == 0) {
            EPRT("Invalid IP address: '%s'\n", ip_addr);
            return -EXIT_FAIL_OPTION;
        }
        server_addr.sin_addr.s_addr = addr.s_addr;
        VPRT("Will bind to %s:%i\n", ip_addr, port);
    }

    if (bind(sockfd, (const struct sockaddr *)&server_addr,
             sizeof(server_addr)) < 0) {
        EPRT("Failed to bind socket (%i) : %s\n", sockfd, strerror(errno));
        close(sockfd);
        return -EXIT_FAIL;
    }
    VPRT("Bind successfully\n");

    return sockfd;
}

void get_flow_key(struct flow_key *out_key, __u8 *data, int len, int iph_offset)
{
    struct iphdr *iph = (struct iphdr *)&(data[iph_offset]);
    /* TODO: Another place to change if we ever need to support IPv4
     * options. */
    int offset = iph_offset + sizeof(struct iphdr);
    out_key->saddr = iph->saddr;
    out_key->daddr = iph->daddr;
    out_key->proto = iph->protocol;
    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)&(data[offset]);
        out_key->sport = udph->source;
        out_key->dport = udph->dest;
    } else if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)&(data[offset]);
        out_key->sport = tcph->source;
        out_key->dport = tcph->dest;
    }
}

void process_legacy_report(__u8 *data, int len, __u32 seq_num, __u32 ts)
{
    struct flow_key key;
    int offset = sizeof(struct int_report_hdr);
    struct iphdr *iph = (struct iphdr *)&(data[offset]);
    get_flow_key(&key, data, len, offset);
    __u8 ip_protocol = iph->protocol;
    int int_meta_offset = 0;
    if (ip_protocol == IPPROTO_UDP) {
        int_meta_offset = udp_int_meta_offset;
    } else if (ip_protocol == IPPROTO_TCP) {
        int_meta_offset = tcp_int_meta_offset;
    } else {
        WPRT("Unknown report with IP proto: 0x%02x\n", ip_protocol);
        return;
    }

    struct timespec tmp_ts = {0};
    tmp_ts.tv_sec = ts;
    if (report_file) {
        print_latency_report(
            report_file,
            (struct int_metadata_entry
                 *)&data[int_meta_offset + sizeof(struct int_metadata_entry)],
            (struct int_metadata_entry *)&data[int_meta_offset], seq_num,
            &tmp_ts, &key);
    }
}

void process_drop_report(__u8 *data, int len, __u32 seq_num, __u32 ts)
{
    struct flow_key key;
    struct timespec tmp_ts = {0};
    tmp_ts.tv_sec = ts;
    if (report_file) {
        struct int_drop_summary_data reportd;
        memcpy(&reportd, data + sizeof(struct int_report_hdr), sizeof(reportd));
        get_flow_key(&key, data, len,
                     (sizeof(struct int_report_hdr) +
                      sizeof(struct int_drop_summary_data)));
        print_drop_report(report_file, &reportd, seq_num, &tmp_ts, &key);
    }
}

void listen_data(int sockfd)
{
    int pkt_len;
    socklen_t addr_len;
    struct sockaddr_in client_addr = {0};
    __u8 data[MAX_PKT_SIZE];
    struct int_report_hdr reporth;

    addr_len = sizeof(client_addr);
    while (!done) {
        pkt_len = recvfrom(sockfd, data, MAX_PKT_SIZE, MSG_DONTWAIT,
                           (struct sockaddr *)&client_addr, &addr_len);
        if (pkt_len < 0) {
            /* No packet available to read at this time.  Sleep for a
             * little while and try again. */
            usleep(10000);
            continue;
        }
        if (pkt_len > (int)sizeof(reporth)) {
#ifdef EXTRA_DEBUG
            int i;
            fprintf(stderr, "Rcv %i bytes from %s:%i\n  ", pkt_len,
                    inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
            for (i = 0; i < pkt_len; i++) {
                fprintf(stderr, "%02x ", data[i]);
                if ((i + 1) % 8 == 0) {
                    printf("\n  ");
                }
            }
            printf("\n");
#endif
            memcpy(&reporth, data, sizeof(reporth));
            if (reporth.proto == INT_REPORT_PROTO_LATENCY) {
                process_legacy_report(data, pkt_len, ntohl(reporth.seq_num),
                                      ntohl(reporth.ts));
            } else if (reporth.proto == INT_REPORT_PROTO_DROP) {
                process_drop_report(data, pkt_len, ntohl(reporth.seq_num),
                                    ntohl(reporth.ts));
            } else {
                WPRT("Unknown report with INT proto: 0x%02x\n", reporth.proto);
            }
        }
    }
}

int main(int argc, char **argv)
{
    struct config cfg = {
        .port = DEFAULT_HOSTINTCOL_PORT,
        .bind_addr = "",
    };
    snprintf(cfg.report_file, sizeof(cfg.report_file), "%s",
             DEFAULT_HOSTINTCOL_REPORT_FILE);

    parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

    if (cfg.report_file[0]) {
        report_file = fopen(cfg.report_file, "ab+");
        if (!report_file) {
            EPRT("Cannot open file '%s'. Report will not write into it.\n",
                 cfg.report_file);
        } else {
            VPRT("Will print report to file %s\n", cfg.report_file);
        }
    }

    int sockfd = launch_udp_receiver(cfg.bind_addr, cfg.port);
    if (sockfd < 0) {
        return sockfd;
    }

    atexit(cleanup);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    listen_data(sockfd);

    close(sockfd);
    return EXIT_OK;
}
