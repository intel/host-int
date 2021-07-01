/* Copyright (C) 2021 Intel Corporation */
/* SPDX-License-Identifier: BSD-3-Clause */

#include "common_report.h"
#include "common_defines.h"
#include "intbpf.h"
#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_REPORT_PAYLOAD_LEN 2048
#define T_LATENCY "Latency"
#define T_DROP "Drop"

// todo: may want to keep the socket open to improve performance
int send_packet(char *server_name, __u32 server_addr, int server_port,
                __u16 pkt_len, __u8 *pkt_data) {
    int sockfd, n;
    int serverlen;
    struct sockaddr_in serveraddr;

    /* socket: create the socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        EPRT("Opening socket (%i) failed\n", sockfd);
        close(sockfd);
        return -1;
    }

    /* build the server's Internet address */
    bzero((char *)&serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    if (server_name) {
        /* gethostbyname: get the server's DNS entry */
        struct hostent *server = gethostbyname(server_name);
        if (server == NULL) {
            EPRT("No such host as '%s'\n", server_name);
            close(sockfd);
            return -1;
        }
        bcopy((char *)server->h_addr, (char *)&serveraddr.sin_addr.s_addr,
              server->h_length);
    } else {
        serveraddr.sin_addr.s_addr = server_addr;
    }
    serveraddr.sin_port = htons(server_port);

    serverlen = sizeof(serveraddr);
    n = sendto(sockfd, pkt_data, pkt_len, 0,
               (const struct sockaddr *)&serveraddr, serverlen);
    if (n < 0) {
        EPRT("Sending report to %s failed\n", inet_ntoa(serveraddr.sin_addr));
        close(sockfd);
        return -1;
    }
    DPRT("Sending report %i bytes to %s\n", n, inet_ntoa(serveraddr.sin_addr));

    close(sockfd);

    return 0;
}

int send_latency_report(char *server_name, __u32 server_addr, int server_port,
                        __u16 pkt_len, __u8 *pkt_data, int report_seq_num,
                        struct timespec *ts) {
    __u8 buf[MAX_REPORT_PAYLOAD_LEN];

    if (sizeof(struct int_report_hdr) + pkt_len > MAX_REPORT_PAYLOAD_LEN) {
        EPRT("Report size (%lu) exceeds the max payload len\n",
             sizeof(struct int_report_hdr) + pkt_len);
        return -1;
    }

    struct int_report_hdr reporth = {
        .proto = INT_REPORT_PROTO_LATENCY,
        .d = 0,
        .q = 0,
        .f = 1,
        .seq_num = htonl(report_seq_num),
        .ts = htonl(ts->tv_sec),
    };
    memcpy(buf, &reporth, sizeof(reporth));

    memcpy(buf + sizeof(reporth), pkt_data, pkt_len);

    return send_packet(server_name, server_addr, server_port,
                       sizeof(reporth) + pkt_len, buf);
}

void print_latency_report(FILE *out, struct int_metadata_entry *source_data,
                          struct int_metadata_entry *sink_data,
                          int report_seq_num, struct timespec *ts) {
    struct tm *tm = localtime(&ts->tv_sec);

    fprintf(out, "Seq: %i Time: %04d-%02d-%02d %.2d:%.2d:%.2d.%.6d Type: %s\n",
            report_seq_num, tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
            tm->tm_hour, tm->tm_min, tm->tm_sec,
            (int)(ts->tv_nsec / NANOSECS_PER_USEC), T_LATENCY);
    fprintf(
        out,
        "  Source  NodeID: %u IngressPort: %i EgressPort: %i IngressTS: %u ns "
        "EgressTS: %u ns\n",
        bpf_ntohl(source_data->node_id), bpf_ntohs(source_data->ingress_port),
        bpf_ntohs(source_data->egress_port), bpf_ntohl(source_data->ingress_ts),
        bpf_ntohl(source_data->egress_ts));
    fprintf(
        out,
        "  Sink    NodeID: %u IngressPort: %i EgressPort: %i IngressTS: %u ns "
        "EgressTS: %u ns\n",
        bpf_ntohl(sink_data->node_id), bpf_ntohs(sink_data->ingress_port),
        bpf_ntohs(sink_data->egress_port), bpf_ntohl(sink_data->ingress_ts),
        bpf_ntohl(sink_data->egress_ts));
    fflush(out);
}

int send_drop_report(char *server_name, __u32 server_addr, int server_port,
                     __u16 pkt_len, __u8 *pkt_data, int report_seq_num,
                     struct timespec *ts) {
    __u8 buf[MAX_REPORT_PAYLOAD_LEN];

    if (sizeof(struct int_report_hdr) + pkt_len > MAX_REPORT_PAYLOAD_LEN) {
        EPRT("Report size (%lu) exceeds the max payload len\n",
             sizeof(struct int_report_hdr) + pkt_len);
        return -1;
    }

    struct int_report_hdr reporth = {
        .proto = INT_REPORT_PROTO_DROP,
        .d = 1,
        .q = 0,
        .f = 1,
        .seq_num = htonl(report_seq_num),
        .ts = htonl(ts->tv_sec),
    };
    memcpy(buf, &reporth, sizeof(reporth));

    memcpy(buf + sizeof(reporth), pkt_data, pkt_len);

    return send_packet(server_name, server_addr, server_port,
                       sizeof(reporth) + pkt_len, buf);
}

void print_drop_report(FILE *out, struct int_drop_summary_data *data,
                       int report_seq_num, struct timespec *ts) {
    struct tm *tm = localtime(&ts->tv_sec);

    fprintf(out, "Seq: %i Time: %04d-%02d-%02d %.2d:%.2d:%.2d.%.6d Type: %s\n",
            report_seq_num, tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
            tm->tm_hour, tm->tm_min, tm->tm_sec,
            (int)(ts->tv_nsec / NANOSECS_PER_USEC), T_DROP);
    fprintf(out, "  SrcNodeID: %u DstNodeID: %u SrcPort: %i DstPort: %i\n",
            bpf_ntohl(data->src_switch_id), bpf_ntohl(data->dst_switch_id),
            bpf_ntohs(data->src_port), bpf_ntohs(data->dst_port));
    fprintf(out, "  GapTS: %u s FlowSeq: %u GapCount: %u\n",
            bpf_ntohl(data->gap_timestamp), bpf_ntohl(data->flow_seq_num),
            bpf_ntohl(data->gap_count));
    fflush(out);
}