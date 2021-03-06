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
#include <pthread.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>
#include <signal.h>
#include <errno.h>

#define MAX_REPORT_PAYLOAD_LEN 2048
#define T_LATENCY "Latency"
#define T_DROP "Drop"

int verbose = 1;
static pthread_mutex_t send_packet_lock;
static pthread_mutex_t printf_lock;

/* buf must point at a buffer that is large enough to hold a string of
 * 16 characters, which includes up to 15 regular characters followed
 * by the null terminator of the C string. */

int init_send_packet_lock()
{
    return pthread_mutex_init(&send_packet_lock, NULL);
}

int init_printf_lock() { return pthread_mutex_init(&printf_lock, NULL); }

void printf_with_lock(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int val;

    val = pthread_mutex_lock(&printf_lock);
    if (val != 0) {
        EPRT("Failed to take mutex lock on printf. err "
             "code: %i\n",
             val);
        exit(1);
    }
    vprintf(format, args);
    val = pthread_mutex_unlock(&printf_lock);
    if (val != 0) {
        EPRT("Failed to unlock mutex lock on printf. err "
             "code: %i\n",
             val);
        exit(1);
    }
    va_end(args);
}

void prt_with_lock(char *str, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int val;

    val = pthread_mutex_lock(&printf_lock);
    if (val != 0) {
        EPRT("Failed to take mutex lock on printf. err "
             "code: %i\n",
             val);
        exit(1);
    }
    fprintf(stderr, "%s", str);
    vfprintf(stderr, format, args);
    val = pthread_mutex_unlock(&printf_lock);
    if (val != 0) {
        EPRT("Failed to unlock mutex lock on printf. err "
             "code: %i\n",
             val);
        exit(1);
    }
    va_end(args);
}

void sprintf_ipv4_addr_dotted_decimal(char *buf,
                                      __u32 ipv4_addr_network_byte_order)
{
    __u32 ipv4_addr_host_byte_order = ntohl(ipv4_addr_network_byte_order);

    snprintf(buf, 16, "%u.%u.%u.%u", (ipv4_addr_host_byte_order >> 24) & 0xff,
             (ipv4_addr_host_byte_order >> 16) & 0xff,
             (ipv4_addr_host_byte_order >> 8) & 0xff,
             (ipv4_addr_host_byte_order >> 0) & 0xff);
}

// todo: may want to keep the socket open to improve performance
int send_packet(char *server_name, __u32 server_addr, int server_port,
                __u16 pkt_len, __u8 *pkt_data)
{
    int sockfd = -1;
    int serverlen;
    int ret = 0;
    int lock_ret = 0;
    struct sockaddr_in serveraddr;
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    char server_port_str[64];
    result = NULL;
    int n;

    lock_ret = pthread_mutex_lock(&send_packet_lock);
    if (lock_ret != 0) {
        EPRT("Failed to take mutex lock on send_packet. err "
             "code: %i\n",
             lock_ret);
        exit(1);
    }
    if (server_name) {
        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = 0;
        hints.ai_protocol = 0; /* Any protocol */
        snprintf(server_port_str, sizeof(server_port_str), "%u", server_port);
        ret = getaddrinfo(server_name, server_port_str, &hints, &result);
        if (ret != 0) {
            EPRT("Error from getaddrinfo for server '%s': %s\n", server_name,
                 gai_strerror(ret));
            ret = -1;
            goto out;
        }
        // debug_print_getaddrinfo_results(result);
        for (rp = result; rp != NULL; rp = rp->ai_next) {
            sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (sockfd != -1) {
                break;
            }
        }
        if (rp == NULL) {
            EPRT("Could not create socket\n");
            ret = -1;
            goto out;
        }
        if (sendto(sockfd, pkt_data, pkt_len, 0, rp->ai_addr, rp->ai_addrlen) ==
            -1) {
            EPRT("sendto failed\n");
            perror("sendto failure");
            ret = -1;
            goto out;
        }
#ifdef EXTRA_DEBUG
        VPRT("Report packet sent of length: %u\n", pkt_len);
#endif
    } else {
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            EPRT("Opening socket (%i) failed\n", sockfd);
            ret = -1;
            goto out;
        }
        bzero((char *)&serveraddr, sizeof(serveraddr));
        serveraddr.sin_family = AF_INET;
        serveraddr.sin_addr.s_addr = server_addr;
        serveraddr.sin_port = htons(server_port);
        serverlen = sizeof(serveraddr);
        n = sendto(sockfd, pkt_data, pkt_len, 0,
                   (const struct sockaddr *)&serveraddr, serverlen);
        if (n < 0) {
            EPRT("Sending report to %s failed\n",
                 inet_ntoa(serveraddr.sin_addr));
            ret = -1;
            goto out;
        }
#ifdef EXTRA_DEBUG
        VPRT("Sending report %i bytes to %s\n", n,
             inet_ntoa(serveraddr.sin_addr));
#endif
    }
    ret = 0;
out:
    if (sockfd >= 0) {
        close(sockfd);
    }
    if (result != NULL) {
        freeaddrinfo(result);
    }
    lock_ret = pthread_mutex_unlock(&send_packet_lock);
    if (lock_ret != 0) {
        EPRT("Failed to unlock mutex lock on send packet. err "
             "code: %i\n",
             lock_ret);
        exit(1);
    }

    return ret;
}

int send_latency_report(char *server_name, __u32 server_addr, __u16 server_port,
                        __u16 pkt_len, __u8 *pkt_data, int report_seq_num,
                        struct timespec *ts)
{
    __u8 buf[MAX_REPORT_PAYLOAD_LEN];

    if (sizeof(struct int_report_hdr) + pkt_len > MAX_REPORT_PAYLOAD_LEN) {
        EPRT("Report size (%lu) exceeds the max payload len\n",
             sizeof(struct int_report_hdr) + pkt_len);
        return -1;
    }

    struct int_report_hdr reporth = {.ver = 0,
                                     .proto = INT_REPORT_PROTO_LATENCY,
                                     .d = 0,
                                     .q = 0,
                                     .f = 1,
                                     .reserved_1 = 0,
                                     .reserved_2_1 = 0,
                                     .hwid = 0,
                                     .seq_num = htonl(report_seq_num),
                                     .ts = htonl(ts->tv_sec)};
    memcpy(buf, &reporth, sizeof(reporth));

    memcpy(buf + sizeof(reporth), pkt_data, pkt_len);

    return send_packet(server_name, server_addr, server_port,
                       sizeof(reporth) + pkt_len, buf);
}

void print_latency_report(FILE *out, struct int_metadata_entry *source_data,
                          struct int_metadata_entry *sink_data,
                          int report_seq_num, struct timespec *ts,
                          struct flow_key *key)
{
    struct tm *tm = localtime(&ts->tv_sec);
    char saddr_buf[IPV4_ADDR_DOTTED_DECIMAL_BUF_SIZE];
    char daddr_buf[IPV4_ADDR_DOTTED_DECIMAL_BUF_SIZE];

    if (tm) {
        fprintf(out,
                "Seq: %i Time: %04d-%02d-%02d %.2d:%.2d:%.2d.%.6d Type: %s\n",
                report_seq_num, tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                tm->tm_hour, tm->tm_min, tm->tm_sec,
                (int)(ts->tv_nsec / NANOSECS_PER_USEC), T_LATENCY);
    } else {
        fprintf(out, "Seq: %i Time: - Type: %s\n", report_seq_num, T_LATENCY);
    }
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
    sprintf_ipv4_addr_dotted_decimal(saddr_buf, key->saddr);
    sprintf_ipv4_addr_dotted_decimal(daddr_buf, key->daddr);
    fprintf(out,
            "  IPv4SrcAddr: %s IPv4DstAddr: %s IPv4Proto: %u"
            " L4SrcPort: %u L4DstPort: %u\n",
            saddr_buf, daddr_buf, key->proto, ntohs(key->sport),
            ntohs(key->dport));
    fflush(out);
}

int send_drop_report(char *server_name, __u32 server_addr, int server_port,
                     __u16 pkt_len, __u8 *pkt_data, int report_seq_num,
                     struct timespec *ts)
{
    __u8 buf[MAX_REPORT_PAYLOAD_LEN];

    if (sizeof(struct int_report_hdr) + pkt_len > MAX_REPORT_PAYLOAD_LEN) {
        EPRT("Report size (%lu) exceeds the max payload len\n",
             sizeof(struct int_report_hdr) + pkt_len);
        return -1;
    }

    struct int_report_hdr reporth = {.ver = 0,
                                     .proto = INT_REPORT_PROTO_DROP,
                                     .d = 1,
                                     .q = 0,
                                     .f = 1,
                                     .reserved_1 = 0,
                                     .reserved_2_1 = 0,
                                     .hwid = 0,
                                     .seq_num = htonl(report_seq_num),
                                     .ts = htonl(ts->tv_sec)};
    memcpy(buf, &reporth, sizeof(reporth));

    memcpy(buf + sizeof(reporth), pkt_data, pkt_len);

    return send_packet(server_name, server_addr, server_port,
                       sizeof(reporth) + pkt_len, buf);
}

void print_drop_report(FILE *out, struct int_drop_summary_data *data,
                       int report_seq_num, struct timespec *ts,
                       struct flow_key *key)
{
    struct tm *tm = localtime(&ts->tv_sec);
    char saddr_buf[IPV4_ADDR_DOTTED_DECIMAL_BUF_SIZE];
    char daddr_buf[IPV4_ADDR_DOTTED_DECIMAL_BUF_SIZE];

    if (tm) {
        fprintf(out,
                "Seq: %i Time: %04d-%02d-%02d %.2d:%.2d:%.2d.%.6d Type: %s\n",
                report_seq_num, tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                tm->tm_hour, tm->tm_min, tm->tm_sec,
                (int)(ts->tv_nsec / NANOSECS_PER_USEC), T_DROP);
    } else {
        fprintf(out, "Seq: %i Time: - Type: %s\n", report_seq_num, T_DROP);
    }
    fprintf(out, "  SrcNodeID: %u DstNodeID: %u SrcPort: %i DstPort: %i\n",
            bpf_ntohl(data->src_switch_id), bpf_ntohl(data->dst_switch_id),
            bpf_ntohs(data->src_port), bpf_ntohs(data->dst_port));
    fprintf(out, "  GapTS: %u s FlowSeq: %u GapCount: %u\n",
            bpf_ntohl(data->gap_timestamp), bpf_ntohl(data->flow_seq_num),
            bpf_ntohl(data->gap_count));
    sprintf_ipv4_addr_dotted_decimal(saddr_buf, key->saddr);
    sprintf_ipv4_addr_dotted_decimal(daddr_buf, key->daddr);
    fprintf(out,
            "  IPv4SrcAddr: %s IPv4DstAddr: %s IPv4Proto: %u"
            " L4SrcPort: %u L4DstPort: %u\n",
            saddr_buf, daddr_buf, key->proto, ntohs(key->sport),
            ntohs(key->dport));
    fflush(out);
}

void set_sig_handler(int signum, void (*handler)())
{
    struct sigaction act;
    char buf[128];

    memset(&act, 0, sizeof(act));
    act.sa_handler = handler;
    if (sigaction(signum, &act, NULL) != 0) {
        strerror_r(errno, buf, sizeof(buf));
        EPRT("sigaction failed: %s\n", buf);
        exit(1);
    }
}
