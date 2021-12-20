/* Copyright (C) 2021 Intel Corporation */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef __UUTILS__
#define __UUTILS__

#include "intbpf.h"
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#define max(a, b) ((a) > (b) ? (a) : (b))
#define INET_NTOP_BUF_LEN max(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)

#define MAX_REPORT_PAYLOAD_LEN 2048
#define IP_HDR_OFF 14

static int pmu_fds[MAX_CPUS];
static struct perf_event_mmap_page *headers[MAX_CPUS];

static inline int perf_event_open(struct perf_event_attr *event, pid_t pid,
                                  int cpu, int group_fd, unsigned long flags)
{
    int res = syscall(__NR_perf_event_open, event, pid, cpu, group_fd, flags);

    return res;
}

static void test_bpf_perf_event(int map_fd, int num)
{
    struct perf_event_attr attr = {
        .sample_type = PERF_SAMPLE_RAW,
        .type = PERF_TYPE_SOFTWARE,
        .config = PERF_COUNT_SW_BPF_OUTPUT,
        .wakeup_events = 1, /* get an fd notification for every event */
    };
    int i;

    for (i = 0; i < num; i++) {
        int key = i;

        pmu_fds[i] =
            perf_event_open(&attr, -1 /*pid*/, i /*cpu*/, -1 /*group_fd*/, 0);

        assert(pmu_fds[i] >= 0);
        assert(bpf_map_update_elem(map_fd, &key, &pmu_fds[i], BPF_ANY) == 0);
        ioctl(pmu_fds[i], PERF_EVENT_IOC_ENABLE, 0);
    }
}

struct perf_record_sample {
    struct perf_event_header header;
    __u32 size;
    char data[];
};

struct perf_record_lost {
    struct perf_event_header header;
    __u64 id;
    __u64 lost;
};

typedef enum bpf_perf_event_ret (*perf_event_print_fn)(void *data, int size);

static enum bpf_perf_event_ret
bpf_perf_event_print(struct perf_event_header *header, void *private_data)
{
    perf_event_print_fn fn = private_data;

    if (header->type == PERF_RECORD_SAMPLE) {
        struct perf_record_sample *prs = (struct perf_record_sample *)header;
        return fn(prs->data, prs->size);
    } else if (header->type == PERF_RECORD_LOST) {
        struct perf_record_lost *prl = (struct perf_record_lost *)header;
        fprintf(stderr, "Warning - Lost %lld events\n", prl->lost);
    } else {
        fprintf(stderr, "Error - Unknown event: type=%d size=%d\n",
                header->type, header->size);
    }

    return LIBBPF_PERF_EVENT_CONT;
}

static int page_size;
static int page_cnt = 8;

int perf_event_mmap_header(int fd, struct perf_event_mmap_page **header)
{
    void *base;
    int mmap_size;

    page_size = getpagesize();
    mmap_size = page_size * (page_cnt + 1);

    base = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        printf("mmap err\n");
        return -1;
    }

    *header = base;
    return 0;
}

int perf_event_poller_multi(int *fds, struct perf_event_mmap_page **headers,
                            int num_fds, perf_event_print_fn output_fn,
                            int *done)
{
    enum bpf_perf_event_ret ret = 0;
    struct pollfd *pfds;
    void *buf = NULL;
    size_t len = 0;
    int i;

    pfds = calloc(num_fds, sizeof(*pfds));
    if (!pfds)
        return LIBBPF_PERF_EVENT_ERROR;

    for (i = 0; i < num_fds; i++) {
        pfds[i].fd = fds[i];
        pfds[i].events = POLLIN;
    }

    while (!*done) {
        poll(pfds, num_fds, 1000);
        for (i = 0; i < num_fds; i++) {
            if (!pfds[i].revents)
                continue;

            ret = bpf_perf_event_read_simple(headers[i], page_cnt * page_size,
                                             page_size, &buf, &len,
                                             bpf_perf_event_print, output_fn);
            if (ret != LIBBPF_PERF_EVENT_CONT)
                break;
        }
    }
    free(buf);
    free(pfds);

    return ret == LIBBPF_PERF_EVENT_ERROR ? ret : 0;
}

void debug_print_getaddrinfo_results(struct addrinfo *result)
{
    struct addrinfo *rp;
    int n, j;
    char *family_desc;
    char *socktype_desc;
    char *protocol_desc;
    char address_buf[INET_NTOP_BUF_LEN];
    void *ptr;

    n = 0;
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        n++;
    }
    printf("getaddrinfo returned list of %d results\n", n);
    n = 0;
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        printf("index=%d:\n", n);
        /* See /usr/include/x86_64-linux-gnu/bits/socket.h for a more
         * complete list.  Only the most common values I have seen in
         * practice are included below. */
        switch (rp->ai_family) {
        case AF_UNSPEC:
            family_desc = "AF_UNSPEC";
            break;
        case AF_INET:
            family_desc = "AF_INET - IPv4";
            break;
        case AF_INET6:
            family_desc = "AF_INET6 - IPv6";
            break;
        default:
            family_desc = "(unknown)";
            break;
        }
        switch (rp->ai_socktype) {
        case SOCK_STREAM:
            socktype_desc = "SOCK_STREAM";
            break;
        case SOCK_DGRAM:
            socktype_desc = "SOCK_DGRAM";
            break;
        default:
            socktype_desc = "(unknown)";
            break;
        }
        switch (rp->ai_protocol) {
        case IPPROTO_TCP:
            protocol_desc = "IPPROTO_TCP";
            break;
        case IPPROTO_UDP:
            protocol_desc = "IPPROTO_UDP";
            break;
        default:
            protocol_desc = "(unknown)";
            break;
        }
        printf("  family=%u (%s)\n", rp->ai_family, family_desc);
        printf("  socktype=%u (%s)\n", rp->ai_socktype, socktype_desc);
        printf("  protocol=%u (%s)\n", rp->ai_protocol, protocol_desc);
        printf("  flags=%u\n", rp->ai_flags);
        printf("  canonname=%s\n", rp->ai_canonname);
        printf("  rp->ai_addrlen=%d\n", rp->ai_addrlen);
        printf("  rp->ai_addr:");
        for (j = 0; j < rp->ai_addrlen; j++) {
            if ((j % 2) == 0) {
                printf(" ");
            }
            printf("%02x", ((unsigned char *)rp->ai_addr)[j]);
        }
        printf("\n");
        switch (rp->ai_family) {
        case AF_INET:
            ptr = &((struct sockaddr_in *)rp->ai_addr)->sin_addr;
            inet_ntop(rp->ai_family, ptr, address_buf, sizeof(address_buf));
            printf("  IPv4 address: %s\n", address_buf);
            /*
            printf("  byte offset within ai_addr data: %lu\n",
                   ptr - ((void *)rp->ai_addr));
            */
            break;
        case AF_INET6:
            ptr = &((struct sockaddr_in6 *)rp->ai_addr)->sin6_addr;
            inet_ntop(rp->ai_family, ptr, address_buf, sizeof(address_buf));
            printf("  IPv6 address: %s\n", address_buf);
            /*
            printf("  byte offset within ai_addr data: %lu\n",
                   ptr - ((void *)rp->ai_addr));
            */
            break;
        default:
            printf("  no support for converting family %u to ASCII string\n",
                   rp->ai_family);
            break;
        }
        n++;
    }
}

#endif /* __UUTILS__ */
