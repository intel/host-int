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

#define MAX_REPORT_PAYLOAD_LEN 2048
#define IP_HDR_OFF 14

static int pmu_fds[MAX_CPUS];
static struct perf_event_mmap_page *headers[MAX_CPUS];

static inline int perf_event_open(struct perf_event_attr *event, pid_t pid,
                                  int cpu, int group_fd, unsigned long flags) {
    int res = syscall(__NR_perf_event_open, event, pid, cpu, group_fd, flags);

    return res;
}

static void test_bpf_perf_event(int map_fd, int num) {
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
bpf_perf_event_print(struct perf_event_header *header, void *private_data) {
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

int perf_event_mmap_header(int fd, struct perf_event_mmap_page **header) {
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
                            int *done) {
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

#endif /* __UUTILS__ */
