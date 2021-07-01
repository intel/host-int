/* Copyright (C) 2021 Intel Corporation */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef __COMMON_REPORT_H
#define __COMMON_REPORT_H

#include "common_defines.h"
#include "intmd_headers.h"

int send_latency_report(char *server_name, __u32 server_addr, int server_port,
                        __u16 pkt_len, __u8 *pkt_data, int report_seq_num,
                        struct timespec *ts);

void print_latency_report(FILE *out, struct int_metadata_entry *source_data,
                          struct int_metadata_entry *sink_data,
                          int report_seq_num, struct timespec *ts);

int send_drop_report(char *server_name, __u32 server_addr, int server_port,
                     __u16 pkt_len, __u8 *pkt_data, int report_seq_num,
                     struct timespec *ts);

void print_drop_report(FILE *out, struct int_drop_summary_data *data,
                       int report_seq_num, struct timespec *ts);

#endif /* __COMMON_REPORT_H */