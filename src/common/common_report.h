/* Copyright (C) 2021 Intel Corporation */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef __COMMON_REPORT_H
#define __COMMON_REPORT_H

#include "common_defines.h"
#include "intmd_headers.h"
#include "intbpf.h"

void printf_with_lock(const char *format, ...);
void prt_with_lock(char *str, const char *format, ...);

/* Defined in common_report.o */
extern int verbose;

#define IPV4_ADDR_DOTTED_DECIMAL_BUF_SIZE 16
#define EPRT(format, args...) prt_with_lock("Error - ", format, ##args)
#define WPRT(format, args...) prt_with_lock("Warning - ", format, ##args)

#define VPRT(format, args...)                                                  \
    if (verbose) {                                                             \
        printf_with_lock(format, ##args);                                      \
    }

void set_sig_handler(int signum, void (*sa_handler)());

int send_latency_report(char *server_name, __u32 server_addr, __u16 server_port,
                        __u16 pkt_len, __u8 *pkt_data, int report_seq_num,
                        struct timespec *ts);

void print_latency_report(FILE *out, struct int_metadata_entry *source_data,
                          struct int_metadata_entry *sink_data,
                          int report_seq_num, struct timespec *ts,
                          struct flow_key *key);

int send_drop_report(char *server_name, __u32 server_addr, int server_port,
                     __u16 pkt_len, __u8 *pkt_data, int report_seq_num,
                     struct timespec *ts);

void print_drop_report(FILE *out, struct int_drop_summary_data *data,
                       int report_seq_num, struct timespec *ts,
                       struct flow_key *key);

void sprintf_ipv4_addr_dotted_decimal(char *buf,
                                      __u32 ipv4_addr_network_byte_order);

int init_send_packet_lock();
int init_printf_lock();
#endif /* __COMMON_REPORT_H */
