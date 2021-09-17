/* Copyright (C) 2021 Intel Corporation */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef __INT_MD_HEADERS_H
#define __INT_MD_HEADERS_H

#include <asm/byteorder.h>

// Most of the INT headers defined here are exactly as defined in
// version 0.5 of the INT specification documents listed below, but
// there are a few that are custom in this project, because in the
// Host INT project we want to support per-flow sequence numbers,
// which are not part of the published INT specifications.  [E2E] is
// the document to read about these custom formats.

// Reference [E2E] is:

// [E2E] "INT Definition for Edge to Edge solution", file
// INT_Edge_to_Edge.md in this repository

// Reference [INT05] is:

// [INT05] "In-band Network Telemetry (INT)", v0.5, The P4.org
// Applications Working Group, 2017-Dec-11,
// https://github.com/p4lang/p4-applications/blob/master/docs/INT_v0_5.pdf

// Reference [TR05] is:

// [TR05] "Telemetry Report Format Specification", v0.5, The P4.org
// Applications Working Group, 2017-Nov-10,
// https://github.com/p4lang/p4-applications/blob/master/docs/telemetry_report_v0_5.pdf

//////////////////////////////////////////////////////////////////////
// INT data plane headers
//////////////////////////////////////////////////////////////////////

// INT shim header for TCP/UDP, 4 bytes
// See [INT05] Section 5.3.1 "Header Location and Format - INT over
// TCP/UDP"
struct int_shim_hdr {
    __u8 type;
    __u8 reserved_1;
    __u8 length;
    __u8 reserved_2;
};

// Possible values for Type field in INT shim header
// See [INT05] Section 5.4 "Examples"
#define INT_TYPE_HOP_BY_HOP 1
#define INT_TYPE_DESTINATION 2
#define INT_TYPE_NON_STANDARD_INCLUDES_SEQUENCE_NUMBER 3

// INT metadata header, 8 bytes
// See [INT05] Section 5.3.4 "INT Metadata Header format"
struct int_metadata_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 e : 1;
    __u8 c : 1;
    __u8 rep : 2;
    __u8 ver : 4;

    __u8 ins_cnt : 5;
    __u8 reserved_1 : 3;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u8 ver : 4;
    __u8 rep : 2;
    __u8 c : 1;
    __u8 e : 1;

    __u8 reserved_1 : 3;
    __u8 ins_cnt : 5;
#else
#error "Neither __LITTLE_ENDIAN_BITFIELD nor __BIG_ENDIAN_BITFIELD #define'd"
#endif
    __u8 max_hop_cnt;
    __u8 total_hop_cnt;
    __be16 ins_bitmap;
    __be16 reserved_2;
};

// Possible values for Rep field in INT metadata header
// See [INT05] Section 5.3.4 "INT Metadata Header format"
#define INT_REPLICATION_NONE 0
#define INT_REPLICATION_PORT_LEVEL 1
#define INT_REPLICATION_NEXT_HOP_LEVEL 2
#define INT_REPLICATION_PORT_AND_NEXT_HOP_LEVEL 3

// Possible values for C (Copy) field in INT metadata header
// See [INT05] Section 5.3.4 "INT Metadata Header format"
#define INT_COPY_ORIGINAL_PACKET 0
#define INT_COPY_REPLICATED_PACKET 1

// 16 bytes
struct int_metadata_entry {
    __be32 node_id;
    __be16 ingress_port;
    __be16 egress_port;
    __be32 ingress_ts;
    __be32 egress_ts;
};

// INT tail header, 4 bytes
// See [INT05] Section 5.3.1 "Header Location and Format - INT over
// TCP/UDP"
struct int_tail_hdr {
    __u8 proto;
    __u8 dest_port_hi;
    __u8 dest_port_lo;
    __u8 reserved;
};

//////////////////////////////////////////////////////////////////////
// INT report headers
//////////////////////////////////////////////////////////////////////

// See [TR05] Section 3.2.1 "Telemetry Report Fixed Header (12
// octets)"

struct int_report_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 proto : 4;
    __u8 ver : 4;

    __u8 reserved_1 : 5;
    __u8 f : 1;
    __u8 q : 1;
    __u8 d : 1;

    __u8 reserved_2_1;

    __u8 hwid : 6;
    __u8 reserved_2_2 : 2;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u8 ver : 4;
    __u8 proto : 4;

    __u8 d : 1;
    __u8 q : 1;
    __u8 f : 1;
    __u8 reserved_1 : 5;

    __u8 reserved_2_1;

    __u8 reserved_2_2 : 2;
    __u8 hwid : 6;
#else
#error "Neither __LITTLE_ENDIAN_BITFIELD nor __BIG_ENDIAN_BITFIELD #define'd"
#endif
    __u32 seq_num;
    __u32 ts;
};

// Possible values for proto field in Telemetry Report Fixed Header.
// See [TR05] Section 3.2.1 "Telemetry Report Fixed Header (12
// octets)" for the published ones.

#define INT_REPORT_PROTO_ETHERNET 0
#define INT_REPORT_PROTO_DROP_ETHERNET 1
#define INT_REPORT_PROTO_SWITCH_LOCAL_ETHERNET 2

// The following values are not defined in [TR05], but in [E2E].
#define INT_REPORT_PROTO_DROP 3
#define INT_REPORT_PROTO_LATENCY 4

// Note: int_drop_summary_data is different from the header referenced
// below by design.  See [E2E].

// [TR05] Section 3.2.2 "Telemetry Drop Report Header (12 octets)"

struct int_drop_summary_data {
    __be32 src_switch_id;
    __be32 dst_switch_id;
    __be16 src_port;
    __be16 dst_port;
    __be32 gap_timestamp;
    __be32 flow_seq_num;
    __be32 gap_count;
};

#endif /* __INT_MD_HEADERS_H */
