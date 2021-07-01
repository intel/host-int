/* Copyright (C) 2021 Intel Corporation */
/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef __INT_MX_HEADERS_H
#define __INT_MX_HEADERS_H

// Most of the INT headers defined here are exactly as defined in
// version 2.1 and 2.0 of the INT specification documents listed
// below, but there are a few that are custom in this project.
// [INT21Addendum] is the document to read about these custom formats.

// Reference [INT21Addendum] is:

// [INT21Addendum] file INT_2.1_MX.md in this repository

// Reference [INT21] is:

// [INT21] "In-band Network Telemetry (INT) Dataplane Specification",
// v2.1, The P4.org Applications Working Group, 2020-Nov-11,
// https://github.com/p4lang/p4-applications/blob/master/docs/INT_v2_1.pdf

// Reference [TR20] is:

// [TR20] "Telemetry Report Format Specification", v2.0, The P4.org
// Applications Working Group, 2020-Oct-08,
// https://github.com/p4lang/p4-applications/blob/master/docs/telemetry_report_v2_0.pdf

//////////////////////////////////////////////////////////////////////
// INT data plane headers
//////////////////////////////////////////////////////////////////////

// INT shim header for TCP/UDP, 4 bytes
// See [INT21] Section 5.7.2 "INT over TCP/UDP"
struct int_mx_shim_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 reserved_1 : 2;
    __u8 npt : 2;
    __u8 type : 4;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u8 type : 4;
    __u8 npt : 2;
    __u8 reserved_1 : 2;
#else
#error "Neither __LITTLE_ENDIAN_BITFIELD nor __BIG_ENDIAN_BITFIELD #define'd"
#endif
    __u8 length;
    __u8 reserved_2;
    __u8 ip_proto;
};

// INT-MD metadata header, 12 bytes
// See [INT21] Section 5.8 "INT-MD Metadata Header format"

struct int_mx_md_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u16 reserved_1 : 11;
    __u16 d : 1;
    __u16 ver : 4;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u16 ver : 4;
    __u16 d : 1;
    __u16 reserved_1 : 11;
#else
#error "Neither __LITTLE_ENDIAN_BITFIELD nor __BIG_ENDIAN_BITFIELD #define'd"
#endif
    __u16 reserved_2;
    __be16 ins_bitmap;
    __be16 domain_id;
    __be16 ds_ins;
    __be16 ds_flags;
};

// Note: int_mx_ds_src_md is not defined in [INT21].  See
// [INT21Addendum]

struct int_mx_ds_src_md { // 20 bytes
    __be32 node_id;
    __be16 port;
    __be16 reserved;
    __be64 timestamp;
    __be32 seq_num;
};

//////////////////////////////////////////////////////////////////////
// INT report headers
//////////////////////////////////////////////////////////////////////

// See [TR20] Section 3.2 "Telemetry Report Group Header (Ver 2.0) (8
// octets)"

struct report_group_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u32 seq_num : 22;
    __u32 hw_id : 6;
    __u32 ver : 4;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u32 ver : 4;
    __u32 hw_id : 6;
    __u32 seq_num : 22;
#else
#error "Neither __LITTLE_ENDIAN_BITFIELD nor __BIG_ENDIAN_BITFIELD #define'd"
#endif
    __u32 node_id;
};

// See [TR20] Section 3.3 "Individual Report Header (Ver 2.0) (4+
// octets)"

struct report_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 inner_type : 4;
    __u8 report_type : 4;

    __u8 report_length;
    __u8 md_length;

    __u8 reserved : 4;
    __u8 i : 1;
    __u8 f : 1;
    __u8 q : 1;
    __u8 d : 1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u8 report_type : 4;
    __u8 inner_type : 4;

    __u8 report_length;
    __u8 md_length;

    __u8 d : 1;
    __u8 q : 1;
    __u8 f : 1;
    __u8 i : 1;
    __u8 reserved : 4;
#else
#error "Neither __LITTLE_ENDIAN_BITFIELD nor __BIG_ENDIAN_BITFIELD #define'd"
#endif
};

// See [TR20] Section 3.3.1 "Individual Report Main Contents for
// RepType 1 (INT) (8+ octets)"

struct int_indv_rep_main_cont_hdr { // 8 bytes
    __u16 report_md_bits;
    __u16 domain_id;
    __u16 ds_md_bits;
    __u16 ds_md_status;
};

struct drop_summary_ds_md { // 24 bytes
    __be32 src_node_id;
    __be16 src_port;
    __be16 sink_port;
    __be64 gap_timestamp;
    __be32 gap_seq_num;
    __be32 gap_count;
};

#endif /* __INT_MX_HEADERS_H */
