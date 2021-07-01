/* Copyright (C) 2021 Intel Corporation */
/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * This file contains functions that are used in the packetXX XDP programs to
 * manipulate on packets data. The functions are marked as __always_inline, and
 * fully defined in this header file to be included in the BPF program.
 */

#ifndef __REWRITE_HELPERS_H
#define __REWRITE_HELPERS_H

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Pops the outermost VLAN tag off the packet. Returns the popped VLAN ID on
 * success or negative errno on failure.
 */
static __always_inline int vlan_tag_pop(struct xdp_md *ctx,
                                        struct ethhdr *eth) {
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr eth_cpy;
    struct vlan_hdr *vlh;
    __be16 h_proto;
    int vlid;

    if (!proto_is_vlan(eth->h_proto))
        return -1;

    /* Careful with the parenthesis here */
    vlh = (void *)(eth + 1);

    /* Still need to do bounds checking */
    if (vlh + 1 > data_end)
        return -1;

    /* Save vlan ID for returning, h_proto for updating Ethernet header */
    vlid = bpf_ntohs(vlh->h_vlan_TCI);
    h_proto = vlh->h_vlan_encapsulated_proto;

    /* Make a copy of the outer Ethernet header before we cut it off */
    __builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

    /* Actually adjust the head pointer */
    if (bpf_xdp_adjust_head(ctx, (int)sizeof(*vlh)))
        return -1;

    /* Need to re-evaluate data *and* data_end and do new bounds checking
     * after adjusting head
     */
    eth = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    if (eth + 1 > data_end)
        return -1;

    /* Copy back the old Ethernet header and update the proto type */
    __builtin_memcpy(eth, &eth_cpy, sizeof(*eth));
    eth->h_proto = h_proto;

    return vlid;
}

/* Pushes a new VLAN tag after the Ethernet header. Returns 0 on success,
 * -1 on failure.
 */
static __always_inline int vlan_tag_push(struct xdp_md *ctx, struct ethhdr *eth,
                                         int vlid) {
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr eth_cpy;
    struct vlan_hdr *vlh;

    /* First copy the original Ethernet header */
    __builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

    /* Then add space in front of the packet */
    if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(*vlh)))
        return -1;

    /* Need to re-evaluate data_end and data after head adjustment, and
     * bounds check, even though we know there is enough space (as we
     * increased it).
     */
    data_end = (void *)(long)ctx->data_end;
    eth = (void *)(long)ctx->data;

    if (eth + 1 > data_end)
        return -1;

    /* Copy back Ethernet header in the right place, populate VLAN tag with
     * ID and proto, and set outer Ethernet header to VLAN type.
     */
    __builtin_memcpy(eth, &eth_cpy, sizeof(*eth));

    vlh = (void *)(eth + 1);

    if (vlh + 1 > data_end)
        return -1;

    vlh->h_vlan_TCI = bpf_htons(vlid);
    vlh->h_vlan_encapsulated_proto = eth->h_proto;

    eth->h_proto = bpf_htons(ETH_P_8021Q);
    return 0;
}

static __always_inline int
variable_length_csum_diff(__u8 *start, __u16 len, __u8 *data_end, __u32 *csum) {
    __be32 tmp;
    /* This is what we would ideally like to write, but it is not
     * easy to see how to make it pass the kernel verifier. */
    /*
    if (start + len > data_end) {
        return -1;
    }
    *csum = bpf_csum_diff(0, 0, start, len, *csum);
    */

    /* This passes the verifier and should be functionally equivalent.
     * It is only intended to work for len up to 2047. */

    __u8 *data_ptr = start;
    if (len >= 1024) {
        if (data_ptr + 1024 > data_end) {
            bpf_printk("variable_length_csum_diff has data_end-data_ptr=%d"
                       " < 1024\n",
                       data_end - data_ptr);
            return -1;
        }
        *csum = bpf_csum_diff(0, 0, (__be32 *)data_ptr, 1024, *csum);
        len -= 1024;
        data_ptr += 1024;
    }
    if (len >= 512) {
        if (data_ptr + 512 > data_end) {
            bpf_printk("variable_length_csum_diff has data_end-data_ptr=%d"
                       " < 512\n",
                       data_end - data_ptr);
            return -1;
        }
        *csum = bpf_csum_diff(0, 0, (__be32 *)data_ptr, 512, *csum);
        len -= 512;
        data_ptr += 512;
    }
    if (len >= 256) {
        if (data_ptr + 256 > data_end) {
            bpf_printk("variable_length_csum_diff has data_end-data_ptr=%d"
                       " < 256\n",
                       data_end - data_ptr);
            return -1;
        }
        *csum = bpf_csum_diff(0, 0, (__be32 *)data_ptr, 256, *csum);
        len -= 256;
        data_ptr += 256;
    }
    if (len >= 128) {
        if (data_ptr + 128 > data_end) {
            bpf_printk("variable_length_csum_diff has data_end-data_ptr=%d"
                       " < 128\n",
                       data_end - data_ptr);
            return -1;
        }
        *csum = bpf_csum_diff(0, 0, (__be32 *)data_ptr, 128, *csum);
        len -= 128;
        data_ptr += 128;
    }
    if (len >= 64) {
        if (data_ptr + 64 > data_end) {
            bpf_printk("variable_length_csum_diff has data_end-data_ptr=%d"
                       " < 64\n",
                       data_end - data_ptr);
            return -1;
        }
        *csum = bpf_csum_diff(0, 0, (__be32 *)data_ptr, 64, *csum);
        len -= 64;
        data_ptr += 64;
    }
    if (len >= 32) {
        if (data_ptr + 32 > data_end) {
            bpf_printk("variable_length_csum_diff has data_end-data_ptr=%d"
                       " < 32\n",
                       data_end - data_ptr);
            return -1;
        }
        *csum = bpf_csum_diff(0, 0, (__be32 *)data_ptr, 32, *csum);
        len -= 32;
        data_ptr += 32;
    }
    if (len >= 16) {
        if (data_ptr + 16 > data_end) {
            bpf_printk("variable_length_csum_diff has data_end-data_ptr=%d"
                       " < 16\n",
                       data_end - data_ptr);
            return -1;
        }
        *csum = bpf_csum_diff(0, 0, (__be32 *)data_ptr, 16, *csum);
        len -= 16;
        data_ptr += 16;
    }
    if (len >= 8) {
        if (data_ptr + 8 > data_end) {
            bpf_printk("variable_length_csum_diff has data_end-data_ptr=%d"
                       " < 8\n",
                       data_end - data_ptr);
            return -1;
        }
        *csum = bpf_csum_diff(0, 0, (__be32 *)data_ptr, 8, *csum);
        len -= 8;
        data_ptr += 8;
    }
    if (len >= 4) {
        if (data_ptr + 4 > data_end) {
            bpf_printk("variable_length_csum_diff has data_end-data_ptr=%d"
                       " < 4\n",
                       data_end - data_ptr);
            return -1;
        }
        *csum = bpf_csum_diff(0, 0, (__be32 *)data_ptr, 4, *csum);
        len -= 4;
        data_ptr += 4;
    }

    // Do any odd bytes left over at the end.  We must pass multiple
    // of 4 length in bytes to bpf_csum_diff().
    if (len > 0) {
        __u8 *buf = (__u8 *)&tmp;
        buf[0] = 0;
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 0;
        if (len >= 2) {
            if (data_ptr + 2 > data_end) {
                bpf_printk("variable_length_csum_diff has data_end-data_ptr=%d"
                           " < 2 when len=%d\n",
                           data_end - data_ptr, len);
                return -1;
            }
            *buf = *data_ptr;
            ++buf;
            ++data_ptr;
            *buf = *data_ptr;
            ++buf;
            ++data_ptr;
            len -= 2;
        }
        if (len >= 1) {
            if (data_ptr + 1 > data_end) {
                bpf_printk("variable_length_csum_diff has data_end-data_ptr=%d"
                           " < 1 when len=%d\n",
                           data_end - data_ptr, len);
                return -1;
            }
            *buf = *data_ptr;
        }
        *csum = bpf_csum_diff(0, 0, &tmp, 4, *csum);
    }
    return 0;
}

#define PROCESS_CSUM_DIFF_CHUNK(skb, csum, offset, temp_data_buf,              \
                                remaining_len, ret, chunk_size_bytes,          \
                                err_msg_case_id)                               \
    ret = bpf_skb_load_bytes(skb, offset, temp_data_buf, chunk_size_bytes);    \
    if (ret < 0) {                                                             \
        bpf_printk(                                                            \
            "Failed (%d) to bpf_skb_load_bytes with offset=%d case=%d\n", ret, \
            offset, err_msg_case_id);                                          \
        return ret;                                                            \
    }                                                                          \
    csum =                                                                     \
        bpf_csum_diff(0, 0, (__be32 *)temp_data_buf, chunk_size_bytes, csum);  \
    remaining_len -= chunk_size_bytes;                                         \
    offset += chunk_size_bytes

static __always_inline int skb_variable_length_csum_diff(struct __sk_buff *skb,
                                                         __u8 *start, __u16 len,
                                                         __u32 *csum) {
    int ret;
    __u8 buf[128];
    /* This is what we would ideally like to write, but it is not
     * easy to see how to make it pass the kernel verifier. */
    /*
    if (start + len > data_end) {
        return -1;
    }
    *csum = bpf_csum_diff(0, 0, start, len, *csum);
    */

    /* This passes the verifier and should be functionally equivalent.
     * It is only intended to work for len up to 2047. */

    __u32 offset = start - (__u8 *)((long)skb->data);
    if (len >= 1024) {
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 1024);
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 1024);
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 1024);
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 1024);
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 1024);
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 1024);
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 1024);
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 1024);
    }
    if (len >= 512) {
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 512);
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 512);
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 512);
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 512);
    }
    if (len >= 256) {
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 256);
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 256);
    }
    if (len >= 128) {
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 128);
    }
    if (len >= 64) {
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 64, 64);
    }
    if (len >= 32) {
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 32, 32);
    }
    if (len >= 16) {
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 16, 16);
    }
    if (len >= 8) {
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 8, 8);
    }
    if (len >= 4) {
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 4, 4);
    }

    // Do any odd bytes left over at the end.  We must pass multiple
    // of 4 length in bytes to bpf_csum_diff().

    // TODO: Test this with all packet lengths 4*n, 4*n+1, 4*n+2,
    // 4*n+3 to see if it works correctly.
    if (len > 0) {
        buf[0] = 0;
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 0;
        if (len >= 2) {
            ret = bpf_skb_load_bytes(skb, offset, buf, 2);
            if (ret < 0) {
                bpf_printk(
                    "Failed (%d) to bpf_skb_load_bytes with offset=%d #2\n",
                    ret, offset);
                return ret;
            }
            len -= 2;
            offset += 2;
        }
        if (len >= 1) {
            ret = bpf_skb_load_bytes(skb, offset, buf, 1);
            if (ret < 0) {
                bpf_printk(
                    "Failed (%d) to bpf_skb_load_bytes with offset=%d #1\n",
                    ret, offset);
                return ret;
            }
            len -= 1;
            offset += 1;
        }
        *csum = bpf_csum_diff(0, 0, (__be32 *)buf, 4, *csum);
    }
    return 0;
}

static __always_inline __u16 csum_fold_helper(__u32 csum) {
    csum = ((csum & 0xffff) + (csum >> 16));
    return ~((csum & 0xffff) + (csum >> 16));
}

/* Note: ipv4_csum currently only works correctly for IPv4 headers
 * with no options. */

static __always_inline void ipv4_csum(struct iphdr *iph) {
    __u32 csum;

    iph->check = 0;
    csum = bpf_csum_diff(0, 0, (__be32 *)iph, sizeof(struct iphdr), 0);
    iph->check = csum_fold_helper(csum);
}

#endif /* __REWRITE_HELPERS_H */
