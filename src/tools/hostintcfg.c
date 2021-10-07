/* Copyright (C) 2021 Intel Corporation */
/* SPDX-License-Identifier: BSD-3-Clause */

#include "common_defines.h"
#include "common_params.h"
#include "common_user_bpf_xdp.h"
#include "intbpf.h"
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <linux/limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>

#define MAX_NAME 128
#define ELM_UPDATED 2
#define ELM_RUN 1

static const char *__doc__ =
    "INT Edge-to-Edge Config Program that config EBPF programs. This command "
    "shall\n"
    "work with hostintd to ensure proper maintenance on shared maps.\n";

static const struct option_wrapper long_options[] = {
    {{"help", no_argument, NULL, 'h'}, "Show help", false},

    {{"Version", no_argument, NULL, 'V'}, "Print version number", false},

    {{"dev", required_argument, NULL, 'd'},
     "Operate on device <ifname>",
     "<ifname>",
     true},

    {{"prog-type", required_argument, NULL, 'T'},
     "Program type. Can be 'SINK' or 'SOURCE'",
     "",
     true},

    {{"quiet", no_argument, NULL, 'q'}, "Quiet mode (no output)"},

    {{"node-id", required_argument, NULL, 'n'}, "Node ID"},

    {{"dscp-val", required_argument, NULL, 'v'}, "DSCP Value"},

    {{"dscp-mask", required_argument, NULL, 'm'}, "DSCP Mask"},

    {{"latency-bucket", required_argument, NULL, 'B'}, "Latency Bucket"},

    {{"filter-filename", required_argument, NULL, 4},
     "Traffic classification (allow list) <file>",
     "<file>"},

    {{"idle-flow-timeout-ms", required_argument, NULL, 't'},
     "Idle flow clear timeout (ms)"},

    {{"pkg-loss-timeout-ms", required_argument, NULL, 'l'},
     "Package loss timeout (ms)"},

    {{0, 0, NULL, 0}, NULL, false}};

int bpf_map_get_next_key_and_delete(int fd, const void *key, void *next_key,
                                    bool del)
{
    int ret = bpf_map_get_next_key(fd, key, next_key);
    if (del) {
        bpf_map_delete_elem(fd, key);
    }
    return ret;
}

/* domain_name_or_ip_addr_string_to_binary_ip_address()
 *
 * Given a C string containing one of these formats (and perhaps
 * others supported by the getaddrinfo(3) library function):
 *
 *   dotted decimal IPv4 address, e.g. "10.1.2.3"
 *   IPv6 address in RFC standard foramt, e.g. "2002::abcd"
 *   A domain name, e.g. "www.google.com"
 *
 * Look up the IPv4 and/or IPv6 addresses in binary format that
 * correspond to this string using getaddrinfo(3).  There can be
 * multiple addresses found for a domain name.
 *
 * If any of the addresses found are IPv4 addresses, pick the first
 * one and return it as a network-byte-order binary 4-byte IPv4
 * address in the buffer pointed at by parameter nbo_ip_address.  Also
 * assign the value AF_INET to *family, and return 0.  The choice of
 * first one in the list returned by getaddrinfo(3) is fairly
 * arbitrary, but should be good enough for where this function is
 * used.
 *
 * If none of the addresses found are IPv4 addresses, pick the first
 * one that has an IPv6 address and return it as a network-byte-order
 * binary 16-byte IPv6 address in the buffer pointed at by
 * nbo_ip_address.  Also assign the value AF_INET6 to *family, and
 * return 0.
 *
 * If any errors occur during this process, or neither any IPv4 nor
 * any IPv6 addresses are found, return -1. */

int domain_name_or_ip_addr_string_to_binary_ip_address(char *name_or_addr_str,
                                                       int udp_dest_port,
                                                       void *nbo_ip_address,
                                                       int *family)
{
    int ret;
    char udp_dest_port_str[64];
    struct addrinfo hints;
    struct addrinfo *result, *rp, *first_ipv4_result, *first_ipv6_result;
    void *ptr;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = 0;
    hints.ai_protocol = IPPROTO_UDP;

    snprintf(udp_dest_port_str, sizeof(udp_dest_port_str), "%d", udp_dest_port);
    ret = getaddrinfo(name_or_addr_str, udp_dest_port_str, &hints, &result);
    if (ret != 0) {
        EPRT("getaddrinfo: %s\n", gai_strerror(ret));
        ret = -1;
        goto out;
    }
    /* debug_print_getaddrinfo_results(result); */
    first_ipv4_result = NULL;
    first_ipv6_result = NULL;
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET) {
            first_ipv4_result = rp;
            ptr = &((struct sockaddr_in *)rp->ai_addr)->sin_addr;
            /* We prefer IPv4 addresses if one exists, so stop
             * scanning through the list if we find any IPv4
             * address. */
            break;
        } else if (rp->ai_family == AF_INET6) {
            if (first_ipv6_result == NULL) {
                first_ipv6_result = rp;
                ptr = &((struct sockaddr_in6 *)rp->ai_addr)->sin6_addr;
            }
        }
    }
    if (first_ipv4_result != NULL) {
        *family = AF_INET;
        memcpy(nbo_ip_address, ptr, 4);
        ret = 0;
    } else if (first_ipv6_result != NULL) {
        *family = AF_INET6;
        memcpy(nbo_ip_address, ptr, 16);
        ret = 0;
    } else {
        ret = -1;
    }

out:
    if (result != NULL) {
        freeaddrinfo(result);
    }
    return ret;
}

int load_filter(int filter_map_fd, FILE *fp)
{
    char buffer[MAX_NAME + 2]; // one for new line, one for null termination
    int count = 0, ret;
    size_t line_len = 0;
    bool skipping = false;
    __u16 dummy_val = ELM_UPDATED, val;
    int family;
    char nbo_ip_address[16]; // enough to hold binary IPv4 or IPv6 address
    struct in_addr ip_addr = {0};

    while (NULL != fgets(buffer, sizeof(buffer), fp) &&
           count < DEST_FILTER_MAP_MAX_ENTRIES) {
        line_len = strlen(buffer);
        if (line_len == 0)
            continue;
        // ignore long line
        if (buffer[line_len - 1] != '\n') {
            skipping = true;
            continue;
        }
        if (skipping) {
            skipping = false;
            continue;
        }
        if (buffer[0] == '#' || buffer[0] == '\n') {
            continue; // ignore comments or empty lines
        }
        // remove '\n'. The last line may have no new line, so we need to check
        // it
        if (buffer[line_len - 1] == '\n') {
            buffer[line_len - 1] = '\0';
        }

        /* getaddrinfo(3) needs a port number.  For dotted decimal
         * IPv4 addresses in the filter file, I believe the numeric
         * value of this port number should never affect the behavior.
         * It might affect the behavior for DNS domain names in the
         * filter file, depending upon how DNS servers are
         * configured. */
        ret = domain_name_or_ip_addr_string_to_binary_ip_address(
            buffer, 0, nbo_ip_address, &family);
        if (ret == -1) {
            WPRT("  Ignore unknown filter target '%s'\n", buffer);
            continue;
        }
        if (family != AF_INET) {
            /* Only IPv4 addresses are currently supported. */
            WPRT("  Ignore unknown filter target '%s'\n", buffer);
            continue;
        }
        memcpy((char *)&ip_addr.s_addr, nbo_ip_address, 4);
        inet_ntop(AF_INET, nbo_ip_address, buffer, sizeof(buffer));
        ret = bpf_map_update_elem(filter_map_fd, &ip_addr.s_addr, &dummy_val,
                                  BPF_ANY);
        if (ret < 0) {
            WPRT("  Failed to insert filter target '%s' in %s map. err code: "
                 "%i\n",
                 buffer, SOURCE_MAP_FILTER, ret);
            continue;
        }
        VPRT("  Inserted filter target '%s' into %s map\n", buffer,
             SOURCE_MAP_FILTER);
        count++;
    }

    __u32 key = -1, next_key;
    bool del = false;
    while (bpf_map_get_next_key_and_delete(filter_map_fd, &key, &next_key,
                                           del) == 0) {
        ip_addr.s_addr = next_key;
        ret = bpf_map_lookup_elem(filter_map_fd, &next_key, &val);
        if (ret < 0) {
            // shouldn't happen
            inet_ntop(AF_INET, &next_key, buffer, sizeof(buffer));
            EPRT("  No value for %s\n", buffer);
        } else if (val != ELM_UPDATED) {
            del = true;
            inet_ntop(AF_INET, &next_key, buffer, sizeof(buffer));
            VPRT("  Removed existing filter target %s\n", buffer);
        } else {
            del = false;
            val = ELM_RUN;
            bpf_map_update_elem(filter_map_fd, &next_key, &val, BPF_EXIST);
        }
        key = next_key;
    }

    if (count) {
        VPRT("%i entries were added in allow list\n", count);
    } else {
        VPRT("ZERO entries in allow list, no packets will have INT headers "
             "added.\n");
    }

    return EXIT_OK;
}

int main(int argc, char **argv)
{
    int ret;
    struct config cfg = {
        .ifindex = -1,
        .prog_type = -1,
        .node_id = -1,
        .dscp_val = -1,
        .dscp_mask = -1,
        .idle_flow_timeout_ms = -1,
        .pkt_loss_timeout_ms = -1,
        .num_latency_entries = 0,
    };

    parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

    if (cfg.ifindex == -1) {
        EPRT("Required option --dev missing\n");
        usage(argv[0], __doc__, long_options, (argc == 1));
        return EXIT_FAIL_OPTION;
    }

    if (cfg.prog_type == -1) {
        EPRT("Required option --prog-type missing\n");
        usage(argv[0], __doc__, long_options, (argc == 1));
        return EXIT_FAIL_OPTION;
    }

    if (cfg.prog_type != PT_SINK && cfg.prog_type != PT_SOURCE) {
        EPRT("Unknown program type: %i\n", cfg.prog_type);
        usage(argv[0], __doc__, long_options, (argc == 1));
        return EXIT_FAIL_OPTION;
    }

    if (cfg.dscp_val == -1 && cfg.dscp_mask != -1) {
        EPRT("dscp value is not specified\n");
        usage(argv[0], __doc__, long_options, (argc == 1));
        return EXIT_FAIL_OPTION;
    }

    if (cfg.dscp_val != -1 && cfg.dscp_mask == -1) {
        EPRT("dscp mask is not specified\n");
        usage(argv[0], __doc__, long_options, (argc == 1));
        return EXIT_FAIL_OPTION;
    }

    if (cfg.num_latency_entries > 0 && cfg.prog_type == PT_SOURCE) {
        cfg.num_latency_entries = 0;
        WPRT("Program type is SOURCE. Ignore latency bucket value.\n");
    }

    if (cfg.filter_filename[0] && cfg.prog_type == PT_SINK) {
        WPRT("Program type is SINK. Ignore filter file '%s'.\n",
             cfg.filter_filename);
        cfg.filter_filename[0] = 0;
    }

    if (cfg.idle_flow_timeout_ms != -1 && cfg.prog_type == PT_SOURCE) {
        cfg.idle_flow_timeout_ms = -1;
        WPRT("Program type is SOURCE. Ignore idle flow timeout.\n");
    }

    if (cfg.pkt_loss_timeout_ms != -1 && cfg.prog_type == PT_SOURCE) {
        cfg.pkt_loss_timeout_ms = -1;
        WPRT("Program type is SOURCE. Ignore packet loss timeout.\n");
    }

    char *map_name;
    if (cfg.prog_type == PT_SINK) {
        map_name = SINK_MAP_CONFIG;
        ret = snprintf(cfg.pin_dir, sizeof(cfg.pin_dir), "%s/%s", PIN_BASE_DIR,
                       cfg.ifname);
    } else {
        map_name = SOURCE_MAP_CONFIG;
        ret = snprintf(cfg.pin_dir, sizeof(cfg.pin_dir), "%s",
                       TC_PIN_GLOBAL_BASE);
    }
    if (ret < 0) {
        EPRT("Failed to create pin dirname. err code: %i\n", ret);
        return EXIT_FAIL_OPTION;
    }

    struct bpf_map_info info = {0};
    int config_map_fd = open_bpf_map_file(cfg.pin_dir, map_name, &info);
    if (config_map_fd < 0) {
        EPRT("Failed to open %s. Please ensure the EBPF program was loaded.\n",
             map_name);
        return EXIT_FAIL_BPF;
    }
    VPRT("Opened %s/%s with id=%i\n", cfg.pin_dir, map_name, info.id);

    if (cfg.node_id != -1) {
        // enum ConfigKey node_id_key = NODE_ID;
        __u16 node_id_key = CONFIG_MAP_KEY_NODE_ID;
        ret = bpf_map_update_elem(config_map_fd, &node_id_key, &cfg.node_id,
                                  BPF_ANY);
        if (ret < 0) {
            EPRT("Failed to insert node_id in %s map. err code: %i\n", map_name,
                 ret);
            return EXIT_FAIL_BPF;
        }
        VPRT("Set node_id in %s to %i\n", map_name, cfg.node_id);
    }

    if (cfg.dscp_val != -1 && cfg.dscp_mask != -1) {
        __u16 dscp_val_key = CONFIG_MAP_KEY_DSCP_VAL;
        ret = bpf_map_update_elem(config_map_fd, &dscp_val_key, &cfg.dscp_val,
                                  BPF_ANY);
        if (ret < 0) {
            EPRT("Failed to insert dscp_val in %s map. err code: %i\n",
                 map_name, ret);
            return EXIT_FAIL_BPF;
        }
        VPRT("Set dscp_val in %s to 0x%02x\n", map_name, cfg.dscp_val);

        __u16 dscp_mask_key = CONFIG_MAP_KEY_DSCP_MASK;
        ret = bpf_map_update_elem(config_map_fd, &dscp_mask_key, &cfg.dscp_mask,
                                  BPF_ANY);
        if (ret < 0) {
            EPRT("Failed to insert dscp_mask in %s map. err code: %i\n",
                 map_name, ret);
            return EXIT_FAIL_BPF;
        }
        VPRT("Set dscp_mask in %s to 0x%02x\n", map_name, cfg.dscp_mask);
    }

    if (cfg.filter_filename[0]) {
        int filter_map_fd =
            open_bpf_map_file(cfg.pin_dir, SOURCE_MAP_FILTER, &info);
        if (filter_map_fd < 0) {
            EPRT("Failed to open %s. Please ensure the EBPF program was "
                 "loaded.\n",
                 SOURCE_MAP_FILTER);
            return EXIT_FAIL_BPF;
        }
        VPRT("Opened %s/%s with id=%i\n", cfg.pin_dir, SOURCE_MAP_FILTER,
             info.id);

        FILE *fp = fopen(cfg.filter_filename, "r");
        if (fp == NULL) {
            EPRT("Failed to open filter file '%s': %s.\n", cfg.filter_filename,
                 strerror(errno));
            return EXIT_FAIL_OPTION;
        }
        VPRT("Loading filter file '%s' into %s...\n", cfg.filter_filename,
             SOURCE_MAP_FILTER);
        ret = load_filter(filter_map_fd, fp);
        fclose(fp);
        if (ret < 0) {
            EPRT("Failed to load filter file' %s' into %s map. err code: %i\n",
                 cfg.filter_filename, SOURCE_MAP_FILTER, ret);
            return EXIT_FAIL_BPF;
        }
        VPRT("Successfully loaded in filter file '%s'\n", cfg.filter_filename);
    }

    if (cfg.idle_flow_timeout_ms != -1) {
        __u16 idel_to_key = CONFIG_MAP_KEY_IDLE_TO;
        ret = bpf_map_update_elem(config_map_fd, &idel_to_key,
                                  &cfg.idle_flow_timeout_ms, BPF_ANY);
        if (ret < 0) {
            EPRT("Failed to insert idle flow timeout in sink config map. err "
                 "code: "
                 "%i\n",
                 ret);
            return EXIT_FAIL_BPF;
        }
        VPRT("Set idle flow timeout in %s to %i ms\n", map_name,
             cfg.idle_flow_timeout_ms);
    }

    if (cfg.pkt_loss_timeout_ms != -1) {
        __u16 pkt_loss_key = CONFIG_MAP_KEY_PKTLOSS_TO;
        ret = bpf_map_update_elem(config_map_fd, &pkt_loss_key,
                                  &cfg.pkt_loss_timeout_ms, BPF_ANY);
        if (ret < 0) {
            EPRT("Failed to insert packet loss timeout in sink config map. err "
                 "code: "
                 "%i\n",
                 ret);
            return EXIT_FAIL_BPF;
        }
        VPRT("Set packet loss timeout in %s to %i ms\n", map_name,
             cfg.pkt_loss_timeout_ms);
    }
    return EXIT_OK;
}
