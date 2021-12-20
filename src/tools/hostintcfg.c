/* Copyright (C) 2021 Intel Corporation */
/* SPDX-License-Identifier: BSD-3-Clause */

#include "common_defines.h"
#include "common_params.h"
#include "common_report.h"
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
#define SOURCE_MAP 1
#define SINK_MAP 2

#define DESCRIPTION_SIZE 32

struct config_map_entry_info_t {
    char description[DESCRIPTION_SIZE];
    int right_shift_value;
    bool show;
    __u64 default_value;
};

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

    {{"show-statistics", no_argument, NULL, 'H'},
     "Show EBPF program statistics"},

    {{"show-filter-entries", no_argument, NULL, 'G'}, "Show Filter entries"},

    {{"show-config-map", no_argument, NULL, 'I'}, "Show config map"},

    {{"copy-node-id", no_argument, NULL, 'J'}, "Copy node id"},

    {{"show-latency-bucket", no_argument, NULL, 'L'}, "Show latency bucket"},

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
    result = NULL;
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
            WPRT("  Ignore unknown filter target '%s'\n", buffer);
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

char *get_stats_desc(__u32 stats_offset)
{
    switch (stats_offset) {
    case STATS_OTHER:
        return "Other";
    case STATS_NOT_IPV4:
        return "Non-IPv4 packets";
    case STATS_IPV4_NO_INT_HEADER:
        return "IPv4 packets with no INT header added";
    case STATS_IPV4_NEITHER_TCP_NOR_UDP:
        return "IPv4 packets that are neither TCP nor UDP";
    case STATS_IPV4_TCP_TOO_LONG_TO_ADD_INT_HEADER:
        return "IPv4/TCP packets too long to add INT header";
    case STATS_IPV4_UDP_TOO_LONG_TO_ADD_INT_HEADER:
        return "IPv4/UDP packets too long to add INT header";
    case STATS_IPV4_NEITHER_TCP_NOR_UDP_TOO_LONG_TO_ADD_INT_HEADER:
        return "IPv4/other packets too long to add INT header";
    case STATS_IPV4_TCP_NON_FIRST_FRAGMENT:
        return "IPv4/TCP non-first fragment";
    case STATS_IPV4_UDP_NON_FIRST_FRAGMENT:
        return "IPv4/UDP non-first fragment";
    case STATS_IPV4_NEITHER_TCP_NOR_UDP_NON_FIRST_FRAGMENT:
        return "IPv4/other non-first fragment";
    case STATS_FLOW_STATS_MAP_FAILED_TO_ADD_ENTRY:
        return "Failed to add entry to per-flow statistics EBPF map";
    case STATS_IPV4_TCP_INT_HEADER_ADDED:
        return "IPv4/TCP added INT header";
    case STATS_IPV4_UDP_INT_HEADER_ADDED:
        return "IPv4/UDP added INT header";
    default:
        return "unknown";
    }
}

int show_statistics_helper(char *pin_dir, char *map_name)
{
    int ret;
    struct bpf_map_info info = {0};
    int source_stats_map_fd = open_bpf_map_file(pin_dir, map_name, &info);
    if (source_stats_map_fd < 0) {
        EPRT("Failed to open %s. Please ensure the EBPF program was loaded.\n",
             map_name);
        return EXIT_FAIL_BPF;
    }
    VPRT("Opened %s/%s with id=%i\n", pin_dir, map_name, info.id);

    printf("Offs packet cnt byte cnt   Description\n");
    printf("---- ---------- ---------- ----------------------------\n");
    struct packet_byte_counter stats_data;
    for (__u32 stats_offset = 0; stats_offset <= STATS_OFFSET_MAX;
         stats_offset++) {
        ret = bpf_map_lookup_elem(source_stats_map_fd, &stats_offset,
                                  &stats_data);
        if (ret < 0) {
            EPRT("Failed to get stats from map '%s' at key %d\n", map_name,
                 stats_offset);
            return EXIT_FAIL_BPF;
        } else {
            char *stats_desc = get_stats_desc(stats_offset);
            printf("%4d %10llu %10llu %s\n", stats_offset, stats_data.pkt_count,
                   stats_data.byte_count, stats_desc);
        }
    }
    return EXIT_OK;
}

void ebpf_map_directory(char *pin_dir, unsigned int pin_dir_buf_size,
                        int prog_type, char *ifname)
{
    if (prog_type == PT_SINK) {
        snprintf(pin_dir, pin_dir_buf_size, "%s/%s", PIN_BASE_DIR, ifname);
    } else {
        snprintf(pin_dir, pin_dir_buf_size, "%s", TC_PIN_GLOBAL_BASE);
    }
}

int show_filter_helper(char *pin_dir, char *map_name)
{
    struct bpf_map_info info = {0};
    char daddr_buf[IPV4_ADDR_DOTTED_DECIMAL_BUF_SIZE];

    int filter_map_fd = open_bpf_map_file(pin_dir, map_name, &info);
    if (filter_map_fd < 0) {
        EPRT("Failed to open %s. Please ensure the EBPF program was loaded.\n",
             map_name);
        return EXIT_FAIL_BPF;
    }
    VPRT("Opened %s/%s with id=%i\n", pin_dir, map_name, info.id);

    __u32 key = -1, next_key;
    while (bpf_map_get_next_key(filter_map_fd, &key, &next_key) == 0) {
        sprintf_ipv4_addr_dotted_decimal(daddr_buf, next_key);
        printf("%s\n", daddr_buf);
        key = next_key;
    }
    return EXIT_OK;
}

int show_latency_bucket_helper(char *pin_dir, char *map_name)
{
    struct bpf_map_info info = {0};
    struct latency_bucket_entries lat_bucket;
    __u16 key;
    int ret;

    int lat_bkt_map_fd = open_bpf_map_file(pin_dir, map_name, &info);
    if (lat_bkt_map_fd < 0) {
        EPRT("Failed to open %s. Please ensure the EBPF program was loaded.\n",
             map_name);
        return EXIT_FAIL_BPF;
    }
    VPRT("Opened %s/%s with id=%i\n", pin_dir, map_name, info.id);

    key = LATENCY_MAP_KEY_LATENCY_BUCKET;
    ret = bpf_map_lookup_elem(lat_bkt_map_fd, &key, &lat_bucket);
    if (ret < 0) {
        EPRT("Failed to get latency bucket entries from map '%s' at key %d\n",
             map_name, key);
        return EXIT_FAIL_BPF;
    } else {
        for (int i = 0; i < LATENCYBUCKET_MAP_MAX_ENTRIES; i++) {
            if (lat_bucket.entries[i] == U64_MAX_VALUE) {
                break;
            } else {
                printf("%llu\n", lat_bucket.entries[i]);
            }
        }
    }
    return EXIT_OK;
}

void get_config_map_entry_info(struct config_map_entry_info_t *out_info,
                               int map_type, __u16 key)
{
    out_info->show = true;
    out_info->right_shift_value = 0;

    switch (key) {
    case CONFIG_MAP_KEY_NODE_ID:
        snprintf(out_info->description, DESCRIPTION_SIZE, "Node id");
        if (map_type == SOURCE_MAP) {
            out_info->default_value = DEFAULT_SOURCE_NODE_ID;
        } else {
            out_info->default_value = DEFAULT_SINK_NODE_ID;
        }
        return;
    case CONFIG_MAP_KEY_DSCP_VAL:
        snprintf(out_info->description, DESCRIPTION_SIZE, "DSCP value");
        out_info->default_value = DEFAULT_INT_DSCP_VAL;
        out_info->right_shift_value = 2;
        return;
    case CONFIG_MAP_KEY_DSCP_MASK:
        snprintf(out_info->description, DESCRIPTION_SIZE, "DSCP mask");
        out_info->default_value = DEFAULT_INT_DSCP_MASK;
        out_info->right_shift_value = 2;
        return;
    case CONFIG_MAP_KEY_DOMAIN_ID:
        snprintf(out_info->description, DESCRIPTION_SIZE, "Domain id");
        out_info->show = false;
        return;
    case CONFIG_MAP_KEY_INS_BITMAP:
        snprintf(out_info->description, DESCRIPTION_SIZE, "Instruction bitmap");
        out_info->show = false;
        return;
    case CONFIG_MAP_KEY_IDLE_TO:
        snprintf(out_info->description, DESCRIPTION_SIZE,
                 "Idle flow timeout in ms");
        if (map_type == SOURCE_MAP) {
            out_info->show = false;
        } else {
            out_info->default_value = DEFAULT_IDLE_FLOW_TIMEOUT_MS;
        }
        return;
    case CONFIG_MAP_KEY_PKTLOSS_TO:
        snprintf(out_info->description, DESCRIPTION_SIZE,
                 "Packet loss timeout in ms");
        if (map_type == SOURCE_MAP) {
            out_info->show = false;
        } else {
            out_info->default_value = PKT_LOSS_TIMEOUT_MS;
        }
        return;
    case CONFIG_MAP_KEY_TIME_OFFSET:
        snprintf(out_info->description, DESCRIPTION_SIZE, "Time offset in ns");
        out_info->default_value = 0;
        return;
    case CONFIG_MAP_KEY_INT_UDP_ENCAP_DEST_PORT:
        snprintf(out_info->description, DESCRIPTION_SIZE,
                 "UDP encap dest port");
        out_info->default_value = DEFAULT_INT_UDP_DEST_PORT;
        return;
    case CONFIG_MAP_KEY_LATENCY_REPORT_PERIOD_NSEC:
        snprintf(out_info->description, DESCRIPTION_SIZE,
                 "Latency report period in ns");
        if (map_type == SOURCE_MAP) {
            out_info->show = false;
        } else {
            out_info->default_value = DEFAULT_LATENCY_REPORT_PERIOD_NSEC;
        }
        return;
    case CONFIG_MAP_KEY_DROP_PACKET:
        snprintf(out_info->description, DESCRIPTION_SIZE, "Drop packet");
        if (map_type == SOURCE_MAP) {
            out_info->show = false;
        } else {
            out_info->default_value = 0;
        }
        return;
    case CONFIG_MAP_KEY_STATS_BASE_ADDRESS:
        snprintf(out_info->description, DESCRIPTION_SIZE,
                 "Statistics base address");
        out_info->show = false;
        return;
    default:
        snprintf(out_info->description, DESCRIPTION_SIZE, "Unknown key");
        out_info->show = false;
        return;
    }
}

int show_config_map_helper(char *pin_dir, char *map_name)
{
    struct bpf_map_info info = {0};
    struct config_map_entry_info_t ei;
    int max_length = 32;
    int map_type;
    __u64 val;
    int ret;

    if (strncmp(map_name, SOURCE_MAP_CONFIG, max_length) == 0) {
        map_type = SOURCE_MAP;
    } else {
        map_type = SINK_MAP;
    }

    int config_map_fd = open_bpf_map_file(pin_dir, map_name, &info);
    if (config_map_fd < 0) {
        EPRT("Failed to open %s. Please ensure the EBPF program was loaded.\n",
             map_name);
        return EXIT_FAIL_BPF;
    }
    VPRT("Opened %s/%s with id=%i\n", pin_dir, map_name, info.id);
    for (__u16 key = CONFIG_MAP_KEY_MIN; key <= CONFIG_MAP_KEY_MAX; key++) {
        get_config_map_entry_info(&ei, map_type, key);
        if (ei.show) {
            ret = bpf_map_lookup_elem(config_map_fd, &key, &val);
            if (ret < 0) {
                printf("%s default value: %llu\n", ei.description,
                       ei.default_value);
            } else {
                printf("%s: %llu\n", ei.description,
                       val >> ei.right_shift_value);
            }
        }
    }
    return EXIT_OK;
}

int show_config_map(struct config *cfg)
{
    char pin_dir[512];
    int ret;

    printf("\n");
    printf("Sink EBPF program config map:\n");
    ebpf_map_directory(pin_dir, sizeof(pin_dir), PT_SINK, cfg->ifname);
    ret = show_config_map_helper(pin_dir, SINK_MAP_CONFIG);
    if (ret != EXIT_OK) {
        EPRT("Function show_config_map_helper failed for %s. err code %i\n",
             SINK_MAP_CONFIG, ret);
        return ret;
    }
    printf("\n");
    printf("Source EBPF program config map:\n");
    ebpf_map_directory(pin_dir, sizeof(pin_dir), PT_SOURCE, cfg->ifname);
    ret = show_config_map_helper(pin_dir, SOURCE_MAP_CONFIG);
    if (ret != EXIT_OK) {
        EPRT("Function show_config_map_helper failed for %s. err code %i\n",
             SOURCE_MAP_CONFIG, ret);
        return ret;
    }
    printf("\n");
    return EXIT_OK;
}

int show_filter_entries(struct config *cfg)
{
    char pin_dir[512];
    int ret;

    ebpf_map_directory(pin_dir, sizeof(pin_dir), PT_SOURCE, cfg->ifname);
    ret = show_filter_helper(pin_dir, SOURCE_MAP_FILTER);
    if (ret != EXIT_OK) {
        EPRT("Function show_filter_helper failed. err code %i\n", ret);
        return ret;
    }
    return EXIT_OK;
}

int show_statistics(struct config *cfg)
{
    char pin_dir[512];
    int ret;

    printf("Sink EBPF program statistics:\n");
    ebpf_map_directory(pin_dir, sizeof(pin_dir), PT_SINK, cfg->ifname);
    ret = show_statistics_helper(pin_dir, SINK_MAP_STATS);
    if (ret != EXIT_OK) {
        EPRT("Function show_statistics_helper failed. err "
             "code: %i\n",
             ret);
        return ret;
    }
    printf("Source EBPF program statistics:\n");
    ebpf_map_directory(pin_dir, sizeof(pin_dir), PT_SOURCE, cfg->ifname);
    ret = show_statistics_helper(pin_dir, SOURCE_MAP_STATS);
    if (ret != EXIT_OK) {
        EPRT("Function show_statistics_helper failed. err "
             "code: %i\n",
             ret);
        return ret;
    }
    return EXIT_OK;
}

int copy_sink_node_id_to_src_node_id(char *pin_dir, char *map_name)
{
    struct bpf_map_info info = {0};
    int source_config_map_fd = -1;
    __u64 sink_node_id;
    __u16 key;
    int ret;

    int sink_config_map_fd = open_bpf_map_file(pin_dir, map_name, &info);
    if (sink_config_map_fd < 0) {
        EPRT("Failed to open %s. Please ensure the sink EBPF program was "
             "loaded.\n",
             map_name);
        return EXIT_FAIL_BPF;
    }
    VPRT("Opened %s/%s with id=%i\n", pin_dir, map_name, info.id);

    key = CONFIG_MAP_KEY_NODE_ID;
    ret = bpf_map_lookup_elem(sink_config_map_fd, &key, &sink_node_id);
    if (ret < 0) {
        EPRT("Failed to get sink node id from map '%s' at key %d\n", map_name,
             key);
        return EXIT_FAIL_BPF;
    }

    source_config_map_fd =
        silent_open_bpf_map_file(TC_PIN_GLOBAL_BASE, SOURCE_MAP_CONFIG, &info);
    if (source_config_map_fd < 0) {
        EPRT("Failed to open %s. Please ensure the source EBPF program was "
             "loaded.\n",
             SOURCE_MAP_CONFIG);
        return EXIT_FAIL_BPF;
    }
    ret =
        bpf_map_update_elem(source_config_map_fd, &key, &sink_node_id, BPF_ANY);
    if (ret < 0) {
        EPRT("Failed to update source node id (%lu) in %s err code: "
             "%i\n",
             sink_node_id, SOURCE_MAP_CONFIG, ret);
        return EXIT_FAIL_BPF;
    }
    VPRT("Updated source node id in %s to %lu ns\n", SOURCE_MAP_CONFIG,
         sink_node_id);
    return EXIT_OK;
}

int copy_node_id(struct config *cfg)
{
    char pin_dir[512];
    int ret;

    ebpf_map_directory(pin_dir, sizeof(pin_dir), PT_SINK, cfg->ifname);
    ret = copy_sink_node_id_to_src_node_id(pin_dir, SINK_MAP_CONFIG);
    if (ret != EXIT_OK) {
        EPRT("Function copy_sink_node_id_to_src_node_id failed. err "
             "code: %i\n",
             ret);
        return ret;
    }
    return EXIT_OK;
}

int show_latency_bucket(struct config *cfg)
{
    char pin_dir[512];
    int ret;

    ebpf_map_directory(pin_dir, sizeof(pin_dir), PT_SINK, cfg->ifname);
    ret = show_latency_bucket_helper(pin_dir, SINK_MAP_LATENCY);
    if (ret != EXIT_OK) {
        EPRT("Function show_latency_bucket_helper failed. err "
             "code: %i\n",
             ret);
        return ret;
    }
    return EXIT_OK;
}

int main(int argc, char **argv)
{
    int ret;
    struct config cfg = {
        .ifindex = -1,
        .prog_type = -1,
        .test_node_id = false,
        .test_dscp_val = false,
        .test_dscp_mask = false,
        .idle_flow_timeout_ms = -1,
        .pkt_loss_timeout_ms = -1,
        .num_latency_entries = 0,
        .show_statistics = false,
        .show_filter_entries = false,
        .show_config_map = false,
        .show_latency_bucket = false,
        .copy_node_id = false,
    };

    if (init_printf_lock() != 0) {
        fprintf(stderr, "Mutex init failed.\n");
        return EXIT_FAIL;
    }

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

    if (!cfg.test_dscp_val && cfg.test_dscp_mask) {
        EPRT("dscp value is not specified\n");
        usage(argv[0], __doc__, long_options, (argc == 1));
        return EXIT_FAIL_OPTION;
    }

    if (cfg.test_dscp_val && !cfg.test_dscp_mask) {
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

    __u64 val;
    if (cfg.test_node_id) {
        __u16 node_id_key = CONFIG_MAP_KEY_NODE_ID;
        val = (__u64)cfg.node_id;
        ret = bpf_map_update_elem(config_map_fd, &node_id_key, &val, BPF_ANY);
        if (ret < 0) {
            EPRT("Failed to insert node_id in %s map. err code: %i\n", map_name,
                 ret);
            return EXIT_FAIL_BPF;
        }
        VPRT("Set node_id in %s to %i\n", map_name, cfg.node_id);
    }

    if (cfg.test_dscp_val && cfg.test_dscp_mask) {
        __u16 dscp_val_key = CONFIG_MAP_KEY_DSCP_VAL;
        val = (__u64)cfg.dscp_val << 2;
        ret = bpf_map_update_elem(config_map_fd, &dscp_val_key, &val, BPF_ANY);
        if (ret < 0) {
            EPRT("Failed to insert dscp_val in %s map. err code: %i\n",
                 map_name, ret);
            return EXIT_FAIL_BPF;
        }
        VPRT("Set dscp_val in %s to 0x%02x\n", map_name, cfg.dscp_val);

        __u16 dscp_mask_key = CONFIG_MAP_KEY_DSCP_MASK;
        val = (__u64)cfg.dscp_mask << 2;
        ret = bpf_map_update_elem(config_map_fd, &dscp_mask_key, &val, BPF_ANY);
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
        val = (__u64)cfg.idle_flow_timeout_ms;
        ret = bpf_map_update_elem(config_map_fd, &idel_to_key, &val, BPF_ANY);
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
        val = (__u64)cfg.pkt_loss_timeout_ms;
        ret = bpf_map_update_elem(config_map_fd, &pkt_loss_key, &val, BPF_ANY);
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

    if (cfg.show_statistics) {
        ret = show_statistics(&cfg);
        if (ret != EXIT_OK) {
            EPRT("Failed to show statistics \n");
            return ret;
        }
        VPRT("Showing statistics\n");
    }

    if (cfg.show_filter_entries) {
        ret = show_filter_entries(&cfg);
        if (ret != EXIT_OK) {
            EPRT("Failed to show filter map entries\n");
            return ret;
        }
        VPRT("Showing filter map entries\n");
    }

    if (cfg.show_config_map) {
        ret = show_config_map(&cfg);
        if (ret != EXIT_OK) {
            EPRT("Failed to show config map entries\n");
            return ret;
        }
        VPRT("Showing config map entries\n");
    }

    if (cfg.show_latency_bucket) {
        ret = show_latency_bucket(&cfg);
        if (ret != EXIT_OK) {
            EPRT("Failed to show latency bucket values\n");
            return ret;
        }
        VPRT("Showing latency bucket values\n");
    }

    if (cfg.copy_node_id) {
        ret = copy_node_id(&cfg);
        if (ret != EXIT_OK) {
            EPRT("Failed to copy sink node id to source node id \n");
            return ret;
        }
        VPRT("Sink node id copied to source node id\n");
    }

    return EXIT_OK;
}
