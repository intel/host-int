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

int load_filter(int filter_map_fd, FILE *fp)
{
    struct hostent *server;
    char buffer[MAX_NAME + 2]; // one for new line, one for null termination
    int count = 0, ret;
    size_t line_len = 0;
    bool skipping = false;
    __u16 dummy_val = ELM_UPDATED, val;
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

        server = gethostbyname(buffer);
        if (server == NULL) {
            WPRT("  Ignore unknown filter target '%s'\n", buffer);
            continue;
        }

        if (server->h_length != 4) {
            /* Only IPv4 addresses are currently supported. */
            WPRT("  Ignore unknown filter target '%s'\n", buffer);
            continue;
        }

        memcpy((char *)&ip_addr.s_addr, (char *)server->h_addr,
               server->h_length);
        ret = bpf_map_update_elem(filter_map_fd, &ip_addr.s_addr, &dummy_val,
                                  BPF_ANY);
        if (ret < 0) {
            WPRT("  Failed to insert filter target '%s' in %s map. err code: "
                 "%i\n",
                 inet_ntoa(ip_addr), SOURCE_MAP_FILTER, ret);
            continue;
        }
        VPRT("  Inserted filter target '%s' into %s map\n", inet_ntoa(ip_addr),
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
            EPRT("  No value for %s\n", inet_ntoa(ip_addr));
        } else if (val != ELM_UPDATED) {
            del = true;
            VPRT("  Removed existing filter target %s\n", inet_ntoa(ip_addr));
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
