/* Copyright (C) 2021 Intel Corporation */
/* SPDX-License-Identifier: BSD-3-Clause */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <errno.h>
#include <ctype.h>
#include <net/if.h>
#include <linux/if_link.h> /* XDP_FLAGS_* depend on kernel-headers installed */
#include <linux/if_xdp.h>

#include "common_params.h"

int verbose = 1;

#define BUFSIZE 54 // 80-26=54

void _print_options(const struct option_wrapper *long_options, bool required) {
    int i, pos, len;
    char buf[BUFSIZE];

    for (i = 0; long_options[i].option.name != 0; i++) {
        if (long_options[i].required != required)
            continue;

        if (long_options[i].option.val > 64) /* ord('A') = 65 */
            printf(" -%c,", long_options[i].option.val);
        else
            printf("    ");
        pos = snprintf(buf, BUFSIZE, " --%s", long_options[i].option.name);
        if (long_options[i].metavar)
            snprintf(&buf[pos], BUFSIZE - pos, " %s", long_options[i].metavar);
        printf("%-22s", buf);
        if (strlen(buf) > 22) {
            printf("\n%-26s", " ");
        }
        // TODO: Improve to wrap by word
        pos = 0;
        while (true) {
            len = snprintf(buf, BUFSIZE, "%s", long_options[i].help + pos);
            printf("  %s", buf);
            printf("\n");
            if (len < BUFSIZE) {
                break;
            }
            pos += BUFSIZE - 1;
            printf("%-26s", " ");
        }
    }
}

void usage(const char *prog_name, const char *doc,
           const struct option_wrapper *long_options, bool full) {
    printf("Usage: %s [options]\n", prog_name);

    if (!full) {
        printf("Use --help (or -h) to see full option list.\n");
        return;
    }

    printf("\nDESCRIPTION:\n %s\n", doc);
    printf("Required options:\n");
    _print_options(long_options, true);
    printf("\n");
    printf("Other options:\n");
    _print_options(long_options, false);
    printf("\n");
}

int option_wrappers_to_options(const struct option_wrapper *wrapper,
                               struct option **options) {
    int i, num;
    struct option *new_options;
    for (i = 0; wrapper[i].option.name != 0; i++) {
    }
    num = i;

    new_options = malloc(sizeof(struct option) * num);
    if (!new_options)
        return -1;
    for (i = 0; i < num; i++) {
        memcpy(&new_options[i], &wrapper[i], sizeof(struct option));
    }

    *options = new_options;
    return 0;
}

void copy_trimmed_string(char *dst, char *src, size_t dst_len) {
    // trim leading spaces
    while (isspace(*src))
        src++;
    // trim trailing spaces
    char *end = src + strlen(src) - 1;
    while (end > src && isspace(*end))
        end--;
    end++;

    size_t copy_len = end - src;
    if (copy_len > dst_len) {
        copy_len = dst_len;
    }
    strncpy(dst, src, copy_len);
    dst[copy_len] = 0;
}

int get_int(char *str) {
    if (strlen(str) > 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        return (int)strtol(str, NULL, 16);
    } else {
        return atoi(str);
    }
}

void parse_cmdline_args(int argc, char **argv,
                        const struct option_wrapper *options_wrapper,
                        struct config *cfg, const char *doc) {
    struct option *long_options;
    bool full_help = false;
    int longindex = 0;
    char *dest;
    int opt;

    if (option_wrappers_to_options(options_wrapper, &long_options)) {
        fprintf(stderr, "Unable to malloc()\n");
        exit(EXIT_FAIL_OPTION);
    }

    /* Parse commands line args */
    while ((opt = getopt_long(argc, argv,
                              "hd:r:ASNFUMQ:czpqf:n:v:m:t:l:s:i:C:P:o:b:T:",
                              long_options, &longindex)) != -1) {
        switch (opt) {
        case 'd':
            if (strlen(optarg) >= IF_NAMESIZE) {
                fprintf(stderr, "ERR: --dev name too long\n");
                goto error;
            }
            cfg->ifname = (char *)&cfg->ifname_buf;
            copy_trimmed_string(cfg->ifname, optarg, IF_NAMESIZE);
            cfg->ifindex = if_nametoindex(cfg->ifname);
            if (cfg->ifindex == 0) {
                fprintf(stderr, "ERR: --dev name unknown err(%d):%s\n", errno,
                        strerror(errno));
                goto error;
            }
            break;
        case 'r':
            if (strlen(optarg) >= IF_NAMESIZE) {
                fprintf(stderr, "ERR: --redirect-dev name too long\n");
                goto error;
            }
            cfg->redirect_ifname = (char *)&cfg->redirect_ifname_buf;
            copy_trimmed_string(cfg->redirect_ifname, optarg, IF_NAMESIZE);
            cfg->redirect_ifindex = if_nametoindex(cfg->redirect_ifname);
            if (cfg->redirect_ifindex == 0) {
                fprintf(stderr, "ERR: --redirect-dev name unknown err(%d):%s\n",
                        errno, strerror(errno));
                goto error;
            }
            break;
        case 'A':
            cfg->xdp_flags &= ~XDP_FLAGS_MODES; /* Clear flags */
            break;
        case 'S':
            cfg->xdp_flags &= ~XDP_FLAGS_MODES;   /* Clear flags */
            cfg->xdp_flags |= XDP_FLAGS_SKB_MODE; /* Set   flag */
            cfg->xsk_bind_flags &= XDP_ZEROCOPY;
            cfg->xsk_bind_flags |= XDP_COPY;
            break;
        case 'N':
            cfg->xdp_flags &= ~XDP_FLAGS_MODES;   /* Clear flags */
            cfg->xdp_flags |= XDP_FLAGS_DRV_MODE; /* Set   flag */
            break;
        case 3:                                  /* --offload-mode */
            cfg->xdp_flags &= ~XDP_FLAGS_MODES;  /* Clear flags */
            cfg->xdp_flags |= XDP_FLAGS_HW_MODE; /* Set   flag */
            break;
        case 'F':
            cfg->xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
            break;
        case 'M':
            cfg->reuse_maps = true;
            break;
        case 'U':
            cfg->do_unload = true;
            break;
        case 'p':
            cfg->xsk_poll_mode = true;
            break;
        case 'q':
            verbose = false;
            break;
        case 'Q':
            cfg->xsk_if_queue = atoi(optarg);
            break;
        case 1: /* --filename */
            dest = (char *)&cfg->filename;
            copy_trimmed_string(dest, optarg, sizeof(cfg->filename));
            break;
        case 2: /* --progsec */
            dest = (char *)&cfg->progsec;
            copy_trimmed_string(dest, optarg, sizeof(cfg->progsec));
            break;
        case 'c':
            cfg->xsk_bind_flags &= XDP_ZEROCOPY;
            cfg->xsk_bind_flags |= XDP_COPY;
            break;
        case 'z':
            cfg->xsk_bind_flags &= XDP_COPY;
            cfg->xsk_bind_flags |= XDP_ZEROCOPY;
            break;
        case 4: /* --filter-filename */
            dest = (char *)&cfg->filter_filename;
            copy_trimmed_string(dest, optarg, sizeof(cfg->filter_filename));
            break;
        case 'n':
            cfg->node_id = get_int(optarg);
            break;
        case 'v':
            cfg->dscp_val = get_int(optarg);
            break;
        case 'm':
            cfg->dscp_mask = get_int(optarg);
            break;
        case 's':
            cfg->domain_specific_id = get_int(optarg);
            break;
        case 'i':
            cfg->ins_bitmap = get_int(optarg);
            break;
        case 't':
            cfg->idle_flow_timeout_ms = atoi(optarg);
            break;
        case 'l':
            cfg->pkt_loss_timeout_ms = atoi(optarg);
            break;
        case 'C': /* --server_hostname */
            dest = (char *)&cfg->server_hostname;
            copy_trimmed_string(dest, optarg, sizeof(cfg->server_hostname));
            break;
        case 'P': /* --server_port */
            cfg->server_port = atoi(optarg);
            break;
        case 'o': /* --report_output */
            dest = (char *)&cfg->report_file;
            copy_trimmed_string(dest, optarg, sizeof(cfg->report_file));
            break;
        case 5:
            cfg->sender_collector_port = get_int(optarg);
            break;
        case 6:
            cfg->port = get_int(optarg);
            break;
        case 'b':
            dest = (char *)&cfg->bind_addr;
            copy_trimmed_string(dest, optarg, sizeof(cfg->bind_addr));
            break;
        case 'T':
            if (strcasecmp(optarg, "SINK") == 0) {
                cfg->prog_type = PT_SINK;
            } else if (strcasecmp(optarg, "SOURCE") == 0) {
                cfg->prog_type = PT_SOURCE;
            }
            break;
        case 'h':
            full_help = true;
            /* fall-through */
        error:
        default:
            usage(argv[0], doc, options_wrapper, full_help);
            free(long_options);
            exit(EXIT_FAIL_OPTION);
        }
    }
    free(long_options);
}
