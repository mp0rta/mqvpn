// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* Private helper for mqvpn-server-nat.sh: use the CLI's parser, without
 * exporting credentials or interpreting config values as shell code. */
#include "config.h"

#include <stdio.h>
#include <string.h>

int
main(int argc, char **argv)
{
    if (argc != 2) return 1;
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    if (mqvpn_config_load(&cfg, argv[1]) < 0) return 1;

    const char *values[] = {cfg.subnet, cfg.subnet6, cfg.tun_name};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        if (strpbrk(values[i], "\r\n")) {
            fprintf(stderr, "error: NAT config values must fit on one line\n");
            return 1;
        }
    }
    printf("%s\n%s\n%s\n", cfg.subnet, cfg.subnet6, cfg.tun_name);
    return ferror(stdout) ? 1 : 0;
}
