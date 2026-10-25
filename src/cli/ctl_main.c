// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#include "ctl_cmd.h"

#include "cmp_endpoint.h"
#include "ctl_sock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
usage(FILE *f)
{
    fprintf(f, "Usage: mqvpnctl [--endpoint EP] [--timeout SEC] [--json] <command>\n"
               "\n"
               "Commands:\n"
               "  version    show the mqvpnctl and client endpoint versions\n"
               "\n"
               "Options:\n"
               "  --endpoint EP   management socket (default: $MQVPN_CLIENT_ENDPOINT or "
               "the OS default)\n"
               "  --timeout SEC   overall wait per step, 1-3600 seconds\n"
               "  --json          machine-readable output\n"
               "  -h, --help      show this help\n");
}

static int
parse_timeout(const char *s)
{
    char *end;
    long v = strtol(s, &end, 10);
    return (*s && !*end && v >= 1 && v <= 3600) ? (int)v : -1;
}

int
main(int argc, char **argv)
{
    ctl_opts_t o = {0};
    const char *cmd = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage(stdout);
            return 0;
        } else if (strcmp(a, "--json") == 0) {
            o.json = 1;
        } else if (strcmp(a, "--endpoint") == 0 || strcmp(a, "--timeout") == 0) {
            if (i + 1 >= argc) {
                usage(stderr);
                return 2;
            }
            const char *v = argv[++i];
            if (a[2] == 'e') {
                o.endpoint = v;
            } else if ((o.timeout_ms_override = parse_timeout(v)) < 0) {
                usage(stderr);
                return 2;
            } else {
                o.timeout_ms_override *= 1000;
            }
        } else if (a[0] == '-' || cmd) {
            usage(stderr);
            return 2;
        } else {
            cmd = a;
        }
    }
    if (!cmd || strcmp(cmd, "version") != 0) {
        usage(stderr);
        return 2;
    }

    char ep[CMP_ENDPOINT_MAX];
    if (!o.endpoint) o.endpoint = getenv("MQVPN_CLIENT_ENDPOINT");
    if (cmp_endpoint_resolve(o.endpoint, ep, sizeof(ep)) != 0) {
        fprintf(stderr, "mqvpnctl: endpoint path too long\n");
        return 2;
    }
    if (strlen(ep) > ctl_sock_max_path()) {
        fprintf(stderr, "mqvpnctl: endpoint path too long for AF_UNIX\n");
        return 2;
    }
    o.endpoint = ep;
    return ctl_cmd_version(&o);
}
