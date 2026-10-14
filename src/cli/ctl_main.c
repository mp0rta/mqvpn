// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* src/cli/ctl_main.c — mqvpnctl: standalone Client Management Protocol
 * (CMP) CLI. Talks NDJSON-over-AF_UNIX to a running mqvpn client's
 * management endpoint (src/mgmt/, src/platform/linux/mgmt_socket.c).
 *
 * Deliberately does not link libmqvpn/xquic/libevent — see the CMakeLists.txt
 * comment above the mqvpnctl target and
 * scripts/ci_e2e/run_client_mgmt_ipc_phase1_test.sh (T9), which verifies
 * this with ldd/nm.
 *
 * Usage: mqvpnctl [--endpoint EP] [--timeout N] [--json] <command>
 * Phase 1 commands: version
 */
#include "cmp_json.h"
#include "cmp_types.h"
#include "ctl_ipc.h"
#include "json_mini.h"

#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
usage(FILE *out, const char *argv0)
{
    fprintf(out,
            "usage: %s [--endpoint EP] [--timeout N] [--json] <command>\n"
            "commands:\n"
            "  version   show CLI and management-endpoint versions\n"
            "options:\n"
            "  --endpoint EP   management socket path (unix:// prefix optional)\n"
            "  --timeout N     override all per-request timeouts, in seconds\n"
            "  --json          machine-readable output\n"
            "  -h, --help      show this help\n",
            argv0);
}

/* --endpoint > $MQVPN_CLIENT_ENDPOINT > CMP_DEFAULT_SOCKET_PATH (if /run
 * exists) > CMP_FALLBACK_SOCKET_PATH. A "unix://" prefix, wherever the value
 * came from, is stripped. */
static const char *
resolve_endpoint(const char *cli_endpoint)
{
    static char buf[256];
    const char *ep = cli_endpoint;
    if (!ep) ep = getenv("MQVPN_CLIENT_ENDPOINT");
    if (!ep) {
        ep = (access("/run", F_OK) == 0) ? CMP_DEFAULT_SOCKET_PATH
                                         : CMP_FALLBACK_SOCKET_PATH;
    }
    if (strncmp(ep, "unix://", 7) == 0) ep += 7;
    snprintf(buf, sizeof(buf), "%s", ep);
    return buf;
}

/* Maps a ctl_err_t to mqvpnctl's process exit code. */
static int
exit_code_for(int ctl_rc)
{
    switch (ctl_rc) {
    case CTL_OK: return 0;
    case CTL_E_UNAVAILABLE: return 5;
    case CTL_E_TIMEOUT: return 8;
    case CTL_E_PROTOCOL: return 9;
    default: return 1; /* CTL_E_IO, CTL_E_REMOTE */
    }
}

static void
print_version_unavailable(int json_out, const char *reason)
{
    if (json_out) {
        printf("{\"cli_version\":\"%s\",\"endpoint\":null}\n", CTL_VERSION_STR);
    } else {
        printf("mqvpnctl %s\n", CTL_VERSION_STR);
        printf("endpoint  unavailable (%s)\n", reason);
    }
}

static void
print_version_ok(int json_out, const char *endpoint_version)
{
    if (json_out) {
        char storage[512];
        cmp_buf_t b;
        cmp_buf_init(&b, storage, sizeof(storage));
        cmp_buf_appendf(&b, "{\"cli_version\":");
        cmp_json_append_str(&b, CTL_VERSION_STR);
        cmp_buf_appendf(&b, ",\"endpoint\":{\"name\":");
        cmp_json_append_str(&b, CMP_ENDPOINT_NAME);
        cmp_buf_appendf(&b, ",\"version\":");
        cmp_json_append_str(&b, endpoint_version);
        cmp_buf_appendf(&b, ",\"protocol\":\"%s\"}}", CMP_PROTOCOL_VERSION);
        /* storage is generous (512 bytes) relative to the small fixed-shape
         * fields above plus a version string; overflow would only happen
         * for a pathological endpoint_version, in which case printing the
         * (empty, NUL-terminated) partial buffer is an acceptable
         * degradation rather than a crash. */
        printf("%s\n", storage);
    } else {
        printf("mqvpnctl %s\n", CTL_VERSION_STR);
        printf("endpoint  %s %s (protocol CMP/%s)\n", CMP_ENDPOINT_NAME, endpoint_version,
               CMP_PROTOCOL_VERSION);
    }
}

static int
cmd_version(const char *endpoint, int timeout_ms, int json_out)
{
    ctl_conn_t c;
    char err[256];

    int rc = ctl_connect(&c, endpoint, timeout_ms, err, sizeof(err));
    if (rc != CTL_OK) {
        print_version_unavailable(json_out, err);
        return exit_code_for(rc);
    }

    char resp[4096];
    rc = ctl_hello(&c, resp, sizeof(resp), err, sizeof(err));
    if (rc != CTL_OK) {
        ctl_close(&c);
        print_version_unavailable(json_out, err);
        return exit_code_for(rc);
    }

    rc = ctl_request(&c, "system.version", "{}", resp, sizeof(resp), err, sizeof(err));
    ctl_close(&c);
    if (rc != CTL_OK) {
        print_version_unavailable(json_out, err);
        return exit_code_for(rc);
    }

    char version[64] = "";
    const char *v = json_find_key(resp, "version");
    if (v) json_read_string(v, version, sizeof(version));
    if (version[0] == '\0') {
        print_version_unavailable(json_out, "malformed system.version response");
        return exit_code_for(CTL_E_PROTOCOL);
    }

    print_version_ok(json_out, version);
    return 0;
}

int
main(int argc, char **argv)
{
    /* A closing endpoint must not kill this process: writes go through
     * MSG_NOSIGNAL (ctl_ipc.c) already, but ignore SIGPIPE belt-and-braces
     * for any libc path that raises it outside send(2) (e.g. stdio to a
     * closed pipe when output is itself piped). */
    signal(SIGPIPE, SIG_IGN);

    const char *cli_endpoint = NULL;
    int timeout_ms = 0;
    int json_out = 0;
    const char *command = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--endpoint") == 0 || strcmp(argv[i], "--timeout") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing argument for %s\n", argv[i]);
                usage(stderr, argv[0]);
                return 2;
            }
            if (argv[i][2] == 'e') { /* --endpoint */
                cli_endpoint = argv[++i];
                continue;
            }
            /* --timeout: seconds on the CLI surface (spec §25); converted
             * to milliseconds internally (ctl_ipc.h works in ms). */
            char *end = NULL;
            long v = strtol(argv[++i], &end, 10);
            if (end == argv[i] || *end != '\0' || v <= 0 || v > INT_MAX / 1000) {
                fprintf(stderr, "invalid --timeout (positive integer seconds): %s\n",
                        argv[i]);
                return 2;
            }
            timeout_ms = (int)(v * 1000);
        } else if (strcmp(argv[i], "--json") == 0) {
            json_out = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(stdout, argv[0]);
            return 0;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "unrecognized option: %s\n", argv[i]);
            usage(stderr, argv[0]);
            return 2;
        } else if (!command) {
            command = argv[i];
        } else {
            fprintf(stderr, "unexpected argument: %s\n", argv[i]);
            usage(stderr, argv[0]);
            return 2;
        }
    }

    if (!command) {
        usage(stderr, argv[0]);
        return 2;
    }

    const char *endpoint = resolve_endpoint(cli_endpoint);

    if (strcmp(command, "version") == 0) {
        return cmd_version(endpoint, timeout_ms, json_out);
    }

    fprintf(stderr, "unknown command: %s\n", command);
    usage(stderr, argv[0]);
    return 2;
}
