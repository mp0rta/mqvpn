// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * status.c — mqvpn --status: query control API and display server status
 */
#include "status.h"
#include "json_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <inttypes.h>

/* Read buffer for one control-API reply. It starts small and doubles up to
 * STATUS_BUF_MAX: the server caps a reply at CTRL_MAX_RESP_BYTES (256 KiB,
 * src/platform/linux/control_socket.h), and get_status reaches ~210 KB with
 * MQVPN_MAX_USERS clients on MQVPN_MAX_PATHS paths each. */
#define STATUS_BUF_INITIAL 32768
#define STATUS_BUF_MAX     (1024 * 1024)

/* ── Human-readable formatting ── */

static void
format_bytes(uint64_t bytes, char *buf, size_t len)
{
    if (bytes >= 1073741824ULL)
        snprintf(buf, len, "%.1f GiB", (double)bytes / 1073741824.0);
    else if (bytes >= 1048576ULL)
        snprintf(buf, len, "%.1f MiB", (double)bytes / 1048576.0);
    else if (bytes >= 1024ULL)
        snprintf(buf, len, "%.1f KiB", (double)bytes / 1024.0);
    else
        snprintf(buf, len, "%" PRIu64 " B", bytes);
}

static void
format_duration(uint64_t seconds, char *buf, size_t len)
{
    if (seconds >= 86400)
        snprintf(buf, len, "%" PRIu64 "d %" PRIu64 "h ago", seconds / 86400,
                 (seconds % 86400) / 3600);
    else if (seconds >= 3600)
        snprintf(buf, len, "%" PRIu64 "h %" PRIu64 "m ago", seconds / 3600,
                 (seconds % 3600) / 60);
    else if (seconds >= 60)
        snprintf(buf, len, "%" PRIu64 "m %" PRIu64 "s ago", seconds / 60, seconds % 60);
    else
        snprintf(buf, len, "%" PRIu64 "s ago", seconds);
}

static void
format_size(uint64_t bytes, char *buf, size_t len)
{
    if (bytes >= 1048576ULL)
        snprintf(buf, len, "%" PRIu64 "M", bytes / 1048576);
    else if (bytes >= 1024ULL)
        snprintf(buf, len, "%" PRIu64 "K", bytes / 1024);
    else
        snprintf(buf, len, "%" PRIu64, bytes);
}

/* The value of `key` if it is a JSON unsigned integer, else 0. */
static uint64_t
jget_u64(yyjson_val *obj, const char *key)
{
    uint64_t v = 0;
    json_get_u64(yyjson_obj_get(obj, key), &v);
    return v;
}

/* ── Print one client ── */

static void
print_client(yyjson_val *client)
{
    char user[64] = {0}, endpoint[64] = {0};

    json_copy_str(yyjson_obj_get(client, "user"), user, sizeof(user));
    json_copy_str(yyjson_obj_get(client, "endpoint"), endpoint, sizeof(endpoint));

    uint64_t conn_sec = jget_u64(client, "connected_sec");
    uint64_t bytes_tx = jget_u64(client, "bytes_tx");
    uint64_t bytes_rx = jget_u64(client, "bytes_rx");

    char dur[32], tx[32], rx[32];
    format_duration(conn_sec, dur, sizeof(dur));
    format_bytes(bytes_rx, rx, sizeof(rx));
    format_bytes(bytes_tx, tx, sizeof(tx));

    printf("\nclient: %s\n", user[0] ? user : "(unknown)");
    printf("  endpoint: %s\n", endpoint[0] ? endpoint : "(unknown)");
    printf("  connected: %s\n", dur);
    printf("  transfer: %s received, %s sent\n", rx, tx);

    /* Print paths; idx counts the path objects shown, not array slots. */
    yyjson_arr_iter it = yyjson_arr_iter_with(yyjson_obj_get(client, "paths"));
    yyjson_val *path;
    int idx = 0;

    while ((path = yyjson_arr_iter_next(&it)) != NULL) {
        if (!yyjson_is_obj(path)) continue;

        int64_t srtt = (int64_t)jget_u64(path, "srtt_ms");
        int64_t min_rtt = (int64_t)jget_u64(path, "min_rtt_ms");
        uint64_t cwnd = jget_u64(path, "cwnd");

        char cwnd_str[16];
        format_size(cwnd, cwnd_str, sizeof(cwnd_str));

        /* The server names the state in "state_label" (control_socket.c,
         * mqvpn_path_state_label); the numeric "state" is a raw xquic
         * path_state whose values are not part of the control-API
         * contract, so never map it here. */
        char state_str[24] = "unknown";
        json_copy_str(yyjson_obj_get(path, "state_label"), state_str, sizeof(state_str));

        printf("  path %d: srtt=%" PRId64 "ms min_rtt=%" PRId64 "ms cwnd=%s %s\n", idx,
               srtt, min_rtt, cwnd_str, state_str);
        idx++;
    }
}

/* ── Control-API query (one command per connection) ── */

/* Connect to the control API, send `cmd` (write → shutdown(SHUT_WR)), read
 * the response to EOF. Returns a malloc'd NUL-terminated buffer (caller
 * frees) or NULL on error (message already printed to stderr). */
static char *
ctrl_query(const char *addr, int port, const char *cmd)
{
    int fd = -1;
    char *buf = NULL;
    struct addrinfo *res = NULL;

    /* Resolve address (supports both IPv4 and IPv6) */
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int gai = getaddrinfo(addr, port_str, &hints, &res);
    if (gai != 0 || !res) {
        fprintf(stderr, "error: cannot resolve '%s': %s\n", addr, gai_strerror(gai));
        goto fail;
    }

    fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        fprintf(stderr, "error: socket: %s\n", strerror(errno));
        goto fail;
    }

    /* Set timeouts to avoid hanging on unresponsive server */
    struct timeval tv = {.tv_sec = 5};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        fprintf(stderr, "error: connect to %s:%d: %s\n", addr, port, strerror(errno));
        goto fail;
    }
    freeaddrinfo(res);
    res = NULL;

    /* Send command (handle EINTR and partial writes) */
    size_t cmd_len = strlen(cmd);
    size_t sent = 0;
    while (sent < cmd_len) {
        ssize_t n = write(fd, cmd + sent, cmd_len - sent);
        if (n < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "error: write: %s\n", strerror(errno));
            goto fail;
        }
        sent += (size_t)n;
    }

    shutdown(fd, SHUT_WR);

    /* Read the response to EOF (handle EINTR), growing the buffer as needed:
     * a reply cut at a fixed size would be parsed as a shorter, valid-looking
     * client list. */
    size_t cap = STATUS_BUF_INITIAL;
    buf = malloc(cap);
    if (!buf) goto fail;
    size_t total = 0;
    for (;;) {
        if (total == cap - 1) {
            if (cap >= STATUS_BUF_MAX) {
                fprintf(stderr, "error: response larger than %d bytes\n", STATUS_BUF_MAX);
                goto fail;
            }
            char *nb = realloc(buf, cap * 2);
            if (!nb) goto fail;
            buf = nb;
            cap *= 2;
        }
        ssize_t n = read(fd, buf + total, cap - 1 - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                fprintf(stderr, "error: read timed out\n");
                goto fail;
            }
            break;
        }
        if (n == 0) break;
        total += (size_t)n;
    }
    buf[total] = '\0';
    close(fd);
    return buf;

fail:
    if (res) freeaddrinfo(res);
    if (fd >= 0) close(fd);
    free(buf);
    return NULL;
}

/* ── Print the get_stats lane/flow summary line ── */

static void
print_stats_summary(yyjson_val *root)
{
    if (!yyjson_is_true(yyjson_obj_get(root, "ok"))) return; /* older server / error */
    /* Only print when the server reports the hybrid lane counters. */
    if (!yyjson_obj_get(root, "pkts_lane_tcp")) return;

    uint64_t lane_tcp = jget_u64(root, "pkts_lane_tcp");
    uint64_t lane_dgram = jget_u64(root, "pkts_lane_dgram");
    uint64_t lane_raw = jget_u64(root, "pkts_lane_raw");
    uint64_t fl_act = jget_u64(root, "tcp_flows_active");
    uint64_t fl_tot = jget_u64(root, "tcp_flows_total");
    uint64_t fl_rej = jget_u64(root, "tcp_flows_rejected");
    uint64_t lane_tcp_drop = jget_u64(root, "pkts_lane_tcp_dropped");
    uint64_t raw_markers = jget_u64(root, "raw_markers_active");

    printf("server: lanes tcp/dgram/raw=%" PRIu64 "/%" PRIu64 "/%" PRIu64
           " (tcp_dropped=%" PRIu64 ") flows act/tot/rej=%" PRIu64 "/%" PRIu64 "/%" PRIu64
           " raw_markers=%" PRIu64 "\n",
           lane_tcp, lane_dgram, lane_raw, lane_tcp_drop, fl_act, fl_tot, fl_rej,
           raw_markers);
}

/* ── Print the outer-UDP offload summary line ── */

/* Separate line and separately gated: this answers a different question from
 * the lane summary above, and a server can report either without the other
 * (that one needs hybrid mode; these counters are unconditional on a server
 * new enough to have them). Printed as a ratio because that is the form which
 * answers the operator's actual question — whether the offload is batching —
 * and which the startup "udp-gso:"/"udp-gro:" markers cannot, since those
 * only report the kernel capability probe. x1.00 means every datagram cost
 * its own syscall. */
static void
print_offload_summary(yyjson_val *root)
{
    if (!yyjson_is_true(yyjson_obj_get(root, "ok"))) return; /* older server / error */
    if (!yyjson_obj_get(root, "udp_tx_sends")) return;       /* pre-offload server */

    uint64_t tx_s = jget_u64(root, "udp_tx_sends");
    uint64_t tx_d = jget_u64(root, "udp_tx_datagrams");
    uint64_t rx_r = jget_u64(root, "udp_rx_receives");
    uint64_t rx_d = jget_u64(root, "udp_rx_datagrams");

    printf("server: udp tx=%" PRIu64 "/%" PRIu64 " (x%.2f) rx=%" PRIu64 "/%" PRIu64
           " (x%.2f)\n",
           tx_d, tx_s, tx_s ? (double)tx_d / (double)tx_s : 0.0, rx_d, rx_r,
           rx_r ? (double)rx_d / (double)rx_r : 0.0);
}

/* The server passes the bytes of a user name through unchecked, and a name
 * cut at 63 bytes can end mid UTF-8 sequence: accept it as the old reader did
 * rather than failing the whole reply. */
static yyjson_doc *
status_parse(char *buf)
{
    return yyjson_read_opts(buf, strlen(buf), YYJSON_READ_ALLOW_INVALID_UNICODE, NULL,
                            NULL);
}

/* ── Main entry point ── */

int
run_status(const char *addr, int port)
{
    if (!addr) addr = "127.0.0.1";

    int rc = 1;

    /* Control API handles one command per connection: get_stats first (lane
     * summary), then get_status (per-client listing). */
    char *stats_buf = ctrl_query(addr, port, "{\"cmd\":\"get_stats\"}\n");
    if (!stats_buf) return 1; /* server unreachable — error already printed */
    /* Unparsable or failed get_stats: no summary lines, carry on (older server). */
    yyjson_doc *doc = status_parse(stats_buf);
    print_stats_summary(yyjson_doc_get_root(doc));
    print_offload_summary(yyjson_doc_get_root(doc));
    yyjson_doc_free(doc);
    free(stats_buf);

    char *buf = ctrl_query(addr, port, "{\"cmd\":\"get_status\"}\n");
    if (!buf) return 1;

    /* Unparsable, non-object or failed reply: report the error string. */
    doc = status_parse(buf);
    yyjson_val *root = yyjson_doc_get_root(doc);
    if (!yyjson_is_true(yyjson_obj_get(root, "ok"))) {
        char errmsg[128] = "unknown error";
        json_copy_str(yyjson_obj_get(root, "error"), errmsg, sizeof(errmsg));
        fprintf(stderr, "error: %s\n", errmsg);
        goto cleanup;
    }

    int n_clients = 0;
    json_get_int(yyjson_obj_get(root, "n_clients"), &n_clients);
    printf("mqvpn server  clients: %d\n", n_clients);

    yyjson_arr_iter it = yyjson_arr_iter_with(yyjson_obj_get(root, "clients"));
    yyjson_val *client;
    while ((client = yyjson_arr_iter_next(&it)) != NULL)
        if (yyjson_is_obj(client)) print_client(client);

    if (n_clients == 0) printf("\n  (no connected clients)\n");

    rc = 0;

cleanup:
    yyjson_doc_free(doc);
    free(buf);
    return rc;
}
