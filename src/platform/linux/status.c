/*
 * status.c — mqvpn --status: query control API and display server status
 */
#include "status.h"
#include "json_mini.h"

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
#include <ctype.h>

#define STATUS_BUF_SIZE 32768

/* JSON helpers (json_find_key, json_read_string, json_read_int64,
 * json_skip_ws) are provided by json_mini.h */

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

/* ── Skip one JSON value ── */

static const char *
skip_json_value(const char *p)
{
    p = json_skip_ws(p);
    if (*p == '"') {
        p++;
        while (*p && *p != '"') {
            if (*p == '\\' && p[1]) p++;
            p++;
        }
        return *p == '"' ? p + 1 : NULL;
    }
    if (*p == '{' || *p == '[') {
        char open = *p, close = (*p == '{') ? '}' : ']';
        int depth = 1;
        int in_str = 0;
        p++;
        while (*p && depth > 0) {
            if (in_str) {
                if (*p == '\\' && p[1]) {
                    p++;
                } else if (*p == '"')
                    in_str = 0;
            } else {
                if (*p == '"')
                    in_str = 1;
                else if (*p == open)
                    depth++;
                else if (*p == close)
                    depth--;
            }
            p++;
        }
        return depth == 0 ? p : NULL;
    }
    /* number, bool, null */
    while (*p && *p != ',' && *p != '}' && *p != ']' && !isspace((unsigned char)*p))
        p++;
    return p;
}

/* ── Print one client ── */

static void
print_client(const char *obj)
{
    char user[64] = {0}, endpoint[64] = {0};
    const char *v;

    v = json_find_key(obj, "user");
    if (v) json_read_string(v, user, sizeof(user));
    v = json_find_key(obj, "endpoint");
    if (v) json_read_string(v, endpoint, sizeof(endpoint));

    uint64_t conn_sec = (uint64_t)json_read_int64(json_find_key(obj, "connected_sec"));
    uint64_t bytes_tx = (uint64_t)json_read_int64(json_find_key(obj, "bytes_tx"));
    uint64_t bytes_rx = (uint64_t)json_read_int64(json_find_key(obj, "bytes_rx"));

    char dur[32], tx[32], rx[32];
    format_duration(conn_sec, dur, sizeof(dur));
    format_bytes(bytes_rx, rx, sizeof(rx));
    format_bytes(bytes_tx, tx, sizeof(tx));

    printf("\nclient: %s\n", user[0] ? user : "(unknown)");
    printf("  endpoint: %s\n", endpoint[0] ? endpoint : "(unknown)");
    printf("  connected: %s\n", dur);
    printf("  transfer: %s received, %s sent\n", rx, tx);

    /* Print paths */
    v = json_find_key(obj, "paths");
    if (!v || *v != '[') return;
    const char *p = json_skip_ws(v + 1);
    int idx = 0;

    while (*p && *p != ']') {
        if (*p == '{') {
            const char *end = skip_json_value(p);
            if (!end) break;

            size_t plen = (size_t)(end - p);
            char path_obj[512];
            if (plen >= sizeof(path_obj)) {
                p = end;
                continue;
            }
            memcpy(path_obj, p, plen);
            path_obj[plen] = '\0';

            int64_t srtt = json_read_int64(json_find_key(path_obj, "srtt_ms"));
            int64_t min_rtt = json_read_int64(json_find_key(path_obj, "min_rtt_ms"));
            uint64_t cwnd = (uint64_t)json_read_int64(json_find_key(path_obj, "cwnd"));
            int state = (int)json_read_int64(json_find_key(path_obj, "state"));

            char cwnd_str[16];
            format_size(cwnd, cwnd_str, sizeof(cwnd_str));

            const char *state_str = "unknown";
            switch (state) {
            case 1: state_str = "active"; break;
            case 3: state_str = "standby"; break;
            case 4: state_str = "closed"; break;
            }

            printf("  path %d: srtt=%" PRId64 "ms min_rtt=%" PRId64 "ms cwnd=%s %s\n",
                   idx, srtt, min_rtt, cwnd_str, state_str);

            p = end;
            idx++;
        }
        if (*p == ',') p++;
        p = json_skip_ws(p);
    }
}

/* ── Main entry point ── */

int
run_status(const char *addr, int port)
{
    if (!addr) addr = "127.0.0.1";

    int rc = 1;
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
        goto cleanup;
    }

    fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        fprintf(stderr, "error: socket: %s\n", strerror(errno));
        goto cleanup;
    }

    /* Set timeouts to avoid hanging on unresponsive server */
    struct timeval tv = {.tv_sec = 5};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        fprintf(stderr, "error: connect to %s:%d: %s\n", addr, port, strerror(errno));
        goto cleanup;
    }
    freeaddrinfo(res);
    res = NULL;

    /* Send command (handle EINTR and partial writes) */
    const char *cmd = "{\"cmd\":\"get_status\"}\n";
    size_t cmd_len = strlen(cmd);
    size_t sent = 0;
    while (sent < cmd_len) {
        ssize_t n = write(fd, cmd + sent, cmd_len - sent);
        if (n < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "error: write: %s\n", strerror(errno));
            goto cleanup;
        }
        sent += (size_t)n;
    }

    shutdown(fd, SHUT_WR);

    /* Read response (handle EINTR) */
    buf = malloc(STATUS_BUF_SIZE);
    if (!buf) goto cleanup;
    size_t total = 0;
    while (total < STATUS_BUF_SIZE - 1) {
        ssize_t n = read(fd, buf + total, STATUS_BUF_SIZE - 1 - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                fprintf(stderr, "error: read timed out\n");
                goto cleanup;
            }
            break;
        }
        if (n == 0) break;
        total += (size_t)n;
    }
    buf[total] = '\0';
    close(fd);
    fd = -1;

    /* Parse and display */
    const char *ok = json_find_key(buf, "ok");
    if (!ok || strncmp(ok, "true", 4) != 0) {
        const char *err = json_find_key(buf, "error");
        char errmsg[128] = "unknown error";
        if (err) json_read_string(err, errmsg, sizeof(errmsg));
        fprintf(stderr, "error: %s\n", errmsg);
        goto cleanup;
    }

    int n_clients = (int)json_read_int64(json_find_key(buf, "n_clients"));
    printf("mqvpn server  clients: %d\n", n_clients);

    const char *clients = json_find_key(buf, "clients");
    if (clients && *clients == '[') {
        const char *p = json_skip_ws(clients + 1);
        while (*p && *p != ']') {
            if (*p == '{') {
                const char *end = skip_json_value(p);
                if (!end) break;

                size_t len = (size_t)(end - p);
                char *client_obj = malloc(len + 1);
                if (client_obj) {
                    memcpy(client_obj, p, len);
                    client_obj[len] = '\0';
                    print_client(client_obj);
                    free(client_obj);
                }
                p = end;
            }
            if (*p == ',') p++;
            p = json_skip_ws(p);
        }
    }

    if (n_clients == 0) printf("\n  (no connected clients)\n");

    rc = 0;

cleanup:
    if (res) freeaddrinfo(res);
    if (fd >= 0) close(fd);
    free(buf);
    return rc;
}
