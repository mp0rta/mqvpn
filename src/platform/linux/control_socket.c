/*
 * control_socket.c — TCP control API for mqvpn server
 *
 * Supported JSON commands:
 *
 *   {"cmd":"add_user",    "name":"alice","key":"alice-secret"}
 *   {"cmd":"remove_user", "name":"alice"}
 *   {"cmd":"list_users"}
 *   {"cmd":"get_stats"}
 *   {"cmd":"get_status"}
 *   {"cmd":"get_build_info"}
 *   {"cmd":"get_fec_stats","user":"alice"}
 *
 * Responses:
 *   {"ok":true}
 *   {"ok":false,"error":"<reason>"}
 *   {"ok":true,"users":["alice","bob"]}
 *   {"ok":true,"n_clients":2,"bytes_tx":12345,"bytes_rx":6789}
 *   {"ok":true,"version":"0.4.0","scheduler":"backup_fec","fec_enabled":1}
 *   {"ok":true,"user":"alice","enable_fec":1,"mp_state":1,
 *    "fec_send_cnt":142,"fec_recover_cnt":17,"lost_dgram_cnt":23,
 *    "total_app_bytes":9123456,"standby_app_bytes":421337}
 */

#include "control_socket.h"
#include "json_mini.h"
#include "log.h"
#include "mqvpn_internal.h" /* mqvpn_server_scheduler_label,
                               mqvpn_internal_fec_stats_t,
                               mqvpn_server_get_client_fec_stats */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <inttypes.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define CTRL_MAX_REQ          4096 /* per-connection request buffer */
#define CTRL_MAX_CONNS        8    /* max concurrent control connections */
#define CTRL_READ_TIMEOUT_SEC 5    /* close idle connections after 5s */
/* Maximum response size. Worst-case get_status with MQVPN_MAX_USERS=64 and
 * MQVPN_MAX_PATHS=4 produces ~105 KB; round up to 128 KB and re-check the
 * math if either limit grows. */
#define CTRL_MAX_RESP_BYTES (128 * 1024)

/* JSON helpers (json_find_key → json_find_key, json_read_string → json_read_string)
 * are provided by json_mini.h */

/* ── Per-connection state ────────────────────────────────────────────────── */

typedef struct {
    int fd;
    struct event *ev;
    char req[CTRL_MAX_REQ + 1];
    size_t req_len;
    ctrl_socket_t *cs;
} ctrl_conn_t;

/* ── Server handle ───────────────────────────────────────────────────────── */

struct ctrl_socket_s {
    int listen_fd;
    struct event *ev_accept;
    struct event_base *eb;
    mqvpn_server_t *server;
    int n_conns; /* active control connections */
};

/* ── Command dispatch ────────────────────────────────────────────────────── */

static int
dispatch(const char *req, char *resp, size_t resp_len, mqvpn_server_t *server)
{
    char cmd[32] = {0};
    const char *v = json_find_key(req, "cmd");
    if (!v || json_read_string(v, cmd, sizeof(cmd)) < 0)
        return snprintf(resp, resp_len, "{\"ok\":false,\"error\":\"missing cmd\"}");

    if (strcmp(cmd, "add_user") == 0) {
        char name[64] = {0}, key[256] = {0};
        const char *nv = json_find_key(req, "name");
        const char *kv = json_find_key(req, "key");
        if (!nv || json_read_string(nv, name, sizeof(name)) < 0 || !kv ||
            json_read_string(kv, key, sizeof(key)) < 0)
            return snprintf(resp, resp_len,
                            "{\"ok\":false,\"error\":\"name and key required\"}");

        int rc = mqvpn_server_add_user(server, name, key);
        if (rc != MQVPN_OK)
            return snprintf(resp, resp_len,
                            "{\"ok\":false,\"error\":\"add_user failed (%d)\"}", rc);
        return snprintf(resp, resp_len, "{\"ok\":true}");

    } else if (strcmp(cmd, "remove_user") == 0) {
        char name[64] = {0};
        const char *nv = json_find_key(req, "name");
        if (!nv || json_read_string(nv, name, sizeof(name)) < 0)
            return snprintf(resp, resp_len, "{\"ok\":false,\"error\":\"name required\"}");

        int rc = mqvpn_server_remove_user(server, name);
        if (rc != MQVPN_OK)
            return snprintf(resp, resp_len,
                            "{\"ok\":false,\"error\":\"user not found\"}");
        return snprintf(resp, resp_len, "{\"ok\":true}");

    } else if (strcmp(cmd, "list_users") == 0) {
        char unames[MQVPN_MAX_USERS][64];
        int n_users = mqvpn_server_list_users(server, unames, MQVPN_MAX_USERS);

        char users[MQVPN_MAX_USERS * 68 + 8];
        int pos = 0;
        users[pos++] = '[';
        for (int i = 0; i < n_users; i++) {
            if (i > 0) users[pos++] = ',';
            /* Clamp pos to prevent underflow on sizeof(users) - pos */
            int w =
                snprintf(users + pos, sizeof(users) - (size_t)pos, "\"%s\"", unames[i]);
            if (w > 0 && (size_t)(pos + w) < sizeof(users))
                pos += w;
            else
                break; /* truncated — stop appending */
        }
        users[pos++] = ']';
        users[pos] = '\0';
        return snprintf(resp, resp_len, "{\"ok\":true,\"users\":%s}", users);

    } else if (strcmp(cmd, "get_stats") == 0) {
        mqvpn_stats_t st;
        mqvpn_server_get_stats(server, &st);
        int nc = mqvpn_server_get_n_clients(server);
        return snprintf(resp, resp_len,
                        "{\"ok\":true,\"n_clients\":%d,"
                        "\"bytes_tx\":%" PRIu64 ",\"bytes_rx\":%" PRIu64 "}",
                        nc, st.bytes_tx, st.bytes_rx);

    } else if (strcmp(cmd, "get_status") == 0) {
        mqvpn_client_info_t clients[MQVPN_MAX_USERS];
        int n_clients = 0;
        mqvpn_server_get_client_info(server, clients, MQVPN_MAX_USERS, &n_clients);

        uint64_t now = 0;
        struct timeval tv;
        if (gettimeofday(&tv, NULL) == 0)
            now = (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;

        char buf[CTRL_MAX_RESP_BYTES];
        int pos = 0;
        int w;
        pos += snprintf(buf, sizeof(buf), "{\"ok\":true,\"n_clients\":%d,\"clients\":[",
                        n_clients);

        for (int i = 0; i < n_clients; i++) {
            mqvpn_client_info_t *ci = &clients[i];
            uint64_t conn_sec = (ci->connected_at_us > 0 && now > ci->connected_at_us)
                                    ? (now - ci->connected_at_us) / 1000000
                                    : 0;

            if (i > 0 && (size_t)pos < sizeof(buf)) buf[pos++] = ',';
            w = snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                         "{\"user\":\"%s\",\"endpoint\":\"%s\","
                         "\"connected_sec\":%" PRIu64 ","
                         "\"bytes_tx\":%" PRIu64 ",\"bytes_rx\":%" PRIu64 ","
                         "\"paths\":[",
                         ci->username, ci->endpoint, conn_sec, ci->bytes_tx,
                         ci->bytes_rx);
            if (w > 0 && (size_t)(pos + w) < sizeof(buf))
                pos += w;
            else
                break;

            for (int p = 0; p < ci->n_paths; p++) {
                mqvpn_path_stats_t *ps = &ci->paths[p];
                if (p > 0 && (size_t)pos < sizeof(buf)) buf[pos++] = ',';
                w = snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                             "{\"path_id\":%" PRIu64 ",\"srtt_ms\":%" PRIu64
                             ",\"min_rtt_ms\":%" PRIu64 ",\"cwnd\":%" PRIu64
                             ",\"in_flight\":%" PRIu64 ",\"bytes_tx\":%" PRIu64
                             ",\"bytes_rx\":%" PRIu64 ",\"pkt_sent\":%" PRIu64
                             ",\"pkt_recv\":%" PRIu64 ",\"pkt_lost\":%" PRIu64
                             ",\"state\":%u}",
                             ps->path_id, ps->srtt_us / 1000, ps->min_rtt_us / 1000,
                             ps->cwnd, ps->bytes_in_flight, ps->bytes_tx, ps->bytes_rx,
                             ps->pkt_sent, ps->pkt_recv, ps->pkt_lost, ps->state);
                if (w > 0 && (size_t)(pos + w) < sizeof(buf))
                    pos += w;
                else
                    break;
            }

            w = snprintf(buf + pos, sizeof(buf) - (size_t)pos, "]}");
            if (w > 0 && (size_t)(pos + w) < sizeof(buf)) pos += w;
        }

        w = snprintf(buf + pos, sizeof(buf) - (size_t)pos, "]}");
        if (w > 0 && (size_t)(pos + w) < sizeof(buf)) pos += w;

        return snprintf(resp, resp_len, "%.*s", pos, buf);

    } else if (strcmp(cmd, "get_build_info") == 0) {
        const char *ver = mqvpn_version_string();
        const char *sched = mqvpn_server_scheduler_label(server);
#ifdef XQC_ENABLE_FEC
        int fec_enabled = 1;
#else
        int fec_enabled = 0;
#endif
        return snprintf(resp, resp_len,
                        "{\"ok\":true,\"version\":\"%s\","
                        "\"scheduler\":\"%s\",\"fec_enabled\":%d}",
                        ver ? ver : "unknown", sched, fec_enabled);

    } else if (strcmp(cmd, "get_fec_stats") == 0) {
        char user[64] = {0};
        const char *uv = json_find_key(req, "user");
        if (!uv || json_read_string(uv, user, sizeof(user)) < 0)
            return snprintf(resp, resp_len, "{\"ok\":false,\"error\":\"user required\"}");

        mqvpn_internal_fec_stats_t fs;
        int rc = mqvpn_server_get_client_fec_stats(server, user, &fs);
        if (rc < 0)
            return snprintf(resp, resp_len, "{\"ok\":false,\"error\":\"fec not built\"}");
        if (rc == 0)
            return snprintf(resp, resp_len,
                            "{\"ok\":false,\"error\":\"user not found\"}");

        return snprintf(resp, resp_len,
                        "{\"ok\":true,\"user\":\"%s\","
                        "\"enable_fec\":%u,\"mp_state\":%u,"
                        "\"fec_send_cnt\":%" PRIu64 ",\"fec_recover_cnt\":%" PRIu64 ","
                        "\"lost_dgram_cnt\":%" PRIu64 ","
                        "\"total_app_bytes\":%" PRIu64 ","
                        "\"standby_app_bytes\":%" PRIu64 "}",
                        user, (unsigned)fs.enable_fec, (unsigned)fs.mp_state,
                        fs.fec_send_cnt, fs.fec_recover_cnt, fs.lost_dgram_cnt,
                        fs.total_app_bytes, fs.standby_app_bytes);

    } else {
        return snprintf(resp, resp_len, "{\"ok\":false,\"error\":\"unknown cmd\"}");
    }
}

/* ── Connection read handler ─────────────────────────────────────────────── */

static void
ctrl_on_read(evutil_socket_t fd, short what, void *arg)
{
    ctrl_conn_t *conn = (ctrl_conn_t *)arg;

    /* Idle timeout — close without processing */
    if (what & EV_TIMEOUT) {
        event_del(conn->ev);
        event_free(conn->ev);
        close(fd);
        conn->cs->n_conns--;
        free(conn);
        return;
    }

    /* Accumulate data until we have a complete request */
    while (conn->req_len < CTRL_MAX_REQ) {
        ssize_t n = read(fd, conn->req + conn->req_len, CTRL_MAX_REQ - conn->req_len);
        if (n > 0) {
            conn->req_len += (size_t)n;

            /* Detect a complete JSON object by brace counting */
            const char *p = conn->req;
            while (*p && isspace((unsigned char)*p))
                p++;
            if (*p == '{') {
                int depth = 0, in_str = 0;
                int complete = 0;
                for (size_t i = (size_t)(p - conn->req); i < conn->req_len; i++) {
                    char c = conn->req[i];
                    if (in_str) {
                        if (c == '\\') {
                            i++;
                            continue;
                        }
                        if (c == '"') in_str = 0;
                    } else {
                        if (c == '"')
                            in_str = 1;
                        else if (c == '{')
                            depth++;
                        else if (c == '}' && --depth == 0) {
                            complete = 1;
                            break;
                        }
                    }
                }
                if (!complete) continue;
            } else if (!memchr(conn->req, '\n', conn->req_len)) {
                continue; /* newline-terminated form: wait for more */
            }
        } else if (n == 0) {
            break; /* EOF — process whatever we have */
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return; /* wait for more data */
        } else {
            /* read error — close connection */
            event_del(conn->ev);
            event_free(conn->ev);
            close(fd);
            conn->cs->n_conns--;
            free(conn);
            return;
        }
        break;
    }

    conn->req[conn->req_len] = '\0';

    char resp[CTRL_MAX_RESP_BYTES];
    int rlen = dispatch(conn->req, resp, sizeof(resp) - 2, conn->cs->server);
    if (rlen <= 0) {
        /* dispatch failed to format anything — close silently. */
    } else if ((size_t)rlen >= sizeof(resp) - 2) {
        /* snprintf would have truncated. Send a small error JSON instead so the
         * client doesn't see a malformed body, and emit a warning. */
        static const char too_large[] =
            "{\"ok\":false,\"error\":\"response too large\"}\n";
        (void)write(fd, too_large, sizeof(too_large) - 1);
        LOG_WRN(
            "control: dispatch response truncated (would have been %d bytes, max %zu)",
            rlen, sizeof(resp) - 2);
    } else {
        resp[rlen] = '\n';
        resp[rlen + 1] = '\0';
        (void)write(fd, resp, (size_t)rlen + 1);
    }

    event_del(conn->ev);
    event_free(conn->ev);
    close(fd);
    conn->cs->n_conns--;
    free(conn);
}

/* ── Accept handler ──────────────────────────────────────────────────────── */

static void
ctrl_on_accept(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    ctrl_socket_t *cs = (ctrl_socket_t *)arg;

    if (cs->n_conns >= CTRL_MAX_CONNS) {
        int cfd = accept(fd, NULL, NULL);
        if (cfd >= 0) {
            const char *msg = "{\"ok\":false,\"error\":\"too many connections\"}\n";
            (void)write(cfd, msg, strlen(msg));
            close(cfd);
        }
        return;
    }

    int cfd = accept(fd, NULL, NULL);
    if (cfd < 0) return;

    int flags = fcntl(cfd, F_GETFL, 0);
    if (flags < 0 || fcntl(cfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(cfd);
        return;
    }

    ctrl_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) {
        close(cfd);
        return;
    }

    conn->fd = cfd;
    conn->cs = cs;
    conn->ev =
        event_new(cs->eb, cfd, EV_READ | EV_PERSIST | EV_TIMEOUT, ctrl_on_read, conn);
    if (!conn->ev) {
        free(conn);
        close(cfd);
        return;
    }
    struct timeval tv = {.tv_sec = CTRL_READ_TIMEOUT_SEC};
    event_add(conn->ev, &tv);
    cs->n_conns++;
}

/* ── Public API ──────────────────────────────────────────────────────────── */

ctrl_socket_t *
ctrl_socket_create(struct event_base *eb, const char *addr, int port,
                   mqvpn_server_t *server)
{
    if (!eb || port <= 0 || port > 65535 || !server) return NULL;

    if (!addr || addr[0] == '\0') addr = "127.0.0.1";

    /* Warn if exposed beyond loopback — the control API has no auth */
    if (strcmp(addr, "127.0.0.1") != 0 && strcmp(addr, "::1") != 0)
        LOG_WRN("control API: binding to non-loopback address %s — "
                "the control API has no authentication",
                addr);

    ctrl_socket_t *cs = calloc(1, sizeof(*cs));
    if (!cs) return NULL;
    cs->eb = eb;
    cs->server = server;

    /* Determine address family */
    struct sockaddr_in sin4;
    struct sockaddr_in6 sin6;
    struct sockaddr *sa;
    socklen_t sa_len;

    memset(&sin4, 0, sizeof(sin4));
    memset(&sin6, 0, sizeof(sin6));

    if (inet_pton(AF_INET6, addr, &sin6.sin6_addr) == 1) {
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port = htons((uint16_t)port);
        sa = (struct sockaddr *)&sin6;
        sa_len = sizeof(sin6);
        cs->listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
    } else {
        if (inet_pton(AF_INET, addr, &sin4.sin_addr) != 1) {
            LOG_ERR("control API: invalid address '%s'", addr);
            free(cs);
            return NULL;
        }
        sin4.sin_family = AF_INET;
        sin4.sin_port = htons((uint16_t)port);
        sa = (struct sockaddr *)&sin4;
        sa_len = sizeof(sin4);
        cs->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    }

    if (cs->listen_fd < 0) {
        LOG_ERR("control API: socket(): %s", strerror(errno));
        free(cs);
        return NULL;
    }

    int opt = 1;
    setsockopt(cs->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(cs->listen_fd, sa, sa_len) < 0) {
        LOG_ERR("control API: bind(%s:%d): %s", addr, port, strerror(errno));
        close(cs->listen_fd);
        free(cs);
        return NULL;
    }

    if (listen(cs->listen_fd, 8) < 0) {
        LOG_ERR("control API: listen(): %s", strerror(errno));
        close(cs->listen_fd);
        free(cs);
        return NULL;
    }

    int flags = fcntl(cs->listen_fd, F_GETFL, 0);
    fcntl(cs->listen_fd, F_SETFL, flags | O_NONBLOCK);

    cs->ev_accept =
        event_new(eb, cs->listen_fd, EV_READ | EV_PERSIST, ctrl_on_accept, cs);
    if (!cs->ev_accept) {
        close(cs->listen_fd);
        free(cs);
        return NULL;
    }
    event_add(cs->ev_accept, NULL);

    LOG_INF("control API listening on %s:%d", addr, port);
    return cs;
}

void
ctrl_socket_destroy(ctrl_socket_t *cs)
{
    if (!cs) return;
    if (cs->ev_accept) {
        event_del(cs->ev_accept);
        event_free(cs->ev_accept);
    }
    if (cs->listen_fd >= 0) close(cs->listen_fd);
    free(cs);
}
