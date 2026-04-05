/*
 * control_socket.c — TCP control API for mqvpn server
 *
 * Supported JSON commands:
 *
 *   {"cmd":"add_user",    "name":"alice","key":"alice-secret"}
 *   {"cmd":"remove_user", "name":"alice"}
 *   {"cmd":"list_users"}
 *   {"cmd":"get_stats"}
 *
 * Responses:
 *   {"ok":true}
 *   {"ok":false,"error":"<reason>"}
 *   {"ok":true,"users":["alice","bob"]}
 *   {"ok":true,"n_clients":2,"bytes_tx":12345,"bytes_rx":6789}
 */

#include "control_socket.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define CTRL_MAX_REQ  4096
#define CTRL_MAX_RESP 4096

/* ── Minimal JSON helpers (same fixed escape logic as config.c) ─────────── */

static const char *
jfind(const char *json, const char *key)
{
    size_t klen = strlen(key);
    const char *p = json;
    while ((p = strchr(p, '"')) != NULL) {
        const char *k = p + 1, *e = k;
        while (*e && *e != '"') { if (*e == '\\' && e[1]) e++; e++; }
        if (*e != '"') return NULL;
        if ((size_t)(e - k) == klen && strncmp(k, key, klen) == 0) {
            const char *c = e + 1;
            while (*c && isspace((unsigned char)*c)) c++;
            if (*c == ':') {
                c++;
                while (*c && isspace((unsigned char)*c)) c++;
                return c;
            }
        }
        p = e + 1;
    }
    return NULL;
}

static int
jstr(const char *p, char *out, size_t out_len)
{
    if (!p || *p != '"' || !out || out_len == 0) return -1;
    p++;
    size_t j = 0;
    while (*p && *p != '"') {
        if (*p == '\\' && p[1]) p++;
        if (j + 1 < out_len) out[j++] = *p;
        p++;
    }
    if (*p != '"') return -1;
    out[j] = '\0';
    return 0;
}

/* ── Per-connection state ────────────────────────────────────────────────── */

typedef struct {
    int              fd;
    struct event    *ev;
    char             req[CTRL_MAX_REQ + 1];
    size_t           req_len;
    ctrl_socket_t   *cs;
} ctrl_conn_t;

/* ── Server handle ───────────────────────────────────────────────────────── */

struct ctrl_socket_s {
    int                listen_fd;
    struct event      *ev_accept;
    struct event_base *eb;
    mqvpn_server_t    *server;
};

/* ── Command dispatch ────────────────────────────────────────────────────── */

static int
dispatch(const char *req, char *resp, size_t resp_len, mqvpn_server_t *server)
{
    char cmd[32] = {0};
    const char *v = jfind(req, "cmd");
    if (!v || jstr(v, cmd, sizeof(cmd)) < 0)
        return snprintf(resp, resp_len, "{\"ok\":false,\"error\":\"missing cmd\"}");

    if (strcmp(cmd, "add_user") == 0) {
        char name[64] = {0}, key[256] = {0};
        const char *nv = jfind(req, "name");
        const char *kv = jfind(req, "key");
        if (!nv || jstr(nv, name, sizeof(name)) < 0 ||
            !kv || jstr(kv, key,  sizeof(key))  < 0)
            return snprintf(resp, resp_len,
                            "{\"ok\":false,\"error\":\"name and key required\"}");

        int rc = mqvpn_server_add_user(server, name, key);
        if (rc != MQVPN_OK)
            return snprintf(resp, resp_len,
                            "{\"ok\":false,\"error\":\"add_user failed (%d)\"}", rc);
        return snprintf(resp, resp_len, "{\"ok\":true}");

    } else if (strcmp(cmd, "remove_user") == 0) {
        char name[64] = {0};
        const char *nv = jfind(req, "name");
        if (!nv || jstr(nv, name, sizeof(name)) < 0)
            return snprintf(resp, resp_len,
                            "{\"ok\":false,\"error\":\"name required\"}");

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
            int w = snprintf(users + pos, sizeof(users) - (size_t)pos,
                             "\"%s\"", unames[i]);
            if (w > 0 && (size_t)(pos + w) < sizeof(users))
                pos += w;
            else
                break;  /* truncated — stop appending */
        }
        users[pos++] = ']';
        users[pos]   = '\0';
        return snprintf(resp, resp_len, "{\"ok\":true,\"users\":%s}", users);

    } else if (strcmp(cmd, "get_stats") == 0) {
        mqvpn_stats_t st;
        mqvpn_server_get_stats(server, &st);
        int nc = mqvpn_server_get_n_clients(server);
        return snprintf(resp, resp_len,
                        "{\"ok\":true,\"n_clients\":%d,"
                        "\"bytes_tx\":%" PRIu64 ",\"bytes_rx\":%" PRIu64 "}",
                        nc, st.bytes_tx, st.bytes_rx);

    } else {
        return snprintf(resp, resp_len,
                        "{\"ok\":false,\"error\":\"unknown cmd\"}");
    }
}

/* ── Connection read handler ─────────────────────────────────────────────── */

static void
ctrl_on_read(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    ctrl_conn_t *conn = (ctrl_conn_t *)arg;

    /* Accumulate data until we have a complete request */
    while (conn->req_len < CTRL_MAX_REQ) {
        ssize_t n = read(fd, conn->req + conn->req_len,
                         CTRL_MAX_REQ - conn->req_len);
        if (n > 0) {
            conn->req_len += (size_t)n;

            /* Detect a complete JSON object by brace counting */
            const char *p = conn->req;
            while (*p && isspace((unsigned char)*p)) p++;
            if (*p == '{') {
                int depth = 0, in_str = 0;
                int complete = 0;
                for (size_t i = (size_t)(p - conn->req); i < conn->req_len; i++) {
                    char c = conn->req[i];
                    if (in_str) {
                        if (c == '\\') { i++; continue; }
                        if (c == '"')  in_str = 0;
                    } else {
                        if      (c == '"')  in_str = 1;
                        else if (c == '{')  depth++;
                        else if (c == '}' && --depth == 0) { complete = 1; break; }
                    }
                }
                if (!complete) continue;
            } else if (!memchr(conn->req, '\n', conn->req_len)) {
                continue;  /* newline-terminated form: wait for more */
            }
        } else if (n == 0) {
            break;  /* EOF — process whatever we have */
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;  /* wait for more data */
        } else {
            /* read error — close connection */
            event_del(conn->ev);
            event_free(conn->ev);
            close(fd);
            free(conn);
            return;
        }
        break;
    }

    conn->req[conn->req_len] = '\0';

    char resp[CTRL_MAX_RESP];
    int rlen = dispatch(conn->req, resp, sizeof(resp) - 2, conn->cs->server);
    if (rlen > 0) {
        resp[rlen]     = '\n';
        resp[rlen + 1] = '\0';
        (void)write(fd, resp, (size_t)rlen + 1);
    }

    event_del(conn->ev);
    event_free(conn->ev);
    close(fd);
    free(conn);
}

/* ── Accept handler ──────────────────────────────────────────────────────── */

static void
ctrl_on_accept(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    ctrl_socket_t *cs = (ctrl_socket_t *)arg;

    int cfd = accept(fd, NULL, NULL);
    if (cfd < 0) return;

    int flags = fcntl(cfd, F_GETFL, 0);
    if (flags < 0 || fcntl(cfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(cfd);
        return;
    }

    ctrl_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) { close(cfd); return; }

    conn->fd = cfd;
    conn->cs = cs;
    conn->ev = event_new(cs->eb, cfd, EV_READ | EV_PERSIST, ctrl_on_read, conn);
    if (!conn->ev) { free(conn); close(cfd); return; }
    event_add(conn->ev, NULL);
}

/* ── Public API ──────────────────────────────────────────────────────────── */

ctrl_socket_t *
ctrl_socket_create(struct event_base *eb, const char *addr, int port,
                   mqvpn_server_t *server)
{
    if (!eb || port <= 0 || port > 65535 || !server) return NULL;

    if (!addr || addr[0] == '\0')
        addr = "127.0.0.1";

    /* Warn if exposed beyond loopback — the control API has no auth */
    if (strcmp(addr, "127.0.0.1") != 0 && strcmp(addr, "::1") != 0)
        LOG_WRN("control API: binding to non-loopback address %s — "
                "the control API has no authentication", addr);

    ctrl_socket_t *cs = calloc(1, sizeof(*cs));
    if (!cs) return NULL;
    cs->eb     = eb;
    cs->server = server;

    /* Determine address family */
    struct sockaddr_in  sin4;
    struct sockaddr_in6 sin6;
    struct sockaddr    *sa;
    socklen_t           sa_len;

    memset(&sin4, 0, sizeof(sin4));
    memset(&sin6, 0, sizeof(sin6));

    if (inet_pton(AF_INET6, addr, &sin6.sin6_addr) == 1) {
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port   = htons((uint16_t)port);
        sa     = (struct sockaddr *)&sin6;
        sa_len = sizeof(sin6);
        cs->listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
    } else {
        if (inet_pton(AF_INET, addr, &sin4.sin_addr) != 1) {
            LOG_ERR("control API: invalid address '%s'", addr);
            free(cs);
            return NULL;
        }
        sin4.sin_family = AF_INET;
        sin4.sin_port   = htons((uint16_t)port);
        sa     = (struct sockaddr *)&sin4;
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

    cs->ev_accept = event_new(eb, cs->listen_fd, EV_READ | EV_PERSIST,
                               ctrl_on_accept, cs);
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
    if (cs->ev_accept) { event_del(cs->ev_accept); event_free(cs->ev_accept); }
    if (cs->listen_fd >= 0) close(cs->listen_fd);
    free(cs);
}
