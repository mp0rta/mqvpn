// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* Server-side `:protocol == "mqvpn-tcp"` dispatch: real auth reuse, a
 * mandatory default-on egress ACL, non-blocking egress connect() with a
 * configurable timeout, and 2xx/4xx/5xx response mapping. Relay (the actual
 * byte-shoveling once the flow is ACTIVE) lands in a follow-up task —
 * svr_tcp_egress_on_relay_ready below is a no-op stub for now, but data CAN
 * arrive on an ACTIVE fd before relay lands, so it must not crash. */

#include "hybrid/tcp_egress.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* "/.well-known/mqvpn/tcp/" — byte-for-byte the prefix mqvpn_client.c's
 * connect-tcp request builder emits (snprintf("/.well-known/mqvpn/tcp/"
 * "%u.%u.%u.%u/%u/", ...)). */
#define TCP_EGRESS_PATH_PREFIX     "/.well-known/mqvpn/tcp/"
#define TCP_EGRESS_PATH_PREFIX_LEN (sizeof(TCP_EGRESS_PATH_PREFIX) - 1)

int
svr_tcp_egress_parse_path(const char *path, size_t path_len, char *out_host,
                          size_t out_host_cap, uint16_t *out_port)
{
    if (!path || !out_host || !out_port || out_host_cap == 0) return -1;
    if (path_len <= TCP_EGRESS_PATH_PREFIX_LEN) return -1;
    if (memcmp(path, TCP_EGRESS_PATH_PREFIX, TCP_EGRESS_PATH_PREFIX_LEN) != 0) return -1;

    const char *p = path + TCP_EGRESS_PATH_PREFIX_LEN;
    const char *end = path + path_len;

    /* Host: everything up to the next '/'. Rejected outright (not
     * truncated) if it doesn't fit out_host_cap incl. NUL. */
    const void *slash1_v = memchr(p, '/', (size_t)(end - p));
    if (!slash1_v) return -1;
    const char *slash1 = (const char *)slash1_v;
    size_t host_len = (size_t)(slash1 - p);
    if (host_len == 0 || host_len >= out_host_cap) return -1;
    memcpy(out_host, p, host_len);
    out_host[host_len] = '\0';

    /* Port: digits only, terminated by exactly one trailing '/' that must
     * be the LAST byte of the path (byte-for-byte match with the client's
     * trailing-slash template — no query string, no extra segments).
     * port_start <= end always holds here: slash1 came from a memchr
     * bounded by end, so slash1 < end and slash1 + 1 <= end. */
    const char *port_start = slash1 + 1;
    const void *slash2_v = memchr(port_start, '/', (size_t)(end - port_start));
    if (!slash2_v) return -1;
    const char *slash2 = (const char *)slash2_v;
    if (slash2 + 1 != end) return -1;

    size_t port_len = (size_t)(slash2 - port_start);
    if (port_len == 0 || port_len > 5) return -1; /* "65535" = 5 digits, max */

    uint32_t port = 0;
    for (size_t i = 0; i < port_len; i++) {
        char c = port_start[i];
        if (c < '0' || c > '9') return -1;
        port = port * 10 + (uint32_t)(c - '0');
        if (port > 65535) return -1; /* overflow guard */
    }
    if (port < 1) return -1; /* 1-65535: reject "0" */

    *out_port = (uint16_t)port;
    return 0;
}

/* Mandatory, default-on deny set: this-network, loopback, RFC1918,
 * link-local, CGNAT, multicast, reserved, broadcast. Evaluated regardless
 * of config — egress_allow is the only way through (see
 * svr_tcp_egress_acl_decide's docstring for the full precedence order,
 * including the tunnel-subnet check that isn't in this table because it
 * depends on the server's own config). */
static const struct {
    uint32_t net;
    uint32_t mask;
} DEFAULT_DENY_V4[] = {
    /* 0.0.0.0/8 "this network" (RFC 1122 §3.2.1.3): NOT a dead range —
     * inet_pton accepts "0.0.0.0" and on Linux connect() to 0.0.0.0 reaches
     * localhost, so without this row a connect-tcp target of 0.0.0.0 would
     * bypass the loopback protection below. */
    {0x00000000u, 0xFF000000u}, /* this-network 0.0.0.0/8 */
    {0x7F000000u, 0xFF000000u}, /* loopback 127.0.0.0/8 */
    {0x0A000000u, 0xFF000000u}, /* rfc1918 10.0.0.0/8 */
    {0xAC100000u, 0xFFF00000u}, /* rfc1918 172.16.0.0/12 */
    {0xC0A80000u, 0xFFFF0000u}, /* rfc1918 192.168.0.0/16 */
    {0xA9FE0000u, 0xFFFF0000u}, /* link-local 169.254.0.0/16 */
    {0x64400000u, 0xFFC00000u}, /* cgnat 100.64.0.0/10 */
    {0xE0000000u, 0xF0000000u}, /* multicast 224.0.0.0/4 */
    /* 240.0.0.0/4 reserved (RFC 1112 Class E), defense-in-depth. Subsumes
     * the broadcast /32 row below; keeping both is harmless (rows are
     * checked sequentially, first match denies) and keeps broadcast
     * explicitly documented rather than implied. */
    {0xF0000000u, 0xF0000000u}, /* reserved 240.0.0.0/4 */
    {0xFFFFFFFFu, 0xFFFFFFFFu}, /* broadcast 255.255.255.255/32 */
};

int
svr_tcp_egress_acl_decide(uint32_t ip, const mqvpn_cidr_entry_t *allow, int n_allow,
                          const mqvpn_cidr_entry_t *deny, int n_deny, uint32_t tunnel_net,
                          uint32_t tunnel_mask)
{
    if ((ip & tunnel_mask) == tunnel_net) return 0;

    for (int i = 0; i < n_allow; i++) {
        if ((ip & allow[i].mask) == allow[i].net) return 1;
    }

    for (size_t i = 0; i < sizeof(DEFAULT_DENY_V4) / sizeof(DEFAULT_DENY_V4[0]); i++) {
        if ((ip & DEFAULT_DENY_V4[i].mask) == DEFAULT_DENY_V4[i].net) return 0;
    }

    for (int i = 0; i < n_deny; i++) {
        if ((ip & deny[i].mask) == deny[i].net) return 0;
    }

    return 1;
}

/* server-bound wrapper: resolves the target string and the server's own
 * policy/tunnel-subnet, then defers to the pure decision core above. */
static int
svr_tcp_egress_acl_allowed(mqvpn_server_t *server, const char *target_host,
                           uint16_t target_port)
{
    (void)target_port; /* v1: host-only ACL — no port-scoped rules requested;
                        * don't add scope beyond what's asked. */

    struct in_addr addr;
    if (inet_pton(AF_INET, target_host, &addr) != 1)
        return 0; /* unparseable target — reject closed, not open */
    uint32_t ip = ntohl(addr.s_addr);

    const mqvpn_cidr_entry_t *allow = NULL, *deny = NULL;
    int n_allow = 0, n_deny = 0;
    uint32_t tunnel_net = 0, tunnel_mask = 0;
    svr_get_egress_policy(server, &allow, &n_allow, &deny, &n_deny, &tunnel_net,
                          &tunnel_mask);

    return svr_tcp_egress_acl_decide(ip, allow, n_allow, deny, n_deny, tunnel_net,
                                     tunnel_mask);
}

/* svr_log-routed warning macro — the only logging path this file has (see
 * the boundary note in mqvpn_server_internal.h). */
#define TLOG_W(server, ...) svr_log((server), MQVPN_LOG_WARN, __VA_ARGS__)

/* Canned status-only response, generalizing the 403 stub this replaces.
 * Mirrors mqvpn_server.c's svr_masque_send_403/501 (kept separate on
 * purpose — see the boundary decision in this task: those two stay
 * CONNECT-IP-flavored helpers private to mqvpn_server.c, this one is the
 * connect-tcp-flavored equivalent private to this file).
 *
 * `fin`: 1 for a final response (stream closes, no relay follows — every
 * 4xx/5xx here), 0 to keep the stream open for what comes after (the 200
 * success response, so relay can use the same stream). Generalizes the
 * original fin=1-only helper rather than adding a second near-duplicate
 * send site for the 200 case. */
static int
svr_tcp_egress_respond(xqc_h3_request_t *h3_request, int status, uint8_t fin)
{
    /* iov_len below is hardcoded 3, so status must be a 3-digit HTTP code
     * (100-999). All call sites pass literals; a value outside that range
     * would send a truncated/garbage :status. */
    char status_str[4];
    snprintf(status_str, sizeof(status_str), "%03d", status);

    xqc_http_header_t resp[] = {
        {.name = {.iov_base = ":status", .iov_len = 7},
         .value = {.iov_base = status_str, .iov_len = 3},
         .flags = 0},
    };
    xqc_http_headers_t resp_hdrs = {.headers = resp, .count = 1, .capacity = 1};
    /* Send-failure deliberately not escalated: returning an error from the
     * H3 read-notify path would kill the whole H3 connection. */
    xqc_h3_request_send_headers(h3_request, &resp_hdrs, fin);
    return 0;
}

/* ── Per-flow state (Step 1) ──
 *
 * Private to this file — nothing outside tcp_egress.c ever dereferences
 * this struct; every other file sees it only as a void*
 * (stream->tcp_egress_flow, the fd_ctx handed to egress_fd_register, the
 * `flow` parameter of svr_tcp_egress_flow_destroy). Relay buffers land with
 * the next task; this task only needs enough to track one outstanding
 * connect() and, once ACTIVE, hand future read/write events somewhere.
 *
 * prev/next: intrusive D3 tick-enumeration list (design decision: no
 * server-side 5-tuple table, see tcp_egress.h's on_request docstring). The
 * list head lives in mqvpn_server_t (storage only; reached through the
 * bundled svr_get_tcp_egress_ctx accessor in mqvpn_server_internal.h). */
typedef enum {
    EGRESS_FLOW_CONNECTING = 0,
    EGRESS_FLOW_ACTIVE,
} svr_tcp_egress_flow_state_t;

typedef struct svr_tcp_egress_flow_s {
    int fd;
    xqc_h3_request_t *h3_request;
    void *stream; /* svr_stream_t*, opaque here — only mqvpn_server.c's
                   * accessors (svr_stream_tcp_egress_flow_ptr,
                   * svr_conn_tcp_flow_count_ptr) dereference it. */
    svr_tcp_egress_flow_state_t state;
    uint64_t connect_deadline_us; /* only meaningful while CONNECTING */
    char username[64];            /* sized to match svr_auth_check's out
                                   * buf; consumed by later stats work */
    struct svr_tcp_egress_flow_s *prev, *next;
} svr_tcp_egress_flow_t;

/* List helpers take the head slot as a parameter — the entry points fetch
 * the server ctx (svr_get_tcp_egress_ctx) once and pass ctx.flow_list_head
 * down, per the one-ctx-call-per-entry-point rule in
 * mqvpn_server_internal.h. */
static void
svr_tcp_egress_list_insert(svr_tcp_egress_flow_t **head, svr_tcp_egress_flow_t *ef)
{
    ef->prev = NULL;
    ef->next = *head;
    if (ef->next) ef->next->prev = ef;
    *head = ef;
}

static void
svr_tcp_egress_list_remove(svr_tcp_egress_flow_t **head, svr_tcp_egress_flow_t *ef)
{
    if (ef->prev) {
        ef->prev->next = ef->next;
    } else {
        *head = ef->next;
    }
    if (ef->next) ef->next->prev = ef->prev;
    ef->prev = NULL;
    ef->next = NULL;
}

/* The ONLY teardown path for a flow (see the docstring in tcp_egress.h for
 * why every call site funnels through here). Bookkeeping invariant: every
 * live flow was counted exactly once, unconditionally, right after it was
 * linked in svr_tcp_egress_start_connect — BEFORE the connect() syscall,
 * regardless of whether that call turns out to complete synchronously,
 * return EINPROGRESS, or fail outright. Because destroy() is only ever
 * reachable after that increment (nothing calls it on the "flow never got
 * created" paths — admission-cap 503s and a failed socket()/calloc()),
 * decrementing here unconditionally is always paired 1:1 with a prior
 * increment. No separate "counted" flag needed. */
void
svr_tcp_egress_flow_destroy(mqvpn_server_t *server, void *flow)
{
    svr_tcp_egress_flow_t *ef = (svr_tcp_egress_flow_t *)flow;
    if (!server || !ef) return;

    /* Unregister before close(): the platform reactor keys its registry
     * off the fd number (see platform_linux.c's egress fd slot table), so
     * dropping interest must happen while the fd is still open and
     * unambiguously refers to this flow. Safe to call even for a flow that
     * was never registered (sync connect() error/admission-cap paths never
     * call svr_egress_fd_register at all) — both the real platform
     * implementation and the test harness treat "unregister a fd I don't
     * know about" as a no-op. */
    svr_egress_fd_unregister(server, ef->fd);
    close(ef->fd);

    svr_tcp_egress_srv_ctx_t ctx;
    svr_get_tcp_egress_ctx(server, &ctx);
    svr_tcp_egress_list_remove(ctx.flow_list_head, ef);

    /* 1:1 with the increments in start_connect (see the invariant comment
     * above) — decrement unconditionally, assert-pinned like the library's
     * other state invariants (path_state_machine.c). conn_count keeps a
     * NULL guard: it's a different concern (stream/conn back-pointer
     * liveness) than the count invariant, and a NULL deref in release
     * would be strictly worse than a skipped decrement. */
    int *conn_count = svr_conn_tcp_flow_count_ptr(ef->stream);
    assert(conn_count != NULL); /* live flow always has stream->conn */
    if (conn_count) {
        assert(*conn_count > 0);
        (*conn_count)--;
    }
    assert(*ctx.global_fd_count > 0);
    (*ctx.global_fd_count)--;

    void **stream_slot = svr_stream_tcp_egress_flow_ptr(ef->stream);
    if (stream_slot) *stream_slot = NULL;

    free(ef);
}

/* Errno -> H3 :status for a failed egress connect(), whether discovered
 * synchronously (connect() itself returned a non-EINPROGRESS error) or via
 * SO_ERROR after a writable event on an EINPROGRESS fd.
 *   ECONNREFUSED           -> 502 (nothing listening / actively refused)
 *   ETIMEDOUT              -> 504 (never completed — includes our own
 *                              connect_deadline_us sweep, which synthesizes
 *                              this errno rather than reading SO_ERROR)
 *   ENETUNREACH/EHOSTUNREACH -> 502 (routing failure reaching the target)
 *   default                -> 502 (every other errno collapses to the same
 *                              "couldn't reach upstream" bucket; 502 is the
 *                              closest HTTP semantic) */
int
svr_tcp_egress_errno_to_status(int err)
{
    switch (err) {
    case ECONNREFUSED: return 502;
    case ETIMEDOUT: return 504;
    case ENETUNREACH:
    case EHOSTUNREACH: return 502;
    default: return 502;
    }
}

/* Flips a CONNECTING flow to ACTIVE and DISARMS the fd (want_read=0,
 * want_write=0 — replaces the connect-signal want_write registration with
 * no interest, keeping the reactor slot). The relay stage arms want_read
 * when it can actually consume data; arming it now, against the no-op
 * relay stub below, would busy-loop a level-triggered reactor — a
 * server-speaks-first upstream (SMTP/SSH banner) or an upstream EOF makes
 * the fd permanently readable, re-firing the platform's event callback
 * every loop pass until stream close. Sends the real 200 with fin=0: the
 * stream stays open, relay traffic rides it. */
static void
svr_tcp_egress_on_connected(mqvpn_server_t *server, svr_tcp_egress_flow_t *ef)
{
    ef->state = EGRESS_FLOW_ACTIVE;
    (void)svr_egress_fd_register(server, ef->fd, 0, 0, ef);
    svr_tcp_egress_respond(ef->h3_request, 200, 0);
}

/* Failed connect (either SO_ERROR after a writable event, or our own
 * connect-timeout sweep synthesizing ETIMEDOUT): respond with the mapped
 * status, then fully tear the flow down. */
static void
svr_tcp_egress_fail_connect(mqvpn_server_t *server, svr_tcp_egress_flow_t *ef, int err)
{
    svr_tcp_egress_respond(ef->h3_request, svr_tcp_egress_errno_to_status(err), 1);
    svr_tcp_egress_flow_destroy(server, ef);
}

/* connect()/relay wiring (Step 1-3): open a non-blocking egress socket,
 * admit it against the per-session and server-wide caps, and either finish
 * synchronously or arm the fd for a connect-completion callback. Response
 * is sent immediately for every admission/syscall failure; on the
 * EINPROGRESS path it is deferred until svr_tcp_egress_fd_ready or
 * svr_tcp_egress_tick resolves the connect. */
static int
svr_tcp_egress_start_connect(mqvpn_server_t *server, void *stream,
                             xqc_h3_request_t *h3_request, const char *target_host,
                             uint16_t target_port, const char *username)
{
    svr_tcp_egress_srv_ctx_t ctx;
    svr_get_tcp_egress_ctx(server, &ctx);
    if (*ctx.global_fd_count >= ctx.global_fd_budget) {
        return svr_tcp_egress_respond(h3_request, 503, 1);
    }

    int *conn_count = svr_conn_tcp_flow_count_ptr(stream);
    if (conn_count && (uint32_t)*conn_count >= ctx.tcp_max_flows) {
        return svr_tcp_egress_respond(h3_request, 503, 1);
    }

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        return svr_tcp_egress_respond(h3_request, 500, 1);
    }

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(target_port);
    if (inet_pton(AF_INET, target_host, &dst.sin_addr) != 1) {
        /* Unreachable in practice: svr_tcp_egress_acl_allowed already ran
         * inet_pton on this exact string. Guarded anyway rather than
         * trusting a cross-function invariant silently. */
        close(fd);
        return svr_tcp_egress_respond(h3_request, 500, 1);
    }

    svr_tcp_egress_flow_t *ef = calloc(1, sizeof(*ef));
    if (!ef) {
        close(fd);
        return svr_tcp_egress_respond(h3_request, 500, 1);
    }
    ef->fd = fd;
    ef->h3_request = h3_request;
    ef->stream = stream;
    ef->state = EGRESS_FLOW_CONNECTING;
    ef->connect_deadline_us =
        svr_now_us() + (uint64_t)ctx.tcp_connect_timeout_sec * 1000000ULL;
    snprintf(ef->username, sizeof(ef->username), "%s", username ? username : "");

    void **stream_slot = svr_stream_tcp_egress_flow_ptr(stream);
    if (stream_slot) *stream_slot = ef; /* the ONE place this is set (D2) */
    svr_tcp_egress_list_insert(ctx.flow_list_head, ef);

    /* Count exactly once, unconditionally, before the syscall — see the
     * bookkeeping-invariant comment on svr_tcp_egress_flow_destroy. */
    if (conn_count) (*conn_count)++;
    (*ctx.global_fd_count)++;

    int r = connect(fd, (struct sockaddr *)&dst, sizeof(dst));
    if (r == 0) {
        /* Rare: loopback/already-routed targets can complete synchronously. */
        svr_tcp_egress_on_connected(server, ef);
        return 0;
    }
    if (errno != EINPROGRESS) {
        int err = errno;
        TLOG_W(server, "connect-tcp: connect() failed synchronously (errno=%d)", err);
        svr_tcp_egress_fail_connect(server, ef, err);
        return 0;
    }

    if (svr_egress_fd_register(server, fd, 0, 1 /* want_write = connect signal */, ef) !=
        0) {
        TLOG_W(server, "egress_fd_register callback unset — connect-tcp flow will stall "
                       "until the connect timeout fires");
    }
    return 0; /* response deferred until connect completes or times out */
}

int
svr_tcp_egress_on_request(mqvpn_server_t *server, void *stream,
                          xqc_h3_request_t *h3_request, const svr_req_headers_t *hdrs)
{
    /* Same optionality as CONNECT-IP, not stricter: svr_auth_required
     * encodes the exact condition svr_connect_ip_on_request uses (PSK or
     * users configured). An intentionally open server (no PSK, testing/
     * trusted-network deployments) stays open on both protocols. */
    char username[64] = "(global)";
    if (svr_auth_required(server) &&
        svr_auth_check(server, hdrs->auth_token, hdrs->auth_token_len, username,
                       sizeof(username)) != 0) {
        return svr_tcp_egress_respond(h3_request, 403, 1);
    }

    /* The egress ACL below is unconditional regardless of auth: an open
     * (no-PSK) server still gets default-deny-private-ranges protection —
     * only the identity check is optional, not the network-reachability
     * check. An open tunnel can already reach the same destinations via
     * RAW/DGRAM, so connect-tcp adds no new exposure, only a second
     * protocol surface. */
    char target_host[16];
    uint16_t target_port;
    if (svr_tcp_egress_parse_path(hdrs->path, hdrs->path_len, target_host,
                                  sizeof(target_host), &target_port) != 0) {
        return svr_tcp_egress_respond(h3_request, 400, 1);
    }

    if (!svr_tcp_egress_acl_allowed(server, target_host, target_port)) {
        return svr_tcp_egress_respond(h3_request, 403, 1);
    }

    return svr_tcp_egress_start_connect(server, stream, h3_request, target_host,
                                        target_port, username);
}

int
svr_tcp_egress_on_body(mqvpn_server_t *server, void *stream, xqc_h3_request_t *h3_request)
{
    (void)server;
    (void)stream;
    (void)h3_request;
    return 0;
}

/* Relay lands in the next task. Data CAN arrive on an ACTIVE fd (upstream
 * becomes readable, or the platform reports writable for a queued send)
 * before that lands — this must not crash, just drop the event. */
static void
svr_tcp_egress_on_relay_ready(mqvpn_server_t *server, svr_tcp_egress_flow_t *ef,
                              int readable, int writable)
{
    (void)server;
    (void)ef;
    (void)readable;
    (void)writable;
}

void
svr_tcp_egress_fd_ready(mqvpn_server_t *server, int fd, void *fd_ctx, int readable,
                        int writable)
{
    svr_tcp_egress_flow_t *ef = (svr_tcp_egress_flow_t *)fd_ctx;
    if (!server || !ef) return;

    /* ef->fd is the single source of truth for which socket this flow
     * owns; the platform-echoed fd param is advisory only (asserted
     * consistent, then unused). */
    assert(fd == ef->fd);
    (void)fd;

    if (ef->state == EGRESS_FLOW_CONNECTING && writable) {
        int soerr = 0;
        socklen_t len = sizeof(soerr);
        if (getsockopt(ef->fd, SOL_SOCKET, SO_ERROR, &soerr, &len) != 0) soerr = errno;
        if (soerr != 0) {
            svr_tcp_egress_fail_connect(server, ef, soerr);
            return;
        }
        svr_tcp_egress_on_connected(server, ef);
        return;
    }
    svr_tcp_egress_on_relay_ready(server, ef, readable, writable);
}

void
svr_tcp_egress_tick(mqvpn_server_t *server, uint64_t now_us)
{
    if (!server) return;

    svr_tcp_egress_srv_ctx_t ctx;
    svr_get_tcp_egress_ctx(server, &ctx);
    svr_tcp_egress_flow_t *ef = *ctx.flow_list_head;
    while (ef) {
        /* Save next before possibly destroying ef — fail_connect() unlinks
         * and frees it, which would otherwise dereference freed memory on
         * the next loop iteration. */
        svr_tcp_egress_flow_t *next = ef->next;
        if (ef->state == EGRESS_FLOW_CONNECTING && now_us >= ef->connect_deadline_us) {
            svr_tcp_egress_fail_connect(server, ef, ETIMEDOUT);
        }
        ef = next;
    }
}
