// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* Server-side `:protocol == "mqvpn-tcp"` dispatch: real auth reuse, a
 * mandatory default-on egress ACL, non-blocking egress connect() with a
 * configurable timeout, 2xx/4xx/5xx response mapping, the downlink/uplink
 * relay once a flow is ACTIVE, and the close mapping that tears a flow down
 * exactly once regardless of which side notices first (see the
 * destroy-ownership note above svr_tcp_egress_on_relay_error). */

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

/* One relay-loop chunk (both directions) and the lazily-allocated stash
 * buffer size: a single in-flight chunk per direction, matching the
 * client's tcp_lane precedent (downlink_stash is TCP_MSS-sized there; here
 * both directions share a flat 4096 to match the relay loop's stack
 * buffers). */
#define TCP_EGRESS_RELAY_CHUNK 4096

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
static const mqvpn_cidr_entry_t DEFAULT_DENY_V4[] = {
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
    const mqvpn_cidr_entry_t tunnel = {.net = tunnel_net, .mask = tunnel_mask};
    if (mqvpn_cidr_match(&tunnel, ip)) return 0;

    for (int i = 0; i < n_allow; i++) {
        if (mqvpn_cidr_match(&allow[i], ip)) return 1;
    }

    for (size_t i = 0; i < sizeof(DEFAULT_DENY_V4) / sizeof(DEFAULT_DENY_V4[0]); i++) {
        if (mqvpn_cidr_match(&DEFAULT_DENY_V4[i], ip)) return 0;
    }

    for (int i = 0; i < n_deny; i++) {
        if (mqvpn_cidr_match(&deny[i], ip)) return 0;
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

/* svr_log-routed log macros — the only logging path this file has (see
 * the boundary note in mqvpn_server_internal.h). */
#define TLOG_W(server, ...) svr_log((server), MQVPN_LOG_WARN, __VA_ARGS__)
#define TLOG_I(server, ...) svr_log((server), MQVPN_LOG_INFO, __VA_ARGS__)

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
    uint64_t last_activity_us;    /* only meaningful while ACTIVE (the
                                   * CONNECTING sweep uses connect_deadline_us
                                   * instead — see svr_tcp_egress_tick).
                                   * Definition of "activity": bytes actually
                                   * moved in EITHER relay direction —
                                   * downlink send() progress
                                   * (svr_tcp_egress_drain_body,
                                   * svr_tcp_egress_flush_downlink_retry) or
                                   * uplink recv() progress
                                   * (svr_tcp_egress_on_relay_ready,
                                   * svr_tcp_egress_on_h3_writable's stash
                                   * flush). A pure readiness notify that
                                   * moves zero bytes (e.g. a writable event
                                   * that still can't drain the stash) does
                                   * NOT refresh this — that is precisely
                                   * what makes a flow parked by uplink
                                   * backpressure (uplink_withheld=1 with the
                                   * client never reopening its H3 receive
                                   * window) eventually idle-evictable: it has
                                   * no other recovery path. Initialized at
                                   * connect() start and again when the flow
                                   * goes ACTIVE; svr_tcp_egress_tick compares
                                   * it against config.hybrid.tcp_idle_timeout_sec
                                   * (0 = disabled, shared field with the
                                   * client's tcp_lane — see classifier.h). */
    char username[64];            /* sized to match svr_auth_check's out
                                   * buf; consumed by later stats work */

    /* ── Relay state (this task) ──
     *
     * Plain booleans, not the client's high/low-water byte-count scheme
     * (tcp_lane.h's MQVPN_TCP_LANE_BP_*_WATER): the server relays between
     * two syscalls through a fixed 4096B stack buffer with no accumulation
     * phase, so there is nothing to hysteresis over — withhold on ANY
     * EWOULDBLOCK/-XQC_EAGAIN, resume on the very next writable/write-ready
     * signal. Stash buffers are lazily malloc'd (first pause) and freed only
     * in svr_tcp_egress_flow_destroy, matching the client's downlink_stash
     * precedent. Memory bound: 2 * TCP_EGRESS_RELAY_CHUNK (8 KiB) per flow
     * that has EVER paused in either direction, times the global egress fd
     * budget — bounded by egress_fd_budget, not tcp_max_flows, since that's
     * the true worst case (every admitted flow pauses once). */
    int downlink_paused; /* send()-side backpressure: downlink_stash holds
                          * one unsent chunk pulled out of xquic's body_buf
                          * (already destructively consumed — cannot be
                          * re-fetched, so it must live somewhere). */
    uint8_t *downlink_stash;
    size_t downlink_stash_len;
    int fin_received_from_h3;   /* client fin observed (recv_body's *fin) —
                                 * latched once; shutdown(fd, SHUT_WR) may
                                 * still be DEFERRED if downlink_paused. */
    int downlink_shutdown_done; /* shutdown(fd, SHUT_WR) actually issued —
                                 * separate from fin_received_from_h3 so the
                                 * deferred-during-pause case retries exactly
                                 * once when the stash finally drains. */

    int uplink_withheld; /* xquic send-side backpressure (-XQC_EAGAIN or a
                          * partial accept): uplink_stash holds one unsent
                          * chunk already pulled out of the egress socket
                          * via recv() (same "already consumed" hazard as
                          * the downlink direction). want_read is dropped
                          * while this is set — see
                          * svr_tcp_egress_update_fd_interest. */
    uint8_t *uplink_stash;
    size_t uplink_stash_len;
    int egress_eof_seen; /* recv()==0 observed — want_read is dropped
                          * PERMANENTLY for this fd (EOF is level-triggered
                          * readable; re-arming would busy-loop). */
    int uplink_fin_sent; /* send_body(NULL,0,1) succeeded — no more FIN
                          * retries needed. Until this is true and
                          * egress_eof_seen is true, cb_request_write
                          * retries the FIN send every H3-writable notify
                          * (mirrors the client's tcp_lane_uplink_maybe_fin:
                          * a fin-only send is NOT buffered by xquic on
                          * -XQC_EAGAIN, so a dedicated retry is
                          * mandatory, not a redundant safety net). */

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

    free(ef->downlink_stash);
    free(ef->uplink_stash);
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

/* ── Relay: the two byte-shoveling directions plus close mapping ──
 *
 * Naming (do not confuse — each side names relative to ITSELF): "downlink"
 * is bytes FROM the H3 stream (the client's uplink) -> send() to the egress
 * socket. "uplink" is recv() from the egress socket -> send_body() to the
 * client. Every function below is named accordingly.
 *
 * Destroy ownership (decided here, once, for the whole relay stage): a
 * fatal relay error (svr_tcp_egress_on_relay_error) NEVER calls
 * svr_tcp_egress_flow_destroy directly — it only calls
 * xqc_h3_request_close(ef->h3_request) and returns immediately without
 * touching `ef` again. The actual destroy happens exactly once, later,
 * from mqvpn_server.c's h3_request_close_notify (cb_request_close, already
 * wired for the connect-timeout/synchronous-failure paths) OR
 * h3_request_closing_notify (this task's new registration, for a peer
 * RESET_STREAM) — both funnel through the SAME svr_tcp_egress_flow_destroy
 * call, guarded by re-reading the stream's tcp_egress_flow slot fresh each
 * time (destroy() NULLs it), so whichever notify fires first destroys the
 * flow and the other one is a no-op. This matters because
 * xqc_h3_request_close can synchronously re-enter the close-notify callback
 * (verified: xqc_h3_stream_close destroys the h3 stream immediately, inline,
 * when its transport stream already carries XQC_HTTP3_STREAM_FLAG_CLOSED —
 * third_party/xquic/src/http3/xqc_h3_stream.c) — so every call site of
 * on_relay_error in this file is its LAST statement before an unconditional
 * `return`/`break` out of the enclosing function, exactly like the client's
 * tcp_lane_flow_status_t discipline (tcp_lane.c), just collapsed to a
 * simpler "did I just possibly free `ef`? then stop touching it" contract
 * since the server has only one relay-error outcome (no clean-close /
 * abort distinction to track). */
static void
svr_tcp_egress_on_relay_error(mqvpn_server_t *server, svr_tcp_egress_flow_t *ef, int err)
{
    TLOG_W(server, "connect-tcp: relay I/O error (errno=%d) — closing stream", err);
    xqc_h3_request_close(ef->h3_request);
    /* Do NOT touch ef again — see the destroy-ownership note above. */
}

/* ACTIVE-flow idle-timeout eviction (the limits work this file's tick
 * docstring referenced). Same destroy-ownership discipline as
 * on_relay_error above — closes the H3 stream and returns without touching
 * `ef` again, letting the close-notify funnel run the real destroy — but
 * kept as its own function rather than reusing on_relay_error under an
 * errno=0 sentinel: an idle timeout is not an I/O error, and a dedicated log
 * line keeps the two cases distinguishable in server logs. Called only from
 * svr_tcp_egress_tick for a flow already confirmed ACTIVE (CONNECTING flows
 * are gated out by state, not by this function).
 *
 * Log-level split: a plain idle eviction is NORMAL operation (a TCP
 * connection simply went quiet past the configured timeout) — INFO. A flow
 * parked by uplink backpressure (uplink_withheld: the client stopped
 * reading its H3 body and never reopened its receive window; this sweep is
 * that flow's ONLY collector) suggests a misbehaving/stuck client — WARN,
 * with distinct wording so an operator can grep the two apart. The flow's
 * target comes from getpeername on its own connected fd (identical to the
 * connect() target, no extra per-flow state needed); the username was
 * captured at auth time. */
static void
svr_tcp_egress_on_idle_evict(mqvpn_server_t *server, svr_tcp_egress_flow_t *ef,
                             uint32_t idle_timeout_sec)
{
    char peer[64] = "?";
    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);
    if (getpeername(ef->fd, (struct sockaddr *)&sa, &sl) == 0 &&
        sa.sin_family == AF_INET) {
        char ip[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &sa.sin_addr, ip, sizeof(ip)))
            snprintf(peer, sizeof(peer), "%s:%u", ip, (unsigned)ntohs(sa.sin_port));
    }
    if (ef->uplink_withheld) {
        TLOG_W(server,
               "connect-tcp: flow to %s (user %s) parked by client backpressure "
               "(client stopped reading) for over %u s — closing stream",
               peer, ef->username, idle_timeout_sec);
    } else {
        TLOG_I(server,
               "connect-tcp: flow to %s (user %s) idle for over %u s — "
               "closing stream",
               peer, ef->username, idle_timeout_sec);
    }
    xqc_h3_request_close(ef->h3_request);
    /* Do NOT touch ef again — see the destroy-ownership note on
     * on_relay_error above. */
}

/* The ONE place fd interest is computed from flow state (per this task's
 * design note: hand-written (want_read, want_write) pairs at every call
 * site WILL drift). Safe to call liberally/redundantly — every caller here
 * only reaches it with `ef` still alive, and re-registering the same
 * interest twice is a harmless no-op reconfigure (platform_linux.c replaces
 * the libevent event in place). No-ops for a CONNECTING flow: that stage
 * manages its own single want_write=1 "connect signal" registration
 * directly (svr_tcp_egress_start_connect) and this helper must not
 * clobber it before the flow reaches ACTIVE. */
static void
svr_tcp_egress_update_fd_interest(mqvpn_server_t *server, svr_tcp_egress_flow_t *ef)
{
    if (ef->state != EGRESS_FLOW_ACTIVE) return;
    int want_write = ef->downlink_paused ? 1 : 0;
    int want_read = (!ef->uplink_withheld && !ef->egress_eof_seen) ? 1 : 0;
    (void)svr_egress_fd_register(server, ef->fd, want_read, want_write, ef);
}

/* Issue the deferred TX half-close once it's actually safe to: the client's
 * fin must have arrived (fin_received_from_h3) AND nothing may still be
 * sitting in the downlink stash waiting to reach the wire ahead of the FIN
 * (downlink_paused) — shutdown(SHUT_WR) queues the FIN behind whatever the
 * kernel already has buffered from send(), but bytes we haven't send()'d
 * yet (still in our userspace stash) would arrive AFTER a premature FIN,
 * corrupting the stream order / truncating it from the receiver's view.
 * Idempotent via downlink_shutdown_done. Called both right after fin_flag
 * observation (on_body's fin branch) and after a stash flush completes
 * (svr_tcp_egress_flush_downlink_retry) — the latter is what makes the
 * fin-during-pause ordering correct. */
static void
svr_tcp_egress_maybe_shutdown_downlink(svr_tcp_egress_flow_t *ef)
{
    if (!ef->fin_received_from_h3 || ef->downlink_paused || ef->downlink_shutdown_done)
        return;
    shutdown(ef->fd, SHUT_WR);
    ef->downlink_shutdown_done = 1;
}

/* Stash one already-pulled-out-of-xquic chunk (destructively read via
 * recv_body — cannot be re-fetched on failure, so losing it here would
 * silently corrupt the relayed stream) and latch downlink_paused. On a
 * stash allocation failure, fails the flow instead of dropping bytes.
 * Returns 1 if `ef` is still alive, 0 if the alloc-failure path tore it
 * down via on_relay_error (same "0 = ef gone, stop touching it" convention
 * as drain_body/flush_downlink_retry — callers MUST propagate a 0). len is
 * always <= TCP_EGRESS_RELAY_CHUNK (a suffix of the caller's fixed-size
 * stack buffer). */
static int
svr_tcp_egress_stash_downlink(mqvpn_server_t *server, svr_tcp_egress_flow_t *ef,
                              const uint8_t *buf, size_t len)
{
    if (!ef->downlink_stash) {
        ef->downlink_stash = malloc(TCP_EGRESS_RELAY_CHUNK);
        if (!ef->downlink_stash) {
            svr_tcp_egress_on_relay_error(server, ef, ENOMEM);
            return 0;
        }
    }
    memcpy(ef->downlink_stash, buf, len);
    ef->downlink_stash_len = len;
    ef->downlink_paused = 1;
    svr_tcp_egress_update_fd_interest(server, ef);
    return 1;
}

/* Drain the flow's H3 request body into the egress socket. Stops at the
 * first would-block (recv_body returning -XQC_EAGAIN — nothing more
 * buffered right now) or the first send()-side backpressure (stash +
 * pause, mirroring the uplink's EAGAIN-stops-the-loop shape). Handles a
 * partial send() the same as a full EWOULDBLOCK. Returns 1 if `ef` is
 * still alive when this returns, 0 if a fatal error tore it down inside
 * this call (the ONLY way that happens is via svr_tcp_egress_on_relay_error,
 * always the last thing done on that path) — callers that get 0 must not
 * touch `ef` again.
 *
 * Called from three places: the H3 body-read notify (svr_tcp_egress_on_body,
 * only once ACTIVE), the post-flush resume (svr_tcp_egress_flush_downlink_
 * retry, once the downlink stash fully drains — H3 may hold more buffered
 * body that arrived while paused, and the data-notify is NOT guaranteed to
 * re-fire for it on its own, see the report), and the drain-on-connect call
 * from svr_tcp_egress_on_connected (draining anything the client sent
 * before the 200 went out). */
static int
svr_tcp_egress_drain_body(mqvpn_server_t *server, svr_tcp_egress_flow_t *ef)
{
    if (ef->downlink_paused) return 1;

    /* Downlink-activity accounting: bytes that actually reached the egress
     * socket are summed here and folded into last_activity_us ONCE at the
     * "still alive" exits (a per-send() refresh inside the loop would call
     * svr_now_us per 4 KiB chunk for no precision gain — the idle sweep has
     * seconds granularity). The relay-error exits skip the refresh: `ef`
     * may already be freed there (see on_relay_error's contract). */
    size_t moved = 0;
    uint8_t buf[TCP_EGRESS_RELAY_CHUNK];
    for (;;) {
        uint8_t fin = 0;
        ssize_t n = xqc_h3_request_recv_body(ef->h3_request, buf, sizeof(buf), &fin);
        if (n == -XQC_EAGAIN) break; /* drained for now */
        if (n < 0) {
            /* Real recv_body error (not would-block) — fatal for the flow,
             * same routing as on_h3_writable's explicit -XQC_EAGAIN check. */
            svr_tcp_egress_on_relay_error(server, ef, 0);
            return 0;
        }

        if (n > 0) {
            size_t off = 0;
            while (off < (size_t)n) {
                ssize_t sent;
                do {
                    /* MSG_NOSIGNAL: a peer that already fully closed
                     * (RST'd) makes a subsequent send raise SIGPIPE, whose
                     * default action kills the whole process — and this
                     * library owns no signal handlers by design (signal
                     * handling is externalized to the platform/CLI), so
                     * suppression must happen at the syscall. EPIPE still
                     * comes back as the errno and routes to on_relay_error
                     * below. */
                    sent = send(ef->fd, buf + off, (size_t)n - off,
                                MSG_DONTWAIT | MSG_NOSIGNAL);
                } while (sent < 0 && errno == EINTR);
                if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    if (!svr_tcp_egress_stash_downlink(server, ef, buf + off,
                                                       (size_t)n - off)) {
                        return 0; /* ef gone (stash alloc failure) */
                    }
                    if (moved) ef->last_activity_us = svr_now_us();
                    return 1;
                }
                if (sent <= 0) {
                    /* Real error, or a spurious 0-length send — never spin
                     * on either. */
                    svr_tcp_egress_on_relay_error(server, ef, sent < 0 ? errno : 0);
                    return 0;
                }
                moved += (size_t)sent;
                off += (size_t)sent;
            }
        }

        if (fin) {
            ef->fin_received_from_h3 = 1;
            svr_tcp_egress_maybe_shutdown_downlink(ef);
            break;
        }
        if (n == 0) break; /* defensive: contract says n==0 implies fin */
    }
    if (moved) ef->last_activity_us = svr_now_us();
    return 1;
}

/* Re-send() the flow's one stashed downlink chunk once the egress fd
 * reports writable. On a full drain: clears the pause, performs the
 * deferred shutdown(SHUT_WR) if the client's fin arrived while paused (see
 * svr_tcp_egress_maybe_shutdown_downlink's ordering note), recomputes fd
 * interest, and re-runs the body drain loop in case xquic is holding more
 * buffered body that arrived during the pause. Returns 1 if `ef` survives,
 * 0 if a fatal write error tore it down (last action on that path — see
 * on_relay_error). */
static int
svr_tcp_egress_flush_downlink_retry(mqvpn_server_t *server, svr_tcp_egress_flow_t *ef)
{
    size_t off = 0;
    while (off < ef->downlink_stash_len) {
        ssize_t sent;
        do {
            /* MSG_NOSIGNAL — same SIGPIPE-suppression rationale as the
             * drain_body send site above. */
            sent = send(ef->fd, ef->downlink_stash + off, ef->downlink_stash_len - off,
                        MSG_DONTWAIT | MSG_NOSIGNAL);
        } while (sent < 0 && errno == EINTR);
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        if (sent <= 0) {
            svr_tcp_egress_on_relay_error(server, ef, sent < 0 ? errno : 0);
            return 0;
        }
        off += (size_t)sent;
    }
    if (off == 0) return 1; /* still fully blocked; nothing changed */
    /* Downlink activity: some (or all) of the stash actually flushed to the
     * socket — a call that returns here with off==0 above must NOT reach
     * this line (see last_activity_us's field comment on why a no-progress
     * readiness notify must not refresh it). */
    ef->last_activity_us = svr_now_us();
    if (off < ef->downlink_stash_len) {
        memmove(ef->downlink_stash, ef->downlink_stash + off,
                ef->downlink_stash_len - off);
        ef->downlink_stash_len -= off;
        return 1; /* partial drain; stays paused for the next writable event */
    }

    ef->downlink_stash_len = 0;
    ef->downlink_paused = 0;
    svr_tcp_egress_maybe_shutdown_downlink(ef);
    svr_tcp_egress_update_fd_interest(server, ef);
    return svr_tcp_egress_drain_body(server, ef);
}

/* Attempt (or retry) the uplink pure-FIN send once the egress socket has
 * seen EOF. CRITICAL xquic fact (verified against the vendored source,
 * mirroring the client's tcp_lane_uplink_maybe_fin citation trail): a
 * fin-only xqc_h3_request_send_body is NOT buffered by xquic across an
 * -XQC_EAGAIN return on the 1-RTT send path — nothing will flush it
 * automatically, so retrying from every subsequent H3-writable notify
 * (svr_tcp_egress_on_h3_writable) is mandatory, not defensive redundancy.
 * Idempotent via uplink_fin_sent. */
static void
svr_tcp_egress_try_uplink_fin(mqvpn_server_t *server, svr_tcp_egress_flow_t *ef)
{
    if (ef->uplink_fin_sent) return;
    ssize_t r = xqc_h3_request_send_body(ef->h3_request, NULL, 0, 1);
    if (r == -XQC_EAGAIN) return; /* retried on the next H3-writable notify */
    if (r < 0) {
        svr_tcp_egress_on_relay_error(server, ef, 0);
        return;
    }
    ef->uplink_fin_sent = 1;
}

/* Stash one already-recv()'d-from-the-socket chunk (same "already consumed,
 * cannot re-fetch" hazard as the downlink direction) that xquic's send_body
 * only partially accepted (or -XQC_EAGAIN'd entirely — the caller
 * normalizes that to a zero-byte accept before calling this). Drops
 * want_read via the interest helper: xquic's own per-stream flow control
 * then backpressures whatever is upstream of the egress socket, mirroring
 * the downlink direction's backpressure the other way. Returns 1 if `ef`
 * is still alive, 0 if the alloc-failure path tore it down — same boolean
 * convention as svr_tcp_egress_stash_downlink. */
static int
svr_tcp_egress_stash_uplink(mqvpn_server_t *server, svr_tcp_egress_flow_t *ef,
                            const uint8_t *buf, size_t len)
{
    if (!ef->uplink_stash) {
        ef->uplink_stash = malloc(TCP_EGRESS_RELAY_CHUNK);
        if (!ef->uplink_stash) {
            svr_tcp_egress_on_relay_error(server, ef, ENOMEM);
            return 0;
        }
    }
    memcpy(ef->uplink_stash, buf, len);
    ef->uplink_stash_len = len;
    ef->uplink_withheld = 1;
    svr_tcp_egress_update_fd_interest(server, ef);
    return 1;
}

/* H3-writable notify dispatch (mqvpn_server.c's cb_request_write delegates
 * here for SVR_STREAM_ROLE_CONNECT_TCP streams — one entry point, per this
 * task's boundary rule, rather than mqvpn_server.c poking flow fields it
 * can't even see the layout of). Flushes the uplink retry stash (FIFO of
 * one chunk; stops at the first -XQC_EAGAIN, idempotent under repeated
 * writable notifies) and, once drained, re-arms want_read; then retries the
 * pending uplink FIN if the egress side has already hit EOF. `stream` is
 * the opaque svr_stream_t* the H3 callback was invoked with. No-ops on an
 * unknown/already-gone flow (stream_slot NULL or already-destroyed). */
void
svr_tcp_egress_on_h3_writable(mqvpn_server_t *server, void *stream)
{
    void **slot = svr_stream_tcp_egress_flow_ptr(stream);
    svr_tcp_egress_flow_t *ef = slot ? (svr_tcp_egress_flow_t *)*slot : NULL;
    if (!ef) return;

    if (ef->uplink_withheld) {
        size_t off = 0;
        while (off < ef->uplink_stash_len) {
            ssize_t sent = xqc_h3_request_send_body(
                ef->h3_request, ef->uplink_stash + off, ef->uplink_stash_len - off, 0);
            if (sent == -XQC_EAGAIN) break;
            if (sent < 0) {
                svr_tcp_egress_on_relay_error(server, ef, 0);
                return;
            }
            off += (size_t)sent;
        }
        /* Uplink activity: guarded by off > 0 so a notify that drains
         * nothing (still fully -XQC_EAGAIN'd) does not refresh
         * last_activity_us — same "no progress, no refresh" rule as the
         * downlink stash flush above. */
        if (off > 0) ef->last_activity_us = svr_now_us();
        if (off < ef->uplink_stash_len) {
            memmove(ef->uplink_stash, ef->uplink_stash + off, ef->uplink_stash_len - off);
            ef->uplink_stash_len -= off;
            return; /* still can't drain fully; retried on the next notify */
        }
        ef->uplink_stash_len = 0;
        ef->uplink_withheld = 0;
        svr_tcp_egress_update_fd_interest(server, ef); /* re-arm want_read */
    }

    if (ef->egress_eof_seen && !ef->uplink_fin_sent) {
        svr_tcp_egress_try_uplink_fin(server, ef);
    }
}

/* Flips a CONNECTING flow to ACTIVE and arms real read interest — the
 * relay stage (above) can now actually consume data, so want_read=1 is
 * correct here (an earlier task's interim registered (0,0): no relay yet,
 * and arming want_read against a no-op stub would busy-loop a
 * level-triggered reactor on a server-speaks-first upstream or an upstream
 * EOF). Sends the real 200 with fin=0 (stream stays open, relay traffic
 * rides it), then drains anything the client already sent before the 200
 * went out — legal per RFC 9114 (the client may speak before the response
 * arrives), and NOT guaranteed to be re-delivered by a later data-notify:
 * verified against xqc_h3_request_on_recv_body (third_party/xquic), the
 * read-notify callback only fires when NEW body data is appended to
 * body_buf, not merely because body_buf is non-empty — a body chunk that
 * arrived while svr_tcp_egress_on_body was a no-op (state != ACTIVE, so it
 * never called recv_body) would sit undrained forever if the client never
 * sends anything further before waiting for the response. */
static void
svr_tcp_egress_on_connected(mqvpn_server_t *server, svr_tcp_egress_flow_t *ef)
{
    ef->state = EGRESS_FLOW_ACTIVE;
    ef->last_activity_us = svr_now_us(); /* idle-sweep clock starts now */
    svr_tcp_egress_update_fd_interest(server, ef);
    svr_tcp_egress_respond(ef->h3_request, 200, 0);
    svr_tcp_egress_drain_body(server, ef);
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
    /* Meaningless until ACTIVE (svr_tcp_egress_on_connected re-latches it to
     * the moment the flow actually becomes idle-sweep-eligible), but
     * initialized here too rather than left at calloc's 0 — 0 would read as
     * "idle since the epoch" if anything ever inspected it before that
     * transition. */
    ef->last_activity_us = svr_now_us();
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

/* H3 body-read notify. h3_request is unused once we have `ef` (the flow
 * caches its own h3_request pointer at connect time) but kept in the
 * signature to match the header/dispatch call site. Never returns negative
 * — an H3 notify path returning < 0 kills the WHOLE h3 connection, not just
 * this stream, so every failure here routes through
 * svr_tcp_egress_on_relay_error (closes just this request) instead. */
int
svr_tcp_egress_on_body(mqvpn_server_t *server, void *stream, xqc_h3_request_t *h3_request)
{
    (void)h3_request;
    void **slot = svr_stream_tcp_egress_flow_ptr(stream);
    svr_tcp_egress_flow_t *ef = slot ? (svr_tcp_egress_flow_t *)*slot : NULL;
    if (!ef)
        return 0; /* role==CONNECT_TCP but no flow: rejected at request
                   * time, or already torn down — nothing to feed. */

    if (ef->state != EGRESS_FLOW_ACTIVE) {
        /* CONNECTING: the client is legally allowed to send body before our
         * 200 arrives, but there is no egress socket yet to send() it to.
         * Leave it buffered in xquic — svr_tcp_egress_on_connected drains it
         * explicitly once the flow goes ACTIVE (see that function's comment
         * for why relying on a later data-notify re-fire is NOT safe). */
        return 0;
    }

    (void)svr_tcp_egress_drain_body(server, ef);
    return 0;
}

/* fd-ready dispatch once the flow is ACTIVE (svr_tcp_egress_fd_ready routes
 * the CONNECTING/connect-completion case elsewhere before reaching here).
 * `readable`/`writable` are the platform's level-triggered signals for
 * ef->fd (the egress socket) — see tcp_egress.h's on_request docstring for
 * the fd-interest contract. */
static void
svr_tcp_egress_on_relay_ready(mqvpn_server_t *server, svr_tcp_egress_flow_t *ef,
                              int readable, int writable)
{
    if (writable && ef->downlink_paused) {
        if (!svr_tcp_egress_flush_downlink_retry(server, ef)) return; /* ef destroyed */
    }

    /* Busy-spin lesson (mqproxy precedent): while uplink_withheld, want_read
     * is already 0 via the interest helper, so `readable` shouldn't even
     * re-fire for this reason — guarded explicitly anyway, belt-and-
     * suspenders against a platform that reports a stale/edge-leftover
     * event. */
    if (readable && !ef->uplink_withheld) {
        uint8_t buf[TCP_EGRESS_RELAY_CHUNK];
        ssize_t n;
        for (;;) {
            do {
                n = recv(ef->fd, buf, sizeof(buf), MSG_DONTWAIT);
            } while (n < 0 && errno == EINTR);
            if (n <= 0) break;
            /* Uplink activity: bytes actually arrived from the egress
             * socket, independent of whether xquic accepts them immediately
             * or they end up stashed below (see last_activity_us's field
             * comment — the recv() itself is the "bytes moved" event). */
            ef->last_activity_us = svr_now_us();
            ssize_t sent = xqc_h3_request_send_body(ef->h3_request, buf, (size_t)n, 0);
            if (sent == -XQC_EAGAIN) sent = 0; /* normalize: nothing accepted */
            if (sent < 0) {
                svr_tcp_egress_on_relay_error(server, ef, 0);
                return;
            }
            if ((size_t)sent < (size_t)n) {
                /* Status legally discarded: this caller returns immediately
                 * on BOTH outcomes (paused-alive or gone), touching ef no
                 * further either way. */
                (void)svr_tcp_egress_stash_uplink(server, ef, buf + sent,
                                                  (size_t)n - (size_t)sent);
                return; /* the ONLY break-equivalent exit of this loop */
            }
        }
        if (n == 0) {
            /* Pure EOF: recv()==0 is level-triggered readable — drop
             * want_read PERMANENTLY for this fd (via the interest helper)
             * or a level-triggered reactor busy-loops on it forever. */
            ef->egress_eof_seen = 1;
            svr_tcp_egress_update_fd_interest(server, ef);
            svr_tcp_egress_try_uplink_fin(server, ef);
            return;
        }
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            svr_tcp_egress_on_relay_error(server, ef, errno);
            return;
        }
        /* n < 0 && EAGAIN/EWOULDBLOCK: nothing more to read right now. */
    }

    svr_tcp_egress_update_fd_interest(server, ef);
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
    /* 0 = disabled (shared client/server field — see classifier.h's
     * tcp_idle_timeout_sec comment). Computed once per tick, mirroring the
     * client's mqvpn_tcp_lane_tick idiom. */
    int idle_evict_enabled = ctx.tcp_idle_timeout_sec != 0;
    uint64_t idle_us = (uint64_t)ctx.tcp_idle_timeout_sec * 1000000ULL;
    svr_tcp_egress_flow_t *ef = *ctx.flow_list_head;
    while (ef) {
        /* Save next before possibly destroying/closing ef — fail_connect()
         * unlinks and frees it, and on_idle_evict() may synchronously
         * re-enter the close-notify funnel that does the same (see the
         * destroy-ownership note above svr_tcp_egress_on_relay_error) —
         * either way, dereferencing ef again after would be a use-after-free
         * on the next loop iteration. */
        svr_tcp_egress_flow_t *next = ef->next;
        if (ef->state == EGRESS_FLOW_CONNECTING) {
            /* CONNECTING flows are never idle-evicted: they use
             * connect_deadline_us, not last_activity_us (which isn't even
             * meaningful yet — see that field's comment). */
            if (now_us >= ef->connect_deadline_us) {
                svr_tcp_egress_fail_connect(server, ef, ETIMEDOUT);
            }
        } else if (idle_evict_enabled && now_us > ef->last_activity_us &&
                   now_us - ef->last_activity_us > idle_us) {
            /* Wraparound-safe age test (now_us > last_activity_us guard),
             * same form as the client's mqvpn_tcp_lane_tick sweep. */
            svr_tcp_egress_on_idle_evict(server, ef, ctx.tcp_idle_timeout_sec);
        }
        ef = next;
    }
}
