// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * mqvpn_server.c — Server lifecycle, xquic engine, MASQUE CONNECT-IP (server)
 *
 * Part of libmqvpn. No platform I/O — all I/O via callbacks.
 */

#include "libmqvpn.h"
#include "mqvpn_internal.h"
#include "mqvpn_scheduler.h"
#include "mqvpn_server_internal.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  include <process.h>
#  undef EAGAIN
#  define EAGAIN WSAEWOULDBLOCK
#  undef EWOULDBLOCK
#  define EWOULDBLOCK WSAEWOULDBLOCK
#  undef EINTR
#  define EINTR WSAEINTR
#  undef errno
#  define errno WSAGetLastError()
#else
#  include <unistd.h>
#  include <sys/time.h>
#  include <sys/resource.h>
#  include <arpa/inet.h>
#  include <pthread.h>
#endif
#ifndef _WIN32
#  include <errno.h>
#endif
#include <inttypes.h>
#include <limits.h>
#include <time.h>
#include <assert.h>

#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>

#include "addr_pool.h"
#include "auth.h"
#include "flow_sched.h"
#include "icmp.h"
#include "reorder.h"
#include "reorder_gate.h"
#include "reorder_rx.h"
#include "reorder_tx.h"
#ifdef MQVPN_HYBRID_TCP_EGRESS_ENABLED
#  include "hybrid/tcp_egress.h"
#endif

/* ─── Constants ─── */

#define PACKET_BUF_SIZE  65536
#define MASQUE_FRAME_BUF (PACKET_BUF_SIZE + 16)
#define MAX_CAPSULE_BUF  65536

/* ─── Forward declarations ─── */

typedef struct svr_conn_s svr_conn_t;
typedef struct svr_stream_s svr_stream_t;

/* ─── Internal types ─── */

struct svr_conn_s {
    mqvpn_server_t *server;
    xqc_h3_conn_t *h3_conn;
    xqc_cid_t cid;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addrlen;

    /* MASQUE session */
    uint64_t masque_stream_id;
    struct in_addr assigned_ip;
    struct in6_addr assigned_ip6;
    int has_v6;
    int tunnel_established;
    size_t dgram_mss;
    uint64_t dgram_lost_cnt;
    uint64_t dgram_acked_cnt;

    /* Auth identity (set on CONNECT-IP auth success) */
    char username[64];
    uint64_t connected_at_us;

    /* Flow-aware reorder shim (§5). Created on accept when cfg.reorder.mode
     * != OFF, freed on conn teardown. peer_reorder_supported is set when the
     * client advertised mqvpn-reorder in its CONNECT-IP request (§19.3). */
    mqvpn_reorder_tx_t *reorder_tx;
    mqvpn_reorder_rx_t *reorder_rx;
    int peer_reorder_supported;

#ifdef MQVPN_HYBRID_TCP_EGRESS_ENABLED
    int tcp_flow_count; /* per-session cap enforcement lands with the
                         * server-side limits work — no 5-tuple table needed
                         * server-side per Design Decision D2. */
#endif
};

/* Forward decl: reorder RX deliver trampoline (defined near the datagram
 * callbacks) — referenced earlier in cb_h3_conn_create when engines are made. */
static void svr_reorder_deliver(const uint8_t *pkt, size_t len, void *ctx);

/* Role of an inbound H3 request stream, decided at header parse.
 * Unrecognized requests keep ROLE_UNKNOWN, which now gets an explicit 501
 * (see cb_request_read) instead of the historical capsule fall-through. */
typedef enum {
    SVR_STREAM_ROLE_UNKNOWN = 0,
    SVR_STREAM_ROLE_CONNECT_IP,
#ifdef MQVPN_HYBRID_TCP_EGRESS_ENABLED
    SVR_STREAM_ROLE_CONNECT_TCP,
#endif
} svr_stream_role_t;

struct svr_stream_s {
    svr_conn_t *conn;
    xqc_h3_request_t *h3_request;
    svr_stream_role_t role;
    int header_sent;
    uint8_t *capsule_buf;
    size_t capsule_len;
    size_t capsule_cap;

#ifdef MQVPN_HYBRID_TCP_EGRESS_ENABLED
    /* Per D2, xqc_h3_request_t's user_data slot stays svr_stream_t*
     * everywhere; per-flow egress state hangs off THIS field instead of
     * ever calling xqc_h3_request_set_user_data() a second time. */
    void *tcp_egress_flow; /* svr_tcp_egress_flow_t*, opaque here — only
                            * tcp_egress.c casts it. */
#endif
};

/* ─── Server handle (opaque mqvpn_server_t) ─── */

struct mqvpn_server_s {
    /* Config (deep copy) */
    mqvpn_config_t config;
    mqvpn_server_callbacks_t cbs;
    void *user_ctx;

    /* xquic engine */
    xqc_engine_t *engine;

    /* UDP socket (provided by platform via set_socket_fd) */
    int udp_fd;
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;

    /* Address pool */
    mqvpn_addr_pool_t pool;

    /* Session table: indexed by IP offset (1-254) within subnet */
    svr_conn_t *sessions[MQVPN_ADDR_POOL_MAX + 1];
    int n_sessions;
    int max_clients;

    /* Backpressure */
    int tun_paused;
    uint64_t tun_drop_cnt;

    /* Timer: next wake (from xquic set_event_timer) */
    uint64_t next_wake_us;

    /* Actual TUN device MTU (set at startup) */
    int tun_mtu;

    /* ICMP PTB rate limit */
    mqvpn_ptb_bucket_t ptb_bucket;

    /* Stats */
    uint64_t bytes_tx;
    uint64_t bytes_rx;

    /* Server-wide datagram counters (aggregated across all sessions). */
    uint64_t dgram_sent;
    uint64_t dgram_recv;
    uint64_t dgram_lost;
    uint64_t dgram_acked;
    /* Set ONCE in mqvpn_server_create after calloc; never re-written.
     * mqvpn_server_uptime_seconds() uses (now_us() - boot_us) / 1e6. */
    uint64_t boot_us;

    /* Egress fd budget, computed ONCE in mqvpn_server_new and intentionally
     * frozen: the platform sizes its fd->event registry from this value at
     * startup, so admission (tcp_egress.c's 503 cap check) must use the
     * same snapshot — recomputing per call would let a runtime setrlimit
     * grow admission past the fixed registry (flows admitted but never
     * polled). min(rlimit_nofile - reserve, config.hybrid.tcp_max_global_flows
     * [TcpMaxGlobalFlows / "tcp_max_global_flows"]) — see
     * svr_compute_egress_fd_budget. */
    int egress_fd_budget;

    /* Log filtering */
    mqvpn_log_level_t log_level;

    int started;

#ifdef MQVPN_HYBRID_TCP_EGRESS_ENABLED
    /* Connect-stage bookkeeping for src/hybrid/tcp_egress.c: STORAGE only.
     * Contents are mutated exclusively by tcp_egress.c through the bundled
     * ctx accessor in mqvpn_server_internal.h (svr_get_tcp_egress_ctx) —
     * this file never reads or writes them directly.
     * tcp_egress_flow_list_head is the head of tcp_egress.c's intrusive
     * doubly-linked (D3) list; the struct is forward-declared in
     * mqvpn_server_internal.h and defined only in tcp_egress.c, so the
     * pointer is typed but the layout stays opaque here. */
    int tcp_egress_global_fd_count;
    /* Cumulative counters (never decrement), same STORAGE-only contract as
     * tcp_egress_global_fd_count above — mutated only by tcp_egress.c via
     * svr_get_tcp_egress_ctx. flows_total_opened counts every admitted
     * egress flow; flows_rejected_cap counts every SYN refused by a cap
     * (503) — the global fd-budget cap and the per-session tcp_max_flows
     * cap, NOT ACL 403s or 5xx syscall failures. Surfaced as get_stats'
     * tcp_flows_total / tcp_flows_rejected. */
    uint64_t tcp_egress_flows_total_opened;
    uint64_t tcp_egress_flows_rejected_cap;
    struct svr_tcp_egress_flow_s *tcp_egress_flow_list_head;
#endif

    /* Debug: tick thread assertion */
#ifndef NDEBUG
#  ifdef _WIN32
    DWORD owner_thread;
#  else
    pthread_t owner_thread;
#  endif
    int owner_thread_set;
#endif
};

/* ─── Helpers ─── */

static const char *
mqvpn_scheduler_label(int s)
{
    switch (s) {
    case MQVPN_SCHED_MINRTT: return "minrtt";
    case MQVPN_SCHED_WLB: return "wlb";
    case MQVPN_SCHED_BACKUP_FEC: return "backup_fec";
    case MQVPN_SCHED_WLB_UDP_PIN: return "wlb_udp_pin";
    default: return "unknown";
    }
}

static uint64_t
now_us(void)
{
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    return t / 10 - 11644473600000000ULL;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;
#endif
}

/* One-shot at mqvpn_server_new (rlimit-derived headroom under the
 * config-supplied cap, config.hybrid.tcp_max_global_flows — TcpMaxGlobalFlows
 * in INI/JSON, MQVPN_TCP_MAX_GLOBAL_FLOWS_DEFAULT if unset); the result is
 * stored in s->egress_fd_budget and intentionally never recomputed — see
 * that field's comment for the admission/registry non-divergence rationale.
 * `configured_max` is a plain uint32_t (not the whole config struct) so this
 * stays a pure, easily-unit-testable function of its input. */
static int
svr_compute_egress_fd_budget(uint32_t configured_max)
{
    int budget = (configured_max > (uint32_t)INT_MAX) ? INT_MAX : (int)configured_max;
#ifndef _WIN32
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY &&
        rl.rlim_cur <= (rlim_t)LLONG_MAX) {
        /* Widen before subtracting/comparing: rlim_cur is unsigned and may
         * exceed int range; the guards above keep the cast well-defined. */
        long long headroom = (long long)rl.rlim_cur - 64;
        if (headroom < 0) headroom = 0;
        if (headroom < budget) budget = (int)headroom;
    }
#endif
    if (budget < 0) budget = 0;
    return budget;
}

static int64_t
now_ms_mono(void)
{
#ifdef _WIN32
    LARGE_INTEGER freq, cnt;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&cnt);
    return (int64_t)(cnt.QuadPart * 1000 / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

#ifndef _MSC_VER
static void server_log(mqvpn_server_t *s, mqvpn_log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
#endif

#include "mqvpn_conn_settings.h"

static void
server_log(mqvpn_server_t *s, mqvpn_log_level_t level, const char *fmt, ...)
{
    if (!s->cbs.log || level < s->log_level) return;
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    s->cbs.log(level, buf, s->user_ctx);
}

#define LOG_D(s, ...) server_log(s, MQVPN_LOG_DEBUG, __VA_ARGS__)
#define LOG_I(s, ...) server_log(s, MQVPN_LOG_INFO, __VA_ARGS__)
#define LOG_W(s, ...) server_log(s, MQVPN_LOG_WARN, __VA_ARGS__)
#define LOG_E(s, ...) server_log(s, MQVPN_LOG_ERROR, __VA_ARGS__)

#ifndef NDEBUG
#  ifdef _WIN32
#    define ASSERT_TICK_THREAD(s)                                   \
        do {                                                        \
            if (!(s)->owner_thread_set) {                           \
                (s)->owner_thread = GetCurrentThreadId();           \
                (s)->owner_thread_set = 1;                          \
            } else {                                                \
                assert((s)->owner_thread == GetCurrentThreadId() && \
                       "mqvpn_server: called from wrong thread");   \
            }                                                       \
        } while (0)
#  else
#    define ASSERT_TICK_THREAD(s)                                          \
        do {                                                               \
            if (!(s)->owner_thread_set) {                                  \
                (s)->owner_thread = pthread_self();                        \
                (s)->owner_thread_set = 1;                                 \
            } else {                                                       \
                assert(pthread_equal((s)->owner_thread, pthread_self()) && \
                       "mqvpn_server: called from wrong thread");          \
            }                                                              \
        } while (0)
#  endif
#else
#  define ASSERT_TICK_THREAD(s) ((void)0)
#endif

static void
svr_log_conn_stats(mqvpn_server_t *s, const char *tag, const xqc_cid_t *cid)
{
    if (!s->engine || !cid) return;
    xqc_conn_stats_t st = xqc_conn_get_stats(s->engine, cid);
    LOG_I(s,
          "%s: send=%u recv=%u lost=%u lost_dgram=%u srtt=%.2fms "
          "min_rtt=%.2fms inflight=%" PRIu64 " app_bytes=%" PRIu64
          " standby_bytes=%" PRIu64 " mp_state=%d "
          "fec_enable=%u fec_send=%u fec_recover=%u",
          tag, st.send_count, st.recv_count, st.lost_count, st.lost_dgram_count,
          (double)st.srtt / 1000.0, (double)st.min_rtt / 1000.0, st.inflight_bytes,
          st.total_app_bytes, st.standby_path_app_bytes, st.mp_state, st.enable_fec,
          st.send_fec_cnt, st.fec_recover_pkt_cnt);
    free(st.paths_info);
}

/* ─── ICMP PTB rate limiter ───
 * Thin wrapper around the shared bucket (src/reorder_gate.h, also used by
 * mqvpn_client.c) so the many call sites below stay untouched; only the
 * struct field and the refill logic itself moved. */

static int
ptb_rate_allow(mqvpn_server_t *s)
{
    return mqvpn_ptb_bucket_allow(&s->ptb_bucket, now_ms_mono());
}

/* ─── Thin wrapper: send ICMP packet via MASQUE datagram to client ─── */

static void
send_icmp_via_datagram(const uint8_t *pkt, size_t len, void *ctx)
{
    svr_conn_t *conn = (svr_conn_t *)ctx;
    uint8_t frame[1400];
    size_t fw = 0;
    xqc_int_t xret = xqc_h3_ext_masque_frame_udp(frame, sizeof(frame), &fw,
                                                 conn->masque_stream_id, pkt, len);
    if (xret == XQC_OK) {
        uint64_t dgram_id;
        xqc_int_t sret = xqc_h3_ext_datagram_send(conn->h3_conn, frame, fw, &dgram_id,
                                                  XQC_DATA_QOS_LOW);
        if (sret == XQC_OK) conn->server->dgram_sent++;
    }
}

/* ================================================================
 *  xquic engine callbacks
 * ================================================================ */

static void
cb_set_event_timer(xqc_usec_t wake_after, void *user_data)
{
    mqvpn_server_t *s = (mqvpn_server_t *)user_data;
    s->next_wake_us = wake_after;
}

static void
cb_xqc_log_write(xqc_log_level_t lvl, const void *buf, size_t size, void *user_data)
{
    mqvpn_server_t *s = (mqvpn_server_t *)user_data;
    if (!s->cbs.log) return;

    /* Reverse map: xquic→mqvpn for display severity. xquic enum is
     * REPORT=0, FATAL=1, ERROR=2, WARN=3, STATS=4, INFO=5, DEBUG=6.
     * This is intentionally NOT the inverse of the forward map below
     * (the engine-threshold setting near the bottom of this file) — the
     * forward map shifts INFO→WARN to suppress xquic's per-packet noise
     * at the engine level; this reverse map keeps incoming severity
     * honest so a real xquic warning is shown as a warning, not
     * relabelled as INFO. Don't symmetrize the two. */
    mqvpn_log_level_t ml;
    switch (lvl) {
    case XQC_LOG_REPORT:
    case XQC_LOG_FATAL:
    case XQC_LOG_ERROR: ml = MQVPN_LOG_ERROR; break;
    case XQC_LOG_WARN: ml = MQVPN_LOG_WARN; break;
    case XQC_LOG_STATS:
    case XQC_LOG_INFO: ml = MQVPN_LOG_INFO; break;
    case XQC_LOG_DEBUG:
    default: ml = MQVPN_LOG_DEBUG; break;
    }

    if (ml < s->log_level) return;

    char msg[512];
    snprintf(msg, sizeof(msg), "[xquic] %.*s", (int)size, (const char *)buf);
    s->cbs.log(ml, msg, s->user_ctx);
}

/* ─── UDP send helper ─── */

static ssize_t
svr_do_send(mqvpn_server_t *s, const unsigned char *buf, size_t size,
            const struct sockaddr *peer, socklen_t peerlen)
{
    if (s->udp_fd < 0) return XQC_SOCKET_ERROR;
    ssize_t res;
    do {
        /* Winsock sendto() len is int; cast silences C4267 under /WX (size<=MTU). */
        res = sendto(s->udp_fd, buf, (int)size, 0, peer, peerlen);
    } while (res < 0 && errno == EINTR);
    if (res < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return XQC_SOCKET_EAGAIN;
        LOG_E(s, "sendto: %s", strerror(errno));
        return XQC_SOCKET_ERROR;
    }
    s->bytes_tx += (uint64_t)res;
    return res;
}

/* ─── xquic transport callbacks ─── */

static ssize_t
cb_write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer,
                socklen_t peerlen, void *conn_user_data)
{
    svr_conn_t *conn = (svr_conn_t *)conn_user_data;
    return svr_do_send(conn->server, buf, size, peer, peerlen);
}

static ssize_t
cb_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
                   const struct sockaddr *peer, socklen_t peerlen, void *conn_user_data)
{
    (void)path_id;
    return cb_write_socket(buf, size, peer, peerlen, conn_user_data);
}

static ssize_t
cb_write_before_accept(const unsigned char *buf, size_t size, const struct sockaddr *peer,
                       socklen_t peerlen, void *user_data)
{
    mqvpn_server_t *s = (mqvpn_server_t *)user_data;
    return svr_do_send(s, buf, size, peer, peerlen);
}

static int
cb_accept(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid,
          void *user_data)
{
    (void)engine;
    (void)conn;
    (void)cid;
    mqvpn_server_t *s = (mqvpn_server_t *)user_data;
    LOG_I(s, "connection accepted");
    return 0;
}

static void
cb_refuse(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid,
          void *user_data)
{
    (void)engine;
    (void)conn;
    (void)cid;
    (void)user_data;
    /* No per-connection context is allocated in cb_accept.
     * svr_conn_t is allocated in cb_h3_conn_create and freed in cb_h3_conn_close.
     * If refuse fires before H3 setup, user_data is the engine user_data
     * (mqvpn_server_t *), which must NOT be freed. */
}

static ssize_t
cb_stateless_reset(const unsigned char *buf, size_t size, const struct sockaddr *peer,
                   socklen_t peerlen, const struct sockaddr *local, socklen_t locallen,
                   void *user_data)
{
    (void)local;
    (void)locallen;
    mqvpn_server_t *s = (mqvpn_server_t *)user_data;
    return svr_do_send(s, buf, size, peer, peerlen);
}

/* ─── Multipath callbacks ─── */

static int
cb_path_created(xqc_connection_t *conn, const xqc_cid_t *cid, uint64_t path_id,
                void *conn_user_data)
{
    (void)conn;
    (void)cid;
    svr_conn_t *sc = (svr_conn_t *)conn_user_data;
    LOG_I(sc->server, "new path created: path_id=%" PRIu64, path_id);
    return 0;
}

static void
cb_path_removed(const xqc_cid_t *cid, uint64_t path_id, void *conn_user_data)
{
    (void)cid;
    svr_conn_t *sc = (svr_conn_t *)conn_user_data;
    LOG_I(sc->server, "path removed: path_id=%" PRIu64, path_id);
}

/* ================================================================
 *  H3 connection callbacks
 * ================================================================ */

static int
cb_h3_conn_create(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *conn_user_data)
{
    /* For server-side connections, xquic passes engine_user_data
     * as conn_user_data initially (set during xqc_engine_create). */
    mqvpn_server_t *s = (mqvpn_server_t *)conn_user_data;

    svr_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) return -1;
    conn->server = s;
    conn->h3_conn = h3_conn;
    /* cid may be misaligned inside xquic's internal structures */
    memcpy(&conn->cid, (const void *)cid, sizeof(conn->cid));

    xqc_h3_conn_set_user_data(h3_conn, conn);
    xqc_h3_ext_datagram_set_user_data(h3_conn, conn);
    xqc_h3_conn_get_peer_addr(h3_conn, (struct sockaddr *)&conn->peer_addr,
                              sizeof(conn->peer_addr), &conn->peer_addrlen);

    /* §5: create the reorder shim engines when locally enabled. TX stamping
     * stays gated on peer_reorder_supported (set when the client advertises in
     * its CONNECT-IP request), so until then everything is sent RAW. The hash
     * seeds need not match the peer (§6.2); derive from wall-clock time. */
    if (s->config.reorder.mode != MQVPN_REORDER_OFF) {
        uint64_t seed_base = now_us();
        conn->reorder_tx = mqvpn_reorder_tx_new(&s->config.reorder, seed_base);
        conn->reorder_rx = mqvpn_reorder_rx_new(
            &s->config.reorder, seed_base ^ 0x9e3779b9, svr_reorder_deliver, conn);
        if (!conn->reorder_tx || !conn->reorder_rx) {
            LOG_W(s, "reorder engine alloc failed; falling back to RAW");
            if (conn->reorder_tx) {
                mqvpn_reorder_tx_free(conn->reorder_tx);
                conn->reorder_tx = NULL;
            }
            if (conn->reorder_rx) {
                mqvpn_reorder_rx_free(conn->reorder_rx);
                conn->reorder_rx = NULL;
            }
        }
    }

    LOG_I(s, "H3 connection created");
    return 0;
}

/* Full per-conn teardown: free the reorder shim engines (allocated in
 * cb_h3_conn_create) and the svr_conn_t itself. Shared by cb_h3_conn_close and
 * the mqvpn_server_destroy defensive sweep so the two sites cannot drift and
 * leak the reorder engines. Does NOT touch the session table / addr pool /
 * disconnect callback — that bookkeeping is close-callback-specific and runs
 * before this is called. */
static void
svr_conn_free(svr_conn_t *conn)
{
    if (!conn) return;
    if (conn->reorder_tx) {
        mqvpn_reorder_tx_free(conn->reorder_tx);
        conn->reorder_tx = NULL;
    }
    if (conn->reorder_rx) {
        mqvpn_reorder_rx_free(conn->reorder_rx);
        conn->reorder_rx = NULL;
    }
    free(conn);
}

static int
cb_h3_conn_close(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *conn_user_data)
{
    (void)h3_conn;
    svr_conn_t *conn = (svr_conn_t *)conn_user_data;
    if (!conn) return 0;

    mqvpn_server_t *s = conn->server;
    svr_log_conn_stats(s, "server conn stats", cid ? cid : &conn->cid);
    LOG_I(s, "server dgram summary: acked=%" PRIu64 " lost=%" PRIu64,
          conn->dgram_acked_cnt, conn->dgram_lost_cnt);

    if (conn->assigned_ip.s_addr) {
        uint32_t offset = ntohl(conn->assigned_ip.s_addr) - ntohl(s->pool.base.s_addr);
        if (offset > 0 && offset <= MQVPN_ADDR_POOL_MAX && s->sessions[offset] == conn) {
            s->sessions[offset] = NULL;
            s->n_sessions--;
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &conn->assigned_ip, ip_str, sizeof(ip_str));
            LOG_I(s, "session removed: %s (active=%d)", ip_str, s->n_sessions);

            if (s->cbs.on_client_disconnected)
                s->cbs.on_client_disconnected(offset, MQVPN_ERR_CLOSED, s->user_ctx);
        }
        mqvpn_addr_pool_release(&s->pool, &conn->assigned_ip);
    }

    LOG_I(s, "H3 connection closed");
    svr_conn_free(conn);
    return 0;
}

static void
cb_h3_handshake_finished(xqc_h3_conn_t *h3_conn, void *conn_user_data)
{
    (void)h3_conn;
    svr_conn_t *conn = (svr_conn_t *)conn_user_data;
    LOG_I(conn->server, "H3 handshake finished");
}

/* ================================================================
 *  MASQUE session handling
 * ================================================================ */

/* Canned error responses. Callers on the H3 read-notify path deliberately
 * ignore the return value: escalating a failed canned-response send by
 * returning an error from the notify callback would kill the whole H3
 * connection (XQC_H3_CONN_ERR) — worse than dropping the reply. */
static int
svr_masque_send_403(xqc_h3_request_t *h3_request)
{
    xqc_http_header_t resp[] = {
        {.name = {.iov_base = ":status", .iov_len = 7},
         .value = {.iov_base = "403", .iov_len = 3},
         .flags = 0},
    };
    xqc_http_headers_t hdrs = {.headers = resp, .count = 1, .capacity = 1};
    return xqc_h3_request_send_headers(h3_request, &hdrs, 1) < 0 ? -1 : 0;
}

/* Unrecognized :protocol (or missing Extended CONNECT framing entirely):
 * explicit 501, replacing the historical silent capsule fall-through. */
static int
svr_masque_send_501(xqc_h3_request_t *h3_request)
{
    xqc_http_header_t resp[] = {
        {.name = {.iov_base = ":status", .iov_len = 7},
         .value = {.iov_base = "501", .iov_len = 3},
         .flags = 0},
    };
    xqc_http_headers_t hdrs = {.headers = resp, .count = 1, .capacity = 1};
    return xqc_h3_request_send_headers(h3_request, &hdrs, 1) < 0 ? -1 : 0;
}

static int
svr_masque_send_response(xqc_h3_request_t *h3_request, svr_stream_t *stream)
{
    svr_conn_t *conn = stream->conn;
    mqvpn_server_t *s = conn->server;
    ssize_t ret;

    if (s->n_sessions >= s->max_clients) {
        LOG_W(s, "max clients reached (%d), rejecting", s->max_clients);
        svr_masque_send_403(h3_request);
        return -1;
    }

    /* 1. Send 200 response headers */
    xqc_http_header_t resp_hdrs[3] = {
        {.name = {.iov_base = ":status", .iov_len = 7},
         .value = {.iov_base = "200", .iov_len = 3},
         .flags = 0},
        {.name = {.iov_base = "capsule-protocol", .iov_len = 16},
         .value = {.iov_base = "?1", .iov_len = 2},
         .flags = 0},
    };
    int resp_count = 2;
    /* §19.2/§19.3: echo mqvpn-reorder only when the server has it enabled, the rx
     * engine actually allocated, AND the client advertised. Echoing with a NULL
     * engine would tell the client to stamp packets we then drop (blackhole). */
    if (mqvpn_reorder_should_advertise(s->config.reorder.mode, conn->reorder_rx) &&
        conn->peer_reorder_supported) {
        resp_hdrs[resp_count].name =
            (struct iovec){.iov_base = MQVPN_REORDER_HDR_NAME,
                           .iov_len = sizeof(MQVPN_REORDER_HDR_NAME) - 1};
        resp_hdrs[resp_count].value =
            (struct iovec){.iov_base = MQVPN_REORDER_HDR_VALUE,
                           .iov_len = sizeof(MQVPN_REORDER_HDR_VALUE) - 1};
        resp_hdrs[resp_count].flags = 0;
        resp_count++;
    }
    xqc_http_headers_t hdrs = {
        .headers = resp_hdrs,
        .count = resp_count,
        .capacity = 3,
    };
    ret = xqc_h3_request_send_headers(h3_request, &hdrs, 0);
    if (ret < 0) {
        LOG_E(s, "send 200 headers: %zd", ret);
        return -1;
    }
    stream->header_sent = 1;
    conn->masque_stream_id = xqc_h3_stream_id(h3_request);

    /* 2. Allocate client IP */
    if (mqvpn_addr_pool_alloc(&s->pool, &conn->assigned_ip) < 0) {
        LOG_E(s, "IP pool exhausted");
        return -1;
    }

    /* 3. ADDRESS_ASSIGN capsule */
    uint8_t addr_payload[64];
    uint8_t ip_bytes[4];
    memcpy(ip_bytes, &conn->assigned_ip.s_addr, 4);
    addr_payload[0] = 0x00; /* request_id=0 */
    addr_payload[1] = 4;    /* IPv4 */
    memcpy(addr_payload + 2, ip_bytes, 4);
    addr_payload[6] = 32; /* /32 */
    size_t addr_written = 7;

    uint8_t capsule_buf[128];
    size_t cap_written = 0;
    xqc_int_t xret = xqc_h3_ext_capsule_encode(
        capsule_buf, sizeof(capsule_buf), &cap_written, XQC_H3_CAPSULE_ADDRESS_ASSIGN,
        addr_payload, addr_written);
    if (xret != XQC_OK) {
        LOG_E(s, "capsule encode ADDRESS_ASSIGN: %d", xret);
        goto fail_release_ip;
    }
    ret = xqc_h3_request_send_body(h3_request, capsule_buf, cap_written, 0);
    if (ret < 0) {
        LOG_E(s, "send ADDRESS_ASSIGN: %zd", ret);
        goto fail_release_ip;
    }

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &conn->assigned_ip, ip_str, sizeof(ip_str));
    LOG_I(s, "ADDRESS_ASSIGN: client=%s/32", ip_str);

    /* 3b. IPv6 ADDRESS_ASSIGN
     *
     * Treat encode/send failure as fatal (matching IPv4 above): a send_body
     * failure here means the same H3 stream that just succeeded for v4 is
     * now broken, so "fall back to v4-only" isn't reachable — the next
     * ROUTE_ADV v4 send would also fail. has_v6 is assigned only AFTER the
     * capsule is successfully sent so fail_release_ip doesn't have to
     * reason about half-set v6 state. */
    if (s->pool.has_v6) {
        struct in6_addr v6;
        uint32_t ip_offset = ntohl(conn->assigned_ip.s_addr) - ntohl(s->pool.base.s_addr);
        mqvpn_addr_pool_get6(&s->pool, ip_offset, &v6);

        uint8_t a6_payload[32];
        size_t a6_off = 0;
        a6_payload[a6_off++] = 0x00;
        a6_payload[a6_off++] = 6;
        memcpy(a6_payload + a6_off, &v6, 16);
        a6_off += 16;
        a6_payload[a6_off++] = (uint8_t)s->pool.prefix6;

        uint8_t cap6_buf[64];
        size_t cap6_written = 0;
        xret =
            xqc_h3_ext_capsule_encode(cap6_buf, sizeof(cap6_buf), &cap6_written,
                                      XQC_H3_CAPSULE_ADDRESS_ASSIGN, a6_payload, a6_off);
        if (xret != XQC_OK) {
            LOG_E(s, "capsule encode ADDRESS_ASSIGN (IPv6): %d", xret);
            goto fail_release_ip;
        }
        ret = xqc_h3_request_send_body(h3_request, cap6_buf, cap6_written, 0);
        if (ret < 0) {
            LOG_E(s, "send ADDRESS_ASSIGN (IPv6): %zd", ret);
            goto fail_release_ip;
        }

        conn->assigned_ip6 = v6;
        conn->has_v6 = 1;

        char v6str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &conn->assigned_ip6, v6str, sizeof(v6str));
        LOG_I(s, "ADDRESS_ASSIGN: client=%s/%d", v6str, s->pool.prefix6);
    }

    /* 4. ROUTE_ADVERTISEMENT (0.0.0.0 — 255.255.255.255) */
    uint8_t route_payload[32];
    size_t rp_off = 0;
    route_payload[rp_off++] = 4;
    memset(route_payload + rp_off, 0, 4);
    rp_off += 4;
    memset(route_payload + rp_off, 0xFF, 4);
    rp_off += 4;
    route_payload[rp_off++] = 0;

    uint8_t route_capsule[64];
    size_t rc_written = 0;
    xret = xqc_h3_ext_capsule_encode(route_capsule, sizeof(route_capsule), &rc_written,
                                     XQC_H3_CAPSULE_ROUTE_ADVERTISEMENT, route_payload,
                                     rp_off);
    if (xret != XQC_OK) {
        LOG_E(s, "capsule encode ROUTE_ADVERTISEMENT: %d", xret);
        goto fail_release_ip;
    }
    ret = xqc_h3_request_send_body(h3_request, route_capsule, rc_written, 0);
    if (ret < 0) {
        LOG_E(s, "send ROUTE_ADVERTISEMENT: %zd", ret);
        goto fail_release_ip;
    }

    /* 4b. IPv6 ROUTE_ADVERTISEMENT — only sent if v6 ADDRESS_ASSIGN succeeded,
     * so guard on conn->has_v6 (not s->pool.has_v6) for consistency. */
    if (conn->has_v6) {
        uint8_t r6_payload[48];
        size_t r6_off = 0;
        r6_payload[r6_off++] = 6;
        memset(r6_payload + r6_off, 0x00, 16);
        r6_off += 16;
        memset(r6_payload + r6_off, 0xFF, 16);
        r6_off += 16;
        r6_payload[r6_off++] = 0;

        uint8_t r6_capsule[80];
        size_t r6c_written = 0;
        xret = xqc_h3_ext_capsule_encode(r6_capsule, sizeof(r6_capsule), &r6c_written,
                                         XQC_H3_CAPSULE_ROUTE_ADVERTISEMENT, r6_payload,
                                         r6_off);
        if (xret != XQC_OK) {
            LOG_E(s, "capsule encode ROUTE_ADVERTISEMENT (IPv6): %d", xret);
            goto fail_release_ip;
        }
        ret = xqc_h3_request_send_body(h3_request, r6_capsule, r6c_written, 0);
        if (ret < 0) {
            LOG_E(s, "send ROUTE_ADVERTISEMENT (IPv6): %zd", ret);
            goto fail_release_ip;
        }
    }

    conn->tunnel_established = 1;

    /* Register in session table */
    uint32_t ip_off = ntohl(conn->assigned_ip.s_addr) - ntohl(s->pool.base.s_addr);
    if (ip_off > 0 && ip_off <= MQVPN_ADDR_POOL_MAX) {
        s->sessions[ip_off] = conn;
        s->n_sessions++;
    }
    LOG_I(s, "MASQUE tunnel established (stream_id=%" PRIu64 ", clients=%d)",
          conn->masque_stream_id, s->n_sessions);

    /* Notify platform of client connection */
    if (s->cbs.on_client_connected) {
        mqvpn_tunnel_info_t client_info = {0};
        client_info.struct_size = sizeof(client_info);
        memcpy(client_info.assigned_ip, &conn->assigned_ip.s_addr, 4);
        client_info.assigned_prefix = 32;
        memcpy(client_info.server_ip, &s->pool.base.s_addr, 4);
        client_info.server_prefix = (uint8_t)s->pool.prefix_len;
        int client_mtu = IPV6_MIN_MTU;
        if (conn->dgram_mss > 0) {
            size_t udp_mss =
                xqc_h3_ext_masque_udp_mss(conn->dgram_mss, conn->masque_stream_id);
            if (udp_mss >= 68) client_mtu = (int)udp_mss;
        }
        if (s->tun_mtu > 0 && client_mtu > s->tun_mtu) {
            LOG_D(s, "capping client MTU %d to TUN MTU %d", client_mtu, s->tun_mtu);
            client_mtu = s->tun_mtu;
        }
        /* §9: when the reorder shim is locally enabled, each stamped inner packet
         * carries an 8-byte header, so the usable inner MTU shrinks by 8. Apply
         * ONCE to the resolved inner MTU (after auto-MSS and TUN-MTU cap). */
        if (s->config.reorder.mode != MQVPN_REORDER_OFF) {
            client_mtu -= MQVPN_REORDER_HDR_LEN;
            if (conn->has_v6 && client_mtu < IPV6_MIN_MTU) client_mtu = IPV6_MIN_MTU;
        }
        client_info.mtu = client_mtu;
        if (conn->has_v6) {
            memcpy(client_info.assigned_ip6, &conn->assigned_ip6, 16);
            client_info.assigned_prefix6 = (uint8_t)s->pool.prefix6;
            client_info.has_v6 = 1;
        }
        s->cbs.on_client_connected(&client_info, ip_off, s->user_ctx);
    }
    return 0;

fail_release_ip:
    mqvpn_addr_pool_release(&s->pool, &conn->assigned_ip);
    memset(&conn->assigned_ip, 0, sizeof(conn->assigned_ip));
    /* Always 0/zero on the goto paths today; reset for safety against
     * future edits that move the assignments above. */
    conn->has_v6 = 0;
    memset(&conn->assigned_ip6, 0, sizeof(conn->assigned_ip6));
    conn->masque_stream_id = 0;
    return -1;
}

/* ================================================================
 *  H3 request callbacks
 * ================================================================ */

static int
cb_request_create(xqc_h3_request_t *h3_request, void *strm_user_data)
{
    (void)strm_user_data;
    svr_conn_t *conn = xqc_h3_get_conn_user_data_by_request(h3_request);

    /* calloc zero-inits role to SVR_STREAM_ROLE_UNKNOWN. */
    svr_stream_t *stream = calloc(1, sizeof(*stream));
    if (!stream) return -1;
    stream->conn = conn;
    stream->h3_request = h3_request;
    xqc_h3_request_set_user_data(h3_request, stream);
    return 0;
}

static int
cb_request_close(xqc_h3_request_t *h3_request, void *strm_user_data)
{
    (void)h3_request;
    svr_stream_t *stream = (svr_stream_t *)strm_user_data;
    if (stream) {
        /* Only the CONNECT-IP tunnel stream owns tunnel_established — a
         * closing non-tunnel stream (per-flow connect-tcp, or a 501'd
         * unknown request) on the same H3 connection must not flip the
         * tunnel dead. Mirrors the client-side role gate in
         * mqvpn_client.c's cb_request_close. */
        if (stream->conn && stream->role == SVR_STREAM_ROLE_CONNECT_IP)
            stream->conn->tunnel_established = 0;
#ifdef MQVPN_HYBRID_TCP_EGRESS_ENABLED
        /* A connect-tcp stream can close (client resets it, or the H3
         * connection itself is torn down) while its egress flow is still
         * CONNECTING or ACTIVE. Tear the flow down here too — closes the
         * fd, unregisters it from the platform reactor, unlinks it from
         * the D3 tick list, decrements both flow counters, and frees it.
         * If the flow already went through svr_tcp_egress_flow_destroy via
         * fail_connect/timeout (which NULLs this same field), this is a
         * no-op: exactly-once teardown either way, and destroy never
         * touches h3_request so calling it from a stream-close path (where
         * the request is already going away) is safe. */
        if (stream->role == SVR_STREAM_ROLE_CONNECT_TCP && stream->conn &&
            stream->tcp_egress_flow) {
            svr_tcp_egress_flow_destroy(stream->conn->server, stream->tcp_egress_flow);
        }
#endif
        free(stream->capsule_buf);
        free(stream);
    }
    return 0;
}

/* svr_req_headers_t is shared with src/hybrid/tcp_egress.c — defined in
 * mqvpn_server_internal.h (see that header for why only this struct + two
 * accessor functions moved, not the rest of this file's internals). */

/* Walks the header list; also sets conn->peer_reorder_supported on the
 * mqvpn-reorder echo (deliberate side effect). */
static void
svr_parse_request_headers(mqvpn_server_t *s, svr_stream_t *stream,
                          xqc_http_headers_t *headers, svr_req_headers_t *out)
{
    memset(out, 0, sizeof(*out));

    for (int i = 0; i < (int)headers->count; i++) {
        xqc_http_header_t *h = &headers->headers[i];
        if (h->name.iov_len == 7 && memcmp(h->name.iov_base, ":method", 7) == 0 &&
            h->value.iov_len == 7 && memcmp(h->value.iov_base, "CONNECT", 7) == 0)
            out->is_connect = 1;
        if (h->name.iov_len == 9 && memcmp(h->name.iov_base, ":protocol", 9) == 0) {
            out->protocol = (const char *)h->value.iov_base;
            out->protocol_len = h->value.iov_len;
            if (h->value.iov_len == 10 &&
                memcmp(h->value.iov_base, "connect-ip", 10) == 0)
                out->is_connect_ip = 1;
        }
        if (h->name.iov_len == 7 && memcmp(h->name.iov_base, ":scheme", 7) == 0 &&
            h->value.iov_len == 5 && memcmp(h->value.iov_base, "https", 5) == 0)
            out->has_scheme_https = 1;
        if (h->name.iov_len == 5 && memcmp(h->name.iov_base, ":path", 5) == 0) {
            /* Raw capture for connect-tcp's own template parse
             * (svr_tcp_egress_parse_path); has_valid_path below stays
             * CONNECT-IP's specific fixed-prefix check. */
            out->path = (const char *)h->value.iov_base;
            out->path_len = h->value.iov_len;
            if (h->value.iov_len >= 24 &&
                memcmp(h->value.iov_base, "/.well-known/masque/ip/", 22) == 0)
                out->has_valid_path = 1;
        }
        if (h->name.iov_len == 16 &&
            memcmp(h->name.iov_base, "capsule-protocol", 16) == 0 &&
            h->value.iov_len == 2 && memcmp(h->value.iov_base, "?1", 2) == 0)
            out->has_capsule_proto = 1;
        if (h->name.iov_len == 13 && memcmp(h->name.iov_base, "authorization", 13) == 0 &&
            h->value.iov_len > 7 && memcmp(h->value.iov_base, "Bearer ", 7) == 0) {
            out->auth_token = (const char *)h->value.iov_base + 7;
            out->auth_token_len = h->value.iov_len - 7;
        }
        /* §19.3: client advertised mqvpn-reorder → it supports the shim. */
        if (mqvpn_reorder_header_match(h->name.iov_base, h->name.iov_len,
                                       h->value.iov_base, h->value.iov_len)) {
            stream->conn->peer_reorder_supported = 1;
            LOG_I(s, "client advertised mqvpn-reorder");
        }
    }
}

/* Whether request-level auth must be checked at all — shared by CONNECT-IP
 * and connect-tcp so the two protocols can never silently diverge on this.
 * Declared in mqvpn_server_internal.h. */
int
svr_auth_required(const mqvpn_server_t *s)
{
    return (s->config.auth_key[0] != '\0') || (s->config.n_users > 0);
}

/* Credential check shared by every authenticated request type (CONNECT-IP,
 * connect-tcp). Constant-time over the global PSK and ALL configured users
 * regardless of early match. Returns 0 and writes the matched identity
 * ("(global)" or the user name) into out_username on success; -1 on
 * failure. Does NOT touch conn state and does NOT log — the caller records
 * username/connected_at_us, logs, and sends the 403. Precondition: caller
 * has already determined auth is required (svr_auth_required); with no
 * credentials configured this always returns -1. Declared (non-static) in
 * mqvpn_server_internal.h for src/hybrid/tcp_egress.c. */
int
svr_auth_check(const mqvpn_server_t *s, const char *auth_token, size_t auth_token_len,
               char *out_username, size_t username_cap)
{
    int authed = 0;

    if (username_cap > 0) out_username[0] = '\0';

    if (auth_token) {
        if (s->config.auth_key[0] != '\0' &&
            mqvpn_auth_ct_compare(auth_token, auth_token_len, s->config.auth_key,
                                  strlen(s->config.auth_key)) == 0) {
            authed = 1;
        }

        /* Always iterate all users to keep timing constant */
        for (int i = 0; i < s->config.n_users; i++) {
            const char *expected_key = s->config.user_keys[i];
            if (expected_key[0] == '\0') continue;
            authed |= (mqvpn_auth_ct_compare(auth_token, auth_token_len, expected_key,
                                             strlen(expected_key)) == 0);
        }
    }

    if (!authed) return -1;

    /* Record which user matched (second pass, not timing-sensitive) */
    if (s->config.auth_key[0] != '\0' &&
        mqvpn_auth_ct_compare(auth_token, auth_token_len, s->config.auth_key,
                              strlen(s->config.auth_key)) == 0) {
        snprintf(out_username, username_cap, "(global)");
    } else {
        for (int i = 0; i < s->config.n_users; i++) {
            const char *ek = s->config.user_keys[i];
            if (ek[0] != '\0' &&
                mqvpn_auth_ct_compare(auth_token, auth_token_len, ek, strlen(ek)) == 0) {
                snprintf(out_username, username_cap, "%s", s->config.user_names[i]);
                break;
            }
        }
    }

    return 0;
}

/* CONNECT-IP request: header-phase handling (validate, auth, 200 response).
 * Returns 0 on success, -1 to reset the stream. */
static int
svr_connect_ip_on_request(mqvpn_server_t *s, svr_stream_t *stream,
                          xqc_h3_request_t *h3_request, const svr_req_headers_t *hdrs)
{
    if (!hdrs->has_scheme_https || !hdrs->has_valid_path || !hdrs->has_capsule_proto) {
        LOG_W(s,
              "rejecting CONNECT-IP: missing headers "
              "(scheme=%d path=%d capsule=%d)",
              hdrs->has_scheme_https, hdrs->has_valid_path, hdrs->has_capsule_proto);
        return -1;
    }

    if (svr_auth_required(s)) {
        char username[sizeof(stream->conn->username)];

        if (svr_auth_check(s, hdrs->auth_token, hdrs->auth_token_len, username,
                           sizeof(username)) != 0) {
            LOG_W(s, "authentication failed: invalid or missing PSK");
            svr_masque_send_403(h3_request);
            return -1;
        }

        stream->conn->connected_at_us = now_us();
        snprintf(stream->conn->username, sizeof(stream->conn->username), "%s", username);

        LOG_I(s, "client authenticated successfully (user=%s)", stream->conn->username);
    }

    LOG_I(s, "Extended CONNECT for connect-ip received");
    if (svr_masque_send_response(h3_request, stream) < 0) return -1;
    return 0;
}

/* Egress ACL policy snapshot for src/hybrid/tcp_egress.c (connect-tcp
 * destination check). Declared in mqvpn_server_internal.h. The v4 tunnel
 * subnet (tunnels[0]) is derived from the SAME address pool CONNECT-IP
 * address assignment uses (s->pool) — addr_pool.c enforces prefix_len in
 * [16,30] at init time, so mqvpn_cidr_premask below never hits a
 * pathological prefix from arbitrary (config-supplied) egress_allow/
 * egress_deny entries. tunnels[1] (v6) mirrors tunnels[0] from s->pool.base6/
 * prefix6, but ONLY when s->pool.has_v6 (i.e. Subnet6 was configured) —
 * left at family == 0 (the unset sentinel) otherwise. This gate is
 * load-bearing, not cosmetic: mqvpn_cidr_match ignores prefix_len when
 * family == 0, but a same-shaped {family=6, prefix_len=0} would be
 * indistinguishable from a real "::/0" entry and would match EVERY v6
 * address, silently denying all v6 egress for any server that never
 * configured Subnet6. */
void
svr_get_egress_policy(const mqvpn_server_t *s, const mqvpn_cidr_entry_t **allow,
                      int *n_allow, const mqvpn_cidr_entry_t **deny, int *n_deny,
                      mqvpn_cidr_entry_t tunnels[2])
{
    *allow = s->config.hybrid.egress_allow;
    *n_allow = s->config.hybrid.n_egress_allow;
    *deny = s->config.hybrid.egress_deny;
    *n_deny = s->config.hybrid.n_egress_deny;

    memset(&tunnels[0], 0, sizeof(tunnels[0]));
    tunnels[0].family = 4;
    tunnels[0].prefix_len = (uint8_t)s->pool.prefix_len;
    uint32_t net_hip = ntohl(s->pool.base.s_addr);
    tunnels[0].net[0] = (uint8_t)(net_hip >> 24);
    tunnels[0].net[1] = (uint8_t)(net_hip >> 16);
    tunnels[0].net[2] = (uint8_t)(net_hip >> 8);
    tunnels[0].net[3] = (uint8_t)(net_hip);
    mqvpn_cidr_premask(tunnels[0].net, tunnels[0].prefix_len);

    memset(&tunnels[1], 0, sizeof(tunnels[1]));
    if (s->pool.has_v6) {
        tunnels[1].family = 6;
        tunnels[1].prefix_len = (uint8_t)s->pool.prefix6;
        memcpy(tunnels[1].net, s->pool.base6.s6_addr, 16);
        mqvpn_cidr_premask(tunnels[1].net, tunnels[1].prefix_len);
    }
    /* else: family stays 0 (memset above) — the unset sentinel, NOT a
     * {family=6, prefix_len=0} "match everything" shape. See the has_v6
     * gate rationale in this function's docstring. */
}

#ifdef MQVPN_HYBRID_TCP_EGRESS_ENABLED
/* ---- connect()/relay boundary accessors for src/hybrid/tcp_egress.c ----
 * See the docstring block in mqvpn_server_internal.h for why each of these
 * exists as its own narrow function. */

void **
svr_stream_tcp_egress_flow_ptr(void *stream)
{
    svr_stream_t *st = (svr_stream_t *)stream;
    return st ? &st->tcp_egress_flow : NULL;
}

int *
svr_conn_tcp_flow_count_ptr(void *stream)
{
    svr_stream_t *st = (svr_stream_t *)stream;
    if (!st || !st->conn) return NULL;
    return &st->conn->tcp_flow_count;
}

void
svr_get_tcp_egress_ctx(mqvpn_server_t *s, svr_tcp_egress_srv_ctx_t *out)
{
    out->flow_list_head = &s->tcp_egress_flow_list_head;
    out->global_fd_count = &s->tcp_egress_global_fd_count;
    out->flows_total_opened = &s->tcp_egress_flows_total_opened;
    out->flows_rejected_cap = &s->tcp_egress_flows_rejected_cap;
    out->tcp_max_flows = s->config.hybrid.tcp_max_flows;
    out->tcp_connect_timeout_sec = s->config.hybrid.tcp_connect_timeout_sec;
    out->tcp_idle_timeout_sec = s->config.hybrid.tcp_idle_timeout_sec;
    out->global_fd_budget = s->egress_fd_budget; /* frozen at server_new */
}

int
svr_egress_fd_register(mqvpn_server_t *s, int fd, int want_read, int want_write,
                       void *fd_ctx)
{
    if (!s->cbs.egress_fd_register) return -1;
    s->cbs.egress_fd_register(fd, want_read, want_write, fd_ctx, s->user_ctx);
    return 0;
}

int
svr_egress_fd_register_is_set(mqvpn_server_t *s)
{
    return s->cbs.egress_fd_register != NULL;
}

void
svr_egress_fd_unregister(mqvpn_server_t *s, int fd)
{
    if (s->cbs.egress_fd_unregister) s->cbs.egress_fd_unregister(fd, s->user_ctx);
}

uint64_t
svr_now_us(void)
{
    return now_us();
}

/* Formats once locally, then hands the finished string to server_log as a
 * literal "%s" argument — reuses server_log's null/level-gate and cbs.log
 * dispatch instead of duplicating them here (server_log can't take a
 * va_list, so a one-shot vsnprintf is the only way to bridge `...`). */
void
svr_log(mqvpn_server_t *s, mqvpn_log_level_t level, const char *fmt, ...)
{
    if (!s->cbs.log || level < s->log_level) return;
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    server_log(s, level, "%s", buf);
}
#endif /* MQVPN_HYBRID_TCP_EGRESS_ENABLED */

/* CONNECT-IP stream body: capsule reassembly + ADDRESS_REQUEST handling. */
static int
svr_connect_ip_on_body(mqvpn_server_t *s, svr_stream_t *stream,
                       xqc_h3_request_t *h3_request)
{
    unsigned char fin = 0;
    unsigned char buf[4096];
    ssize_t n;
    do {
        n = xqc_h3_request_recv_body(h3_request, buf, sizeof(buf), &fin);
        if (n <= 0) break;

        size_t need = stream->capsule_len + (size_t)n;
        if (need > MAX_CAPSULE_BUF) {
            LOG_E(s, "server capsule buffer overflow");
            break;
        }
        if (need > stream->capsule_cap) {
            size_t new_cap = stream->capsule_cap ? stream->capsule_cap * 2 : 4096;
            while (new_cap < need) {
                if (new_cap > SIZE_MAX / 2) {
                    new_cap = need;
                    break;
                }
                new_cap *= 2;
            }
            uint8_t *nb = realloc(stream->capsule_buf, new_cap);
            if (!nb) break;
            stream->capsule_buf = nb;
            stream->capsule_cap = new_cap;
        }
        memcpy(stream->capsule_buf + stream->capsule_len, buf, (size_t)n);
        stream->capsule_len += (size_t)n;

        while (stream->capsule_len > 0) {
            uint64_t cap_type;
            const uint8_t *cap_payload;
            size_t cap_len, consumed;
            xqc_int_t xr =
                xqc_h3_ext_capsule_decode(stream->capsule_buf, stream->capsule_len,
                                          &cap_type, &cap_payload, &cap_len, &consumed);
            if (xr != XQC_OK) break;

            if (cap_type == XQC_H3_CAPSULE_ADDRESS_REQUEST && stream->conn &&
                stream->conn->tunnel_established) {
                uint64_t req_id;
                uint8_t ip_ver, ip_addr[16], prefix;
                size_t ip_len = 16, aa_consumed;
                xr = xqc_h3_ext_connectip_parse_address_assign(
                    cap_payload, cap_len, &req_id, &ip_ver, ip_addr, &ip_len, &prefix,
                    &aa_consumed);
                if (xr == XQC_OK && req_id != 0) {
                    LOG_I(s, "ADDRESS_REQUEST: req_id=%" PRIu64 " ipv%d", req_id, ip_ver);
                    uint8_t resp_payload[64];
                    size_t resp_written = 0;
                    uint8_t resp_ip[4];
                    memcpy(resp_ip, &stream->conn->assigned_ip.s_addr, 4);
                    xqc_h3_ext_connectip_build_address_request(
                        resp_payload, sizeof(resp_payload), &resp_written, req_id, 4,
                        resp_ip, 32);
                    uint8_t cap_buf[128];
                    size_t cap_w = 0;
                    xqc_h3_ext_capsule_encode(cap_buf, sizeof(cap_buf), &cap_w,
                                              XQC_H3_CAPSULE_ADDRESS_ASSIGN, resp_payload,
                                              resp_written);
                    xqc_h3_request_send_body(h3_request, cap_buf, cap_w, 0);
                }
            }

            if (consumed < stream->capsule_len)
                memmove(stream->capsule_buf, stream->capsule_buf + consumed,
                        stream->capsule_len - consumed);
            stream->capsule_len -= consumed;
        }
    } while (1);

    return 0;
}

/*
 * cb_request_read — xquic H3 request read callback for MASQUE streams.
 *
 * Parses request headers, tags the stream's role, and dispatches to the
 * role's handlers (header phase and body phase).
 */
static int
cb_request_read(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag,
                void *strm_user_data)
{
    svr_stream_t *stream = (svr_stream_t *)strm_user_data;
    mqvpn_server_t *s = stream->conn->server;
    unsigned char fin = 0;

    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        xqc_http_headers_t *headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (!headers) return -1;

        svr_req_headers_t hdrs;
        svr_parse_request_headers(s, stream, headers, &hdrs);

        if (hdrs.is_connect && hdrs.is_connect_ip) {
            /* Role is tagged even though the handler may still fail with -1
             * (stream reset); harmless — a reset stream's role is never
             * consulted again. */
            stream->role = SVR_STREAM_ROLE_CONNECT_IP;
            return svr_connect_ip_on_request(s, stream, h3_request, &hdrs);
        }
#ifdef MQVPN_HYBRID_TCP_EGRESS_ENABLED
        /* [Hybrid] Enabled is a client+server kill switch (docs/control-api.md),
         * default false, and IS parsed into config.hybrid.enabled (config.c
         * CFG_BOOL(SEC_HYBRID, "Enabled", ...)). Gating on the compile flag
         * alone means a hybrid-compiled server with Enabled=false still
         * serves egress — require the runtime flag too. A disabled feature
         * is treated exactly like an unrecognized protocol: fall through to
         * the 501 below rather than a dedicated status, since the server
         * offers no such capability right now. */
        if (hdrs.is_connect && hdrs.protocol_len == 9 &&
            memcmp(hdrs.protocol, "mqvpn-tcp", 9) == 0 && s->config.hybrid.enabled) {
            stream->role = SVR_STREAM_ROLE_CONNECT_TCP;
            return svr_tcp_egress_on_request(s, stream, h3_request, &hdrs);
        }
#endif
        /* Unrecognized request: explicit 501, replacing the historical
         * silent fall-through. Role stays UNKNOWN — no body is expected. */
        svr_masque_send_501(h3_request);
        return 0;
    }

#ifdef MQVPN_HYBRID_TCP_EGRESS_ENABLED
    /* READ_BODY is the common case; READ_EMPTY_FIN is the OTHER real wire
     * shape for a downlink close (third_party/xquic src/http3/xqc_h3_request.c
     * xqc_h3_request_on_recv_empty_fin): fired standalone, WITHOUT READ_BODY,
     * when a bodiless FIN STREAM frame arrives while the request's read_flag
     * is back to NULL (no header/body notify still pending application
     * consumption — see that function's own guard). Missing this notify
     * would mean a peer that FINs on an idle/fully-drained stream never gets
     * its downlink half-close observed, so shutdown(fd, SHUT_WR) is never
     * issued and a peer waiting for EOF hangs. Mirrors the client's handling
     * at mqvpn_client.c cb_request_read (CLI_STREAM_ROLE_CONNECT_TCP case).
     * svr_tcp_egress_on_body/svr_tcp_egress_drain_body correctly report this
     * as n==0 && *fin==1 either way, so one handler covers both notify
     * shapes; this is scoped to CONNECT_TCP only — CONNECT_IP and UNKNOWN
     * are unaffected and still route through the switch below. */
    if (stream->role == SVR_STREAM_ROLE_CONNECT_TCP &&
        (flag & (XQC_REQ_NOTIFY_READ_BODY | XQC_REQ_NOTIFY_READ_EMPTY_FIN))) {
        return svr_tcp_egress_on_body(s, stream, h3_request);
    }
#endif

    if (flag & XQC_REQ_NOTIFY_READ_BODY) {
        switch (stream->role) {
        case SVR_STREAM_ROLE_CONNECT_IP:
            return svr_connect_ip_on_body(s, stream, h3_request);
#ifdef MQVPN_HYBRID_TCP_EGRESS_ENABLED
        case SVR_STREAM_ROLE_CONNECT_TCP:
            /* Handled above in the CONNECT_TCP-scoped block
             * (READ_BODY | READ_EMPTY_FIN); unreachable here, listed only
             * to satisfy -Wswitch. */
            return 0;
#endif
        case SVR_STREAM_ROLE_UNKNOWN: {
            /* 501 already sent at header time. Drain and discard any body
             * so it doesn't sit in xquic's recv buffers until flow control
             * stalls. */
            unsigned char drain[4096];
            while (xqc_h3_request_recv_body(h3_request, drain, sizeof(drain), &fin) > 0) {
            }
            return 0;
        }
        }
        return 0;
    }

    return 0;
}

static int
cb_request_write(xqc_h3_request_t *h3_request, void *strm_user_data)
{
    (void)h3_request;
    svr_stream_t *stream = (svr_stream_t *)strm_user_data;
#ifdef MQVPN_HYBRID_TCP_EGRESS_ENABLED
    if (stream && stream->role == SVR_STREAM_ROLE_CONNECT_TCP && stream->conn) {
        svr_tcp_egress_on_h3_writable(stream->conn->server, stream);
    }
#else
    (void)stream;
#endif
    return 0;
}

/* Peer sent RESET_STREAM — xquic is already tearing this
 * request down (verified against the vendored source, same citation trail
 * as mqvpn_client.c's cb_request_closing_notify: this notify fires ONLY on
 * RESET_STREAM frame reception, never on STOP_SENDING alone or on a clean
 * bidi-FIN completion). CONNECT-IP has no per-flow teardown concept of its
 * own (its close is handled via cb_request_close/h3_conn_close_notify), so
 * only the connect-tcp branch does anything here — reuses the EXISTING
 * svr_tcp_egress_flow_destroy funnel (the same one cb_request_close below
 * already calls for the connect-timeout/synchronous-failure paths): the
 * `stream->tcp_egress_flow` guard is what makes this idempotent against a
 * flow that already went through a different teardown (svr_tcp_egress_
 * flow_destroy NULLs it), so whichever of this callback or
 * cb_request_close reaches the flow first destroys it and the other is a
 * no-op. (void)err: the flow is dead either way, no err-code-specific
 * handling needed. */
static void
cb_request_closing_notify(xqc_h3_request_t *h3_request, xqc_int_t err,
                          void *strm_user_data)
{
    (void)h3_request;
    (void)err;
#ifdef MQVPN_HYBRID_TCP_EGRESS_ENABLED
    svr_stream_t *stream = (svr_stream_t *)strm_user_data;
    if (stream && stream->role == SVR_STREAM_ROLE_CONNECT_TCP && stream->conn &&
        stream->tcp_egress_flow) {
        svr_tcp_egress_flow_destroy(stream->conn->server, stream->tcp_egress_flow);
    }
#else
    (void)strm_user_data;
#endif
}

/* ================================================================
 *  Datagram callbacks
 * ================================================================ */

/*
 * forward_inner_ip — post-process one de-stamped inner IP packet received from a
 * client and hand it to TUN. Shared by the RAW dispatch in cb_dgram_read AND the
 * reorder RX deliver() callback so reordered packets get IDENTICAL handling.
 *
 * Unlike the client helper, the server ADDITIONALLY (a) validates the inner
 * source address against the session's assigned IP (anti-spoof) and (b) emits
 * rate-limited ICMP Time-Exceeded back to the client via the datagram path. The
 * order is: src validation → TTL/ICMP (§5). `pkt[0..len)` is the bare inner IP
 * packet (no reorder header).
 */
static void
forward_inner_ip(svr_conn_t *conn, const uint8_t *pkt, size_t len)
{
    mqvpn_server_t *s = conn->server;
    if (len < 1) return;

    uint8_t ip_ver = pkt[0] >> 4;
    uint8_t fwd_pkt[PACKET_BUF_SIZE];
    if (len > sizeof(fwd_pkt)) return;

    if (ip_ver == 4) {
        if (len < 20) return;
        if (memcmp(pkt + 12, &conn->assigned_ip.s_addr, 4) != 0) {
            LOG_W(s, "dropping packet: src IP mismatch");
            return;
        }
        memcpy(fwd_pkt, pkt, len);
        if (fwd_pkt[8] <= 1) {
            if (ptb_rate_allow(s)) {
                struct in_addr srv;
                mqvpn_addr_pool_server_addr(&s->pool, &srv);
                mqvpn_icmp_send_v4(send_icmp_via_datagram, conn,
                                   (const uint8_t *)&srv.s_addr, 11, 0, 0, pkt, len);
                LOG_D(s, "sent ICMP Time Exceeded to client");
            }
            return;
        }
        fwd_pkt[8]--;
        uint32_t sum = ((uint32_t)fwd_pkt[10] << 8 | fwd_pkt[11]) + 0x0100;
        sum = (sum & 0xFFFF) + (sum >> 16);
        fwd_pkt[10] = (sum >> 8) & 0xFF;
        fwd_pkt[11] = sum & 0xFF;
    } else if (ip_ver == 6) {
        if (len < 40) return;
        if (!conn->has_v6 || memcmp(pkt + 8, &conn->assigned_ip6, 16) != 0) {
            LOG_W(s, "dropping IPv6 packet: src IP mismatch");
            return;
        }
        memcpy(fwd_pkt, pkt, len);
        if (fwd_pkt[7] <= 1) {
            if (s->pool.has_v6 && ptb_rate_allow(s)) {
                struct in6_addr srv6;
                mqvpn_addr_pool_server_addr6(&s->pool, &srv6);
                mqvpn_icmp_send_v6(send_icmp_via_datagram, conn, srv6.s6_addr, 3, 0, 0,
                                   pkt, len);
                LOG_D(s, "sent ICMPv6 Time Exceeded to client");
            }
            return;
        }
        fwd_pkt[7]--;
    } else {
        return;
    }

    s->bytes_rx += len;
    s->dgram_recv++;
    s->cbs.tun_output(fwd_pkt, len, s->user_ctx);
}

/* Reorder RX deliver() trampoline: routes in-order packets from the reorder
 * engine through the same forward_inner_ip post-processing. */
static void
svr_reorder_deliver(const uint8_t *pkt, size_t len, void *ctx)
{
    forward_inner_ip((svr_conn_t *)ctx, pkt, len);
}

static void
cb_dgram_read(xqc_h3_conn_t *h3_conn, const void *data, size_t data_len, void *user_data,
              uint64_t ts)
{
    (void)h3_conn;
    (void)ts;
    svr_conn_t *conn = (svr_conn_t *)user_data;
    if (!conn || !conn->tunnel_established) return;
    mqvpn_server_t *s = conn->server;

    uint64_t qsid = 0, ctx_id = 0;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;

    xqc_int_t xret = xqc_h3_ext_masque_unframe_udp((const uint8_t *)data, data_len, &qsid,
                                                   &ctx_id, &payload, &payload_len);
    if (xret != XQC_OK) return;
    if (payload_len < 1) return;

    /* §5/§8.1 self-describing dispatch on payload[0]. */
    switch (mqvpn_reorder_classify_byte(payload[0])) {
    case MQVPN_REORDER_KIND_RAW: forward_inner_ip(conn, payload, payload_len); return;
    case MQVPN_REORDER_KIND_REORDER_V1:
        if (conn->reorder_rx) {
            mqvpn_reorder_rx_on_packet(conn->reorder_rx, payload, payload_len, now_us());
        } else {
            LOG_D(s, "dgram: reorder packet but rx engine off; dropping");
        }
        return;
    default: LOG_D(s, "dgram: unknown reorder type 0x%02x; dropping", payload[0]); return;
    }
}

static void
cb_dgram_write(xqc_h3_conn_t *h3_conn, void *user_data)
{
    (void)h3_conn;
    svr_conn_t *conn = (svr_conn_t *)user_data;
    if (!conn) return;
    mqvpn_server_t *s = conn->server;
    if (s->tun_paused) {
        s->tun_paused = 0;
        LOG_D(s, "TUN read resumed (QUIC queue has space)");
    }
}

static void
cb_dgram_acked(xqc_h3_conn_t *h, uint64_t id, void *ud)
{
    (void)h;
    (void)id;
    svr_conn_t *conn = (svr_conn_t *)ud;
    if (conn) {
        conn->dgram_acked_cnt++;
        conn->server->dgram_acked++;
    }
}

static int
cb_dgram_lost(xqc_h3_conn_t *h, uint64_t id, void *ud)
{
    (void)h;
    svr_conn_t *conn = (svr_conn_t *)ud;
    if (!conn) return 0;
    mqvpn_server_t *s = conn->server;
    conn->dgram_lost_cnt++;
    conn->server->dgram_lost++;
    if ((conn->dgram_lost_cnt % 256) == 0) {
        LOG_W(s,
              "datagram loss: lost=%" PRIu64 " acked=%" PRIu64 " (last_dgram_id=%" PRIu64
              ")",
              conn->dgram_lost_cnt, conn->dgram_acked_cnt, id);
        svr_log_conn_stats(s, "server loss checkpoint", &conn->cid);
    }
    return 0;
}

static void
cb_dgram_mss_updated(xqc_h3_conn_t *h3_conn, size_t mss, void *user_data)
{
    (void)h3_conn;
    svr_conn_t *conn = (svr_conn_t *)user_data;
    if (conn) conn->dgram_mss = mss;
    if (conn) LOG_I(conn->server, "datagram MSS updated: %zu", mss);
}

/* ================================================================
 *  Public API — Lifecycle
 * ================================================================ */

mqvpn_server_t *
mqvpn_server_new(const mqvpn_config_t *cfg, const mqvpn_server_callbacks_t *cbs,
                 void *user_ctx)
{
    if (!cfg || !cbs) return NULL;
    if (cbs->abi_version != MQVPN_CALLBACKS_ABI_VERSION) return NULL;
    if (!cbs->tun_output || !cbs->tunnel_config_ready) return NULL;

    mqvpn_server_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;

    memcpy(&s->config, cfg, sizeof(*cfg));
    /* Clamp to the caller's struct_size: a platform built against an older
     * (shorter) callbacks struct must not be over-read — appended fields
     * stay NULL (s is calloc'd), which is the "callback unset" state. */
    size_t cbs_size = (cbs->struct_size && cbs->struct_size < sizeof(*cbs))
                          ? cbs->struct_size
                          : sizeof(*cbs);
    memcpy(&s->cbs, cbs, cbs_size);
    s->user_ctx = user_ctx;
    s->log_level = cfg->log_level;
    /* caller guarantees lifetime exceeds this object */ // lgtm[cpp/stack-address-escape]
    s->udp_fd = -1;
    s->max_clients = cfg->max_clients > 0 ? cfg->max_clients : 64;
    mqvpn_ptb_bucket_init(&s->ptb_bucket);
    s->boot_us = now_us();
    /* Sanitize the [Hybrid] block at its consumer (validate-at-consumer
     * pattern — same as mqvpn_reorder_config_validate run by
     * mqvpn_reorder_rx_new): the INI/JSON loaders store raw scalars (CFG_U32
     * accepts 0) and only the PUBLIC setters range-check, so a file config
     * with e.g. TcpMaxGlobalFlows = 0 would otherwise freeze the egress fd
     * budget at 0 below and silently 503 every connect-tcp request.
     * PER-FIELD reset (mqvpn_hybrid_config_sanitize), never a whole-block
     * default reset: that would silently drop the operator's EgressDeny/
     * EgressAllow policy over an unrelated scalar typo — fail-open. Warned
     * per field, matching the loaders' own per-key warn-and-ignore
     * convention; never a hard server-start failure. */
    {
        const char *bad_fields[8];
        int n_bad = mqvpn_hybrid_config_sanitize(&s->config.hybrid, bad_fields, 8);
        for (int i = 0; i < n_bad && i < 8; i++)
            LOG_W(s, "invalid [Hybrid] %s; using default", bad_fields[i]);
    }
    /* s->config was already populated by the memcpy above (and its hybrid
     * scalars possibly sanitized just above) — the budget computation MUST
     * read the applied config, not `cfg` directly, so a future refactor that
     * changes what memcpy copies can't silently desync the two. */
    s->egress_fd_budget =
        svr_compute_egress_fd_budget(s->config.hybrid.tcp_max_global_flows);

    /* Initialize address pool */
    if (cfg->subnet[0] == '\0') {
        LOG_E(s, "subnet not configured");
        goto cleanup;
    }
    if (mqvpn_addr_pool_init(&s->pool, cfg->subnet) < 0) {
        LOG_E(s, "failed to init address pool: %s", cfg->subnet);
        goto cleanup;
    }
    if (cfg->subnet6[0] != '\0') {
        if (mqvpn_addr_pool_init6(&s->pool, cfg->subnet6) < 0) {
            LOG_E(s, "failed to init IPv6 pool: %s", cfg->subnet6);
            goto cleanup;
        }
    }

    /* Startup advisory, not a refusal: a pool wider than /24 is legal
     * (addr_pool.c allows prefix_len in [16,30]) and plenty of deployments
     * never use intra-VPN client-to-client TCP. But the client widens its
     * assigned /32 to /24 for the tunnel-subnet RAW gate, and the server's
     * egress ACL denies the full pool subnet, so two clients outside a
     * shared /24 within a wider pool get their hybrid TCP-lane traffic
     * silently, permanently RST'd. Warn once at startup so operators with a
     * wide pool + hybrid enabled know to either narrow the pool to /24 (or
     * smaller) or add an explicit EgressAllow for the pool subnet. */
    if (s->config.hybrid.enabled && s->pool.prefix_len < 24) {
        LOG_W(s,
              "hybrid TCP-lane: pool subnet is wider than /24 (prefix_len=%u) — "
              "client-to-client TCP between clients outside a shared /24 will be "
              "denied by the egress ACL; use a /24-or-narrower pool or add an "
              "EgressAllow entry",
              (unsigned)s->pool.prefix_len);
    }

    /* ── xquic engine setup ── */
    xqc_engine_ssl_config_t engine_ssl;
    memset(&engine_ssl, 0, sizeof(engine_ssl));
    engine_ssl.private_key_file = cfg->tls_key[0] ? (char *)cfg->tls_key : NULL;
    engine_ssl.cert_file = cfg->tls_cert[0] ? (char *)cfg->tls_cert : NULL;
    engine_ssl.ciphers = XQC_TLS_CIPHERS;
    engine_ssl.groups = XQC_TLS_GROUPS;

    xqc_engine_callback_t engine_cbs = {
        .set_event_timer = cb_set_event_timer,
        .log_callbacks =
            {
                .xqc_log_write_err = cb_xqc_log_write,
                .xqc_log_write_stat = cb_xqc_log_write,
            },
    };

    xqc_transport_callbacks_t tcbs = {
        .server_accept = cb_accept,
        .server_refuse = cb_refuse,
        .write_socket = cb_write_socket,
        .write_socket_ex = cb_write_socket_ex,
        .stateless_reset = cb_stateless_reset,
        .conn_send_packet_before_accept = cb_write_before_accept,
        .path_created_notify = cb_path_created,
        .path_removed_notify = cb_path_removed,
    };

    /* xquic INFO emits per-packet logs (effectively DEBUG-grade noise that
     * also tanks throughput on slow consoles like Windows PowerShell). Map
     * mqvpn INFO -> xquic WARN so --log-level info shows mqvpn state without
     * the per-packet flood; users who want xquic detail use --log-level debug.
     * Mirrors the client-side mapping in mqvpn_client.c. */
    int xqc_log_level;
    switch (cfg->log_level) {
    case MQVPN_LOG_DEBUG: xqc_log_level = XQC_LOG_DEBUG; break;
    case MQVPN_LOG_INFO: xqc_log_level = XQC_LOG_WARN; break;
    case MQVPN_LOG_WARN: xqc_log_level = XQC_LOG_WARN; break;
    case MQVPN_LOG_ERROR: xqc_log_level = XQC_LOG_ERROR; break;
    default: xqc_log_level = XQC_LOG_WARN; break;
    }

    xqc_config_t xconfig;
    if (xqc_engine_get_default_config(&xconfig, XQC_ENGINE_SERVER) < 0) goto cleanup;
    xconfig.cfg_log_level = (xqc_log_level_t)xqc_log_level;

    s->engine = xqc_engine_create(XQC_ENGINE_SERVER, &xconfig, &engine_ssl, &engine_cbs,
                                  &tcbs, s);
    if (!s->engine) goto cleanup;

        /* Connection settings — see src/mqvpn_conn_settings.c for the full body. */
#if !defined(XQC_ENABLE_FEC) || !defined(XQC_ENABLE_XOR)
    if (cfg->scheduler == MQVPN_SCHED_BACKUP_FEC) {
        LOG_W(s, "backup_fec scheduler requested but library built without FEC "
                 "support (XQC_ENABLE_FEC/XQC_ENABLE_XOR); downgrading to minrtt");
    }
#endif
    xqc_conn_settings_t conn_settings;
    mqvpn_conn_settings_input_t cs_input = {
        .is_server = true,
        .enable_multipath = true, /* server: always on, see mqvpn_conn_settings.c */
        .scheduler = cfg->scheduler,
        .cc = cfg->cc,
        .init_max_path_id = cfg->init_max_path_id,
    };
    mqvpn_build_conn_settings(&cs_input, &conn_settings);
    xqc_server_set_conn_settings(s->engine, &conn_settings);

    /* H3 callbacks */
    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs =
            {
                .h3_conn_create_notify = cb_h3_conn_create,
                .h3_conn_close_notify = cb_h3_conn_close,
                .h3_conn_handshake_finished = cb_h3_handshake_finished,
            },
        .h3r_cbs =
            {
                .h3_request_create_notify = cb_request_create,
                .h3_request_close_notify = cb_request_close,
                .h3_request_read_notify = cb_request_read,
                .h3_request_write_notify = cb_request_write,
                .h3_request_closing_notify = cb_request_closing_notify,
            },
        .h3_ext_dgram_cbs =
            {
                .dgram_read_notify = cb_dgram_read,
                .dgram_write_notify = cb_dgram_write,
                .dgram_acked_notify = cb_dgram_acked,
                .dgram_lost_notify = cb_dgram_lost,
                .dgram_mss_updated_notify = cb_dgram_mss_updated,
            },
    };
    if (xqc_h3_ctx_init(s->engine, &h3_cbs) != XQC_OK) goto cleanup;

    xqc_h3_conn_settings_t h3s = {
        .max_field_section_size = 32 * 1024,
        .qpack_blocked_streams = 64,
        .qpack_enc_max_table_capacity = 16 * 1024,
        .qpack_dec_max_table_capacity = 16 * 1024,
        .enable_connect_protocol = 1,
        .h3_datagram = 1,
    };
    xqc_h3_engine_set_local_settings(s->engine, &h3s);

    return s;

cleanup:
    if (s->engine) {
        xqc_engine_destroy(s->engine);
        s->engine = NULL;
    }
    free(s);
    return NULL;
}

void
mqvpn_server_destroy(mqvpn_server_t *s)
{
    if (!s) return;

    /* Step 1: xqc_engine_destroy triggers h3_conn_close → session free */
    if (s->engine) {
        xqc_engine_destroy(s->engine);
        s->engine = NULL;
    }

#ifdef MQVPN_HYBRID_TCP_EGRESS_ENABLED
    /* Step 2: Defensive sweep — destroy any egress flows not torn down by
     * the request-closing notify during the engine destroy above (same
     * contingency the session sweep below defends against: a stream whose
     * h3_request_closing_notify didn't fire leaves its tcp_egress_flow on
     * the D3 list, leaking the open OS fd + heap). MUST run BEFORE the
     * session sweep below: svr_tcp_egress_flow_destroy dereferences
     * ef->stream->conn (via svr_conn_tcp_flow_count_ptr) to decrement the
     * per-connection flow counter, and svr_conn_free() below frees that
     * same conn — reversing the order would turn this leak fix into a
     * heap-use-after-free on any conn that hit both contingencies at once. */
    svr_tcp_egress_destroy_all(s);
#endif

    /* Step 3: Defensive sweep — free any sessions not freed by engine callbacks.
     * Uses svr_conn_free so the reorder engines are freed here too (the close
     * callback that would normally free them did not fire for these conns). */
    for (int i = 1; i <= MQVPN_ADDR_POOL_MAX; i++) {
        if (s->sessions[i]) {
            svr_conn_free(s->sessions[i]);
            s->sessions[i] = NULL;
        }
    }

    /* Step 4: free server handle */
    free(s);
}

int
mqvpn_server_set_socket_fd(mqvpn_server_t *s, int fd, const struct sockaddr *local_addr,
                           socklen_t local_addrlen)
{
    if (!s || fd < 0) return MQVPN_ERR_INVALID_ARG;
    s->udp_fd = fd;
    if (local_addr && local_addrlen > 0) {
        if (local_addrlen > sizeof(s->local_addr)) local_addrlen = sizeof(s->local_addr);
        memcpy(&s->local_addr, local_addr, local_addrlen);
        s->local_addrlen = local_addrlen;
    }
    return MQVPN_OK;
}

int
mqvpn_server_start(mqvpn_server_t *s)
{
    if (!s) return MQVPN_ERR_INVALID_ARG;
    ASSERT_TICK_THREAD(s);

    if (s->started) return MQVPN_ERR_INVALID_ARG;
    s->started = 1;

    /* Notify platform of TUN configuration via callback */
    mqvpn_tunnel_info_t info = {0};
    info.struct_size = sizeof(info);

    struct in_addr srv_addr;
    mqvpn_addr_pool_server_addr(&s->pool, &srv_addr);
    memcpy(info.assigned_ip, &srv_addr.s_addr, 4);
    info.assigned_prefix = (uint8_t)s->pool.prefix_len;
    memcpy(info.server_ip, &s->pool.base.s_addr, 4);
    info.server_prefix = (uint8_t)s->pool.prefix_len;
    s->tun_mtu = s->config.tun_mtu > 0 ? s->config.tun_mtu : MQVPN_TUN_MTU_AUTO;
    info.mtu = s->tun_mtu;

    if (s->pool.has_v6) {
        struct in6_addr srv_addr6;
        mqvpn_addr_pool_server_addr6(&s->pool, &srv_addr6);
        memcpy(info.assigned_ip6, &srv_addr6, 16);
        info.assigned_prefix6 = (uint8_t)s->pool.prefix6;
        info.has_v6 = 1;
    }

    s->cbs.tunnel_config_ready(&info, s->user_ctx);

    LOG_I(s, "server started (subnet=%s, max_clients=%d)", s->config.subnet,
          s->max_clients);
    return MQVPN_OK;
}

int
mqvpn_server_stop(mqvpn_server_t *s)
{
    if (!s) return MQVPN_ERR_INVALID_ARG;
    ASSERT_TICK_THREAD(s);
    s->started = 0;
    return MQVPN_OK;
}

/* ─── I/O feed ─── */

int
mqvpn_server_on_socket_recv(mqvpn_server_t *s, const uint8_t *pkt, size_t len,
                            const struct sockaddr *peer, socklen_t peer_len)
{
    if (!s || !pkt || len == 0 || len > 65536) return MQVPN_ERR_INVALID_ARG;
    ASSERT_TICK_THREAD(s);
    if (!s->engine) return MQVPN_ERR_ENGINE;

    uint64_t recv_time = now_us();
    xqc_int_t ret = xqc_engine_packet_process(
        s->engine, pkt, len, (struct sockaddr *)&s->local_addr, s->local_addrlen, peer,
        peer_len, (xqc_usec_t)recv_time, s);
    if (ret != XQC_OK) {
        LOG_D(s, "packet_process: %d", ret);
    }
    return MQVPN_OK;
}

void
mqvpn_server_on_egress_fd_ready(mqvpn_server_t *s, int fd, void *fd_ctx, int readable,
                                int writable)
{
#ifdef MQVPN_HYBRID_TCP_EGRESS_ENABLED
    svr_tcp_egress_fd_ready(s, fd, fd_ctx, readable, writable);
#else
    (void)s;
    (void)fd;
    (void)fd_ctx;
    (void)readable;
    (void)writable;
#endif
}

int
mqvpn_server_egress_fd_budget(mqvpn_server_t *s)
{
    /* Frozen snapshot from mqvpn_server_new — see svr_compute_egress_fd_
     * budget and the egress_fd_budget field comment for why this must not
     * recompute per call. Fed by config.hybrid.tcp_max_global_flows
     * (TcpMaxGlobalFlows in INI/JSON). */
    if (!s) return 0;
    return s->egress_fd_budget;
}

int
mqvpn_server_on_tun_packet(mqvpn_server_t *s, const uint8_t *pkt, size_t len)
{
    if (!s || !pkt || len == 0) return MQVPN_ERR_INVALID_ARG;
    ASSERT_TICK_THREAD(s);

    if (s->n_sessions == 0) return MQVPN_OK;
    if (s->tun_paused) return MQVPN_ERR_AGAIN;
    uint8_t ip_ver = pkt[0] >> 4;
    svr_conn_t *target = NULL;

    if (ip_ver == 4 && len >= 20) {
        struct in_addr dst_ip;
        memcpy(&dst_ip.s_addr, pkt + 16, 4);
        uint32_t offset = ntohl(dst_ip.s_addr) - ntohl(s->pool.base.s_addr);
        if (offset == 0 || offset > MQVPN_ADDR_POOL_MAX) return MQVPN_OK;
        target = s->sessions[offset];
    } else if (ip_ver == 6 && len >= 40 && s->pool.has_v6) {
        struct in6_addr dst_ip6;
        memcpy(&dst_ip6, pkt + 24, 16);
        uint32_t offset = mqvpn_addr_pool_offset6(&s->pool, &dst_ip6);
        if (offset == 0 || offset > MQVPN_ADDR_POOL_MAX) return MQVPN_OK;
        target = s->sessions[offset];
    } else {
        return MQVPN_OK;
    }

    if (!target || !target->tunnel_established) {
        /* §7.3: ICMP Dest Unreachable for unknown destination (rate limited) */
        if (ip_ver == 4) {
            if (ptb_rate_allow(s)) {
                struct in_addr srv;
                mqvpn_addr_pool_server_addr(&s->pool, &srv);
                mqvpn_icmp_send_v4(s->cbs.tun_output, s->user_ctx,
                                   (const uint8_t *)&srv.s_addr, 3, 1, 0, pkt, len);
                LOG_D(s, "sent ICMP Dest Unreachable to TUN");
            }
        } else {
            if (s->pool.has_v6 && ptb_rate_allow(s)) {
                struct in6_addr srv6;
                mqvpn_addr_pool_server_addr6(&s->pool, &srv6);
                mqvpn_icmp_send_v6(s->cbs.tun_output, s->user_ctx, srv6.s6_addr, 1, 3, 0,
                                   pkt, len);
                LOG_D(s, "sent ICMPv6 Dest Unreachable to TUN");
            }
        }
        return MQVPN_OK;
    }

    /* §5/§9: reorder gating decides STAMP vs RAW vs DROP_MTU. Stamping is gated
     * on peer support (§19.3/§19.4): until the client advertised mqvpn-reorder,
     * everything stays RAW. The peek runs on the bare inner IP (5-tuple is
     * TTL-independent), with udp_mss as the "max inner without reorder" budget
     * (§9 — a STAMP consumes 8 of those bytes). */
    size_t udp_mss = 0;
    if (target->dgram_mss > 0)
        udp_mss = xqc_h3_ext_masque_udp_mss(target->dgram_mss, target->masque_stream_id);

    mqvpn_reorder_tx_peek_t peek = {0};
    int do_stamp = 0;
    size_t ptb_mtu = 0;
    mqvpn_rgate_verdict_t rv = mqvpn_rgate_decide(
        target->reorder_tx, target->peer_reorder_supported, s->config.reorder.mode, pkt,
        len, now_us(), (uint32_t)udp_mss, &do_stamp, &peek, &ptb_mtu);
    if (rv == MQVPN_RGATE_DROP_REORDER_MTU || rv == MQVPN_RGATE_DROP_RAW_MTU) {
        int sent;
        if (ip_ver == 4) {
            struct in_addr srv;
            mqvpn_addr_pool_server_addr(&s->pool, &srv);
            sent = mqvpn_rgate_send_ptb(&s->ptb_bucket, now_ms_mono(), 4, /*addr_ok=*/1,
                                        (const uint8_t *)&srv.s_addr, ptb_mtu,
                                        s->cbs.tun_output, s->user_ctx, pkt, len);
        } else {
            struct in6_addr srv6;
            mqvpn_addr_pool_server_addr6(&s->pool, &srv6);
            sent = mqvpn_rgate_send_ptb(&s->ptb_bucket, now_ms_mono(), 6, s->pool.has_v6,
                                        srv6.s6_addr, ptb_mtu, s->cbs.tun_output,
                                        s->user_ctx, pkt, len);
        }
        if (sent) {
            if (rv == MQVPN_RGATE_DROP_REORDER_MTU) {
                if (ip_ver == 4)
                    LOG_D(s, "sent ICMP Frag Needed (reorder mtu=%zu) to TUN", ptb_mtu);
                else
                    LOG_D(s, "sent ICMPv6 PTB (reorder mtu=%zu) to TUN", ptb_mtu);
            } else {
                if (ip_ver == 4)
                    LOG_D(s, "sent ICMP Fragmentation Needed (mtu=%zu) to TUN", ptb_mtu);
                else
                    LOG_D(s, "sent ICMPv6 Packet Too Big (mtu=%zu) to TUN", ptb_mtu);
            }
        }
        return MQVPN_OK;
    }

    /* §7.3 step 4: TTL / Hop Limit decrement (RFC 9484 §4.3) */
    uint8_t fwd_pkt[PACKET_BUF_SIZE];
    if (len > sizeof(fwd_pkt)) return MQVPN_ERR_INVALID_ARG;
    memcpy(fwd_pkt, pkt, len);

    if (ip_ver == 4) {
        if (fwd_pkt[8] <= 1) {
            /* DL: source is on TUN side → ICMP goes via tun_output */
            if (ptb_rate_allow(s)) {
                struct in_addr srv;
                mqvpn_addr_pool_server_addr(&s->pool, &srv);
                mqvpn_icmp_send_v4(s->cbs.tun_output, s->user_ctx,
                                   (const uint8_t *)&srv.s_addr, 11, 0, 0, pkt, len);
                LOG_D(s, "sent ICMP Time Exceeded via TUN");
            }
            return MQVPN_OK;
        }
        fwd_pkt[8]--;
        uint32_t sum = ((uint32_t)fwd_pkt[10] << 8 | fwd_pkt[11]) + 0x0100;
        sum = (sum & 0xFFFF) + (sum >> 16);
        fwd_pkt[10] = (sum >> 8) & 0xFF;
        fwd_pkt[11] = sum & 0xFF;
    } else {
        if (fwd_pkt[7] <= 1) {
            if (s->pool.has_v6 && ptb_rate_allow(s)) {
                struct in6_addr srv6;
                mqvpn_addr_pool_server_addr6(&s->pool, &srv6);
                mqvpn_icmp_send_v6(s->cbs.tun_output, s->user_ctx, srv6.s6_addr, 3, 0, 0,
                                   pkt, len);
                LOG_D(s, "sent ICMPv6 Time Exceeded via TUN");
            }
            return MQVPN_OK;
        }
        fwd_pkt[7]--;
    }

    /* On STAMP, prepend the 8-byte reorder header to the TTL-decremented inner
     * IP packet; the framed payload is then [hdr || fwd_pkt]. On RAW, frame the
     * bare fwd_pkt (current behavior). */
    const uint8_t *frame_src = fwd_pkt;
    size_t frame_src_len = len;
    uint8_t stamped[MQVPN_REORDER_HDR_LEN + PACKET_BUF_SIZE];
    if (do_stamp) {
        memcpy(stamped, peek.hdr, MQVPN_REORDER_HDR_LEN);
        memcpy(stamped + MQVPN_REORDER_HDR_LEN, fwd_pkt, len);
        frame_src = stamped;
        frame_src_len = len + MQVPN_REORDER_HDR_LEN;
    }

    /* MASQUE frame and send */
    uint8_t frame_buf[MASQUE_FRAME_BUF];
    size_t frame_written = 0;
    xqc_int_t xret =
        xqc_h3_ext_masque_frame_udp(frame_buf, sizeof(frame_buf), &frame_written,
                                    target->masque_stream_id, frame_src, frame_src_len);
    if (xret != XQC_OK) return MQVPN_ERR_ENGINE;

    uint64_t dgram_id;
    uint32_t fh =
        flow_hash_pkt(pkt, (int)len, s->config.scheduler == MQVPN_SCHED_WLB_UDP_PIN);
    xqc_conn_set_dgram_flow_hash(xqc_h3_conn_get_xqc_conn(target->h3_conn), fh);
    xret = xqc_h3_ext_datagram_send(target->h3_conn, frame_buf, frame_written, &dgram_id,
                                    mqvpn_dgram_qos_level(s->config.scheduler));

    if (xret == -XQC_EAGAIN) {
        s->tun_paused = 1;
        LOG_D(s, "TUN read paused (QUIC backpressure)");
        return MQVPN_ERR_AGAIN;
    }
    if (xret == XQC_OK) {
        s->dgram_sent++;
        /* §10.3: advance the send_flow sequence only on a successful datagram. */
        if (do_stamp) mqvpn_reorder_tx_commit(target->reorder_tx, &peek, now_us());
    }
    if (xret < 0) {
        LOG_D(s, "datagram_send: %d", xret);
    }

    return MQVPN_OK;
}

/* ─── Tick ─── */

int
mqvpn_server_tick(mqvpn_server_t *s)
{
    if (!s) return MQVPN_ERR_INVALID_ARG;
    ASSERT_TICK_THREAD(s);

    if (s->engine) xqc_engine_main_logic(s->engine);

    /* §5/§11.1: drive reorder RX gap timeouts + idle eviction for every active
     * session. Sessions are indexed by pool offset (1..MAX); the slot is set
     * only after ADDRESS_ASSIGN, but a conn's reorder_rx exists from accept. */
    if (s->config.reorder.mode != MQVPN_REORDER_OFF && s->n_sessions > 0) {
        uint64_t t = now_us();
        for (int i = 1; i <= MQVPN_ADDR_POOL_MAX; i++) {
            svr_conn_t *conn = s->sessions[i];
            if (conn && conn->reorder_rx) mqvpn_reorder_rx_tick(conn->reorder_rx, t);
        }
    }

#ifdef MQVPN_HYBRID_TCP_EGRESS_ENABLED
    /* Connect-timeout sweep over the D3 egress-flow list (one list, one
     * tick function — the future ACTIVE-idle-timeout work extends this
     * same walk rather than adding a second sweep). */
    svr_tcp_egress_tick(s, now_us());
#endif

    return MQVPN_OK;
}

/* ─── Query functions ─── */

int
mqvpn_server_get_stats(const mqvpn_server_t *s, mqvpn_stats_t *out)
{
    if (!s || !out) return MQVPN_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->bytes_tx = s->bytes_tx;
    out->bytes_rx = s->bytes_rx;
    out->dgram_sent = s->dgram_sent;
    out->dgram_recv = s->dgram_recv;
    out->dgram_lost = s->dgram_lost;
    out->dgram_acked = s->dgram_acked;
#ifdef MQVPN_HYBRID_TCP_EGRESS_ENABLED
    /* tcp_flows_active: whole-server count of currently open egress TCP
     * flows. tcp_egress_global_fd_count is the live, exactly-once
     * incremented/decremented admission counter (svr_tcp_egress_start_connect
     * / svr_tcp_egress_flow_destroy) — no separate list-length walk needed.
     * tcp_flows_total: cumulative admitted egress flows (never decrements).
     * tcp_flows_rejected: cumulative cap-503 rejections (global fd-budget +
     * per-session tcp_max_flows caps; ACL 403s and 5xx syscall failures are
     * not caps and are not counted). See tcp_egress.c for the sites. */
    out->tcp_flows_active = (uint64_t)s->tcp_egress_global_fd_count;
    out->tcp_flows_total = s->tcp_egress_flows_total_opened;
    out->tcp_flows_rejected = s->tcp_egress_flows_rejected_cap;
#endif
    return MQVPN_OK;
}

uint64_t
mqvpn_server_uptime_seconds(const mqvpn_server_t *s)
{
    if (!s) return 0;
    uint64_t cur = now_us();
    if (cur <= s->boot_us) return 0;
    return (cur - s->boot_us) / 1000000;
}

const char *
mqvpn_server_scheduler_label(const mqvpn_server_t *s)
{
    if (!s) return "unknown";
    return mqvpn_scheduler_label(s->config.scheduler);
}

/* xqc_path_state_t values (private xqc_multipath.h). Uses the mqvpn mirror
 * constants rather than the xquic enum so this TU need not include xquic
 * internal headers — the values are part of the xquic stats contract and
 * are surfaced through the public control API. Every value is pinned to the
 * real enum by tests/test_xquic_abi_pin.c, so an upstream renumber fails
 * the build instead of silently mislabeling paths. */
const char *
mqvpn_path_state_label(int state)
{
    switch (state) {
    case MQVPN_XQC_PATH_STATE_INIT: return "init";
    case MQVPN_XQC_PATH_STATE_VALIDATING: return "validating";
    case MQVPN_XQC_PATH_STATE_ACTIVE: return "active";
    case MQVPN_XQC_PATH_STATE_CLOSING: return "closing";
    case MQVPN_XQC_PATH_STATE_CLOSED: return "closed";
    default: return "unknown";
    }
}

/* Derive an operator-readable mp_state label by walking the per-path metrics
 * xquic populated. The raw xqc_conn_stats_t.mp_state field only distinguishes
 * "no multipath / not validated / validated" (values 0/2/1, see
 * xqc_multipath.c::xqc_conn_path_metrics_print) and cannot answer the
 * operationally interesting question "is the standby path the only one
 * carrying traffic right now?". The path-class signal lives in
 * paths_info[].path_app_status, which we summarise here.
 *
 * Result classes (returned as static strings):
 *   single_path           <= 1 active path, or multipath disabled
 *   active_with_standby   >= 2 active paths, mix of available + standby (good)
 *   standby_only          >= 1 standby active and 0 available (degraded)
 *   active_only           >= 2 active paths, all available, no standby
 *   unknown               NULL stats argument */
static const char *
derive_mp_state_label(const xqc_conn_stats_t *st)
{
    /* This function reads path_app_status via the public XQC_APP_PATH_STATUS_*
     * symbols (below), so it does not depend on their numeric values. The
     * path_state values it does depend on (via MQVPN_XQC_PATH_STATE_ACTIVE)
     * are pinned in tests/test_xquic_abi_pin.c. */
    if (!st) return "unknown";

    int available = 0, standby = 0;
    /* paths_info is now dynamically allocated (xquic PR3 §4.3 Rev 4);
     * iterate by paths_info_count. paths_info may be NULL when count==0. */
    for (uint32_t i = 0; st->paths_info && i < st->paths_info_count; i++) {
        const xqc_path_metrics_t *p = &st->paths_info[i];
        /* Only count ACTIVE paths; paths that are still validating,
         * closing, or already closed should not influence the
         * operator-facing label. */
        if (p->path_state != MQVPN_XQC_PATH_STATE_ACTIVE) continue;
        /* FROZEN means xquic flushed the send buffer and stopped forwarding
         * on that path (xqc_set_application_path_status, xqc_multipath.c).
         * It cannot contribute to operational redundancy — neither as
         * available nor as standby — so exclude it entirely. NONE and
         * AVAILABLE are both counted as available, matching xquic's own
         * convention in xqc_request_path_metrics_print. */
        if (p->path_app_status == XQC_APP_PATH_STATUS_FROZEN) continue;
        if (p->path_app_status == XQC_APP_PATH_STATUS_STANDBY) {
            standby++;
        } else {
            available++;
        }
    }

    int total = available + standby;
    if (total <= 1) return "single_path";
    if (available > 0 && standby > 0) return "active_with_standby";
    if (standby > 0) return "standby_only"; /* available == 0 */
    return "active_only";                   /* standby == 0 */
}

int
mqvpn_server_get_client_fec_stats(const mqvpn_server_t *s, const char *user,
                                  mqvpn_internal_fec_stats_t *out)
{
    /* NULL args are caller bugs. Map to -1 so the caller doesn't confuse them
     * with the legitimate "user not found" sentinel (0). */
    if (!s || !user || !out) return -1;
    memset(out, 0, sizeof(*out));

#ifndef XQC_ENABLE_FEC
    (void)s;
    (void)user;
    return -1;
#else
    /* sessions[] is a sparse pointer array; iterate non-null slots. Skip
     * connections that haven't completed the MASQUE tunnel — xqc_conn_get_stats
     * returns zeroed counters for half-attached conns, which would falsely
     * report (1, all-zero) and pollute the Prometheus output. Same guard as
     * mqvpn_server_get_client_info. */
    for (int i = 1; i <= MQVPN_ADDR_POOL_MAX; i++) {
        svr_conn_t *conn = s->sessions[i];
        if (!conn || !conn->tunnel_established) continue;
        if (strncmp(conn->username, user, sizeof(conn->username)) != 0) continue;

        xqc_conn_stats_t st = xqc_conn_get_stats(s->engine, &conn->cid);
        out->enable_fec = (uint8_t)st.enable_fec;
        out->mp_state = (uint8_t)st.mp_state;
        out->mp_state_label = derive_mp_state_label(&st);
        out->fec_send_cnt = (uint64_t)st.send_fec_cnt;
        out->fec_recover_cnt = (uint64_t)st.fec_recover_pkt_cnt;
        out->lost_dgram_cnt = (uint64_t)st.lost_dgram_count;
        out->total_app_bytes = st.total_app_bytes;
        out->standby_app_bytes = st.standby_path_app_bytes;
        free(st.paths_info);
        return 1;
    }
    return 0;
#endif
}

int
mqvpn_server_get_all_fec_stats(const mqvpn_server_t *s, mqvpn_internal_fec_entry_t *out,
                               int max)
{
    if (!s || !out || max <= 0) return -1;

#ifndef XQC_ENABLE_FEC
    (void)s;
    (void)out;
    (void)max;
    return -1;
#else
    int n = 0;
    for (int i = 1; i <= MQVPN_ADDR_POOL_MAX && n < max; i++) {
        svr_conn_t *conn = s->sessions[i];
        if (!conn || !conn->tunnel_established) continue;

        xqc_conn_stats_t st = xqc_conn_get_stats(s->engine, &conn->cid);
        mqvpn_internal_fec_entry_t *e = &out[n];

        size_t ulen = strnlen(conn->username, sizeof(e->user) - 1);
        memcpy(e->user, conn->username, ulen);
        e->user[ulen] = '\0';

        e->stats.enable_fec = (uint8_t)st.enable_fec;
        e->stats.mp_state = (uint8_t)st.mp_state;
        e->stats.mp_state_label = derive_mp_state_label(&st);
        e->stats.fec_send_cnt = (uint64_t)st.send_fec_cnt;
        e->stats.fec_recover_cnt = (uint64_t)st.fec_recover_pkt_cnt;
        e->stats.lost_dgram_cnt = (uint64_t)st.lost_dgram_count;
        e->stats.total_app_bytes = st.total_app_bytes;
        e->stats.standby_app_bytes = st.standby_path_app_bytes;
        free(st.paths_info);
        n++;
    }
    return n;
#endif
}

int
mqvpn_server_get_reorder_stats(const mqvpn_server_t *s, mqvpn_reorder_stats_t *out)
{
    if (!s || !out) return -1;
    memset(out, 0, sizeof(*out));

    /* Sum the per-conn RX snapshots across every live session that built a
     * reorder engine. reorder_rx is NULL on conns where reorder mode is OFF or
     * engine alloc failed (RAW fallback) — skip those. Unlike the FEC getters
     * we don't gate on tunnel_established: reorder_rx is only created during
     * accept and only ever fed post-tunnel, so a non-NULL reorder_rx already
     * implies an attached conn; its counters are zero until traffic flows. */
    for (int i = 1; i <= MQVPN_ADDR_POOL_MAX; i++) {
        svr_conn_t *conn = s->sessions[i];
        if (!conn || !conn->reorder_rx) continue;

        mqvpn_reorder_stats_t st;
        mqvpn_reorder_rx_get_stats(conn->reorder_rx, &st);

        /* Reuse the engine's single accumulation path so every stats field
         * (incl. the residence histogram + max) is carried — a hand-rolled
         * field list here silently dropped residence_bucket[]/residence_max_us. */
        mqvpn_reorder_stats_accumulate(out, &st);
    }
    return 0;
}

int
mqvpn_server_get_n_clients(const mqvpn_server_t *s)
{
    if (!s) return 0;
    return s->n_sessions;
}

int
mqvpn_server_list_users(const mqvpn_server_t *s, char names[][64], int max)
{
    if (!s || !names || max <= 0) return 0;
    int n = s->config.n_users < max ? s->config.n_users : max;
    for (int i = 0; i < n; i++)
        snprintf(names[i], 64, "%s", s->config.user_names[i]);
    return n;
}

int
mqvpn_server_add_user(mqvpn_server_t *s, const char *username, const char *key)
{
    if (!s || !username || !key || username[0] == '\0' || key[0] == '\0')
        return MQVPN_ERR_INVALID_ARG;

    /* Reject characters that would break JSON serialization in control API */
    for (const char *p = username; *p; p++) {
        if (*p == '"' || *p == '\\' || (unsigned char)*p < 0x20)
            return MQVPN_ERR_INVALID_ARG;
    }

    for (int i = 0; i < s->config.n_users; i++) {
        if (strcmp(s->config.user_names[i], username) == 0) {
            snprintf(s->config.user_keys[i], sizeof(s->config.user_keys[i]), "%s", key);
            return MQVPN_OK;
        }
    }

    if (s->config.n_users >= MQVPN_MAX_USERS) return MQVPN_ERR_MAX_CLIENTS;

    snprintf(s->config.user_names[s->config.n_users],
             sizeof(s->config.user_names[s->config.n_users]), "%s", username);
    snprintf(s->config.user_keys[s->config.n_users],
             sizeof(s->config.user_keys[s->config.n_users]), "%s", key);
    s->config.n_users++;
    return MQVPN_OK;
}

int
mqvpn_server_remove_user(mqvpn_server_t *s, const char *username)
{
    if (!s || !username || username[0] == '\0') return MQVPN_ERR_INVALID_ARG;

    int found = 0;
    for (int i = 0; i < s->config.n_users; i++) {
        if (strcmp(s->config.user_names[i], username) == 0) {
            for (int j = i + 1; j < s->config.n_users; j++) {
                memcpy(s->config.user_names[j - 1], s->config.user_names[j],
                       sizeof(s->config.user_names[j - 1]));
                memcpy(s->config.user_keys[j - 1], s->config.user_keys[j],
                       sizeof(s->config.user_keys[j - 1]));
            }
            s->config.n_users--;
            found = 1;
            break;
        }
    }
    if (!found) return MQVPN_ERR_INVALID_ARG;

    /* Disconnect active sessions for the removed user */
    for (int i = 1; i <= MQVPN_ADDR_POOL_MAX; i++) {
        svr_conn_t *conn = s->sessions[i];
        if (!conn) continue;
        if (strcmp(conn->username, username) == 0) {
            LOG_I(s, "disconnecting session for removed user '%s'", username);
            xqc_h3_conn_close(s->engine, &conn->cid);
        }
    }

    return MQVPN_OK;
}

int
mqvpn_server_get_client_info(const mqvpn_server_t *server, mqvpn_client_info_t *out,
                             int max_clients, int *n_clients)
{
    if (!server || !out || max_clients <= 0 || !n_clients) return MQVPN_ERR_INVALID_ARG;

    mqvpn_server_t *s = (mqvpn_server_t *)server;
    int count = 0;

    for (int i = 1; i <= MQVPN_ADDR_POOL_MAX && count < max_clients; i++) {
        svr_conn_t *conn = s->sessions[i];
        if (!conn || !conn->tunnel_established) continue;

        mqvpn_client_info_t *ci = &out[count];
        memset(ci, 0, sizeof(*ci));
        ci->struct_size = sizeof(*ci);
        snprintf(ci->username, sizeof(ci->username), "%s", conn->username);

        /* Format endpoint. peer_addr is sockaddr_storage because xquic may
         * deliver either sockaddr_in (IPv4 socket → 16 B) or sockaddr_in6
         * (IPv6 socket → 28 B). Dispatch by ss_family; for IPv6 also unwrap
         * IPv4-mapped (::ffff:x.x.x.x) so the dashboard shows the real v4. */
        char addr_str[INET6_ADDRSTRLEN] = {0};
        uint16_t port = 0;
        if (conn->peer_addr.ss_family == AF_INET) {
            const struct sockaddr_in *s4 = (const struct sockaddr_in *)&conn->peer_addr;
            inet_ntop(AF_INET, &s4->sin_addr, addr_str, sizeof(addr_str));
            port = ntohs(s4->sin_port);
        } else if (conn->peer_addr.ss_family == AF_INET6) {
            const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)&conn->peer_addr;
            const uint8_t *b = s6->sin6_addr.s6_addr;
            if (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 && b[4] == 0 &&
                b[5] == 0 && b[6] == 0 && b[7] == 0 && b[8] == 0 && b[9] == 0 &&
                b[10] == 0xff && b[11] == 0xff) {
                struct in_addr v4;
                memcpy(&v4, &b[12], 4);
                inet_ntop(AF_INET, &v4, addr_str, sizeof(addr_str));
            } else {
                inet_ntop(AF_INET6, &s6->sin6_addr, addr_str, sizeof(addr_str));
            }
            port = ntohs(s6->sin6_port);
        }
        snprintf(ci->endpoint, sizeof(ci->endpoint), "%s:%u", addr_str, port);

        ci->connected_at_us = conn->connected_at_us;

        /* Get xquic per-path stats. paths_info is dynamically allocated
         * (xquic PR3 §4.3 Rev 4); caller must free(). */
        xqc_conn_stats_t st = xqc_conn_get_stats(s->engine, &conn->cid);
        ci->bytes_tx = st.total_app_bytes;
        ci->bytes_rx = 0;
        for (uint32_t p = 0; st.paths_info && p < st.paths_info_count; p++)
            ci->bytes_rx += st.paths_info[p].path_recv_bytes;

        int np = 0;
        for (uint32_t p = 0;
             st.paths_info && p < st.paths_info_count && np < MQVPN_MAX_PATHS; p++) {
            xqc_path_metrics_t *pm = &st.paths_info[p];

            mqvpn_path_stats_t *ps = &ci->paths[np];
            ps->struct_size = sizeof(*ps);
            ps->path_id = pm->path_id;
            ps->srtt_us = pm->path_srtt;
            ps->min_rtt_us = pm->path_min_rtt;
            ps->cwnd = pm->path_cwnd;
            ps->bytes_in_flight = pm->path_bytes_in_flight;
            ps->bytes_tx = pm->path_send_bytes;
            ps->bytes_rx = pm->path_recv_bytes;
            ps->pkt_sent = pm->path_pkt_send_count;
            ps->pkt_recv = pm->path_pkt_recv_count;
            ps->pkt_lost = pm->path_lost_count;
            ps->state = pm->path_state;
            np++;
        }
        ci->n_paths = np;
        free(st.paths_info);
        count++;
    }

    *n_clients = count;
    return MQVPN_OK;
}

int
mqvpn_server_get_interest(const mqvpn_server_t *s, mqvpn_interest_t *out)
{
    if (!s || !out) return MQVPN_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);

    int ms = (int)(s->next_wake_us / 1000);
    out->next_timer_ms = ms > 0 ? ms : 1;
#ifdef MQVPN_HYBRID_TCP_EGRESS_ENABLED
    /* next_wake_us above comes solely from xquic's event timer, which knows
     * nothing about the egress deadlines (connect timeout -> 504, ACTIVE
     * idle eviction) that svr_tcp_egress_tick enforces — on a quiet server
     * they could otherwise fire arbitrarily late. Clamp to a 1s ceiling
     * whenever any egress flow is live: a simple clamp on purpose (not the
     * exact nearest deadline — both deadlines have seconds granularity, so
     * sub-second precision buys nothing and the clamp can't go stale). */
    if (s->tcp_egress_flow_list_head != NULL && out->next_timer_ms > 1000)
        out->next_timer_ms = 1000;
#endif
    out->tun_readable = s->tun_paused ? 0 : 1;
    out->is_idle = (s->n_sessions == 0) ? 1 : 0;
    return MQVPN_OK;
}
