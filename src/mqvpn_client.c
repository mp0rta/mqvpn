// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * mqvpn_client.c — Client lifecycle, xquic engine, MASQUE CONNECT-IP
 *
 * Part of libmqvpn. No platform I/O — all I/O via callbacks.
 */

#include "libmqvpn.h"
#include "mqvpn_internal.h"
#include "mqvpn_scheduler.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  include <process.h>
#  define MSG_DONTWAIT 0
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
#  include <arpa/inet.h>
#  include <pthread.h>
#endif
#ifndef _WIN32
#  include <errno.h>
#endif
#include <inttypes.h>
#include <time.h>
#include <assert.h>

#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>

#include "flow_sched.h"
#include "hybrid/classifier.h"
#ifdef MQVPN_HYBRID_TCP_LANE_ENABLED
#  include "hybrid/lwip_glue.h"
#  include "hybrid/tcp_lane.h"
#endif
#include "icmp.h"
#include "path_state_machine.h"
#include "reorder.h"
#include "reorder_rx.h"
#include "reorder_tx.h"

/* ─── Constants ─── */

#define PACKET_BUF_SIZE           65536
#define MASQUE_FRAME_BUF          (PACKET_BUF_SIZE + 16)
#define MAX_CAPSULE_BUF           65536
#define RECONNECT_BACKOFF_MAX_SEC 60
/* Force-close the QUIC handshake if it doesn't progress past CONNECTING within
 * this window, so a dead first-listed path triggers reconnect (and primary_path_idx
 * rotation, issue #46) rather than waiting for xquic's idle_time_out (120s). */
#define HANDSHAKE_STALL_TIMEOUT_MS 5000
#define PTB_RATE_LIMIT             10
/* PATH_RECREATE_* and PATH_STABLE_THRESHOLD_US relocated to path_state_machine.h
 * for PR4 — shared with path_state_machine.c. */
#define SOCKET_BUF_SIZE (7 * 1024 * 1024) /* 7 MiB socket buffer */

/* ─── Forward declarations ─── */

typedef struct cli_conn_s cli_conn_t;
typedef struct cli_stream_s cli_stream_t;

static int cli_start_connection(mqvpn_client_t *c);
static void cli_conn_destroy(mqvpn_client_t *c);

/* Look up xquic per-path metrics by path_id in a stats snapshot.
 *
 * xqc_conn_stats_t.paths_info is a dynamically allocated buffer of
 * paths_info_count entries (xquic PR3 §4.3 Rev 4). Returns NULL if
 * path_id is not found. Read-only — caller may inspect any pm->* field
 * but must not write through the pointer. */
static inline const xqc_path_metrics_t *
xqc_find_path_metrics(const xqc_conn_stats_t *stats, uint64_t path_id)
{
    if (stats->paths_info == NULL) return NULL;
    for (uint32_t j = 0; j < stats->paths_info_count; j++) {
        const xqc_path_metrics_t *pm = &stats->paths_info[j];
        if (pm->path_id == path_id) return pm;
    }
    return NULL;
}

/* ─── Internal types ─── */

/* Per-path entry (Level 1 — survives reconnect).
 * Definition lives in path_entry_internal.h so that path_state_machine.c
 * and test_path_state_machine can construct slots directly. */
#include "path_entry_internal.h"

/* Per-connection state (Level 2 — destroyed on reconnect) */
struct cli_conn_s {
    mqvpn_client_t *client;
    xqc_h3_conn_t *h3_conn;
    xqc_cid_t cid;
    size_t dgram_mss;
    xqc_h3_request_t *masque_request;
    uint64_t masque_stream_id;
    int tunnel_ok;
    int addr_assigned;
    uint8_t assigned_ip[4];
    uint8_t assigned_prefix;
    int addr6_assigned;
    uint8_t assigned_ip6[16];
    uint8_t assigned_prefix6;
    uint64_t dgram_lost_cnt;
    uint64_t dgram_acked_cnt;

    /* Flow-aware reorder shim (§5). Created on connect when
     * cfg.reorder.mode != OFF, freed on conn teardown. peer_reorder_supported
     * gates TX stamping (§19.3/§19.4): set once negotiation confirms the peer
     * advertised mqvpn-reorder. */
    mqvpn_reorder_tx_t *reorder_tx;
    mqvpn_reorder_rx_t *reorder_rx;
    int peer_reorder_supported;

#ifdef MQVPN_HYBRID_TCP_LANE_ENABLED
    /* H2: lwIP TCP-lane stack. Created at tunnel-ready (needs the resolved
     * inner MTU) when hybrid is enabled and tcp mode != raw; freed on conn
     * teardown. This struct is private to this TU, so gating the field on
     * the build flag is ODR-safe. */
    mqvpn_lwip_ctx_t *lwip_ctx;
    /* H2: sticky per-flow lane table. Created ONLY when lwip_ctx creation
     * succeeded (the ingress fast path guards on tcp_lane alone and feeds
     * lwip_ctx, so the two must be coherent: both live or both NULL). Freed
     * BEFORE lwip_ctx on teardown — tcp_lane will eventually own pcb aborts
     * against the still-live stack. */
    mqvpn_tcp_lane_t *tcp_lane;
#endif
};

/* Role of an H3 request stream. v0.8 has exactly one role; hybrid mode's
 * connect-tcp streams add more. Body/header handling in cb_request_read
 * dispatches on this. */
typedef enum {
    CLI_STREAM_ROLE_CONNECT_IP = 0,
#ifdef MQVPN_HYBRID_TCP_LANE_ENABLED
    CLI_STREAM_ROLE_CONNECT_TCP,
#endif
} cli_stream_role_t;

/* Per-stream state (Level 2) */
struct cli_stream_s {
    cli_conn_t *conn;
    xqc_h3_request_t *h3_request;
    cli_stream_role_t role;
    uint8_t *capsule_buf;
    size_t capsule_len;
    size_t capsule_cap;
};

/* ─── Client handle (opaque mqvpn_client_t) ─── */

struct mqvpn_client_s {
    /* Config (deep copy, Level 1) */
    mqvpn_config_t config;
    mqvpn_client_callbacks_t cbs;
    void *user_ctx;

    /* State machine */
    mqvpn_client_state_t state;

    /* xquic engine (Level 1) */
    xqc_engine_t *engine;

    /* Connection (Level 2, NULL when disconnected) */
    cli_conn_t *conn;

    /* Server address */
    struct sockaddr_storage server_addr;
    socklen_t server_addrlen;

    /* Tunnel info (after TUNNEL_READY) */
    uint8_t assigned_ip[4];
    uint8_t assigned_prefix;
    uint8_t server_ip[4];
    uint8_t server_prefix;
    int mtu;
    uint8_t assigned_ip6[16];
    uint8_t assigned_prefix6;
    int has_v6;
    int tun_active;
    int backpressure;
    int last_notified_mtu;

    /* Stats */
    uint64_t bytes_tx;
    uint64_t bytes_rx;
    uint64_t dgram_sent;
    uint64_t dgram_recv;
    uint64_t dgram_lost;
    uint64_t dgram_acked;
    /* Hybrid-mode per-lane TX counters. Stay 0 unless hybrid is enabled.
     * tcp_flows_rejected counts SYNs that wanted the TCP lane but were
     * refused pre-lwIP (cap or alloc failure); authoritative source for the
     * public tcp_flows_rejected stat surfaced by mqvpn_client_get_stats,
     * which reads THIS counter, not the lane's flows_rejected_cap — summing
     * them would double-count (the lane's rejected_cap/rejected_other split
     * overlaps this but is not equal). pkts_lane_tcp_dropped counts packets
     * lwIP refused. */
    uint64_t pkts_lane_tcp;
    uint64_t pkts_lane_dgram;
    uint64_t pkts_lane_raw;
    uint64_t tcp_flows_rejected;
    uint64_t pkts_lane_tcp_dropped;
    int srtt_ms;

    /* Multipath (Level 1) */
    path_entry_t paths[MQVPN_MAX_PATHS];
    int n_paths;
    int64_t next_path_handle;
    int multipath_ready; /* 1 after cb_ready_to_create_path */
    /* Path index used for the QUIC handshake. Rotated on each reconnect so a
     * dead first path doesn't trap the client forever. */
    int primary_path_idx;

    /* Reconnect */
    int reconnect_attempts;
    uint64_t reconnect_scheduled_us;
    int shutting_down;

    /* Log correlation + filtering */
    uint32_t conn_id; /* monotonic, bumped on each connect */
    mqvpn_log_level_t
        log_level; /* cached for early filtering in client_log/cb_xqc_log_write */

    /* Timer: next wake (from xquic set_event_timer) */
    uint64_t next_wake_us;

    /* Handshake stall watchdog. Set when entering CONNECTING, cleared on every
     * exit transition. Used to abort a CONNECTING that is making no progress
     * (typically a dead primary path) before xquic's 120s idle_time_out. */
    uint64_t handshake_started_us;

    /* ICMP PTB rate limit */
    int ptb_tokens;
    int64_t ptb_refill_ms;

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

/* ─── State transition table (M0-5) ─── */

static const uint8_t state_transitions[MQVPN_STATE__COUNT][MQVPN_STATE__COUNT] = {
    /*                    IDLE CONN AUTH TREADY EST  RECON CLOSE */
    /* IDLE           */ {0, 1, 0, 0, 0, 0, 0},
    /* CONNECTING     */ {0, 0, 1, 0, 0, 1, 1},
    /* AUTHENTICATING */ {0, 0, 0, 1, 0, 1, 1},
    /* TUNNEL_READY   */ {0, 0, 0, 0, 1, 0, 1},
    /* ESTABLISHED    */ {0, 0, 0, 0, 0, 1, 1},
    /* RECONNECTING   */ {0, 1, 0, 0, 0, 0, 1},
    /* CLOSED         */ {0, 0, 0, 0, 0, 0, 0},
};

int
mqvpn_state_transition_valid(mqvpn_client_state_t from, mqvpn_client_state_t to)
{
    if (from < 0 || from >= MQVPN_STATE__COUNT || to < 0 || to >= MQVPN_STATE__COUNT)
        return 0;
    return state_transitions[from][to];
}

/* ─── Helpers ─── */

static uint64_t
now_us(void)
{
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    return t / 10 - 11644473600000000ULL; /* FILETIME epoch → Unix epoch, in µs */
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;
#endif
}

/* Injectable clock: use config clock_fn if set, else default now_us().
 * PR4 — non-static + visibility hidden so path_state_machine.c can call it
 * without exporting from libmqvpn.so. MSVC ignores visibility(). */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
uint64_t
client_now_us(const mqvpn_client_t *c)
{
    if (c->config.clock_fn) return c->config.clock_fn(c->config.clock_ctx);
    return now_us();
}

/*
 * xquic timestamp adapter.
 * xqc_timestamp_pt is void→uint64_t (no user_ctx), so we use a global.
 * Safe for single-client-per-process (Android VpnService model).
 */
static mqvpn_clock_fn s_xqc_clock_fn = NULL;
static void *s_xqc_clock_ctx = NULL;

static xqc_usec_t
xqc_custom_timestamp(void)
{
    if (s_xqc_clock_fn) return s_xqc_clock_fn(s_xqc_clock_ctx);
    return now_us();
}

#ifdef MQVPN_HYBRID_TCP_LANE_ENABLED
/* lwIP glue shims (H2). Clock: same injected-clock rules as client_now_us. */
static uint64_t
cli_lwip_clock_wrapper(void *clock_ctx)
{
    return client_now_us((const mqvpn_client_t *)clock_ctx);
}

/* lwIP-generated packets (SYN-ACK, ACKs, downlink data) are locally
 * originated by the stack, not tunnel-forwarded — hand them straight to
 * cbs.tun_output (the same sink every other lane's TUN delivery ends at)
 * WITHOUT forward_inner_ip's TTL decrement / dgram stats, which are
 * forwarding semantics. */
static void
cli_lwip_output_wrapper(const uint8_t *pkt, size_t len, void *output_ctx)
{
    mqvpn_client_t *c = (mqvpn_client_t *)output_ctx;
    if (!c->tun_active) return;
    c->cbs.tun_output(pkt, len, c->user_ctx);
}
#endif /* MQVPN_HYBRID_TCP_LANE_ENABLED */

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

#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden"))) void
client_log(mqvpn_client_t *c, mqvpn_log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
#endif

/* PR4 — non-static + visibility hidden so path_state_machine.c can call it
 * without exporting from libmqvpn.so. MSVC ignores visibility(). */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
void
client_log(mqvpn_client_t *c, mqvpn_log_level_t level, const char *fmt, ...)
{
    if (!c->cbs.log || level < c->log_level) return;
    char buf[512];
    int off = snprintf(buf, sizeof(buf), "[conn:%u] ", c->conn_id);
    if (off < 0 || off >= (int)sizeof(buf)) off = 0;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf + off, sizeof(buf) - off, fmt, ap);
    va_end(ap);
    c->cbs.log(level, buf, c->user_ctx);
}

/* PR4 - Fire public path_event callback from FSM body.
 * MSVC ignores visibility(). */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
void
path_fsm_fire_path_event(mqvpn_client_t *c, const path_entry_t *p)
{
    if (c->cbs.path_event) c->cbs.path_event(p->handle, p->status, c->user_ctx);
}

/* G-P15 (draft-21 §3.3 ¶6): emit PATH_STATUS to peer when local lifecycle
 * demotes. app_status: 1=STANDBY, 2=AVAILABLE, 3=FROZEN (xqc_typedef.h).
 * No-op if engine or conn is missing (e.g. during reconnect, or for
 * pre-handshake transitions); path-status will be re-asserted by the
 * caller when the conn is re-established and the lifecycle moves again. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
void
client_notify_xqc_path_state(mqvpn_client_t *c, const path_entry_t *p, int app_status)
{
    if (!c || !c->engine || !c->conn) return;
    if (!p->xquic_path_live) return;
    const xqc_cid_t *cid = &c->conn->cid;
    uint64_t pid = p->xqc_path_id;
    switch (app_status) {
    case 1: xqc_conn_mark_path_standby(c->engine, cid, pid); break;
    case 2: xqc_conn_mark_path_available(c->engine, cid, pid); break;
    case 3: xqc_conn_mark_path_frozen(c->engine, cid, pid); break;
    default: break;
    }
}

#define LOG_D(c, ...) client_log(c, MQVPN_LOG_DEBUG, __VA_ARGS__)
#define LOG_I(c, ...) client_log(c, MQVPN_LOG_INFO, __VA_ARGS__)
#define LOG_W(c, ...) client_log(c, MQVPN_LOG_WARN, __VA_ARGS__)
#define LOG_E(c, ...) client_log(c, MQVPN_LOG_ERROR, __VA_ARGS__)

/* ─── Path observability helpers ─── */

/* PR4 — set_path_state_with_log / path_log_state_change relocated to
 * path_state_machine.c (declarations in path_state_machine.h). The bodies
 * still call client_log/client_now_us via the non-static accessors. */

/* Wrapper: check if path p has been in its current state too long, and if so
 * emit a LOG_W and debounce the next warning. */
static void
client_path_residence_check(mqvpn_client_t *c, path_entry_t *p, uint64_t now_us)
{
    if (!path_should_warn_residence(p, now_us)) return;

    switch (p->status) {
    /* The "stuck in PENDING" / "DEGRADED retry overdue" wordings are
     * grepped by scripts/ci_e2e/sanitizer_check.sh as a suite-wide
     * postcondition — rewording them silently disables that gate. */
    case MQVPN_PATH_PENDING:
        LOG_W(c, "path[%lld %s] stuck in PENDING for %llu ms", (long long)p->handle,
              p->name, (unsigned long long)((now_us - p->state_entered_at_us) / 1000));
        break;
    case MQVPN_PATH_DEGRADED:
        LOG_W(c, "path[%lld %s] DEGRADED retry overdue by %llu ms", (long long)p->handle,
              p->name, (unsigned long long)((now_us - p->recreate_after_us) / 1000));
        break;
    default: break;
    }
    p->last_residence_warn_at_us = now_us;
}

static void
client_set_state(mqvpn_client_t *c, mqvpn_client_state_t new_state)
{
    mqvpn_client_state_t old = c->state;
    if (old == new_state) return;
    assert(mqvpn_state_transition_valid(old, new_state) &&
           "mqvpn_client: invalid state transition");
    if (new_state == MQVPN_STATE_CONNECTING) {
        c->handshake_started_us = client_now_us(c);
    } else if (old == MQVPN_STATE_CONNECTING) {
        c->handshake_started_us = 0;
    }
    c->state = new_state;
    if (c->cbs.state_changed) c->cbs.state_changed(old, new_state, c->user_ctx);
}

static int
client_handshake_stalled(const mqvpn_client_t *c, uint64_t now_us)
{
    if (c->state != MQVPN_STATE_CONNECTING) return 0;
    if (c->handshake_started_us == 0) return 0;
    if (now_us <= c->handshake_started_us) return 0;
    uint64_t elapsed = now_us - c->handshake_started_us;
    return elapsed >= (uint64_t)HANDSHAKE_STALL_TIMEOUT_MS * 1000;
}

#ifndef NDEBUG
#  ifdef _WIN32
#    define ASSERT_TICK_THREAD(c)                                   \
        do {                                                        \
            if (!(c)->owner_thread_set) {                           \
                (c)->owner_thread = GetCurrentThreadId();           \
                (c)->owner_thread_set = 1;                          \
            } else {                                                \
                assert((c)->owner_thread == GetCurrentThreadId() && \
                       "mqvpn_client: called from wrong thread");   \
            }                                                       \
        } while (0)
#  else
#    define ASSERT_TICK_THREAD(c)                                          \
        do {                                                               \
            if (!(c)->owner_thread_set) {                                  \
                (c)->owner_thread = pthread_self();                        \
                (c)->owner_thread_set = 1;                                 \
            } else {                                                       \
                assert(pthread_equal((c)->owner_thread, pthread_self()) && \
                       "mqvpn_client: called from wrong thread");          \
            }                                                              \
        } while (0)
#  endif
#else
#  define ASSERT_TICK_THREAD(c) ((void)0)
#endif

/* Find path by xquic path_id */
static path_entry_t *
find_path_by_xqc_id(mqvpn_client_t *c, uint64_t xqc_path_id)
{
    for (int i = 0; i < c->n_paths; i++) {
        if (c->paths[i].xquic_path_live && c->paths[i].xqc_path_id == xqc_path_id)
            return &c->paths[i];
    }
    return NULL;
}

/* Find path by handle */
static path_entry_t *
find_path_by_handle(mqvpn_client_t *c, mqvpn_path_handle_t h)
{
    for (int i = 0; i < c->n_paths; i++) {
        if (c->paths[i].handle == h) return &c->paths[i];
    }
    return NULL;
}

/* Returns the index of the first active path slot, or -1 if none. */
static int
first_active_idx(const mqvpn_client_t *c)
{
    if (!c) return -1;
    for (int i = 0; i < c->n_paths; i++)
        if (c->paths[i].platform_attached) return i;
    return -1;
}

/* Returns the fd of the first active path slot, or -1 if none.
 *
 * cb_write_socket() (no path_id) and get_fd_for_path()'s fallback both
 * use this when xquic asks for a write socket but the slot indexed by
 * path_id is not currently usable.  The naive `paths[0].fd` fallback
 * would otherwise hand back the fd of a path that was just dropped (see
 * ysurac/mqvpn 654f598).  We search instead so a still-active sibling
 * slot wins.
 *
 * Exported (non-static) so tests can verify the selection without
 * driving xquic.  Marked `hidden` so it does not show up in
 * libmqvpn.so's dynamic symbol table — not part of the public ABI,
 * and intentionally absent from libmqvpn.h. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
int
mqvpn_client_first_active_fd(const mqvpn_client_t *c)
{
    int idx = first_active_idx(c);
    return idx >= 0 ? c->paths[idx].fd : -1;
}

/* Get fd for xquic path_id, falling back to the (rotated) primary slot if
 * still active, else to the first active slot.
 *
 * Two requirements compose here:
 *   - The handshake fallback must use `primary_path_idx` (rotation owner)
 *     so a dead first-configured path doesn't trap reconnect (issue #46).
 *   - After multipath setup, if the primary was dropped mid-session we
 *     must NOT hand back its stale fd — fall through to any active sibling
 *     (post-OMR-backport semantics protecting against EBADF / sendto-on-
 *     dead-iface).
 */
static int
get_fd_for_path(mqvpn_client_t *c, uint64_t xqc_path_id)
{
    path_entry_t *p = find_path_by_xqc_id(c, xqc_path_id);
    if (p) return p->fd;
    int pidx = c->primary_path_idx;
    if (pidx < c->n_paths && c->paths[pidx].platform_attached) return c->paths[pidx].fd;
    return mqvpn_client_first_active_fd(c);
}

/* Pick the next active path index for the next handshake attempt.
 * Skips paths that the platform has marked inactive or the library has
 * already closed. Returns the input index if no other candidate exists. */
static int
client_next_primary_idx(const mqvpn_client_t *c, int from_idx)
{
    if (c->n_paths <= 0) return 0;
    int start = (from_idx + 1) % c->n_paths;
    int i = start;
    do {
        const path_entry_t *p = &c->paths[i];
        if (p->platform_attached && p->status != MQVPN_PATH_CLOSED) return i;
        i = (i + 1) % c->n_paths;
    } while (i != start);
    return from_idx;
}

/* Test-only wrappers: expose primary-rotation internals so test_api can
 * lock in the issue #46 + OMR-backport composite fallback semantics
 * without driving xquic.  Hidden from libmqvpn.so's dynamic export
 * table (not part of public ABI). */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
int
mqvpn_client_test_set_primary_path_idx(mqvpn_client_t *c, int idx)
{
    if (!c) return -1;
    c->primary_path_idx = idx;
    return 0;
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
int
mqvpn_client_test_get_fd_for_path(mqvpn_client_t *c, uint64_t xqc_path_id)
{
    if (!c) return -1;
    return get_fd_for_path(c, xqc_path_id);
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
int
mqvpn_client_test_next_primary_idx(const mqvpn_client_t *c, int from_idx)
{
    if (!c) return -1;
    return client_next_primary_idx(c, from_idx);
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
uint64_t
mqvpn_client_test_get_handshake_started_us(const mqvpn_client_t *c)
{
    if (!c) return 0;
    return c->handshake_started_us;
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
int
mqvpn_client_test_set_handshake_started_us(mqvpn_client_t *c, uint64_t us)
{
    if (!c) return -1;
    c->handshake_started_us = us;
    return 0;
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
int
mqvpn_client_test_handshake_stalled(const mqvpn_client_t *c, uint64_t now_us)
{
    if (!c) return -1;
    return client_handshake_stalled(c, now_us) ? 1 : 0;
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
int
mqvpn_client_test_force_state(mqvpn_client_t *c, mqvpn_client_state_t s)
{
    if (!c) return -1;
    client_set_state(c, s);
    return 0;
}

/* P1 test-only: force the client into the ESTABLISHED + multipath_ready
 * shape that gates the Recovery/Stability timer block in
 * mqvpn_client_get_interest, without driving a real handshake. Writes the
 * connection-level c->state / c->multipath_ready directly (bypassing the
 * transition table); these are NOT path_entry_t lifecycle fields, so no
 * LINT-ALLOW is required. Hidden from libmqvpn.so's dynamic export table
 * (not part of the public ABI). */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
int
mqvpn_client_test_force_established(mqvpn_client_t *c)
{
    if (!c) return -1;
    c->state = MQVPN_STATE_ESTABLISHED;
    c->multipath_ready = 1;
    return 0;
}

/* P1 test-only: seed c->next_wake_us — the xquic-requested wake that
 * mqvpn_client_get_interest starts `ms` from (normally set by
 * cb_set_event_timer). Lets a pure-function test observe whether the
 * Recovery timer block clamps or leaves the wake untouched. Hidden from
 * libmqvpn.so's dynamic export table (not part of the public ABI). */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
int
mqvpn_client_test_set_next_wake_us(mqvpn_client_t *c, uint64_t us)
{
    if (!c) return -1;
    c->next_wake_us = us;
    return 0;
}

/* ─── ICMP PTB rate limiter ─── */

static int
ptb_rate_allow(mqvpn_client_t *c)
{
    int64_t ms = now_ms_mono();
    if (ms - c->ptb_refill_ms >= 1000) {
        c->ptb_tokens = PTB_RATE_LIMIT;
        c->ptb_refill_ms = ms;
    }
    if (c->ptb_tokens > 0) {
        c->ptb_tokens--;
        return 1;
    }
    return 0;
}

static int
client_validate_new_args(const mqvpn_config_t *cfg, const mqvpn_client_callbacks_t *cbs)
{
    if (!cfg || !cbs) return 0;
    if (cbs->abi_version != MQVPN_CALLBACKS_ABI_VERSION) return 0;
    if (!cbs->tun_output || !cbs->tunnel_config_ready) return 0;
    return 1;
}

static void
client_init_handle(mqvpn_client_t *c, const mqvpn_config_t *cfg,
                   const mqvpn_client_callbacks_t *cbs, void *user_ctx)
{
    memcpy(&c->config, cfg, sizeof(*cfg));
    /* Clamp to the caller's struct_size: a platform built against an older
     * (shorter) callbacks struct must not be over-read — appended fields
     * stay NULL (c is calloc'd), which is the "callback unset" state. */
    size_t cbs_size = (cbs->struct_size && cbs->struct_size < sizeof(*cbs))
                          ? cbs->struct_size
                          : sizeof(*cbs);
    memcpy(&c->cbs, cbs, cbs_size);
    c->user_ctx = user_ctx; // lgtm[cpp/stack-address-escape]
    c->log_level = cfg->log_level;
    c->state = MQVPN_STATE_IDLE;
    c->next_path_handle = 1;
    c->ptb_tokens = PTB_RATE_LIMIT;
}

static void
client_destroy_engine(mqvpn_client_t *c)
{
    if (!c || !c->engine) return;
    xqc_engine_destroy(c->engine);
    c->engine = NULL;
}

static void
client_reset_path_runtime(mqvpn_client_t *c, path_entry_t *p)
{
    /* Pre-reconnect cleanup: a slot that was ACTIVE/STANDBY/DEGRADED before
     * reconnect must drop xquic-side state and fall back to PENDING so the
     * lifecycle invariant holds. Dispatched via PATH_EVENT_CONN_RESET which
     * centralises the field clearing + state transition in path_on_conn_reset. */

    /* Observability state (not §3.3 lifecycle field) — clear directly so the
     * next stuck-PENDING window can warn. */
    p->last_residence_warn_at_us = 0;

    path_event_ctx_t ctx = {.now_us = client_now_us(c)};
    path_on_event(c, p, PATH_EVENT_CONN_RESET, &ctx);
}

static void
client_reset_paths_for_reconnect(mqvpn_client_t *c)
{
    c->multipath_ready = 0;
    for (int i = 0; i < c->n_paths; i++) {
        client_reset_path_runtime(c, &c->paths[i]);
    }
    /* Try the next configured path next time so a dead first path
     * (e.g. interface up but no upstream connectivity) doesn't trap us. */
    c->primary_path_idx = client_next_primary_idx(c, c->primary_path_idx);
}

static int
client_reconnect_delay_sec(const mqvpn_client_t *c)
{
    int base = c->config.reconnect_interval_sec;
    if (base <= 0) base = 5;

    int delay = base;
    for (int i = 0; i < c->reconnect_attempts && delay < RECONNECT_BACKOFF_MAX_SEC; i++)
        delay *= 2;
    if (delay > RECONNECT_BACKOFF_MAX_SEC) delay = RECONNECT_BACKOFF_MAX_SEC;
    return delay;
}

static int
client_arm_reconnect_timer(mqvpn_client_t *c)
{
    int delay = client_reconnect_delay_sec(c);
    c->reconnect_attempts++;
    c->reconnect_scheduled_us = client_now_us(c) + (uint64_t)delay * 1000000;
    return delay;
}

/* ================================================================
 *  xquic engine callbacks
 * ================================================================ */

static void
cb_set_event_timer(xqc_usec_t wake_after, void *user_data)
{
    mqvpn_client_t *c = (mqvpn_client_t *)user_data;
    c->next_wake_us = wake_after;
}

static void
cb_xqc_log_write(xqc_log_level_t lvl, const void *buf, size_t size, void *user_data)
{
    mqvpn_client_t *c = (mqvpn_client_t *)user_data;
    if (!c->cbs.log) return;

    /* Reverse map: xquic→mqvpn for display severity. xquic enum is
     * REPORT=0, FATAL=1, ERROR=2, WARN=3, STATS=4, INFO=5, DEBUG=6.
     * This is intentionally NOT the inverse of map_log_level_to_xquic
     * below — the forward map shifts INFO→WARN to suppress xquic's
     * per-packet noise at the engine level; this reverse map keeps
     * incoming severity honest so a real xquic warning is shown as a
     * warning, not relabelled as INFO. Don't symmetrize the two. */
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

    /* Early filter: skip snprintf for messages below configured level */
    if (ml < c->log_level) return;

    char msg[512];
    snprintf(msg, sizeof(msg), "[xquic] %.*s", (int)size, (const char *)buf);
    c->cbs.log(ml, msg, c->user_ctx);
}

/* ─── UDP write callback (xquic → network) ─── */

/* Return code for a per-path send that failed on the transport socket.
 *
 * Per xquic's write_socket_ex contract (xquic.h xqc_socket_write_ex_pt),
 * XQC_SOCKET_ERROR triggers xqc_conn_should_close(), which tears down the
 * WHOLE connection once it is down to its last active path (active_path_count
 * < 2).
 *
 * Design: a send error is NEVER taken as proof of path death. Path life is
 * decided solely by the platform monitors (netlink_mon / route_mon), which
 * detach a dead path (platform_attached=0, fd closed). While any path is
 * still attached, a failed send is downgraded to EAGAIN (xquic keeps the
 * connection and retries); only when the monitors have detached every path
 * does the hard XQC_SOCKET_ERROR propagate and close/reconnect.
 *
 * Send errors are untrustworthy on macOS because IP_BOUND_IF does not
 * restrict the route lookup to the bound device up front the way Linux's
 * SO_BINDTODEVICE does — it validates interface consistency against a lookup
 * on the SHARED routing tree. A failover on a DIFFERENT interface invalidates
 * cached routes, forcing surviving sockets to re-run the lookup, and while
 * the table is being reconstructed there may transiently be no route
 * consistent with the bound scope: sendto() on a perfectly healthy path
 * fails. This applies even to a sole remaining path (e.g. during the scoped
 * server-pin re-install window), so the downgrade deliberately covers the
 * single-path case too — do NOT "tighten" this guard to exclude the failing
 * path itself; that reintroduces the ~5s full reconnect (new tunnel IP) on
 * transient flux. Other platforms' sockets do not fail this way, so this
 * branch rarely fires there. */
static ssize_t
path_send_dead_retcode(const mqvpn_client_t *c)
{
    return (mqvpn_client_first_active_fd(c) >= 0) ? XQC_SOCKET_EAGAIN : XQC_SOCKET_ERROR;
}

static ssize_t
cb_write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer,
                socklen_t peerlen, void *conn_user_data)
{
    cli_conn_t *conn = (cli_conn_t *)conn_user_data;
    mqvpn_client_t *c = conn->client;
    /* Prefer the rotated handshake primary (issue #46); fall back to any
     * still-active slot if the primary was dropped mid-session. Without
     * primary preference, handshake on a non-paths[0] primary would silently
     * sendto via paths[0].fd. Without first-active fallback, a dropped
     * primary mid-session would sendto via a dead fd / EBADF. */
    int active_idx = -1;
    int pidx = c->primary_path_idx;
    if (pidx < c->n_paths && c->paths[pidx].platform_attached)
        active_idx = pidx;
    else
        active_idx = first_active_idx(c);
    int fd = (active_idx >= 0) ? c->paths[active_idx].fd : -1;
    if (fd < 0) return XQC_SOCKET_ERROR;

    ssize_t res;
    do {
        /* Winsock sendto() len is int; cast silences C4267 under /WX (size<=MTU). */
        res = sendto(fd, buf, (int)size, MSG_DONTWAIT, peer, peerlen);
    } while (res < 0 && errno == EINTR);
    if (res < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return XQC_SOCKET_EAGAIN;
        return XQC_SOCKET_ERROR;
    }
    c->bytes_tx += (uint64_t)res;
    c->paths[active_idx].bytes_tx += (uint64_t)res;
    return res;
}

static ssize_t
cb_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
                   const struct sockaddr *peer, socklen_t peerlen, void *conn_user_data)
{
    cli_conn_t *conn = (cli_conn_t *)conn_user_data;
    mqvpn_client_t *c = conn->client;
    int fd = get_fd_for_path(c, path_id);
    if (fd < 0) return path_send_dead_retcode(c);

    ssize_t res;
    do {
        /* Winsock sendto() len is int; cast silences C4267 under /WX (size<=MTU). */
        res = sendto(fd, buf, (int)size, MSG_DONTWAIT, peer, peerlen);
    } while (res < 0 && errno == EINTR);
    if (res < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return XQC_SOCKET_EAGAIN;
        return path_send_dead_retcode(c);
    }
    c->bytes_tx += (uint64_t)res;
    {
        path_entry_t *p = find_path_by_xqc_id(c, path_id);
        if (p) p->bytes_tx += (uint64_t)res;
    }
    return res;
}

/* ─── TLS callbacks ─── */

static int
cb_cert_verify(const unsigned char *certs[], const size_t cert_len[], size_t certs_len,
               void *conn_user_data)
{
    (void)certs;
    (void)cert_len;
    (void)certs_len;
    cli_conn_t *conn = (cli_conn_t *)conn_user_data;
    if (conn && conn->client->config.insecure) return 0;
    LOG_E(conn->client, "TLS certificate verification failed");
    return -1;
}

static void
cb_save_token(const unsigned char *t, unsigned tl, void *u)
{
    (void)t;
    (void)tl;
    (void)u;
}
static void
cb_save_session(const char *d, size_t dl, void *u)
{
    (void)d;
    (void)dl;
    (void)u;
}
static void
cb_save_tp(const char *d, size_t dl, void *u)
{
    (void)d;
    (void)dl;
    (void)u;
}

/* ─── H3 connection callbacks ─── */

static int cli_masque_start_tunnel(cli_conn_t *conn);

static int
cb_h3_conn_create(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *user_data)
{
    (void)cid;
    cli_conn_t *conn = (cli_conn_t *)user_data;
    conn->h3_conn = h3_conn;
    conn->dgram_mss = xqc_h3_ext_datagram_get_mss(h3_conn);
    return 0;
}

static void
cb_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data)
{
    cli_conn_t *conn = (cli_conn_t *)user_data;
    conn->dgram_mss = xqc_h3_ext_datagram_get_mss(h3_conn);
    LOG_I(conn->client, "handshake finished (dgram_mss=%zu)", conn->dgram_mss);
    client_set_state(conn->client, MQVPN_STATE_AUTHENTICATING);
    cli_masque_start_tunnel(conn);
}

static int
cb_h3_conn_close(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *user_data)
{
    (void)h3_conn;
    (void)cid;
    cli_conn_t *conn = (cli_conn_t *)user_data;
    mqvpn_client_t *c = conn->client;

    int err = xqc_h3_conn_get_errno(h3_conn);
    LOG_I(c, "connection closed (errno=%d)", err);

    /* Notify platform */
    if (c->cbs.tunnel_closed) c->cbs.tunnel_closed(MQVPN_ERR_CLOSED, c->user_ctx);

    cli_conn_destroy(c);

    if (!c->shutting_down && c->config.reconnect_enable) {
        int delay = client_arm_reconnect_timer(c);
        LOG_I(c, "reconnecting in %d seconds (attempt %d)...", delay,
              c->reconnect_attempts);
        client_set_state(c, MQVPN_STATE_RECONNECTING);
        if (c->cbs.reconnect_scheduled) c->cbs.reconnect_scheduled(delay, c->user_ctx);
        return 0;
    }

    client_set_state(c, MQVPN_STATE_CLOSED);
    return 0;
}

/* ─── MASQUE tunnel start ─── */

/* Append `authorization: Bearer <auth_key>` when configured. auth_buf is
 * caller-owned and must stay live until xqc_h3_request_send_headers (the
 * header only holds an iovec into it). Returns the new header count. Shared
 * by cli_masque_start_tunnel and cli_tcp_lane_open_stream. */
static int
cli_append_auth_header(const mqvpn_client_t *c, xqc_http_header_t *hdrs, int hdr_count,
                       char *auth_buf, size_t auth_buf_len)
{
    if (c->config.auth_key[0] == '\0') return hdr_count;
    snprintf(auth_buf, auth_buf_len, "Bearer %s", c->config.auth_key);
    hdrs[hdr_count].name = (struct iovec){.iov_base = "authorization", .iov_len = 13};
    hdrs[hdr_count].value =
        (struct iovec){.iov_base = auth_buf, .iov_len = strlen(auth_buf)};
    hdrs[hdr_count].flags = 0;
    return hdr_count + 1;
}

static int
cli_masque_start_tunnel(cli_conn_t *conn)
{
    mqvpn_client_t *c = conn->client;
    cli_stream_t *stream = calloc(1, sizeof(*stream));
    if (!stream) return -1;
    stream->conn = conn;
    stream->role = CLI_STREAM_ROLE_CONNECT_IP;

    xqc_h3_request_t *req = xqc_h3_request_create(c->engine, &conn->cid, NULL, stream);
    if (!req) {
        LOG_E(c, "xqc_h3_request_create failed");
        free(stream);
        return -1;
    }
    stream->h3_request = req;
    conn->masque_request = req;

    char authority[280];
    snprintf(authority, sizeof(authority), "%s:%d", c->config.server_host,
             c->config.server_port);

    char auth_value[300];

    xqc_http_header_t hdrs[8] = {
        {.name = {.iov_base = ":method", .iov_len = 7},
         .value = {.iov_base = "CONNECT", .iov_len = 7},
         .flags = 0},
        {.name = {.iov_base = ":protocol", .iov_len = 9},
         .value = {.iov_base = "connect-ip", .iov_len = 10},
         .flags = 0},
        {.name = {.iov_base = ":scheme", .iov_len = 7},
         .value = {.iov_base = "https", .iov_len = 5},
         .flags = 0},
        {.name = {.iov_base = ":authority", .iov_len = 10},
         .value = {.iov_base = authority, .iov_len = strlen(authority)},
         .flags = 0},
        {.name = {.iov_base = ":path", .iov_len = 5},
         .value = {.iov_base = "/.well-known/masque/ip/*/*/", .iov_len = 27},
         .flags = 0},
        {.name = {.iov_base = "capsule-protocol", .iov_len = 16},
         .value = {.iov_base = "?1", .iov_len = 2},
         .flags = 0},
    };
    int hdr_count = 6;
    hdr_count =
        cli_append_auth_header(c, hdrs, hdr_count, auth_value, sizeof(auth_value));
    /* §19.2/§19.3: advertise the reorder capability only when locally enabled AND
     * the rx engine actually allocated — advertising with a NULL engine would make
     * the server stamp packets we then drop (one-way blackhole). */
    if (mqvpn_reorder_should_advertise(c->config.reorder.mode, conn->reorder_rx)) {
        hdrs[hdr_count].name =
            (struct iovec){.iov_base = MQVPN_REORDER_HDR_NAME,
                           .iov_len = sizeof(MQVPN_REORDER_HDR_NAME) - 1};
        hdrs[hdr_count].value =
            (struct iovec){.iov_base = MQVPN_REORDER_HDR_VALUE,
                           .iov_len = sizeof(MQVPN_REORDER_HDR_VALUE) - 1};
        hdrs[hdr_count].flags = 0;
        hdr_count++;
    }
    xqc_http_headers_t headers = {.headers = hdrs, .count = hdr_count, .capacity = 8};

    ssize_t ret = xqc_h3_request_send_headers(req, &headers, 0);
    if (ret < 0) {
        LOG_E(c, "send Extended CONNECT: %zd", ret);
        conn->masque_request = NULL;
        xqc_h3_request_close(req);
        return -1;
    }

    conn->masque_stream_id = xqc_h3_stream_id(req);
    LOG_I(c, "Extended CONNECT sent (stream_id=%" PRIu64 ")", conn->masque_stream_id);
    return 0;
}

#ifdef MQVPN_HYBRID_TCP_LANE_ENABLED
/* H2: open the per-flow CONNECT `:protocol=mqvpn-tcp` H3 request for a
 * freshly lwIP-accepted TCP-lane flow. NOT static — called cross-TU from
 * tcp_lane.c's accept callback (the one deliberate coupling point; prototype
 * lives in tcp_lane.h). Every failure path here is post-SYN-ACK, so it must
 * reject via mqvpn_tcp_lane_abort_pending — never fall the flow back to RAW.
 *
 * Returns 0 when the flow proceeds; nonzero (abort_pending's return,
 * propagated verbatim) when a failure path tore the flow down AND
 * tcp_abort()ed its pcb. This runs INSIDE lwIP's accept callback frame,
 * which must return ERR_ABRT in that case — lwIP's tcp_process would
 * otherwise keep using the freed pcb (see the contracts in tcp_lane.h). */
int
cli_tcp_lane_open_stream(void *client_ctx, void *flow_handle, const mqvpn_flow_key_t *key)
{
    mqvpn_client_t *c = (mqvpn_client_t *)client_ctx;
    cli_conn_t *conn = c->conn;
    if (!conn || !conn->h3_conn) {
        /* Accept fired without a live H3 connection (teardown race) — the
         * flow can never become real. */
        return mqvpn_tcp_lane_abort_pending(flow_handle);
    }

    cli_stream_t *stream = calloc(1, sizeof(*stream));
    if (!stream) {
        return mqvpn_tcp_lane_abort_pending(flow_handle);
    }
    stream->conn = conn;
    stream->role = CLI_STREAM_ROLE_CONNECT_TCP;

    xqc_h3_request_t *req = xqc_h3_request_create(c->engine, &conn->cid, NULL, stream);
    if (!req) {
        /* Known v1 simplification: NULL here is transient stream-credit
         * exhaustion, treated as a reject instead of queue-and-retry.
         * Practically unreachable — the default credit of 1024 auto-extends
         * and the flow cap is <= 256. */
        LOG_E(c, "connect-tcp: xqc_h3_request_create failed (stream credit?)");
        free(stream);
        return mqvpn_tcp_lane_abort_pending(flow_handle);
    }
    stream->h3_request = req;

    char authority[280];
    snprintf(authority, sizeof(authority), "%s:%d", c->config.server_host,
             c->config.server_port);

    /* Original inner destination — see mqvpn_tcp_lane_format_connect_path's
     * doc comment (tcp_lane.h) for the key-field byte-order contract and the
     * MQVPN_TCP_CONNECT_PATH_CAP worst-case sizing this relies on. A negative
     * return is inet_ntop failure (path left unwritten) — reject via the same
     * abort path the allocation failures above use, so the later strlen(path)
     * never reads an uninitialized buffer. Dead today (AF_INET6 hardcoded,
     * cap large enough) but guards a future refactor. */
    char path[MQVPN_TCP_CONNECT_PATH_CAP];
    if (mqvpn_tcp_lane_format_connect_path(path, sizeof(path), key) < 0) {
        LOG_E(c, "connect-tcp: could not format request path");
        xqc_h3_request_close(req); /* close notify frees stream */
        return mqvpn_tcp_lane_abort_pending(flow_handle);
    }

    char auth_value[300];

    /* 2026-07-03 wire decision: `:protocol` is "mqvpn-tcp" (NOT connect-tcp),
     * and deliberately NO capsule-protocol / mqvpn-reorder headers — the TCP
     * lane carries a raw byte relay, not capsules, and reorder is a
     * DATAGRAM-lane concern. */
    xqc_http_header_t hdrs[6] = {
        {.name = {.iov_base = ":method", .iov_len = 7},
         .value = {.iov_base = "CONNECT", .iov_len = 7},
         .flags = 0},
        {.name = {.iov_base = ":protocol", .iov_len = 9},
         .value = {.iov_base = "mqvpn-tcp", .iov_len = 9},
         .flags = 0},
        {.name = {.iov_base = ":scheme", .iov_len = 7},
         .value = {.iov_base = "https", .iov_len = 5},
         .flags = 0},
        {.name = {.iov_base = ":authority", .iov_len = 10},
         .value = {.iov_base = authority, .iov_len = strlen(authority)},
         .flags = 0},
        {.name = {.iov_base = ":path", .iov_len = 5},
         .value = {.iov_base = path, .iov_len = strlen(path)},
         .flags = 0},
    };
    int hdr_count = 5;
    hdr_count =
        cli_append_auth_header(c, hdrs, hdr_count, auth_value, sizeof(auth_value));
    xqc_http_headers_t headers = {.headers = hdrs, .count = hdr_count, .capacity = 6};

    mqvpn_tcp_lane_bind_h3_request(flow_handle, req, stream);

    ssize_t ret = xqc_h3_request_send_headers(req, &headers, 0);
    if (ret < 0 && ret != -XQC_EAGAIN) {
        LOG_E(c, "connect-tcp: send headers failed (%zd)", ret);
        xqc_h3_request_close(req); /* close notify frees stream */
        /* abort_pending clears f->h3_request/f->stream (they point at the
         * just-closed request) and never closes H3 itself — bind ran before
         * send per the plan order, and we already closed the request one
         * line up. */
        return mqvpn_tcp_lane_abort_pending(flow_handle);
    }

    LOG_D(c, "connect-tcp: stream %" PRIu64 " opened for %s", xqc_h3_stream_id(req),
          path);
    return 0;
}

/* H2/Task 10: uplink body send for the TCP lane. Cross-TU like
 * cli_tcp_lane_open_stream above (prototype in tcp_lane.h) — tcp_lane.c
 * never includes xquic headers, so xquic's return codes are normalized to
 * the MQVPN_TCP_LANE_H3_SEND_* contract at this boundary. len == 0 with
 * fin == 1 is the uplink half-close (xqc_h3_request_send_body documents the
 * fin-only shape; data may be NULL then). */
ssize_t
cli_tcp_lane_h3_send(void *h3_request, const uint8_t *buf, size_t len, int fin)
{
    /* xquic's send_body takes a non-const buffer but only reads from it. */
    ssize_t ret =
        xqc_h3_request_send_body((xqc_h3_request_t *)h3_request,
                                 (unsigned char *)(uintptr_t)buf, len, fin ? 1 : 0);
    if (ret == -XQC_EAGAIN) return MQVPN_TCP_LANE_H3_SEND_AGAIN;
    if (ret < 0) return MQVPN_TCP_LANE_H3_SEND_ERR;
    return ret;
}

/* H2/Task 11: downlink body recv for the TCP lane. Cross-TU like
 * cli_tcp_lane_h3_send above — same one-way boundary, same normalization
 * duty, opposite direction. xqc_h3_request_recv_body (third_party/xquic
 * src/http3/xqc_h3_request.c) writes *fin unconditionally on every call
 * (starts XQC_FALSE, may become true), including alongside n > 0: the final
 * DATA frame's bytes and its FIN can arrive in the SAME recv_body call, not
 * only as a separate zero-byte "fin-only" call — both shapes are real wire
 * behavior (confirmed by reading the vendored implementation), not a
 * simplification tcp_lane.c's caller may skip handling. */
ssize_t
cli_tcp_lane_h3_recv(void *h3_request, uint8_t *buf, size_t len, int *fin)
{
    unsigned char xfin = 0;
    ssize_t n = xqc_h3_request_recv_body((xqc_h3_request_t *)h3_request, buf, len, &xfin);
    if (n == -XQC_EAGAIN) return MQVPN_TCP_LANE_H3_RECV_AGAIN;
    if (n < 0) return MQVPN_TCP_LANE_H3_RECV_ERR;
    *fin = xfin ? 1 : 0;
    return n;
}

/* H2/Task 12: close-mapping RST direction for the TCP lane. Cross-TU like
 * cli_tcp_lane_h3_send/_recv above — wraps xqc_h3_request_close (sends
 * RESET_STREAM to the peer; h3_request_close_notify fires later when xquic
 * finally destroys the request struct, whatever the close reason). void:
 * every caller in tcp_lane.c has already unconditionally decided the flow
 * is dead, so there is no different action to take on success vs. failure
 * here (matches tcp_abort's void contract on the pcb side). */
void
cli_tcp_lane_h3_close(void *h3_request)
{
    xqc_h3_request_close((xqc_h3_request_t *)h3_request);
}
#endif /* MQVPN_HYBRID_TCP_LANE_ENABLED */

/* ─── Capsule parsing ─── */

static int
stream_append_capsules(cli_stream_t *s, const uint8_t *buf, size_t len)
{
    if (len == 0) return 0;
    size_t need = s->capsule_len + len;
    if (need > MAX_CAPSULE_BUF) return -1;
    if (need > s->capsule_cap) {
        size_t cap = s->capsule_cap ? s->capsule_cap * 2 : 4096;
        while (cap < need) {
            if (cap > SIZE_MAX / 2) {
                cap = need;
                break;
            }
            cap *= 2;
        }
        uint8_t *nb = realloc(s->capsule_buf, cap);
        if (!nb) return -1;
        s->capsule_buf = nb;
        s->capsule_cap = cap;
    }
    memcpy(s->capsule_buf + s->capsule_len, buf, len);
    s->capsule_len += len;
    return 0;
}

static void
process_capsules(cli_stream_t *stream)
{
    cli_conn_t *conn = stream->conn;
    mqvpn_client_t *c = conn->client;

    while (stream->capsule_len > 0) {
        uint64_t cap_type;
        const uint8_t *payload;
        size_t cap_len, consumed;

        xqc_int_t xret =
            xqc_h3_ext_capsule_decode(stream->capsule_buf, stream->capsule_len, &cap_type,
                                      &payload, &cap_len, &consumed);
        if (xret != XQC_OK) break;

        if (cap_type == XQC_H3_CAPSULE_ADDRESS_ASSIGN) {
            const uint8_t *ap = payload;
            size_t aremain = cap_len;
            while (aremain > 0) {
                uint64_t req_id;
                uint8_t ip_ver, ip_addr[16], prefix;
                size_t ip_len = 16, aa_consumed;
                xret = xqc_h3_ext_connectip_parse_address_assign(
                    ap, aremain, &req_id, &ip_ver, ip_addr, &ip_len, &prefix,
                    &aa_consumed);
                if (xret != XQC_OK) break;

                if (ip_ver == 4 && !conn->addr_assigned) {
                    memcpy(conn->assigned_ip, ip_addr, 4);
                    conn->assigned_prefix = prefix;
                    conn->addr_assigned = 1;
                    memcpy(c->assigned_ip, ip_addr, 4);
                    c->assigned_prefix = prefix;
                    LOG_I(c, "ADDRESS_ASSIGN: IPv4 %d.%d.%d.%d/%d", ip_addr[0],
                          ip_addr[1], ip_addr[2], ip_addr[3], prefix);
                } else if (ip_ver == 6 && !conn->addr6_assigned) {
                    memcpy(conn->assigned_ip6, ip_addr, 16);
                    conn->assigned_prefix6 = prefix;
                    conn->addr6_assigned = 1;
                    memcpy(c->assigned_ip6, ip_addr, 16);
                    c->assigned_prefix6 = prefix;
                    c->has_v6 = 1;
                    char v6s[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, ip_addr, v6s, sizeof(v6s));
                    LOG_I(c, "ADDRESS_ASSIGN: IPv6 %s/%d", v6s, prefix);
                }
                ap += aa_consumed;
                aremain -= aa_consumed;
            }
        } else if (cap_type == XQC_H3_CAPSULE_ROUTE_ADVERTISEMENT) {
            xret = xqc_h3_ext_connectip_validate_route_advertisement(payload, cap_len);
            if (xret != XQC_OK) {
                LOG_E(c, "ROUTE_ADVERTISEMENT validation failed");
                xqc_h3_request_close(stream->h3_request);
                return;
            }
            /* Log routes but no action needed */
        }

        if (consumed < stream->capsule_len)
            memmove(stream->capsule_buf, stream->capsule_buf + consumed,
                    stream->capsule_len - consumed);
        stream->capsule_len -= consumed;
    }
}

/* ─── H3 request callbacks ─── */

/* H2/Task 12: peer sent RESET_STREAM — xquic is already tearing this
 * request down (verified against the vendored source: this notify fires
 * ONLY on RESET_STREAM frame reception, never on a clean bidi-FIN
 * completion or on STOP_SENDING alone — see tcp_lane.h's
 * mqvpn_tcp_lane_on_h3_closing doc for the full citation trail). CONNECT-IP
 * ignores this: the tunnel stream has no separate per-flow teardown
 * concept, and its own close is handled via cb_request_close/
 * h3_conn_close_notify instead — routing it here too would be a no-op
 * anyway (mqvpn_tcp_lane_on_h3_closing only exists for the TCP lane), so
 * the CONNECT-IP case is simply not routed. (void)err: the flow is dead
 * either way, no err-code-specific handling needed (deliberate
 * simplification, matching cb_h3_conn_close's coarse-grained treatment
 * elsewhere in this file). */
static void
cb_request_closing_notify(xqc_h3_request_t *h3_request, xqc_int_t err, void *user_data)
{
    (void)h3_request;
    (void)err;
    cli_stream_t *stream = (cli_stream_t *)user_data;
    if (!stream) return;
#ifdef MQVPN_HYBRID_TCP_LANE_ENABLED
    if (stream->role == CLI_STREAM_ROLE_CONNECT_TCP && stream->conn) {
        mqvpn_tcp_lane_on_h3_closing(stream->conn->tcp_lane, stream);
    }
#endif
}

static int
cb_request_close(xqc_h3_request_t *h3_request, void *user_data)
{
    (void)h3_request;
    cli_stream_t *stream = (cli_stream_t *)user_data;
    if (stream) {
        /* Only the CONNECT-IP tunnel stream owns tunnel_ok — a closing
         * per-flow connect-tcp stream must not flip the tunnel dead. */
        if (stream->conn && stream->role == CLI_STREAM_ROLE_CONNECT_IP)
            stream->conn->tunnel_ok = 0;
#ifdef MQVPN_HYBRID_TCP_LANE_ENABLED
        /* Task 12 (reconciliation G): this is the FINAL close notify for
         * ANY reason (clean bidi-FIN, RST, or an explicit close call) —
         * xqc_h3_request_destroy calls it unconditionally right before
         * freeing the request struct (verified: exactly one call site,
         * third_party/xquic src/http3/xqc_h3_stream.c). Route to
         * on_h3_closing BEFORE freeing the stream below so no path can ever
         * leave a flow with a dangling h3_request/stream pointer: a flow
         * that already went through a different teardown (RST from us,
         * on_stream_rejected, on_relay_error, or the RESET_STREAM
         * closing-notify above) is already removed, so this is an
         * idempotent no-op lookup miss for it; a flow that reached this
         * point via a clean bidi-FIN completion has ALSO already cleared
         * its f->stream to NULL (tcp_lane_finish_clean_close runs
         * synchronously well before xquic gets around to destroying the
         * request, and transitions the flow to a CLOSING routing-residency
         * marker rather than removing it outright — C1 — but either way
         * f->stream == NULL never matches a real stream pointer, so the
         * lookup below still misses) — this call exists
         * for the one remaining shape: a request that closes for some
         * OTHER reason without either teardown path having run first. */
        if (stream->conn && stream->role == CLI_STREAM_ROLE_CONNECT_TCP) {
            mqvpn_tcp_lane_on_h3_closing(stream->conn->tcp_lane, stream);
        }
#endif
        free(stream->capsule_buf);
        free(stream);
    }
    return 0;
}

static int
apply_mtu_cap(int cfg_mtu, int negotiated, mqvpn_client_t *c)
{
    if (cfg_mtu > 0) {
        if (cfg_mtu < negotiated) {
            LOG_D(c, "capping MTU %d to config MTU %d", negotiated, cfg_mtu);
            return cfg_mtu;
        }
        if (cfg_mtu > negotiated) {
            LOG_W(c, "config MTU %d exceeds negotiated MTU %d, using %d", cfg_mtu,
                  negotiated, negotiated);
        }
    }
    return negotiated;
}

/* CONNECT-IP tunnel stream: response headers (:status 200 → tunnel_ok,
 * mqvpn-reorder echo → peer_reorder_supported). */
static void
cli_connect_ip_on_headers(cli_stream_t *stream, xqc_h3_request_t *h3_request)
{
    cli_conn_t *conn = stream->conn;
    mqvpn_client_t *c = conn->client;
    unsigned char fin = 0;

    xqc_http_headers_t *headers = xqc_h3_request_recv_headers(h3_request, &fin);
    if (headers) {
        for (int i = 0; i < (int)headers->count; i++) {
            xqc_http_header_t *h = &headers->headers[i];
            if (h->name.iov_len == 7 && memcmp(h->name.iov_base, ":status", 7) == 0 &&
                h->value.iov_len == 3 && memcmp(h->value.iov_base, "200", 3) == 0) {
                conn->tunnel_ok = 1;
                LOG_I(c, "tunnel 200 OK");
            }
            /* §19.3: server echoed mqvpn-reorder → it supports the shim, so
             * we may now stamp (gated below by cfg.reorder.mode != OFF). */
            if (mqvpn_reorder_header_match(h->name.iov_base, h->name.iov_len,
                                           h->value.iov_base, h->value.iov_len)) {
                conn->peer_reorder_supported = 1;
                LOG_I(c, "peer advertised mqvpn-reorder; TX stamping enabled");
            }
        }
    }
}

/* CONNECT-IP tunnel stream: capsule body + ADDRESS_ASSIGN → tunnel_config_ready.
 * Returns -1 on capsule buffer failure. */
static int
cli_connect_ip_on_body(cli_stream_t *stream, xqc_h3_request_t *h3_request)
{
    cli_conn_t *conn = stream->conn;
    mqvpn_client_t *c = conn->client;
    unsigned char fin = 0;

    unsigned char buf[4096];
    ssize_t n;
    do {
        n = xqc_h3_request_recv_body(h3_request, buf, sizeof(buf), &fin);
        if (n <= 0) break;
        if (stream_append_capsules(stream, buf, (size_t)n) < 0) return -1;
        process_capsules(stream);
    } while (!fin);

    /* Notify platform on ADDRESS_ASSIGN */
    if (conn->addr_assigned && c->state != MQVPN_STATE_ESTABLISHED &&
        c->state != MQVPN_STATE_TUNNEL_READY) {
        /* Compute MTU */
        int tun_mtu = IPV6_MIN_MTU;
        if (conn->dgram_mss > 0) {
            size_t udp_mss =
                xqc_h3_ext_masque_udp_mss(conn->dgram_mss, conn->masque_stream_id);
            if (udp_mss >= 68) tun_mtu = (int)udp_mss;
        }
        if (conn->addr6_assigned && tun_mtu < IPV6_MIN_MTU) tun_mtu = IPV6_MIN_MTU;
        tun_mtu = apply_mtu_cap(c->config.tun_mtu, tun_mtu, c);
        /* §9: when the reorder shim is locally enabled, each stamped inner
         * packet carries an 8-byte header, so the usable inner MTU shrinks
         * by 8. Apply ONCE to the resolved inner MTU (after auto-MSS / cap).
         * Floor at IPV6_MIN_MTU when v6 is in play. */
        if (c->config.reorder.mode != MQVPN_REORDER_OFF) {
            tun_mtu -= MQVPN_REORDER_HDR_LEN;
            if (conn->addr6_assigned && tun_mtu < IPV6_MIN_MTU) tun_mtu = IPV6_MIN_MTU;
        }
        c->mtu = tun_mtu;

        /* Hybrid: learn the tunnel subnet for the classifier's TCP-lane
         * exclusion. The full rationale (server ACL denies the tunnel
         * subnet unconditionally → lane could only RST; RAW keeps intra-VPN
         * TCP working) and the /24 widening rule (with its wider-pool
         * limitation) live on mqvpn_tunnel_subnet_learn and
         * client_tunnel_subnet in classifier.h. Deliberately OUTSIDE the
         * MQVPN_HYBRID_TCP_LANE_ENABLED block: lane-less builds still
         * classify for counters and must report the same verdicts.
         * client_tunnel_subnet[0] is v4 (always learned here); [1] is v6,
         * learned only once an IPv6 address has actually been assigned —
         * classify() doesn't consult it yet (v1: IPv6 TCP is always RAW),
         * but learning it now means Chunk 6's classifier gate needs no
         * further mqvpn_client.c wiring. */
        mqvpn_tunnel_subnet_learn(conn->assigned_ip, (int)conn->assigned_prefix,
                                  &c->config.hybrid.client_tunnel_subnet[0]);
        if (conn->addr6_assigned) {
            mqvpn_tunnel_subnet_learn_v6(conn->assigned_ip6, (int)conn->assigned_prefix6,
                                         &c->config.hybrid.client_tunnel_subnet[1]);
        }

#ifdef MQVPN_HYBRID_TCP_LANE_ENABLED
        /* Sanitize the [Hybrid] block at its consumer, BEFORE the enabled
         * gate below (validate-at-consumer pattern — mirrors
         * mqvpn_reorder_config_validate at mqvpn_reorder_rx_new and the
         * server-side check in mqvpn_server_new): the INI/JSON loaders store
         * raw scalars, so an invalid block (e.g. TcpMaxFlows = 0) reaches
         * here unchecked and would size the lane's flow table from garbage.
         * PER-FIELD reset (mqvpn_hybrid_config_sanitize), never a
         * whole-block default reset: enabled and every valid field stay as
         * configured — an unrelated scalar typo must not silently disable
         * the whole TCP lane (nor, on the server side, drop ACL policy).
         * Warned per field; never a hard failure. Idempotent across
         * reconnects: the reset makes the config valid, so the warns fire
         * at most once per client. */
        {
            const char *bad_fields[8];
            int n_bad = mqvpn_hybrid_config_sanitize(&c->config.hybrid, bad_fields, 8);
            for (int i = 0; i < n_bad && i < 8; i++)
                LOG_W(c, "invalid [Hybrid] %s; using default", bad_fields[i]);
        }
        /* H2: bring up the lwIP TCP-lane stack now that the inner MTU is
         * resolved (lwIP derives each pcb's MSS from netif->mtu at accept
         * time). Gate mirrors the classifier's TCP-lane rule: enabled &&
         * tcp mode != raw. Alloc failure degrades to RAW (lwip_ctx stays
         * NULL), same policy as the reorder engines above. The !lwip_ctx
         * guard's stale-MTU case is unreachable today: this block only
         * re-fires for a NEW conn (reconnect destroys the old conn — and
         * its lwip_ctx — first), never twice on the same conn. */
        if (!conn->lwip_ctx && c->config.hybrid.enabled &&
            c->config.hybrid.tcp_mode != MQVPN_HYBRID_TCP_RAW) {
            conn->lwip_ctx = mqvpn_lwip_ctx_new(cli_lwip_clock_wrapper, c,
                                                cli_lwip_output_wrapper, c, tun_mtu);
            if (!conn->lwip_ctx)
                LOG_W(c, "lwIP ctx create failed; TCP lane disabled (RAW fallback)");
        }
        /* Flow table rides the same lifecycle. Coherence rule: tcp_lane is
         * created only when lwip_ctx exists, and a tcp_lane alloc failure
         * tears lwip_ctx back down — the ingress path guards on tcp_lane
         * alone and dereferences lwip_ctx. Hash seed mirrors the reorder
         * engines' per-conn derivation (wall clock ^ conn_id; §6.2 needs no
         * peer agreement). */
        if (conn->lwip_ctx && !conn->tcp_lane) {
            uint64_t lane_seed = client_now_us(c) ^ ((uint64_t)c->conn_id << 32);
            conn->tcp_lane = mqvpn_tcp_lane_new(&c->config.hybrid, lane_seed, c,
                                                cli_lwip_clock_wrapper, c);
            if (!conn->tcp_lane) {
                LOG_W(c, "tcp_lane alloc failed; TCP lane disabled (RAW fallback)");
                mqvpn_lwip_ctx_free(conn->lwip_ctx);
                conn->lwip_ctx = NULL;
            } else {
                /* Task 8: accepted flows land in the lane's accept callback,
                 * which opens the per-flow H3 stream back through
                 * cli_tcp_lane_open_stream above. */
                mqvpn_lwip_ctx_set_accept_cb(conn->lwip_ctx, mqvpn_tcp_lane_lwip_accept,
                                             conn->tcp_lane);
            }
        }
#endif

        /* Build tunnel info for callback */
        mqvpn_tunnel_info_t info = {0};
        info.struct_size = sizeof(info);
        memcpy(info.assigned_ip, conn->assigned_ip, 4);
        info.assigned_prefix = conn->assigned_prefix;
        /* Server IP is .1 in same subnet */
        memcpy(info.server_ip, conn->assigned_ip, 3);
        info.server_ip[3] = 1;
        info.server_prefix = conn->assigned_prefix;
        info.mtu = tun_mtu;
        if (conn->addr6_assigned) {
            memcpy(info.assigned_ip6, conn->assigned_ip6, 16);
            info.assigned_prefix6 = conn->assigned_prefix6;
            info.has_v6 = 1;
        }

        /* Primary path is now validated by handshake — drive
         * VALIDATING -> ACTIVE via the standard event. tick_check_all_validations
         * may also fire VALIDATION_OK if it polls between now and the next
         * tick boundary; path_on_validation_ok's `if (state != VALIDATING)`
         * guard makes the second dispatch a LOG_D no-op. */
        int pidx = c->primary_path_idx;
        if (c->n_paths > 0 && pidx < c->n_paths && c->paths[pidx].platform_attached &&
            c->paths[pidx].state == PATH_LC_VALIDATING) {
            path_entry_t *pp = &c->paths[pidx];
            path_event_ctx_t v_ctx = {
                .validated_target = PATH_LC_ACTIVE,
                .now_us = client_now_us(c),
            };
            path_on_event(c, pp, PATH_EVENT_VALIDATION_OK, &v_ctx);
        }

        client_set_state(c, MQVPN_STATE_TUNNEL_READY);
        LOG_D(c, "firing tunnel_config_ready callback");
        c->cbs.tunnel_config_ready(&info, c->user_ctx);
        c->reconnect_attempts = 0;
    }
    return 0;
}

#ifdef MQVPN_HYBRID_TCP_LANE_ENABLED
/* Parse the numeric ":status" pseudo-header out of a response header block.
 * Returns the parsed status code, or -1 if absent/malformed. Kept local
 * (not shared with cli_connect_ip_on_headers above): that function only
 * ever matches the exact literal "200", never needs a general numeric
 * range, and factoring a shared helper would mean touching the already-
 * shipped CONNECT-IP tunnel path for no behavioral gain here. */
static int
cli_connect_tcp_parse_status(xqc_http_headers_t *hdrs)
{
    for (int i = 0; i < (int)hdrs->count; i++) {
        xqc_http_header_t *h = &hdrs->headers[i];
        if (h->name.iov_len == 7 && memcmp(h->name.iov_base, ":status", 7) == 0) {
            size_t n = h->value.iov_len;
            char buf[8];
            if (n == 0 || n >= sizeof(buf)) return -1;
            memcpy(buf, h->value.iov_base, n);
            buf[n] = '\0';
            /* Reject strtol's leading-whitespace/sign lenience (" 200",
             * "+200") — a :status value must start with a digit. */
            if (buf[0] < '0' || buf[0] > '9') return -1;
            char *end = NULL;
            long v = strtol(buf, &end, 10);
            if (end == buf || *end != '\0' || v < 100 || v > 599) return -1;
            return (int)v;
        }
    }
    return -1;
}

/* mqvpn-tcp CONNECT stream: response headers gate the flow. A 2xx moves the
 * flow PENDING_STREAM -> ACTIVE (uplink may now flow); anything else is a
 * rejection routed to the lane (Task 12 does the real tcp_abort + removal;
 * this only signals it). */
static void
cli_connect_tcp_on_headers(cli_stream_t *stream, xqc_h3_request_t *h3_request)
{
    uint8_t fin = 0;
    xqc_http_headers_t *hdrs = xqc_h3_request_recv_headers(h3_request, &fin);
    if (!hdrs) return;

    int status = cli_connect_tcp_parse_status(hdrs);
    if (status >= 200 && status < 300) {
        mqvpn_tcp_lane_on_stream_established(stream->conn->tcp_lane, stream);
    } else {
        mqvpn_tcp_lane_on_stream_rejected(stream->conn->tcp_lane, stream);
    }
}

/* mqvpn-tcp CONNECT stream: response body. Routes to the per-flow downlink
 * pump (tcp_lane.c), which locates the flow by this stream's back-pointer
 * and drains xqc_h3_request_recv_body into lwIP via tcp_write.
 *
 * Return value contract — deliberately ALWAYS 0, never the pump's result:
 * verified against xquic (third_party/xquic src/http3/xqc_h3_stream.c)
 * that a negative return from h3_request_read_notify propagates up through
 * xqc_h3_stream_process_bidi -> xqc_h3_stream_process_in ->
 * XQC_H3_CONN_ERR, which closes the WHOLE H3/QUIC connection. That is the
 * correct behavior for cli_connect_ip_on_body's -1 (the CONNECT-IP request
 * IS the tunnel — if it's broken, the connection is dead anyway), but it
 * would be catastrophic here: one flow's relay error killing every other
 * TCP-lane flow AND the CONNECT-IP tunnel on the same connection. Fatal
 * downlink errors are instead handled entirely inside
 * mqvpn_tcp_lane_downlink_pump via mqvpn_tcp_lane_on_relay_error (routes
 * just this flow to CLOSING); Task 12 tears down only that flow's pcb/H3
 * request. */
static int
cli_connect_tcp_on_body(cli_stream_t *stream, xqc_h3_request_t *h3_request)
{
    (void)h3_request; /* the pump re-derives it from the flow via `stream` */
    mqvpn_tcp_lane_downlink_pump(stream->conn->tcp_lane, stream);
    return 0;
}
#endif /* MQVPN_HYBRID_TCP_LANE_ENABLED */

static int
cb_request_read(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag,
                void *user_data)
{
    cli_stream_t *stream = (cli_stream_t *)user_data;

    switch (stream->role) {
    case CLI_STREAM_ROLE_CONNECT_IP:
        if (flag & XQC_REQ_NOTIFY_READ_HEADER)
            cli_connect_ip_on_headers(stream, h3_request);
        if (flag & XQC_REQ_NOTIFY_READ_BODY)
            return cli_connect_ip_on_body(stream, h3_request);
        return 0;
#ifdef MQVPN_HYBRID_TCP_LANE_ENABLED
    case CLI_STREAM_ROLE_CONNECT_TCP:
        if (flag & XQC_REQ_NOTIFY_READ_HEADER)
            cli_connect_tcp_on_headers(stream, h3_request);
        /* READ_BODY is the common case; READ_EMPTY_FIN is the OTHER real
         * wire shape for a downlink close (third_party/xquic
         * src/http3/xqc_h3_request.c xqc_h3_request_on_recv_empty_fin):
         * fired standalone, WITHOUT READ_BODY, when a bodiless FIN STREAM
         * frame arrives after every previously-buffered body byte has
         * already been drained (read_flag == NULL at that point). Missing
         * this notify would mean a peer that FINs on an idle/fully-drained
         * stream never gets its downlink half-close observed — the flow
         * would hang forever waiting for a body notify that never comes.
         * cli_connect_tcp_on_body's recv_body call correctly reports this
         * as n==0 && *fin==1 either way (verified in the vendored source),
         * so one handler covers both notify shapes. */
        if (flag & (XQC_REQ_NOTIFY_READ_BODY | XQC_REQ_NOTIFY_READ_EMPTY_FIN))
            return cli_connect_tcp_on_body(stream, h3_request);
        return 0;
#endif
    }
    /* No default: -Wswitch-ready shape; unknown roles intentionally no-op. */
    return 0;
}

static int
cb_request_write(xqc_h3_request_t *h3_request, void *user_data)
{
    (void)h3_request;
    cli_stream_t *stream = (cli_stream_t *)user_data;
    switch (stream->role) {
    case CLI_STREAM_ROLE_CONNECT_IP:
        /* No consumer today — deliberately no plumbing (nothing withholds
         * uplink writes on the CONNECT-IP tunnel stream). */
        return 0;
#ifdef MQVPN_HYBRID_TCP_LANE_ENABLED
    case CLI_STREAM_ROLE_CONNECT_TCP:
        /* Uplink re-arm: flush the flow's H3 retry queue and resume the
         * withheld lwIP receive window (Task 10). */
        return mqvpn_tcp_lane_on_h3_writable(stream->conn->tcp_lane, stream);
#endif
    }
    return 0;
}

/* ─── Datagram callbacks ─── */

/*
 * forward_inner_ip — post-process one de-stamped inner IP packet and hand it to
 * TUN. Shared by the RAW dispatch in cb_dgram_read AND the reorder RX deliver()
 * callback, so reordered packets get identical TTL/hop-limit + ICMP handling
 * (§5: both paths MUST be semantically identical). `pkt[0..len)` is the bare
 * inner IP packet (no reorder header).
 */
static void
forward_inner_ip(cli_conn_t *conn, const uint8_t *pkt, size_t len)
{
    mqvpn_client_t *c = conn->client;
    if (len < 1) return;

    uint8_t ip_ver = pkt[0] >> 4;
    uint8_t fwd_pkt[PACKET_BUF_SIZE];
    if (len > sizeof(fwd_pkt)) return;

    if (ip_ver == 4) {
        if (len < IPV4_MIN_HDR) {
            LOG_D(c, "dgram: IPv4 too short (%zu bytes)", len);
            return;
        }
        memcpy(fwd_pkt, pkt, len);
        if (fwd_pkt[8] <= 1) {
            if (c->conn && c->conn->addr_assigned)
                mqvpn_icmp_send_v4(c->cbs.tun_output, c->user_ctx, c->conn->assigned_ip,
                                   11, 0, 0, pkt, len);
            return;
        }
        fwd_pkt[8]--;
        uint32_t sum = ((uint32_t)fwd_pkt[10] << 8 | fwd_pkt[11]) + 0x0100;
        sum = (sum & 0xFFFF) + (sum >> 16);
        fwd_pkt[10] = (sum >> 8) & 0xFF;
        fwd_pkt[11] = sum & 0xFF;
    } else if (ip_ver == 6) {
        if (len < IPV6_MIN_HDR || !conn->addr6_assigned) {
            LOG_D(c, "dgram: IPv6 too short or no addr6 (%zu bytes)", len);
            return;
        }
        memcpy(fwd_pkt, pkt, len);
        if (fwd_pkt[7] <= 1) {
            if (c->conn && c->conn->addr6_assigned)
                mqvpn_icmp_send_v6(c->cbs.tun_output, c->user_ctx, c->conn->assigned_ip6,
                                   3, 0, 0, pkt, len);
            return;
        }
        fwd_pkt[7]--;
    } else {
        LOG_D(c, "dgram: unknown IP version %d", ip_ver);
        return;
    }

    c->dgram_recv++;
    c->bytes_rx += len;
    c->cbs.tun_output(fwd_pkt, len, c->user_ctx);
}

/* Reorder RX deliver() trampoline: routes in-order packets from the reorder
 * engine through the same forward_inner_ip post-processing. */
static void
cli_reorder_deliver(const uint8_t *pkt, size_t len, void *ctx)
{
    forward_inner_ip((cli_conn_t *)ctx, pkt, len);
}

static void
cb_dgram_read(xqc_h3_conn_t *h3_conn, const void *data, size_t data_len, void *user_data,
              uint64_t ts)
{
    (void)h3_conn;
    (void)ts;
    cli_conn_t *conn = (cli_conn_t *)user_data;
    if (!conn) return;
    mqvpn_client_t *c = conn->client;
    if (!c->tun_active) return;

    uint64_t qsid = 0, ctx_id = 0;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;

    xqc_int_t xret = xqc_h3_ext_masque_unframe_udp((const uint8_t *)data, data_len, &qsid,
                                                   &ctx_id, &payload, &payload_len);
    if (xret != XQC_OK) {
        LOG_D(c, "dgram: unframe failed (xret=%d, data_len=%zu)", xret, data_len);
        return;
    }
    if (payload_len < 1) {
        LOG_D(c, "dgram: empty payload");
        return;
    }

    /* §5/§8.1 self-describing dispatch on payload[0]. */
    switch (mqvpn_reorder_classify_byte(payload[0])) {
    case MQVPN_REORDER_KIND_RAW: forward_inner_ip(conn, payload, payload_len); return;
    case MQVPN_REORDER_KIND_REORDER_V1:
        if (conn->reorder_rx) {
            mqvpn_reorder_rx_on_packet(conn->reorder_rx, payload, payload_len,
                                       client_now_us(c));
        } else {
            LOG_D(c, "dgram: reorder packet but rx engine off; dropping");
        }
        return;
    default: LOG_D(c, "dgram: unknown reorder type 0x%02x; dropping", payload[0]); return;
    }
}

static void
cb_dgram_write(xqc_h3_conn_t *h3_conn, void *user_data)
{
    (void)h3_conn;
    cli_conn_t *conn = (cli_conn_t *)user_data;
    if (!conn) return;
    mqvpn_client_t *c = conn->client;

    if (c->backpressure) {
        c->backpressure = 0;
        if (c->cbs.ready_for_tun) c->cbs.ready_for_tun(c->user_ctx);
    }
}

static void
cb_dgram_acked(xqc_h3_conn_t *h, uint64_t id, void *ud)
{
    (void)h;
    (void)id;
    cli_conn_t *conn = (cli_conn_t *)ud;
    if (conn) {
        conn->dgram_acked_cnt++;
        conn->client->dgram_acked++;
    }
}

static int
cb_dgram_lost(xqc_h3_conn_t *h, uint64_t id, void *ud)
{
    (void)h;
    (void)id;
    cli_conn_t *conn = (cli_conn_t *)ud;
    if (conn) {
        conn->dgram_lost_cnt++;
        conn->client->dgram_lost++;
    }
    return 0;
}

static void
cb_dgram_mss_updated(xqc_h3_conn_t *h, size_t mss, void *ud)
{
    (void)h;
    cli_conn_t *conn = (cli_conn_t *)ud;
    if (conn) conn->dgram_mss = mss;
    mqvpn_client_t *c = conn->client;
    LOG_I(c, "datagram MSS updated: %zu", mss);

    if (conn && c->tun_active) {
        size_t udp_mss = xqc_h3_ext_masque_udp_mss(mss, conn->masque_stream_id);
        if (udp_mss >= 68) {
            int new_mtu = (int)udp_mss;
            if (conn->addr6_assigned && new_mtu < IPV6_MIN_MTU) new_mtu = IPV6_MIN_MTU;
            new_mtu = apply_mtu_cap(c->config.tun_mtu, new_mtu, c);
            if (new_mtu != c->last_notified_mtu) {
                c->mtu = new_mtu;
                c->last_notified_mtu = new_mtu;
                if (c->cbs.mtu_updated) c->cbs.mtu_updated(new_mtu, c->user_ctx);
            }
        }
    }
}

/* ─── Multipath helpers ─── */

/* PR4 — Call xqc_conn_create_path() and classify per spec §6.6.
 * On OK, *out_path_id receives the new xqc-side path_id; on fail it is 0.
 * The caller passes the classification + path_id into path_on_event()'s
 * ctx (ACTIVATE_REQUESTED / RETRY_TIMER / MANUAL_REACTIVATE). */
static activate_result_t
activate_via_xquic_classify(mqvpn_client_t *c, uint64_t *out_path_id)
{
    int path_status = (c->config.scheduler == MQVPN_SCHED_BACKUP_FEC) ? 1 : 0;
    *out_path_id = 0;
    xqc_int_t ret =
        xqc_conn_create_path(c->engine, &c->conn->cid, out_path_id, path_status);
    if (ret == 0) return ACTIVATE_OK;
    if (ret == -XQC_EMP_CREATE_PATH) return ACTIVATE_PERMANENT_FAIL;
    return ACTIVATE_TRANSIENT_FAIL;
}

/* Create an xquic path for a secondary path entry. Thin caller — all state
 * mutation happens inside path_on_event(ACTIVATE_REQUESTED) per spec §6.6.
 *
 * For MQVPN_SCHED_BACKUP_FEC the secondary path is created in STANDBY
 * (path_status=1) so that xquic's backup_fec scheduler routes only FEC repair
 * symbols to it, while the primary path stays AVAILABLE. Per xquic's public
 * API: 1 = STANDBY, anything else = AVAILABLE (xquic.h L2210). */
static void
client_activate_path(mqvpn_client_t *c, path_entry_t *p, int idx)
{
    if (p->xquic_path_live) return;

    uint64_t new_id = 0;
    activate_result_t r = activate_via_xquic_classify(c, &new_id);
    LOG_I(c, "path[%d] activate: result=%s id=%llu", idx,
          r == ACTIVATE_OK               ? "OK"
          : r == ACTIVATE_PERMANENT_FAIL ? "PERMANENT"
                                         : "TRANSIENT",
          (unsigned long long)new_id);

    path_event_ctx_t ctx = {
        .result = r,
        .new_xqc_path_id = new_id,
        .now_us = client_now_us(c),
    };
    path_on_event(c, p, PATH_EVENT_ACTIVATE_REQUESTED, &ctx);
}

/* Activate every path currently in PATH_LC_PENDING.
 *
 * PR3 translator: the legacy predicate (xquic_path_live=0 && platform_attached=1)
 * is now expressed by the PENDING lifecycle state. CREATE_WAIT slots (also
 * have xquic_path_live=0) are correctly skipped — they wait for their retry
 * timer in tick(), not for re-activation here. */
static void
activate_pending_paths(mqvpn_client_t *c)
{
    for (int i = 0; i < c->n_paths; i++) {
        path_entry_t *p = &c->paths[i];
        if (p->state != PATH_LC_PENDING) continue;
        client_activate_path(c, p, i);
    }
}

/* ─── Multipath callbacks ─── */

static void
cb_ready_to_create_path(const xqc_cid_t *cid, void *conn_user_data)
{
    (void)cid;
    cli_conn_t *conn = (cli_conn_t *)conn_user_data;
    mqvpn_client_t *c = conn->client;

    c->multipath_ready = 1;
    if (!c->config.multipath) return;

    activate_pending_paths(c);
}

/* PR4 — path_recreate_backoff relocated to path_state_machine.c
 * (declaration in path_state_machine.h). */

/* Test-only wrapper: drives the synchronous activation failure path via
 * path_on_event(). Hidden from libmqvpn.so's dynamic export table (not
 * part of public ABI). The event chosen depends on current state — fresh
 * PENDING slots take ACTIVATE_REQUESTED, retry-armed slots (CREATE_WAIT /
 * DEGRADED) take RETRY_TIMER. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
int
mqvpn_client_apply_path_activation_failure(mqvpn_client_t *c, mqvpn_path_handle_t handle,
                                           uint64_t now_us)
{
    if (!c) return -1;
    path_entry_t *p = find_path_by_handle(c, handle);
    if (!p) return -1;
    path_event_ctx_t ctx = {.result = ACTIVATE_TRANSIENT_FAIL, .now_us = now_us};
    path_event_t ev = (p->state == PATH_LC_PENDING) ? PATH_EVENT_ACTIVATE_REQUESTED
                                                    : PATH_EVENT_RETRY_TIMER;
    path_on_event(c, p, ev, &ctx);
    return 0;
}

/* Test-only wrapper: drives the permanent path-create failure path via
 * path_on_event(). Hidden from libmqvpn.so's dynamic export table. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
int
mqvpn_client_test_apply_path_create_permanent_failure(mqvpn_client_t *c,
                                                      mqvpn_path_handle_t handle)
{
    if (!c) return -1;
    path_entry_t *p = find_path_by_handle(c, handle);
    if (!p) return -1;
    path_event_ctx_t ctx = {.result = ACTIVATE_PERMANENT_FAIL,
                            .now_us = client_now_us(c)};
    path_event_t ev = (p->state == PATH_LC_PENDING) ? PATH_EVENT_ACTIVATE_REQUESTED
                                                    : PATH_EVENT_RETRY_TIMER;
    path_on_event(c, p, ev, &ctx);
    return 0;
}

/* PR3 test-only wrapper: forces a slot into VALIDATING with the given
 * xqc_path_id (so find_path_by_xqc_id can resolve later). Hidden from
 * libmqvpn.so's dynamic export table.
 *
 * §7.1 visibility=hidden test wrapper: seed VALIDATING-shape invariants
 * directly so tests can pin transitions without spinning up xquic. Each
 * direct write carries a LINT-ALLOW trailer for check_lifecycle_field_writes.sh. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
int
mqvpn_client_test_force_validating(mqvpn_client_t *c, mqvpn_path_handle_t handle,
                                   uint64_t xqc_path_id)
{
    if (!c) return -1;
    path_entry_t *p = find_path_by_handle(c, handle);
    if (!p) return -1;
    /* Force the slot into VALIDATING — the invariants for VALIDATING
     * require platform_attached=1, xquic_path_live=1, fd>=0,
     * recreate_after_us=0 (see path_invariant_check in path_state_machine.c). */
    p->platform_attached = 1;     /* LINT-ALLOW: test wrapper seed */
    p->xquic_path_live = 1;       /* LINT-ALLOW: test wrapper seed */
    p->xqc_path_id = xqc_path_id; /* LINT-ALLOW: test wrapper seed */
    p->recreate_after_us = 0;     /* LINT-ALLOW: test wrapper seed */
    p->path_stable_since_us = 0;  /* LINT-ALLOW: test wrapper seed */
    p->recreate_retries = 0;      /* LINT-ALLOW: test wrapper seed */
    set_path_state_with_log(c, p, PATH_LC_VALIDATING, PATH_REASON_ACTIVATE_OK);
    path_invariant_check(p);
    return 0;
}

/* PR3 test-only: seed a path slot's Stability-timer inputs
 * (path_stable_since_us + xquic_path_live) so the Stability-timer block in
 * mqvpn_client_get_interest can be exercised without a live xquic engine
 * driving the VALIDATING -> ACTIVE transition that normally sets them. This
 * is the parallel of the Recovery-timer seed used by the recovery tests
 * (recreate_after_us via apply_path_activation_failure). Pass xquic_live=0 to
 * model a stability anchor left on a path xquic no longer considers live — the
 * block must stay inert in that case (guard: path_stable_since_us > 0 &&
 * xquic_path_live). Does NOT run path_invariant_check: it deliberately writes
 * a non-lifecycle-consistent shape to isolate the get_interest read path.
 * Hidden from libmqvpn.so's dynamic export table (not part of the public ABI). */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
int
mqvpn_client_test_set_path_stable_us(mqvpn_client_t *c, mqvpn_path_handle_t handle,
                                     uint64_t stable_since_us, int xquic_live)
{
    if (!c) return -1;
    path_entry_t *p = find_path_by_handle(c, handle);
    if (!p) return -1;
    p->path_stable_since_us = stable_since_us; /* LINT-ALLOW: test wrapper seed */
    p->xquic_path_live = xquic_live ? 1 : 0;   /* LINT-ALLOW: test wrapper seed */
    return 0;
}

/* PR3 test-only wrapper: forces a slot into VALIDATING then dispatches
 * path_on_event(XQUIC_REMOVED). Used by test_api to pin the
 * VALIDATING -> CREATE_WAIT dispatch without spinning up a live xquic
 * engine. Hidden from libmqvpn.so's dynamic export table. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
int
mqvpn_client_test_force_validating_then_remove(mqvpn_client_t *c,
                                               mqvpn_path_handle_t handle,
                                               uint64_t xqc_path_id)
{
    if (mqvpn_client_test_force_validating(c, handle, xqc_path_id) < 0) return -1;
    path_entry_t *p = find_path_by_handle(c, handle);
    if (!p) return -1;
    path_event_ctx_t ctx = {.now_us = client_now_us(c)};
    path_on_event(c, p, PATH_EVENT_XQUIC_REMOVED, &ctx);
    return 0;
}

/* PR3 test-only getter: expose internal lifecycle state name + recreate_retries
 * by handle so tests can pin transitions that don't change the public
 * 5-state projection (e.g. CREATE_WAIT and PENDING both map to PENDING).
 * Returns the lifecycle name (static string, never NULL on success), writes
 * recreate_retries to *out_retries. Returns NULL on bad input. Hidden from
 * libmqvpn.so's dynamic export table. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
const char *
mqvpn_client_test_get_path_state_name(mqvpn_client_t *c, mqvpn_path_handle_t handle,
                                      int *out_retries)
{
    if (!c) return NULL;
    path_entry_t *p = find_path_by_handle(c, handle);
    if (!p) return NULL;
    if (out_retries) *out_retries = p->recreate_retries;
    return path_lifecycle_name(p->state);
}

/* PR4 — cb_path_removed is a thin caller that dispatches
 * PATH_EVENT_XQUIC_REMOVED. State-aware retry-target dispatch (VALIDATING ->
 * CREATE_WAIT, ACTIVE/STANDBY -> DEGRADED, CLOSED_DROPPED -> FREE on cleanup)
 * is centralised in path_on_xquic_removed in path_state_machine.c. */
static void
cb_path_removed(const xqc_cid_t *cid, uint64_t path_id, void *conn_user_data)
{
    (void)cid;
    cli_conn_t *conn = (cli_conn_t *)conn_user_data;
    mqvpn_client_t *c = conn->client;

    path_entry_t *p = find_path_by_xqc_id(c, path_id);
    if (!p) {
        LOG_D(c, "cb_path_removed: no slot for path_id=%" PRIu64, path_id);
        return;
    }

    LOG_I(c, "xquic removed path: path_id=%" PRIu64 " iface=%s state=%s", path_id,
          p->name, path_lifecycle_name(p->state));

    path_event_ctx_t ctx = {.now_us = client_now_us(c)};
    path_on_event(c, p, PATH_EVENT_XQUIC_REMOVED, &ctx);
}

/* ─── Connection destroy (Level 2) ─── */

static void
cli_conn_destroy(mqvpn_client_t *c)
{
    if (!c->conn) return;

    cli_conn_t *conn = c->conn;

    /*
     * Note: h3_conn and masque_request are owned by the xquic engine.
     * When the connection is closed normally, xquic releases them via
     * the close notify callbacks. We only need to free the conn struct.
     *
     * For reconnect (Level 2 teardown), the connection close callbacks
     * have already been invoked by xquic before we reach here, so
     * h3_conn/masque_request are already invalid.
     */
    conn->h3_conn = NULL;
    conn->masque_request = NULL;
    conn->tunnel_ok = 0;
    conn->addr_assigned = 0;
    conn->addr6_assigned = 0;

    if (conn->reorder_tx) {
        mqvpn_reorder_tx_free(conn->reorder_tx);
        conn->reorder_tx = NULL;
    }
    if (conn->reorder_rx) {
        mqvpn_reorder_rx_free(conn->reorder_rx);
        conn->reorder_rx = NULL;
    }

#ifdef MQVPN_HYBRID_TCP_LANE_ENABLED
    /* Teardown contract: tcp_lane BEFORE lwip_ctx — flow teardown will
     * eventually abort pcbs, which needs the stack still alive. */
    if (conn->tcp_lane) {
        mqvpn_tcp_lane_free(conn->tcp_lane);
        conn->tcp_lane = NULL;
    }
    if (conn->lwip_ctx) {
        mqvpn_lwip_ctx_free(conn->lwip_ctx);
        conn->lwip_ctx = NULL;
    }
#endif

    free(conn);
    c->conn = NULL;
}

/* ─── Scheduler precondition predicate (used by client + server) ─── */

bool
mqvpn_check_scheduler_preconditions(mqvpn_scheduler_t scheduler, int n_paths)
{
    return scheduler == MQVPN_SCHED_BACKUP_FEC && n_paths < 2;
}

#include "mqvpn_conn_settings.h"

/* ─── Start a QUIC/H3 connection ─── */

static int
cli_start_connection(mqvpn_client_t *c)
{
    c->conn_id++;
    cli_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) return -1;
    conn->client = c;

    int multipath = c->config.multipath ? 1 : 0;

    /* Guard: primary path must be platform-attached before we create the
     * xquic connection (avoids leaking an xquic conn on early bail-out). */
    if (c->n_paths > 0 && c->primary_path_idx < c->n_paths) {
        path_entry_t *pp = &c->paths[c->primary_path_idx];
        if (!pp->platform_attached || pp->fd < 0) {
            LOG_W(c, "primary path[%s] not ready (attached=%d fd=%d state=%s)", pp->name,
                  pp->platform_attached, pp->fd, path_lifecycle_name(pp->state));
            goto cleanup;
        }
    }

    /* Connection settings — see src/mqvpn_conn_settings.c for the full body. */
    xqc_conn_settings_t cs;
    mqvpn_conn_settings_input_t cs_input = {
        .is_server = false,
        .enable_multipath = (multipath != 0),
        .scheduler = c->config.scheduler,
        .cc = c->config.cc,
        .init_max_path_id = c->config.init_max_path_id,
    };
    mqvpn_build_conn_settings(&cs_input, &cs);

    xqc_conn_ssl_config_t ssl_cfg;
    memset(&ssl_cfg, 0, sizeof(ssl_cfg));
    ssl_cfg.cert_verify_flag = c->config.insecure ? XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED
                                                  : XQC_TLS_CERT_FLAG_NEED_VERIFY;

    const char *sni =
        c->config.tls_server_name[0] ? c->config.tls_server_name : c->config.server_host;

    const xqc_cid_t *cid =
        xqc_h3_connect(c->engine, &cs, NULL, 0, sni, 0, &ssl_cfg,
                       (struct sockaddr *)&c->server_addr, c->server_addrlen, conn);
    if (!cid) {
        LOG_E(c, "xqc_h3_connect failed");
        goto cleanup;
    }

    /* cid may be misaligned inside xquic's internal structures */
    memcpy(&conn->cid, (const void *)cid, sizeof(conn->cid));
    if (conn->h3_conn) xqc_h3_ext_datagram_set_user_data(conn->h3_conn, conn);

    /* Primary path: xquic synchronously creates path_id 0 as part of conn
     * creation. PR4 transitions PENDING -> VALIDATING via direct write
     * (LINT-ALLOW marker) since no xqc_conn_create_path() is called and
     * EVENT_ACTIVATE_REQUESTED would be a semantic mismatch (no activation
     * attempt was made). Spec §8.1 "special invariant site". */
    if (c->n_paths > 0 && c->primary_path_idx < c->n_paths) {
        path_entry_t *pp = &c->paths[c->primary_path_idx];
        pp->xqc_path_id = 0;     /* LINT-ALLOW: primary bootstrap */
        pp->xquic_path_live = 1; /* LINT-ALLOW: primary bootstrap */
        set_path_state_with_log(c, pp, PATH_LC_VALIDATING, PATH_REASON_ACTIVATE_OK);
        path_invariant_check(pp);
    }

    c->conn = conn; /* ownership transfer — cleanup won't free */

    /* §5: create the reorder shim engines when locally enabled. TX stamping
     * stays gated on peer_reorder_supported (set later by negotiation), so until
     * then everything is sent RAW. RX is created so we can accept stamped
     * datagrams as soon as the peer advertises support. The hash seeds need not
     * match the peer (§6.2); derive them from wall-clock time + conn_id. */
    if (c->config.reorder.mode != MQVPN_REORDER_OFF) {
        uint64_t seed_base = client_now_us(c) ^ ((uint64_t)c->conn_id << 32);
        conn->reorder_tx = mqvpn_reorder_tx_new(&c->config.reorder, seed_base);
        conn->reorder_rx = mqvpn_reorder_rx_new(
            &c->config.reorder, seed_base ^ 0x9e3779b9, cli_reorder_deliver, conn);
        if (!conn->reorder_tx || !conn->reorder_rx) {
            LOG_W(c, "reorder engine alloc failed; falling back to RAW");
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

    conn = NULL;

    LOG_I(c, "connecting to %s:%d (multipath=%d, paths=%d)", c->config.server_host,
          c->config.server_port, multipath, c->n_paths);
    return 0;

cleanup:
    free(conn);
    return -1;
}

/* ================================================================
 *  Public API — Lifecycle
 * ================================================================ */

static int
map_log_level_to_xquic(mqvpn_log_level_t level)
{
    /* xqc_log_level_t: REPORT=0, FATAL=1, ERROR=2, WARN=3, STATS=4, INFO=5, DEBUG=6
     *
     * mqvpn INFO is intentionally mapped to xquic WARN (one tier lower).
     * xquic INFO emits per-packet logs (effectively DEBUG-grade), which
     * tanks throughput on slow consoles like Windows PowerShell. Shifting
     * keeps --log-level info usable; users who want xquic detail use
     * --log-level debug. Do not restore the 1:1 mapping. */
    switch (level) {
    case MQVPN_LOG_DEBUG: return XQC_LOG_DEBUG;
    case MQVPN_LOG_INFO: return XQC_LOG_WARN;
    case MQVPN_LOG_WARN: return XQC_LOG_WARN;
    case MQVPN_LOG_ERROR: return XQC_LOG_ERROR;
    default: return XQC_LOG_WARN;
    }
}

/* Create xquic engine with transport + H3 + datagram callbacks. Returns 0 on success. */
static int
init_xquic_engine(mqvpn_client_t *c)
{
    const mqvpn_config_t *cfg = &c->config;
    xqc_engine_ssl_config_t engine_ssl;
    memset(&engine_ssl, 0, sizeof(engine_ssl));
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

    /* Inject custom clock — critical for Android CLOCK_BOOTTIME */
    if (cfg->clock_fn) {
        s_xqc_clock_fn = cfg->clock_fn;
        s_xqc_clock_ctx = cfg->clock_ctx;
        engine_cbs.realtime_ts = xqc_custom_timestamp;
        engine_cbs.monotonic_ts = xqc_custom_timestamp;
    }

    xqc_transport_callbacks_t tcbs = {
        .write_socket = cb_write_socket,
        .write_socket_ex = cb_write_socket_ex,
        .save_token = cb_save_token,
        .save_session_cb = cb_save_session,
        .save_tp_cb = cb_save_tp,
        .cert_verify_cb = cb_cert_verify,
        .ready_to_create_path_notify = cb_ready_to_create_path,
        .path_removed_notify = cb_path_removed,
    };

    xqc_config_t xconfig;
    if (xqc_engine_get_default_config(&xconfig, XQC_ENGINE_CLIENT) < 0) goto fail;
    xconfig.cfg_log_level = (xqc_log_level_t)map_log_level_to_xquic(cfg->log_level);

    c->engine = xqc_engine_create(XQC_ENGINE_CLIENT, &xconfig, &engine_ssl, &engine_cbs,
                                  &tcbs, c);
    if (!c->engine) goto fail;

    /* H3 callbacks */
    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs =
            {
                .h3_conn_create_notify = cb_h3_conn_create,
                .h3_conn_close_notify = cb_h3_conn_close,
                .h3_conn_handshake_finished = cb_h3_conn_handshake_finished,
            },
        .h3r_cbs =
            {
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
    if (xqc_h3_ctx_init(c->engine, &h3_cbs) != XQC_OK) goto fail;

    xqc_h3_conn_settings_t h3s = {
        .max_field_section_size = 32 * 1024,
        .qpack_blocked_streams = 64,
        .qpack_enc_max_table_capacity = 16 * 1024,
        .qpack_dec_max_table_capacity = 16 * 1024,
        .enable_connect_protocol = 1,
        .h3_datagram = 1,
    };
    xqc_h3_engine_set_local_settings(c->engine, &h3s);
    return 0;

fail:
    client_destroy_engine(c);
    return -1;
}

mqvpn_client_t *
mqvpn_client_new(const mqvpn_config_t *cfg, const mqvpn_client_callbacks_t *cbs,
                 void *user_ctx)
{
    if (!client_validate_new_args(cfg, cbs)) return NULL;

    mqvpn_client_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;

    client_init_handle(c, cfg, cbs, user_ctx);

    if (init_xquic_engine(c) < 0) {
        client_destroy_engine(c);
        free(c);
        return NULL;
    }

    return c;
}

void
mqvpn_client_destroy(mqvpn_client_t *client)
{
    if (!client) return;

    client_destroy_engine(client);
    cli_conn_destroy(client);
    free(client);
}

int
mqvpn_client_connect(mqvpn_client_t *c)
{
    if (!c) return MQVPN_ERR_INVALID_ARG;
    ASSERT_TICK_THREAD(c);

    if (!mqvpn_state_transition_valid(c->state, MQVPN_STATE_CONNECTING))
        return MQVPN_ERR_INVALID_ARG;

    /* Warn if the scheduler choice has unmet path-count preconditions.
     * This is a snapshot at connect time — adding a second path later via
     * mqvpn_client_add_path_fd() resolves the underlying issue but does
     * not retract the warning. Acceptable tradeoff: the warning is
     * informational only and the typical backup_fec deployment configures
     * both paths before connect(). */
    if (mqvpn_check_scheduler_preconditions(c->config.scheduler, c->n_paths)) {
        LOG_W(c,
              "backup_fec scheduler is most effective with >=2 paths; "
              "currently %d path(s) configured",
              c->n_paths);
    }

    /* Warn if backup_fec was selected via the public API on a build that
     * lacks FEC — mqvpn_apply_scheduler() will silently downgrade to MINRTT.
     * The CLI parser rejects "backup_fec" earlier in this case, but direct
     * libmqvpn API consumers (e.g. JNI/Kotlin SDK in M3) don't go through
     * the parser. */
#if !defined(XQC_ENABLE_FEC) || !defined(XQC_ENABLE_XOR)
    if (c->config.scheduler == MQVPN_SCHED_BACKUP_FEC) {
        LOG_W(c, "backup_fec scheduler requested but library built without FEC "
                 "support (XQC_ENABLE_FEC/XQC_ENABLE_XOR); downgrading to minrtt");
    }
#endif

    if (cli_start_connection(c) < 0) return MQVPN_ERR_ENGINE;

    client_set_state(c, MQVPN_STATE_CONNECTING);
    /* Platform drives the engine via tick() — no main_logic here */
    return MQVPN_OK;
}

int
mqvpn_client_disconnect(mqvpn_client_t *c)
{
    if (!c) return MQVPN_ERR_INVALID_ARG;
    ASSERT_TICK_THREAD(c);

    if (c->state == MQVPN_STATE_CLOSED || c->state == MQVPN_STATE_IDLE) return MQVPN_OK;

    c->shutting_down = 1;
    if (c->conn && c->engine) {
        xqc_conn_close(c->engine, &c->conn->cid);
        xqc_engine_main_logic(c->engine);
    }
    client_set_state(c, MQVPN_STATE_CLOSED);
    return MQVPN_OK;
}

/* ─── Path management ─── */

/* Map the slot's lifecycle state after the synchronous activation half of
 * mqvpn_client_add_path_fd_with_outcome to the public add-path outcome.
 *
 * Called only when activation was attempted (multipath_ready was true).
 *
 * @invariant post-activate: s ∈ {
 *     VALIDATING, ACTIVE, STANDBY,    // sync success (xqc path live)
 *     CREATE_WAIT,                     // sync transient failure
 *     CLOSED_RECOVERABLE               // sync permanent failure (budget/OOM)
 * }
 * activate_pending_paths -> client_activate_path always lands the slot in
 * one of these 5 states. The other 4 (PENDING, DEGRADED, CLOSED_DROPPED,
 * CLOSED_FREE) only occur if an upstream invariant is violated — fail
 * loud in debug/ASAN builds, fall back to OK in release so a freshly-
 * added handle still reports "stored, will activate later" semantics
 * rather than misclassifying as a hard failure. */
static mqvpn_add_path_outcome_t
add_path_outcome_from_state(path_lifecycle_t s)
{
    /* PR4 — function-local _Static_assert removed; the equivalent
     * compile-time pin now lives at file scope in path_state_machine.h
     * (consolidated to header). */

    switch (s) {
    case PATH_LC_VALIDATING:
    case PATH_LC_ACTIVE:
    case PATH_LC_STANDBY: return MQVPN_ADD_PATH_OK;
    case PATH_LC_CREATE_WAIT: return MQVPN_ADD_PATH_TRANSIENT_FAIL;
    case PATH_LC_CLOSED_RECOVERABLE: return MQVPN_ADD_PATH_PERMANENT_FAIL;
    case PATH_LC_PENDING:
    case PATH_LC_DEGRADED:
    case PATH_LC_CLOSED_DROPPED:
    case PATH_LC_CLOSED_FREE:
        /* Unreachable per the post-activate invariant above. Asserts
         * trip in debug / ASAN / UBSan so FSM regressions surface in CI
         * rather than silently degrading bench numbers. */
        assert(0 && "add_path_outcome_from_state: lifecycle invariant violated");
        return MQVPN_ADD_PATH_OK;
    }
    /* Unreachable: compiler exhaustiveness (-Wswitch-enum) + the
     * _Static_assert above cover every path_lifecycle_t value. Kept as
     * a last-resort runtime guard in case either guard is locally
     * disabled. */
    assert(0 && "add_path_outcome_from_state: unknown lifecycle value");
    return MQVPN_ADD_PATH_OK;
}

mqvpn_path_handle_t
mqvpn_client_add_path_fd_with_outcome(mqvpn_client_t *c, int fd,
                                      const mqvpn_path_desc_t *desc,
                                      mqvpn_add_path_outcome_t *outcome)
{
    if (!c || fd < 0) return -1;
    ASSERT_TICK_THREAD(c);

    /* Reuse a CLOSED slot if available, otherwise append.
     *
     * Tighten the predicate with `!xquic_path_live`: a slot in CLOSED_DROPPED
     * whose xquic-side path hasn't drained yet (xquic_path_live=1 with a
     * pending cb_path_removed) carries a live xqc_path_id binding. Reusing
     * the slot now zeroes that binding via path_entry_init() — when the
     * delayed cb_path_removed fires it can no longer find_path_by_xqc_id,
     * leaving xquic's removal accounting unreconciled with the lib slot.
     * Waiting for xquic-side cleanup (xquic_path_live=0) is the natural fence. */
    int idx = -1;
    for (int i = 0; i < c->n_paths; i++) {
        if (c->paths[i].status == MQVPN_PATH_CLOSED && !c->paths[i].platform_attached &&
            !c->paths[i].xquic_path_live) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        if (c->n_paths >= MQVPN_MAX_PATHS) return -1;
        idx = c->n_paths++;
    }

    path_entry_t *p = &c->paths[idx];
    /* Slot init (§7.1 file-scope allow — slot has no prior state to preserve).
     * path_entry_init leaves p->state at PATH_LC_CLOSED_FREE so EVENT_ADD_FD
     * transitions cleanly to PENDING and the platform_attached=1 field is
     * applied inside path_on_add_fd. */
    path_entry_init(p);
    p->handle = c->next_path_handle++;
    p->fd = fd;

    /* Ensure adequate socket buffers for high-throughput UDP (ref: WireGuard) */
    int bufsize = SOCKET_BUF_SIZE;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char *)&bufsize, sizeof(bufsize));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&bufsize, sizeof(bufsize));
#ifdef SO_SNDBUFFORCE
    setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, (const char *)&bufsize, sizeof(bufsize));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, (const char *)&bufsize, sizeof(bufsize));
#endif

    if (desc) {
        memcpy(p->name, desc->iface, sizeof(p->name));
        p->name[sizeof(p->name) - 1] = '\0';
        if (desc->local_addr_len > 0 && desc->local_addr_len <= sizeof(p->local_addr))
            memcpy(&p->local_addr, desc->local_addr, desc->local_addr_len);
        p->local_addr_len = desc->local_addr_len;
        p->platform_net_id = desc->platform_net_id;
        p->flags = desc->flags;
    }

    /* CLOSED_FREE -> PENDING via EVENT_ADD_FD. path_on_add_fd handler sets
     * platform_attached=1 and emits the transition log. */
    path_event_ctx_t add_ctx = {.now_us = client_now_us(c)};
    path_on_event(c, p, PATH_EVENT_ADD_FD, &add_ctx);

    /* Default outcome: OK (deferred until cb_ready_to_create_path drains
     * PENDING slots). Will be overwritten if activation runs synchronously. */
    if (outcome) *outcome = MQVPN_ADD_PATH_OK;

    /* If multipath is already negotiated, activate immediately. Any other
     * PENDING slot (rare — usually drained by the ready_to_create_path
     * callback) should have been activated too. */
    if (c->multipath_ready && c->config.multipath && c->conn) {
        activate_pending_paths(c);
        if (outcome) *outcome = add_path_outcome_from_state(p->state);
    }

    return p->handle;
}

mqvpn_path_handle_t
mqvpn_client_add_path_fd(mqvpn_client_t *c, int fd, const mqvpn_path_desc_t *desc)
{
    return mqvpn_client_add_path_fd_with_outcome(c, fd, desc, NULL);
}

int
mqvpn_client_remove_path(mqvpn_client_t *c, mqvpn_path_handle_t path)
{
    if (!c) return MQVPN_ERR_INVALID_ARG;
    ASSERT_TICK_THREAD(c);

    path_entry_t *p = find_path_by_handle(c, path);
    if (!p) return MQVPN_ERR_INVALID_ARG;
    if (p->state == PATH_LC_CLOSED_FREE) return MQVPN_OK;

    /* Spec §5.0: REMOVE_API allows orderly xquic close. Issue before
     * dispatch so the FSM stays xquic-API-free (avoids layer leak). */
    if (p->xquic_path_live && p->xqc_path_id != 0 && c->engine && c->conn)
        xqc_conn_close_path(c->engine, &c->conn->cid, p->xqc_path_id);

    path_event_ctx_t ctx = {.now_us = client_now_us(c)};
    path_on_event(c, p, PATH_EVENT_REMOVE_API, &ctx);
    return MQVPN_OK;
}

int
mqvpn_client_drop_path(mqvpn_client_t *c, mqvpn_path_handle_t handle)
{
    /* PR5: thin wrapper of mqvpn_client_on_platform_path_dropped() with
     * NULL info (no diagnostic context). Preserved for ABI compat. */
    return mqvpn_client_on_platform_path_dropped(c, handle, NULL);
}

int
mqvpn_client_on_platform_path_dropped(mqvpn_client_t *c, mqvpn_path_handle_t handle,
                                      const mqvpn_platform_path_event_info_t *info)
{
    if (!c) return MQVPN_ERR_INVALID_ARG;
    ASSERT_TICK_THREAD(c);
    path_entry_t *p = find_path_by_handle(c, handle);
    if (!p) return MQVPN_ERR_INVALID_ARG;

    /* NULL info case is silent (preserve pre-PR5 drop_path log-free behavior).
     * Only log when caller provided diagnostic context. */
    if (info && info->iface[0]) {
        LOG_I(c, "platform path dropped: handle=%lld iface=%s reason=%d",
              (long long)handle, info->iface, (int)info->reason);
    }

    /* Draft-21 PATH_ABANDON: tell xquic to abandon the dead path so its
     * CID/path_id slot is released for reuse. Non-blocking (queues frame
     * on an alternate path). Fails gracefully if this is the only active
     * path or if the connection is already closing. */
    if (p->xquic_path_live && c->engine && c->conn)
        xqc_conn_close_path(c->engine, &c->conn->cid, p->xqc_path_id);

    path_event_ctx_t ctx = {.now_us = client_now_us(c)};
    path_on_event(c, p, PATH_EVENT_PLATFORM_DROP, &ctx);
    return MQVPN_OK;
}

int
mqvpn_client_on_platform_fd_closed(mqvpn_client_t *c, mqvpn_path_handle_t handle)
{
    if (!c) return MQVPN_ERR_INVALID_ARG;
    ASSERT_TICK_THREAD(c);
    path_entry_t *p = find_path_by_handle(c, handle);
    if (!p) return MQVPN_ERR_INVALID_ARG;

    path_event_ctx_t ctx = {.now_us = client_now_us(c)};
    path_on_event(c, p, PATH_EVENT_FD_CLOSED, &ctx);
    return MQVPN_OK;
}

/* ─── Path re-activation (platform-triggered) ─── */

/* Per-slot eligibility for platform-driven reactivation. Returns MQVPN_OK
 * if the slot is in a state where the next action would be a retry — i.e.
 * xquic-side dead and waiting (DEGRADED, CREATE_WAIT) or fully closed but
 * platform-restorable (CLOSED_RECOVERABLE). VALIDATING is excluded by the
 * xquic_path_live==1 check; PENDING (never tried) is excluded so the normal
 * cb_ready_to_create_path drain remains authoritative on first activation.
 *
 * CREATE_WAIT was added by PR3 as the post-VALIDATING-fail state; before
 * that split the same slot would have been in DEGRADED. */
static int
reactivate_slot_eligible(const path_entry_t *p)
{
    if (p->xquic_path_live) return MQVPN_ERR_INVALID_STATE;
    if (!p->platform_attached) return MQVPN_ERR_INVALID_STATE;
    if (p->state != PATH_LC_DEGRADED && p->state != PATH_LC_CREATE_WAIT &&
        p->state != PATH_LC_CLOSED_RECOVERABLE)
        return MQVPN_ERR_INVALID_STATE;
    return MQVPN_OK;
}

int
mqvpn_client_reactivate_path(mqvpn_client_t *c, mqvpn_path_handle_t handle)
{
    if (!c) return MQVPN_ERR_INVALID_ARG;
    ASSERT_TICK_THREAD(c);

    /* Conn-level guards (preserved from main 433272f). */
    if (c->state != MQVPN_STATE_ESTABLISHED || !c->multipath_ready)
        return MQVPN_ERR_INVALID_STATE;

    path_entry_t *p = find_path_by_handle(c, handle);
    if (!p) return MQVPN_ERR_INVALID_ARG;

    /* Per-slot eligibility: DEGRADED / CREATE_WAIT / CLOSED_RECOVERABLE only.
     * Entry gate (live regression follow-up — main 433272f). Defense in depth
     * with path_on_manual_reactivate's own 3-state check. */
    int gate = reactivate_slot_eligible(p);
    if (gate != MQVPN_OK) return gate;

    LOG_I(c, "platform reactivating path: %s (state=%s)", p->name,
          path_lifecycle_name(p->state));

    uint64_t new_id = 0;
    activate_result_t r = activate_via_xquic_classify(c, &new_id);
    path_event_ctx_t ctx = {
        .result = r,
        .new_xqc_path_id = new_id,
        .now_us = client_now_us(c),
    };
    path_on_event(c, p, PATH_EVENT_MANUAL_REACTIVATE, &ctx);

    /* path_on_event(MANUAL_REACTIVATE) lands the slot in VALIDATING on OK,
     * or leaves state unchanged on TRANSIENT/PERMANENT. */
    if (p->state != PATH_LC_VALIDATING) return MQVPN_ERR_ENGINE;
    return MQVPN_OK;
}

/* PR3 test-only helper: runs only the per-slot eligibility gate of
 * mqvpn_client_reactivate_path. Bypasses the c->state==ESTABLISHED +
 * multipath_ready guard and the live activation call so tests can pin
 * the gate without a real engine/conn. Hidden from libmqvpn.so's
 * dynamic export table. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
int
mqvpn_client_test_reactivate_slot_eligible(mqvpn_client_t *c, mqvpn_path_handle_t handle)
{
    if (!c) return MQVPN_ERR_INVALID_ARG;
    path_entry_t *p = find_path_by_handle(c, handle);
    if (!p) return MQVPN_ERR_INVALID_ARG;
    return reactivate_slot_eligible(p);
}

int
mqvpn_client_set_tun_active(mqvpn_client_t *c, int active, int tun_fd)
{
    if (!c) return MQVPN_ERR_INVALID_ARG;
    ASSERT_TICK_THREAD(c);
    c->tun_active = active;
    (void)tun_fd;

    if (active && c->state == MQVPN_STATE_TUNNEL_READY)
        client_set_state(c, MQVPN_STATE_ESTABLISHED);

    return MQVPN_OK;
}

/* ─── I/O feed ─── */

/* Outcome of ingress validation / lane decision — internal to the TUN path. */
typedef enum {
    TUN_INGRESS_PROCEED = 0,
    TUN_INGRESS_DROP, /* consumed (silent drop or ICMP emitted): return MQVPN_OK */
} tun_ingress_verdict_t;

/* Src-address validation. ip_ver is computed by the CALLER (pkt[0] >> 4) and
 * passed by value; the caller also keeps the IPv4 len < IPV4_MIN_HDR check
 * (its return value differs). All failures here are silent drops.
 * PRECONDITION: for ip_ver == 4 the caller has ensured len >= IPV4_MIN_HDR
 * (the memcmp below reads pkt[12..15]). */
static tun_ingress_verdict_t
tun_validate_src(mqvpn_client_t *c, cli_conn_t *conn, const uint8_t *pkt, size_t len,
                 uint8_t ip_ver)
{
    if (ip_ver == 4) {
        if (conn->addr_assigned && memcmp(pkt + 12, conn->assigned_ip, 4) != 0) {
            LOG_D(c, "tun drop: IPv4 src mismatch (len=%zu)", len);
            return TUN_INGRESS_DROP; /* silently drop: src mismatch */
        }
    } else if (ip_ver == 6) {
        if (len < IPV6_MIN_HDR || !conn->addr6_assigned) {
            LOG_D(c, "tun drop: IPv6 too short or no addr6 (len=%zu)", len);
            return TUN_INGRESS_DROP;
        }
        if (memcmp(pkt + 8, conn->assigned_ip6, 16) != 0) {
            LOG_D(c, "tun drop: IPv6 src mismatch (len=%zu)", len);
            return TUN_INGRESS_DROP;
        }
    } else {
        LOG_D(c, "tun drop: unknown IP version %d (len=%zu)", ip_ver, len);
        return TUN_INGRESS_DROP;
    }
    return TUN_INGRESS_PROCEED;
}

#ifdef MQVPN_HYBRID_TCP_LANE_ENABLED
/* Paths a new TCP-lane flow could actually be striped across right now.
 * Same slot array mqvpn_client_get_paths() aggregates; only PATH_LC_ACTIVE
 * counts — VALIDATING/STANDBY/DEGRADED paths carry no scheduled traffic,
 * so they don't justify the TCP-lane detour under tcp=auto. */
static int
active_paths_count(const mqvpn_client_t *c)
{
    int n = 0;
    for (int i = 0; i < c->n_paths; i++)
        if (c->paths[i].state == PATH_LC_ACTIVE) n++;
    return n;
}

/* SYN-time lane verdict (spec: snapshot at flow creation, never
 * re-evaluated mid-flow — callers invoke this exactly once per new flow,
 * right before mqvpn_tcp_lane_on_syn commits it). Returns 1 = TCP lane,
 * 0 = sticky RAW. */
static int
hybrid_tcp_syn_policy(const mqvpn_client_t *c)
{
    switch (c->config.hybrid.tcp_mode) {
    case MQVPN_HYBRID_TCP_STREAM: return 1;
    case MQVPN_HYBRID_TCP_RAW:
        return 0; /* unreachable: classifier never
                   * yields LANE_TCP under tcp=raw */
    case MQVPN_HYBRID_TCP_AUTO: break;
    }
    return active_paths_count(c) >= 2;
}
#endif /* MQVPN_HYBRID_TCP_LANE_ENABLED */

/* Reorder STAMP/RAW/DROP_MTU decision + both ICMP PTB paths (stamped
 * over-MTU and RAW over-MTU). Computes udp_mss internally. Fills *do_stamp
 * and *peek. Caller must zero-initialize *do_stamp and *peek; they are
 * written only on the STAMP path. */
static tun_ingress_verdict_t
tun_decide_lane(mqvpn_client_t *c, cli_conn_t *conn, const uint8_t *pkt, size_t len,
                uint8_t ip_ver, int *do_stamp, mqvpn_reorder_tx_peek_t *peek)
{
    /* Hybrid H2: classify, then route TCP-lane candidates through the
     * sticky per-flow table — feed lwIP or fall to RAW. `break` out of the
     * switch IS the RAW fallthrough (continues to the reorder gating
     * below). DGRAM verdicts fall through to the existing reorder
     * STAMP/RAW gating unchanged. Skipped entirely when hybrid is
     * disabled (default) — zero hot-path cost. */
    if (c->config.hybrid.enabled) {
        mqvpn_flow_key_t flow_key;
        /* Set on entry to the LANE_TCP case; every exit from it EXCEPT the
         * lwIP hand-off (which returns TUN_INGRESS_DROP before reaching the
         * post-switch bump) is a fall-back to the RAW lane, so this flag
         * lets those packets land in pkts_lane_raw — keeping the
         * tcp+dgram+raw partition total. Without it, a TCP candidate that
         * fell back to RAW (sticky-RAW marker, cap-rejected SYN, non-SYN on
         * an unknown flow, marker-cap refusal, or a lane-less build) would
         * be transmitted RAW yet counted in no lane at all. */
        int tcp_candidate_to_raw = 0;
        switch (mqvpn_hybrid_classify(pkt, len, &c->config.hybrid, &flow_key)) {
        case MQVPN_LANE_TCP:
            /* pkts_lane_tcp is deliberately NOT incremented here: at this
             * point the packet is only TCP-shaped (IPv4 TCP, hybrid
             * enabled, tcp mode != raw) — whether it actually reaches the
             * TCP lane still depends on the per-flow sticky verdict below
             * (an established sticky-RAW flow, a cap-rejected new flow, or
             * a non-SYN packet on an unknown flow all `break` out to RAW
             * without ever touching lwIP). Counting here would make
             * pkts_lane_tcp indistinguishable between a sticky-RAW flow and
             * a real TCP-lane flow under tcp=auto. The counter is bumped
             * instead right before the lwIP hand-off below, once the
             * verdict has actually resolved to "feed lwIP"; every OTHER
             * exit from this case is a RAW fall-back (tcp_candidate_to_raw,
             * counted in pkts_lane_raw after the switch). */
            tcp_candidate_to_raw = 1;
#ifdef MQVPN_HYBRID_TCP_LANE_ENABLED
            if (conn->tcp_lane) { /* implies lwip_ctx != NULL (coherence
                                   * rule at the creation site) */
                int is_raw = 0, is_closing = 0;
                int found = mqvpn_tcp_lane_lookup(conn->tcp_lane, &flow_key, &is_raw,
                                                  &is_closing);

                /* Flags parse: needed whenever the entry is unknown OR is a
                 * CLOSING routing-residency marker (C1) OR a sticky-RAW
                 * marker (I2) — a pure SYN in any of those cases needs
                 * re-evaluating for tuple reuse. The common established-
                 * flow case (found, ACTIVE / PENDING-anything) skips this
                 * parse (and the ISN parse below) entirely. */
                int is_syn = 0;
                uint32_t pkt_isn = 0;
                if (!found || is_closing || is_raw) {
                    /* Chunk 3: mqvpn_tcp_syn_flag is now family-aware (v4
                     * IHL-derived offset, v6 fixed offset 40) — no ip_ver
                     * gate needed here. Chunk 2's classifier already
                     * excluded ext-header/fragmented v6 (MQVPN_LANE_TCP
                     * only fires for base-NH==TCP), so a v6 is_syn here is
                     * always lane-terminable. */
                    is_syn = mqvpn_tcp_syn_flag(pkt, len);
                    if (is_syn) pkt_isn = mqvpn_tcp_syn_isn(pkt, len);
                }
                if (found && is_syn) {
                    if (is_closing) {
                        /* C1: tuple reuse after close. The prior connection
                         * on this 5-tuple already finished (CLOSING grace-
                         * sweep residency, see tcp_lane_finish_clean_close)
                         * — this is a genuinely new connection. Evaluate it
                         * as brand-new; mqvpn_tcp_lane_on_syn removes the
                         * stale CLOSING marker itself (see its own comment)
                         * before committing the fresh verdict. */
                        found = 0;
                    } else if (is_raw && pkt_isn != mqvpn_tcp_lane_marker_isn(
                                                        conn->tcp_lane, &flow_key)) {
                        /* I2: a different ISN on a sticky-RAW marker means a
                         * genuinely new connection reusing this 5-tuple
                         * (ephemeral port recycling under tcp=auto) — the
                         * old RAW verdict must not apply to it forever.
                         * Same-ISN (the common case: a SYN retransmit of the
                         * SAME still-forming/RAW-committed handshake) stays
                         * sticky-RAW below without ever reaching here. */
                        found = 0;
                    }
                }

                if (!found) {
                    if (!is_syn) {
                        /* Non-SYN for an unknown flow: evicted, mid-stream
                         * (hybrid just enabled), or inbound-connection
                         * traffic (SYN|ACK is deliberately not
                         * flow-starting — see mqvpn_tcp_syn_flag). No
                         * sticky decision to honor — RAW. Do NOT call
                         * on_syn: committing a NEW flow is a SYN-only
                         * action. */
                        break;
                    }
                    int want_tcp = hybrid_tcp_syn_policy(c);
                    if (mqvpn_tcp_lane_on_syn(conn->tcp_lane, &flow_key, want_tcp,
                                              pkt_isn) < 0) {
                        /* Cap hit BEFORE lwIP saw the SYN — safe RAW
                         * fallback (on_syn contract in tcp_lane.h; Task 8's
                         * post-accept rejection point must abort instead).
                         * A want_tcp=0 refusal is just the marker cap: the
                         * flow stays unsticky, not a TCP-lane rejection. */
                        if (want_tcp) c->tcp_flows_rejected++;
                        break;
                    }
                    if (!want_tcp) break; /* sticky-RAW just recorded */
                    /* want_tcp: fall through to feed lwIP */
                } else if (is_raw) {
                    break; /* sticky RAW: same-ISN retransmit (or non-SYN) */
                }
                /* found && is_closing && !is_syn falls through here too:
                 * routing residency (C1) — feed whatever this packet is
                 * (the LAST_ACK final ACK, a TIME_WAIT-era stray, ...) to
                 * lwIP, which demuxes it against its OWN pcb/TIME_WAIT
                 * state; we are only routing, not relaying. */

                /* The verdict has resolved to "feed lwIP" — this IS the TCP
                 * lane, count it here (see the case-entry comment above for
                 * why counting at classify-time instead would conflate
                 * sticky-RAW/rejected packets with real TCP-lane ones). */
                c->pkts_lane_tcp++;
                if (mqvpn_lwip_input(conn->lwip_ctx, pkt, len) < 0)
                    c->pkts_lane_tcp_dropped++;
                /* Consumed by lwIP. MUST be an explicit TUN_INGRESS_DROP:
                 * proceeding would ALSO send the packet RAW via
                 * tun_send_datagram (double-processing). */
                return TUN_INGRESS_DROP;
            }
#endif
            /* No tcp_lane (build flag off or alloc failed): RAW, as H1. */
            break;
        case MQVPN_LANE_DGRAM: c->pkts_lane_dgram++; break;
        case MQVPN_LANE_RAW: c->pkts_lane_raw++; break;
        }
        /* A TCP candidate that fell back to RAW (see tcp_candidate_to_raw's
         * declaration): count it in the raw lane exactly once here. Cannot
         * double-count with the MQVPN_LANE_RAW case above — that case never
         * sets the flag — nor with the lwIP hand-off, which returns before
         * reaching this point. */
        if (tcp_candidate_to_raw) c->pkts_lane_raw++;
    }

    /* §5/§9: reorder gating decides STAMP vs RAW vs DROP_MTU. Stamping is
     * additionally gated on peer support (§19.3/§19.4): until the peer advertises
     * mqvpn-reorder, everything stays RAW (wire-compatible with non-reorder
     * peers). udp_mss is the max inner IP that fits the DATAGRAM; with reorder a
     * STAMP consumes 8 of those bytes (§9), so the peek uses udp_mss as the
     * "max inner without reorder" budget. */
    size_t udp_mss = 0;
    if (conn->dgram_mss > 0)
        udp_mss = xqc_h3_ext_masque_udp_mss(conn->dgram_mss, conn->masque_stream_id);

    if (conn->reorder_tx && conn->peer_reorder_supported &&
        c->config.reorder.mode != MQVPN_REORDER_OFF && udp_mss > 0) {
        mqvpn_reorder_tx_action_t act = mqvpn_reorder_tx_peek(
            conn->reorder_tx, pkt, len, client_now_us(c), (uint32_t)udp_mss, peek);
        if (act == MQVPN_REORDER_TX_STAMP) {
            *do_stamp = 1;
        } else if (act == MQVPN_REORDER_TX_DROP_MTU) {
            /* 8 + len exceeds the DATAGRAM payload: emit ICMP PTB advertising the
             * reorder-reduced effective MTU (udp_mss - 8) and drop, mirroring the
             * RAW MTU-too-big handling below. */
            size_t eff_mtu =
                udp_mss > MQVPN_REORDER_HDR_LEN ? udp_mss - MQVPN_REORDER_HDR_LEN : 0;
            if (ip_ver == 4) {
                if (conn->addr_assigned && ptb_rate_allow(c))
                    mqvpn_icmp_send_v4(
                        c->cbs.tun_output, c->user_ctx, conn->assigned_ip, 3, 4,
                        (eff_mtu > 0xFFFF) ? 0xFFFF : (uint16_t)eff_mtu, pkt, len);
            } else {
                if (conn->addr6_assigned && ptb_rate_allow(c))
                    mqvpn_icmp_send_v6(c->cbs.tun_output, c->user_ctx, conn->assigned_ip6,
                                       2, 0, (uint32_t)eff_mtu, pkt, len);
            }
            return TUN_INGRESS_DROP;
        }
        /* MQVPN_REORDER_TX_RAW falls through to the RAW path. */
    }

    /* ICMP PTB if a RAW packet exceeds tunnel capacity. (When stamping, the
     * §9 MTU reduction already keeps len within budget; the peek's DROP_MTU
     * branch above covers the stamped over-MTU case.) */
    if (!*do_stamp && udp_mss > 0) {
        if (len > udp_mss) {
            if (ip_ver == 4) {
                if (conn->addr_assigned && ptb_rate_allow(c))
                    mqvpn_icmp_send_v4(
                        c->cbs.tun_output, c->user_ctx, conn->assigned_ip, 3, 4,
                        (udp_mss > 0xFFFF) ? 0xFFFF : (uint16_t)udp_mss, pkt, len);
            } else {
                if (conn->addr6_assigned && ptb_rate_allow(c))
                    mqvpn_icmp_send_v6(c->cbs.tun_output, c->user_ctx, conn->assigned_ip6,
                                       2, 0, (uint32_t)udp_mss, pkt, len);
            }
            return TUN_INGRESS_DROP;
        }
    }

    return TUN_INGRESS_PROCEED;
}

/* MASQUE framing + flow-hash hint + datagram send + reorder commit +
 * backpressure latch. Returns the mqvpn error code. */
static int
tun_send_datagram(mqvpn_client_t *c, cli_conn_t *conn, const uint8_t *pkt, size_t len,
                  int do_stamp, mqvpn_reorder_tx_peek_t *peek)
{
    /* On STAMP, prepend the 8-byte reorder header to the inner IP packet; the
     * framed payload is then [hdr || pkt]. On RAW, frame the bare packet. */
    const uint8_t *frame_src = pkt;
    size_t frame_src_len = len;
    uint8_t stamped[MQVPN_REORDER_HDR_LEN + PACKET_BUF_SIZE];
    if (do_stamp) {
        if (len > PACKET_BUF_SIZE) return MQVPN_ERR_INVALID_ARG;
        memcpy(stamped, peek->hdr, MQVPN_REORDER_HDR_LEN);
        memcpy(stamped + MQVPN_REORDER_HDR_LEN, pkt, len);
        frame_src = stamped;
        frame_src_len = len + MQVPN_REORDER_HDR_LEN;
    }

    /* MASQUE frame and send */
    uint8_t frame_buf[MASQUE_FRAME_BUF];
    size_t frame_written = 0;
    xqc_int_t xret =
        xqc_h3_ext_masque_frame_udp(frame_buf, sizeof(frame_buf), &frame_written,
                                    conn->masque_stream_id, frame_src, frame_src_len);
    if (xret != XQC_OK) {
        LOG_W(c, "masque frame failed: xret=%d", xret);
        return MQVPN_ERR_ENGINE;
    }

    uint64_t dgram_id;
    uint32_t fh =
        flow_hash_pkt(pkt, (int)len, c->config.scheduler == MQVPN_SCHED_WLB_UDP_PIN);
    xqc_conn_set_dgram_flow_hash(xqc_h3_conn_get_xqc_conn(conn->h3_conn), fh);
    xret = xqc_h3_ext_datagram_send(conn->h3_conn, frame_buf, frame_written, &dgram_id,
                                    mqvpn_dgram_qos_level(c->config.scheduler));

    if (xret == -XQC_EAGAIN) {
        c->backpressure = 1;
        c->dgram_sent++;
        return MQVPN_ERR_AGAIN;
    }
    if (xret < 0) {
        LOG_W(c, "datagram send failed: xret=%d", xret);
        return MQVPN_ERR_ENGINE;
    }

    /* §10.3: only advance the send_flow sequence on a successful datagram. */
    if (do_stamp) mqvpn_reorder_tx_commit(conn->reorder_tx, peek, client_now_us(c));

    c->dgram_sent++;
    return MQVPN_OK;
}

int
mqvpn_client_on_tun_packet(mqvpn_client_t *c, const uint8_t *pkt, size_t len)
{
    if (!c || !pkt || len == 0) return MQVPN_ERR_INVALID_ARG;
    ASSERT_TICK_THREAD(c);

    cli_conn_t *conn = c->conn;
    if (!conn || !conn->tunnel_ok) return MQVPN_ERR_INVALID_ARG;
    if (c->backpressure) return MQVPN_ERR_AGAIN;

    uint8_t ip_ver = pkt[0] >> 4;
    /* Kept inline, NOT in tun_validate_src: this is the one validation
     * failure that returns MQVPN_ERR_INVALID_ARG instead of a silent drop,
     * and it guards the pkt[12..15] read inside the helper. */
    if (ip_ver == 4 && len < IPV4_MIN_HDR) return MQVPN_ERR_INVALID_ARG;

    if (tun_validate_src(c, conn, pkt, len, ip_ver) != TUN_INGRESS_PROCEED)
        return MQVPN_OK;

    int do_stamp = 0;
    mqvpn_reorder_tx_peek_t peek = {0};
    if (tun_decide_lane(c, conn, pkt, len, ip_ver, &do_stamp, &peek) !=
        TUN_INGRESS_PROCEED) {
        return MQVPN_OK;
    }

    return tun_send_datagram(c, conn, pkt, len, do_stamp, &peek);
}

int
mqvpn_client_on_socket_recv(mqvpn_client_t *c, mqvpn_path_handle_t path,
                            const uint8_t *pkt, size_t len, const struct sockaddr *peer,
                            socklen_t peer_len)
{
    if (!c || !pkt || len == 0 || len > 65536) return MQVPN_ERR_INVALID_ARG;
    ASSERT_TICK_THREAD(c);
    if (!c->engine) return MQVPN_ERR_ENGINE;

    /* Find local address for this path */
    struct sockaddr_storage local_addr;
    socklen_t local_len = sizeof(local_addr);
    memset(&local_addr, 0, sizeof(local_addr));

    path_entry_t *pe = find_path_by_handle(c, path);
    if (pe) {
        pe->bytes_rx += len;
        if (pe->local_addr_len > 0) {
            memcpy(&local_addr, &pe->local_addr, pe->local_addr_len);
            local_len = pe->local_addr_len;
        }
    }

    uint64_t recv_time = client_now_us(c);
    xqc_engine_packet_process(c->engine, pkt, len, (struct sockaddr *)&local_addr,
                              local_len, peer, peer_len, (xqc_usec_t)recv_time, NULL);

    return MQVPN_OK;
}

/* ─── Tick: path recovery ─── */

/* PR4 — drive retry timer for both CREATE_WAIT (never validated) and
 * DEGRADED (was validated). Spec §5.1 / §6.1: shared retry counter, shared
 * backoff, shared activation entrypoint. Dispatches PATH_EVENT_RETRY_TIMER;
 * path_on_retry_timer in path_state_machine.c handles the state-aware
 * retry_target dispatch + retry counter bookkeeping. */
static void
tick_drive_retry_timer(mqvpn_client_t *c, path_entry_t *p, int idx, uint64_t now)
{
    if (p->state != PATH_LC_DEGRADED && p->state != PATH_LC_CREATE_WAIT) return;
    if (p->recreate_after_us == 0 || now < p->recreate_after_us) return;

    uint64_t new_id = 0;
    activate_result_t r = activate_via_xquic_classify(c, &new_id);
    LOG_I(c, "path[%d] retry: result=%s retries=%d/%d", idx,
          r == ACTIVATE_OK               ? "OK"
          : r == ACTIVATE_PERMANENT_FAIL ? "PERMANENT"
                                         : "TRANSIENT",
          p->recreate_retries, PATH_RECREATE_MAX_RETRIES);

    path_event_ctx_t ctx = {
        .result = r,
        .new_xqc_path_id = new_id,
        .now_us = now,
    };
    path_on_event(c, p, PATH_EVENT_RETRY_TIMER, &ctx);
    /* Note: the old code set p->path_stable_since_us to `now` after success
     * here, but that violated the VALIDATING invariant (path_stable_since_us
     * must be 0 in VALIDATING). The stability-timer anchor is now set on
     * VALIDATION_OK in path_on_validation_ok. */
}

/* Detect xquic-side path validation completion. xquic does not expose a
 * callback for "path validated" — server-side mqvpn already polls
 * paths_info[].path_state (mqvpn_server.c:1605 derive_mp_state_label); we
 * mirror that here for the client side. Called once per tick before the
 * per-slot loop so the xqc_conn_get_stats result is shared across all
 * VALIDATING slots.
 *
 * Note on the literal `2`: XQC_PATH_STATE_ACTIVE lives in the private
 * xqc_multipath.h header and is not visible to library consumers. Server-side
 * also uses the literal with a comment cross-reference (no _Static_assert
 * exists — there is nothing public to assert against). */
static void
tick_check_all_validations(mqvpn_client_t *c, uint64_t now)
{
    /* multipath_ready guards against c->conn->cid being garbage before
     * cb_conn_create populates it, AND against cb_ready_to_create_path not
     * yet having created any paths (paths_info would be empty sentinels). */
    if (!c->multipath_ready || !c->conn) return;

    /* Quick scan: any VALIDATING slot at all? Avoid the get_stats call when
     * nothing to do (the common steady-state). */
    int any_validating = 0;
    for (int i = 0; i < c->n_paths; i++) {
        if (c->paths[i].state == PATH_LC_VALIDATING) {
            any_validating = 1;
            break;
        }
    }
    if (!any_validating) return;

    xqc_conn_stats_t st = xqc_conn_get_stats(c->engine, &c->conn->cid);

    for (int i = 0; i < c->n_paths; i++) {
        path_entry_t *p = &c->paths[i];
        if (p->state != PATH_LC_VALIDATING) continue;

        const xqc_path_metrics_t *pm = xqc_find_path_metrics(&st, p->xqc_path_id);
        if (!pm) continue;
        if (pm->path_state != 2) continue;
        /* XQC_PATH_STATE_ACTIVE = 2 lives in private xqc_multipath.h;
         * still validating below that. */

        /* Branch on connection-scoped scheduler config — secondary paths
         * created under backup_fec are STANDBY (spec §10.1.1). Scheduler
         * is immutable per-connection so the result is stable for the
         * lifetime of this path. Dispatched via VALIDATION_OK; the
         * handler sets path_stable_since_us = now and transitions to
         * the carried target. */
        path_lifecycle_t target = (c->config.scheduler == MQVPN_SCHED_BACKUP_FEC)
                                      ? PATH_LC_STANDBY
                                      : PATH_LC_ACTIVE;
        path_event_ctx_t v_ctx = {.validated_target = target, .now_us = now};
        path_on_event(c, p, PATH_EVENT_VALIDATION_OK, &v_ctx);
        LOG_I(c, "path[%d] activated: path_id=%" PRIu64 " iface=%s state=%s", i,
              p->xqc_path_id, p->name, path_lifecycle_name(target));
    }
    free(st.paths_info);
}

/* PR4 — tick_confirm_stable_path relocated to path_state_machine.c as
 * path_fsm_tick_confirm_stable() (§7.1 file-scope allow for path_stable_since_us
 * and recreate_retries direct writes). */

static void
tick_path_recovery(mqvpn_client_t *c)
{
    if (!c->multipath_ready || c->state != MQVPN_STATE_ESTABLISHED) return;

    uint64_t now = client_now_us(c);
    tick_check_all_validations(c, now);
    for (int i = 0; i < c->n_paths; i++) {
        path_entry_t *p = &c->paths[i];
        client_path_residence_check(c, p, now);
        tick_drive_retry_timer(c, p, i, now);
        path_fsm_tick_confirm_stable(c, p, now);
    }
}

/* ─── Tick: reconnect ─── */

static void
tick_reconnect(mqvpn_client_t *c)
{
    if (c->state != MQVPN_STATE_RECONNECTING || c->reconnect_scheduled_us == 0) return;

    uint64_t t = client_now_us(c);
    if (t < c->reconnect_scheduled_us) return;

    c->reconnect_scheduled_us = 0;
    LOG_I(c, "attempting reconnection (attempt %d)...", c->reconnect_attempts);

    /* Reset path state for a fresh connection attempt. */
    client_reset_paths_for_reconnect(c);

    if (cli_start_connection(c) < 0) {
        int delay = client_arm_reconnect_timer(c);
        LOG_I(c, "reconnect failed, retrying in %ds (attempt %d)", delay,
              c->reconnect_attempts);
        if (c->cbs.reconnect_scheduled) c->cbs.reconnect_scheduled(delay, c->user_ctx);
    } else {
        client_set_state(c, MQVPN_STATE_CONNECTING);
        xqc_engine_main_logic(c->engine);
    }
}

/* ─── Tick: handshake stall watchdog ─── */

static void
tick_handshake_watchdog(mqvpn_client_t *c)
{
    if (c->shutting_down) return;
    if (!client_handshake_stalled(c, client_now_us(c))) return;

    const char *iface = "?";
    if (c->primary_path_idx >= 0 && c->primary_path_idx < c->n_paths) {
        iface = c->paths[c->primary_path_idx].name;
    }
    LOG_W(c, "handshake stalled %dms on path[%d] (%s); aborting to rotate",
          HANDSHAKE_STALL_TIMEOUT_MS, c->primary_path_idx, iface);

    /* Clear immediately so xqc_engine_main_logic running below can fire
     * cb_h3_conn_close synchronously without the watchdog re-firing. */
    c->handshake_started_us = 0;

    if (c->engine && c->conn) {
        /* xqc_h3_conn_close marks the conn for close. Engine drains it on
         * the next main_logic call (already queued in mqvpn_client_tick after
         * this watchdog) and fires cb_h3_conn_close, which arms the reconnect
         * timer; tick_reconnect → client_reset_paths_for_reconnect rotates
         * primary_path_idx so the dead first path is skipped. */
        xqc_h3_conn_close(c->engine, &c->conn->cid);
    } else {
        /* No live conn (cli_start_connection failed earlier) — shortcut to
         * reconnect via the same code path. Rotation still happens in
         * client_reset_paths_for_reconnect. */
        client_arm_reconnect_timer(c);
        client_set_state(c, MQVPN_STATE_RECONNECTING);
    }
}

/* ─── Tick ─── */

int
mqvpn_client_tick(mqvpn_client_t *c)
{
    if (!c) return MQVPN_ERR_INVALID_ARG;
    ASSERT_TICK_THREAD(c);

    tick_handshake_watchdog(c);
    if (c->engine) xqc_engine_main_logic(c->engine);
    tick_path_recovery(c);
    tick_reconnect(c);

    /* §5/§11.1: drive reorder RX gap timeouts + idle eviction. */
    if (c->conn && c->conn->reorder_rx)
        mqvpn_reorder_rx_tick(c->conn->reorder_rx, client_now_us(c));

#ifdef MQVPN_HYBRID_TCP_LANE_ENABLED
    /* H2: drive lwIP's manual timers (tcp_tmr cadence lives in the glue). */
    if (c->conn && c->conn->lwip_ctx) mqvpn_lwip_tick(c->conn->lwip_ctx);
    /* H2/Task 13: TCP-lane idle-timeout eviction sweep. Order relative to
     * mqvpn_lwip_tick above is irrelevant (both run every tick; neither
     * depends on the other having just run). */
    if (c->conn && c->conn->tcp_lane)
        mqvpn_tcp_lane_tick(c->conn->tcp_lane, client_now_us(c));
#endif

    return MQVPN_OK;
}

/* ─── Query functions ─── */

mqvpn_client_state_t
mqvpn_client_get_state(const mqvpn_client_t *c)
{
    if (!c) return MQVPN_STATE_CLOSED;
    return c->state;
}

int
mqvpn_client_get_stats(const mqvpn_client_t *c, mqvpn_stats_t *out)
{
    if (!c || !out) return MQVPN_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->bytes_tx = c->bytes_tx;
    out->bytes_rx = c->bytes_rx;
    out->dgram_sent = c->dgram_sent;
    out->dgram_recv = c->dgram_recv;
    out->dgram_lost = c->dgram_lost;
    out->dgram_acked = c->dgram_acked;
    out->pkts_lane_tcp = c->pkts_lane_tcp;
    out->pkts_lane_dgram = c->pkts_lane_dgram;
    out->pkts_lane_raw = c->pkts_lane_raw;
    out->pkts_lane_tcp_dropped = c->pkts_lane_tcp_dropped;
    /* tcp_flows_rejected's authoritative source is c->tcp_flows_rejected
     * (pre-lwIP SYN rejections, cap and alloc-failure alike) — see the
     * field comment on c->pkts_lane_tcp above for why this must not be
     * summed with the lane's internal flows_rejected_cap. */
    out->tcp_flows_rejected = c->tcp_flows_rejected;
#ifdef MQVPN_HYBRID_TCP_LANE_ENABLED
    /* tcp_flows_active/total and raw_markers_active are gauges/counters
     * the TCP-lane flow table already maintains (mqvpn_tcp_lane_get_stats)
     * — surface them verbatim rather than re-deriving. Stay 0 (memset
     * above) when hybrid is disabled or the lane never came up. */
    if (c->conn && c->conn->tcp_lane) {
        mqvpn_tcp_lane_stats_t lane_stats;
        mqvpn_tcp_lane_get_stats(c->conn->tcp_lane, &lane_stats);
        out->tcp_flows_active = lane_stats.flows_active;
        out->tcp_flows_total = lane_stats.flows_total;
        out->raw_markers_active = lane_stats.raw_markers_active;
    }
#endif

    /* Get connection-level SRTT from xquic (μs → ms) */
    if (c->engine && c->conn) {
        xqc_conn_stats_t xs = xqc_conn_get_stats(c->engine, &c->conn->cid);
        out->srtt_ms = (int)(xs.srtt / 1000);
        free(xs.paths_info);
    }
    return MQVPN_OK;
}

int
mqvpn_client_get_reorder_stats(const mqvpn_client_t *c, mqvpn_reorder_stats_t *out)
{
    if (!c || !out) return -1;
    if (c->conn && c->conn->reorder_rx) {
        mqvpn_reorder_rx_get_stats(c->conn->reorder_rx, out);
    } else {
        memset(out, 0, sizeof(*out));
    }
    return 0;
}

int
mqvpn_client_get_paths(const mqvpn_client_t *c, mqvpn_path_info_t *out, int max_paths,
                       int *n_paths)
{
    if (!c || !out || !n_paths) return MQVPN_ERR_INVALID_ARG;

    /* Query xquic per-path metrics for SRTT */
    xqc_conn_stats_t xstats;
    memset(&xstats, 0, sizeof(xstats));
    if (c->engine && c->conn) xstats = xqc_conn_get_stats(c->engine, &c->conn->cid);

    int count = c->n_paths < max_paths ? c->n_paths : max_paths;
    for (int i = 0; i < count; i++) {
        const path_entry_t *p = &c->paths[i];
        out[i].struct_size = sizeof(out[i]);
        out[i].handle = p->handle;
        out[i].status = p->status;
        memcpy(out[i].name, p->name, sizeof(out[i].name));
        out[i].bytes_tx = p->bytes_tx;
        out[i].bytes_rx = p->bytes_rx;

        /* Map SRTT from xquic path metrics (us -> ms) */
        out[i].srtt_ms = 0;
        if (p->xquic_path_live) {
            const xqc_path_metrics_t *pm = xqc_find_path_metrics(&xstats, p->xqc_path_id);
            if (pm) out[i].srtt_ms = (int)(pm->path_srtt / 1000);
        }
    }
    *n_paths = count;
    free(xstats.paths_info);
    return MQVPN_OK;
}

int
mqvpn_client_get_interest(const mqvpn_client_t *c, mqvpn_interest_t *out)
{
    if (!c || !out) return MQVPN_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);

    int ms = (int)(c->next_wake_us / 1000);

    /* RECONNECTING / CONNECTING blocks below legitimately extend `ms`
     * when xquic hasn't requested a wake (`ms <= 0`): the tunnel is not
     * live in those states, there is no pacing to protect, and we MUST
     * wake at the reconnect / handshake-stall deadline or the FSM stalls.
     * The Recovery / Stability blocks further down are different — there
     * the tunnel is live and extending `ms` would starve BBR pacing. */

    /* During reconnect, wake up for the reconnect timer */
    if (c->state == MQVPN_STATE_RECONNECTING && c->reconnect_scheduled_us > 0) {
        uint64_t t = client_now_us(c);
        if (c->reconnect_scheduled_us > t) {
            int rms = (int)((c->reconnect_scheduled_us - t) / 1000);
            if (ms <= 0 || rms < ms) ms = rms;
        } else {
            ms = 1; /* reconnect is due */
        }
    }

    /* During CONNECTING, wake up no later than the handshake stall deadline
     * so tick_handshake_watchdog can fire even if no packets arrive (a dead
     * primary path produces zero recv events). */
    if (c->state == MQVPN_STATE_CONNECTING && c->handshake_started_us > 0) {
        uint64_t deadline =
            c->handshake_started_us + (uint64_t)HANDSHAKE_STALL_TIMEOUT_MS * 1000;
        uint64_t now_val = client_now_us(c);
        int hms = (deadline > now_val) ? (int)((deadline - now_val) / 1000) : 1;
        if (ms <= 0 || hms < ms) ms = hms;
    }

    /* Account for path recovery and stability timers */
    if (c->multipath_ready && c->state == MQVPN_STATE_ESTABLISHED) {
        uint64_t now_val = client_now_us(c);
        for (int i = 0; i < c->n_paths; i++) {
            const path_entry_t *p = &c->paths[i];
            /* Recovery timer — shorten `ms` only, never extend. Same shape as
             * Stability timer below. Unlike the RECONNECTING / CONNECTING
             * blocks above, the tunnel is live here and BBR pacing depends
             * on near-term ticks.
             *
             * recreate_after_us != 0 exactly in CREATE_WAIT (public PENDING)
             * and DEGRADED — both carry a retry deadline the tick must honor.
             * Gating on the public DEGRADED status alone left CREATE_WAIT
             * retries waiting for an unrelated timer. */
            if (p->recreate_after_us > 0) {
                if (p->recreate_after_us > now_val) {
                    int pms = (int)((p->recreate_after_us - now_val) / 1000);
                    if (ms > 0 && pms < ms) ms = pms;
                } else {
                    ms = 1;
                }
            }
            /* Stability timer — same shape as Recovery timer above. The
             * earlier `ms <= 0 || sms < ms` form was a latent bug: when
             * `path_stable_since_us` is set (PR3+ starts doing this on
             * VALIDATING -> ACTIVE), this block extended `ms` from 0 to
             * ~30000 (PATH_STABLE_THRESHOLD_US in ms), pinning the next
             * libevent tick 30 seconds out. Without periodic ticks, BBR
             * pacing stalled between I/O events, tanking multipath
             * throughput ~3-4x in the WLB aggregate bench. */
            if (p->path_stable_since_us > 0 && p->xquic_path_live) {
                uint64_t stable_at = p->path_stable_since_us + PATH_STABLE_THRESHOLD_US;
                if (stable_at > now_val) {
                    int sms = (int)((stable_at - now_val) / 1000);
                    if (ms > 0 && sms < ms) ms = sms;
                } else {
                    ms = 1;
                }
            }
        }
    }

#ifdef MQVPN_HYBRID_TCP_LANE_ENABLED
    /* H2: lwIP TCP-lane timer (retransmits, TIME-WAIT reaping). Shorten-only,
     * same shape as the Recovery / Stability blocks above: `ms <= 0` here
     * means xquic requested a SUB-MILLISECOND wake (next_wake_us/1000
     * truncates to 0), which the final `ms > 0 ? ms : 1` clamp below
     * services in 1ms — overwriting it with up to 250ms (TCP_TMR_INTERVAL)
     * would delay that imminent pacing wake, the exact BBR stall the
     * Stability comment above records. The lone-TCP-flow-while-xquic-quiet
     * case is covered by that same clamp (ms <= 0 always yields a 1ms
     * wake), so shorten-only is sufficient AND protects pacing. Returns -1
     * when no lwIP timer is pending, leaving `ms` untouched. */
    if (c->conn && c->conn->lwip_ctx) {
        int lwip_ms = mqvpn_lwip_next_timeout_ms(c->conn->lwip_ctx);
        if (lwip_ms >= 0 && ms > 0 && lwip_ms < ms) ms = lwip_ms;
    }
#endif

    out->next_timer_ms = ms > 0 ? ms : 1;
    out->tun_readable = (c->tun_active && !c->backpressure) ? 1 : 0;
    out->is_idle = (c->state != MQVPN_STATE_ESTABLISHED) ? 1 : 0;
    return MQVPN_OK;
}

/* ─── Server address setup (called by platform before connect) ─── */

int
mqvpn_client_set_server_addr(mqvpn_client_t *c, const struct sockaddr *addr,
                             socklen_t addrlen)
{
    if (!c || !addr) return MQVPN_ERR_INVALID_ARG;
    memcpy(&c->server_addr, addr, addrlen);
    c->server_addrlen = addrlen;
    return MQVPN_OK;
}
