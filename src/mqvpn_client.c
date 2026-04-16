/*
 * mqvpn_client.c — Client lifecycle, xquic engine, MASQUE CONNECT-IP
 *
 * Part of libmqvpn. No platform I/O — all I/O via callbacks.
 */

#include "libmqvpn.h"
#include "mqvpn_internal.h"

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
#  define EAGAIN       WSAEWOULDBLOCK
#  define EWOULDBLOCK  WSAEWOULDBLOCK
#  define EINTR        WSAEINTR
#  define errno        WSAGetLastError()
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
#include "icmp.h"

/* ─── Constants ─── */

#define PACKET_BUF_SIZE            65536
#define MASQUE_FRAME_BUF           (PACKET_BUF_SIZE + 16)
#define MAX_CAPSULE_BUF            65536
#define XQC_SNDQ_MAX_PKTS          16384
#define RECONNECT_BACKOFF_MAX_SEC  60
#define PTB_RATE_LIMIT             10
#define PATH_RECREATE_DELAY_US     (5ULL * 1000000)  /* 5 sec initial */
#define PATH_RECREATE_MAX_DELAY_US (60ULL * 1000000) /* 60 sec max backoff */
#define PATH_RECREATE_MAX_RETRIES  6                 /* max consecutive failures */
#define PATH_STABLE_THRESHOLD_US   (30ULL * 1000000) /* 30 sec to confirm stable */
#define SOCKET_BUF_SIZE            (7 * 1024 * 1024) /* 7 MiB socket buffer */

/* ─── Forward declarations ─── */

typedef struct cli_conn_s cli_conn_t;
typedef struct cli_stream_s cli_stream_t;

static int cli_start_connection(mqvpn_client_t *c);

/* ─── Internal types ─── */

/* Per-path entry (Level 1 — survives reconnect) */
typedef struct {
    mqvpn_path_handle_t handle;
    int fd;
    char name[16];
    mqvpn_path_status_t status;
    int active;
    struct sockaddr_storage local_addr;
    uint32_t local_addr_len;
    int64_t platform_net_id;
    uint32_t flags;
    uint64_t xqc_path_id;
    int in_use;
    int srtt_ms;
    uint64_t bytes_tx;
    uint64_t bytes_rx;
    uint64_t recreate_after_us;    /* 0 = no pending timer */
    int recreate_retries;          /* consecutive failures, reset after 30s stable */
    uint64_t path_stable_since_us; /* non-zero = awaiting stability confirmation */
} path_entry_t;

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
};

/* Per-stream state (Level 2) */
struct cli_stream_s {
    cli_conn_t *conn;
    xqc_h3_request_t *h3_request;
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
    int srtt_ms;

    /* Multipath (Level 1) */
    path_entry_t paths[MQVPN_MAX_PATHS];
    int n_paths;
    int64_t next_path_handle;
    int multipath_ready; /* 1 after cb_ready_to_create_path */

    /* Reconnect */
    int reconnect_attempts;
    uint64_t reconnect_scheduled_us;
    int shutting_down;

    /* Log correlation */
    uint32_t
        conn_id; /* monotonic connection ID for log correlation, bumped on each connect */

    /* Timer: next wake (from xquic set_event_timer) */
    uint64_t next_wake_us;

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

/* Injectable clock: use config clock_fn if set, else default now_us() */
static uint64_t
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
static void client_log(mqvpn_client_t *c, mqvpn_log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
#endif

static void
client_log(mqvpn_client_t *c, mqvpn_log_level_t level, const char *fmt, ...)
{
    if (!c->cbs.log) return;
    char buf[512];
    int off = snprintf(buf, sizeof(buf), "[conn:%u] ", c->conn_id);
    if (off < 0 || off >= (int)sizeof(buf)) off = 0;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf + off, sizeof(buf) - off, fmt, ap);
    va_end(ap);
    c->cbs.log(level, buf, c->user_ctx);
}

#define LOG_D(c, ...) client_log(c, MQVPN_LOG_DEBUG, __VA_ARGS__)
#define LOG_I(c, ...) client_log(c, MQVPN_LOG_INFO, __VA_ARGS__)
#define LOG_W(c, ...) client_log(c, MQVPN_LOG_WARN, __VA_ARGS__)
#define LOG_E(c, ...) client_log(c, MQVPN_LOG_ERROR, __VA_ARGS__)

static void
client_set_state(mqvpn_client_t *c, mqvpn_client_state_t new_state)
{
    mqvpn_client_state_t old = c->state;
    if (old == new_state) return;
    assert(mqvpn_state_transition_valid(old, new_state) &&
           "mqvpn_client: invalid state transition");
    c->state = new_state;
    if (c->cbs.state_changed) c->cbs.state_changed(old, new_state, c->user_ctx);
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
        if (c->paths[i].in_use && c->paths[i].xqc_path_id == xqc_path_id)
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

/* Get fd for xquic path_id (primary fd fallback) */
static int
get_fd_for_path(mqvpn_client_t *c, uint64_t xqc_path_id)
{
    path_entry_t *p = find_path_by_xqc_id(c, xqc_path_id);
    if (p) return p->fd;
    /* Fallback to primary path */
    if (c->n_paths > 0) return c->paths[0].fd;
    return -1;
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

    /* Map xquic levels (xqc_log_level_t): REPORT=0, FATAL=1, ERROR=2,
     * WARN=3, STATS=4, INFO=5, DEBUG=6 */
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

    char msg[512];
    snprintf(msg, sizeof(msg), "[xquic] %.*s", (int)size, (const char *)buf);
    c->cbs.log(ml, msg, c->user_ctx);
}

/* ─── UDP write callback (xquic → network) ─── */

static ssize_t
cb_write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer,
                socklen_t peerlen, void *conn_user_data)
{
    cli_conn_t *conn = (cli_conn_t *)conn_user_data;
    mqvpn_client_t *c = conn->client;
    int fd = (c->n_paths > 0) ? c->paths[0].fd : -1;
    if (fd < 0) return XQC_SOCKET_ERROR;

    ssize_t res;
    do {
        res = sendto(fd, buf, size, MSG_DONTWAIT, peer, peerlen);
    } while (res < 0 && errno == EINTR);
    if (res < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return XQC_SOCKET_EAGAIN;
        return XQC_SOCKET_ERROR;
    }
    c->bytes_tx += (uint64_t)res;
    if (c->n_paths > 0) c->paths[0].bytes_tx += (uint64_t)res;
    return res;
}

static ssize_t
cb_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
                   const struct sockaddr *peer, socklen_t peerlen, void *conn_user_data)
{
    cli_conn_t *conn = (cli_conn_t *)conn_user_data;
    mqvpn_client_t *c = conn->client;
    int fd = get_fd_for_path(c, path_id);
    if (fd < 0) return XQC_SOCKET_ERROR;

    ssize_t res;
    do {
        res = sendto(fd, buf, size, MSG_DONTWAIT, peer, peerlen);
    } while (res < 0 && errno == EINTR);
    if (res < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return XQC_SOCKET_EAGAIN;
        return XQC_SOCKET_ERROR;
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

static void cli_conn_destroy(mqvpn_client_t *c);

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
        /* Schedule reconnect */
        int base = c->config.reconnect_interval_sec;
        if (base <= 0) base = 5;
        int delay = base;
        for (int i = 0; i < c->reconnect_attempts && delay < RECONNECT_BACKOFF_MAX_SEC;
             i++)
            delay *= 2;
        if (delay > RECONNECT_BACKOFF_MAX_SEC) delay = RECONNECT_BACKOFF_MAX_SEC;
        c->reconnect_attempts++;
        c->reconnect_scheduled_us = client_now_us(c) + (uint64_t)delay * 1000000;
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

static int
cli_masque_start_tunnel(cli_conn_t *conn)
{
    mqvpn_client_t *c = conn->client;
    cli_stream_t *stream = calloc(1, sizeof(*stream));
    if (!stream) return -1;
    stream->conn = conn;

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
    int has_auth = (c->config.auth_key[0] != '\0');
    if (has_auth)
        snprintf(auth_value, sizeof(auth_value), "Bearer %s", c->config.auth_key);

    xqc_http_header_t hdrs[7] = {
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
    if (has_auth) {
        hdrs[hdr_count].name = (struct iovec){.iov_base = "authorization", .iov_len = 13};
        hdrs[hdr_count].value =
            (struct iovec){.iov_base = auth_value, .iov_len = strlen(auth_value)};
        hdrs[hdr_count].flags = 0;
        hdr_count++;
    }
    xqc_http_headers_t headers = {.headers = hdrs, .count = hdr_count, .capacity = 7};

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

static int
cb_request_close(xqc_h3_request_t *h3_request, void *user_data)
{
    (void)h3_request;
    cli_stream_t *stream = (cli_stream_t *)user_data;
    if (stream) {
        if (stream->conn) stream->conn->tunnel_ok = 0;
        free(stream->capsule_buf);
        free(stream);
    }
    return 0;
}

static int
cb_request_read(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag,
                void *user_data)
{
    cli_stream_t *stream = (cli_stream_t *)user_data;
    cli_conn_t *conn = stream->conn;
    mqvpn_client_t *c = conn->client;
    unsigned char fin = 0;

    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        xqc_http_headers_t *headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (headers) {
            for (int i = 0; i < (int)headers->count; i++) {
                xqc_http_header_t *h = &headers->headers[i];
                if (h->name.iov_len == 7 && memcmp(h->name.iov_base, ":status", 7) == 0 &&
                    h->value.iov_len == 3 && memcmp(h->value.iov_base, "200", 3) == 0) {
                    conn->tunnel_ok = 1;
                    LOG_I(c, "tunnel 200 OK");
                }
            }
        }
    }

    if (flag & XQC_REQ_NOTIFY_READ_BODY) {
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
            c->mtu = tun_mtu;

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

            /* Primary path is now active */
            if (c->n_paths > 0 && c->paths[0].active) {
                c->paths[0].status = MQVPN_PATH_ACTIVE;
                if (c->cbs.path_event)
                    c->cbs.path_event(c->paths[0].handle, MQVPN_PATH_ACTIVE, c->user_ctx);
            }

            client_set_state(c, MQVPN_STATE_TUNNEL_READY);
            LOG_D(c, "firing tunnel_config_ready callback");
            c->cbs.tunnel_config_ready(&info, c->user_ctx);
            c->reconnect_attempts = 0;
        }
    }
    return 0;
}

static int
cb_request_write(xqc_h3_request_t *h3_request, void *user_data)
{
    (void)h3_request;
    (void)user_data;
    return 0;
}

/* ─── Datagram callbacks ─── */

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

    uint8_t ip_ver = payload[0] >> 4;
    uint8_t fwd_pkt[PACKET_BUF_SIZE];

    if (ip_ver == 4) {
        if (payload_len < IPV4_MIN_HDR) {
            LOG_D(c, "dgram: IPv4 too short (%zu bytes)", payload_len);
            return;
        }
        memcpy(fwd_pkt, payload, payload_len);
        if (fwd_pkt[8] <= 1) {
            if (c->conn && c->conn->addr_assigned)
                mqvpn_icmp_send_v4(c->cbs.tun_output, c->user_ctx, c->conn->assigned_ip,
                                   11, 0, 0, payload, payload_len);
            return;
        }
        fwd_pkt[8]--;
        uint32_t sum = ((uint32_t)fwd_pkt[10] << 8 | fwd_pkt[11]) + 0x0100;
        sum = (sum & 0xFFFF) + (sum >> 16);
        fwd_pkt[10] = (sum >> 8) & 0xFF;
        fwd_pkt[11] = sum & 0xFF;
    } else if (ip_ver == 6) {
        if (payload_len < IPV6_MIN_HDR || !conn->addr6_assigned) {
            LOG_D(c, "dgram: IPv6 too short or no addr6 (%zu bytes)", payload_len);
            return;
        }
        memcpy(fwd_pkt, payload, payload_len);
        if (fwd_pkt[7] <= 1) {
            if (c->conn && c->conn->addr6_assigned)
                mqvpn_icmp_send_v6(c->cbs.tun_output, c->user_ctx, c->conn->assigned_ip6,
                                   3, 0, 0, payload, payload_len);
            return;
        }
        fwd_pkt[7]--;
    } else {
        LOG_D(c, "dgram: unknown IP version %d", ip_ver);
        return;
    }

    c->dgram_recv++;
    c->bytes_rx += payload_len;
    c->cbs.tun_output(fwd_pkt, payload_len, c->user_ctx);
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
            if (new_mtu != c->last_notified_mtu) {
                c->mtu = new_mtu;
                c->last_notified_mtu = new_mtu;
                if (c->cbs.mtu_updated) c->cbs.mtu_updated(new_mtu, c->user_ctx);
            }
        }
    }
}

/* ─── Multipath helpers ─── */

/* Create an xquic path for a secondary path entry and mark it ACTIVE. */
static void
client_activate_path(mqvpn_client_t *c, path_entry_t *p, int idx)
{
    uint64_t new_id = 0;
    xqc_int_t ret = xqc_conn_create_path(c->engine, &c->conn->cid, &new_id, 0);
    if (ret < 0) {
        LOG_W(c, "xqc_conn_create_path[%d]: %d", idx, ret);
        return;
    }
    p->xqc_path_id = new_id;
    p->in_use = 1;
    p->status = MQVPN_PATH_ACTIVE;
    LOG_I(c, "path[%d] activated: path_id=%" PRIu64 " iface=%s", idx, new_id, p->name);
    if (c->cbs.path_event) c->cbs.path_event(p->handle, MQVPN_PATH_ACTIVE, c->user_ctx);
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

    for (int i = 1; i < c->n_paths; i++) {
        path_entry_t *p = &c->paths[i];
        if (p->in_use || !p->active) continue;
        client_activate_path(c, p, i);
    }
}

static uint64_t
path_recreate_backoff(int retries)
{
    uint64_t delay = PATH_RECREATE_DELAY_US;
    for (int r = 1; r < retries && delay < PATH_RECREATE_MAX_DELAY_US; r++)
        delay *= 2;
    if (delay > PATH_RECREATE_MAX_DELAY_US) delay = PATH_RECREATE_MAX_DELAY_US;
    return delay;
}

static void
cb_path_removed(const xqc_cid_t *cid, uint64_t path_id, void *conn_user_data)
{
    (void)cid;
    cli_conn_t *conn = (cli_conn_t *)conn_user_data;
    mqvpn_client_t *c = conn->client;

    path_entry_t *p = find_path_by_xqc_id(c, path_id);
    if (p) {
        LOG_I(c, "path removed: path_id=%" PRIu64 " iface=%s", path_id, p->name);
        p->in_use = 0;
        p->xqc_path_id = 0;
        p->path_stable_since_us = 0; /* validation failed before stability */

        if (p->active) {
            /* Increment first, then check against max.  Uses >= for
             * consistency with the tick() recovery path. */
            p->recreate_retries++;

            if (p->recreate_retries >= PATH_RECREATE_MAX_RETRIES) {
                p->status = MQVPN_PATH_CLOSED;
                p->recreate_after_us = 0;
                LOG_W(c,
                      "path closed: %s (max retries %d exhausted, "
                      "platform can still recover)",
                      p->name, PATH_RECREATE_MAX_RETRIES);
            } else {
                p->status = MQVPN_PATH_DEGRADED;
                uint64_t delay = path_recreate_backoff(p->recreate_retries);
                p->recreate_after_us = client_now_us(c) + delay;
                LOG_I(c, "path degraded: %s (retry %d/%d in %ds)", p->name,
                      p->recreate_retries, PATH_RECREATE_MAX_RETRIES,
                      (int)(delay / 1000000));
            }
        } else {
            p->status = MQVPN_PATH_CLOSED;
        }

        if (c->cbs.path_event) c->cbs.path_event(p->handle, p->status, c->user_ctx);
    }
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

    free(conn);
    c->conn = NULL;
}

/* ─── Start a QUIC/H3 connection ─── */

static int
cli_start_connection(mqvpn_client_t *c)
{
    c->conn_id++;
    cli_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) return -1;
    conn->client = c;

    int multipath = c->config.multipath ? 1 : 0;

    xqc_conn_settings_t cs;
    memset(&cs, 0, sizeof(cs));
    cs.max_datagram_frame_size = 65535;
    cs.proto_version = XQC_VERSION_V1;
    cs.enable_multipath = multipath;
    cs.ping_on = 1;
    cs.mp_ping_on = multipath;
    cs.pacing_on = 1;
    cs.max_pkt_out_size = 1400;
    cs.cong_ctrl_callback = xqc_bbr2_cb;
    cs.cc_params.cc_optimization_flags =
        XQC_BBR2_FLAG_RTTVAR_COMPENSATION | XQC_BBR2_FLAG_FAST_CONVERGENCE;
    cs.sndq_packets_used_max = XQC_SNDQ_MAX_PKTS;
    cs.so_sndbuf = 8 * 1024 * 1024;
    cs.idle_time_out = 120000;
    cs.init_idle_time_out = 10000;
    if (c->config.scheduler == MQVPN_SCHED_WLB)
        cs.scheduler_callback = xqc_wlb_scheduler_cb;
    else
        cs.scheduler_callback = xqc_minrtt_scheduler_cb;

    xqc_conn_ssl_config_t ssl_cfg;
    memset(&ssl_cfg, 0, sizeof(ssl_cfg));
    ssl_cfg.cert_verify_flag = c->config.insecure ? XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED
                                                  : XQC_TLS_CERT_FLAG_NEED_VERIFY;

    const xqc_cid_t *cid =
        xqc_h3_connect(c->engine, &cs, NULL, 0, c->config.server_host, 0, &ssl_cfg,
                       (struct sockaddr *)&c->server_addr, c->server_addrlen, conn);
    if (!cid) {
        LOG_E(c, "xqc_h3_connect failed");
        goto cleanup;
    }

    /* cid may be misaligned inside xquic's internal structures */
    memcpy(&conn->cid, (const void *)cid, sizeof(conn->cid));
    if (conn->h3_conn) xqc_h3_ext_datagram_set_user_data(conn->h3_conn, conn);

    /* Mark primary path */
    if (c->n_paths > 0) {
        c->paths[0].xqc_path_id = 0;
        c->paths[0].in_use = 1;
    }

    c->conn = conn; /* ownership transfer — cleanup won't free */
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
    /* xqc_log_level_t: REPORT=0, FATAL=1, ERROR=2, WARN=3, STATS=4, INFO=5, DEBUG=6 */
    switch (level) {
    case MQVPN_LOG_DEBUG: return XQC_LOG_DEBUG;
    case MQVPN_LOG_INFO: return XQC_LOG_INFO;
    case MQVPN_LOG_WARN: return XQC_LOG_WARN;
    case MQVPN_LOG_ERROR: return XQC_LOG_ERROR;
    default: return XQC_LOG_INFO;
    }
}

mqvpn_client_t *
mqvpn_client_new(const mqvpn_config_t *cfg, const mqvpn_client_callbacks_t *cbs,
                 void *user_ctx)
{
    if (!cfg || !cbs) return NULL;
    if (cbs->abi_version != MQVPN_CALLBACKS_ABI_VERSION) return NULL;
    if (!cbs->tun_output || !cbs->tunnel_config_ready) return NULL;

    mqvpn_client_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;

    memcpy(&c->config, cfg, sizeof(*cfg));
    memcpy(&c->cbs, cbs, sizeof(*cbs));
    c->user_ctx = user_ctx;
    /* caller guarantees lifetime exceeds this object */ // lgtm[cpp/stack-address-escape]
    c->state = MQVPN_STATE_IDLE;
    c->next_path_handle = 1;
    c->ptb_tokens = PTB_RATE_LIMIT;

    /* ── xquic engine setup ── */
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

    /* Inject custom clock into xquic engine — ensures xquic's internal
     * timestamps match recv_time passed to xqc_engine_packet_process().
     * Critical for Android: CLOCK_BOOTTIME vs gettimeofday mismatch
     * causes immediate idle timeout without this. */
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

    /* Map log level */
    int xqc_log_level = map_log_level_to_xquic(cfg->log_level);

    xqc_config_t xconfig;
    if (xqc_engine_get_default_config(&xconfig, XQC_ENGINE_CLIENT) < 0) goto cleanup;
    xconfig.cfg_log_level = (xqc_log_level_t)xqc_log_level;

    c->engine = xqc_engine_create(XQC_ENGINE_CLIENT, &xconfig, &engine_ssl, &engine_cbs,
                                  &tcbs, c);
    if (!c->engine) goto cleanup;

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
    if (xqc_h3_ctx_init(c->engine, &h3_cbs) != XQC_OK) goto cleanup;

    xqc_h3_conn_settings_t h3s = {
        .max_field_section_size = 32 * 1024,
        .qpack_blocked_streams = 64,
        .qpack_enc_max_table_capacity = 16 * 1024,
        .qpack_dec_max_table_capacity = 16 * 1024,
        .enable_connect_protocol = 1,
        .h3_datagram = 1,
    };
    xqc_h3_engine_set_local_settings(c->engine, &h3s);

    return c;

cleanup:
    if (c->engine) {
        xqc_engine_destroy(c->engine);
        c->engine = NULL;
    }
    free(c);
    return NULL;
}

void
mqvpn_client_destroy(mqvpn_client_t *client)
{
    if (!client) return;

    if (client->engine) {
        xqc_engine_destroy(client->engine);
        client->engine = NULL;
    }
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

mqvpn_path_handle_t
mqvpn_client_add_path_fd(mqvpn_client_t *c, int fd, const mqvpn_path_desc_t *desc)
{
    if (!c || fd < 0) return -1;
    ASSERT_TICK_THREAD(c);

    /* Reuse a CLOSED slot if available, otherwise append */
    int idx = -1;
    for (int i = 0; i < c->n_paths; i++) {
        if (c->paths[i].status == MQVPN_PATH_CLOSED && !c->paths[i].active) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        if (c->n_paths >= MQVPN_MAX_PATHS) return -1;
        idx = c->n_paths++;
    }

    path_entry_t *p = &c->paths[idx];
    memset(p, 0, sizeof(*p));
    p->handle = c->next_path_handle++;
    p->fd = fd;

    /* Ensure adequate socket buffers for high-throughput UDP (ref: WireGuard) */
    int bufsize = SOCKET_BUF_SIZE;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
#ifdef SO_SNDBUFFORCE
    setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &bufsize, sizeof(bufsize));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &bufsize, sizeof(bufsize));
#endif

    p->status = MQVPN_PATH_PENDING;
    p->active = 1;

    if (desc) {
        memcpy(p->name, desc->iface, sizeof(p->name));
        p->name[sizeof(p->name) - 1] = '\0';
        if (desc->local_addr_len > 0 && desc->local_addr_len <= sizeof(p->local_addr))
            memcpy(&p->local_addr, desc->local_addr, desc->local_addr_len);
        p->local_addr_len = desc->local_addr_len;
        p->platform_net_id = desc->platform_net_id;
        p->flags = desc->flags;
    }

    /* If multipath is already negotiated, activate immediately */
    if (c->multipath_ready && c->config.multipath && c->conn) {
        client_activate_path(c, p, idx);
    }

    return p->handle;
}

int
mqvpn_client_remove_path(mqvpn_client_t *c, mqvpn_path_handle_t path)
{
    if (!c) return MQVPN_ERR_INVALID_ARG;
    ASSERT_TICK_THREAD(c);

    path_entry_t *p = find_path_by_handle(c, path);
    if (!p) return MQVPN_ERR_INVALID_ARG;

    p->status = MQVPN_PATH_CLOSED;
    p->active = 0;
    p->recreate_after_us = 0;
    p->recreate_retries = 0;
    p->path_stable_since_us = 0;
    if (p->in_use && c->engine && c->conn)
        xqc_conn_close_path(c->engine, &c->conn->cid, p->xqc_path_id);
    return MQVPN_OK;
}

int
mqvpn_client_drop_path(mqvpn_client_t *c, mqvpn_path_handle_t path)
{
    if (!c) return MQVPN_ERR_INVALID_ARG;
    ASSERT_TICK_THREAD(c);

    path_entry_t *p = find_path_by_handle(c, path);
    if (!p) return MQVPN_ERR_INVALID_ARG;

    /* Free the slot but do NOT call xqc_conn_close_path().
     * xquic will detect the dead fd via sendto() errors and remove
     * the path through its normal PTO-based failure detection. */
    p->status = MQVPN_PATH_CLOSED;
    p->active = 0;
    p->recreate_after_us = 0;
    p->recreate_retries = 0;
    p->path_stable_since_us = 0;
    return MQVPN_OK;
}

/* ─── Path re-activation (platform-triggered) ─── */

int
mqvpn_client_reactivate_path(mqvpn_client_t *c, mqvpn_path_handle_t handle)
{
    if (!c) return MQVPN_ERR_INVALID_ARG;
    ASSERT_TICK_THREAD(c);

    if (c->state != MQVPN_STATE_ESTABLISHED || !c->multipath_ready)
        return MQVPN_ERR_INVALID_STATE;

    /* Find path by handle */
    int idx = -1;
    path_entry_t *p = NULL;
    for (int i = 0; i < c->n_paths; i++) {
        if (c->paths[i].handle == handle) {
            idx = i;
            p = &c->paths[i];
            break;
        }
    }
    if (!p) return MQVPN_ERR_INVALID_ARG;

    if (p->in_use) return MQVPN_ERR_INVALID_STATE;
    if (!p->active) return MQVPN_ERR_INVALID_STATE;
    if (p->status != MQVPN_PATH_DEGRADED && p->status != MQVPN_PATH_CLOSED)
        return MQVPN_ERR_INVALID_STATE;

    LOG_I(c, "platform reactivating path: %s (was %s)", p->name,
          p->status == MQVPN_PATH_DEGRADED ? "degraded" : "closed");

    client_activate_path(c, p, idx);
    if (!p->in_use) return MQVPN_ERR_ENGINE;

    /* Success: cancel library timer, start stability timer */
    p->recreate_after_us = 0;
    p->path_stable_since_us = client_now_us(c);
    return MQVPN_OK;
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

int
mqvpn_client_on_tun_packet(mqvpn_client_t *c, const uint8_t *pkt, size_t len)
{
    if (!c || !pkt || len == 0) return MQVPN_ERR_INVALID_ARG;
    ASSERT_TICK_THREAD(c);

    cli_conn_t *conn = c->conn;
    if (!conn || !conn->tunnel_ok) return MQVPN_ERR_INVALID_ARG;

    if (c->backpressure) return MQVPN_ERR_AGAIN;

    uint8_t ip_ver = pkt[0] >> 4;
    if (ip_ver == 4) {
        if (len < IPV4_MIN_HDR) return MQVPN_ERR_INVALID_ARG;
        if (conn->addr_assigned && memcmp(pkt + 12, conn->assigned_ip, 4) != 0) {
            LOG_D(c, "tun drop: IPv4 src mismatch (len=%zu)", len);
            return MQVPN_OK; /* silently drop: src mismatch */
        }
    } else if (ip_ver == 6) {
        if (len < IPV6_MIN_HDR || !conn->addr6_assigned) {
            LOG_D(c, "tun drop: IPv6 too short or no addr6 (len=%zu)", len);
            return MQVPN_OK;
        }
        if (memcmp(pkt + 8, conn->assigned_ip6, 16) != 0) {
            LOG_D(c, "tun drop: IPv6 src mismatch (len=%zu)", len);
            return MQVPN_OK;
        }
    } else {
        LOG_D(c, "tun drop: unknown IP version %d (len=%zu)", ip_ver, len);
        return MQVPN_OK;
    }

    /* ICMP PTB if packet exceeds tunnel capacity */
    if (conn->dgram_mss > 0) {
        size_t udp_mss =
            xqc_h3_ext_masque_udp_mss(conn->dgram_mss, conn->masque_stream_id);
        if (len > udp_mss) {
            if (ip_ver == 4) {
                if (conn->addr_assigned && ptb_rate_allow(c))
                    mqvpn_icmp_send_v4(
                        c->cbs.tun_output, c->user_ctx, c->conn->assigned_ip, 3, 4,
                        (udp_mss > 0xFFFF) ? 0xFFFF : (uint16_t)udp_mss, pkt, len);
            } else {
                if (conn->addr6_assigned && ptb_rate_allow(c))
                    mqvpn_icmp_send_v6(c->cbs.tun_output, c->user_ctx,
                                       c->conn->assigned_ip6, 2, 0, (uint32_t)udp_mss,
                                       pkt, len);
            }
            return MQVPN_OK;
        }
    }

    /* MASQUE frame and send */
    uint8_t frame_buf[MASQUE_FRAME_BUF];
    size_t frame_written = 0;
    xqc_int_t xret = xqc_h3_ext_masque_frame_udp(
        frame_buf, sizeof(frame_buf), &frame_written, conn->masque_stream_id, pkt, len);
    if (xret != XQC_OK) {
        LOG_W(c, "masque frame failed: xret=%d", xret);
        return MQVPN_ERR_ENGINE;
    }

    uint64_t dgram_id;
    uint32_t fh = flow_hash_pkt(pkt, (int)len);
    xqc_conn_set_dgram_flow_hash(xqc_h3_conn_get_xqc_conn(conn->h3_conn), fh);
    xret = xqc_h3_ext_datagram_send(conn->h3_conn, frame_buf, frame_written, &dgram_id,
                                    XQC_DATA_QOS_HIGH);

    if (xret == -XQC_EAGAIN) {
        c->backpressure = 1;
        c->dgram_sent++;
        return MQVPN_ERR_AGAIN;
    }
    if (xret < 0) {
        LOG_W(c, "datagram send failed: xret=%d", xret);
        return MQVPN_ERR_ENGINE;
    }

    c->dgram_sent++;
    return MQVPN_OK;
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

/* ─── Tick ─── */

int
mqvpn_client_tick(mqvpn_client_t *c)
{
    if (!c) return MQVPN_ERR_INVALID_ARG;
    ASSERT_TICK_THREAD(c);

    if (c->engine) xqc_engine_main_logic(c->engine);

    /* Path recovery timer (exponential backoff) */
    if (c->multipath_ready && c->state == MQVPN_STATE_ESTABLISHED) {
        uint64_t now = client_now_us(c);
        for (int i = 0; i < c->n_paths; i++) {
            path_entry_t *p = &c->paths[i];

            /* Recovery timer: attempt re-creation for DEGRADED paths */
            if (p->status == MQVPN_PATH_DEGRADED && p->recreate_after_us > 0 &&
                now >= p->recreate_after_us) {
                p->recreate_after_us = 0;
                LOG_I(c, "path recovery attempt: %s (retry %d/%d)", p->name,
                      p->recreate_retries, PATH_RECREATE_MAX_RETRIES);
                client_activate_path(c, p, i);

                if (p->in_use) {
                    /* Create succeeded — start stability timer.
                     * xquic validates async. If fail, cb_path_removed fires. */
                    p->path_stable_since_us = now;
                } else {
                    /* xqc_conn_create_path() failed synchronously */
                    p->recreate_retries++;
                    if (p->recreate_retries >= PATH_RECREATE_MAX_RETRIES) {
                        p->status = MQVPN_PATH_CLOSED;
                        p->recreate_after_us = 0;
                        LOG_W(c, "path closed: %s (retries exhausted)", p->name);
                        if (c->cbs.path_event)
                            c->cbs.path_event(p->handle, MQVPN_PATH_CLOSED, c->user_ctx);
                    } else {
                        uint64_t backoff = path_recreate_backoff(p->recreate_retries);
                        p->recreate_after_us = now + backoff;
                        LOG_D(c, "path %s: scheduling retry in %ds", p->name,
                              (int)(backoff / 1000000));
                    }
                }
            }

            /* Stability confirmation: reset retry budget after 30s stable */
            if (p->path_stable_since_us > 0 && p->in_use &&
                now - p->path_stable_since_us >= PATH_STABLE_THRESHOLD_US) {
                LOG_I(c, "path %s: stable for 30s, resetting retry budget", p->name);
                p->recreate_retries = 0;
                p->path_stable_since_us = 0;
            }
        }
    }

    /* Reconnect timer check */
    if (c->state == MQVPN_STATE_RECONNECTING && c->reconnect_scheduled_us > 0) {
        uint64_t t = client_now_us(c);
        if (t >= c->reconnect_scheduled_us) {
            c->reconnect_scheduled_us = 0;
            LOG_I(c, "attempting reconnection (attempt %d)...", c->reconnect_attempts);

            /* Reset path state for fresh connection */
            c->multipath_ready = 0;
            for (int i = 0; i < c->n_paths; i++) {
                c->paths[i].in_use = 0;
                c->paths[i].xqc_path_id = 0;
                c->paths[i].recreate_after_us = 0;
                c->paths[i].recreate_retries = 0;
                c->paths[i].path_stable_since_us = 0;
            }

            if (cli_start_connection(c) < 0) {
                /* Reschedule */
                int base = c->config.reconnect_interval_sec;
                if (base <= 0) base = 5;
                int delay = base;
                for (int i = 0;
                     i < c->reconnect_attempts && delay < RECONNECT_BACKOFF_MAX_SEC; i++)
                    delay *= 2;
                if (delay > RECONNECT_BACKOFF_MAX_SEC) delay = RECONNECT_BACKOFF_MAX_SEC;
                c->reconnect_attempts++;
                c->reconnect_scheduled_us = client_now_us(c) + (uint64_t)delay * 1000000;
            } else {
                client_set_state(c, MQVPN_STATE_CONNECTING);
                xqc_engine_main_logic(c->engine);
            }
        }
    }

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

    /* Get connection-level SRTT from xquic (μs → ms) */
    if (c->engine && c->conn) {
        xqc_conn_stats_t xs = xqc_conn_get_stats(c->engine, &c->conn->cid);
        out->srtt_ms = (int)(xs.srtt / 1000);
    }
    return MQVPN_OK;
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

        /* Map SRTT from xquic path metrics (μs → ms) */
        out[i].srtt_ms = 0;
        if (p->in_use) {
            for (int j = 0; j < XQC_MAX_PATHS_COUNT; j++) {
                if (xstats.paths_info[j].path_id == p->xqc_path_id) {
                    out[i].srtt_ms = (int)(xstats.paths_info[j].path_srtt / 1000);
                    break;
                }
            }
        }
    }
    *n_paths = count;
    return MQVPN_OK;
}

int
mqvpn_client_get_interest(const mqvpn_client_t *c, mqvpn_interest_t *out)
{
    if (!c || !out) return MQVPN_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);

    int ms = (int)(c->next_wake_us / 1000);

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

    /* Account for path recovery and stability timers */
    if (c->multipath_ready && c->state == MQVPN_STATE_ESTABLISHED) {
        uint64_t now_val = client_now_us(c);
        for (int i = 0; i < c->n_paths; i++) {
            const path_entry_t *p = &c->paths[i];
            /* Recovery timer */
            if (p->status == MQVPN_PATH_DEGRADED && p->recreate_after_us > 0) {
                if (p->recreate_after_us > now_val) {
                    int pms = (int)((p->recreate_after_us - now_val) / 1000);
                    if (ms <= 0 || pms < ms) ms = pms;
                } else {
                    ms = 1;
                }
            }
            /* Stability timer */
            if (p->path_stable_since_us > 0 && p->in_use) {
                uint64_t stable_at = p->path_stable_since_us + PATH_STABLE_THRESHOLD_US;
                if (stable_at > now_val) {
                    int sms = (int)((stable_at - now_val) / 1000);
                    if (ms <= 0 || sms < ms) ms = sms;
                } else {
                    ms = 1;
                }
            }
        }
    }

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
