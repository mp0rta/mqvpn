/*
 * mqvpn_server.c — Server lifecycle, xquic engine, MASQUE CONNECT-IP (server)
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
#  define EAGAIN      WSAEWOULDBLOCK
#  define EWOULDBLOCK WSAEWOULDBLOCK
#  define EINTR       WSAEINTR
#  define errno       WSAGetLastError()
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

#include "addr_pool.h"
#include "auth.h"
#include "flow_sched.h"

/* ─── Constants ─── */

#define PACKET_BUF_SIZE   65536
#define MASQUE_FRAME_BUF  (PACKET_BUF_SIZE + 16)
#define MAX_CAPSULE_BUF   65536
#define XQC_SNDQ_MAX_PKTS 16384
#define PTB_RATE_LIMIT    10

/* ─── Forward declarations ─── */

typedef struct svr_conn_s svr_conn_t;
typedef struct svr_stream_s svr_stream_t;

/* ─── Internal types ─── */

struct svr_conn_s {
    mqvpn_server_t *server;
    xqc_h3_conn_t *h3_conn;
    xqc_cid_t cid;
    struct sockaddr_in6 peer_addr;
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
};

struct svr_stream_s {
    svr_conn_t *conn;
    xqc_h3_request_t *h3_request;
    int header_sent;
    uint8_t *capsule_buf;
    size_t capsule_len;
    size_t capsule_cap;
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

    /* ICMP PTB rate limit */
    int ptb_tokens;
    int64_t ptb_refill_ms;

    /* Stats */
    uint64_t bytes_tx;
    uint64_t bytes_rx;

    int started;

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

static void
server_log(mqvpn_server_t *s, mqvpn_log_level_t level, const char *fmt, ...)
{
    if (!s->cbs.log) return;
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
          " standby_bytes=%" PRIu64 " mp_state=%d",
          tag, st.send_count, st.recv_count, st.lost_count, st.lost_dgram_count,
          (double)st.srtt / 1000.0, (double)st.min_rtt / 1000.0, st.inflight_bytes,
          st.total_app_bytes, st.standby_path_app_bytes, st.mp_state);
}

/* ─── ICMP PTB rate limiter ─── */

static int
ptb_rate_allow(mqvpn_server_t *s)
{
    int64_t ms = now_ms_mono();
    if (ms - s->ptb_refill_ms >= 1000) {
        s->ptb_tokens = PTB_RATE_LIMIT;
        s->ptb_refill_ms = ms;
    }
    if (s->ptb_tokens > 0) {
        s->ptb_tokens--;
        return 1;
    }
    return 0;
}

/* ─── ICMP Packet Too Big (IPv4) ─── */

static void
send_icmpv4_ptb(mqvpn_server_t *s, const uint8_t *orig, size_t orig_len,
                size_t tunnel_mtu)
{
    if (orig_len < 20) return;
    if (!ptb_rate_allow(s)) return;

    struct in_addr srv_addr;
    mqvpn_addr_pool_server_addr(&s->pool, &srv_addr);

    size_t ihl = (orig[0] & 0x0F) * 4;
    if (ihl < 20 || ihl > orig_len) return;
    size_t icmp_data_len = ihl + 8;
    if (icmp_data_len > orig_len) icmp_data_len = orig_len;
    size_t total = 20 + 8 + icmp_data_len;
    uint8_t pkt[128];
    if (total > sizeof(pkt)) return;
    memset(pkt, 0, total);

    pkt[0] = 0x45;
    pkt[1] = 0xC0;
    pkt[2] = (total >> 8) & 0xFF;
    pkt[3] = total & 0xFF;
    pkt[8] = 64;
    pkt[9] = 1;
    memcpy(pkt + 12, &srv_addr.s_addr, 4);
    memcpy(pkt + 16, orig + 12, 4);

    uint32_t cksum = 0;
    for (int i = 0; i < 20; i += 2)
        cksum += ((uint32_t)pkt[i] << 8) | pkt[i + 1];
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t ip_ck = ~(uint16_t)cksum;
    pkt[10] = ip_ck >> 8;
    pkt[11] = ip_ck & 0xFF;

    uint8_t *icmp = pkt + 20;
    icmp[0] = 3;
    icmp[1] = 4;
    uint16_t m16 = (tunnel_mtu > 0xFFFF) ? 0xFFFF : (uint16_t)tunnel_mtu;
    icmp[6] = m16 >> 8;
    icmp[7] = m16 & 0xFF;
    memcpy(icmp + 8, orig, icmp_data_len);

    size_t icmp_total = 8 + icmp_data_len;
    cksum = 0;
    for (size_t i = 0; i < icmp_total; i += 2) {
        cksum += ((uint32_t)icmp[i] << 8);
        if (i + 1 < icmp_total) cksum += icmp[i + 1];
    }
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t ic = ~(uint16_t)cksum;
    icmp[2] = ic >> 8;
    icmp[3] = ic & 0xFF;

    s->cbs.tun_output(pkt, total, s->user_ctx);
    LOG_D(s, "sent ICMP Fragmentation Needed (mtu=%zu) to TUN", tunnel_mtu);
}

/* ─── ICMPv6 Packet Too Big ─── */

static void
send_icmpv6_ptb(mqvpn_server_t *s, const uint8_t *orig, size_t orig_len,
                size_t tunnel_mtu)
{
    if (orig_len < 40 || !s->pool.has_v6) return;
    if (!ptb_rate_allow(s)) return;

    struct in6_addr srv_addr6;
    mqvpn_addr_pool_server_addr6(&s->pool, &srv_addr6);

    size_t icmpv6_data_len = orig_len;
    if (40 + 8 + icmpv6_data_len > 1280) icmpv6_data_len = 1280 - 40 - 8;
    size_t icmpv6_len = 8 + icmpv6_data_len;
    size_t total = 40 + icmpv6_len;
    uint8_t pkt[1280];
    memset(pkt, 0, total);

    pkt[0] = 0x60;
    pkt[4] = (icmpv6_len >> 8) & 0xFF;
    pkt[5] = icmpv6_len & 0xFF;
    pkt[6] = 58;
    pkt[7] = 64;
    memcpy(pkt + 8, &srv_addr6, 16);
    memcpy(pkt + 24, orig + 8, 16);

    uint8_t *icmp = pkt + 40;
    icmp[0] = 2;
    icmp[1] = 0;
    uint32_t m32 = (uint32_t)tunnel_mtu;
    icmp[4] = (m32 >> 24) & 0xFF;
    icmp[5] = (m32 >> 16) & 0xFF;
    icmp[6] = (m32 >> 8) & 0xFF;
    icmp[7] = m32 & 0xFF;
    memcpy(icmp + 8, orig, icmpv6_data_len);

    uint32_t cksum = 0;
    for (int i = 0; i < 16; i += 2)
        cksum += ((uint32_t)pkt[8 + i] << 8) | pkt[8 + i + 1];
    for (int i = 0; i < 16; i += 2)
        cksum += ((uint32_t)pkt[24 + i] << 8) | pkt[24 + i + 1];
    cksum += (uint32_t)(icmpv6_len >> 16);
    cksum += (uint32_t)(icmpv6_len & 0xFFFF);
    cksum += 58;
    for (size_t i = 0; i < icmpv6_len; i += 2) {
        cksum += ((uint32_t)icmp[i] << 8);
        if (i + 1 < icmpv6_len) cksum += icmp[i + 1];
    }
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t ic = ~(uint16_t)cksum;
    icmp[2] = ic >> 8;
    icmp[3] = ic & 0xFF;

    s->cbs.tun_output(pkt, total, s->user_ctx);
    LOG_D(s, "sent ICMPv6 Packet Too Big (mtu=%zu) to TUN", tunnel_mtu);
}

/* ─── ICMP Destination Unreachable (IPv4) — sent to TUN ─── */

static void
send_icmpv4_dest_unreach(mqvpn_server_t *s, const uint8_t *orig, size_t orig_len)
{
    if (orig_len < 20) return;
    if (!ptb_rate_allow(s)) return;

    struct in_addr srv_addr;
    mqvpn_addr_pool_server_addr(&s->pool, &srv_addr);

    size_t ihl = (orig[0] & 0x0F) * 4;
    if (ihl < 20 || ihl > orig_len) return;
    size_t icmp_data_len = ihl + 8;
    if (icmp_data_len > orig_len) icmp_data_len = orig_len;
    size_t total = 20 + 8 + icmp_data_len;
    uint8_t pkt[128];
    if (total > sizeof(pkt)) return;
    memset(pkt, 0, total);

    /* IPv4 header */
    pkt[0] = 0x45;
    pkt[1] = 0xC0;
    pkt[2] = (total >> 8) & 0xFF;
    pkt[3] = total & 0xFF;
    pkt[8] = 64;
    pkt[9] = 1;                            /* TTL=64, proto=ICMP */
    memcpy(pkt + 12, &srv_addr.s_addr, 4); /* src = server */
    memcpy(pkt + 16, orig + 12, 4);        /* dst = original src */

    uint32_t cksum = 0;
    for (int i = 0; i < 20; i += 2)
        cksum += ((uint32_t)pkt[i] << 8) | pkt[i + 1];
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t ip_ck = ~(uint16_t)cksum;
    pkt[10] = ip_ck >> 8;
    pkt[11] = ip_ck & 0xFF;

    /* ICMP: Type=3 (Dest Unreachable), Code=1 (Host Unreachable) */
    uint8_t *icmp = pkt + 20;
    icmp[0] = 3;
    icmp[1] = 1;
    memcpy(icmp + 8, orig, icmp_data_len);

    size_t icmp_total = 8 + icmp_data_len;
    cksum = 0;
    for (size_t i = 0; i < icmp_total; i += 2) {
        cksum += ((uint32_t)icmp[i] << 8);
        if (i + 1 < icmp_total) cksum += icmp[i + 1];
    }
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t ic = ~(uint16_t)cksum;
    icmp[2] = ic >> 8;
    icmp[3] = ic & 0xFF;

    s->cbs.tun_output(pkt, total, s->user_ctx);
    LOG_D(s, "sent ICMP Dest Unreachable to TUN");
}

/* ─── ICMPv6 Destination Unreachable — sent to TUN ─── */

static void
send_icmpv6_dest_unreach(mqvpn_server_t *s, const uint8_t *orig, size_t orig_len)
{
    if (orig_len < 40 || !s->pool.has_v6) return;
    if (!ptb_rate_allow(s)) return;

    struct in6_addr srv_addr6;
    mqvpn_addr_pool_server_addr6(&s->pool, &srv_addr6);

    size_t icmpv6_data_len = orig_len;
    if (40 + 8 + icmpv6_data_len > 1280) icmpv6_data_len = 1280 - 40 - 8;
    size_t icmpv6_len = 8 + icmpv6_data_len;
    size_t total = 40 + icmpv6_len;
    uint8_t pkt[1280];
    memset(pkt, 0, total);

    /* IPv6 header */
    pkt[0] = 0x60;
    pkt[4] = (icmpv6_len >> 8) & 0xFF;
    pkt[5] = icmpv6_len & 0xFF;
    pkt[6] = 58;
    pkt[7] = 64;                     /* next=ICMPv6, hop=64 */
    memcpy(pkt + 8, &srv_addr6, 16); /* src = server */
    memcpy(pkt + 24, orig + 8, 16);  /* dst = original src */

    /* ICMPv6: Type=1 (Dest Unreachable), Code=3 (Address Unreachable) */
    uint8_t *icmp = pkt + 40;
    icmp[0] = 1;
    icmp[1] = 3;
    memcpy(icmp + 8, orig, icmpv6_data_len);

    /* ICMPv6 checksum (pseudo-header + ICMPv6) */
    uint32_t cksum = 0;
    for (int i = 0; i < 16; i += 2)
        cksum += ((uint32_t)pkt[8 + i] << 8) | pkt[8 + i + 1];
    for (int i = 0; i < 16; i += 2)
        cksum += ((uint32_t)pkt[24 + i] << 8) | pkt[24 + i + 1];
    cksum += (uint32_t)(icmpv6_len >> 16);
    cksum += (uint32_t)(icmpv6_len & 0xFFFF);
    cksum += 58;
    for (size_t i = 0; i < icmpv6_len; i += 2) {
        cksum += ((uint32_t)icmp[i] << 8);
        if (i + 1 < icmpv6_len) cksum += icmp[i + 1];
    }
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t ic = ~(uint16_t)cksum;
    icmp[2] = ic >> 8;
    icmp[3] = ic & 0xFF;

    s->cbs.tun_output(pkt, total, s->user_ctx);
    LOG_D(s, "sent ICMPv6 Dest Unreachable to TUN");
}

/* ─── ICMP Time Exceeded (IPv4) — sent via tunnel to client ─── */

static void
send_icmpv4_time_exceeded(mqvpn_server_t *s, svr_conn_t *conn, const uint8_t *orig,
                          size_t orig_len)
{
    if (orig_len < 20) return;
    if (!ptb_rate_allow(s)) return;

    struct in_addr srv_addr;
    mqvpn_addr_pool_server_addr(&s->pool, &srv_addr);

    size_t ihl = (orig[0] & 0x0F) * 4;
    if (ihl < 20 || ihl > orig_len) return;
    size_t icmp_data_len = ihl + 8;
    if (icmp_data_len > orig_len) icmp_data_len = orig_len;
    size_t total = 20 + 8 + icmp_data_len;
    uint8_t pkt[128];
    if (total > sizeof(pkt)) return;
    memset(pkt, 0, total);

    pkt[0] = 0x45;
    pkt[1] = 0xC0;
    pkt[2] = (total >> 8) & 0xFF;
    pkt[3] = total & 0xFF;
    pkt[8] = 64;
    pkt[9] = 1;
    memcpy(pkt + 12, &srv_addr.s_addr, 4);
    memcpy(pkt + 16, orig + 12, 4);

    uint32_t cksum = 0;
    for (int i = 0; i < 20; i += 2)
        cksum += ((uint32_t)pkt[i] << 8) | pkt[i + 1];
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t ip_ck = ~(uint16_t)cksum;
    pkt[10] = ip_ck >> 8;
    pkt[11] = ip_ck & 0xFF;

    uint8_t *icmp = pkt + 20;
    icmp[0] = 11;
    icmp[1] = 0;
    memcpy(icmp + 8, orig, icmp_data_len);

    size_t icmp_total = 8 + icmp_data_len;
    cksum = 0;
    for (size_t i = 0; i < icmp_total; i += 2) {
        cksum += ((uint32_t)icmp[i] << 8);
        if (i + 1 < icmp_total) cksum += icmp[i + 1];
    }
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t ic = ~(uint16_t)cksum;
    icmp[2] = ic >> 8;
    icmp[3] = ic & 0xFF;

    /* Send via MASQUE datagram back to client */
    uint8_t frame_buf[256];
    size_t frame_written = 0;
    xqc_int_t xret = xqc_h3_ext_masque_frame_udp(
        frame_buf, sizeof(frame_buf), &frame_written, conn->masque_stream_id, pkt, total);
    if (xret != XQC_OK) return;
    uint64_t dgram_id;
    xqc_h3_ext_datagram_send(conn->h3_conn, frame_buf, frame_written, &dgram_id,
                             XQC_DATA_QOS_LOW);
    LOG_D(s, "sent ICMP Time Exceeded to client");
}

/* ─── ICMPv6 Time Exceeded — sent via tunnel to client ─── */

static void
send_icmpv6_time_exceeded(mqvpn_server_t *s, svr_conn_t *conn, const uint8_t *orig,
                          size_t orig_len)
{
    if (orig_len < 40 || !s->pool.has_v6) return;
    if (!ptb_rate_allow(s)) return;

    struct in6_addr srv_addr6;
    mqvpn_addr_pool_server_addr6(&s->pool, &srv_addr6);

    size_t icmpv6_data_len = orig_len;
    if (40 + 8 + icmpv6_data_len > 1280) icmpv6_data_len = 1280 - 40 - 8;
    size_t icmpv6_len = 8 + icmpv6_data_len;
    size_t total = 40 + icmpv6_len;
    uint8_t pkt[1280];
    memset(pkt, 0, total);

    pkt[0] = 0x60;
    pkt[4] = (icmpv6_len >> 8) & 0xFF;
    pkt[5] = icmpv6_len & 0xFF;
    pkt[6] = 58;
    pkt[7] = 64;
    memcpy(pkt + 8, &srv_addr6, 16);
    memcpy(pkt + 24, orig + 8, 16);

    uint8_t *icmp = pkt + 40;
    icmp[0] = 3;
    icmp[1] = 0;
    memcpy(icmp + 8, orig, icmpv6_data_len);

    uint32_t cksum = 0;
    for (int i = 0; i < 16; i += 2)
        cksum += ((uint32_t)pkt[8 + i] << 8) | pkt[8 + i + 1];
    for (int i = 0; i < 16; i += 2)
        cksum += ((uint32_t)pkt[24 + i] << 8) | pkt[24 + i + 1];
    cksum += (uint32_t)(icmpv6_len >> 16);
    cksum += (uint32_t)(icmpv6_len & 0xFFFF);
    cksum += 58;
    for (size_t i = 0; i < icmpv6_len; i += 2) {
        cksum += ((uint32_t)icmp[i] << 8);
        if (i + 1 < icmpv6_len) cksum += icmp[i + 1];
    }
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t ic = ~(uint16_t)cksum;
    icmp[2] = ic >> 8;
    icmp[3] = ic & 0xFF;

    uint8_t frame_buf[1400];
    size_t frame_written = 0;
    xqc_int_t xret = xqc_h3_ext_masque_frame_udp(
        frame_buf, sizeof(frame_buf), &frame_written, conn->masque_stream_id, pkt, total);
    if (xret != XQC_OK) return;
    uint64_t dgram_id;
    xqc_h3_ext_datagram_send(conn->h3_conn, frame_buf, frame_written, &dgram_id,
                             XQC_DATA_QOS_LOW);
    LOG_D(s, "sent ICMPv6 Time Exceeded to client");
}

/* ─── ICMP Time Exceeded — DL direction (sent via tun_output to source) ─── */

static void
send_icmpv4_time_exceeded_tun(mqvpn_server_t *s, const uint8_t *orig, size_t orig_len)
{
    if (orig_len < 20) return;
    if (!ptb_rate_allow(s)) return;

    struct in_addr srv_addr;
    mqvpn_addr_pool_server_addr(&s->pool, &srv_addr);

    size_t ihl = (orig[0] & 0x0F) * 4;
    if (ihl < 20 || ihl > orig_len) return;
    size_t icmp_data_len = ihl + 8;
    if (icmp_data_len > orig_len) icmp_data_len = orig_len;
    size_t total = 20 + 8 + icmp_data_len;
    uint8_t pkt[128];
    if (total > sizeof(pkt)) return;
    memset(pkt, 0, total);

    pkt[0] = 0x45;
    pkt[1] = 0xC0;
    pkt[2] = (total >> 8) & 0xFF;
    pkt[3] = total & 0xFF;
    pkt[8] = 64;
    pkt[9] = 1;
    memcpy(pkt + 12, &srv_addr.s_addr, 4);
    memcpy(pkt + 16, orig + 12, 4); /* dst = original src */

    uint32_t cksum = 0;
    for (int i = 0; i < 20; i += 2)
        cksum += ((uint32_t)pkt[i] << 8) | pkt[i + 1];
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t ip_ck = ~(uint16_t)cksum;
    pkt[10] = ip_ck >> 8;
    pkt[11] = ip_ck & 0xFF;

    uint8_t *icmp = pkt + 20;
    icmp[0] = 11;
    icmp[1] = 0;
    memcpy(icmp + 8, orig, icmp_data_len);

    size_t icmp_total = 8 + icmp_data_len;
    cksum = 0;
    for (size_t i = 0; i < icmp_total; i += 2) {
        cksum += ((uint32_t)icmp[i] << 8);
        if (i + 1 < icmp_total) cksum += icmp[i + 1];
    }
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t ic = ~(uint16_t)cksum;
    icmp[2] = ic >> 8;
    icmp[3] = ic & 0xFF;

    s->cbs.tun_output(pkt, total, s->user_ctx);
    LOG_D(s, "sent ICMP Time Exceeded via TUN");
}

static void
send_icmpv6_time_exceeded_tun(mqvpn_server_t *s, const uint8_t *orig, size_t orig_len)
{
    if (orig_len < 40 || !s->pool.has_v6) return;
    if (!ptb_rate_allow(s)) return;

    struct in6_addr srv_addr6;
    mqvpn_addr_pool_server_addr6(&s->pool, &srv_addr6);

    size_t icmpv6_data_len = orig_len;
    if (40 + 8 + icmpv6_data_len > 1280) icmpv6_data_len = 1280 - 40 - 8;
    size_t icmpv6_len = 8 + icmpv6_data_len;
    size_t total = 40 + icmpv6_len;
    uint8_t pkt[1280];
    memset(pkt, 0, total);

    pkt[0] = 0x60;
    pkt[4] = (icmpv6_len >> 8) & 0xFF;
    pkt[5] = icmpv6_len & 0xFF;
    pkt[6] = 58;
    pkt[7] = 64;
    memcpy(pkt + 8, &srv_addr6, 16);
    memcpy(pkt + 24, orig + 8, 16); /* dst = original src */

    uint8_t *icmp = pkt + 40;
    icmp[0] = 3;
    icmp[1] = 0;
    memcpy(icmp + 8, orig, icmpv6_data_len);

    uint32_t cksum = 0;
    for (int i = 0; i < 16; i += 2)
        cksum += ((uint32_t)pkt[8 + i] << 8) | pkt[8 + i + 1];
    for (int i = 0; i < 16; i += 2)
        cksum += ((uint32_t)pkt[24 + i] << 8) | pkt[24 + i + 1];
    cksum += (uint32_t)(icmpv6_len >> 16);
    cksum += (uint32_t)(icmpv6_len & 0xFFFF);
    cksum += 58;
    for (size_t i = 0; i < icmpv6_len; i += 2) {
        cksum += ((uint32_t)icmp[i] << 8);
        if (i + 1 < icmpv6_len) cksum += icmp[i + 1];
    }
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t ic = ~(uint16_t)cksum;
    icmp[2] = ic >> 8;
    icmp[3] = ic & 0xFF;

    s->cbs.tun_output(pkt, total, s->user_ctx);
    LOG_D(s, "sent ICMPv6 Time Exceeded via TUN");
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
    (void)lvl;
    mqvpn_server_t *s = (mqvpn_server_t *)user_data;
    if (s->cbs.log) {
        char msg[512];
        snprintf(msg, sizeof(msg), "[xquic] %.*s", (int)size, (const char *)buf);
        s->cbs.log(MQVPN_LOG_DEBUG, msg, s->user_ctx);
    }
}

/* ─── UDP send helper ─── */

static ssize_t
svr_do_send(mqvpn_server_t *s, const unsigned char *buf, size_t size,
            const struct sockaddr *peer, socklen_t peerlen)
{
    if (s->udp_fd < 0) return XQC_SOCKET_ERROR;
    ssize_t res;
    do {
        res = sendto(s->udp_fd, buf, size, 0, peer, peerlen);
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
    memcpy(&conn->cid, cid, sizeof(*cid));

    xqc_h3_conn_set_user_data(h3_conn, conn);
    xqc_h3_ext_datagram_set_user_data(h3_conn, conn);
    xqc_h3_conn_get_peer_addr(h3_conn, (struct sockaddr *)&conn->peer_addr,
                              sizeof(conn->peer_addr), &conn->peer_addrlen);

    LOG_I(s, "H3 connection created");
    return 0;
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
    free(conn);
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
    xqc_http_header_t resp_hdrs[] = {
        {.name = {.iov_base = ":status", .iov_len = 7},
         .value = {.iov_base = "200", .iov_len = 3},
         .flags = 0},
        {.name = {.iov_base = "capsule-protocol", .iov_len = 16},
         .value = {.iov_base = "?1", .iov_len = 2},
         .flags = 0},
    };
    xqc_http_headers_t hdrs = {
        .headers = resp_hdrs,
        .count = 2,
        .capacity = 2,
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

    /* 3b. IPv6 ADDRESS_ASSIGN */
    if (s->pool.has_v6) {
        uint32_t ip_offset = ntohl(conn->assigned_ip.s_addr) - ntohl(s->pool.base.s_addr);
        mqvpn_addr_pool_get6(&s->pool, ip_offset, &conn->assigned_ip6);
        conn->has_v6 = 1;

        uint8_t a6_payload[32];
        size_t a6_off = 0;
        a6_payload[a6_off++] = 0x00;
        a6_payload[a6_off++] = 6;
        memcpy(a6_payload + a6_off, &conn->assigned_ip6, 16);
        a6_off += 16;
        a6_payload[a6_off++] = (uint8_t)s->pool.prefix6;

        uint8_t cap6_buf[64];
        size_t cap6_written = 0;
        xret =
            xqc_h3_ext_capsule_encode(cap6_buf, sizeof(cap6_buf), &cap6_written,
                                      XQC_H3_CAPSULE_ADDRESS_ASSIGN, a6_payload, a6_off);
        if (xret == XQC_OK) {
            ret = xqc_h3_request_send_body(h3_request, cap6_buf, cap6_written, 0);
            if (ret < 0) {
                LOG_E(s, "send ADDRESS_ASSIGN (IPv6): %zd", ret);
            } else {
                char v6str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &conn->assigned_ip6, v6str, sizeof(v6str));
                LOG_I(s, "ADDRESS_ASSIGN: client=%s/%d", v6str, s->pool.prefix6);
            }
        }
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

    /* 4b. IPv6 ROUTE_ADVERTISEMENT */
    if (s->pool.has_v6) {
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
        if (xret == XQC_OK) {
            ret = xqc_h3_request_send_body(h3_request, r6_capsule, r6c_written, 0);
            if (ret < 0) LOG_E(s, "send ROUTE_ADVERTISEMENT (IPv6): %zd", ret);
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
        client_info.mtu = 1280;
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
        if (stream->conn) stream->conn->tunnel_established = 0;
        free(stream->capsule_buf);
        free(stream);
    }
    return 0;
}

/*
 * cb_request_read — xquic H3 request read callback for MASQUE streams.
 *
 * Handles the CONNECT-IP handshake (header validation, 200 response,
 * DATAGRAM context setup) and processes incoming MASQUE capsules
 * (ADDRESS_REQUEST → allocate IP, ROUTE_ADVERTISEMENT parsing).
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

        int is_connect = 0, is_connect_ip = 0;
        int has_scheme_https = 0, has_capsule_proto = 0, has_valid_path = 0;
        const char *auth_token = NULL;
        size_t auth_token_len = 0;

        for (int i = 0; i < (int)headers->count; i++) {
            xqc_http_header_t *h = &headers->headers[i];
            if (h->name.iov_len == 7 && memcmp(h->name.iov_base, ":method", 7) == 0 &&
                h->value.iov_len == 7 && memcmp(h->value.iov_base, "CONNECT", 7) == 0)
                is_connect = 1;
            if (h->name.iov_len == 9 && memcmp(h->name.iov_base, ":protocol", 9) == 0 &&
                h->value.iov_len == 10 &&
                memcmp(h->value.iov_base, "connect-ip", 10) == 0)
                is_connect_ip = 1;
            if (h->name.iov_len == 7 && memcmp(h->name.iov_base, ":scheme", 7) == 0 &&
                h->value.iov_len == 5 && memcmp(h->value.iov_base, "https", 5) == 0)
                has_scheme_https = 1;
            if (h->name.iov_len == 5 && memcmp(h->name.iov_base, ":path", 5) == 0 &&
                h->value.iov_len >= 24 &&
                memcmp(h->value.iov_base, "/.well-known/masque/ip/", 22) == 0)
                has_valid_path = 1;
            if (h->name.iov_len == 16 &&
                memcmp(h->name.iov_base, "capsule-protocol", 16) == 0 &&
                h->value.iov_len == 2 && memcmp(h->value.iov_base, "?1", 2) == 0)
                has_capsule_proto = 1;
            if (h->name.iov_len == 13 &&
                memcmp(h->name.iov_base, "authorization", 13) == 0 &&
                h->value.iov_len > 7 && memcmp(h->value.iov_base, "Bearer ", 7) == 0) {
                auth_token = (const char *)h->value.iov_base + 7;
                auth_token_len = h->value.iov_len - 7;
            }
        }

        if (is_connect && is_connect_ip) {
            if (!has_scheme_https || !has_valid_path || !has_capsule_proto) {
                LOG_W(s,
                      "rejecting CONNECT-IP: missing headers "
                      "(scheme=%d path=%d capsule=%d)",
                      has_scheme_https, has_valid_path, has_capsule_proto);
                return -1;
            }

            int auth_required = (s->config.auth_key[0] != '\0') ||
                                (s->config.n_users > 0);
            if (auth_required) {
                int authed = 0;

                if (auth_token) {
                    if (s->config.auth_key[0] != '\0' &&
                        mqvpn_auth_ct_compare(auth_token, auth_token_len,
                                              s->config.auth_key,
                                              strlen(s->config.auth_key)) == 0) {
                        authed = 1;
                    }

                    /* Always iterate all users to keep timing constant */
                    for (int i = 0; i < s->config.n_users; i++) {
                        const char *expected_key = s->config.user_keys[i];
                        if (expected_key[0] == '\0') continue;
                        authed |= (mqvpn_auth_ct_compare(
                                       auth_token, auth_token_len,
                                       expected_key,
                                       strlen(expected_key)) == 0);
                    }
                }

                if (!authed) {
                    LOG_W(s, "authentication failed: invalid or missing PSK");
                    svr_masque_send_403(h3_request);
                    return -1;
                }

                LOG_I(s, "client authenticated successfully");
            }

            LOG_I(s, "Extended CONNECT for connect-ip received");
            if (svr_masque_send_response(h3_request, stream) < 0) return -1;
            return 0;
        }
    }

    /* Parse capsule traffic (ADDRESS_REQUEST) */
    if (flag & XQC_REQ_NOTIFY_READ_BODY) {
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
                xqc_int_t xr = xqc_h3_ext_capsule_decode(
                    stream->capsule_buf, stream->capsule_len, &cap_type, &cap_payload,
                    &cap_len, &consumed);
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
                        LOG_I(s, "ADDRESS_REQUEST: req_id=%" PRIu64 " ipv%d", req_id,
                              ip_ver);
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
                                                  XQC_H3_CAPSULE_ADDRESS_ASSIGN,
                                                  resp_payload, resp_written);
                        xqc_h3_request_send_body(h3_request, cap_buf, cap_w, 0);
                    }
                }

                if (consumed < stream->capsule_len)
                    memmove(stream->capsule_buf, stream->capsule_buf + consumed,
                            stream->capsule_len - consumed);
                stream->capsule_len -= consumed;
            }
        } while (1);
    }

    return 0;
}

static int
cb_request_write(xqc_h3_request_t *h3_request, void *strm_user_data)
{
    (void)h3_request;
    (void)strm_user_data;
    return 0;
}

/* ================================================================
 *  Datagram callbacks
 * ================================================================ */

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

    uint8_t ip_ver = payload[0] >> 4;
    uint8_t fwd_pkt[PACKET_BUF_SIZE];

    if (ip_ver == 4) {
        if (payload_len < 20) return;
        if (memcmp(payload + 12, &conn->assigned_ip.s_addr, 4) != 0) {
            LOG_W(s, "dropping packet: src IP mismatch");
            return;
        }
        memcpy(fwd_pkt, payload, payload_len);
        if (fwd_pkt[8] <= 1) {
            send_icmpv4_time_exceeded(s, conn, payload, payload_len);
            return;
        }
        fwd_pkt[8]--;
        uint32_t sum = ((uint32_t)fwd_pkt[10] << 8 | fwd_pkt[11]) + 0x0100;
        sum = (sum & 0xFFFF) + (sum >> 16);
        fwd_pkt[10] = (sum >> 8) & 0xFF;
        fwd_pkt[11] = sum & 0xFF;
    } else if (ip_ver == 6) {
        if (payload_len < 40) return;
        if (!conn->has_v6 || memcmp(payload + 8, &conn->assigned_ip6, 16) != 0) {
            LOG_W(s, "dropping IPv6 packet: src IP mismatch");
            return;
        }
        memcpy(fwd_pkt, payload, payload_len);
        if (fwd_pkt[7] <= 1) {
            send_icmpv6_time_exceeded(s, conn, payload, payload_len);
            return;
        }
        fwd_pkt[7]--;
    } else {
        return;
    }

    s->bytes_rx += payload_len;
    s->cbs.tun_output(fwd_pkt, payload_len, s->user_ctx);
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
    if (conn) conn->dgram_acked_cnt++;
}

static int
cb_dgram_lost(xqc_h3_conn_t *h, uint64_t id, void *ud)
{
    (void)h;
    svr_conn_t *conn = (svr_conn_t *)ud;
    if (!conn) return 0;
    mqvpn_server_t *s = conn->server;
    conn->dgram_lost_cnt++;
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
    memcpy(&s->cbs, cbs, sizeof(*cbs));
    s->user_ctx = user_ctx;
        /* caller guarantees lifetime exceeds this object */ // lgtm[cpp/stack-address-escape]
    s->udp_fd = -1;
    s->max_clients = cfg->max_clients > 0 ? cfg->max_clients : 64;
    s->ptb_tokens = PTB_RATE_LIMIT;

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

    int xqc_log_level;
    switch (cfg->log_level) {
    case MQVPN_LOG_DEBUG: xqc_log_level = 5; break;
    case MQVPN_LOG_INFO: xqc_log_level = 3; break;
    case MQVPN_LOG_WARN: xqc_log_level = 2; break;
    case MQVPN_LOG_ERROR: xqc_log_level = 1; break;
    default: xqc_log_level = 3; break;
    }

    xqc_config_t xconfig;
    if (xqc_engine_get_default_config(&xconfig, XQC_ENGINE_SERVER) < 0) goto cleanup;
    xconfig.cfg_log_level = (xqc_log_level_t)xqc_log_level;

    s->engine = xqc_engine_create(XQC_ENGINE_SERVER, &xconfig, &engine_ssl, &engine_cbs,
                                  &tcbs, s);
    if (!s->engine) goto cleanup;

    /* Connection settings */
    xqc_conn_settings_t conn_settings;
    memset(&conn_settings, 0, sizeof(conn_settings));
    conn_settings.max_datagram_frame_size = 65535;
    conn_settings.proto_version = XQC_VERSION_V1;
    conn_settings.enable_multipath = 1;
    conn_settings.mp_ping_on = 1;
    conn_settings.pacing_on = 1;
    conn_settings.max_pkt_out_size = 1400;
    conn_settings.cong_ctrl_callback = xqc_bbr2_cb;
    conn_settings.cc_params.cc_optimization_flags =
        XQC_BBR2_FLAG_RTTVAR_COMPENSATION | XQC_BBR2_FLAG_FAST_CONVERGENCE;
    if (cfg->scheduler == MQVPN_SCHED_WLB)
        conn_settings.scheduler_callback = xqc_wlb_scheduler_cb;
    else
        conn_settings.scheduler_callback = xqc_minrtt_scheduler_cb;
    conn_settings.sndq_packets_used_max = XQC_SNDQ_MAX_PKTS;
    conn_settings.so_sndbuf = 8 * 1024 * 1024;
    conn_settings.idle_time_out = 120000;
    conn_settings.init_idle_time_out = 10000;
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

    /* Step 2: Defensive sweep — free any sessions not freed by engine callbacks */
    for (int i = 1; i <= MQVPN_ADDR_POOL_MAX; i++) {
        if (s->sessions[i]) {
            free(s->sessions[i]);
            s->sessions[i] = NULL;
        }
    }

    /* Step 3: free server handle */
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
    info.mtu = 1280;

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
        if (ip_ver == 4)
            send_icmpv4_dest_unreach(s, pkt, len);
        else
            send_icmpv6_dest_unreach(s, pkt, len);
        return MQVPN_OK;
    }

    /* ICMP PTB if packet exceeds tunnel capacity */
    if (target->dgram_mss > 0) {
        size_t udp_mss =
            xqc_h3_ext_masque_udp_mss(target->dgram_mss, target->masque_stream_id);
        if (len > udp_mss) {
            if (ip_ver == 4)
                send_icmpv4_ptb(s, pkt, len, udp_mss);
            else
                send_icmpv6_ptb(s, pkt, len, udp_mss);
            return MQVPN_OK;
        }
    }

    /* §7.3 step 4: TTL / Hop Limit decrement (RFC 9484 §4.3) */
    uint8_t fwd_pkt[PACKET_BUF_SIZE];
    if (len > sizeof(fwd_pkt)) return MQVPN_ERR_INVALID_ARG;
    memcpy(fwd_pkt, pkt, len);

    if (ip_ver == 4) {
        if (fwd_pkt[8] <= 1) {
            /* DL: source is on TUN side → ICMP goes via tun_output */
            send_icmpv4_time_exceeded_tun(s, pkt, len);
            return MQVPN_OK;
        }
        fwd_pkt[8]--;
        uint32_t sum = ((uint32_t)fwd_pkt[10] << 8 | fwd_pkt[11]) + 0x0100;
        sum = (sum & 0xFFFF) + (sum >> 16);
        fwd_pkt[10] = (sum >> 8) & 0xFF;
        fwd_pkt[11] = sum & 0xFF;
    } else {
        if (fwd_pkt[7] <= 1) {
            send_icmpv6_time_exceeded_tun(s, pkt, len);
            return MQVPN_OK;
        }
        fwd_pkt[7]--;
    }

    /* MASQUE frame and send */
    uint8_t frame_buf[MASQUE_FRAME_BUF];
    size_t frame_written = 0;
    xqc_int_t xret =
        xqc_h3_ext_masque_frame_udp(frame_buf, sizeof(frame_buf), &frame_written,
                                    target->masque_stream_id, fwd_pkt, len);
    if (xret != XQC_OK) return MQVPN_ERR_ENGINE;

    uint64_t dgram_id;
    uint32_t fh = flow_hash_pkt(pkt, (int)len);
    xqc_conn_set_dgram_flow_hash(xqc_h3_conn_get_xqc_conn(target->h3_conn), fh);
    xret = xqc_h3_ext_datagram_send(target->h3_conn, frame_buf, frame_written, &dgram_id,
                                    XQC_DATA_QOS_HIGH);

    if (xret == -XQC_EAGAIN) {
        s->tun_paused = 1;
        LOG_D(s, "TUN read paused (QUIC backpressure)");
        return MQVPN_ERR_AGAIN;
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
    return MQVPN_OK;
}

int mqvpn_server_get_n_clients(const mqvpn_server_t *s)
{
    if (!s) return 0;
    return s->n_sessions;
}

int mqvpn_server_list_users(const mqvpn_server_t *s, char names[][64], int max)
{
    if (!s || !names || max <= 0) return 0;
    int n = s->config.n_users < max ? s->config.n_users : max;
    for (int i = 0; i < n; i++)
        snprintf(names[i], 64, "%s", s->config.user_names[i]);
    return n;
}

int mqvpn_server_add_user(mqvpn_server_t *s, const char *username, const char *key)
{
    if (!s || !username || !key || username[0] == '\0' || key[0] == '\0')
        return MQVPN_ERR_INVALID_ARG;

    for (int i = 0; i < s->config.n_users; i++) {
        if (strcmp(s->config.user_names[i], username) == 0) {
            snprintf(s->config.user_keys[i], sizeof(s->config.user_keys[i]),
                     "%s", key);
            return MQVPN_OK;
        }
    }

    if (s->config.n_users >= MQVPN_MAX_USERS)
        return MQVPN_ERR_MAX_CLIENTS;

    snprintf(s->config.user_names[s->config.n_users],
             sizeof(s->config.user_names[s->config.n_users]), "%s", username);
    snprintf(s->config.user_keys[s->config.n_users],
             sizeof(s->config.user_keys[s->config.n_users]), "%s", key);
    s->config.n_users++;
    return MQVPN_OK;
}

int mqvpn_server_remove_user(mqvpn_server_t *s, const char *username)
{
    if (!s || !username || username[0] == '\0')
        return MQVPN_ERR_INVALID_ARG;

    for (int i = 0; i < s->config.n_users; i++) {
        if (strcmp(s->config.user_names[i], username) == 0) {
            for (int j = i + 1; j < s->config.n_users; j++) {
                memcpy(s->config.user_names[j - 1], s->config.user_names[j],
                       sizeof(s->config.user_names[j - 1]));
                memcpy(s->config.user_keys[j - 1], s->config.user_keys[j],
                       sizeof(s->config.user_keys[j - 1]));
            }
            s->config.n_users--;
            return MQVPN_OK;
        }
    }
    return MQVPN_ERR_INVALID_ARG;
}

int mqvpn_server_get_interest(const mqvpn_server_t *s, mqvpn_interest_t *out)
{
    if (!s || !out) return MQVPN_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);

    int ms = (int)(s->next_wake_us / 1000);
    out->next_timer_ms = ms > 0 ? ms : 1;
    out->tun_readable = s->tun_paused ? 0 : 1;
    out->is_idle = (s->n_sessions == 0) ? 1 : 0;
    return MQVPN_OK;
}
