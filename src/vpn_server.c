#include "vpn_server.h"
#include "flow_sched.h"
#include "tun.h"
#include "addr_pool.h"
#include "auth.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <inttypes.h>

#include <event2/event.h>
#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>

#define PACKET_BUF_SIZE      65536
#define MASQUE_FRAME_BUF     (PACKET_BUF_SIZE + 16)
#define MAX_CAPSULE_BUF      65536
#define TUN_RESUME_SAFETY_MS 100
#define XQC_SNDQ_MAX_PKTS    16384

static uint64_t
mqvpn_now_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;
}

/* ---------- forward declarations ---------- */

typedef struct svr_ctx_s        svr_ctx_t;
typedef struct svr_conn_s       svr_conn_t;
typedef struct svr_stream_s     svr_stream_t;

/* ---------- server context (global per server instance) ---------- */

struct svr_ctx_s {
    const mqvpn_server_cfg_t *cfg;

    xqc_engine_t        *engine;
    struct event_base   *eb;
    struct event        *ev_engine;  /* xquic timer */
    struct event        *ev_socket;  /* UDP socket read */
    struct event        *ev_tun;     /* TUN device read */
    struct event        *ev_tun_resume; /* safety timer to resume TUN read */
    struct event        *ev_sigint;
    struct event        *ev_sigterm;

    int                  udp_fd;
    struct sockaddr_storage local_addr;
    socklen_t            local_addrlen;

    mqvpn_tun_t          tun;
    int                  tun_paused;     /* TUN reading paused (QUIC backpressure) */
    uint64_t             tun_drop_cnt;   /* TUN write failure counter */
    mqvpn_addr_pool_t    pool;

    /* Session table: indexed by IP offset (1-254) within the subnet */
    svr_conn_t          *sessions[MQVPN_ADDR_POOL_MAX + 1];
    int                  n_sessions;
    int                  max_clients;

};

/* ---------- per-connection state ---------- */

struct svr_conn_s {
    svr_ctx_t           *ctx;
    xqc_h3_conn_t       *h3_conn;
    xqc_cid_t            cid;
    struct sockaddr_in6   peer_addr;
    socklen_t             peer_addrlen;

    /* MASQUE session */
    uint64_t              masque_stream_id;
    struct in_addr        assigned_ip;
    struct in6_addr       assigned_ip6;
    int                   has_v6;
    int                   tunnel_established;
    size_t                dgram_mss;
    uint64_t              dgram_lost_cnt;
    uint64_t              dgram_acked_cnt;
};

/* ---------- per-stream (request) state ---------- */

struct svr_stream_s {
    svr_conn_t          *conn;
    xqc_h3_request_t    *h3_request;
    int                  header_sent;
    uint8_t             *capsule_buf;
    size_t               capsule_len;
    size_t               capsule_cap;
};

/* ---------- static context (M1: single instance) ---------- */

static svr_ctx_t g_svr;

static void
svr_log_conn_stats(const char *tag, const xqc_cid_t *cid)
{
    if (!g_svr.engine || !cid) {
        return;
    }
    xqc_conn_stats_t st = xqc_conn_get_stats(g_svr.engine, cid);
    LOG_INF("%s: send=%u recv=%u lost=%u lost_dgram=%u srtt=%.2fms min_rtt=%.2fms inflight=%" PRIu64 " app_bytes=%" PRIu64 " standby_bytes=%" PRIu64 " mp_state=%d",
            tag,
            st.send_count, st.recv_count, st.lost_count, st.lost_dgram_count,
            (double)st.srtt / 1000.0, (double)st.min_rtt / 1000.0,
            st.inflight_bytes, st.total_app_bytes, st.standby_path_app_bytes,
            st.mp_state);
}

static void
svr_signal_event_callback(evutil_socket_t sig, short events, void *arg)
{
    (void)sig;
    (void)events;
    svr_ctx_t *ctx = (svr_ctx_t *)arg;
    event_base_loopbreak(ctx->eb);
}

/* ================================================================
 *  xquic log callback
 * ================================================================ */

static void
svr_xqc_log_write(xqc_log_level_t lvl, const void *buf, size_t size,
                   void *engine_user_data)
{
    (void)engine_user_data;
    (void)lvl;
    /* Route all xquic logs through our logger; app log level controls output. */
    LOG_DBG("[xquic] %.*s", (int)size, (const char *)buf);
}

/* ================================================================
 *  Engine timer callback
 * ================================================================ */

static void
svr_set_event_timer(xqc_usec_t wake_after, void *engine_user_data)
{
    svr_ctx_t *ctx = (svr_ctx_t *)engine_user_data;
    struct timeval tv;
    tv.tv_sec  = (long)(wake_after / 1000000);
    tv.tv_usec = (long)(wake_after % 1000000);
    event_add(ctx->ev_engine, &tv);
}

static void
svr_engine_callback(int fd, short what, void *arg)
{
    (void)fd; (void)what;
    svr_ctx_t *ctx = (svr_ctx_t *)arg;
    xqc_engine_main_logic(ctx->engine);
}

/* ================================================================
 *  UDP socket write callback (xquic → network)
 * ================================================================ */

static ssize_t
svr_write_socket(const unsigned char *buf, size_t size,
                 const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                 void *conn_user_data)
{
    (void)conn_user_data;
    ssize_t res;
    do {
        res = sendto(g_svr.udp_fd, buf, size, 0, peer_addr, peer_addrlen);
    } while (res < 0 && errno == EINTR);

    if (res < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return XQC_SOCKET_EAGAIN;
        }
        LOG_ERR("sendto: %s", strerror(errno));
        return XQC_SOCKET_ERROR;
    }
    return res;
}

static ssize_t
svr_write_socket_ex(uint64_t path_id,
                    const unsigned char *buf, size_t size,
                    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                    void *conn_user_data)
{
    (void)path_id;
    return svr_write_socket(buf, size, peer_addr, peer_addrlen, conn_user_data);
}

/* ================================================================
 *  UDP socket read handler (network → xquic)
 * ================================================================ */

static void
svr_socket_read_handler(svr_ctx_t *ctx)
{
    unsigned char buf[PACKET_BUF_SIZE];
    struct sockaddr_in6 peer_addr;
    socklen_t peer_addrlen = sizeof(peer_addr);

    for (;;) {
        ssize_t n = recvfrom(ctx->udp_fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&peer_addr, &peer_addrlen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            LOG_ERR("recvfrom: %s", strerror(errno));
            break;
        }

        uint64_t recv_time = mqvpn_now_us();
        xqc_int_t ret = xqc_engine_packet_process(
            ctx->engine, buf, (size_t)n,
            (struct sockaddr *)&ctx->local_addr, ctx->local_addrlen,
            (struct sockaddr *)&peer_addr, peer_addrlen,
            (xqc_usec_t)recv_time, NULL);
        if (ret != XQC_OK) {
            LOG_DBG("packet_process: %d", ret);
        }
    }
    xqc_engine_finish_recv(ctx->engine);
    xqc_engine_main_logic(ctx->engine);
}

static void
svr_socket_event_callback(int fd, short what, void *arg)
{
    (void)fd;
    svr_ctx_t *ctx = (svr_ctx_t *)arg;
    if (what & EV_READ) {
        svr_socket_read_handler(ctx);
    }
}

/* ================================================================
 *  TUN read handler (internet return traffic → MASQUE datagram to client)
 * ================================================================ */

static void
svr_tun_resume_safety(int fd, short what, void *arg)
{
    (void)fd; (void)what;
    svr_ctx_t *ctx = (svr_ctx_t *)arg;
    if (ctx->tun_paused && ctx->ev_tun) {
        event_add(ctx->ev_tun, NULL);
        ctx->tun_paused = 0;
        LOG_DBG("TUN read resumed (safety timer)");
    }
}

/* ---- ICMP Packet Too Big (RFC 9484 §10.1) ---- */

#define PTB_RATE_LIMIT  10  /* max PTB responses per second */

static int     svr_ptb_tokens    = PTB_RATE_LIMIT;
static int64_t svr_ptb_refill_ms = 0;

static int
svr_ptb_rate_allow(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    int64_t now_ms = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    if (now_ms - svr_ptb_refill_ms >= 1000) {
        svr_ptb_tokens = PTB_RATE_LIMIT;
        svr_ptb_refill_ms = now_ms;
    }
    if (svr_ptb_tokens > 0) {
        svr_ptb_tokens--;
        return 1;
    }
    return 0;
}

/*
 * Send ICMP Destination Unreachable / Fragmentation Needed (type=3, code=4)
 * back to the TUN device when a packet is too large for the QUIC tunnel.
 */
static void
svr_send_icmp_ptb(svr_ctx_t *ctx, const uint8_t *orig_pkt, size_t orig_len,
                   size_t tunnel_mtu)
{
    if (orig_len < 20) return;
    if (!svr_ptb_rate_allow()) return;

    struct in_addr srv_addr;
    mqvpn_addr_pool_server_addr(&ctx->pool, &srv_addr);

    /* ICMP payload: original IP header + first 8 bytes of data */
    size_t ihl = (orig_pkt[0] & 0x0F) * 4;
    if (ihl < 20 || ihl > orig_len) return;
    size_t icmp_data_len = ihl + 8;
    if (icmp_data_len > orig_len) icmp_data_len = orig_len;

    size_t total_len = 20 + 8 + icmp_data_len;
    uint8_t pkt[128];
    if (total_len > sizeof(pkt)) return;
    memset(pkt, 0, total_len);

    /* IP header: server TUN addr → original src */
    pkt[0]  = 0x45;
    pkt[1]  = 0xC0;                          /* DSCP=CS6 */
    pkt[2]  = (total_len >> 8) & 0xFF;
    pkt[3]  = total_len & 0xFF;
    pkt[8]  = 64;                            /* TTL */
    pkt[9]  = 1;                             /* ICMP */
    memcpy(pkt + 12, &srv_addr.s_addr, 4);  /* src = server TUN */
    memcpy(pkt + 16, orig_pkt + 12, 4);     /* dst = original src */

    /* IP header checksum */
    uint32_t cksum = 0;
    for (int i = 0; i < 20; i += 2)
        cksum += ((uint32_t)pkt[i] << 8) | pkt[i + 1];
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t ip_cksum = ~(uint16_t)cksum;
    pkt[10] = ip_cksum >> 8;
    pkt[11] = ip_cksum & 0xFF;

    /* ICMP: type=3 (Dest Unreachable), code=4 (Frag Needed) */
    uint8_t *icmp = pkt + 20;
    icmp[0] = 3;
    icmp[1] = 4;
    /* icmp[2..3] = checksum */
    /* icmp[4..5] = unused (0) */
    /* icmp[6..7] = next-hop MTU */
    uint16_t mtu16 = (tunnel_mtu > 0xFFFF) ? 0xFFFF : (uint16_t)tunnel_mtu;
    icmp[6] = mtu16 >> 8;
    icmp[7] = mtu16 & 0xFF;
    memcpy(icmp + 8, orig_pkt, icmp_data_len);

    /* ICMP checksum */
    size_t icmp_total = 8 + icmp_data_len;
    cksum = 0;
    for (size_t i = 0; i < icmp_total; i += 2) {
        cksum += ((uint32_t)icmp[i] << 8);
        if (i + 1 < icmp_total)
            cksum += icmp[i + 1];
    }
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t icmp_cksum = ~(uint16_t)cksum;
    icmp[2] = icmp_cksum >> 8;
    icmp[3] = icmp_cksum & 0xFF;

    mqvpn_tun_write(&ctx->tun, pkt, total_len);
    LOG_DBG("sent ICMP Fragmentation Needed (mtu=%zu) to TUN", tunnel_mtu);
}

/*
 * Send ICMPv6 Packet Too Big (type=2, code=0) back to the TUN device.
 */
static void
svr_send_icmpv6_ptb(svr_ctx_t *ctx, const uint8_t *orig_pkt, size_t orig_len,
                      size_t tunnel_mtu)
{
    if (orig_len < 40) return;
    if (!ctx->pool.has_v6) return;
    if (!svr_ptb_rate_allow()) return;

    struct in6_addr srv_addr6;
    mqvpn_addr_pool_server_addr6(&ctx->pool, &srv_addr6);

    /* ICMPv6 payload: as much of original packet as fits in 1280 total */
    size_t icmpv6_data_len = orig_len;
    if (40 + 8 + icmpv6_data_len > 1280)
        icmpv6_data_len = 1280 - 40 - 8;
    size_t icmpv6_len = 8 + icmpv6_data_len;
    size_t total_len = 40 + icmpv6_len;

    uint8_t pkt[1280];
    memset(pkt, 0, total_len);

    /* IPv6 header */
    pkt[0] = 0x60;
    pkt[4] = (icmpv6_len >> 8) & 0xFF;
    pkt[5] = icmpv6_len & 0xFF;
    pkt[6] = 58;    /* next header: ICMPv6 */
    pkt[7] = 64;    /* hop limit */
    memcpy(pkt + 8, &srv_addr6, 16);        /* src = server TUN */
    memcpy(pkt + 24, orig_pkt + 8, 16);     /* dst = original src */

    /* ICMPv6 Packet Too Big: type=2, code=0 */
    uint8_t *icmp = pkt + 40;
    icmp[0] = 2;
    icmp[1] = 0;
    /* icmp[2..3] = checksum */
    /* icmp[4..7] = MTU (network byte order) */
    uint32_t mtu32 = (uint32_t)tunnel_mtu;
    icmp[4] = (mtu32 >> 24) & 0xFF;
    icmp[5] = (mtu32 >> 16) & 0xFF;
    icmp[6] = (mtu32 >>  8) & 0xFF;
    icmp[7] = mtu32 & 0xFF;
    memcpy(icmp + 8, orig_pkt, icmpv6_data_len);

    /* ICMPv6 checksum with pseudo-header */
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
        if (i + 1 < icmpv6_len)
            cksum += icmp[i + 1];
    }
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t icmp_cksum = ~(uint16_t)cksum;
    icmp[2] = icmp_cksum >> 8;
    icmp[3] = icmp_cksum & 0xFF;

    mqvpn_tun_write(&ctx->tun, pkt, total_len);
    LOG_DBG("sent ICMPv6 Packet Too Big (mtu=%zu) to TUN", tunnel_mtu);
}

static void
svr_tun_read_handler(int fd, short what, void *arg)
{
    (void)fd; (void)what;
    svr_ctx_t *ctx = (svr_ctx_t *)arg;

    if (ctx->n_sessions == 0) {
        /* Drain the fd even if no active tunnel */
        uint8_t discard[PACKET_BUF_SIZE];
        while (mqvpn_tun_read(&ctx->tun, discard, sizeof(discard)) > 0)
            ;
        return;
    }

    uint8_t pkt[PACKET_BUF_SIZE];
    uint8_t frame_buf[MASQUE_FRAME_BUF];

    for (;;) {
        int n = mqvpn_tun_read(&ctx->tun, pkt, sizeof(pkt));
        if (n <= 0) break;

        if (n < 1) continue;
        uint8_t ip_ver = pkt[0] >> 4;
        svr_conn_t *target = NULL;

        if (ip_ver == 4 && n >= 20) {
            struct in_addr dst_ip;
            memcpy(&dst_ip.s_addr, pkt + 16, 4);
            uint32_t offset = ntohl(dst_ip.s_addr) - ntohl(ctx->pool.base.s_addr);
            if (offset == 0 || offset > MQVPN_ADDR_POOL_MAX) continue;
            target = ctx->sessions[offset];
        } else if (ip_ver == 6 && n >= 40 && ctx->pool.has_v6) {
            struct in6_addr dst_ip6;
            memcpy(&dst_ip6, pkt + 24, 16);
            uint32_t offset = mqvpn_addr_pool_offset6(&ctx->pool, &dst_ip6);
            if (offset == 0 || offset > MQVPN_ADDR_POOL_MAX) continue;
            target = ctx->sessions[offset];
        } else {
            continue;
        }

        if (!target || !target->tunnel_established) continue;

        /* RFC 9484 §10.1: if packet exceeds tunnel capacity, send ICMP PTB */
        if (target->dgram_mss > 0) {
            size_t udp_mss = xqc_h3_ext_masque_udp_mss(
                target->dgram_mss, target->masque_stream_id);
            if ((size_t)n > udp_mss) {
                if (ip_ver == 4)
                    svr_send_icmp_ptb(ctx, pkt, (size_t)n, udp_mss);
                else
                    svr_send_icmpv6_ptb(ctx, pkt, (size_t)n, udp_mss);
                continue;
            }
        }

        /* Frame with quarter-stream-ID + context_id=0 */
        size_t frame_written = 0;
        xqc_int_t xret = xqc_h3_ext_masque_frame_udp(
            frame_buf, sizeof(frame_buf), &frame_written,
            target->masque_stream_id, pkt, (size_t)n);
        if (xret != XQC_OK) {
            LOG_ERR("masque_frame_udp: %d", xret);
            continue;
        }

        uint64_t dgram_id;
        /* Provide per-packet flow hint for xquic WLB (same as client side). */
        uint32_t fh = flow_hash_pkt(pkt, n);
        xqc_conn_set_dgram_flow_hash(
            xqc_h3_conn_get_xqc_conn(target->h3_conn), fh);

        xret = xqc_h3_ext_datagram_send(
            target->h3_conn, frame_buf, frame_written,
            &dgram_id, XQC_DATA_QOS_HIGH);
        if (xret == -XQC_EAGAIN) {
            /* QUIC send queue full — pause TUN reading */
            event_del(ctx->ev_tun);
            ctx->tun_paused = 1;
            LOG_DBG("TUN read paused (QUIC backpressure)");
            struct timeval tv = { .tv_sec = 0,
                                  .tv_usec = TUN_RESUME_SAFETY_MS * 1000 };
            event_add(ctx->ev_tun_resume, &tv);
            break;
        }
        if (xret < 0) {
            LOG_DBG("datagram_send return: %d", xret);
        }
    }

    xqc_engine_main_logic(ctx->engine);
}

/* ================================================================
 *  Transport-level callbacks
 * ================================================================ */

static int
svr_accept(xqc_engine_t *engine, xqc_connection_t *conn,
           const xqc_cid_t *cid, void *user_data)
{
    (void)engine;
    (void)user_data;
    (void)conn;
    (void)cid;

    LOG_INF("connection accepted");
    return 0;
}

static void
svr_refuse(xqc_engine_t *engine, xqc_connection_t *conn,
           const xqc_cid_t *cid, void *user_data)
{
    (void)engine; (void)conn; (void)cid;
    svr_conn_t *svr_conn = (svr_conn_t *)user_data;
    if (svr_conn) {
        free(svr_conn);
    }
}

static ssize_t
svr_stateless_reset(const unsigned char *buf, size_t size,
                    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                    const struct sockaddr *local_addr, socklen_t local_addrlen,
                    void *user_data)
{
    (void)local_addr; (void)local_addrlen;
    return svr_write_socket(buf, size, peer_addr, peer_addrlen, user_data);
}

/* ================================================================
 *  Multipath callbacks (server is passive — accepts paths from client)
 * ================================================================ */

static int
svr_path_created(xqc_connection_t *conn, const xqc_cid_t *cid,
                  uint64_t path_id, void *conn_user_data)
{
    (void)conn; (void)cid; (void)conn_user_data;
    LOG_INF("new path created: path_id=%" PRIu64, path_id);
    return 0;
}

static void
svr_path_removed(const xqc_cid_t *cid, uint64_t path_id,
                  void *conn_user_data)
{
    (void)cid; (void)conn_user_data;
    LOG_INF("path removed: path_id=%" PRIu64, path_id);
}

/* ================================================================
 *  H3 connection callbacks
 * ================================================================ */

static int
svr_h3_conn_create_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
                           void *conn_user_data)
{
    (void)conn_user_data;
    svr_conn_t *svr_conn = calloc(1, sizeof(*svr_conn));
    if (!svr_conn) return -1;

    svr_conn->ctx = &g_svr;
    svr_conn->h3_conn = h3_conn;
    memcpy(&svr_conn->cid, cid, sizeof(*cid));

    xqc_h3_conn_set_user_data(h3_conn, svr_conn);
    xqc_h3_ext_datagram_set_user_data(h3_conn, svr_conn);
    xqc_h3_conn_get_peer_addr(h3_conn, (struct sockaddr *)&svr_conn->peer_addr,
                               sizeof(svr_conn->peer_addr), &svr_conn->peer_addrlen);

    LOG_INF("H3 connection created");
    return 0;
}

static int
svr_h3_conn_close_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
                          void *conn_user_data)
{
    (void)h3_conn; (void)cid;
    svr_conn_t *svr_conn = (svr_conn_t *)conn_user_data;
    if (!svr_conn) return 0;

    svr_log_conn_stats("server conn stats",
                       cid ? cid : &svr_conn->cid);
    LOG_INF("server dgram summary: acked=%" PRIu64 " lost=%" PRIu64,
            svr_conn->dgram_acked_cnt, svr_conn->dgram_lost_cnt);

    if (svr_conn->assigned_ip.s_addr) {
        /* Remove from session table */
        uint32_t offset = ntohl(svr_conn->assigned_ip.s_addr) -
                          ntohl(svr_conn->ctx->pool.base.s_addr);
        if (offset > 0 && offset <= MQVPN_ADDR_POOL_MAX &&
            svr_conn->ctx->sessions[offset] == svr_conn) {
            svr_conn->ctx->sessions[offset] = NULL;
            svr_conn->ctx->n_sessions--;
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &svr_conn->assigned_ip, ip_str, sizeof(ip_str));
            LOG_INF("session removed: %s (active=%d)", ip_str,
                    svr_conn->ctx->n_sessions);
        }
        mqvpn_addr_pool_release(&svr_conn->ctx->pool, &svr_conn->assigned_ip);
    }

    LOG_INF("H3 connection closed");
    free(svr_conn);
    return 0;
}

static void
svr_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *conn_user_data)
{
    (void)h3_conn;
    (void)conn_user_data;
    LOG_INF("H3 handshake finished");
}

/* ================================================================
 *  MASQUE session handling — Extended CONNECT → 200 + capsules
 * ================================================================ */

static int
svr_masque_send_403(xqc_h3_request_t *h3_request)
{
    xqc_http_header_t resp[] = {
        { .name  = {.iov_base = ":status", .iov_len = 7},
          .value = {.iov_base = "403",     .iov_len = 3}, .flags = 0 },
    };
    xqc_http_headers_t hdrs = { .headers = resp, .count = 1, .capacity = 1 };
    return xqc_h3_request_send_headers(h3_request, &hdrs, 1) < 0 ? -1 : 0;
}

static int
svr_masque_send_response(xqc_h3_request_t *h3_request, svr_stream_t *stream)
{
    svr_conn_t *conn = stream->conn;
    svr_ctx_t *ctx = conn->ctx;
    ssize_t ret;

    /* Check max_clients limit */
    if (ctx->n_sessions >= ctx->max_clients) {
        LOG_WRN("max clients reached (%d), rejecting new connection",
                ctx->max_clients);
        svr_masque_send_403(h3_request);
        return -1;
    }

    /* 1. Send 200 response headers (fin=0 to keep stream open) */
    xqc_http_header_t resp_hdrs[] = {
        { .name  = {.iov_base = ":status",          .iov_len = 7},
          .value = {.iov_base = "200",               .iov_len = 3},
          .flags = 0 },
        { .name  = {.iov_base = "capsule-protocol",  .iov_len = 16},
          .value = {.iov_base = "?1",                 .iov_len = 2},
          .flags = 0 },
    };
    xqc_http_headers_t hdrs = {
        .headers  = resp_hdrs,
        .count    = 2,
        .capacity = 2,
    };

    ret = xqc_h3_request_send_headers(h3_request, &hdrs, 0);
    if (ret < 0) {
        LOG_ERR("send 200 headers: %zd", ret);
        return -1;
    }
    stream->header_sent = 1;

    /* Store stream_id for datagram framing */
    conn->masque_stream_id = xqc_h3_stream_id(h3_request);

    /* 2. Allocate client IP from pool */
    if (mqvpn_addr_pool_alloc(&ctx->pool, &conn->assigned_ip) < 0) {
        LOG_ERR("IP pool exhausted");
        return -1;
    }

    /* 3. Build and send ADDRESS_ASSIGN capsule */
    uint8_t addr_payload[64];
    size_t addr_written = 0;
    uint8_t ip_bytes[4];
    memcpy(ip_bytes, &conn->assigned_ip.s_addr, 4);

    /* Build ADDRESS_ASSIGN payload directly (RFC 9484 §4.7.1):
     * request_id=0 (unsolicited) + ip_version + ip_addr + prefix_len.
     * Cannot use build_address_request() as it rejects request_id=0. */
    addr_payload[0] = 0x00;  /* request_id=0 (varint) */
    addr_payload[1] = 4;     /* IPv4 */
    memcpy(addr_payload + 2, ip_bytes, 4);
    addr_payload[6] = 32;    /* /32 */
    addr_written = 7;

    uint8_t capsule_buf[128];
    size_t cap_written = 0;
    xqc_int_t xret = xqc_h3_ext_capsule_encode(
        capsule_buf, sizeof(capsule_buf), &cap_written,
        XQC_H3_CAPSULE_ADDRESS_ASSIGN,
        addr_payload, addr_written);
    if (xret != XQC_OK) {
        LOG_ERR("capsule encode ADDRESS_ASSIGN: %d", xret);
        return -1;
    }

    ret = xqc_h3_request_send_body(h3_request, capsule_buf, cap_written, 0);
    if (ret < 0) {
        LOG_ERR("send ADDRESS_ASSIGN: %zd", ret);
        return -1;
    }

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &conn->assigned_ip, ip_str, sizeof(ip_str));
    LOG_INF("ADDRESS_ASSIGN: client=%s/32", ip_str);

    /*
     * 3b. Send IPv6 ADDRESS_ASSIGN if configured.
     *
     * Note (RFC 9484 §7.2): At connection start the QUIC initial
     * max_udp_payload is 1200 (RFC 9000 §14), giving an IP payload
     * capacity of ~1182 — below the IPv6 minimum link MTU of 1280.
     * The TUN MTU is clamped to 1280 so the kernel accepts IPv6
     * addresses, and ICMP Packet Too Big (§10.1) is sent for packets
     * exceeding the actual tunnel capacity.  Once PMTUD completes
     * (typically within one RTT), the sender adjusts its MSS and
     * full-size IPv6 packets flow normally.
     */
    if (ctx->pool.has_v6) {
        uint32_t ip_offset = ntohl(conn->assigned_ip.s_addr) -
                             ntohl(ctx->pool.base.s_addr);
        mqvpn_addr_pool_get6(&ctx->pool, ip_offset, &conn->assigned_ip6);
        conn->has_v6 = 1;

        uint8_t a6_payload[32];
        size_t a6_off = 0;
        a6_payload[a6_off++] = 0x00;  /* request_id=0 */
        a6_payload[a6_off++] = 6;     /* IPv6 */
        memcpy(a6_payload + a6_off, &conn->assigned_ip6, 16);
        a6_off += 16;
        a6_payload[a6_off++] = (uint8_t)ctx->pool.prefix6;

        uint8_t cap6_buf[64];
        size_t cap6_written = 0;
        xret = xqc_h3_ext_capsule_encode(
            cap6_buf, sizeof(cap6_buf), &cap6_written,
            XQC_H3_CAPSULE_ADDRESS_ASSIGN,
            a6_payload, a6_off);
        if (xret == XQC_OK) {
            ret = xqc_h3_request_send_body(h3_request, cap6_buf, cap6_written, 0);
            if (ret < 0) {
                LOG_ERR("send ADDRESS_ASSIGN (IPv6): %zd", ret);
            } else {
                char v6str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &conn->assigned_ip6, v6str, sizeof(v6str));
                LOG_INF("ADDRESS_ASSIGN: client=%s/%d", v6str, ctx->pool.prefix6);
            }
        }
    }

    /* 4. Build and send ROUTE_ADVERTISEMENT capsule (0.0.0.0 → 255.255.255.255) */
    uint8_t route_payload[32];
    size_t rp_off = 0;
    route_payload[rp_off++] = 4;   /* IPv4 */
    /* start_ip: 0.0.0.0 */
    route_payload[rp_off++] = 0; route_payload[rp_off++] = 0;
    route_payload[rp_off++] = 0; route_payload[rp_off++] = 0;
    /* end_ip: 255.255.255.255 */
    route_payload[rp_off++] = 255; route_payload[rp_off++] = 255;
    route_payload[rp_off++] = 255; route_payload[rp_off++] = 255;
    /* protocol: 0 (any) */
    route_payload[rp_off++] = 0;

    uint8_t route_capsule[64];
    size_t rc_written = 0;
    xret = xqc_h3_ext_capsule_encode(
        route_capsule, sizeof(route_capsule), &rc_written,
        XQC_H3_CAPSULE_ROUTE_ADVERTISEMENT,
        route_payload, rp_off);
    if (xret != XQC_OK) {
        LOG_ERR("capsule encode ROUTE_ADVERTISEMENT: %d", xret);
        return -1;
    }

    ret = xqc_h3_request_send_body(h3_request, route_capsule, rc_written, 0);
    if (ret < 0) {
        LOG_ERR("send ROUTE_ADVERTISEMENT: %zd", ret);
        return -1;
    }

    /* 4b. IPv6 ROUTE_ADVERTISEMENT (:: → ffff:...:ffff) */
    if (ctx->pool.has_v6) {
        uint8_t r6_payload[48];
        size_t r6_off = 0;
        r6_payload[r6_off++] = 6;    /* IPv6 */
        memset(r6_payload + r6_off, 0x00, 16);  /* start: :: */
        r6_off += 16;
        memset(r6_payload + r6_off, 0xFF, 16);  /* end: ffff:...:ffff */
        r6_off += 16;
        r6_payload[r6_off++] = 0;    /* protocol: any */

        uint8_t r6_capsule[80];
        size_t r6c_written = 0;
        xret = xqc_h3_ext_capsule_encode(
            r6_capsule, sizeof(r6_capsule), &r6c_written,
            XQC_H3_CAPSULE_ROUTE_ADVERTISEMENT,
            r6_payload, r6_off);
        if (xret == XQC_OK) {
            ret = xqc_h3_request_send_body(h3_request, r6_capsule, r6c_written, 0);
            if (ret < 0) LOG_ERR("send ROUTE_ADVERTISEMENT (IPv6): %zd", ret);
        }
    }

    conn->tunnel_established = 1;

    /* Register in session table (indexed by IP offset) */
    uint32_t ip_offset = ntohl(conn->assigned_ip.s_addr) -
                         ntohl(ctx->pool.base.s_addr);
    if (ip_offset > 0 && ip_offset <= MQVPN_ADDR_POOL_MAX) {
        ctx->sessions[ip_offset] = conn;
        ctx->n_sessions++;
    }
    LOG_INF("MASQUE tunnel established (stream_id=%" PRIu64 ", clients=%d)",
            conn->masque_stream_id, ctx->n_sessions);
    return 0;
}

/* ================================================================
 *  H3 request callbacks
 * ================================================================ */

static int
svr_request_create_notify(xqc_h3_request_t *h3_request,
                           void *strm_user_data)
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
svr_request_close_notify(xqc_h3_request_t *h3_request,
                          void *strm_user_data)
{
    (void)h3_request;
    svr_stream_t *stream = (svr_stream_t *)strm_user_data;
    if (stream) {
        if (stream->conn) {
            stream->conn->tunnel_established = 0;
        }
        free(stream->capsule_buf);
        free(stream);
    }
    return 0;
}

static int
svr_request_read_notify(xqc_h3_request_t *h3_request,
                         xqc_request_notify_flag_t flag, void *strm_user_data)
{
    svr_stream_t *stream = (svr_stream_t *)strm_user_data;
    unsigned char fin = 0;

    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        xqc_http_headers_t *headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (!headers) return -1;

        /* Validate Extended CONNECT for connect-ip (RFC 9484 §4.5) */
        int is_connect = 0, is_connect_ip = 0;
        int has_scheme_https = 0, has_capsule_proto = 0, has_valid_path = 0;
        const char *auth_token = NULL;
        size_t auth_token_len = 0;
        for (int i = 0; i < (int)headers->count; i++) {
            xqc_http_header_t *h = &headers->headers[i];
            if (h->name.iov_len == 7
                && memcmp(h->name.iov_base, ":method", 7) == 0
                && h->value.iov_len == 7
                && memcmp(h->value.iov_base, "CONNECT", 7) == 0) {
                is_connect = 1;
            }
            if (h->name.iov_len == 9
                && memcmp(h->name.iov_base, ":protocol", 9) == 0
                && h->value.iov_len == 10
                && memcmp(h->value.iov_base, "connect-ip", 10) == 0) {
                is_connect_ip = 1;
            }
            if (h->name.iov_len == 7
                && memcmp(h->name.iov_base, ":scheme", 7) == 0
                && h->value.iov_len == 5
                && memcmp(h->value.iov_base, "https", 5) == 0) {
                has_scheme_https = 1;
            }
            if (h->name.iov_len == 5
                && memcmp(h->name.iov_base, ":path", 5) == 0
                && h->value.iov_len >= 24
                && memcmp(h->value.iov_base,
                          "/.well-known/masque/ip/", 22) == 0) {
                has_valid_path = 1;
            }
            if (h->name.iov_len == 16
                && memcmp(h->name.iov_base, "capsule-protocol", 16) == 0
                && h->value.iov_len == 2
                && memcmp(h->value.iov_base, "?1", 2) == 0) {
                has_capsule_proto = 1;
            }
            if (h->name.iov_len == 13
                && memcmp(h->name.iov_base, "authorization", 13) == 0) {
                /* Expect "Bearer <token>" */
                if (h->value.iov_len > 7
                    && memcmp(h->value.iov_base, "Bearer ", 7) == 0) {
                    auth_token = (const char *)h->value.iov_base + 7;
                    auth_token_len = h->value.iov_len - 7;
                }
            }
        }

        if (is_connect && is_connect_ip) {
            if (!has_scheme_https || !has_valid_path || !has_capsule_proto) {
                LOG_WRN("rejecting CONNECT-IP: missing required headers "
                        "(scheme=%d path=%d capsule=%d)",
                        has_scheme_https, has_valid_path, has_capsule_proto);
                return -1;
            }

            /* PSK authentication check */
            const char *expected_key = stream->conn->ctx->cfg->auth_key;
            if (expected_key && expected_key[0] != '\0') {
                if (!auth_token ||
                    mqvpn_auth_ct_compare(auth_token, auth_token_len,
                                          expected_key,
                                          strlen(expected_key)) != 0) {
                    LOG_WRN("authentication failed: invalid or missing PSK");
                    svr_masque_send_403(h3_request);
                    return -1;
                }
                LOG_INF("client authenticated successfully");
            }

            LOG_INF("Extended CONNECT for connect-ip received");
            svr_masque_send_response(h3_request, stream);
            return 0;
        }
    }

    /* Parse capsule traffic from client (RFC 9484 §4.7.2: ADDRESS_REQUEST) */
    if (flag & XQC_REQ_NOTIFY_READ_BODY) {
        unsigned char buf[4096];
        ssize_t n;
        do {
            n = xqc_h3_request_recv_body(h3_request, buf, sizeof(buf), &fin);
            if (n <= 0) break;

            /* Append to capsule buffer */
            size_t need = stream->capsule_len + (size_t)n;
            if (need > MAX_CAPSULE_BUF) {
                LOG_ERR("server capsule buffer overflow");
                break;
            }
            if (need > stream->capsule_cap) {
                size_t new_cap = stream->capsule_cap ? stream->capsule_cap * 2 : 4096;
                while (new_cap < need) {
                    if (new_cap > SIZE_MAX / 2) { new_cap = need; break; }
                    new_cap *= 2;
                }
                uint8_t *new_buf = realloc(stream->capsule_buf, new_cap);
                if (!new_buf) break;
                stream->capsule_buf = new_buf;
                stream->capsule_cap = new_cap;
            }
            memcpy(stream->capsule_buf + stream->capsule_len, buf, (size_t)n);
            stream->capsule_len += (size_t)n;

            /* Process complete capsules */
            while (stream->capsule_len > 0) {
                uint64_t cap_type;
                const uint8_t *cap_payload;
                size_t cap_len, consumed;
                xqc_int_t xr = xqc_h3_ext_capsule_decode(
                    stream->capsule_buf, stream->capsule_len,
                    &cap_type, &cap_payload, &cap_len, &consumed);
                if (xr != XQC_OK) break;

                if (cap_type == XQC_H3_CAPSULE_ADDRESS_REQUEST
                    && stream->conn && stream->conn->tunnel_established) {
                    /* Parse ADDRESS_REQUEST (same wire format as ADDRESS_ASSIGN) */
                    uint64_t req_id;
                    uint8_t ip_ver, ip_addr[16], prefix;
                    size_t ip_len = 16, aa_consumed;
                    xr = xqc_h3_ext_connectip_parse_address_assign(
                        cap_payload, cap_len, &req_id, &ip_ver,
                        ip_addr, &ip_len, &prefix, &aa_consumed);
                    if (xr == XQC_OK && req_id != 0) {
                        LOG_INF("ADDRESS_REQUEST: req_id=%" PRIu64 " ipv%d",
                                req_id, ip_ver);
                        /* Respond with ADDRESS_ASSIGN for already-assigned IP */
                        uint8_t resp_payload[64];
                        size_t resp_written = 0;
                        uint8_t ip_bytes[4];
                        memcpy(ip_bytes, &stream->conn->assigned_ip.s_addr, 4);
                        xqc_h3_ext_connectip_build_address_request(
                            resp_payload, sizeof(resp_payload), &resp_written,
                            req_id, 4, ip_bytes, 32);
                        uint8_t cap_buf[128];
                        size_t cap_written = 0;
                        xqc_h3_ext_capsule_encode(
                            cap_buf, sizeof(cap_buf), &cap_written,
                            XQC_H3_CAPSULE_ADDRESS_ASSIGN,
                            resp_payload, resp_written);
                        xqc_h3_request_send_body(h3_request,
                            cap_buf, cap_written, 0);
                    }
                }
                /* RFC 9297 §3.2: unknown capsule types silently ignored */

                if (consumed < stream->capsule_len) {
                    memmove(stream->capsule_buf,
                            stream->capsule_buf + consumed,
                            stream->capsule_len - consumed);
                }
                stream->capsule_len -= consumed;
            }
        } while (n > 0);
    }

    return 0;
}

static int
svr_request_write_notify(xqc_h3_request_t *h3_request,
                          void *strm_user_data)
{
    (void)h3_request; (void)strm_user_data;
    return 0;
}

/* ================================================================
 *  H3 datagram callbacks (client → server: IP packets)
 * ================================================================ */

/* Send ICMP Time Exceeded back to client through the tunnel (RFC 9484 §4.4 SHOULD) */
static void
svr_send_icmp_time_exceeded(svr_conn_t *svr_conn, const uint8_t *orig_pkt,
                             size_t orig_len)
{
    if (orig_len < 20) return;

    /* ICMP payload: original IP header + first 8 bytes of original data */
    size_t ihl = (orig_pkt[0] & 0x0F) * 4;
    if (ihl < 20 || ihl > orig_len) return;
    size_t icmp_data_len = ihl + 8;
    if (icmp_data_len > orig_len) icmp_data_len = orig_len;

    /* Build IP + ICMP packet */
    size_t total_len = 20 + 8 + icmp_data_len;  /* IP(20) + ICMP hdr(8) + data */
    uint8_t pkt[128];
    if (total_len > sizeof(pkt)) return;
    memset(pkt, 0, total_len);

    /* IP header: server TUN addr → client assigned addr */
    svr_ctx_t *ctx = svr_conn->ctx;
    struct in_addr srv_addr;
    mqvpn_addr_pool_server_addr(&ctx->pool, &srv_addr);

    pkt[0]  = 0x45;                          /* IPv4, IHL=5 */
    pkt[1]  = 0xC0;                          /* DSCP=CS6 (network control) */
    pkt[2]  = (total_len >> 8) & 0xFF;       /* total length */
    pkt[3]  = total_len & 0xFF;
    pkt[8]  = 64;                            /* TTL */
    pkt[9]  = 1;                             /* protocol: ICMP */
    memcpy(pkt + 12, &srv_addr.s_addr, 4);  /* src = server */
    memcpy(pkt + 16, orig_pkt + 12, 4);     /* dst = original src */

    /* IP header checksum */
    uint32_t cksum = 0;
    for (int i = 0; i < 20; i += 2)
        cksum += ((uint32_t)pkt[i] << 8) | pkt[i + 1];
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t ip_cksum = ~(uint16_t)cksum;
    pkt[10] = ip_cksum >> 8;
    pkt[11] = ip_cksum & 0xFF;

    /* ICMP Time Exceeded: type=11, code=0, unused=0 */
    uint8_t *icmp = pkt + 20;
    icmp[0] = 11;   /* type: Time Exceeded */
    icmp[1] = 0;    /* code: TTL exceeded in transit */
    /* icmp[2..3] = checksum (computed below) */
    /* icmp[4..7] = unused (zeroed) */
    memcpy(icmp + 8, orig_pkt, icmp_data_len);

    /* ICMP checksum */
    size_t icmp_total = 8 + icmp_data_len;
    cksum = 0;
    for (size_t i = 0; i < icmp_total; i += 2) {
        cksum += ((uint32_t)icmp[i] << 8);
        if (i + 1 < icmp_total)
            cksum += icmp[i + 1];
    }
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t icmp_cksum = ~(uint16_t)cksum;
    icmp[2] = icmp_cksum >> 8;
    icmp[3] = icmp_cksum & 0xFF;

    /* Send back through tunnel as MASQUE datagram */
    uint8_t frame_buf[256];
    size_t frame_written = 0;
    xqc_int_t xret = xqc_h3_ext_masque_frame_udp(
        frame_buf, sizeof(frame_buf), &frame_written,
        svr_conn->masque_stream_id, pkt, total_len);
    if (xret != XQC_OK) return;

    uint64_t dgram_id;
    xqc_h3_ext_datagram_send(svr_conn->h3_conn, frame_buf, frame_written,
                              &dgram_id, XQC_DATA_QOS_LOW);
    LOG_DBG("sent ICMP Time Exceeded to client");
}

/* Send ICMPv6 Time Exceeded (type=3, code=0) back through the tunnel */
static void
svr_send_icmpv6_time_exceeded(svr_conn_t *svr_conn, const uint8_t *orig_pkt,
                               size_t orig_len)
{
    if (orig_len < 40) return;
    if (!svr_conn->ctx->pool.has_v6) return;

    struct in6_addr srv_addr6;
    mqvpn_addr_pool_server_addr6(&svr_conn->ctx->pool, &srv_addr6);

    /* ICMPv6 payload: as much of original packet as fits in 1280 MTU */
    size_t icmpv6_data_len = orig_len;
    if (40 + 8 + icmpv6_data_len > 1280)
        icmpv6_data_len = 1280 - 40 - 8;
    size_t icmpv6_len = 8 + icmpv6_data_len;  /* ICMPv6 header + data */
    size_t total_len = 40 + icmpv6_len;        /* IPv6 header + ICMPv6 */

    uint8_t pkt[1280];
    memset(pkt, 0, total_len);

    /* IPv6 header */
    pkt[0] = 0x60;  /* version=6, traffic class=0, flow label=0 */
    pkt[4] = (icmpv6_len >> 8) & 0xFF;
    pkt[5] = icmpv6_len & 0xFF;
    pkt[6] = 58;    /* next header: ICMPv6 */
    pkt[7] = 64;    /* hop limit */
    memcpy(pkt + 8, &srv_addr6, 16);     /* src = server */
    memcpy(pkt + 24, orig_pkt + 8, 16);  /* dst = original src */

    /* ICMPv6 Time Exceeded: type=3, code=0 */
    uint8_t *icmp = pkt + 40;
    icmp[0] = 3;   /* type: Time Exceeded */
    icmp[1] = 0;   /* code: hop limit exceeded in transit */
    /* icmp[2..3] = checksum (below) */
    /* icmp[4..7] = unused (zeroed) */
    memcpy(icmp + 8, orig_pkt, icmpv6_data_len);

    /* ICMPv6 checksum with pseudo-header (RFC 4443 §2.3) */
    uint32_t cksum = 0;
    /* Pseudo-header: src addr (16 bytes) */
    for (int i = 0; i < 16; i += 2)
        cksum += ((uint32_t)pkt[8 + i] << 8) | pkt[8 + i + 1];
    /* Pseudo-header: dst addr (16 bytes) */
    for (int i = 0; i < 16; i += 2)
        cksum += ((uint32_t)pkt[24 + i] << 8) | pkt[24 + i + 1];
    /* Pseudo-header: upper-layer packet length (32-bit) */
    cksum += (uint32_t)(icmpv6_len >> 16);
    cksum += (uint32_t)(icmpv6_len & 0xFFFF);
    /* Pseudo-header: next header = 58 */
    cksum += 58;
    /* ICMPv6 message */
    for (size_t i = 0; i < icmpv6_len; i += 2) {
        cksum += ((uint32_t)icmp[i] << 8);
        if (i + 1 < icmpv6_len)
            cksum += icmp[i + 1];
    }
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t icmp_cksum = ~(uint16_t)cksum;
    icmp[2] = icmp_cksum >> 8;
    icmp[3] = icmp_cksum & 0xFF;

    /* Send back through tunnel as MASQUE datagram */
    uint8_t frame_buf[1400];
    size_t frame_written = 0;
    xqc_int_t xret = xqc_h3_ext_masque_frame_udp(
        frame_buf, sizeof(frame_buf), &frame_written,
        svr_conn->masque_stream_id, pkt, total_len);
    if (xret != XQC_OK) return;

    uint64_t dgram_id;
    xqc_h3_ext_datagram_send(svr_conn->h3_conn, frame_buf, frame_written,
                              &dgram_id, XQC_DATA_QOS_LOW);
    LOG_DBG("sent ICMPv6 Time Exceeded to client");
}

static void
svr_dgram_read_notify(xqc_h3_conn_t *conn, const void *data,
                       size_t data_len, void *user_data, uint64_t ts)
{
    (void)conn; (void)ts;
    svr_conn_t *svr_conn = (svr_conn_t *)user_data;
    if (!svr_conn || !svr_conn->tunnel_established) return;

    /* Unframe: strip quarter-stream-ID + context_id */
    uint64_t qsid = 0, ctx_id = 0;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;

    xqc_int_t xret = xqc_h3_ext_masque_unframe_udp(
        (const uint8_t *)data, data_len, &qsid, &ctx_id,
        &payload, &payload_len);
    if (xret != XQC_OK) {
        LOG_DBG("unframe_udp: %d", xret);
        return;
    }

    /* Check IP version */
    if (payload_len < 1) return;
    uint8_t ip_ver = payload[0] >> 4;

    uint8_t fwd_pkt[PACKET_BUF_SIZE];

    if (ip_ver == 4) {
        if (payload_len < 20) {
            LOG_DBG("dropping short IPv4 packet (len=%zu)", payload_len);
            return;
        }

        /* Validate source IP matches assigned address (prevent spoofing) */
        if (memcmp(payload + 12, &svr_conn->assigned_ip.s_addr, 4) != 0) {
            LOG_WRN("dropping packet: src IP mismatch (expected %s)",
                    inet_ntoa(svr_conn->assigned_ip));
            return;
        }

        /* Decrement TTL before forwarding (RFC 9484 §4.3 MUST) */
        memcpy(fwd_pkt, payload, payload_len);
        if (fwd_pkt[8] <= 1) {
            LOG_DBG("dropping packet: TTL expired");
            svr_send_icmp_time_exceeded(svr_conn, payload, payload_len);
            return;
        }
        fwd_pkt[8]--;
        /* Incremental IP header checksum update (RFC 1141) */
        uint32_t sum = ((uint32_t)fwd_pkt[10] << 8 | fwd_pkt[11]) + 0x0100;
        sum = (sum & 0xFFFF) + (sum >> 16);
        fwd_pkt[10] = (sum >> 8) & 0xFF;
        fwd_pkt[11] = sum & 0xFF;

    } else if (ip_ver == 6) {
        if (payload_len < 40) {
            LOG_DBG("dropping short IPv6 packet (len=%zu)", payload_len);
            return;
        }

        /* Validate source IPv6 matches assigned address (prevent spoofing) */
        if (!svr_conn->has_v6 ||
            memcmp(payload + 8, &svr_conn->assigned_ip6, 16) != 0) {
            LOG_WRN("dropping IPv6 packet: src IP mismatch");
            return;
        }

        /* Decrement Hop Limit (byte 7) before forwarding */
        memcpy(fwd_pkt, payload, payload_len);
        if (fwd_pkt[7] <= 1) {
            LOG_DBG("dropping IPv6 packet: hop limit expired");
            svr_send_icmpv6_time_exceeded(svr_conn, payload, payload_len);
            return;
        }
        fwd_pkt[7]--;
        /* IPv6 has no header checksum */

    } else {
        LOG_DBG("dropping non-IP packet (version=%d len=%zu)", ip_ver, payload_len);
        return;
    }

    /* Write IP packet to TUN (kernel routes to internet via NAT) */
    int wret = mqvpn_tun_write(&svr_conn->ctx->tun, fwd_pkt, payload_len);
    if (wret < 0) {
        svr_conn->ctx->tun_drop_cnt++;
        if (wret == MQVPN_TUN_EAGAIN) {
            LOG_DBG("TUN write EAGAIN (drops=%" PRIu64 ")",
                    svr_conn->ctx->tun_drop_cnt);
        } else {
            LOG_WRN("TUN write failed (drops=%" PRIu64 ")",
                    svr_conn->ctx->tun_drop_cnt);
        }
    }
}

static void
svr_dgram_write_notify(xqc_h3_conn_t *h3_conn, void *user_data)
{
    (void)h3_conn;
    svr_conn_t *svr_conn = (svr_conn_t *)user_data;
    if (!svr_conn) return;
    svr_ctx_t *ctx = svr_conn->ctx;

    if (ctx->tun_paused && ctx->ev_tun) {
        event_add(ctx->ev_tun, NULL);
        ctx->tun_paused = 0;
        evtimer_del(ctx->ev_tun_resume);
        LOG_DBG("TUN read resumed (QUIC queue has space)");
    }
}

static void
svr_dgram_acked_notify(xqc_h3_conn_t *conn, uint64_t dgram_id,
                        void *user_data)
{
    (void)conn; (void)dgram_id;
    svr_conn_t *svr_conn = (svr_conn_t *)user_data;
    if (!svr_conn) return;
    svr_conn->dgram_acked_cnt++;
}

static int
svr_dgram_lost_notify(xqc_h3_conn_t *conn, uint64_t dgram_id,
                       void *user_data)
{
    (void)conn;
    svr_conn_t *svr_conn = (svr_conn_t *)user_data;
    if (!svr_conn) return 0;

    svr_conn->dgram_lost_cnt++;
    if ((svr_conn->dgram_lost_cnt % 256) == 0) {
        LOG_WRN("datagram loss checkpoint: lost=%" PRIu64 " acked=%" PRIu64 " (last_dgram_id=%" PRIu64 ")",
                svr_conn->dgram_lost_cnt, svr_conn->dgram_acked_cnt, dgram_id);
        svr_log_conn_stats("server loss checkpoint", &svr_conn->cid);
    }
    return 0;
}

static void
svr_dgram_mss_updated_notify(xqc_h3_conn_t *conn, size_t mss,
                              void *user_data)
{
    (void)conn;
    svr_conn_t *svr_conn = (svr_conn_t *)user_data;
    if (svr_conn)
        svr_conn->dgram_mss = mss;
    LOG_INF("datagram MSS updated: %zu", mss);

    /* Update server TUN MTU based on QUIC datagram MSS */
    if (svr_conn && svr_conn->ctx) {
        size_t udp_mss = xqc_h3_ext_masque_udp_mss(
            mss, svr_conn->masque_stream_id);
        if (udp_mss >= 68) {
            int new_mtu = (int)udp_mss;
            if (g_svr.pool.has_v6 && new_mtu < 1280)
                new_mtu = 1280;
            mqvpn_tun_set_mtu(&svr_conn->ctx->tun, new_mtu);
        }
    }
}

/* ================================================================
 *  UDP socket creation
 * ================================================================ */

static int
svr_create_udp_socket(const char *addr, int port, svr_ctx_t *ctx)
{
    /* Detect address family from bind address */
    sa_family_t af = AF_INET;
    struct in_addr  addr4;
    struct in6_addr addr6;
    if (addr && addr[0]) {
        if (inet_pton(AF_INET6, addr, &addr6) == 1) {
            af = AF_INET6;
        } else if (inet_pton(AF_INET, addr, &addr4) == 1) {
            af = AF_INET;
        } else {
            LOG_ERR("invalid listen address: %s", addr);
            return -1;
        }
    }

    int fd = socket(af, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOG_ERR("socket: %s", strerror(errno));
        return -1;
    }

    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        LOG_ERR("fcntl: %s", strerror(errno));
        close(fd);
        return -1;
    }

    int optval = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    int bufsize = 1 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    memset(&ctx->local_addr, 0, sizeof(ctx->local_addr));

    if (af == AF_INET6) {
        int v6only = 1;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));

        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ctx->local_addr;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons((uint16_t)port);
        if (addr && addr[0]) {
            sin6->sin6_addr = addr6;
        } else {
            sin6->sin6_addr = in6addr_any;
        }
        ctx->local_addrlen = sizeof(struct sockaddr_in6);
    } else {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ctx->local_addr;
        sin->sin_family = AF_INET;
        sin->sin_port = htons((uint16_t)port);
        if (addr && addr[0]) {
            sin->sin_addr = addr4;
        } else {
            sin->sin_addr.s_addr = htonl(INADDR_ANY);
        }
        ctx->local_addrlen = sizeof(struct sockaddr_in);
    }

    if (bind(fd, (struct sockaddr *)&ctx->local_addr, ctx->local_addrlen) < 0) {
        LOG_ERR("bind %s:%d: %s", addr ? addr : (af == AF_INET6 ? "::" : "0.0.0.0"),
                port, strerror(errno));
        close(fd);
        return -1;
    }

    LOG_INF("UDP socket bound to %s:%d (%s)",
            addr ? addr : (af == AF_INET6 ? "::" : "0.0.0.0"),
            port, af == AF_INET6 ? "IPv6" : "IPv4");
    return fd;
}

/* ================================================================
 *  Server main
 * ================================================================ */

int
mqvpn_server_run(const mqvpn_server_cfg_t *cfg)
{
    memset(&g_svr, 0, sizeof(g_svr));
    g_svr.cfg = cfg;
    g_svr.tun.fd = -1;
    g_svr.max_clients = cfg->max_clients > 0 ? cfg->max_clients : 64;

    /* Initialize address pool */
    if (mqvpn_addr_pool_init(&g_svr.pool, cfg->subnet) < 0) {
        return -1;
    }
    if (cfg->subnet6 && cfg->subnet6[0]) {
        if (mqvpn_addr_pool_init6(&g_svr.pool, cfg->subnet6) < 0) {
            return -1;
        }
    }

    /* Create event base */
    g_svr.eb = event_base_new();
    if (!g_svr.eb) {
        LOG_ERR("event_base_new failed");
        return -1;
    }

    g_svr.ev_engine = event_new(g_svr.eb, -1, 0, svr_engine_callback, &g_svr);
    g_svr.ev_tun_resume = evtimer_new(g_svr.eb, svr_tun_resume_safety, &g_svr);
    g_svr.ev_sigint = evsignal_new(g_svr.eb, SIGINT, svr_signal_event_callback, &g_svr);
    g_svr.ev_sigterm = evsignal_new(g_svr.eb, SIGTERM, svr_signal_event_callback, &g_svr);
    if (!g_svr.ev_sigint || !g_svr.ev_sigterm) {
        LOG_ERR("failed to create signal events");
        return -1;
    }
    event_add(g_svr.ev_sigint, NULL);
    event_add(g_svr.ev_sigterm, NULL);

    /* ---- xquic engine setup ---- */
    xqc_engine_ssl_config_t engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));
    engine_ssl_config.private_key_file = (char *)cfg->key_file;
    engine_ssl_config.cert_file        = (char *)cfg->cert_file;
    engine_ssl_config.ciphers          = XQC_TLS_CIPHERS;
    engine_ssl_config.groups           = XQC_TLS_GROUPS;

    xqc_engine_callback_t engine_cbs = {
        .set_event_timer = svr_set_event_timer,
        .log_callbacks = {
            .xqc_log_write_err  = svr_xqc_log_write,
            .xqc_log_write_stat = svr_xqc_log_write,
        },
    };

    xqc_transport_callbacks_t tcbs = {
        .server_accept                  = svr_accept,
        .server_refuse                  = svr_refuse,
        .write_socket                   = svr_write_socket,
        .write_socket_ex                = svr_write_socket_ex,
        .stateless_reset                = svr_stateless_reset,
        .conn_send_packet_before_accept = svr_write_socket,
        .path_created_notify            = svr_path_created,
        .path_removed_notify            = svr_path_removed,
    };

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_SERVER) < 0) {
        LOG_ERR("xqc_engine_get_default_config failed");
        return -1;
    }
    config.cfg_log_level = (xqc_log_level_t)cfg->log_level;

    g_svr.engine = xqc_engine_create(XQC_ENGINE_SERVER, &config,
                                      &engine_ssl_config, &engine_cbs,
                                      &tcbs, &g_svr);
    if (!g_svr.engine) {
        LOG_ERR("xqc_engine_create failed");
        return -1;
    }

    /* Connection settings: enable datagrams + multipath */
    xqc_conn_settings_t conn_settings;
    memset(&conn_settings, 0, sizeof(conn_settings));
    conn_settings.max_datagram_frame_size = 65535;
    conn_settings.proto_version = XQC_VERSION_V1;
    conn_settings.enable_multipath = 1;
    conn_settings.mp_ping_on = 1;
    conn_settings.pacing_on = 1;
    conn_settings.cong_ctrl_callback = xqc_bbr2_cb;
    conn_settings.cc_params.cc_optimization_flags =
        XQC_BBR2_FLAG_RTTVAR_COMPENSATION | XQC_BBR2_FLAG_FAST_CONVERGENCE;
    if (cfg->scheduler == MQVPN_SCHED_WLB) {
        conn_settings.scheduler_callback = xqc_wlb_scheduler_cb;
    } else {
        conn_settings.scheduler_callback = xqc_minrtt_scheduler_cb;
    }
    conn_settings.sndq_packets_used_max = XQC_SNDQ_MAX_PKTS;
    conn_settings.so_sndbuf = 8 * 1024 * 1024;
    conn_settings.idle_time_out = 30000;       /* 30s idle timeout */
    conn_settings.init_idle_time_out = 10000;  /* 10s initial idle timeout */
    xqc_server_set_conn_settings(g_svr.engine, &conn_settings);

    /* H3 callbacks */
    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs = {
            .h3_conn_create_notify      = svr_h3_conn_create_notify,
            .h3_conn_close_notify       = svr_h3_conn_close_notify,
            .h3_conn_handshake_finished = svr_h3_conn_handshake_finished,
        },
        .h3r_cbs = {
            .h3_request_create_notify = svr_request_create_notify,
            .h3_request_close_notify  = svr_request_close_notify,
            .h3_request_read_notify   = svr_request_read_notify,
            .h3_request_write_notify  = svr_request_write_notify,
        },
        .h3_ext_dgram_cbs = {
            .dgram_read_notify        = svr_dgram_read_notify,
            .dgram_write_notify       = svr_dgram_write_notify,
            .dgram_acked_notify       = svr_dgram_acked_notify,
            .dgram_lost_notify        = svr_dgram_lost_notify,
            .dgram_mss_updated_notify = svr_dgram_mss_updated_notify,
        },
    };

    xqc_int_t ret = xqc_h3_ctx_init(g_svr.engine, &h3_cbs);
    if (ret != XQC_OK) {
        LOG_ERR("xqc_h3_ctx_init: %d", ret);
        return -1;
    }

    /* H3 settings: enable Extended CONNECT + datagram */
    xqc_h3_conn_settings_t h3s = {
        .max_field_section_size       = 32 * 1024,
        .qpack_blocked_streams        = 64,
        .qpack_enc_max_table_capacity = 16 * 1024,
        .qpack_dec_max_table_capacity = 16 * 1024,
        .enable_connect_protocol      = 1,
        .h3_datagram                  = 1,
    };
    xqc_h3_engine_set_local_settings(g_svr.engine, &h3s);

    /* ---- Create TUN device ---- */
    if (mqvpn_tun_create(&g_svr.tun, cfg->tun_name) < 0) {
        return -1;
    }

    /* Server gets .1, clients get .2+ */
    struct in_addr srv_addr;
    mqvpn_addr_pool_server_addr(&g_svr.pool, &srv_addr);
    char srv_ip[INET_ADDRSTRLEN], base_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &srv_addr, srv_ip, sizeof(srv_ip));
    inet_ntop(AF_INET, &g_svr.pool.base, base_ip, sizeof(base_ip));

    if (mqvpn_tun_set_addr(&g_svr.tun, srv_ip, base_ip,
                            g_svr.pool.prefix_len) < 0) {
        return -1;
    }
    if (mqvpn_tun_set_mtu(&g_svr.tun, 1280) < 0) {
        return -1;
    }
    if (mqvpn_tun_up(&g_svr.tun) < 0) {
        return -1;
    }

    /* Set IPv6 address on TUN if configured */
    if (g_svr.pool.has_v6) {
        struct in6_addr srv_addr6;
        mqvpn_addr_pool_server_addr6(&g_svr.pool, &srv_addr6);
        char srv_ip6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &srv_addr6, srv_ip6, sizeof(srv_ip6));
        if (mqvpn_tun_set_addr6(&g_svr.tun, srv_ip6, g_svr.pool.prefix6) < 0) {
            return -1;
        }
    }

    /* ---- Create UDP socket ---- */
    g_svr.udp_fd = svr_create_udp_socket(cfg->listen_addr, cfg->listen_port, &g_svr);
    if (g_svr.udp_fd < 0) {
        return -1;
    }

    /* ---- Register events ---- */
    g_svr.ev_socket = event_new(g_svr.eb, g_svr.udp_fd,
                                 EV_READ | EV_PERSIST,
                                 svr_socket_event_callback, &g_svr);
    event_add(g_svr.ev_socket, NULL);

    g_svr.ev_tun = event_new(g_svr.eb, g_svr.tun.fd,
                              EV_READ | EV_PERSIST,
                              svr_tun_read_handler, &g_svr);
    event_add(g_svr.ev_tun, NULL);

    LOG_INF("mqvpn server ready — listening on %s:%d, subnet %s",
            cfg->listen_addr ? cfg->listen_addr : "0.0.0.0",
            cfg->listen_port, cfg->subnet);

    /* ---- Main event loop ---- */
    event_base_dispatch(g_svr.eb);

    /* ---- Cleanup ---- */
    LOG_INF("server shutting down");
    if (g_svr.ev_sigterm) event_free(g_svr.ev_sigterm);
    if (g_svr.ev_sigint)  event_free(g_svr.ev_sigint);
    if (g_svr.ev_tun)          event_free(g_svr.ev_tun);
    if (g_svr.ev_tun_resume)  event_free(g_svr.ev_tun_resume);
    if (g_svr.ev_socket)      event_free(g_svr.ev_socket);
    if (g_svr.ev_engine)      event_free(g_svr.ev_engine);
    if (g_svr.udp_fd >= 0) close(g_svr.udp_fd);
    mqvpn_tun_destroy(&g_svr.tun);
    xqc_engine_destroy(g_svr.engine);
    event_base_free(g_svr.eb);

    return 0;
}
