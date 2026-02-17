#include "vpn_server.h"
#include "tun.h"
#include "addr_pool.h"
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
#include <inttypes.h>

#include <event2/event.h>
#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>

#define PACKET_BUF_SIZE      65536
#define MASQUE_FRAME_BUF     (PACKET_BUF_SIZE + 16)
#define TUN_RESUME_SAFETY_MS 100

static uint64_t
mpvpn_now_us(void)
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
    const mpvpn_server_cfg_t *cfg;

    xqc_engine_t        *engine;
    struct event_base   *eb;
    struct event        *ev_engine;  /* xquic timer */
    struct event        *ev_socket;  /* UDP socket read */
    struct event        *ev_tun;     /* TUN device read */
    struct event        *ev_tun_resume; /* safety timer to resume TUN read */
    struct event        *ev_sigint;
    struct event        *ev_sigterm;

    int                  udp_fd;
    struct sockaddr_in   local_addr;
    socklen_t            local_addrlen;

    mpvpn_tun_t          tun;
    int                  tun_paused;     /* TUN reading paused (QUIC backpressure) */
    uint64_t             tun_drop_cnt;   /* TUN write failure counter */
    mpvpn_addr_pool_t    pool;

    /* M1: single client — track the active conn for return traffic */
    svr_conn_t          *active_conn;
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
    int                   tunnel_established;
};

/* ---------- per-stream (request) state ---------- */

struct svr_stream_s {
    svr_conn_t          *conn;
    xqc_h3_request_t    *h3_request;
    int                  header_sent;
};

/* ---------- static context (M1: single instance) ---------- */

static svr_ctx_t g_svr;

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
    /* Route xquic logs through our logger at debug level */
    if (lvl <= XQC_LOG_WARN) {
        LOG_DBG("[xquic] %.*s", (int)size, (const char *)buf);
    }
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

        uint64_t recv_time = mpvpn_now_us();
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

static void
svr_tun_read_handler(int fd, short what, void *arg)
{
    (void)fd; (void)what;
    svr_ctx_t *ctx = (svr_ctx_t *)arg;

    if (!ctx->active_conn || !ctx->active_conn->tunnel_established) {
        /* Drain the fd even if no active tunnel */
        uint8_t discard[PACKET_BUF_SIZE];
        while (mpvpn_tun_read(&ctx->tun, discard, sizeof(discard)) > 0)
            ;
        return;
    }

    uint8_t pkt[PACKET_BUF_SIZE];
    uint8_t frame_buf[MASQUE_FRAME_BUF];

    for (;;) {
        int n = mpvpn_tun_read(&ctx->tun, pkt, sizeof(pkt));
        if (n <= 0) break;

        /* Frame with quarter-stream-ID + context_id=0 */
        size_t frame_written = 0;
        xqc_int_t xret = xqc_h3_ext_masque_frame_udp(
            frame_buf, sizeof(frame_buf), &frame_written,
            ctx->active_conn->masque_stream_id, pkt, (size_t)n);
        if (xret != XQC_OK) {
            LOG_ERR("masque_frame_udp: %d", xret);
            continue;
        }

        uint64_t dgram_id;
        xret = xqc_h3_ext_datagram_send(
            ctx->active_conn->h3_conn, frame_buf, frame_written,
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

    if (svr_conn->assigned_ip.s_addr) {
        mpvpn_addr_pool_release(&svr_conn->ctx->pool, &svr_conn->assigned_ip);
    }

    if (svr_conn->ctx->active_conn == svr_conn) {
        svr_conn->ctx->active_conn = NULL;
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
svr_masque_send_response(xqc_h3_request_t *h3_request, svr_stream_t *stream)
{
    svr_conn_t *conn = stream->conn;
    svr_ctx_t *ctx = conn->ctx;
    ssize_t ret;

    /* M1: refuse early if another client is already tunneled */
    if (ctx->active_conn && ctx->active_conn != conn
        && ctx->active_conn->tunnel_established) {
        LOG_WRN("rejecting new MASQUE tunnel: active connection exists");
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
    if (mpvpn_addr_pool_alloc(&ctx->pool, &conn->assigned_ip) < 0) {
        LOG_ERR("IP pool exhausted");
        return -1;
    }

    /* 3. Build and send ADDRESS_ASSIGN capsule */
    uint8_t addr_payload[64];
    size_t addr_written = 0;
    uint8_t ip_bytes[4];
    memcpy(ip_bytes, &conn->assigned_ip.s_addr, 4);

    xqc_int_t xret = xqc_h3_ext_connectip_build_address_request(
        addr_payload, sizeof(addr_payload), &addr_written,
        1,          /* request_id */
        4,          /* IPv4 */
        ip_bytes,
        32          /* /32 */
    );
    if (xret != XQC_OK) {
        LOG_ERR("build ADDRESS_ASSIGN payload: %d", xret);
        return -1;
    }

    uint8_t capsule_buf[128];
    size_t cap_written = 0;
    xret = xqc_h3_ext_capsule_encode(
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

    conn->tunnel_established = 1;
    ctx->active_conn = conn;
    LOG_INF("MASQUE tunnel established (stream_id=%" PRIu64 ")",
            conn->masque_stream_id);
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

        /* Detect Extended CONNECT for connect-ip */
        int is_connect = 0, is_connect_ip = 0;
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
        }

        if (is_connect && is_connect_ip) {
            LOG_INF("Extended CONNECT for connect-ip received");
            svr_masque_send_response(h3_request, stream);
            return 0;
        }
    }

    /* Drain any body data (capsule traffic from client — not expected in M1) */
    if (flag & XQC_REQ_NOTIFY_READ_BODY) {
        unsigned char discard[4096];
        ssize_t n;
        do {
            n = xqc_h3_request_recv_body(h3_request, discard, sizeof(discard), &fin);
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

    /* Write raw IP packet to TUN (kernel routes to internet via NAT) */
    int wret = mpvpn_tun_write(&svr_conn->ctx->tun, payload, payload_len);
    if (wret < 0) {
        svr_conn->ctx->tun_drop_cnt++;
        if (wret == MPVPN_TUN_EAGAIN) {
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
    (void)conn; (void)dgram_id; (void)user_data;
}

static int
svr_dgram_lost_notify(xqc_h3_conn_t *conn, uint64_t dgram_id,
                       void *user_data)
{
    (void)conn; (void)dgram_id; (void)user_data;
    LOG_DBG("datagram lost: %" PRIu64, dgram_id);
    return 0;
}

static void
svr_dgram_mss_updated_notify(xqc_h3_conn_t *conn, size_t mss,
                              void *user_data)
{
    (void)conn;
    svr_conn_t *svr_conn = (svr_conn_t *)user_data;
    LOG_INF("datagram MSS updated: %zu", mss);

    /* Update server TUN MTU based on QUIC datagram MSS */
    if (svr_conn && svr_conn->ctx) {
        size_t udp_mss = xqc_h3_ext_masque_udp_mss(
            mss, svr_conn->masque_stream_id);
        if (udp_mss >= 68) {
            mpvpn_tun_set_mtu(&svr_conn->ctx->tun, (int)udp_mss);
        }
    }
}

/* ================================================================
 *  UDP socket creation
 * ================================================================ */

static int
svr_create_udp_socket(const char *addr, int port, svr_ctx_t *ctx)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
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

    struct sockaddr_in *sin = &ctx->local_addr;
    memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;
    sin->sin_port = htons((uint16_t)port);
    if (addr && addr[0]) {
        sin->sin_addr.s_addr = inet_addr(addr);
    } else {
        sin->sin_addr.s_addr = htonl(INADDR_ANY);
    }
    ctx->local_addrlen = sizeof(*sin);

    if (bind(fd, (struct sockaddr *)sin, sizeof(*sin)) < 0) {
        LOG_ERR("bind %s:%d: %s", addr ? addr : "0.0.0.0", port, strerror(errno));
        close(fd);
        return -1;
    }

    LOG_INF("UDP socket bound to %s:%d", addr ? addr : "0.0.0.0", port);
    return fd;
}

/* ================================================================
 *  Server main
 * ================================================================ */

int
mpvpn_server_run(const mpvpn_server_cfg_t *cfg)
{
    memset(&g_svr, 0, sizeof(g_svr));
    g_svr.cfg = cfg;
    g_svr.tun.fd = -1;

    /* Initialize address pool */
    if (mpvpn_addr_pool_init(&g_svr.pool, cfg->subnet) < 0) {
        return -1;
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
    if (mpvpn_tun_create(&g_svr.tun, cfg->tun_name) < 0) {
        return -1;
    }

    /* Server gets .1, clients get .2+ */
    struct in_addr srv_addr;
    mpvpn_addr_pool_server_addr(&g_svr.pool, &srv_addr);
    char srv_ip[INET_ADDRSTRLEN], base_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &srv_addr, srv_ip, sizeof(srv_ip));
    inet_ntop(AF_INET, &g_svr.pool.base, base_ip, sizeof(base_ip));

    if (mpvpn_tun_set_addr(&g_svr.tun, srv_ip, base_ip,
                            g_svr.pool.prefix_len) < 0) {
        return -1;
    }
    if (mpvpn_tun_set_mtu(&g_svr.tun, 1280) < 0) {
        return -1;
    }
    if (mpvpn_tun_up(&g_svr.tun) < 0) {
        return -1;
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

    LOG_INF("mpvpn server ready — listening on %s:%d, subnet %s",
            cfg->listen_addr ? cfg->listen_addr : "0.0.0.0",
            cfg->listen_port, cfg->subnet);

    /* ---- Main event loop ---- */
    event_base_dispatch(g_svr.eb);

    /* ---- Cleanup ---- */
    LOG_INF("server shutting down");
    if (g_svr.ev_sigterm) event_free(g_svr.ev_sigterm);
    if (g_svr.ev_sigint)  event_free(g_svr.ev_sigint);
    if (g_svr.ev_tun)         event_free(g_svr.ev_tun);
    if (g_svr.ev_tun_resume) event_free(g_svr.ev_tun_resume);
    if (g_svr.ev_socket)     event_free(g_svr.ev_socket);
    if (g_svr.ev_engine)     event_free(g_svr.ev_engine);
    if (g_svr.udp_fd >= 0) close(g_svr.udp_fd);
    mpvpn_tun_destroy(&g_svr.tun);
    xqc_engine_destroy(g_svr.engine);
    event_base_free(g_svr.eb);

    return 0;
}
