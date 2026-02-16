#include "vpn_client.h"
#include "tun.h"
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
#include <net/if.h>
#include <inttypes.h>

#include <event2/event.h>
#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>

#define PACKET_BUF_SIZE  65536
#define MASQUE_FRAME_BUF 65536

static uint64_t
mpvpn_now_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;
}

/* ---------- forward declarations ---------- */

typedef struct cli_ctx_s        cli_ctx_t;
typedef struct cli_conn_s       cli_conn_t;
typedef struct cli_stream_s     cli_stream_t;

static void cli_tun_read_handler(int fd, short what, void *arg);

/* ---------- client context ---------- */

struct cli_ctx_s {
    const mpvpn_client_cfg_t *cfg;

    xqc_engine_t        *engine;
    struct event_base   *eb;
    struct event        *ev_engine;  /* xquic timer */
    struct event        *ev_socket;  /* UDP socket read */
    struct event        *ev_tun;     /* TUN device read (added after tunnel up) */

    int                  udp_fd;
    struct sockaddr_in   local_addr;
    socklen_t            local_addrlen;
    struct sockaddr_in   server_addr;
    socklen_t            server_addrlen;

    mpvpn_tun_t          tun;
    int                  tun_up;

    /* Split tunneling state */
    int                  routing_configured;
    char                 orig_gateway[INET_ADDRSTRLEN];
    char                 orig_iface[IFNAMSIZ];
    char                 server_ip_str[INET_ADDRSTRLEN];

    cli_conn_t          *conn;
};

/* ---------- per-connection state ---------- */

struct cli_conn_s {
    cli_ctx_t           *ctx;
    xqc_h3_conn_t       *h3_conn;
    xqc_cid_t            cid;
    size_t               dgram_mss;
    int                  fd;    /* UDP socket fd (same as ctx->udp_fd) */

    /* MASQUE session */
    xqc_h3_request_t    *masque_request;
    uint64_t             masque_stream_id;
    int                  tunnel_ok;       /* 200 received */
    int                  addr_assigned;   /* ADDRESS_ASSIGN received */
    uint8_t              assigned_ip[4];
    uint8_t              assigned_prefix;
};

/* ---------- per-stream state ---------- */

struct cli_stream_s {
    cli_conn_t          *conn;
    xqc_h3_request_t    *h3_request;
};

/* ---------- static context ---------- */

static cli_ctx_t g_cli;
static volatile sig_atomic_t g_running = 1;

static void
signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
    if (g_cli.eb) {
        event_base_loopbreak(g_cli.eb);
    }
}

/* ================================================================
 *  xquic log callback
 * ================================================================ */

static void
cli_xqc_log_write(xqc_log_level_t lvl, const void *buf, size_t size,
                   void *engine_user_data)
{
    (void)engine_user_data;
    if (lvl <= XQC_LOG_WARN) {
        LOG_DBG("[xquic] %.*s", (int)size, (const char *)buf);
    }
}

/* ================================================================
 *  Engine timer
 * ================================================================ */

static void
cli_set_event_timer(xqc_usec_t wake_after, void *engine_user_data)
{
    cli_ctx_t *ctx = (cli_ctx_t *)engine_user_data;
    struct timeval tv;
    tv.tv_sec  = (long)(wake_after / 1000000);
    tv.tv_usec = (long)(wake_after % 1000000);
    event_add(ctx->ev_engine, &tv);
}

static void
cli_engine_callback(int fd, short what, void *arg)
{
    (void)fd; (void)what;
    cli_ctx_t *ctx = (cli_ctx_t *)arg;
    xqc_engine_main_logic(ctx->engine);
}

/* ================================================================
 *  UDP socket write (xquic → network)
 * ================================================================ */

static ssize_t
cli_write_socket(const unsigned char *buf, size_t size,
                 const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                 void *conn_user_data)
{
    cli_conn_t *conn = (cli_conn_t *)conn_user_data;
    ssize_t res;
    do {
        res = sendto(conn->fd, buf, size, 0, peer_addr, peer_addrlen);
    } while (res < 0 && errno == EINTR);

    if (res < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return XQC_SOCKET_EAGAIN;
        }
        return XQC_SOCKET_ERROR;
    }
    return res;
}

static ssize_t
cli_write_socket_ex(uint64_t path_id,
                    const unsigned char *buf, size_t size,
                    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                    void *conn_user_data)
{
    (void)path_id;
    return cli_write_socket(buf, size, peer_addr, peer_addrlen, conn_user_data);
}

/* ================================================================
 *  UDP socket read (network → xquic)
 * ================================================================ */

static void
cli_socket_read_handler(cli_ctx_t *ctx)
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
        xqc_engine_packet_process(
            ctx->engine, buf, (size_t)n,
            (struct sockaddr *)&ctx->local_addr, ctx->local_addrlen,
            (struct sockaddr *)&peer_addr, peer_addrlen,
            (xqc_usec_t)recv_time, NULL);
    }
    xqc_engine_finish_recv(ctx->engine);
}

static void
cli_socket_event_callback(int fd, short what, void *arg)
{
    (void)fd;
    cli_ctx_t *ctx = (cli_ctx_t *)arg;
    if (what & EV_READ) {
        cli_socket_read_handler(ctx);
    }
}

/* ================================================================
 *  Split tunneling: route server IP via original gateway
 * ================================================================ */

static int
cli_setup_routes(cli_ctx_t *ctx)
{
    /* Extract server IP (without port) */
    struct in_addr saddr = { .s_addr = ctx->server_addr.sin_addr.s_addr };
    inet_ntop(AF_INET, &saddr, ctx->server_ip_str, sizeof(ctx->server_ip_str));

    /* Discover current gateway and interface for the server IP */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip route get %s", ctx->server_ip_str);
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        LOG_WRN("popen(ip route get) failed: %s", strerror(errno));
        return -1;
    }

    char line[512];
    ctx->orig_gateway[0] = '\0';
    ctx->orig_iface[0] = '\0';

    while (fgets(line, sizeof(line), fp)) {
        char *via = strstr(line, "via ");
        if (via && ctx->orig_gateway[0] == '\0') {
            sscanf(via + 4, "%15s", ctx->orig_gateway);
        }
        char *dev = strstr(line, "dev ");
        if (dev && ctx->orig_iface[0] == '\0') {
            sscanf(dev + 4, "%15s", ctx->orig_iface);
        }
    }
    pclose(fp);

    if (ctx->orig_gateway[0] == '\0' || ctx->orig_iface[0] == '\0') {
        LOG_WRN("could not determine original gateway/iface for %s",
                ctx->server_ip_str);
        return -1;
    }

    LOG_INF("split tunnel: server %s via %s dev %s",
            ctx->server_ip_str, ctx->orig_gateway, ctx->orig_iface);

    /* Pin server IP to original route */
    snprintf(cmd, sizeof(cmd),
             "ip route add %s/32 via %s dev %s 2>/dev/null || true",
             ctx->server_ip_str, ctx->orig_gateway, ctx->orig_iface);
    if (system(cmd)) { /* best-effort */ }

    /* Set default route through TUN */
    snprintf(cmd, sizeof(cmd),
             "ip route add default dev %s metric 10 2>/dev/null || true",
             ctx->tun.name);
    if (system(cmd)) { /* best-effort */ }

    ctx->routing_configured = 1;
    return 0;
}

static void
cli_cleanup_routes(cli_ctx_t *ctx)
{
    if (!ctx->routing_configured)
        return;

    char cmd[256];

    /* Remove TUN default route */
    snprintf(cmd, sizeof(cmd), "ip route del default dev %s 2>/dev/null || true",
             ctx->tun.name);
    if (system(cmd)) { /* best-effort */ }

    /* Remove server IP pinned route */
    snprintf(cmd, sizeof(cmd), "ip route del %s/32 via %s dev %s 2>/dev/null || true",
             ctx->server_ip_str, ctx->orig_gateway, ctx->orig_iface);
    if (system(cmd)) { /* best-effort */ }

    ctx->routing_configured = 0;
    LOG_INF("split tunnel routes cleaned up");
}

/* ================================================================
 *  TUN device setup (called after ADDRESS_ASSIGN)
 * ================================================================ */

static int
cli_setup_tun(cli_ctx_t *ctx, const uint8_t *ip, uint8_t prefix)
{
    (void)prefix;

    if (mpvpn_tun_create(&ctx->tun, ctx->cfg->tun_name) < 0) {
        return -1;
    }

    char local_ip[INET_ADDRSTRLEN];
    snprintf(local_ip, sizeof(local_ip), "%d.%d.%d.%d",
             ip[0], ip[1], ip[2], ip[3]);

    /* Peer is .1 (server side of the tunnel) */
    char peer_ip[INET_ADDRSTRLEN];
    snprintf(peer_ip, sizeof(peer_ip), "%d.%d.%d.1", ip[0], ip[1], ip[2]);

    if (mpvpn_tun_set_addr(&ctx->tun, local_ip, peer_ip, 32) < 0) {
        return -1;
    }
    if (mpvpn_tun_set_mtu(&ctx->tun, 1280) < 0) {
        return -1;
    }
    if (mpvpn_tun_up(&ctx->tun) < 0) {
        return -1;
    }

    /* Register TUN read event */
    ctx->ev_tun = event_new(ctx->eb, ctx->tun.fd,
                             EV_READ | EV_PERSIST,
                             cli_tun_read_handler, ctx);
    event_add(ctx->ev_tun, NULL);
    ctx->tun_up = 1;

    LOG_INF("TUN %s configured: %s → %s", ctx->tun.name, local_ip, peer_ip);

    /* Set up split tunneling routes */
    cli_setup_routes(ctx);

    return 0;
}

/* ================================================================
 *  TUN read handler (local apps → MASQUE datagram to server)
 * ================================================================ */

static void
cli_tun_read_handler(int fd, short what, void *arg)
{
    (void)fd; (void)what;
    cli_ctx_t *ctx = (cli_ctx_t *)arg;
    cli_conn_t *conn = ctx->conn;

    if (!conn || !conn->tunnel_ok) return;

    uint8_t pkt[PACKET_BUF_SIZE];
    uint8_t frame_buf[MASQUE_FRAME_BUF];

    for (;;) {
        int n = mpvpn_tun_read(&ctx->tun, pkt, sizeof(pkt));
        if (n <= 0) break;

        size_t frame_written = 0;
        xqc_int_t xret = xqc_h3_ext_masque_frame_udp(
            frame_buf, sizeof(frame_buf), &frame_written,
            conn->masque_stream_id, pkt, (size_t)n);
        if (xret != XQC_OK) {
            LOG_ERR("masque_frame_udp: %d", xret);
            continue;
        }

        uint64_t dgram_id;
        xret = xqc_h3_ext_datagram_send(
            conn->h3_conn, frame_buf, frame_written,
            &dgram_id, XQC_DATA_QOS_HIGH);
        if (xret < 0 && xret != -XQC_EAGAIN) {
            LOG_DBG("datagram_send: %d", xret);
        }
    }

    xqc_engine_main_logic(ctx->engine);
}

/* ================================================================
 *  H3 connection callbacks
 * ================================================================ */

static int
cli_h3_conn_create_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
                           void *user_data)
{
    (void)cid;
    cli_conn_t *conn = (cli_conn_t *)user_data;
    conn->h3_conn = h3_conn;
    conn->dgram_mss = xqc_h3_ext_datagram_get_mss(h3_conn);
    return 0;
}

static int
cli_h3_conn_close_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
                          void *user_data)
{
    (void)h3_conn; (void)cid;
    cli_conn_t *conn = (cli_conn_t *)user_data;
    int err = xqc_h3_conn_get_errno(h3_conn);
    LOG_INF("connection closed (errno=%d)", err);

    if (conn->ctx->eb) {
        event_base_loopbreak(conn->ctx->eb);
    }
    return 0;
}

/* ================================================================
 *  MASQUE tunnel start (called after handshake)
 * ================================================================ */

static int
cli_masque_start_tunnel(cli_conn_t *conn)
{
    cli_stream_t *stream = calloc(1, sizeof(*stream));
    if (!stream) return -1;
    stream->conn = conn;

    xqc_h3_request_t *req = xqc_h3_request_create(
        conn->ctx->engine, &conn->cid, NULL, stream);
    if (!req) {
        LOG_ERR("xqc_h3_request_create failed");
        free(stream);
        return -1;
    }
    stream->h3_request = req;
    conn->masque_request = req;

    /* Build Extended CONNECT headers */
    char authority[256];
    snprintf(authority, sizeof(authority), "%s:%d",
             conn->ctx->cfg->server_addr, conn->ctx->cfg->server_port);

    xqc_http_header_t hdrs[] = {
        { .name  = {.iov_base = ":method",   .iov_len = 7},
          .value = {.iov_base = "CONNECT",   .iov_len = 7},    .flags = 0 },
        { .name  = {.iov_base = ":protocol", .iov_len = 9},
          .value = {.iov_base = "connect-ip",.iov_len = 10},   .flags = 0 },
        { .name  = {.iov_base = ":scheme",   .iov_len = 7},
          .value = {.iov_base = "https",     .iov_len = 5},    .flags = 0 },
        { .name  = {.iov_base = ":authority",.iov_len = 10},
          .value = {.iov_base = authority,   .iov_len = strlen(authority)}, .flags = 0 },
        { .name  = {.iov_base = ":path",     .iov_len = 5},
          .value = {.iov_base = "/.well-known/masque/ip/*/*/", .iov_len = 27}, .flags = 0 },
        { .name  = {.iov_base = "capsule-protocol", .iov_len = 16},
          .value = {.iov_base = "?1",        .iov_len = 2},    .flags = 0 },
    };
    xqc_http_headers_t headers = {
        .headers  = hdrs,
        .count    = 6,
        .capacity = 6,
    };

    ssize_t ret = xqc_h3_request_send_headers(req, &headers, 0);
    if (ret < 0) {
        LOG_ERR("send Extended CONNECT: %zd", ret);
        return -1;
    }

    conn->masque_stream_id = xqc_h3_stream_id(req);
    LOG_INF("Extended CONNECT sent (stream_id=%" PRIu64 ")",
            conn->masque_stream_id);
    return 0;
}

static void
cli_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data)
{
    cli_conn_t *conn = (cli_conn_t *)user_data;
    conn->dgram_mss = xqc_h3_ext_datagram_get_mss(h3_conn);
    LOG_INF("handshake finished (dgram_mss=%zu)", conn->dgram_mss);
    cli_masque_start_tunnel(conn);
}

/* ================================================================
 *  H3 request callbacks (capsule parsing)
 * ================================================================ */

static int
cli_request_close_notify(xqc_h3_request_t *h3_request,
                          void *strm_user_data)
{
    (void)h3_request;
    cli_stream_t *stream = (cli_stream_t *)strm_user_data;
    if (stream) {
        if (stream->conn) {
            stream->conn->tunnel_ok = 0;
        }
        free(stream);
    }
    return 0;
}

static int
cli_request_read_notify(xqc_h3_request_t *h3_request,
                         xqc_request_notify_flag_t flag, void *strm_user_data)
{
    cli_stream_t *stream = (cli_stream_t *)strm_user_data;
    cli_conn_t *conn = stream->conn;
    unsigned char fin = 0;

    /* Handle response headers (200 OK) */
    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        xqc_http_headers_t *headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (headers) {
            for (int i = 0; i < (int)headers->count; i++) {
                xqc_http_header_t *h = &headers->headers[i];
                if (h->name.iov_len == 7
                    && memcmp(h->name.iov_base, ":status", 7) == 0
                    && h->value.iov_len == 3
                    && memcmp(h->value.iov_base, "200", 3) == 0) {
                    conn->tunnel_ok = 1;
                    LOG_INF("tunnel 200 OK");
                }
            }
        }
    }

    /* Handle body (capsules) */
    if (flag & XQC_REQ_NOTIFY_READ_BODY) {
        unsigned char buf[4096];
        ssize_t n;
        do {
            n = xqc_h3_request_recv_body(h3_request, buf, sizeof(buf), &fin);
            if (n <= 0) break;

            const uint8_t *p = (const uint8_t *)buf;
            size_t remain = (size_t)n;

            while (remain > 0) {
                uint64_t cap_type;
                const uint8_t *cap_payload;
                size_t cap_len, consumed;

                xqc_int_t xret = xqc_h3_ext_capsule_decode(
                    p, remain, &cap_type, &cap_payload, &cap_len, &consumed);
                if (xret != XQC_OK) {
                    LOG_DBG("capsule decode: %d (remain=%zu)", xret, remain);
                    break;
                }

                if (cap_type == XQC_H3_CAPSULE_ADDRESS_ASSIGN) {
                    uint64_t req_id;
                    uint8_t ip_ver, ip_addr[16], prefix;
                    size_t ip_len = 16;
                    xret = xqc_h3_ext_connectip_parse_address_assign(
                        cap_payload, cap_len, &req_id, &ip_ver,
                        ip_addr, &ip_len, &prefix);
                    if (xret == XQC_OK && ip_ver == 4) {
                        memcpy(conn->assigned_ip, ip_addr, 4);
                        conn->assigned_prefix = prefix;
                        conn->addr_assigned = 1;
                        LOG_INF("ADDRESS_ASSIGN: %d.%d.%d.%d/%d",
                                ip_addr[0], ip_addr[1], ip_addr[2],
                                ip_addr[3], prefix);
                    }
                } else if (cap_type == XQC_H3_CAPSULE_ROUTE_ADVERTISEMENT) {
                    uint8_t ip_ver, start_ip[16], end_ip[16], ip_proto;
                    size_t ip_len, bytes_consumed;

                    const uint8_t *rp = cap_payload;
                    size_t rremain = cap_len;
                    while (rremain > 0) {
                        ip_len = 16;
                        xret = xqc_h3_ext_connectip_parse_route_advertisement(
                            rp, rremain, &ip_ver, start_ip, end_ip,
                            &ip_len, &ip_proto, &bytes_consumed);
                        if (xret != XQC_OK) break;
                        LOG_INF("ROUTE_ADVERTISEMENT: ipv%d proto=%d "
                                "%d.%d.%d.%d-%d.%d.%d.%d",
                                ip_ver, ip_proto,
                                start_ip[0], start_ip[1], start_ip[2], start_ip[3],
                                end_ip[0], end_ip[1], end_ip[2], end_ip[3]);
                        rp += bytes_consumed;
                        rremain -= bytes_consumed;
                    }
                }

                p += consumed;
                remain -= consumed;
            }
        } while (n > 0 && !fin);

        /* Set up TUN after ADDRESS_ASSIGN */
        if (conn->addr_assigned && !conn->ctx->tun_up) {
            cli_setup_tun(conn->ctx, conn->assigned_ip, conn->assigned_prefix);
        }
    }

    return 0;
}

static int
cli_request_write_notify(xqc_h3_request_t *h3_request,
                          void *strm_user_data)
{
    (void)h3_request; (void)strm_user_data;
    return 0;
}

/* ================================================================
 *  H3 datagram callbacks (server → client: IP packets)
 * ================================================================ */

static void
cli_dgram_read_notify(xqc_h3_conn_t *h3_conn, const void *data,
                       size_t data_len, void *user_data, uint64_t ts)
{
    (void)h3_conn; (void)ts;
    cli_conn_t *conn = (cli_conn_t *)user_data;
    if (!conn || !conn->ctx->tun_up) return;

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

    /* Write IP packet to TUN (delivered to local apps) */
    mpvpn_tun_write(&conn->ctx->tun, payload, payload_len);
}

static void
cli_dgram_write_notify(xqc_h3_conn_t *conn, void *user_data)
{
    (void)conn; (void)user_data;
}

static void
cli_dgram_acked_notify(xqc_h3_conn_t *conn, uint64_t dgram_id,
                        void *user_data)
{
    (void)conn; (void)dgram_id; (void)user_data;
}

static int
cli_dgram_lost_notify(xqc_h3_conn_t *conn, uint64_t dgram_id,
                       void *user_data)
{
    (void)conn; (void)dgram_id; (void)user_data;
    return 0;
}

static void
cli_dgram_mss_updated_notify(xqc_h3_conn_t *conn, size_t mss,
                              void *user_data)
{
    (void)conn;
    cli_conn_t *cli_conn = (cli_conn_t *)user_data;
    if (cli_conn) {
        cli_conn->dgram_mss = mss;
    }
    LOG_INF("datagram MSS updated: %zu", mss);
}

/* ================================================================
 *  TLS session callbacks (stubs for M1)
 * ================================================================ */

static void
cli_save_token(const unsigned char *token, unsigned token_len, void *user_data)
{
    (void)token; (void)token_len; (void)user_data;
}

static void
cli_save_session_cb(const char *data, size_t data_len, void *user_data)
{
    (void)data; (void)data_len; (void)user_data;
}

static void
cli_save_tp_cb(const char *data, size_t data_len, void *user_data)
{
    (void)data; (void)data_len; (void)user_data;
}

/* ================================================================
 *  UDP socket creation
 * ================================================================ */

static int
cli_create_udp_socket(cli_ctx_t *ctx)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOG_ERR("socket: %s", strerror(errno));
        return -1;
    }

    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        close(fd);
        return -1;
    }

    int bufsize = 1 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    /* Bind to any local address */
    memset(&ctx->local_addr, 0, sizeof(ctx->local_addr));
    ctx->local_addr.sin_family = AF_INET;
    ctx->local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    ctx->local_addrlen = sizeof(ctx->local_addr);

    if (bind(fd, (struct sockaddr *)&ctx->local_addr, sizeof(ctx->local_addr)) < 0) {
        LOG_ERR("bind: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* Resolve server address */
    memset(&ctx->server_addr, 0, sizeof(ctx->server_addr));
    ctx->server_addr.sin_family = AF_INET;
    ctx->server_addr.sin_port = htons((uint16_t)ctx->cfg->server_port);
    if (inet_pton(AF_INET, ctx->cfg->server_addr, &ctx->server_addr.sin_addr) != 1) {
        LOG_ERR("invalid server address: %s", ctx->cfg->server_addr);
        close(fd);
        return -1;
    }
    ctx->server_addrlen = sizeof(ctx->server_addr);

    return fd;
}

/* ================================================================
 *  Client main
 * ================================================================ */

int
mpvpn_client_run(const mpvpn_client_cfg_t *cfg)
{
    memset(&g_cli, 0, sizeof(g_cli));
    g_cli.cfg = cfg;
    g_cli.tun.fd = -1;
    g_running = 1;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    /* Create event base */
    g_cli.eb = event_base_new();
    if (!g_cli.eb) {
        LOG_ERR("event_base_new failed");
        return -1;
    }

    g_cli.ev_engine = event_new(g_cli.eb, -1, 0, cli_engine_callback, &g_cli);

    /* ---- xquic engine setup ---- */
    xqc_engine_ssl_config_t engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups  = XQC_TLS_GROUPS;

    xqc_engine_callback_t engine_cbs = {
        .set_event_timer = cli_set_event_timer,
        .log_callbacks = {
            .xqc_log_write_err  = cli_xqc_log_write,
            .xqc_log_write_stat = cli_xqc_log_write,
        },
    };

    xqc_transport_callbacks_t tcbs = {
        .write_socket    = cli_write_socket,
        .write_socket_ex = cli_write_socket_ex,
        .save_token      = cli_save_token,
        .save_session_cb = cli_save_session_cb,
        .save_tp_cb      = cli_save_tp_cb,
    };

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_CLIENT) < 0) {
        LOG_ERR("xqc_engine_get_default_config failed");
        return -1;
    }
    config.cfg_log_level = (xqc_log_level_t)cfg->log_level;

    g_cli.engine = xqc_engine_create(XQC_ENGINE_CLIENT, &config,
                                      &engine_ssl_config, &engine_cbs,
                                      &tcbs, &g_cli);
    if (!g_cli.engine) {
        LOG_ERR("xqc_engine_create failed");
        return -1;
    }

    /* H3 callbacks */
    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs = {
            .h3_conn_create_notify      = cli_h3_conn_create_notify,
            .h3_conn_close_notify       = cli_h3_conn_close_notify,
            .h3_conn_handshake_finished = cli_h3_conn_handshake_finished,
        },
        .h3r_cbs = {
            .h3_request_close_notify  = cli_request_close_notify,
            .h3_request_read_notify   = cli_request_read_notify,
            .h3_request_write_notify  = cli_request_write_notify,
        },
        .h3_ext_dgram_cbs = {
            .dgram_read_notify        = cli_dgram_read_notify,
            .dgram_write_notify       = cli_dgram_write_notify,
            .dgram_acked_notify       = cli_dgram_acked_notify,
            .dgram_lost_notify        = cli_dgram_lost_notify,
            .dgram_mss_updated_notify = cli_dgram_mss_updated_notify,
        },
    };

    xqc_int_t ret = xqc_h3_ctx_init(g_cli.engine, &h3_cbs);
    if (ret != XQC_OK) {
        LOG_ERR("xqc_h3_ctx_init: %d", ret);
        return -1;
    }

    /* H3 settings: Extended CONNECT + datagram */
    xqc_h3_conn_settings_t h3s = {
        .max_field_section_size       = 32 * 1024,
        .qpack_blocked_streams        = 64,
        .qpack_enc_max_table_capacity = 16 * 1024,
        .qpack_dec_max_table_capacity = 16 * 1024,
        .enable_connect_protocol      = 1,
        .h3_datagram                  = 1,
    };
    xqc_h3_engine_set_local_settings(g_cli.engine, &h3s);

    /* ---- Create UDP socket ---- */
    g_cli.udp_fd = cli_create_udp_socket(&g_cli);
    if (g_cli.udp_fd < 0) {
        return -1;
    }

    g_cli.ev_socket = event_new(g_cli.eb, g_cli.udp_fd,
                                 EV_READ | EV_PERSIST,
                                 cli_socket_event_callback, &g_cli);
    event_add(g_cli.ev_socket, NULL);

    /* ---- Create H3 connection ---- */
    cli_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) {
        LOG_ERR("calloc conn");
        return -1;
    }
    conn->ctx = &g_cli;
    conn->fd  = g_cli.udp_fd;
    g_cli.conn = conn;

    xqc_conn_settings_t conn_settings;
    memset(&conn_settings, 0, sizeof(conn_settings));
    conn_settings.max_datagram_frame_size = 65535;
    conn_settings.proto_version = XQC_VERSION_V1;

    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));
    if (!cfg->insecure) {
        conn_ssl_config.cert_verify_flag = XQC_TLS_CERT_FLAG_NEED_VERIFY;
    }

    const xqc_cid_t *cid = xqc_h3_connect(
        g_cli.engine, &conn_settings,
        NULL, 0,                    /* no token for first connection */
        cfg->server_addr, 0,        /* no_crypt = 0 */
        &conn_ssl_config,
        (struct sockaddr *)&g_cli.server_addr, g_cli.server_addrlen,
        conn);
    if (!cid) {
        LOG_ERR("xqc_h3_connect failed");
        free(conn);
        return -1;
    }

    memcpy(&conn->cid, cid, sizeof(*cid));

    if (conn->h3_conn) {
        xqc_h3_ext_datagram_set_user_data(conn->h3_conn, conn);
    }

    LOG_INF("connecting to %s:%d ...", cfg->server_addr, cfg->server_port);

    /* ---- Main event loop ---- */
    event_base_dispatch(g_cli.eb);

    /* ---- Cleanup ---- */
    LOG_INF("client shutting down");
    cli_cleanup_routes(&g_cli);
    if (g_cli.ev_tun)    event_free(g_cli.ev_tun);
    if (g_cli.ev_socket) event_free(g_cli.ev_socket);
    if (g_cli.ev_engine) event_free(g_cli.ev_engine);
    if (g_cli.udp_fd >= 0) close(g_cli.udp_fd);
    mpvpn_tun_destroy(&g_cli.tun);
    xqc_engine_destroy(g_cli.engine);
    event_base_free(g_cli.eb);
    free(conn);

    return 0;
}
