#include "vpn_client.h"
#include "path_mgr.h"
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
#include <sys/wait.h>

#include <event2/event.h>
#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>

#define PACKET_BUF_SIZE  65536
#define MASQUE_FRAME_BUF (PACKET_BUF_SIZE + 16)

#define PATH_RECREATE_DELAY_SEC   5
#define PATH_RECREATE_MAX_RETRIES 6
#define TUN_RESUME_SAFETY_MS      100
#define XQC_SNDQ_MAX_PKTS         16384

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
    struct event        *ev_tun;     /* TUN device read (added after tunnel up) */
    struct event        *ev_sigint;
    struct event        *ev_sigterm;
    struct event        *ev_path_recreate;  /* timer to re-create removed paths */
    struct event        *ev_tun_resume;     /* safety timer to resume TUN read */
    int                  path_recreate_retries;

    /* Multipath: per-path UDP sockets */
    mpvpn_path_mgr_t     path_mgr;
    struct sockaddr_in   server_addr;
    socklen_t            server_addrlen;

    mpvpn_tun_t          tun;
    int                  tun_up;
    int                  tun_paused;     /* TUN reading paused (QUIC backpressure) */
    uint64_t             tun_drop_cnt;   /* TUN write failure counter */

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

    /* MASQUE session */
    xqc_h3_request_t    *masque_request;
    uint64_t             masque_stream_id;
    int                  tunnel_ok;       /* 200 received */
    int                  addr_assigned;   /* ADDRESS_ASSIGN received */
    uint8_t              assigned_ip[4];
    uint8_t              assigned_prefix;
    uint64_t             dgram_lost_cnt;
    uint64_t             dgram_acked_cnt;
};

/* ---------- per-stream state ---------- */

struct cli_stream_s {
    cli_conn_t          *conn;
    xqc_h3_request_t    *h3_request;
    uint8_t             *capsule_buf;
    size_t               capsule_len;
    size_t               capsule_cap;
};

/* ---------- static context ---------- */

static cli_ctx_t g_cli;

static void
cli_log_conn_stats(const char *tag, const xqc_cid_t *cid)
{
    if (!g_cli.engine || !cid) {
        return;
    }
    xqc_conn_stats_t st = xqc_conn_get_stats(g_cli.engine, cid);
    LOG_INF("%s: send=%u recv=%u lost=%u lost_dgram=%u srtt=%.2fms min_rtt=%.2fms inflight=%" PRIu64 " app_bytes=%" PRIu64 " standby_bytes=%" PRIu64 " mp_state=%d",
            tag,
            st.send_count, st.recv_count, st.lost_count, st.lost_dgram_count,
            (double)st.srtt / 1000.0, (double)st.min_rtt / 1000.0,
            st.inflight_bytes, st.total_app_bytes, st.standby_path_app_bytes,
            st.mp_state);
}

static void
cli_signal_event_callback(evutil_socket_t sig, short events, void *arg)
{
    (void)sig;
    (void)events;
    cli_ctx_t *ctx = (cli_ctx_t *)arg;
    event_base_loopbreak(ctx->eb);
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
    /* Legacy single-path write — use primary path */
    cli_conn_t *conn = (cli_conn_t *)conn_user_data;
    int fd = mpvpn_path_mgr_get_fd(&conn->ctx->path_mgr, 0);
    ssize_t res;
    do {
        res = sendto(fd, buf, size, 0, peer_addr, peer_addrlen);
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
    cli_conn_t *conn = (cli_conn_t *)conn_user_data;
    int fd = mpvpn_path_mgr_get_fd(&conn->ctx->path_mgr, path_id);
    ssize_t res;
    do {
        res = sendto(fd, buf, size, 0, peer_addr, peer_addrlen);
    } while (res < 0 && errno == EINTR);

    if (res < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return XQC_SOCKET_EAGAIN;
        }
        return XQC_SOCKET_ERROR;
    }
    return res;
}

/* ================================================================
 *  UDP socket read (network → xquic)
 * ================================================================ */

static void
cli_socket_read_handler(cli_ctx_t *ctx, int sock_fd)
{
    unsigned char buf[PACKET_BUF_SIZE];
    struct sockaddr_in6 peer_addr;
    socklen_t peer_addrlen = sizeof(peer_addr);

    /* Find local addr for this path's socket */
    mpvpn_path_t *path = mpvpn_path_mgr_find_by_fd(&ctx->path_mgr, sock_fd);
    struct sockaddr_in local_addr;
    socklen_t local_addrlen = sizeof(local_addr);
    if (path) {
        memcpy(&local_addr, &path->local_addr, sizeof(local_addr));
        local_addrlen = path->local_addrlen;
    } else {
        memset(&local_addr, 0, sizeof(local_addr));
    }

    for (;;) {
        ssize_t n = recvfrom(sock_fd, buf, sizeof(buf), 0,
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
            (struct sockaddr *)&local_addr, local_addrlen,
            (struct sockaddr *)&peer_addr, peer_addrlen,
            (xqc_usec_t)recv_time, NULL);
    }
    xqc_engine_finish_recv(ctx->engine);
}

static void
cli_socket_event_callback(int fd, short what, void *arg)
{
    cli_ctx_t *ctx = (cli_ctx_t *)arg;
    if (what & EV_READ) {
        cli_socket_read_handler(ctx, fd);
    }
}

/* ================================================================
 *  Split tunneling: route server IP via original gateway
 * ================================================================ */

static int
cli_run_ip_cmd(const char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) {
        LOG_WRN("fork for ip command failed: %s", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        execvp("ip", (char * const *)argv);
        _exit(127);
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) {
            continue;
        }
        LOG_WRN("waitpid failed: %s", strerror(errno));
        return -1;
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return -1;
    }
    return 0;
}

static int
cli_discover_route(const char *server_ip, char *gateway, size_t gateway_len,
                    char *iface, size_t iface_len)
{
    int fds[2];
    if (pipe(fds) < 0) {
        LOG_WRN("pipe failed: %s", strerror(errno));
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        LOG_WRN("fork failed: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        const char *const argv[] = {"ip", "-4", "route", "get", server_ip, NULL};
        close(fds[0]);
        if (dup2(fds[1], STDOUT_FILENO) < 0) {
            _exit(127);
        }
        close(fds[1]);
        execvp("ip", (char * const *)argv);
        _exit(127);
    }

    close(fds[1]);
    char out[1024];
    ssize_t nread = read(fds[0], out, sizeof(out) - 1);
    close(fds[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            return -1;
        }
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || nread <= 0) {
        return -1;
    }

    out[nread] = '\0';
    gateway[0] = '\0';
    iface[0] = '\0';

    char *saveptr = NULL;
    for (char *tok = strtok_r(out, " \t\r\n", &saveptr);
         tok;
         tok = strtok_r(NULL, " \t\r\n", &saveptr)) {
        if (strcmp(tok, "via") == 0) {
            tok = strtok_r(NULL, " \t\r\n", &saveptr);
            if (tok) {
                snprintf(gateway, gateway_len, "%s", tok);
            }
            continue;
        }
        if (strcmp(tok, "dev") == 0) {
            tok = strtok_r(NULL, " \t\r\n", &saveptr);
            if (tok) {
                snprintf(iface, iface_len, "%s", tok);
            }
            continue;
        }
    }

    if (gateway[0] == '\0' || iface[0] == '\0') {
        return -1;
    }
    return 0;
}

static int
cli_setup_routes(cli_ctx_t *ctx)
{
    /* Extract server IP (without port) */
    struct in_addr saddr = { .s_addr = ctx->server_addr.sin_addr.s_addr };
    inet_ntop(AF_INET, &saddr, ctx->server_ip_str, sizeof(ctx->server_ip_str));

    /* Discover current gateway and interface for the server IP */
    if (cli_discover_route(ctx->server_ip_str, ctx->orig_gateway, sizeof(ctx->orig_gateway),
                            ctx->orig_iface, sizeof(ctx->orig_iface)) < 0) {
        LOG_WRN("could not determine original gateway/iface for %s",
                ctx->server_ip_str);
        return -1;
    }

    LOG_INF("split tunnel: server %s via %s dev %s",
            ctx->server_ip_str, ctx->orig_gateway, ctx->orig_iface);

    char host_cidr[INET_ADDRSTRLEN + 4];
    snprintf(host_cidr, sizeof(host_cidr), "%s/32", ctx->server_ip_str);
    const char *const pin_route[] = {
        "ip", "route", "replace", host_cidr, "via", ctx->orig_gateway,
        "dev", ctx->orig_iface, NULL
    };
    if (cli_run_ip_cmd(pin_route) < 0) {
        LOG_WRN("failed to pin server route");
        return -1;
    }

    const char *const tun_default[] = {
        "ip", "route", "replace", "default", "dev", ctx->tun.name,
        "metric", "10", NULL
    };
    if (cli_run_ip_cmd(tun_default) < 0) {
        LOG_WRN("failed to set default route via %s", ctx->tun.name);
        const char *const undo_pin[] = {
            "ip", "route", "del", host_cidr, "via", ctx->orig_gateway,
            "dev", ctx->orig_iface, NULL
        };
        (void)cli_run_ip_cmd(undo_pin);
        return -1;
    }

    ctx->routing_configured = 1;
    return 0;
}

static void
cli_cleanup_routes(cli_ctx_t *ctx)
{
    if (!ctx->routing_configured)
        return;

    /* Remove TUN default route */
    const char *const del_default[] = {
        "ip", "route", "del", "default", "dev", ctx->tun.name, NULL
    };
    (void)cli_run_ip_cmd(del_default);

    /* Remove server IP pinned route */
    char host_cidr[INET_ADDRSTRLEN + 4];
    snprintf(host_cidr, sizeof(host_cidr), "%s/32", ctx->server_ip_str);
    const char *const del_pin[] = {
        "ip", "route", "del", host_cidr, "via", ctx->orig_gateway,
        "dev", ctx->orig_iface, NULL
    };
    (void)cli_run_ip_cmd(del_pin);

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
    /* Set MTU based on QUIC datagram MSS minus MASQUE framing overhead */
    int tun_mtu = 1280;
    if (ctx->conn && ctx->conn->dgram_mss > 0) {
        size_t udp_mss = xqc_h3_ext_masque_udp_mss(
            ctx->conn->dgram_mss, ctx->conn->masque_stream_id);
        if (udp_mss >= 68) {
            tun_mtu = (int)udp_mss;
        }
        LOG_INF("TUN MTU from dgram_mss=%zu masque_udp_mss=%zu → %d",
                ctx->conn->dgram_mss, udp_mss, tun_mtu);
    }
    if (mpvpn_tun_set_mtu(&ctx->tun, tun_mtu) < 0) {
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
cli_tun_resume_safety(int fd, short what, void *arg)
{
    (void)fd; (void)what;
    cli_ctx_t *ctx = (cli_ctx_t *)arg;
    if (ctx->tun_paused && ctx->ev_tun) {
        event_add(ctx->ev_tun, NULL);
        ctx->tun_paused = 0;
        LOG_DBG("TUN read resumed (safety timer)");
    }
}

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

        /* Validate source IP matches assigned address */
        if (n >= 20 && (pkt[0] >> 4) == 4 && conn->addr_assigned) {
            if (memcmp(pkt + 12, conn->assigned_ip, 4) != 0) {
                LOG_DBG("dropping outbound packet: src IP mismatch");
                continue;
            }
        }

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
    cli_log_conn_stats("client conn stats",
                       cid ? cid : &conn->cid);
    LOG_INF("client dgram summary: acked=%" PRIu64 " lost=%" PRIu64,
            conn->dgram_acked_cnt, conn->dgram_lost_cnt);

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
        free(stream);
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
        free(stream->capsule_buf);
        free(stream);
    }
    return 0;
}

#define MAX_CAPSULE_BUF  65536

static int
cli_stream_append_capsules(cli_stream_t *stream, const uint8_t *buf, size_t len)
{
    if (len == 0) {
        return 0;
    }

    size_t need = stream->capsule_len + len;
    if (need > MAX_CAPSULE_BUF) {
        LOG_ERR("capsule buffer exceeds max (%zu > %d)", need, MAX_CAPSULE_BUF);
        return -1;
    }
    if (need > stream->capsule_cap) {
        size_t new_cap = stream->capsule_cap ? stream->capsule_cap * 2 : 4096;
        while (new_cap < need) {
            new_cap *= 2;
        }
        uint8_t *new_buf = realloc(stream->capsule_buf, new_cap);
        if (!new_buf) {
            return -1;
        }
        stream->capsule_buf = new_buf;
        stream->capsule_cap = new_cap;
    }

    memcpy(stream->capsule_buf + stream->capsule_len, buf, len);
    stream->capsule_len += len;
    return 0;
}

static void
cli_process_capsules(cli_stream_t *stream)
{
    cli_conn_t *conn = stream->conn;

    while (stream->capsule_len > 0) {
        uint64_t cap_type;
        const uint8_t *cap_payload;
        size_t cap_len, consumed;

        xqc_int_t xret = xqc_h3_ext_capsule_decode(
            stream->capsule_buf, stream->capsule_len,
            &cap_type, &cap_payload, &cap_len, &consumed);
        if (xret != XQC_OK) {
            break;
        }

        if (cap_type == XQC_H3_CAPSULE_ADDRESS_ASSIGN) {
            uint64_t req_id;
            uint8_t ip_ver, ip_addr[16], prefix;
            size_t ip_len = 16, aa_consumed;
            xret = xqc_h3_ext_connectip_parse_address_assign(
                cap_payload, cap_len, &req_id, &ip_ver,
                ip_addr, &ip_len, &prefix, &aa_consumed);
            if (xret == XQC_OK && ip_ver == 4) {
                memcpy(conn->assigned_ip, ip_addr, 4);
                conn->assigned_prefix = prefix;
                conn->addr_assigned = 1;
                LOG_INF("ADDRESS_ASSIGN: %d.%d.%d.%d/%d",
                        ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3], prefix);
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

        if (consumed < stream->capsule_len) {
            memmove(stream->capsule_buf,
                    stream->capsule_buf + consumed,
                    stream->capsule_len - consumed);
        }
        stream->capsule_len -= consumed;
    }
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
            if (cli_stream_append_capsules(stream, buf, (size_t)n) < 0) {
                LOG_ERR("capsule buffer OOM");
                return -1;
            }
            cli_process_capsules(stream);
        } while (n > 0 && !fin);

        /* Set up TUN after ADDRESS_ASSIGN */
        if (conn->addr_assigned && !conn->ctx->tun_up) {
            if (cli_setup_tun(conn->ctx, conn->assigned_ip, conn->assigned_prefix) < 0) {
                LOG_ERR("TUN setup failed after ADDRESS_ASSIGN");
                return -1;
            }
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
    int wret = mpvpn_tun_write(&conn->ctx->tun, payload, payload_len);
    if (wret < 0) {
        conn->ctx->tun_drop_cnt++;
        if (wret == MPVPN_TUN_EAGAIN) {
            LOG_DBG("TUN write EAGAIN (drops=%" PRIu64 ")", conn->ctx->tun_drop_cnt);
        } else {
            LOG_WRN("TUN write failed (drops=%" PRIu64 ")", conn->ctx->tun_drop_cnt);
        }
    }
}

static void
cli_dgram_write_notify(xqc_h3_conn_t *h3_conn, void *user_data)
{
    (void)h3_conn;
    cli_conn_t *conn = (cli_conn_t *)user_data;
    if (!conn) return;
    cli_ctx_t *ctx = conn->ctx;

    if (ctx->tun_paused && ctx->ev_tun) {
        event_add(ctx->ev_tun, NULL);
        ctx->tun_paused = 0;
        evtimer_del(ctx->ev_tun_resume);
        LOG_DBG("TUN read resumed (QUIC queue has space)");
    }
}

static void
cli_dgram_acked_notify(xqc_h3_conn_t *conn, uint64_t dgram_id,
                        void *user_data)
{
    (void)conn; (void)dgram_id;
    cli_conn_t *cli_conn = (cli_conn_t *)user_data;
    if (!cli_conn) return;
    cli_conn->dgram_acked_cnt++;
}

static int
cli_dgram_lost_notify(xqc_h3_conn_t *conn, uint64_t dgram_id,
                       void *user_data)
{
    (void)conn;
    cli_conn_t *cli_conn = (cli_conn_t *)user_data;
    if (!cli_conn) return 0;
    cli_conn->dgram_lost_cnt++;
    if ((cli_conn->dgram_lost_cnt % 256) == 0) {
        LOG_WRN("client datagram loss checkpoint: lost=%" PRIu64 " acked=%" PRIu64 " (last_dgram_id=%" PRIu64 ")",
                cli_conn->dgram_lost_cnt, cli_conn->dgram_acked_cnt, dgram_id);
        cli_log_conn_stats("client loss checkpoint", &cli_conn->cid);
    }
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

    /* Update TUN MTU if tunnel is already up */
    if (cli_conn && cli_conn->ctx->tun_up) {
        size_t udp_mss = xqc_h3_ext_masque_udp_mss(
            mss, cli_conn->masque_stream_id);
        if (udp_mss >= 68) {
            mpvpn_tun_set_mtu(&cli_conn->ctx->tun, (int)udp_mss);
        }
    }
}

/* ================================================================
 *  TLS callbacks
 * ================================================================ */

static int
cli_cert_verify_cb(const unsigned char *certs[], const size_t cert_len[],
                   size_t certs_len, void *conn_user_data)
{
    (void)certs; (void)cert_len; (void)certs_len; (void)conn_user_data;
    /* xquic's internal xqc_ssl_cert_verify_cb already does BoringSSL chain +
     * hostname verification before calling us.  This callback is only reached
     * for UNABLE_TO_GET_ISSUER_CERT_LOCALLY or ALLOW_SELF_SIGNED cases.
     * Accept: xquic already filtered fatal errors. */
    return 0;
}

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
 *  Multipath callbacks
 * ================================================================ */

static void
cli_ready_to_create_path(const xqc_cid_t *cid, void *conn_user_data)
{
    cli_conn_t *conn = (cli_conn_t *)conn_user_data;
    cli_ctx_t *ctx = conn->ctx;

    if (ctx->cfg->n_paths <= 1) {
        return;  /* single-path mode */
    }

    LOG_INF("ready_to_create_path: adding secondary paths");

    for (int i = 1; i < ctx->path_mgr.n_paths; i++) {
        mpvpn_path_t *p = &ctx->path_mgr.paths[i];
        if (p->in_use) continue;

        uint64_t new_path_id = 0;
        xqc_int_t ret = xqc_conn_create_path(
            ctx->engine, &conn->cid, &new_path_id, 0);
        if (ret < 0) {
            LOG_WRN("xqc_conn_create_path[%d]: %d", i, ret);
            return;
        }

        p->path_id = new_path_id;
        p->in_use = 1;
        LOG_INF("path[%d] created: path_id=%" PRIu64 " iface=%s",
                i, new_path_id, p->iface);
    }
}

static void
cli_path_recreate_callback(int fd, short what, void *arg)
{
    (void)fd; (void)what;
    cli_ctx_t *ctx = (cli_ctx_t *)arg;
    cli_conn_t *conn = ctx->conn;

    if (!conn || !conn->h3_conn) {
        return;  /* connection shutting down */
    }

    int recreated = 0;
    for (int i = 0; i < ctx->path_mgr.n_paths; i++) {
        mpvpn_path_t *p = &ctx->path_mgr.paths[i];
        if (!p->in_use && p->active && p->fd >= 0) {
            uint64_t new_path_id = 0;
            xqc_int_t ret = xqc_conn_create_path(
                ctx->engine, &conn->cid, &new_path_id, 0);
            if (ret < 0) {
                LOG_WRN("path re-create[%d]: xqc_conn_create_path failed: %d",
                        i, ret);
            } else {
                p->path_id = new_path_id;
                p->in_use = 1;
                recreated++;
                LOG_INF("path[%d] re-created: path_id=%" PRIu64 " iface=%s",
                        i, new_path_id, p->iface);
            }
        }
    }

    xqc_engine_main_logic(ctx->engine);

    /* Reset retries only if all recreated paths survived main_logic
     * (i.e. were not immediately removed by xquic) */
    if (recreated > 0) {
        int all_survived = 1;
        for (int i = 0; i < ctx->path_mgr.n_paths; i++) {
            mpvpn_path_t *p = &ctx->path_mgr.paths[i];
            if (p->active && p->fd >= 0 && !p->in_use) {
                all_survived = 0;
                break;
            }
        }
        if (all_survived) {
            ctx->path_recreate_retries = 0;
        }
    }
}

static void
cli_path_removed(const xqc_cid_t *cid, uint64_t path_id,
                  void *conn_user_data)
{
    (void)cid;
    cli_conn_t *conn = (cli_conn_t *)conn_user_data;
    cli_ctx_t *ctx = conn->ctx;

    mpvpn_path_t *p = mpvpn_path_mgr_find_by_path_id(&ctx->path_mgr, path_id);
    if (p) {
        LOG_INF("path removed: path_id=%" PRIu64 " iface=%s", path_id, p->iface);
        p->in_use = 0;
        p->path_id = 0;

        /* Schedule path re-creation (with retry limit) */
        if (ctx->ev_path_recreate && p->active && p->fd >= 0
            && ctx->path_recreate_retries < PATH_RECREATE_MAX_RETRIES) {
            ctx->path_recreate_retries++;
            struct timeval tv = { .tv_sec = PATH_RECREATE_DELAY_SEC };
            event_add(ctx->ev_path_recreate, &tv);
            LOG_INF("path re-creation scheduled in %d sec (attempt %d/%d)",
                    PATH_RECREATE_DELAY_SEC,
                    ctx->path_recreate_retries, PATH_RECREATE_MAX_RETRIES);
        } else if (ctx->path_recreate_retries >= PATH_RECREATE_MAX_RETRIES) {
            LOG_WRN("path re-creation: max retries (%d) reached, giving up",
                    PATH_RECREATE_MAX_RETRIES);
        }
    } else {
        LOG_WRN("path_removed: unknown path_id=%" PRIu64, path_id);
    }
}

/* ================================================================
 *  Resolve server address
 * ================================================================ */

static int
cli_resolve_server(cli_ctx_t *ctx)
{
    memset(&ctx->server_addr, 0, sizeof(ctx->server_addr));
    ctx->server_addr.sin_family = AF_INET;
    ctx->server_addr.sin_port = htons((uint16_t)ctx->cfg->server_port);
    if (inet_pton(AF_INET, ctx->cfg->server_addr, &ctx->server_addr.sin_addr) != 1) {
        LOG_ERR("invalid server address: %s", ctx->cfg->server_addr);
        return -1;
    }
    ctx->server_addrlen = sizeof(ctx->server_addr);
    return 0;
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

    /* Create event base */
    g_cli.eb = event_base_new();
    if (!g_cli.eb) {
        LOG_ERR("event_base_new failed");
        return -1;
    }

    g_cli.ev_engine = event_new(g_cli.eb, -1, 0, cli_engine_callback, &g_cli);
    g_cli.ev_path_recreate = event_new(g_cli.eb, -1, 0,
                                        cli_path_recreate_callback, &g_cli);
    g_cli.ev_tun_resume = evtimer_new(g_cli.eb, cli_tun_resume_safety, &g_cli);
    g_cli.ev_sigint = evsignal_new(g_cli.eb, SIGINT, cli_signal_event_callback, &g_cli);
    g_cli.ev_sigterm = evsignal_new(g_cli.eb, SIGTERM, cli_signal_event_callback, &g_cli);
    if (!g_cli.ev_sigint || !g_cli.ev_sigterm) {
        LOG_ERR("failed to create signal events");
        return -1;
    }
    event_add(g_cli.ev_sigint, NULL);
    event_add(g_cli.ev_sigterm, NULL);

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
        .write_socket                = cli_write_socket,
        .write_socket_ex             = cli_write_socket_ex,
        .save_token                  = cli_save_token,
        .save_session_cb             = cli_save_session_cb,
        .save_tp_cb                  = cli_save_tp_cb,
        .cert_verify_cb              = cli_cert_verify_cb,
        .ready_to_create_path_notify = cli_ready_to_create_path,
        .path_removed_notify         = cli_path_removed,
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

    /* ---- Resolve server address ---- */
    if (cli_resolve_server(&g_cli) < 0) {
        return -1;
    }

    /* ---- Create UDP sockets (one per path) ---- */
    mpvpn_path_mgr_init(&g_cli.path_mgr);

    if (cfg->n_paths > 0) {
        /* Multipath: create one socket per specified interface */
        for (int i = 0; i < cfg->n_paths; i++) {
            int idx = mpvpn_path_mgr_add(&g_cli.path_mgr, cfg->path_ifaces[i],
                                          &g_cli.server_addr);
            if (idx < 0) {
                LOG_ERR("failed to create path socket for %s", cfg->path_ifaces[i]);
                return -1;
            }
        }
    } else {
        /* Single-path: one socket on any interface */
        int idx = mpvpn_path_mgr_add(&g_cli.path_mgr, NULL, &g_cli.server_addr);
        if (idx < 0) {
            return -1;
        }
    }

    /* Register all path sockets with libevent */
    for (int i = 0; i < g_cli.path_mgr.n_paths; i++) {
        mpvpn_path_t *p = &g_cli.path_mgr.paths[i];
        p->ev_socket = event_new(g_cli.eb, p->fd,
                                  EV_READ | EV_PERSIST,
                                  cli_socket_event_callback, &g_cli);
        event_add(p->ev_socket, NULL);
    }

    /* Mark primary path (path 0) as in-use with path_id=0 */
    g_cli.path_mgr.paths[0].path_id = 0;
    g_cli.path_mgr.paths[0].in_use = 1;

    /* ---- Create H3 connection ---- */
    cli_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) {
        LOG_ERR("calloc conn");
        return -1;
    }
    conn->ctx = &g_cli;
    g_cli.conn = conn;

    int multipath = (cfg->n_paths > 1) ? 1 : 0;

    xqc_conn_settings_t conn_settings;
    memset(&conn_settings, 0, sizeof(conn_settings));
    conn_settings.max_datagram_frame_size = 65535;
    conn_settings.proto_version = XQC_VERSION_V1;
    conn_settings.enable_multipath = multipath;
    conn_settings.mp_ping_on = multipath;
    conn_settings.pacing_on = 1;
    conn_settings.cong_ctrl_callback = xqc_bbr_cb;
    conn_settings.sndq_packets_used_max = XQC_SNDQ_MAX_PKTS;
    conn_settings.so_sndbuf = 8 * 1024 * 1024;

    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));
    if (!cfg->insecure) {
        conn_ssl_config.cert_verify_flag = XQC_TLS_CERT_FLAG_NEED_VERIFY
                                         | XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED;
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

    LOG_INF("connecting to %s:%d (multipath=%d, paths=%d) ...",
            cfg->server_addr, cfg->server_port, multipath, g_cli.path_mgr.n_paths);

    /* ---- Main event loop ---- */
    event_base_dispatch(g_cli.eb);

    /* ---- Cleanup ---- */
    LOG_INF("client shutting down");
    cli_cleanup_routes(&g_cli);
    if (g_cli.ev_sigterm) event_free(g_cli.ev_sigterm);
    if (g_cli.ev_sigint)  event_free(g_cli.ev_sigint);
    if (g_cli.ev_tun)            event_free(g_cli.ev_tun);
    if (g_cli.ev_tun_resume)     event_free(g_cli.ev_tun_resume);
    if (g_cli.ev_path_recreate)  event_free(g_cli.ev_path_recreate);
    if (g_cli.ev_engine)         event_free(g_cli.ev_engine);
    mpvpn_path_mgr_destroy(&g_cli.path_mgr);
    mpvpn_tun_destroy(&g_cli.tun);
    xqc_engine_destroy(g_cli.engine);
    event_base_free(g_cli.eb);
    free(conn);

    return 0;
}
