// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_server_double_connectip.c — Regression for the server admitting a
 * SECOND Extended CONNECT connect-ip request on an H3 connection that
 * already owns a tunnel.
 *
 * Root cause
 * ----------
 * The server had no guard against a second connect-ip request arriving on
 * one H3 connection that already owns a tunnel. The second request re-ran
 * mqvpn_addr_pool_alloc, overwrote conn->assigned_ip, and registered a
 * second sessions[] entry pointing at the same svr_conn_t while
 * incrementing n_sessions again. On connection close only the CURRENT
 * address's slot is released (mqvpn_addr_pool_release / sessions[] clear
 * both key off conn->assigned_ip, which by then is the SECOND address) —
 * so the first sessions[] entry is left pointing at a freed svr_conn_t:
 * heap use-after-free the next time a TUN packet routes to the old IP, or
 * at server destroy (sessions[] is walked and every non-NULL slot freed).
 * Plus an address-pool leak and an n_sessions over-count.
 *
 * Fix (src/mqvpn_server.c, cb_request_read)
 * ------------------------------------------
 * Just before tagging the stream's role, reject a second connect-ip
 * request on a connection whose assigned_ip is already non-zero: log a
 * warning, send 409 Conflict via svr_masque_send_409(), and return without
 * touching the address pool, sessions[], or the stream's role. The
 * connection and its existing tunnel are left untouched.
 *
 * What this test does
 * --------------------
 * Stands up a REAL mqvpn server on a loopback UDP socket (no PSK
 * configured, so no auth token is needed) and drives it with a RAW xquic
 * H3 client — built directly on the xquic public API, NOT the mqvpn
 * client, because the mqvpn client API has no way to open a second
 * connect-ip request on an already-tunneled connection. The raw client
 * completes a genuine QUIC+TLS+H3 handshake, then runs four phases on the
 * SAME H3 connection:
 *
 *   1. Duplicate rejection: request #1 establishes the tunnel, request #2
 *      (a second connect-ip on the same connection) must be rejected.
 *      Asserts mqvpn_server_get_n_clients() == 1, request #1's :status is
 *      MANDATORILY 200 and request #2's MANDATORILY 409 (not best-effort —
 *      a regressed 409 guard would route request #2 down the
 *      re-establishment path instead, which ALSO leaves n_clients==1, so
 *      the status pair is what actually discriminates the two), and the
 *      callback counts (on_client_connected==1, on_client_disconnected==0).
 *   2. Re-establishment (a): closes request #1's stream
 *      (xqc_h3_request_close) and asserts n_clients drops to 0 and
 *      on_client_disconnected fires exactly once — pins the EAGER release
 *      in cb_request_close (a lazy, conn-close-only release would leave
 *      n_clients==1 here).
 *   3. Re-establishment (b): sends a THIRD connect-ip request on the same
 *      connection and asserts it succeeds (:status 200, n_clients==1,
 *      on_client_connected total 2) — pins the re-establishment path in
 *      svr_connect_ip_on_request.
 *   4. qsid fence: frames one inner IPv4 packet (source = the second
 *      tunnel's assigned IP, to pass forward_inner_ip's anti-spoof check)
 *      as an HTTP Datagram twice — once under request #1's closed
 *      (stale-generation) stream id, once under request #3's live stream
 *      id — and asserts the server's tun_output fires exactly ONCE: the
 *      stale-generation datagram must be dropped by cb_dgram_read's qsid
 *      fence, not delivered.
 *
 * It then routes a TUN packet at the FIRST assigned IP (by now released
 * and not reallocated) through mqvpn_server_on_tun_packet() and destroys
 * the server, so ASan gets a chance to catch any lingering dangling
 * sessions[] pointer.
 *
 * The whole run is also, throughout, the original core security
 * assertion: the server process must survive every phase above and a
 * subsequent mqvpn_server_destroy with no ASan use-after-free / leak
 * report (this binary is built with ASan).
 *
 * No root, no TUN device, no elevated privileges: two loopback UDP
 * sockets only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>

#include "libmqvpn.h"

#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
#include <xquic/xqc_http3.h>

/* ─── raw xquic H3 client plumbing ─── */

/* One-shot test: fd + engine + connection state live at file scope rather
 * than threading a context through every xquic callback. */
static int g_cli_fd = -1;
static xqc_engine_t *g_cli_engine = NULL;
static xqc_cid_t g_cli_cid;
static int g_handshake_finished = 0;

typedef struct {
    int status; /* :status captured from the response, -1 = not yet seen */
    int closed; /* h3_request_close_notify fired */
} cli_req_ctx_t;

static cli_req_ctx_t g_req1 = {.status = -1};
static cli_req_ctx_t g_req2 = {.status = -1};
/* Third connect-ip request, sent in the re-establishment phase (§3b) after
 * request #1's stream is closed and its session is eagerly released. */
static cli_req_ctx_t g_req3 = {.status = -1};

/* The client's H3 connection handle, captured in cli_h3_conn_create — needed
 * by the qsid-fence phase to call xqc_h3_ext_datagram_send() directly (the
 * request-level helpers above never need it). */
static xqc_h3_conn_t *g_cli_h3_conn = NULL;

/* First and second ADDRESS_ASSIGN'd IPv4 the server handed out (first
 * establishment via request #1, second via the re-establishment request
 * #3). Captured from the server's own on_client_connected callback rather
 * than by decoding the client's capsule stream — server and client both
 * live in this one process, so that is simpler and just as faithful to "the
 * Nth assigned IP" as parsing capsules would be. */
static uint8_t g_assigned_ip[4];
static uint8_t g_assigned_ip2[4];
static int g_client_connected_calls = 0;
static int g_client_disconnected_calls = 0;
/* Times the server's tun_output callback fired — the qsid-fence phase's core
 * assertion is that this stays at exactly 1 after two datagrams are sent
 * (one on the closed generation-1 stream, one on the live generation-2
 * stream) — AND that the one delivered packet is the live-generation one.
 * The two datagrams carry distinguishable inner destination addresses;
 * the mock records the delivered packet's destination so an inverted fence
 * (stale accepted, live dropped — also exactly one call) cannot pass. */
static int g_tun_output_calls = 0;
static uint8_t g_tun_last_dst[4];

/* xquic's own internal clock (exported by the static lib, forward-declared
 * here as third_party/xquic/tests/masque_client.c does — it is not part of
 * the public xquic.h). engine_cbs below leaves realtime_ts/monotonic_ts
 * unset, so xquic's internal idle-timeout/RTT bookkeeping runs on THIS
 * clock; a hand-rolled CLOCK_MONOTONIC timestamp handed to
 * xqc_engine_packet_process()'s recv_time instead is a DIFFERENT clock
 * (different epoch/magnitude) from what that bookkeeping compares against,
 * which manifests as the connection's idle timer appearing to have already
 * expired and tearing the connection down before the handshake completes. */
extern xqc_usec_t xqc_now(void);

static ssize_t
cli_write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer,
                 socklen_t peerlen, void *conn_user_data)
{
    (void)conn_user_data;
    ssize_t n = sendto(g_cli_fd, buf, size, 0, peer, peerlen);
    return n < 0 ? XQC_SOCKET_ERROR : n;
}

static ssize_t
cli_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
                    const struct sockaddr *peer, socklen_t peerlen, void *conn_user_data)
{
    (void)path_id;
    return cli_write_socket(buf, size, peer, peerlen, conn_user_data);
}

static void
cli_set_event_timer(xqc_usec_t wake_after, void *engine_user_data)
{
    (void)wake_after;
    (void)engine_user_data; /* test pumps the engine manually */
}

static void
cli_log_write(xqc_log_level_t lvl, const void *buf, size_t size, void *engine_user_data)
{
    (void)lvl;
    (void)buf;
    (void)size;
    (void)engine_user_data;
}

static int
cli_cert_verify(const unsigned char *certs[], const size_t cert_len[], size_t certs_len,
                void *conn_user_data)
{
    (void)certs;
    (void)cert_len;
    (void)certs_len;
    (void)conn_user_data;
    return 0; /* self-signed test cert: accept anything */
}

/* Server may send a NEW_TOKEN frame and/or a TLS session ticket after a
 * real 1-RTT handshake completes; xquic invokes save_token/save_session_cb
 * unconditionally (unlike save_tp_cb, which is NULL-checked), so leaving
 * these unset would SIGSEGV this test client on a real handshake. No-ops —
 * this test never attempts 0-RTT resumption. */
static void
cli_save_token(const unsigned char *token, uint32_t token_len, void *conn_user_data)
{
    (void)token;
    (void)token_len;
    (void)conn_user_data;
}

static void
cli_save_session(const char *data, size_t data_len, void *conn_user_data)
{
    (void)data;
    (void)data_len;
    (void)conn_user_data;
}

static void
cli_save_tp(const char *data, size_t data_len, void *conn_user_data)
{
    (void)data;
    (void)data_len;
    (void)conn_user_data;
}

static int
cli_h3_conn_create(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *user_data)
{
    (void)cid;
    (void)user_data;
    g_cli_h3_conn = h3_conn;
    return 0;
}

static int
cli_h3_conn_close(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *user_data)
{
    (void)h3_conn;
    (void)cid;
    (void)user_data;
    return 0;
}

static void
cli_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data)
{
    (void)h3_conn;
    (void)user_data;
    g_handshake_finished = 1;
}

/* Send the RFC 9484 Extended CONNECT connect-ip headers on a fresh H3
 * request already created on the shared connection. Mirrors
 * src/mqvpn_client.c's cli_masque_start_tunnel — the server has no PSK
 * configured, so no authorization header is sent, and reorder is off by
 * default server-side, so no mqvpn-reorder header either. */
static int
cli_send_connect_ip(xqc_h3_request_t *req, int svr_port)
{
    char authority[64];
    snprintf(authority, sizeof(authority), "127.0.0.1:%d", svr_port);

    xqc_http_header_t hdrs[6] = {
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
    xqc_http_headers_t headers = {.headers = hdrs, .count = 6, .capacity = 6};

    /* fin=0: a real connect-ip tunnel keeps the stream open for capsules
     * (and would carry DATAGRAMs); the rejected duplicate never gets a
     * chance to send a body either way. */
    return xqc_h3_request_send_headers(req, &headers, 0) < 0 ? -1 : 0;
}

static int
cli_h3_request_close(xqc_h3_request_t *h3_request, void *user_data)
{
    (void)h3_request;
    cli_req_ctx_t *ctx = (cli_req_ctx_t *)user_data;
    if (ctx) ctx->closed = 1;
    return 0;
}

static int
cli_h3_request_read(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag,
                    void *user_data)
{
    cli_req_ctx_t *ctx = (cli_req_ctx_t *)user_data;

    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        unsigned char fin = 0;
        xqc_http_headers_t *headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (headers) {
            for (size_t i = 0; i < headers->count; i++) {
                xqc_http_header_t *h = &headers->headers[i];
                if (h->name.iov_len == 7 && memcmp(h->name.iov_base, ":status", 7) == 0 &&
                    h->value.iov_len == 3) {
                    const unsigned char *v = h->value.iov_base;
                    if (v[0] >= '0' && v[0] <= '9' && v[1] >= '0' && v[1] <= '9' &&
                        v[2] >= '0' && v[2] <= '9' && ctx) {
                        ctx->status =
                            (v[0] - '0') * 100 + (v[1] - '0') * 10 + (v[2] - '0');
                    }
                }
            }
        }
    }

    if (flag & XQC_REQ_NOTIFY_READ_BODY) {
        /* Drain and discard capsule bytes (ADDRESS_ASSIGN etc.) — this test
         * captures the assigned IP from the server's on_client_connected
         * callback instead, so the client side never needs to decode
         * capsules to make progress. */
        unsigned char drain[4096];
        unsigned char fin = 0;
        while (xqc_h3_request_recv_body(h3_request, drain, sizeof(drain), &fin) > 0) {}
    }

    return 0;
}

/* ─── server plumbing ─── */

static void
svr_tun_output(const uint8_t *pkt, size_t len, void *user_ctx)
{
    (void)user_ctx;
    g_tun_output_calls++;
    /* Record the delivered packet's IPv4 destination for the qsid-fence
     * phase's which-generation assertion. */
    if (len >= 20 && (pkt[0] >> 4) == 4) memcpy(g_tun_last_dst, pkt + 16, 4);
}

static void
svr_tunnel_config_ready(const mqvpn_tunnel_info_t *info, void *user_ctx)
{
    (void)info;
    (void)user_ctx;
}

static void
svr_on_client_connected(const mqvpn_tunnel_info_t *info, uint32_t session_id,
                        void *user_ctx)
{
    (void)session_id;
    (void)user_ctx;
    if (g_client_connected_calls == 0) {
        memcpy(g_assigned_ip, info->assigned_ip, 4);
    } else if (g_client_connected_calls == 1) {
        memcpy(g_assigned_ip2, info->assigned_ip, 4);
    }
    g_client_connected_calls++;
}

static void
svr_on_client_disconnected(uint32_t session_id, mqvpn_error_t reason, void *user_ctx)
{
    (void)session_id;
    (void)reason;
    (void)user_ctx;
    g_client_disconnected_calls++;
}

static int
make_udp_loopback(struct sockaddr_in *out_addr)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(0); /* OS picks the port */
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        close(fd);
        return -1;
    }
    socklen_t alen = sizeof(*out_addr);
    if (getsockname(fd, (struct sockaddr *)out_addr, &alen) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* One pump iteration shared by every wait loop below: flush the client's
 * queued sends, feed anything that arrived at either loopback socket into
 * the matching engine, and tick the server. Mirrors
 * test_server_preaccept_dos.c's manual pump (no libevent dependency). */
static void
pump_once(mqvpn_server_t *svr, int svr_fd, struct sockaddr_in *cli_addr, int cli_fd)
{
    uint8_t buf[65536];

    xqc_engine_main_logic(g_cli_engine);

    for (;;) {
        struct sockaddr_storage from;
        socklen_t flen = sizeof(from);
        ssize_t n = recvfrom(svr_fd, buf, sizeof(buf), MSG_DONTWAIT,
                             (struct sockaddr *)&from, &flen);
        if (n <= 0) break;
        mqvpn_server_on_socket_recv(svr, buf, (size_t)n, (struct sockaddr *)&from, flen);
    }

    mqvpn_server_tick(svr);

    for (;;) {
        struct sockaddr_storage from;
        socklen_t flen = sizeof(from);
        ssize_t n = recvfrom(cli_fd, buf, sizeof(buf), MSG_DONTWAIT,
                             (struct sockaddr *)&from, &flen);
        if (n <= 0) break;
        xqc_engine_packet_process(g_cli_engine, buf, (size_t)n,
                                  (struct sockaddr *)cli_addr, sizeof(*cli_addr),
                                  (struct sockaddr *)&from, flen, xqc_now(), NULL);
    }
}

static void
pump_wait(mqvpn_server_t *svr, int svr_fd, struct sockaddr_in *cli_addr, int cli_fd,
          int max_iters, const volatile int *done)
{
    for (int i = 0; i < max_iters && !*done; i++) {
        pump_once(svr, svr_fd, cli_addr, cli_fd);
        if (*done) return;
        struct pollfd pfds[2] = {
            {.fd = svr_fd, .events = POLLIN},
            {.fd = cli_fd, .events = POLLIN},
        };
        poll(pfds, 2, 5);
    }
}

/* One pump budget shared by every condition-based wait below: 1500 iterations
 * * a 5ms poll = 7.5s worst case per phase. This test has ~5 such waits, so a
 * simultaneous worst case across all of them (~37.5s) still leaves headroom
 * under the 60s CTest timeout — in practice every condition below resolves
 * within a handful of iterations on loopback with no induced delay, so this
 * ceiling only matters when a guard has regressed and the expected event
 * never arrives. */
#define PUMP_BUDGET_ITERS 1500

/* Flexible condition for pump_until below: every field defaults to "don't
 * care" (-1 / NULL) and must be set explicitly per use, since 0 is a
 * meaningful value for min_clients/eq_clients (e.g. "n_clients == 0") and a
 * zero-initialized field would silently change what is being waited for. */
typedef struct {
    mqvpn_server_t *svr;
    int min_clients;    /* -1 = don't check; else require n_clients >= this */
    int eq_clients;     /* -1 = don't check; else require n_clients == this */
    cli_req_ctx_t *req; /* NULL = don't check; else require status != -1 ||
                         * closed (a captured response header, or the stream
                         * closing without one) */
    int *counter;       /* NULL = don't check */
    int counter_target; /* require *counter >= this */
} pump_cond_ctx_t;

static int
pump_cond(void *vctx)
{
    pump_cond_ctx_t *c = (pump_cond_ctx_t *)vctx;
    if (c->min_clients >= 0 && mqvpn_server_get_n_clients(c->svr) < c->min_clients)
        return 0;
    if (c->eq_clients >= 0 && mqvpn_server_get_n_clients(c->svr) != c->eq_clients)
        return 0;
    if (c->req && c->req->status == -1 && !c->req->closed) return 0;
    if (c->counter && *c->counter < c->counter_target) return 0;
    return 1;
}

/* Pump until pump_cond(ctx) is true or max_iters is exhausted (checked before
 * pumping too, so an already-satisfied condition costs nothing). Returns the
 * final condition value — callers assert on that, not on the return value of
 * this function being "success", so a timed-out wait degrades to a normal
 * (informative) assertion failure below rather than a silent hang. */
static int
pump_until(mqvpn_server_t *svr, int svr_fd, struct sockaddr_in *cli_addr, int cli_fd,
           int max_iters, pump_cond_ctx_t *ctx)
{
    if (pump_cond(ctx)) return 1;
    for (int i = 0; i < max_iters; i++) {
        pump_once(svr, svr_fd, cli_addr, cli_fd);
        if (pump_cond(ctx)) return 1;
        struct pollfd pfds[2] = {
            {.fd = svr_fd, .events = POLLIN},
            {.fd = cli_fd, .events = POLLIN},
        };
        poll(pfds, 2, 5);
    }
    return pump_cond(ctx);
}

int
main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    printf("test_server_double_connectip: duplicate CONNECT-IP regression\n");

    int rc = 0;

    /* 1. Loopback UDP sockets for server and client. */
    struct sockaddr_in svr_addr, cli_addr;
    int svr_fd = make_udp_loopback(&svr_addr);
    int cli_fd = make_udp_loopback(&cli_addr);
    if (svr_fd < 0 || cli_fd < 0) {
        printf("FAIL: socket setup\n");
        return 1;
    }
    g_cli_fd = cli_fd;

    /* 2. mqvpn server bound to svr_fd — insecure (no PSK configured, so no
     * auth token is required from the client). */
    mqvpn_config_t *cfg = mqvpn_config_new();
    mqvpn_config_set_listen(cfg, "127.0.0.1", ntohs(svr_addr.sin_port));
    mqvpn_config_set_subnet(cfg, "10.0.0.0/24");
    mqvpn_config_set_tls_cert(cfg, TEST_CERT_FILE, TEST_KEY_FILE);
    mqvpn_config_set_log_level(cfg, MQVPN_LOG_ERROR);

    mqvpn_server_callbacks_t cbs = MQVPN_SERVER_CALLBACKS_INIT;
    cbs.tun_output = svr_tun_output;
    cbs.tunnel_config_ready = svr_tunnel_config_ready;
    cbs.on_client_connected = svr_on_client_connected;
    cbs.on_client_disconnected = svr_on_client_disconnected;

    mqvpn_server_t *svr = mqvpn_server_new(cfg, &cbs, NULL);
    mqvpn_config_free(cfg);
    if (!svr) {
        printf("FAIL: mqvpn_server_new\n");
        return 1;
    }
    if (mqvpn_server_set_socket_fd(svr, svr_fd, (struct sockaddr *)&svr_addr,
                                   sizeof(svr_addr)) != MQVPN_OK ||
        mqvpn_server_start(svr) != MQVPN_OK) {
        printf("FAIL: server start\n");
        return 1;
    }

    /* 3. Raw xquic H3 client engine — completes a REAL QUIC+TLS+H3
     * handshake (unlike test_server_preaccept_dos.c, which deliberately
     * never gets past ALPN selection). */
    xqc_engine_ssl_config_t engine_ssl;
    memset(&engine_ssl, 0, sizeof(engine_ssl));
    engine_ssl.ciphers = XQC_TLS_CIPHERS;
    engine_ssl.groups = XQC_TLS_GROUPS;

    xqc_engine_callback_t engine_cbs = {
        .set_event_timer = cli_set_event_timer,
        .log_callbacks =
            {
                .xqc_log_write_err = cli_log_write,
                .xqc_log_write_stat = cli_log_write,
            },
    };
    xqc_transport_callbacks_t tcbs = {
        .write_socket = cli_write_socket,
        .write_socket_ex = cli_write_socket_ex,
        .save_token = cli_save_token,
        .save_session_cb = cli_save_session,
        .save_tp_cb = cli_save_tp,
        .cert_verify_cb = cli_cert_verify,
    };

    xqc_config_t xconfig;
    if (xqc_engine_get_default_config(&xconfig, XQC_ENGINE_CLIENT) < 0) {
        printf("FAIL: xqc default config\n");
        return 1;
    }
    xconfig.cfg_log_level = XQC_LOG_ERROR;

    g_cli_engine = xqc_engine_create(XQC_ENGINE_CLIENT, &xconfig, &engine_ssl,
                                     &engine_cbs, &tcbs, NULL);
    if (!g_cli_engine) {
        printf("FAIL: xqc_engine_create(client)\n");
        return 1;
    }

    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs =
            {
                .h3_conn_create_notify = cli_h3_conn_create,
                .h3_conn_close_notify = cli_h3_conn_close,
                .h3_conn_handshake_finished = cli_h3_conn_handshake_finished,
            },
        .h3r_cbs =
            {
                .h3_request_close_notify = cli_h3_request_close,
                .h3_request_read_notify = cli_h3_request_read,
            },
    };
    if (xqc_h3_ctx_init(g_cli_engine, &h3_cbs) != XQC_OK) {
        printf("FAIL: xqc_h3_ctx_init\n");
        return 1;
    }

    /* enable_connect_protocol + h3_datagram: without these the server's own
     * SETTINGS negotiation would refuse Extended CONNECT outright, before
     * this test ever reaches the duplicate-request path it exists to
     * exercise. */
    xqc_h3_conn_settings_t h3s = {
        .max_field_section_size = 32 * 1024,
        .qpack_blocked_streams = 64,
        .qpack_enc_max_table_capacity = 16 * 1024,
        .qpack_dec_max_table_capacity = 16 * 1024,
        .enable_connect_protocol = 1,
        .h3_datagram = 1,
    };
    xqc_h3_engine_set_local_settings(g_cli_engine, &h3s);

    xqc_conn_settings_t cs;
    memset(&cs, 0, sizeof(cs));
    cs.proto_version = XQC_VERSION_V1;
    cs.max_datagram_frame_size = 65535;

    xqc_conn_ssl_config_t ssl_cfg;
    memset(&ssl_cfg, 0, sizeof(ssl_cfg));
    ssl_cfg.cert_verify_flag = XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED;

    const xqc_cid_t *cid =
        xqc_h3_connect(g_cli_engine, &cs, NULL, 0, "mqvpn-test.invalid", 0, &ssl_cfg,
                       (struct sockaddr *)&svr_addr, sizeof(svr_addr), NULL);
    if (!cid) {
        printf("FAIL: xqc_h3_connect\n");
        return 1;
    }
    /* cid may be misaligned inside xquic's internal structures — copy via
     * an explicit (const void *) source, matching mqvpn_client.c. */
    memcpy(&g_cli_cid, (const void *)cid, sizeof(g_cli_cid));

    /* 4. Pump until the handshake finishes (bounded — QUIC PTO
     * retransmission can be 1s+, so give this generous headroom), then fire
     * request #1. */
    pump_wait(svr, svr_fd, &cli_addr, cli_fd, 2000, &g_handshake_finished);

    xqc_h3_request_t *req1 = NULL;
    /* Captured immediately after creation, before req1 is ever closed — the
     * qsid-fence phase (§10) needs this stream id after req1's stream (and
     * possibly the request object itself) has been closed. */
    uint64_t req1_stream_id = 0;
    if (!g_handshake_finished) {
        printf("FAIL: handshake never finished\n");
        rc = 1;
    } else {
        req1 = xqc_h3_request_create(g_cli_engine, &g_cli_cid, NULL, &g_req1);
        if (!req1 || cli_send_connect_ip(req1, ntohs(svr_addr.sin_port)) != 0) {
            printf("FAIL: send request #1\n");
            rc = 1;
        } else {
            req1_stream_id = xqc_h3_stream_id(req1);
        }
    }

    /* 5. Pump until the server has established the first tunnel (session
     * count reaches 1) AND request #1's response headers have arrived,
     * then fire request #2 on the SAME H3 connection — the duplicate the
     * fix guards against. Waiting on both (not just n_clients) is what
     * makes the mandatory status assertion in phase 7 reliable instead of
     * racy. */
    int n_after_first = 0;
    if (rc == 0) {
        pump_cond_ctx_t est1_cond = {
            .svr = svr,
            .min_clients = 1,
            .eq_clients = -1,
            .req = &g_req1,
            .counter = NULL,
            .counter_target = 0,
        };
        pump_until(svr, svr_fd, &cli_addr, cli_fd, PUMP_BUDGET_ITERS, &est1_cond);

        n_after_first = mqvpn_server_get_n_clients(svr);
        fprintf(stderr,
                "[phase1] n_clients=%d req1_status=%d assigned_ip=%d.%d.%d.%d "
                "on_client_connected_calls=%d\n",
                n_after_first, g_req1.status, g_assigned_ip[0], g_assigned_ip[1],
                g_assigned_ip[2], g_assigned_ip[3], g_client_connected_calls);
        if (n_after_first != 1) {
            printf("  first CONNECT-IP did not establish exactly one session   FAIL\n");
            rc = 1;
        }
    }

    if (rc == 0) {
        xqc_h3_request_t *req2 =
            xqc_h3_request_create(g_cli_engine, &g_cli_cid, NULL, &g_req2);
        if (!req2 || cli_send_connect_ip(req2, ntohs(svr_addr.sin_port)) != 0) {
            printf("FAIL: send request #2\n");
            rc = 1;
        }
    }

    /* 6. Pump until request #2's response headers arrive (or it closes) or
     * a generous bounded budget expires. Under the (neutralized) bug this
     * may instead surface as an ASan report before this loop ever returns
     * — that is the point of the revert-check in the task, not something
     * this loop needs to detect itself. */
    pump_cond_ctx_t req2_cond = {
        .svr = svr,
        .min_clients = -1,
        .eq_clients = -1,
        .req = &g_req2,
        .counter = NULL,
        .counter_target = 0,
    };
    pump_until(svr, svr_fd, &cli_addr, cli_fd, PUMP_BUDGET_ITERS, &req2_cond);

    int n_clients = mqvpn_server_get_n_clients(svr);
    fprintf(stderr,
            "[phase2] n_clients=%d req1_status=%d req2_status=%d req2_closed=%d "
            "on_client_connected_calls=%d on_client_disconnected_calls=%d\n",
            n_clients, g_req1.status, g_req2.status, g_req2.closed,
            g_client_connected_calls, g_client_disconnected_calls);

    /* 7. Core security assertion: exactly one session survives the
     * duplicate request — the second was rejected, not admitted. On its
     * own this no longer discriminates a regressed 409 guard (a
     * re-establishment would also leave n_clients==1 — see the status and
     * callback-count assertions right below), but it stays as the
     * headline gate since it is what the fix's UAF is ultimately about. */
    if (n_clients == 1) {
        printf("  n_clients == 1 after duplicate CONNECT-IP                  PASS\n");
    } else {
        printf("  n_clients == %d (expected 1)                               FAIL\n",
               n_clients);
        rc = 1;
    }

    /* Mandatory status assertion (no longer best-effort/skippable): this is
     * what actually discriminates "duplicate rejected" from "duplicate
     * silently routed down the re-establishment path" — both leave
     * n_clients==1, but only the first leaves req2_status==409. Phase 5's
     * wait above makes status capture reliable, so an incomplete capture is
     * now itself a FAIL rather than a skip. */
    if (g_req1.status == 200 && g_req2.status == 409) {
        printf("  req1=200, req2=409                                         PASS\n");
    } else {
        printf("  req1=%d req2=%d (expected 200/409)                        FAIL\n",
               g_req1.status, g_req2.status);
        rc = 1;
    }

    /* Callback-count assertions: the duplicate must not have fired a
     * SECOND on_client_connected (that would mean it was admitted, not
     * rejected) or ANY on_client_disconnected (nothing has torn down
     * yet — the existing tunnel is untouched). */
    if (g_client_connected_calls == 1 && g_client_disconnected_calls == 0 &&
        n_clients == 1) {
        printf("  callback counts: connected=1 disconnected=0 n_clients=1        PASS\n");
    } else {
        printf("  callback counts: connected=%d disconnected=%d n_clients=%d "
               "(expected 1/0/1)                                              FAIL\n",
               g_client_connected_calls, g_client_disconnected_calls, n_clients);
        rc = 1;
    }

    /* 8. Re-establishment phase (a): close request #1's stream from the
     * client. RFC 9484 §4.1 ties the tunnel's lifetime to its request
     * stream, so the server must release the WHOLE session — sessions[]
     * slot, pool address, on_client_disconnected — as soon as it sees the
     * RESET_STREAM, not merely when the H3 connection itself later closes.
     * This pins the EAGER release in cb_request_close: the lazy
     * (conn-close-only) release alone would leave n_clients==1 here. */
    if (rc == 0) {
        xqc_h3_request_close(req1);

        pump_cond_ctx_t closed_cond = {
            .svr = svr,
            .min_clients = -1,
            .eq_clients = 0,
            .req = NULL,
            .counter = NULL,
            .counter_target = 0,
        };
        pump_until(svr, svr_fd, &cli_addr, cli_fd, PUMP_BUDGET_ITERS, &closed_cond);

        int n_after_close = mqvpn_server_get_n_clients(svr);
        fprintf(stderr, "[phase3a] n_clients=%d on_client_disconnected_calls=%d\n",
                n_after_close, g_client_disconnected_calls);
        if (n_after_close == 0 && g_client_disconnected_calls == 1) {
            printf(
                "  eager release on stream close: n_clients=0 disconnected=1    PASS\n");
        } else {
            printf("  eager release on stream close: n_clients=%d disconnected=%d "
                   "(expected 0/1)                                             FAIL\n",
                   n_after_close, g_client_disconnected_calls);
            rc = 1;
        }
    }

    /* 9. Re-establishment phase (b): a THIRD connect-ip request on the SAME
     * H3 connection, after the previous tunnel stream closed. Per
     * svr_connect_ip_on_request this is a legitimate re-establishment (NOT
     * a duplicate — tunnel_established is 0 at this point), so it must
     * succeed with a fresh 200/ADDRESS_ASSIGN and a second
     * on_client_connected. This pins the re-establishment path itself,
     * distinct from the reject-duplicate path pinned above. */
    xqc_h3_request_t *req3 = NULL;
    uint64_t req3_stream_id = 0;
    if (rc == 0) {
        req3 = xqc_h3_request_create(g_cli_engine, &g_cli_cid, NULL, &g_req3);
        if (!req3 || cli_send_connect_ip(req3, ntohs(svr_addr.sin_port)) != 0) {
            printf("FAIL: send request #3\n");
            rc = 1;
        } else {
            req3_stream_id = xqc_h3_stream_id(req3);
        }
    }

    if (rc == 0) {
        pump_cond_ctx_t reest_cond = {
            .svr = svr,
            .min_clients = 1,
            .eq_clients = -1,
            .req = &g_req3,
            .counter = NULL,
            .counter_target = 0,
        };
        pump_until(svr, svr_fd, &cli_addr, cli_fd, PUMP_BUDGET_ITERS, &reest_cond);

        int n_after_reest = mqvpn_server_get_n_clients(svr);
        fprintf(stderr,
                "[phase3b] n_clients=%d req3_status=%d on_client_connected_calls=%d "
                "assigned_ip2=%d.%d.%d.%d\n",
                n_after_reest, g_req3.status, g_client_connected_calls, g_assigned_ip2[0],
                g_assigned_ip2[1], g_assigned_ip2[2], g_assigned_ip2[3]);
        if (g_req3.status == 200 && n_after_reest == 1 && g_client_connected_calls == 2) {
            printf("  re-establishment: req3=200, n_clients=1, connected_calls=2     "
                   "PASS\n");
        } else {
            printf("  re-establishment: req3=%d n_clients=%d connected_calls=%d "
                   "(expected 200/1/2)                                          FAIL\n",
                   g_req3.status, n_after_reest, g_client_connected_calls);
            rc = 1;
        }
    }

    /* 10. qsid-fence phase: build one inner IPv4 packet whose SOURCE is the
     * SECOND tunnel's assigned IP (g_assigned_ip2 — required to pass
     * forward_inner_ip's anti-spoof check) and frame it as an HTTP
     * Datagram TWICE — once under req1's (closed, stale-generation) stream
     * id and once under req3's (live, current-generation) stream id. Only
     * the live-generation datagram should ever reach tun_output: cb_dgram_
     * read's qsid fence drops any datagram whose quarter-stream-id does not
     * match the CURRENT tunnel stream's, which is exactly what a late
     * datagram from a closed prior generation looks like. */
    if (rc == 0) {
        uint8_t inner_pkt[40];
        memset(inner_pkt, 0, sizeof(inner_pkt));
        inner_pkt[0] = 0x45; /* IPv4, IHL=5 — classified RAW by
                              * mqvpn_reorder_classify_byte (nibble 4). */
        inner_pkt[3] = 40;   /* total length */
        inner_pkt[8] = 64;   /* TTL > 1, so forward_inner_ip forwards rather
                              * than ICMP Time-Exceeded-ing it. */
        inner_pkt[9] = 17;   /* UDP */
        memcpy(inner_pkt + 12, g_assigned_ip2, 4); /* source: second tunnel's IP
                                                    * (anti-spoof) */
        /* Distinguishable destinations: stale-generation copy goes to
         * 8.8.8.8, live-generation copy to 8.8.8.9. tun_output records the
         * delivered destination, so the assertion below can require that
         * the ONE delivered packet is the live one — a count-only check
         * would also pass with the fence inverted (stale accepted, live
         * dropped). forward_inner_ip rewrites only TTL/checksum, never the
         * destination. */
        inner_pkt[16] = 8; /* destination: 8.8.8.8 (stale marker) */
        inner_pkt[17] = 8;
        inner_pkt[18] = 8;
        inner_pkt[19] = 8;

        uint8_t inner_live[sizeof(inner_pkt)];
        memcpy(inner_live, inner_pkt, sizeof(inner_pkt));
        inner_live[19] = 9; /* destination: 8.8.8.9 (live marker) */

        uint8_t frame_stale[64], frame_live[64];
        size_t fw_stale = 0, fw_live = 0;
        xqc_int_t xr_stale =
            xqc_h3_ext_masque_frame_udp(frame_stale, sizeof(frame_stale), &fw_stale,
                                        req1_stream_id, inner_pkt, sizeof(inner_pkt));
        xqc_int_t xr_live =
            xqc_h3_ext_masque_frame_udp(frame_live, sizeof(frame_live), &fw_live,
                                        req3_stream_id, inner_live, sizeof(inner_live));

        if (xr_stale != XQC_OK || xr_live != XQC_OK || !g_cli_h3_conn) {
            printf("FAIL: qsid-fence datagram framing\n");
            rc = 1;
        } else {
            uint64_t dgram_id = 0;
            xqc_int_t sr_stale = xqc_h3_ext_datagram_send(
                g_cli_h3_conn, frame_stale, fw_stale, &dgram_id, XQC_DATA_QOS_LOW);
            xqc_int_t sr_live = xqc_h3_ext_datagram_send(
                g_cli_h3_conn, frame_live, fw_live, &dgram_id, XQC_DATA_QOS_LOW);
            fprintf(stderr, "[phase4] datagram_send stale=%d live=%d\n", sr_stale,
                    sr_live);

            if (sr_stale != XQC_OK || sr_live != XQC_OK) {
                printf("FAIL: qsid-fence datagram send\n");
                rc = 1;
            } else {
                pump_cond_ctx_t tun_cond = {
                    .svr = svr,
                    .min_clients = -1,
                    .eq_clients = -1,
                    .req = NULL,
                    .counter = &g_tun_output_calls,
                    .counter_target = 1,
                };
                pump_until(svr, svr_fd, &cli_addr, cli_fd, PUMP_BUDGET_ITERS, &tun_cond);
                /* Extra drain: give a wrongly-delivered stale-generation
                 * datagram a chance to surface as a SECOND tun_output call
                 * before asserting the count is exactly one. */
                for (int i = 0; i < 20; i++) {
                    pump_once(svr, svr_fd, &cli_addr, cli_fd);
                }

                fprintf(stderr, "[phase4] tun_output_calls=%d last_dst=%u.%u.%u.%u\n",
                        g_tun_output_calls, g_tun_last_dst[0], g_tun_last_dst[1],
                        g_tun_last_dst[2], g_tun_last_dst[3]);
                if (g_tun_output_calls == 1 && g_tun_last_dst[3] == 9) {
                    printf("  qsid fence: exactly 1 tun_output call, live marker "
                           "(stale generation dropped)                       PASS\n");
                } else {
                    printf("  qsid fence: tun_output_calls == %d, last_dst end %u "
                           "(expected 1 call, live marker 9)                 FAIL\n",
                           g_tun_output_calls, g_tun_last_dst[3]);
                    rc = 1;
                }
            }
        }
    }

    /* 11. Route a TUN packet at the FIRST assigned IP, then destroy the
     * server. Historically (pre-fix) the second, unrejected CONNECT-IP
     * would have overwritten conn->assigned_ip and added a second
     * sessions[] slot for the same svr_conn_t; only the CURRENT address's
     * slot was released on connection close, leaving the slot keyed by
     * THIS (first) IP dangling. By this point in the test the first IP has
     * ALREADY been legitimately released (phase 8's eager release) and NOT
     * reallocated (addr_pool.c's `next` cursor advanced past it — see
     * phase 9's assigned_ip2), so this now exercises the more general
     * invariant that routing to a released-and-unused address is a
     * harmless no-op rather than a UAF. Destroying the server afterward
     * walks every non-NULL sessions[] slot under ASan. */
    if (g_client_connected_calls > 0) {
        uint8_t tun_pkt[40];
        memset(tun_pkt, 0, sizeof(tun_pkt));
        tun_pkt[0] = 0x45; /* IPv4, IHL=5 */
        tun_pkt[3] = 40;   /* total length */
        tun_pkt[8] = 64;   /* TTL */
        tun_pkt[9] = 17;   /* UDP */
        tun_pkt[12] = 8;   /* source: 8.8.8.8 (arbitrary) */
        tun_pkt[13] = 8;
        tun_pkt[14] = 8;
        tun_pkt[15] = 8;
        memcpy(tun_pkt + 16, g_assigned_ip, 4); /* destination: first assigned IP */

        int tret = mqvpn_server_on_tun_packet(svr, tun_pkt, sizeof(tun_pkt));
        fprintf(stderr, "[tun] on_tun_packet(first assigned ip) -> %d\n", tret);

        /* One more pump so a routed datagram (if any) reaches xquic's send
         * path before we tear the server down. */
        pump_once(svr, svr_fd, &cli_addr, cli_fd);
    } else {
        printf("  no client ever connected — cannot exercise sessions[] via TUN "
               "routing                                                    FAIL\n");
        rc = 1;
    }

    xqc_engine_destroy(g_cli_engine);
    mqvpn_server_destroy(svr);
    close(cli_fd);
    close(svr_fd);

    printf(rc == 0 ? "test_server_double_connectip: PASS\n"
                   : "test_server_double_connectip: FAIL\n");
    return rc;
}
