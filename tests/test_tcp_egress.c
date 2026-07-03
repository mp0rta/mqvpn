// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_tcp_egress.c — server-side H3 request dispatch tests.
 *
 * Unlike test_tcp_lane.c (fake-xquic), this needs the REAL xquic engine:
 * the thing under test is xquic-facing dispatch in cb_request_read
 * (mqvpn_server.c). mqvpn_server_t is exercised through the public
 * libmqvpn.h API (as in test_server.c's loopback harness), but the public
 * mqvpn_client API only ever sends fixed :protocol values ("connect-ip",
 * and "mqvpn-tcp" from the hybrid TCP lane) — it has no way to send an
 * arbitrary/bogus :protocol. So the "client" side here is a minimal raw H3
 * probe built directly on top of xquic, mirroring the engine/connection
 * setup mqvpn_client.c uses internally, just enough to open one Extended
 * CONNECT request with a caller-chosen :protocol value and read back the
 * response's :status.
 */

#include "libmqvpn.h"
#include "mqvpn_conn_settings.h"
#include "mqvpn_internal.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <xquic/xqc_http3.h>
#include <xquic/xquic.h>

/* ── Test infrastructure (mirrors test_server.c) ── */

static int g_tests_run = 0;
static int g_tests_passed = 0;

#define TEST(name)                 \
    static void test_##name(void); \
    static void run_##name(void)   \
    {                              \
        g_tests_run++;             \
        printf("  %-50s ", #name); \
        test_##name();             \
        g_tests_passed++;          \
        printf("PASS\n");          \
    }                              \
    static void test_##name(void)

#define ASSERT_EQ(a, b)                                                                \
    do {                                                                               \
        if ((a) != (b)) {                                                              \
            printf("FAIL\n    %s:%d: %s == %lld, expected %lld\n", __FILE__, __LINE__, \
                   #a, (long long)(a), (long long)(b));                                \
            exit(1);                                                                   \
        }                                                                              \
    } while (0)

#define ASSERT_STREQ(a, b)                                                           \
    do {                                                                             \
        if (strcmp((a), (b)) != 0) {                                                 \
            printf("FAIL\n    %s:%d: \"%s\" == \"%s\", expected \"%s\"\n", __FILE__, \
                   __LINE__, #a, (a), (b));                                          \
            exit(1);                                                                 \
        }                                                                            \
    } while (0)

static uint64_t
test_now_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ull + (uint64_t)tv.tv_usec;
}

/* mqvpn_server_new() requires both callbacks non-NULL; this test never
 * exercises the tun/tunnel-config-ready paths (no CONNECT-IP session is
 * ever established), so both are no-ops. */
static void
noop_tun_output(const uint8_t *pkt, size_t len, void *user_ctx)
{
    (void)pkt;
    (void)len;
    (void)user_ctx;
}

static void
noop_tunnel_config_ready(const mqvpn_tunnel_info_t *info, void *user_ctx)
{
    (void)info;
    (void)user_ctx;
}

/* ── Minimal raw H3 probe client ── */

typedef struct {
    xqc_engine_t *engine;
    int fd;
    xqc_cid_t cid;

    const char *protocol;
    size_t protocol_len;
    char authority[64];

    int handshake_done;
    int response_done;
    char status[16];
} probe_conn_t;

static void
probe_log_write(xqc_log_level_t lvl, const void *buf, size_t size, void *user_data)
{
    (void)lvl;
    (void)buf;
    (void)size;
    (void)user_data;
    /* Silent — this test cares about dispatch behavior, not xquic's own log
     * noise. */
}

static void
probe_set_event_timer(xqc_usec_t wake_after, void *user_data)
{
    (void)wake_after;
    (void)user_data;
    /* No-op: the driving loop below polls unconditionally rather than
     * waiting for xquic's requested wake time (mirrors test_server.c's
     * bounded poll-loop idiom). */
}

static ssize_t
probe_write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer,
                   socklen_t peerlen, void *conn_user_data)
{
    probe_conn_t *p = (probe_conn_t *)conn_user_data;
    ssize_t res;
    do {
        res = sendto(p->fd, buf, size, MSG_DONTWAIT, peer, peerlen);
    } while (res < 0 && errno == EINTR);
    if (res < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return XQC_SOCKET_EAGAIN;
        return XQC_SOCKET_ERROR;
    }
    return res;
}

static int
probe_cert_verify(const unsigned char *certs[], const size_t cert_len[], size_t certs_len,
                  void *conn_user_data)
{
    (void)certs;
    (void)cert_len;
    (void)certs_len;
    (void)conn_user_data;
    return 0; /* accept the test server's self-signed cert */
}

static void
probe_save_token(const unsigned char *t, unsigned tl, void *u)
{
    (void)t;
    (void)tl;
    (void)u;
}
static void
probe_save_session(const char *d, size_t dl, void *u)
{
    (void)d;
    (void)dl;
    (void)u;
}
static void
probe_save_tp(const char *d, size_t dl, void *u)
{
    (void)d;
    (void)dl;
    (void)u;
}

static int
probe_open_request(probe_conn_t *p)
{
    xqc_h3_request_t *req = xqc_h3_request_create(p->engine, &p->cid, NULL, p);
    if (!req) return -1;

    xqc_http_header_t hdrs[5] = {
        {.name = {.iov_base = ":method", .iov_len = 7},
         .value = {.iov_base = "CONNECT", .iov_len = 7},
         .flags = 0},
        {.name = {.iov_base = ":protocol", .iov_len = 9},
         .value = {.iov_base = (void *)p->protocol, .iov_len = p->protocol_len},
         .flags = 0},
        {.name = {.iov_base = ":scheme", .iov_len = 7},
         .value = {.iov_base = "https", .iov_len = 5},
         .flags = 0},
        {.name = {.iov_base = ":authority", .iov_len = 10},
         .value = {.iov_base = p->authority, .iov_len = strlen(p->authority)},
         .flags = 0},
        {.name = {.iov_base = ":path", .iov_len = 5},
         .value = {.iov_base = "/probe", .iov_len = 6},
         .flags = 0},
    };
    xqc_http_headers_t headers = {.headers = hdrs, .count = 5, .capacity = 5};

    /* fin=1: headers-only probe request, no body needed for any of the
     * dispatch branches under test. */
    ssize_t ret = xqc_h3_request_send_headers(req, &headers, 1);
    if (ret < 0) return -1;
    return 0;
}

static int
probe_cb_h3_conn_create(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *user_data)
{
    (void)h3_conn;
    (void)cid;
    (void)user_data;
    return 0;
}

static void
probe_cb_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data)
{
    (void)h3_conn;
    probe_conn_t *p = (probe_conn_t *)user_data;
    p->handshake_done = 1;
    probe_open_request(p);
}

static int
probe_cb_h3_conn_close(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *user_data)
{
    (void)h3_conn;
    (void)cid;
    (void)user_data;
    return 0;
}

static int
probe_cb_request_read(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag,
                      void *user_data)
{
    probe_conn_t *p = (probe_conn_t *)user_data;

    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        unsigned char fin = 0;
        xqc_http_headers_t *headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (headers) {
            for (int i = 0; i < (int)headers->count; i++) {
                xqc_http_header_t *h = &headers->headers[i];
                if (h->name.iov_len == 7 && memcmp(h->name.iov_base, ":status", 7) == 0) {
                    size_t n = h->value.iov_len < sizeof(p->status) - 1
                                   ? h->value.iov_len
                                   : sizeof(p->status) - 1;
                    memcpy(p->status, h->value.iov_base, n);
                    p->status[n] = '\0';
                }
            }
            p->response_done = 1;
        }
    }

    if (flag & XQC_REQ_NOTIFY_READ_BODY) {
        unsigned char buf[256], fin = 0;
        while (xqc_h3_request_recv_body(h3_request, buf, sizeof(buf), &fin) > 0) {}
    }

    return 0;
}

static int
probe_cb_request_write(xqc_h3_request_t *h3_request, void *user_data)
{
    (void)h3_request;
    (void)user_data;
    return 0;
}

static int
probe_cb_request_close(xqc_h3_request_t *h3_request, void *user_data)
{
    (void)h3_request;
    (void)user_data;
    return 0;
}

static void
probe_cb_request_closing_notify(xqc_h3_request_t *h3_request, xqc_int_t err,
                                void *user_data)
{
    (void)h3_request;
    (void)err;
    (void)user_data;
}

static xqc_engine_t *
probe_create_engine(void)
{
    xqc_engine_ssl_config_t engine_ssl;
    memset(&engine_ssl, 0, sizeof(engine_ssl));
    engine_ssl.ciphers = XQC_TLS_CIPHERS;
    engine_ssl.groups = XQC_TLS_GROUPS;

    xqc_engine_callback_t engine_cbs = {
        .set_event_timer = probe_set_event_timer,
        .log_callbacks =
            {
                .xqc_log_write_err = probe_log_write,
                .xqc_log_write_stat = probe_log_write,
            },
    };

    xqc_transport_callbacks_t tcbs = {
        .write_socket = probe_write_socket,
        .save_token = probe_save_token,
        .save_session_cb = probe_save_session,
        .save_tp_cb = probe_save_tp,
        .cert_verify_cb = probe_cert_verify,
    };

    xqc_config_t xconfig;
    if (xqc_engine_get_default_config(&xconfig, XQC_ENGINE_CLIENT) < 0) return NULL;
    xconfig.cfg_log_level = XQC_LOG_ERROR;

    xqc_engine_t *engine = xqc_engine_create(XQC_ENGINE_CLIENT, &xconfig, &engine_ssl,
                                             &engine_cbs, &tcbs, NULL);
    if (!engine) return NULL;

    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs =
            {
                .h3_conn_create_notify = probe_cb_h3_conn_create,
                .h3_conn_close_notify = probe_cb_h3_conn_close,
                .h3_conn_handshake_finished = probe_cb_h3_conn_handshake_finished,
            },
        .h3r_cbs =
            {
                .h3_request_close_notify = probe_cb_request_close,
                .h3_request_read_notify = probe_cb_request_read,
                .h3_request_write_notify = probe_cb_request_write,
                .h3_request_closing_notify = probe_cb_request_closing_notify,
            },
    };
    if (xqc_h3_ctx_init(engine, &h3_cbs) != XQC_OK) {
        xqc_engine_destroy(engine);
        return NULL;
    }

    xqc_h3_conn_settings_t h3s = {
        .max_field_section_size = 32 * 1024,
        .qpack_blocked_streams = 64,
        .qpack_enc_max_table_capacity = 16 * 1024,
        .qpack_dec_max_table_capacity = 16 * 1024,
        .enable_connect_protocol = 1,
    };
    xqc_h3_engine_set_local_settings(engine, &h3s);

    return engine;
}

/* ── Shared loopback dispatch probe ──
 *
 * Spins up a real mqvpn_server_t (public API, loopback UDP) plus the raw H3
 * probe client above, opens one Extended CONNECT with `protocol`, drives
 * both engines to completion, and returns the response :status in
 * out_status. Returns 0 if a response was observed before the timeout, -1
 * otherwise. */
static int
run_dispatch_probe(const char *protocol, size_t protocol_len, char *out_status,
                   size_t out_status_cap)
{
    int svr_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (svr_fd < 0) return -1;
    int cli_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (cli_fd < 0) {
        close(svr_fd);
        return -1;
    }

    struct sockaddr_in svr_addr, cli_addr;
    memset(&svr_addr, 0, sizeof(svr_addr));
    svr_addr.sin_family = AF_INET;
    svr_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    svr_addr.sin_port = htons(0);
    if (bind(svr_fd, (struct sockaddr *)&svr_addr, sizeof(svr_addr)) != 0)
        goto fail_sockets;

    memset(&cli_addr, 0, sizeof(cli_addr));
    cli_addr.sin_family = AF_INET;
    cli_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    cli_addr.sin_port = htons(0);
    if (bind(cli_fd, (struct sockaddr *)&cli_addr, sizeof(cli_addr)) != 0)
        goto fail_sockets;

    socklen_t alen = sizeof(svr_addr);
    getsockname(svr_fd, (struct sockaddr *)&svr_addr, &alen);
    alen = sizeof(cli_addr);
    getsockname(cli_fd, (struct sockaddr *)&cli_addr, &alen);

    /* ── Server ── */
    mqvpn_config_t *svr_cfg = mqvpn_config_new();
    mqvpn_config_set_listen(svr_cfg, "0.0.0.0", 443);
    mqvpn_config_set_subnet(svr_cfg, "10.0.0.0/24");
    mqvpn_config_set_tls_cert(svr_cfg, TEST_CERT_FILE, TEST_KEY_FILE);
    mqvpn_config_set_log_level(svr_cfg, MQVPN_LOG_ERROR);

    mqvpn_server_callbacks_t svr_cbs = MQVPN_SERVER_CALLBACKS_INIT;
    svr_cbs.tun_output = noop_tun_output;
    svr_cbs.tunnel_config_ready = noop_tunnel_config_ready;

    mqvpn_server_t *svr = mqvpn_server_new(svr_cfg, &svr_cbs, NULL);
    mqvpn_config_free(svr_cfg);
    if (!svr) goto fail_sockets;

    if (mqvpn_server_set_socket_fd(svr, svr_fd, (struct sockaddr *)&svr_addr,
                                   sizeof(svr_addr)) != MQVPN_OK ||
        mqvpn_server_start(svr) != MQVPN_OK) {
        mqvpn_server_destroy(svr);
        goto fail_sockets;
    }

    /* ── Raw H3 probe client ── */
    probe_conn_t probe;
    memset(&probe, 0, sizeof(probe));
    probe.fd = cli_fd;
    probe.protocol = protocol;
    probe.protocol_len = protocol_len;
    snprintf(probe.authority, sizeof(probe.authority), "127.0.0.1:%d",
             ntohs(svr_addr.sin_port));

    probe.engine = probe_create_engine();
    if (!probe.engine) {
        mqvpn_server_destroy(svr);
        goto fail_sockets;
    }

    xqc_conn_settings_t cs;
    mqvpn_conn_settings_input_t cs_in = {
        .is_server = false,
        .enable_multipath = false,
        .scheduler = MQVPN_SCHED_MINRTT,
        .cc = MQVPN_CC_BBR2,
        .init_max_path_id = 0,
    };
    mqvpn_build_conn_settings(&cs_in, &cs);

    xqc_conn_ssl_config_t ssl_cfg;
    memset(&ssl_cfg, 0, sizeof(ssl_cfg));
    ssl_cfg.cert_verify_flag = XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED;

    const xqc_cid_t *cid =
        xqc_h3_connect(probe.engine, &cs, NULL, 0, "127.0.0.1", 0, &ssl_cfg,
                       (struct sockaddr *)&svr_addr, sizeof(svr_addr), &probe);
    if (!cid) {
        xqc_engine_destroy(probe.engine);
        mqvpn_server_destroy(svr);
        goto fail_sockets;
    }
    memcpy(&probe.cid, cid, sizeof(probe.cid));

    /* ── Drive both engines to completion ── */
    uint8_t buf[65536];
    for (int elapsed = 0; elapsed < 10000 && !probe.response_done;) {
        struct sockaddr_storage from;
        socklen_t from_len;

        for (;;) {
            from_len = sizeof(from);
            ssize_t n = recvfrom(svr_fd, buf, sizeof(buf), MSG_DONTWAIT,
                                 (struct sockaddr *)&from, &from_len);
            if (n <= 0) break;
            mqvpn_server_on_socket_recv(svr, buf, (size_t)n, (struct sockaddr *)&from,
                                        from_len);
        }
        for (;;) {
            from_len = sizeof(from);
            ssize_t n = recvfrom(cli_fd, buf, sizeof(buf), MSG_DONTWAIT,
                                 (struct sockaddr *)&from, &from_len);
            if (n <= 0) break;
            xqc_engine_packet_process(probe.engine, buf, (size_t)n,
                                      (struct sockaddr *)&cli_addr, sizeof(cli_addr),
                                      (struct sockaddr *)&from, from_len,
                                      (xqc_usec_t)test_now_us(), NULL);
        }

        mqvpn_server_tick(svr);
        xqc_engine_main_logic(probe.engine);

        if (probe.response_done) break;

        mqvpn_interest_t svr_int = {0};
        mqvpn_server_get_interest(svr, &svr_int);
        int wait_ms = 20;
        if (svr_int.next_timer_ms > 0 && svr_int.next_timer_ms < wait_ms)
            wait_ms = svr_int.next_timer_ms;
        if (wait_ms < 1) wait_ms = 1;

        struct pollfd pfds[2] = {
            {.fd = svr_fd, .events = POLLIN},
            {.fd = cli_fd, .events = POLLIN},
        };
        poll(pfds, 2, wait_ms);
        elapsed += wait_ms;
    }

    int ok = probe.response_done;
    if (ok) snprintf(out_status, out_status_cap, "%s", probe.status);

    xqc_engine_destroy(probe.engine);
    mqvpn_server_destroy(svr);
    close(svr_fd);
    close(cli_fd);
    return ok ? 0 : -1;

fail_sockets:
    close(svr_fd);
    close(cli_fd);
    return -1;
}

/* ── Tests ── */

TEST(unrecognized_protocol_gets_501)
{
    char status[16] = {0};
    int rc = run_dispatch_probe("something-bogus", 16, status, sizeof(status));
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(status, "501");
}

TEST(mqvpn_tcp_protocol_gets_403)
{
    /* Proves the dispatch branch itself is reached (the unconditional 403
     * stub is replaced by real auth/ACL later). */
    char status[16] = {0};
    int rc = run_dispatch_probe("mqvpn-tcp", 9, status, sizeof(status));
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(status, "403");
}

int
main(void)
{
    printf("test_tcp_egress: server mqvpn-tcp dispatch tests\n");

    run_unrecognized_protocol_gets_501();
    run_mqvpn_tcp_protocol_gets_403();

    printf("\n  %d/%d tests passed\n", g_tests_passed, g_tests_run);
    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
