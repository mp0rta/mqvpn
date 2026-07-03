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
 * setup mqvpn_client.c uses internally: it can open Extended CONNECT
 * requests with a caller-chosen :protocol and read back the response's
 * :status, and it can establish a genuine CONNECT-IP tunnel (200 +
 * ADDRESS_ASSIGN) and push inner-IP datagrams through it, which the
 * tunnel-survives-non-tunnel-stream-close regression test needs.
 */

#include "libmqvpn.h"
#include "hybrid/tcp_egress.h"
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

/* Counts inner-IP packets the server forwarded out of the tunnel — the
 * observable the tunnel-survival regression test asserts on. */
static int g_tun_output_count = 0;

static void
counting_tun_output(const uint8_t *pkt, size_t len, void *user_ctx)
{
    (void)pkt;
    (void)len;
    (void)user_ctx;
    g_tun_output_count++;
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
    xqc_h3_conn_t *h3_conn;

    /* :protocol for the probe request (the one probe_open_request sends) */
    const char *protocol;
    size_t protocol_len;
    char authority[64];
    int auto_open; /* open the probe request from handshake_finished */
    /* :path for the probe request; NULL -> "/probe" (the historical
     * fixed probe path, still fine for tests that only care about
     * :protocol dispatch). Must be set BEFORE the request is opened
     * (either before harness_start with auto_open, or before a manual
     * probe_open_request call). */
    const char *path;

    int handshake_done;
    int response_done;
    int request_closed;
    char status[16];

    /* CONNECT-IP tunnel state (probe_open_connect_ip) */
    uint64_t masque_stream_id;
    int tunnel_ready; /* ADDRESS_ASSIGN (v4) parsed from the response body */
    uint8_t assigned_ip[4];
    uint8_t body_buf[256];
    size_t body_len;
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

/* Extended CONNECT with the probe's caller-chosen :protocol. */
static int
probe_open_request(probe_conn_t *p)
{
    xqc_h3_request_t *req = xqc_h3_request_create(p->engine, &p->cid, NULL, p);
    if (!req) return -1;

    const char *path = p->path ? p->path : "/probe";
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
         .value = {.iov_base = (void *)path, .iov_len = strlen(path)},
         .flags = 0},
    };
    xqc_http_headers_t headers = {.headers = hdrs, .count = 5, .capacity = 5};

    /* fin=1: headers-only probe request, no body needed for any of the
     * dispatch branches under test. */
    ssize_t ret = xqc_h3_request_send_headers(req, &headers, 1);
    if (ret < 0) return -1;
    return 0;
}

/* Genuine CONNECT-IP request (same header set mqvpn_client sends, minus
 * optional auth/reorder). fin=0 — this stream IS the tunnel. */
static int
probe_open_connect_ip(probe_conn_t *p)
{
    xqc_h3_request_t *req = xqc_h3_request_create(p->engine, &p->cid, NULL, p);
    if (!req) return -1;

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
         .value = {.iov_base = p->authority, .iov_len = strlen(p->authority)},
         .flags = 0},
        {.name = {.iov_base = ":path", .iov_len = 5},
         .value = {.iov_base = "/.well-known/masque/ip/*/*/", .iov_len = 27},
         .flags = 0},
        {.name = {.iov_base = "capsule-protocol", .iov_len = 16},
         .value = {.iov_base = "?1", .iov_len = 2},
         .flags = 0},
    };
    xqc_http_headers_t headers = {.headers = hdrs, .count = 6, .capacity = 6};

    if (xqc_h3_request_send_headers(req, &headers, 0) < 0) return -1;
    p->masque_stream_id = xqc_h3_stream_id(req);
    return 0;
}

/* Minimal inner IPv4 packet (20-byte header, no payload) framed per RFC
 * 9297 and sent as an H3 DATAGRAM on the tunnel. src = the session's
 * assigned IP so the server's anti-spoof check passes. */
static int
probe_send_inner_ipv4(probe_conn_t *p)
{
    uint8_t pkt[20];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45; /* v4, IHL 5 */
    pkt[3] = 20;   /* total length */
    pkt[8] = 64;   /* TTL */
    pkt[9] = 17;   /* protocol: UDP (arbitrary) */
    memcpy(pkt + 12, p->assigned_ip, 4);
    pkt[16] = 10; /* dst 10.0.0.1 (server-side pool addr; not validated) */
    pkt[19] = 1;

    uint8_t frame[64];
    size_t written = 0;
    if (xqc_h3_ext_masque_frame_udp(frame, sizeof(frame), &written, p->masque_stream_id,
                                    pkt, sizeof(pkt)) != XQC_OK)
        return -1;

    uint64_t dgram_id = 0;
    return xqc_h3_ext_datagram_send(p->h3_conn, frame, written, &dgram_id,
                                    XQC_DATA_QOS_HIGH) == XQC_OK
               ? 0
               : -1;
}

static int
probe_cb_h3_conn_create(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, void *user_data)
{
    (void)cid;
    probe_conn_t *p = (probe_conn_t *)user_data;
    p->h3_conn = h3_conn;
    return 0;
}

static void
probe_cb_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data)
{
    (void)h3_conn;
    probe_conn_t *p = (probe_conn_t *)user_data;
    p->handshake_done = 1;
    if (p->auto_open) probe_open_request(p);
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
        /* Accumulate and decode capsules — the CONNECT-IP response body
         * carries ADDRESS_ASSIGN (and ROUTE_ADVERTISEMENT), which the
         * tunnel-survival test needs for the inner packet's src IP. */
        unsigned char buf[256];
        unsigned char fin = 0;
        ssize_t n;
        while ((n = xqc_h3_request_recv_body(h3_request, buf, sizeof(buf), &fin)) > 0) {
            size_t space = sizeof(p->body_buf) - p->body_len;
            size_t take = (size_t)n < space ? (size_t)n : space;
            memcpy(p->body_buf + p->body_len, buf, take);
            p->body_len += take;
        }
        while (p->body_len > 0) {
            uint64_t cap_type;
            const uint8_t *cap_payload;
            size_t cap_len, consumed;
            if (xqc_h3_ext_capsule_decode(p->body_buf, p->body_len, &cap_type,
                                          &cap_payload, &cap_len, &consumed) != XQC_OK)
                break;
            if (cap_type == XQC_H3_CAPSULE_ADDRESS_ASSIGN) {
                uint64_t req_id;
                uint8_t ip_ver, ip_addr[16], prefix;
                size_t ip_len = 16, aa_consumed;
                if (xqc_h3_ext_connectip_parse_address_assign(
                        cap_payload, cap_len, &req_id, &ip_ver, ip_addr, &ip_len, &prefix,
                        &aa_consumed) == XQC_OK &&
                    ip_ver == 4) {
                    memcpy(p->assigned_ip, ip_addr, 4);
                    p->tunnel_ready = 1;
                }
            }
            if (consumed < p->body_len)
                memmove(p->body_buf, p->body_buf + consumed, p->body_len - consumed);
            p->body_len -= consumed;
        }
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
    probe_conn_t *p = (probe_conn_t *)user_data;
    if (p) p->request_closed = 1;
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
        .h3_datagram = 1,
    };
    xqc_h3_engine_set_local_settings(engine, &h3s);

    return engine;
}

/* ── Loopback harness: mqvpn server (public API) + raw H3 probe ── */

typedef struct {
    int svr_fd, cli_fd;
    struct sockaddr_in svr_addr, cli_addr;
    mqvpn_server_t *svr;
    probe_conn_t probe;
} harness_t;

/* Everything up to (and including) the QUIC connect. Returns 0 on success;
 * on failure everything partially created is torn down. `cfg_hook`
 * (nullable) runs on the server config after the fixed harness defaults and
 * before mqvpn_server_new — the seam tests use to exercise config-dependent
 * server behavior (e.g. the egress ACL) through the PUBLIC setter API. */
static int
harness_start(harness_t *h, const char *protocol, size_t protocol_len, int auto_open,
              void (*cfg_hook)(mqvpn_config_t *))
{
    memset(h, 0, sizeof(*h));
    h->svr_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (h->svr_fd < 0) return -1;
    h->cli_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (h->cli_fd < 0) {
        close(h->svr_fd);
        return -1;
    }

    memset(&h->svr_addr, 0, sizeof(h->svr_addr));
    h->svr_addr.sin_family = AF_INET;
    h->svr_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    h->svr_addr.sin_port = htons(0);
    if (bind(h->svr_fd, (struct sockaddr *)&h->svr_addr, sizeof(h->svr_addr)) != 0)
        goto fail_sockets;

    memset(&h->cli_addr, 0, sizeof(h->cli_addr));
    h->cli_addr.sin_family = AF_INET;
    h->cli_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    h->cli_addr.sin_port = htons(0);
    if (bind(h->cli_fd, (struct sockaddr *)&h->cli_addr, sizeof(h->cli_addr)) != 0)
        goto fail_sockets;

    socklen_t alen = sizeof(h->svr_addr);
    getsockname(h->svr_fd, (struct sockaddr *)&h->svr_addr, &alen);
    alen = sizeof(h->cli_addr);
    getsockname(h->cli_fd, (struct sockaddr *)&h->cli_addr, &alen);

    /* ── Server ── */
    {
        mqvpn_config_t *svr_cfg = mqvpn_config_new();
        mqvpn_config_set_listen(svr_cfg, "0.0.0.0", 443);
        mqvpn_config_set_subnet(svr_cfg, "10.0.0.0/24");
        mqvpn_config_set_tls_cert(svr_cfg, TEST_CERT_FILE, TEST_KEY_FILE);
        mqvpn_config_set_log_level(svr_cfg, MQVPN_LOG_ERROR);
        if (cfg_hook) cfg_hook(svr_cfg);

        mqvpn_server_callbacks_t svr_cbs = MQVPN_SERVER_CALLBACKS_INIT;
        svr_cbs.tun_output = counting_tun_output;
        svr_cbs.tunnel_config_ready = noop_tunnel_config_ready;

        h->svr = mqvpn_server_new(svr_cfg, &svr_cbs, NULL);
        mqvpn_config_free(svr_cfg);
        if (!h->svr) goto fail_sockets;

        if (mqvpn_server_set_socket_fd(h->svr, h->svr_fd, (struct sockaddr *)&h->svr_addr,
                                       sizeof(h->svr_addr)) != MQVPN_OK ||
            mqvpn_server_start(h->svr) != MQVPN_OK)
            goto fail_server;
    }

    /* ── Raw H3 probe client ── */
    h->probe.fd = h->cli_fd;
    h->probe.protocol = protocol;
    h->probe.protocol_len = protocol_len;
    h->probe.auto_open = auto_open;
    snprintf(h->probe.authority, sizeof(h->probe.authority), "127.0.0.1:%d",
             ntohs(h->svr_addr.sin_port));

    h->probe.engine = probe_create_engine();
    if (!h->probe.engine) goto fail_server;

    {
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

        const xqc_cid_t *cid = xqc_h3_connect(
            h->probe.engine, &cs, NULL, 0, "127.0.0.1", 0, &ssl_cfg,
            (struct sockaddr *)&h->svr_addr, sizeof(h->svr_addr), &h->probe);
        if (!cid) {
            xqc_engine_destroy(h->probe.engine);
            goto fail_server;
        }
        memcpy(&h->probe.cid, cid, sizeof(h->probe.cid));
    }
    return 0;

fail_server:
    mqvpn_server_destroy(h->svr);
fail_sockets:
    close(h->svr_fd);
    close(h->cli_fd);
    return -1;
}

/* Drives both engines (drain sockets, tick, poll) until *done becomes
 * nonzero or ~budget_ms of wall time elapses. */
static void
harness_pump(harness_t *h, const int *done, int budget_ms)
{
    uint8_t buf[65536];
    for (int elapsed = 0; elapsed < budget_ms && !*done;) {
        struct sockaddr_storage from;
        socklen_t from_len;

        for (;;) {
            from_len = sizeof(from);
            ssize_t n = recvfrom(h->svr_fd, buf, sizeof(buf), MSG_DONTWAIT,
                                 (struct sockaddr *)&from, &from_len);
            if (n <= 0) break;
            mqvpn_server_on_socket_recv(h->svr, buf, (size_t)n, (struct sockaddr *)&from,
                                        from_len);
        }
        for (;;) {
            from_len = sizeof(from);
            ssize_t n = recvfrom(h->cli_fd, buf, sizeof(buf), MSG_DONTWAIT,
                                 (struct sockaddr *)&from, &from_len);
            if (n <= 0) break;
            xqc_engine_packet_process(h->probe.engine, buf, (size_t)n,
                                      (struct sockaddr *)&h->cli_addr,
                                      sizeof(h->cli_addr), (struct sockaddr *)&from,
                                      from_len, (xqc_usec_t)test_now_us(), NULL);
        }

        mqvpn_server_tick(h->svr);
        xqc_engine_main_logic(h->probe.engine);

        if (*done) break;

        mqvpn_interest_t svr_int = {0};
        mqvpn_server_get_interest(h->svr, &svr_int);
        int wait_ms = 20;
        if (svr_int.next_timer_ms > 0 && svr_int.next_timer_ms < wait_ms)
            wait_ms = svr_int.next_timer_ms;
        if (wait_ms < 1) wait_ms = 1;

        struct pollfd pfds[2] = {
            {.fd = h->svr_fd, .events = POLLIN},
            {.fd = h->cli_fd, .events = POLLIN},
        };
        poll(pfds, 2, wait_ms);
        elapsed += wait_ms;
    }
}

static void
harness_stop(harness_t *h)
{
    xqc_engine_destroy(h->probe.engine);
    mqvpn_server_destroy(h->svr);
    close(h->svr_fd);
    close(h->cli_fd);
}

/* ── Shared dispatch probe ──
 *
 * Opens one Extended CONNECT with `protocol`, drives to a response, returns
 * the response :status in out_status. 0 = response observed, -1 = timeout. */
static int
run_dispatch_probe(const char *protocol, size_t protocol_len, char *out_status,
                   size_t out_status_cap)
{
    harness_t h;
    if (harness_start(&h, protocol, protocol_len, /*auto_open=*/1, NULL) != 0) return -1;

    harness_pump(&h, &h.probe.response_done, 10000);

    int ok = h.probe.response_done;
    if (ok) snprintf(out_status, out_status_cap, "%s", h.probe.status);

    harness_stop(&h);
    return ok ? 0 : -1;
}

/* Same as run_dispatch_probe but with a caller-chosen :path — needed for
 * the connect-tcp ACL wiring test below, which must send a syntactically
 * valid connect-tcp template (run_dispatch_probe's probes all use the
 * fixed "/probe" path, which never gets past svr_tcp_egress_parse_path).
 * auto_open is NOT used here: the path must be set on the probe before its
 * request is opened, and auto_open would fire from handshake_finished
 * before this function gets a chance to set it. `cfg_hook` (nullable)
 * customizes the server config — see harness_start. */
static int
run_dispatch_probe_with_path(const char *protocol, size_t protocol_len, const char *path,
                             void (*cfg_hook)(mqvpn_config_t *), char *out_status,
                             size_t out_status_cap)
{
    harness_t h;
    if (harness_start(&h, protocol, protocol_len, /*auto_open=*/0, cfg_hook) != 0)
        return -1;
    h.probe.path = path;

    harness_pump(&h, &h.probe.handshake_done, 10000);
    if (!h.probe.handshake_done || probe_open_request(&h.probe) != 0) {
        harness_stop(&h);
        return -1;
    }

    harness_pump(&h, &h.probe.response_done, 10000);
    int ok = h.probe.response_done;
    if (ok) snprintf(out_status, out_status_cap, "%s", h.probe.status);

    harness_stop(&h);
    return ok ? 0 : -1;
}

/* ── Tests ── */

TEST(unrecognized_protocol_gets_501)
{
    char status[16] = {0};
    int rc = run_dispatch_probe("something-bogus", strlen("something-bogus"), status,
                                sizeof(status));
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(status, "501");
}

TEST(mqvpn_tcp_bad_path_gets_400)
{
    /* Proves the dispatch branch is reached and real request-path parsing
     * runs: the probe's fixed "/probe" :path doesn't match the connect-tcp
     * template, so (with no PSK configured, i.e. auth open) the request is
     * rejected for a malformed path — not the old unconditional 403 stub. */
    char status[16] = {0};
    int rc = run_dispatch_probe("mqvpn-tcp", 9, status, sizeof(status));
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(status, "400");
}

TEST(mqvpn_tcp_acl_denied_gets_403)
{
    /* Proves the egress ACL is wired into the LIVE request path, not just
     * unit-tested in isolation: a syntactically valid connect-tcp request
     * targeting an RFC1918 address must be denied even though this
     * harness's server has no PSK configured (the ACL is unconditional;
     * only the identity check is optional). */
    char status[16] = {0};
    int rc = run_dispatch_probe_with_path("mqvpn-tcp", 9,
                                          "/.well-known/mqvpn/tcp/10.0.0.5/80/", NULL,
                                          status, sizeof(status));
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(status, "403");
}

/* Config hook for the allow-hole test below: the PUBLIC egress-ACL setter,
 * exactly as a platform embedding libmqvpn would call it. */
static void
harness_cfg_allow_10_slash_8(mqvpn_config_t *cfg)
{
    const char *allow[] = {"10.0.0.0/8"};
    if (mqvpn_config_set_hybrid_egress_acl(cfg, allow, 1, NULL, 0) != MQVPN_OK) {
        printf("FAIL\n    mqvpn_config_set_hybrid_egress_acl rejected valid input\n");
        exit(1);
    }
}

TEST(mqvpn_tcp_acl_allow_hole_gets_503)
{
    /* Proves CONFIGURED allow lists reach the live request path (public
     * setter -> config.hybrid -> svr_get_egress_policy -> decision), not
     * just the built-in default-deny table: with egress_allow=10.0.0.0/8
     * punched through, a 10.x target now clears the ACL and reaches the
     * start_connect stub (503) instead of the ACL's 403. Target 10.1.2.3,
     * NOT 10.0.0.x: the harness server's tunnel subnet is 10.0.0.0/24 and
     * the tunnel-subnet check deliberately precedes egress_allow, so a
     * 10.0.0.x target would (correctly) still be 403 despite the hole. */
    char status[16] = {0};
    int rc = run_dispatch_probe_with_path(
        "mqvpn-tcp", 9, "/.well-known/mqvpn/tcp/10.1.2.3/80/",
        harness_cfg_allow_10_slash_8, status, sizeof(status));
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(status, "503");
}

/* Regression: a non-tunnel stream closing on the SAME H3 connection as an
 * established CONNECT-IP tunnel must NOT clear tunnel_established (the
 * hybrid client multiplexes per-flow mqvpn-tcp requests onto the tunnel
 * connection, and 501'd unknown requests close promptly too). Guards the
 * role gate in mqvpn_server.c's cb_request_close. */
TEST(non_tunnel_close_keeps_tunnel_established)
{
    harness_t h;
    ASSERT_EQ(harness_start(&h, "something-bogus", strlen("something-bogus"),
                            /*auto_open=*/0, NULL),
              0);
    probe_conn_t *p = &h.probe;

    /* 1. Handshake, then a genuine CONNECT-IP tunnel (200 + ADDRESS_ASSIGN). */
    harness_pump(&h, &p->handshake_done, 10000);
    ASSERT_EQ(p->handshake_done, 1);
    ASSERT_EQ(probe_open_connect_ip(p), 0);
    harness_pump(&h, &p->tunnel_ready, 10000);
    ASSERT_EQ(p->tunnel_ready, 1);
    ASSERT_STREQ(p->status, "200");

    /* 2. Baseline: the tunnel forwards inner-IP datagrams to tun_output. */
    g_tun_output_count = 0;
    int forwarded = 0;
    for (int i = 0; i < 40 && !forwarded; i++) {
        ASSERT_EQ(probe_send_inner_ipv4(p), 0);
        harness_pump(&h, &g_tun_output_count, 50);
        forwarded = g_tun_output_count > 0;
    }
    ASSERT_EQ(forwarded, 1);

    /* 3. Bogus request on the SAME connection → 501, fin both ways; wait
     * for the client-side close of that request, then pump a little more
     * so the server-side stream close definitely lands too. */
    p->response_done = 0;
    p->status[0] = '\0';
    p->request_closed = 0;
    ASSERT_EQ(probe_open_request(p), 0);
    harness_pump(&h, &p->request_closed, 10000);
    ASSERT_EQ(p->request_closed, 1);
    ASSERT_STREQ(p->status, "501");
    int never = 0;
    harness_pump(&h, &never, 200);

    /* 4. The tunnel must still forward. */
    g_tun_output_count = 0;
    forwarded = 0;
    for (int i = 0; i < 40 && !forwarded; i++) {
        ASSERT_EQ(probe_send_inner_ipv4(p), 0);
        harness_pump(&h, &g_tun_output_count, 50);
        forwarded = g_tun_output_count > 0;
    }
    ASSERT_EQ(forwarded, 1);

    harness_stop(&h);
}

/* ── ACL decision core (pure, no live mqvpn_server_t) ── */

static uint32_t
ipv4(unsigned a, unsigned b, unsigned c, unsigned d)
{
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | d;
}

/* TEST-NET-2 (RFC 5737), ipv4(198,51,100,0): a neutral stand-in tunnel
 * subnet that never overlaps the default-deny ranges or the public/
 * RFC1918 IPs used below — isolates each ACL branch under test from the
 * others. */
#define NEUTRAL_TUNNEL_MASK 0xFFFFFF00u /* /24 */

TEST(acl_blocks_rfc1918)
{
    int allowed = svr_tcp_egress_acl_decide(ipv4(10, 0, 0, 5), NULL, 0, NULL, 0,
                                            ipv4(198, 51, 100, 0), NEUTRAL_TUNNEL_MASK);
    ASSERT_EQ(allowed, 0);
}

TEST(acl_blocks_loopback)
{
    int allowed = svr_tcp_egress_acl_decide(ipv4(127, 0, 0, 1), NULL, 0, NULL, 0,
                                            ipv4(198, 51, 100, 0), NEUTRAL_TUNNEL_MASK);
    ASSERT_EQ(allowed, 0);
}

TEST(acl_allow_punches_hole)
{
    mqvpn_cidr_entry_t allow[1] = {{ipv4(10, 0, 0, 0), 0xFF000000u}};
    int allowed = svr_tcp_egress_acl_decide(ipv4(10, 0, 0, 5), allow, 1, NULL, 0,
                                            ipv4(198, 51, 100, 0), NEUTRAL_TUNNEL_MASK);
    ASSERT_EQ(allowed, 1);
}

TEST(acl_blocks_own_tunnel_subnet)
{
    /* TEST-NET-3 (RFC 5737) as the tunnel subnet this time — outside every
     * DEFAULT_DENY_V4 entry, so a deny here can only be the tunnel-subnet
     * check, not an incidental default-deny match. No egress_deny at all. */
    uint32_t tunnel_net = ipv4(203, 0, 113, 0);
    uint32_t tunnel_mask = 0xFFFFFF00u;
    int allowed = svr_tcp_egress_acl_decide(ipv4(203, 0, 113, 5), NULL, 0, NULL, 0,
                                            tunnel_net, tunnel_mask);
    ASSERT_EQ(allowed, 0);
}

TEST(acl_default_allows_public_ip)
{
    int allowed = svr_tcp_egress_acl_decide(ipv4(8, 8, 8, 8), NULL, 0, NULL, 0,
                                            ipv4(198, 51, 100, 0), NEUTRAL_TUNNEL_MASK);
    ASSERT_EQ(allowed, 1);
}

TEST(acl_blocks_this_network)
{
    /* 0.0.0.0 is not a dead address: Linux connect() to it reaches
     * localhost, so it must hit the 0.0.0.0/8 default-deny row or the
     * loopback protection is bypassable. */
    int allowed = svr_tcp_egress_acl_decide(ipv4(0, 0, 0, 0), NULL, 0, NULL, 0,
                                            ipv4(198, 51, 100, 0), NEUTRAL_TUNNEL_MASK);
    ASSERT_EQ(allowed, 0);
}

TEST(acl_blocks_reserved_240)
{
    int allowed = svr_tcp_egress_acl_decide(ipv4(240, 0, 0, 1), NULL, 0, NULL, 0,
                                            ipv4(198, 51, 100, 0), NEUTRAL_TUNNEL_MASK);
    ASSERT_EQ(allowed, 0);
}

TEST(acl_deny_blocks_public_ip)
{
    /* egress_deny must be reachable past the default-deny table: a target
     * OUTSIDE every built-in range is denied only by the configured list. */
    mqvpn_cidr_entry_t deny[1] = {{ipv4(8, 8, 8, 8), 0xFFFFFFFFu}};
    int allowed = svr_tcp_egress_acl_decide(ipv4(8, 8, 8, 8), NULL, 0, deny, 1,
                                            ipv4(198, 51, 100, 0), NEUTRAL_TUNNEL_MASK);
    ASSERT_EQ(allowed, 0);
}

TEST(acl_allow_beats_deny)
{
    /* Precedence pin: the SAME range in both lists resolves to allowed,
     * because allow is checked before both the default-deny table and the
     * configured deny list (spec'd order — see acl_decide's docstring). */
    mqvpn_cidr_entry_t allow[1] = {{ipv4(8, 8, 8, 8), 0xFFFFFFFFu}};
    mqvpn_cidr_entry_t deny[1] = {{ipv4(8, 8, 8, 8), 0xFFFFFFFFu}};
    int allowed = svr_tcp_egress_acl_decide(ipv4(8, 8, 8, 8), allow, 1, deny, 1,
                                            ipv4(198, 51, 100, 0), NEUTRAL_TUNNEL_MASK);
    ASSERT_EQ(allowed, 1);
}

/* ── svr_tcp_egress_parse_path — fully attacker-controlled H3 :path bytes ── */

TEST(parse_path_accepts_valid)
{
    const char *path = "/.well-known/mqvpn/tcp/192.168.1.1/8080/";
    char host[16] = {0};
    uint16_t port = 0;
    int rc = svr_tcp_egress_parse_path(path, strlen(path), host, sizeof(host), &port);
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(host, "192.168.1.1");
    ASSERT_EQ(port, 8080);
}

TEST(parse_path_rejects_oversized_host)
{
    /* "255.255.255.255" is 15 chars + NUL = exactly fills a 16-byte
     * buffer; one more digit must not fit (and must not truncate). */
    const char *path = "/.well-known/mqvpn/tcp/1255.255.255.255/80/";
    char host[16];
    uint16_t port;
    int rc = svr_tcp_egress_parse_path(path, strlen(path), host, sizeof(host), &port);
    ASSERT_EQ(rc == 0, 0);
}

TEST(parse_path_rejects_missing_port)
{
    const char *path = "/.well-known/mqvpn/tcp/1.2.3.4/";
    char host[16];
    uint16_t port;
    int rc = svr_tcp_egress_parse_path(path, strlen(path), host, sizeof(host), &port);
    ASSERT_EQ(rc == 0, 0);

    const char *path2 = "/.well-known/mqvpn/tcp/1.2.3.4/notanumber/";
    rc = svr_tcp_egress_parse_path(path2, strlen(path2), host, sizeof(host), &port);
    ASSERT_EQ(rc == 0, 0);
}

TEST(parse_path_rejects_port_out_of_range)
{
    char host[16];
    uint16_t port;

    /* Port 0 is not a connectable port. */
    const char *p0 = "/.well-known/mqvpn/tcp/1.2.3.4/0/";
    ASSERT_EQ(svr_tcp_egress_parse_path(p0, strlen(p0), host, sizeof(host), &port) == 0,
              0);

    /* One past the max — must be rejected, not wrapped to 0. */
    const char *p65536 = "/.well-known/mqvpn/tcp/1.2.3.4/65536/";
    ASSERT_EQ(
        svr_tcp_egress_parse_path(p65536, strlen(p65536), host, sizeof(host), &port) == 0,
        0);
}

TEST(parse_path_rejects_trailing_bytes)
{
    /* The trailing '/' must be the LAST byte — extra segments/bytes after
     * it break the byte-for-byte template match. */
    const char *path = "/.well-known/mqvpn/tcp/1.2.3.4/443/x";
    char host[16];
    uint16_t port;
    int rc = svr_tcp_egress_parse_path(path, strlen(path), host, sizeof(host), &port);
    ASSERT_EQ(rc == 0, 0);
}

TEST(parse_path_rejects_wrong_prefix)
{
    const char *path = "/probe";
    char host[16];
    uint16_t port;
    int rc = svr_tcp_egress_parse_path(path, strlen(path), host, sizeof(host), &port);
    ASSERT_EQ(rc == 0, 0);
}

TEST(parse_path_rejects_empty)
{
    char host[16];
    uint16_t port;
    int rc = svr_tcp_egress_parse_path("", 0, host, sizeof(host), &port);
    ASSERT_EQ(rc == 0, 0);
}

int
main(void)
{
    printf("test_tcp_egress: server mqvpn-tcp dispatch tests\n");

    run_unrecognized_protocol_gets_501();
    run_mqvpn_tcp_bad_path_gets_400();
    run_mqvpn_tcp_acl_denied_gets_403();
    run_mqvpn_tcp_acl_allow_hole_gets_503();
    run_non_tunnel_close_keeps_tunnel_established();
    run_acl_blocks_rfc1918();
    run_acl_blocks_loopback();
    run_acl_allow_punches_hole();
    run_acl_blocks_own_tunnel_subnet();
    run_acl_default_allows_public_ip();
    run_acl_blocks_this_network();
    run_acl_blocks_reserved_240();
    run_acl_deny_blocks_public_ip();
    run_acl_allow_beats_deny();
    run_parse_path_accepts_valid();
    run_parse_path_rejects_oversized_host();
    run_parse_path_rejects_missing_port();
    run_parse_path_rejects_port_out_of_range();
    run_parse_path_rejects_trailing_bytes();
    run_parse_path_rejects_wrong_prefix();
    run_parse_path_rejects_empty();

    printf("\n  %d/%d tests passed\n", g_tests_passed, g_tests_run);
    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
