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
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
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

    /* Cached request object (relay tests below): probe_open_request_
     * with_body sets this so probe_send_body_retry/probe_send_fin_retry
     * and a direct xqc_h3_request_close (closing-notify idempotency test)
     * have something to act on. NULL for the fire-and-forget dispatch
     * probes above, which never need it. */
    xqc_h3_request_t *req;

    /* CONNECT-IP tunnel state (probe_open_connect_ip) */
    uint64_t masque_stream_id;
    int tunnel_ready; /* ADDRESS_ASSIGN (v4) parsed from the response body */
    uint8_t assigned_ip[4];
    uint8_t body_buf[256];
    size_t body_len;

    /* Raw body capture (relay tests below): when set, probe_cb_request_
     * read's body branch accumulates bytes verbatim into a growable buffer
     * instead of running the CONNECT-IP capsule decoder above — the
     * connect-tcp relay tests need the exact echoed bytes, not capsule
     * semantics. raw_recv_fin mirrors recv_body's *fin contract (verified
     * level-triggered re-report — set once observed, never cleared). */
    int raw_capture;
    uint8_t *raw_recv_buf;
    size_t raw_recv_len;
    size_t raw_recv_cap;
    int raw_recv_fin;

    /* Parked-flow idle-eviction test: when set, probe_cb_request_read's body
     * branch does NOT call xqc_h3_request_recv_body at all on a
     * XQC_REQ_NOTIFY_READ_BODY notify — no consumption means xquic never
     * grows this stream's receive window back, which is exactly the
     * condition (client stops reading, never reopens flow control) that
     * parks a server-side connect-tcp flow in uplink_withheld. Independent
     * of raw_capture (checked first) so the two knobs don't fight. */
    int suppress_body_drain;
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

/* Same header set as probe_open_request, but fin=0 (a body follows) and
 * caches the request object on the probe (p->req) for the relay tests
 * below — those need to drive send_body/send_fin/close on the SAME
 * request object across multiple harness_pump slices, not just fire
 * headers and forget it. Kept as a separate function rather than adding a
 * fin parameter to probe_open_request: every existing caller of that one
 * wants the fixed fin=1 dispatch-probe shape, and this one is only ever
 * used by the mqvpn-tcp relay tests (which always want fin=0 + the cached
 * pointer). */
static int
probe_open_request_with_body(probe_conn_t *p)
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

    ssize_t ret = xqc_h3_request_send_headers(req, &headers, 0);
    if (ret < 0) return -1;
    p->req = req;
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
        if (p->suppress_body_drain) {
            /* Deliberately do not call recv_body — see the field comment on
             * probe_conn_t.suppress_body_drain. */
            return 0;
        }
        if (p->raw_capture) {
            /* Relay tests: capture the echoed bytes verbatim,
             * growing the buffer as needed — no capsule framing on a
             * connect-tcp stream, this IS the relayed payload. */
            unsigned char buf[4096];
            unsigned char fin = 0;
            ssize_t n;
            while ((n = xqc_h3_request_recv_body(h3_request, buf, sizeof(buf), &fin)) >
                   0) {
                if (p->raw_recv_len + (size_t)n > p->raw_recv_cap) {
                    size_t new_cap = p->raw_recv_cap ? p->raw_recv_cap * 2 : 65536;
                    while (new_cap < p->raw_recv_len + (size_t)n)
                        new_cap *= 2;
                    uint8_t *nb = realloc(p->raw_recv_buf, new_cap);
                    if (!nb) {
                        printf("FAIL\n    probe raw_recv_buf realloc failed\n");
                        exit(1);
                    }
                    p->raw_recv_buf = nb;
                    p->raw_recv_cap = new_cap;
                }
                memcpy(p->raw_recv_buf + p->raw_recv_len, buf, (size_t)n);
                p->raw_recv_len += (size_t)n;
            }
            if (n == 0 && fin) p->raw_recv_fin = 1;
            return 0;
        }
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

/* Minimal fd-interest reactor for mqvpn_server_callbacks_t.egress_fd_register
 * — a real platform embedder runs an actual event loop (epoll/kqueue/IOCP);
 * this harness just tracks the handful of egress fds a test's connect-tcp
 * flows open and polls them from harness_pump. Without this, tcp_egress.c's
 * EINPROGRESS connects register interest but nothing ever calls
 * mqvpn_server_on_egress_fd_ready, so they stall forever (exactly the
 * documented rough edge for an operator who never wires the callback —
 * except here it's the TEST that must wire it, not the code under test). */
#define HARNESS_MAX_EGRESS_FDS 8

typedef struct {
    int fd;
    void *fd_ctx;
    int want_read, want_write;
    int active;
} harness_egress_fd_t;

typedef struct {
    int svr_fd, cli_fd;
    struct sockaddr_in svr_addr, cli_addr;
    mqvpn_server_t *svr;
    probe_conn_t probe;
    harness_egress_fd_t egress_fds[HARNESS_MAX_EGRESS_FDS];
} harness_t;

/* mqvpn_server_callbacks_t.egress_fd_register implementation: records/
 * updates one slot in h->egress_fds, keyed by fd. Passed mqvpn_server_new's
 * user_ctx (the harness itself) as `user_ctx`. Mirrors the real contract
 * (libmqvpn.h / platform_linux.c): register only ever (re)arms interest —
 * dropping it is the SEPARATE egress_fd_unregister callback below, not a
 * want_read=want_write=0 call here. */
static void
harness_egress_fd_register(int fd, int want_read, int want_write, void *fd_ctx,
                           void *user_ctx)
{
    harness_t *h = (harness_t *)user_ctx;
    for (int i = 0; i < HARNESS_MAX_EGRESS_FDS; i++) {
        if (h->egress_fds[i].active && h->egress_fds[i].fd == fd) {
            h->egress_fds[i].fd_ctx = fd_ctx;
            h->egress_fds[i].want_read = want_read;
            h->egress_fds[i].want_write = want_write;
            return;
        }
    }
    for (int i = 0; i < HARNESS_MAX_EGRESS_FDS; i++) {
        if (!h->egress_fds[i].active) {
            h->egress_fds[i].fd = fd;
            h->egress_fds[i].fd_ctx = fd_ctx;
            h->egress_fds[i].want_read = want_read;
            h->egress_fds[i].want_write = want_write;
            h->egress_fds[i].active = 1;
            return;
        }
    }
    /* Slot table full: this harness only ever runs one or two flows per
     * test, so silently dropping here would only mask a real test bug —
     * fail loudly instead of stalling mysteriously later. */
    printf("FAIL\n    harness_egress_fd_register: HARNESS_MAX_EGRESS_FDS exceeded\n");
    exit(1);
}

/* mqvpn_server_callbacks_t.egress_fd_unregister implementation: clears the
 * slot for fd, if any. No-op for an fd the harness never registered
 * (mirrors platform_linux.c's find_egress_slot-returns-NULL no-op) — every
 * flow-destroy path calls this, including ones that never registered a fd
 * at all (synchronous connect() failures). Critical for correctness, not
 * just bookkeeping: once tcp_egress.c close()s the real fd, the fd number
 * can be reused by an unrelated socket; if the harness kept polling a stale
 * slot it would eventually call mqvpn_server_on_egress_fd_ready with a
 * dangling fd_ctx pointing at an already-freed flow. */
static void
harness_egress_fd_unregister(int fd, void *user_ctx)
{
    harness_t *h = (harness_t *)user_ctx;
    for (int i = 0; i < HARNESS_MAX_EGRESS_FDS; i++) {
        if (h->egress_fds[i].active && h->egress_fds[i].fd == fd) {
            h->egress_fds[i].active = 0;
            return;
        }
    }
}

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
        /* [Hybrid] Enabled defaults to false (docs/control-api.md) — this
         * whole file's dispatch tests exercise the connect-tcp path, which
         * (I2 fix) now ALSO gates on this runtime flag, not just the compile
         * flag. Default it on here so every existing test keeps exercising
         * real dispatch; run_hybrid_disabled_gets_501 below overrides it
         * back off via cfg_hook to cover the gate itself. */
        mqvpn_config_set_hybrid_enabled(svr_cfg, 1);
        if (cfg_hook) cfg_hook(svr_cfg);

        mqvpn_server_callbacks_t svr_cbs = MQVPN_SERVER_CALLBACKS_INIT;
        svr_cbs.tun_output = counting_tun_output;
        svr_cbs.tunnel_config_ready = noop_tunnel_config_ready;
        svr_cbs.egress_fd_register = harness_egress_fd_register;
        svr_cbs.egress_fd_unregister = harness_egress_fd_unregister;

        h->svr = mqvpn_server_new(svr_cfg, &svr_cbs, h);
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

        /* Egress fd events (connect-tcp connect()/relay I/O the server
         * registered via egress_fd_register). Zero-timeout poll: this is
         * the reactor's "check what's ready right now" pass, matched by
         * the harness-wide sleep-and-retry loop below for the case where
         * nothing is ready yet. */
        for (int i = 0; i < HARNESS_MAX_EGRESS_FDS; i++) {
            if (!h->egress_fds[i].active) continue;
            /* No-interest registration (want_read=0, want_write=0): the
             * server parked the fd (e.g. ACTIVE flow awaiting the relay
             * stage). libevent would never fire an event with neither
             * EV_READ nor EV_WRITE — skip entirely, or poll()'s
             * always-reported POLLHUP/POLLERR would dispatch events the
             * real platform never delivers. */
            if (!h->egress_fds[i].want_read && !h->egress_fds[i].want_write) continue;
            struct pollfd epfd = {.fd = h->egress_fds[i].fd, .events = 0};
            if (h->egress_fds[i].want_read) epfd.events |= POLLIN;
            if (h->egress_fds[i].want_write) epfd.events |= POLLOUT;
            if (poll(&epfd, 1, 0) > 0 && epfd.revents != 0) {
                int readable = (epfd.revents & (POLLIN | POLLHUP | POLLERR)) != 0;
                int writable = (epfd.revents & (POLLOUT | POLLERR)) != 0;
                mqvpn_server_on_egress_fd_ready(h->svr, h->egress_fds[i].fd,
                                                h->egress_fds[i].fd_ctx, readable,
                                                writable);
            }
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

/* Send `len` bytes of H3 body from `data`, retrying across -XQC_EAGAIN by
 * pumping the harness between attempts (mirrors the client tcp_lane's own
 * partial-accept-then-retry discipline — the probe's send window is
 * finite, and the downlink-backpressure test deliberately never drains its
 * sink, which propagates all the way back to blocking the probe's own H3
 * sends via ordinary QUIC stream flow control). `iter_budget` bounds the
 * number of 20ms pump slices attempted (not wall-clock time — the harness's
 * own poll already has generous per-iteration timeouts) as a livelock
 * backstop; a real bug shows up as a failed byte-count assertion long
 * before this fires. Returns 0 once every byte was accepted by xquic, -1 on
 * a fatal send error or exhausted budget. */
static int
probe_send_body_retry(harness_t *h, probe_conn_t *p, const uint8_t *data, size_t len,
                      int iter_budget)
{
    size_t off = 0;
    for (int i = 0; i < iter_budget; i++) {
        while (off < len) {
            ssize_t sent = xqc_h3_request_send_body(
                p->req, (unsigned char *)(uintptr_t)(data + off), len - off, 0);
            if (sent == -XQC_EAGAIN) break;
            if (sent < 0) return -1;
            off += (size_t)sent;
        }
        if (off >= len) return 0;
        int never = 0;
        harness_pump(h, &never, 20);
    }
    return -1;
}

/* Bare H3 fin (send_body(NULL, 0, 1)), same EAGAIN-retry shape as above.
 * Mirrors the server's own svr_tcp_egress_try_uplink_fin retry discipline
 * from the OTHER direction — xquic does not buffer a fin-only send across
 * -XQC_EAGAIN on either side of the connection. */
static int
probe_send_fin_retry(harness_t *h, probe_conn_t *p, int iter_budget)
{
    for (int i = 0; i < iter_budget; i++) {
        ssize_t sent = xqc_h3_request_send_body(p->req, NULL, 0, 1);
        if (sent >= 0) return 0;
        if (sent != -XQC_EAGAIN) return -1;
        int never = 0;
        harness_pump(h, &never, 20);
    }
    return -1;
}

static void
harness_stop(harness_t *h)
{
    xqc_engine_destroy(h->probe.engine);
    mqvpn_server_destroy(h->svr);
    close(h->svr_fd);
    close(h->cli_fd);
}

/* ── Minimal in-test TCP echo/sink server (relay tests below) ──
 *
 * The relay paths under test run REAL syscalls against a REAL egress
 * socket (send()/recv()/shutdown() in tcp_egress.c) — proving them needs a
 * real TCP peer, not a fake-xquic double (test_tcp_lane.c's approach
 * doesn't apply: the thing under test IS the socket boundary itself). This
 * is a tiny, single-connection, manually-pumped TCP server driven from the
 * SAME test-loop tick as harness_pump — no threads, so it composes with
 * the existing poll-based harness without adding concurrency to reason
 * about. */
typedef struct {
    int listen_fd;
    int conn_fd; /* -1 until accepted */
    int port;
    int echo;                   /* 1: echo every byte read straight back (tests 1-3);
                                 * 0: sink mode — accept only, never read (test 4 drains
                                 * the accepted fd directly from the test body instead). */
    int close_after_first_echo; /* test 2 (EOF -> H3 FIN): close() right
                                 * after echoing back whatever was read. */
    int eof_seen;               /* recv()==0 observed on conn_fd (echo mode only). */
    uint64_t echoed_bytes;
} tcp_sink_t;

static int
tcp_sink_open(tcp_sink_t *s, int echo)
{
    memset(s, 0, sizeof(*s));
    s->conn_fd = -1;
    s->echo = echo;
    s->listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (s->listen_fd < 0) return -1;
    int one = 1;
    setsockopt(s->listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);
    if (bind(s->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(s->listen_fd, 4) != 0) {
        close(s->listen_fd);
        return -1;
    }
    socklen_t alen = sizeof(addr);
    getsockname(s->listen_fd, (struct sockaddr *)&addr, &alen);
    s->port = ntohs(addr.sin_port);
    return 0;
}

/* One non-blocking tick: accept if not yet accepted, then (echo mode only)
 * drain+echo whatever's currently available and note EOF. Sink mode
 * (echo=0) only ever accepts here — test 4 reads the accepted fd directly
 * from the test body once it's ready to start draining, which is the
 * entire point of that test. Call once per harness_pump slice. */
static void
tcp_sink_pump(tcp_sink_t *s)
{
    if (s->conn_fd < 0) {
        struct sockaddr_in from;
        socklen_t flen = sizeof(from);
        int fd = accept(s->listen_fd, (struct sockaddr *)&from, &flen);
        if (fd >= 0) {
            int fl = fcntl(fd, F_GETFL, 0);
            fcntl(fd, F_SETFL, fl | O_NONBLOCK);
            s->conn_fd = fd;
        }
        return;
    }
    if (!s->echo) return;

    uint8_t buf[4096];
    for (;;) {
        ssize_t n = recv(s->conn_fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n == 0) {
            s->eof_seen = 1;
            break;
        }
        if (n < 0) break; /* EAGAIN (or a real error) — nothing more now */
        ssize_t off = 0;
        while (off < n) {
            /* MSG_NOSIGNAL: don't let a peer that already closed take the
             * whole test process down with SIGPIPE (same suppression the
             * code under test applies to its own sends). */
            ssize_t sent = send(s->conn_fd, buf + off, (size_t)(n - off),
                                MSG_DONTWAIT | MSG_NOSIGNAL);
            if (sent <= 0)
                break; /* best-effort; the small test payloads
                        * used here never hit real backpressure
                        * echoing back over loopback. */
            off += sent;
        }
        s->echoed_bytes += (uint64_t)n;
        if (s->close_after_first_echo) {
            close(s->conn_fd);
            s->conn_fd = -1;
            return;
        }
    }
}

static void
tcp_sink_close(tcp_sink_t *s)
{
    if (s->conn_fd >= 0) close(s->conn_fd);
    close(s->listen_fd);
}

/* harness_pump, plus a tcp_sink_pump tick before each slice — the shape
 * every relay test drives its I/O with. `done` follows harness_pump's own
 * contract (a probe-side flag such as response_done); pass a throwaway int
 * for tests that only care about the sink-side observable. */
static void
harness_pump_with_sink(harness_t *h, tcp_sink_t *sink, const int *done, int budget_ms)
{
    for (int elapsed = 0; elapsed < budget_ms && !*done; elapsed += 20) {
        tcp_sink_pump(sink);
        int slice_done = 0;
        harness_pump(h, &slice_done, 20);
        if (*done) break;
    }
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

/* Config hook for hybrid_disabled_gets_501 below: overrides harness_start's
 * default (Enabled=1, see its comment) back to false, matching the real
 * documented default (docs/control-api.md: "[Hybrid] Enabled" is a
 * client+server kill switch, default false). */
static void
harness_cfg_hybrid_disabled(mqvpn_config_t *cfg)
{
    mqvpn_config_set_hybrid_enabled(cfg, 0);
}

TEST(hybrid_disabled_gets_501)
{
    /* I2 regression: a hybrid-compiled server with runtime Enabled=false
     * must treat :protocol=="mqvpn-tcp" exactly like an unrecognized
     * protocol (501), not serve egress. Uses a syntactically VALID
     * connect-tcp path (same template mqvpn_tcp_acl_denied_gets_403 above
     * uses) specifically to prove the gate fires before path parsing / ACL
     * / connect ever run — a bad-path or ACL-denied response would not
     * distinguish "gated off" from "gated on but rejected downstream". */
    char status[16] = {0};
    int rc = run_dispatch_probe_with_path(
        "mqvpn-tcp", 9, "/.well-known/mqvpn/tcp/10.0.0.5/80/",
        harness_cfg_hybrid_disabled, status, sizeof(status));
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(status, "501");
}

/* Config hook for the allow-hole tests below: the PUBLIC egress-ACL setter,
 * exactly as a platform embedding libmqvpn would call it. 127.0.0.1/32
 * (not 10.0.0.0/8): these tests now drive a REAL egress connect() against a
 * loopback listener the test process itself opens, so the hole needs to
 * punch through the built-in loopback default-deny, not RFC1918. */
static void
harness_cfg_allow_127(mqvpn_config_t *cfg)
{
    const char *allow[] = {"127.0.0.1/32"};
    if (mqvpn_config_set_hybrid_egress_acl(cfg, allow, 1, NULL, 0) != MQVPN_OK) {
        printf("FAIL\n    mqvpn_config_set_hybrid_egress_acl rejected valid input\n");
        exit(1);
    }
}

/* Same allow-hole, plus a short (1s) connect timeout — used by the
 * connect-timeout test so the deadline sweep fires quickly instead of
 * waiting out the 10s config default. */
static void
harness_cfg_allow_127_short_timeout(mqvpn_config_t *cfg)
{
    harness_cfg_allow_127(cfg);
    if (mqvpn_config_set_hybrid_connect_timeout(cfg, 1) != MQVPN_OK) {
        printf(
            "FAIL\n    mqvpn_config_set_hybrid_connect_timeout rejected valid input\n");
        exit(1);
    }
}

/* Allow-hole + a global egress fd cap of 1 (limits work, Step 1) — used by
 * the global-cap 503 test below. */
static void
harness_cfg_allow_127_global_cap1(mqvpn_config_t *cfg)
{
    harness_cfg_allow_127(cfg);
    if (mqvpn_config_set_hybrid_max_global_flows(cfg, 1) != MQVPN_OK) {
        printf("FAIL\n    mqvpn_config_set_hybrid_max_global_flows rejected valid "
               "input\n");
        exit(1);
    }
}

/* Allow-hole + a 1s ACTIVE idle timeout (limits work, Step 2) — shared
 * tcp_idle_timeout_sec field with the client's tcp_lane, set via the same
 * public setter tcp_lane's own tests use; tcp_max_flows kept at its
 * ordinary default (256) since these tests aren't exercising that cap. */
static void
harness_cfg_allow_127_idle_timeout_1(mqvpn_config_t *cfg)
{
    harness_cfg_allow_127(cfg);
    if (mqvpn_config_set_hybrid_limits(cfg, 256, 1) != MQVPN_OK) {
        printf("FAIL\n    mqvpn_config_set_hybrid_limits rejected valid input\n");
        exit(1);
    }
}

/* Injects an INVALID hybrid scalar the way the INI/JSON bridge does —
 * mqvpn_config_apply_hybrid (mqvpn_internal.h) copies raw with no range
 * checks, exactly like platform_linux.c's file-config bridge; the PUBLIC
 * setters would reject the 0 — then punches the usual loopback allow hole
 * alongside it. Used by the sanitize-at-consumer test below: server_new
 * must warn-reset ONLY the bad field, leaving the hole (ACL) intact. */
static void
harness_cfg_invalid_hybrid_global_cap0(mqvpn_config_t *cfg)
{
    mqvpn_hybrid_config_t bad;
    mqvpn_hybrid_config_default(&bad);
    bad.enabled = 1;              /* mqvpn_config_apply_hybrid replaces the WHOLE block,
                                   * including Enabled — without this, this test's own
                                   * harness_start default (Enabled=1) is wiped out by
                                   * mqvpn_hybrid_config_default's false, and I2's runtime
                                   * gate would 501 the probe before it ever reaches the
                                   * sanitize-then-ACL behavior this test targets. */
    bad.tcp_max_global_flows = 0; /* invalid: would freeze the fd budget at 0 */
    mqvpn_config_apply_hybrid(cfg, &bad);
    harness_cfg_allow_127(cfg);
}

/* Opens a real loopback listener on an ephemeral port and returns it
 * (still LISTENing, nothing accepted) plus the port in host byte order.
 * Shared by the real-connect-success test and the second-probe-after-
 * timeout regression below. */
static int
open_loopback_listener(int *out_port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, 4) != 0) {
        close(fd);
        return -1;
    }
    socklen_t alen = sizeof(addr);
    getsockname(fd, (struct sockaddr *)&addr, &alen);
    *out_port = ntohs(addr.sin_port);
    return fd;
}

TEST(mqvpn_tcp_acl_allow_hole_reaches_real_connect)
{
    /* Proves CONFIGURED allow lists reach the live request path (public
     * setter -> config.hybrid -> svr_get_egress_policy -> decision) all the
     * way through to a real, successful egress connect(): with
     * egress_allow=127.0.0.1/32 punched through the loopback default-deny,
     * a connect-tcp request targeting a real local listener gets a genuine
     * 200 (replacing the old start_connect stub's unconditional 503), AND
     * the stream stays open (fin=0 — the relay-ready contract the next
     * task's relay depends on): no request-close lands within a post-200
     * pump window. Contrast the 501/4xx paths, where fin=1 makes
     * request_closed fire promptly (see the tunnel-survival test). */
    int target_port = 0;
    int listen_fd = open_loopback_listener(&target_port);
    ASSERT_EQ(listen_fd >= 0, 1);

    char path[64];
    snprintf(path, sizeof(path), "/.well-known/mqvpn/tcp/127.0.0.1/%d/", target_port);

    harness_t h;
    ASSERT_EQ(harness_start(&h, "mqvpn-tcp", 9, /*auto_open=*/0, harness_cfg_allow_127),
              0);
    h.probe.path = path;

    harness_pump(&h, &h.probe.handshake_done, 10000);
    ASSERT_EQ(h.probe.handshake_done, 1);

    /* Zero egress flows: get_interest works and imposes no egress clamp
     * (whatever xquic's timer says stands — only sanity-assertable here
     * since xquic's own value isn't pinned). Contrast the <= 1000 assert
     * below once a flow is live. */
    {
        mqvpn_interest_t it = {0};
        ASSERT_EQ(mqvpn_server_get_interest(h.svr, &it), MQVPN_OK);
        ASSERT_EQ(it.next_timer_ms >= 1, 1);
    }

    ASSERT_EQ(probe_open_request(&h.probe), 0);

    harness_pump(&h, &h.probe.response_done, 10000);
    ASSERT_EQ(h.probe.response_done, 1);
    ASSERT_STREQ(h.probe.status, "200");

    /* One live egress flow: the interest timer must be clamped to <= 1s so
     * a quiet platform still ticks often enough for the connect-timeout /
     * idle-eviction sweeps (svr_tcp_egress_tick) to fire near their
     * deadlines — xquic's own timer knows nothing about them. */
    {
        mqvpn_interest_t it = {0};
        ASSERT_EQ(mqvpn_server_get_interest(h.svr, &it), MQVPN_OK);
        ASSERT_EQ(it.next_timer_ms >= 1 && it.next_timer_ms <= 1000, 1);
    }

    /* fin=0 assertion: keep pumping past the 200 — the request must NOT
     * close. (400ms window; a server-sent fin would close the client-side
     * request well within it, as the 501 test's request_closed wait shows.) */
    harness_pump(&h, &h.probe.request_closed, 400);
    ASSERT_EQ(h.probe.request_closed, 0);

    harness_stop(&h);
    close(listen_fd);
}

TEST(mqvpn_tcp_connect_timeout_gets_504)
{
    /* Deterministic, netns-free "blackhole": a listening socket with a
     * small backlog whose accept queue is filled by non-blocking filler
     * connects that are never accept()ed. A subsequent connect() to the
     * same listener then never resolves (empirically verified 5/5 runs
     * with an 800ms poll window standalone before wiring this in) — the
     * server's own connect_deadline_us sweep (svr_tcp_egress_tick), not any
     * OS-level SYN-retry timeout, is what must fire here. TcpConnectTimeoutSec
     * is set to 1 via cfg_hook so the test doesn't wait out the 10s default. */
    int target_port = 0;
    int listen_fd = open_loopback_listener(&target_port);
    ASSERT_EQ(listen_fd >= 0, 1);
    ASSERT_EQ(listen(listen_fd, 1), 0); /* re-listen with backlog=1 (was 4) */

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    target_addr.sin_port = htons((uint16_t)target_port);

#define N_FILLERS 16
    int filler_fds[N_FILLERS];
    for (int i = 0; i < N_FILLERS; i++) {
        filler_fds[i] = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        ASSERT_EQ(filler_fds[i] >= 0, 1);
        connect(filler_fds[i], (struct sockaddr *)&target_addr, sizeof(target_addr));
    }
    usleep(200000); /* let whichever fillers can complete their handshake do so */

    char path[64];
    snprintf(path, sizeof(path), "/.well-known/mqvpn/tcp/127.0.0.1/%d/", target_port);

    harness_t h;
    ASSERT_EQ(harness_start(&h, "mqvpn-tcp", 9, /*auto_open=*/0,
                            harness_cfg_allow_127_short_timeout),
              0);
    h.probe.path = path;

    harness_pump(&h, &h.probe.handshake_done, 10000);
    ASSERT_EQ(h.probe.handshake_done, 1);
    ASSERT_EQ(probe_open_request(&h.probe), 0);

    harness_pump(&h, &h.probe.response_done, 10000);
    ASSERT_EQ(h.probe.response_done, 1);
    ASSERT_STREQ(h.probe.status, "504");

    /* Regression: after the timed-out flow is torn down, its counters
     * (per-connection tcp_flow_count, global tcp_egress_global_fd_count)
     * must not be stuck elevated (or underflowed) — a second connect-tcp
     * request on the SAME h3 connection, this time to a real listener,
     * must still succeed. */
    int ok_port = 0;
    int ok_listen_fd = open_loopback_listener(&ok_port);
    ASSERT_EQ(ok_listen_fd >= 0, 1);
    char ok_path[64];
    snprintf(ok_path, sizeof(ok_path), "/.well-known/mqvpn/tcp/127.0.0.1/%d/", ok_port);

    h.probe.path = ok_path;
    h.probe.response_done = 0;
    h.probe.status[0] = '\0';
    ASSERT_EQ(probe_open_request(&h.probe), 0);
    harness_pump(&h, &h.probe.response_done, 10000);
    ASSERT_EQ(h.probe.response_done, 1);
    ASSERT_STREQ(h.probe.status, "200");

    harness_stop(&h);
    close(ok_listen_fd);
    for (int i = 0; i < N_FILLERS; i++)
        close(filler_fds[i]);
    close(listen_fd);
#undef N_FILLERS
}

/* Global fd cap (limits work, Step 1): with tcp_max_global_flows=1, a first
 * connect-tcp flow is admitted and stays open; a SECOND, CONCURRENT flow on
 * the SAME H3 connection is rejected with 503 before it even attempts a
 * connect() (the admission check in svr_tcp_egress_start_connect runs before
 * socket()). Proves the cap is server-wide, not merely per-H3-connection:
 * distinct from tcp_max_flows (default 256), which wouldn't reject a second
 * request on the same connection at all. Uses a second, independently
 * request-scoped probe_conn_t as request-level user_data for the SAME
 * xquic connection/cid (probe_open_request_with_body only touches
 * request-scoped fields, so this is safe) rather than a second full client
 * connection — simpler, and the global counter tcp_egress.c decrements/
 * increments doesn't care which connection a flow came from either way. */
TEST(mqvpn_tcp_global_cap_gets_503)
{
    int port1 = 0, port2 = 0;
    int fd1 = open_loopback_listener(&port1);
    ASSERT_EQ(fd1 >= 0, 1);
    int fd2 = open_loopback_listener(&port2);
    ASSERT_EQ(fd2 >= 0, 1);

    char path1[64], path2[64];
    snprintf(path1, sizeof(path1), "/.well-known/mqvpn/tcp/127.0.0.1/%d/", port1);
    snprintf(path2, sizeof(path2), "/.well-known/mqvpn/tcp/127.0.0.1/%d/", port2);

    harness_t h;
    ASSERT_EQ(harness_start(&h, "mqvpn-tcp", 9, /*auto_open=*/0,
                            harness_cfg_allow_127_global_cap1),
              0);
    h.probe.path = path1;

    harness_pump(&h, &h.probe.handshake_done, 10000);
    ASSERT_EQ(h.probe.handshake_done, 1);
    ASSERT_EQ(probe_open_request_with_body(&h.probe), 0);

    harness_pump(&h, &h.probe.response_done, 10000);
    ASSERT_EQ(h.probe.response_done, 1);
    ASSERT_STREQ(h.probe.status, "200"); /* consumes the one global fd slot */

    /* mqvpn_server_get_stats().tcp_flows_active must reflect exactly this
     * one open egress flow — the whole-server wiring reads
     * tcp_egress_global_fd_count verbatim (see mqvpn_server.c), so this
     * pins that it is neither stuck at 0 nor double-counting. */
    {
        mqvpn_stats_t st;
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(mqvpn_server_get_stats(h.svr, &st), MQVPN_OK);
        ASSERT_EQ(st.tcp_flows_active, 1);
    }

    probe_conn_t second;
    memset(&second, 0, sizeof(second));
    second.engine = h.probe.engine;
    memcpy(&second.cid, &h.probe.cid, sizeof(second.cid));
    second.protocol = h.probe.protocol;
    second.protocol_len = h.probe.protocol_len;
    snprintf(second.authority, sizeof(second.authority), "%s", h.probe.authority);
    second.path = path2;
    ASSERT_EQ(probe_open_request_with_body(&second), 0);

    harness_pump(&h, &second.response_done, 10000);
    ASSERT_EQ(second.response_done, 1);
    ASSERT_STREQ(second.status, "503");

    /* The cumulative cap counters must move: exactly one flow was admitted
     * so far (flows_total == 1, still active) and exactly one was cap-503'd
     * (flows_rejected == 1). Neither decrements, so these are stable proofs
     * the wiring reads the real tcp_egress counters, not a stub. */
    {
        mqvpn_stats_t st;
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(mqvpn_server_get_stats(h.svr, &st), MQVPN_OK);
        ASSERT_EQ(st.tcp_flows_total, 1);
        ASSERT_EQ(st.tcp_flows_rejected, 1);
    }

    /* Release the one slot (close flow #1's stream and wait for the
     * client-visible close), then a THIRD attempt on the same connection
     * must succeed again — the cap releases on destroy, same regression
     * shape as the connect-timeout test above. */
    ASSERT_EQ(xqc_h3_request_close(h.probe.req), 0);
    int flow1_gone = 0;
    for (int i = 0; i < 500 && !flow1_gone; i++) {
        int never = 0;
        harness_pump(&h, &never, 20);
        flow1_gone = h.probe.request_closed;
    }
    ASSERT_EQ(flow1_gone, 1);

    /* The slot's release must be visible in tcp_flows_active too — proves
     * the counter decrements on flow teardown, not just increments on
     * open (a stuck-elevated counter would otherwise silently mislead
     * monitoring long after the flow that caused it is gone). */
    {
        mqvpn_stats_t st;
        memset(&st, 0, sizeof(st));
        ASSERT_EQ(mqvpn_server_get_stats(h.svr, &st), MQVPN_OK);
        ASSERT_EQ(st.tcp_flows_active, 0);
    }

    h.probe.path = path1;
    h.probe.response_done = 0;
    h.probe.status[0] = '\0';
    h.probe.request_closed = 0;
    ASSERT_EQ(probe_open_request_with_body(&h.probe), 0);
    harness_pump(&h, &h.probe.response_done, 10000);
    ASSERT_EQ(h.probe.response_done, 1);
    ASSERT_STREQ(h.probe.status, "200");

    harness_stop(&h);
    close(fd1);
    close(fd2);
    free(h.probe.raw_recv_buf);
    free(second.raw_recv_buf);
}

/* Sanitize-at-consumer (limits follow-up): an INVALID hybrid scalar arriving
 * through the raw file-config bridge (TcpMaxGlobalFlows = 0 — CFG_U32
 * stores it unchecked) must be warn-reset PER FIELD by mqvpn_server_new
 * BEFORE the fd budget is frozen — and ONLY that field: a whole-block
 * default reset would silently drop the operator's egress ACL policy over
 * an unrelated typo (fail-open on the deny direction). Two behavioral pins:
 *   1. the frozen budget is nonzero (came from the DEFAULT cap, not the
 *      invalid 0 — without the consumer-side sanitize it would freeze at 0
 *      and every connect-tcp request would 503 with zero log);
 *   2. the allow hole injected ALONGSIDE the invalid scalar SURVIVES: a
 *      loopback target gets a real 200 — not 403 (which a whole-block
 *      reset wiping the ACL would produce) and not 503 (which the
 *      unsanitized budget-0 config would produce).
 * The warns themselves aren't asserted (the harness pins log_level=ERROR
 * and has no capture hook); the behavioral outcome is the contract. */
TEST(mqvpn_tcp_invalid_hybrid_field_sanitized_acl_survives)
{
    int target_port = 0;
    int listen_fd = open_loopback_listener(&target_port);
    ASSERT_EQ(listen_fd >= 0, 1);

    char path[64];
    snprintf(path, sizeof(path), "/.well-known/mqvpn/tcp/127.0.0.1/%d/", target_port);

    harness_t h;
    ASSERT_EQ(harness_start(&h, "mqvpn-tcp", 9, /*auto_open=*/0,
                            harness_cfg_invalid_hybrid_global_cap0),
              0);

    /* Pin 1: budget frozen from the per-field default, not the invalid 0. */
    ASSERT_EQ(mqvpn_server_egress_fd_budget(h.svr) > 0, 1);

    /* Pin 2: 200 — hole survived AND budget admits (403 = ACL wiped by a
     * whole-block reset; 503 = budget frozen at the unsanitized 0). */
    h.probe.path = path;
    harness_pump(&h, &h.probe.handshake_done, 10000);
    ASSERT_EQ(h.probe.handshake_done, 1);
    ASSERT_EQ(probe_open_request(&h.probe), 0);
    harness_pump(&h, &h.probe.response_done, 10000);
    ASSERT_EQ(h.probe.response_done, 1);
    ASSERT_STREQ(h.probe.status, "200");

    harness_stop(&h);
    close(listen_fd);
}

/* ── Relay: real syscalls against a real TCP peer ──
 *
 * Every test below opens a genuine connect-tcp flow against tcp_sink_t
 * (never against the raw H3 probe's own transport — this exercises
 * tcp_egress.c's send()/recv()/shutdown() calls for real, over loopback). */

/* Test 1: echo roundtrip — proves BOTH relay directions in one shot: the
 * probe's body reaches the sink (downlink), and the sink's echoed reply
 * reaches the probe's H3 response body (uplink). */
TEST(mqvpn_tcp_echo_roundtrip)
{
    tcp_sink_t sink;
    ASSERT_EQ(tcp_sink_open(&sink, /*echo=*/1), 0);

    char path[64];
    snprintf(path, sizeof(path), "/.well-known/mqvpn/tcp/127.0.0.1/%d/", sink.port);

    harness_t h;
    ASSERT_EQ(harness_start(&h, "mqvpn-tcp", 9, /*auto_open=*/0, harness_cfg_allow_127),
              0);
    h.probe.path = path;
    h.probe.raw_capture = 1;

    harness_pump(&h, &h.probe.handshake_done, 10000);
    ASSERT_EQ(h.probe.handshake_done, 1);
    ASSERT_EQ(probe_open_request_with_body(&h.probe), 0);

    harness_pump_with_sink(&h, &sink, &h.probe.response_done, 10000);
    ASSERT_EQ(h.probe.response_done, 1);
    ASSERT_STREQ(h.probe.status, "200");

    const char *msg = "hello mqvpn-tcp relay";
    size_t msg_len = strlen(msg);
    ASSERT_EQ(probe_send_body_retry(&h, &h.probe, (const uint8_t *)msg, msg_len, 500), 0);

    int got_all = 0;
    for (int i = 0; i < 500 && !got_all; i++) {
        int never = 0;
        harness_pump_with_sink(&h, &sink, &never, 20);
        got_all = h.probe.raw_recv_len >= msg_len;
    }
    ASSERT_EQ(got_all, 1);
    ASSERT_EQ(h.probe.raw_recv_len, msg_len);
    ASSERT_EQ(memcmp(h.probe.raw_recv_buf, msg, msg_len), 0);

    harness_stop(&h);
    tcp_sink_close(&sink);
    free(h.probe.raw_recv_buf);
}

/* Test 2: egress EOF -> pure H3 FIN. The sink closes right after echoing,
 * so the server's egress recv() sees EOF and must map it to
 * send_body(NULL, 0, 1) rather than silently going quiet or resetting the
 * stream. */
TEST(mqvpn_tcp_egress_eof_becomes_h3_fin)
{
    tcp_sink_t sink;
    ASSERT_EQ(tcp_sink_open(&sink, /*echo=*/1), 0);
    sink.close_after_first_echo = 1;

    char path[64];
    snprintf(path, sizeof(path), "/.well-known/mqvpn/tcp/127.0.0.1/%d/", sink.port);

    harness_t h;
    ASSERT_EQ(harness_start(&h, "mqvpn-tcp", 9, /*auto_open=*/0, harness_cfg_allow_127),
              0);
    h.probe.path = path;
    h.probe.raw_capture = 1;

    harness_pump(&h, &h.probe.handshake_done, 10000);
    ASSERT_EQ(h.probe.handshake_done, 1);
    ASSERT_EQ(probe_open_request_with_body(&h.probe), 0);

    harness_pump_with_sink(&h, &sink, &h.probe.response_done, 10000);
    ASSERT_EQ(h.probe.response_done, 1);
    ASSERT_STREQ(h.probe.status, "200");

    const char *msg = "goodbye";
    size_t msg_len = strlen(msg);
    ASSERT_EQ(probe_send_body_retry(&h, &h.probe, (const uint8_t *)msg, msg_len, 500), 0);

    int fin_seen = 0;
    for (int i = 0; i < 500 && !fin_seen; i++) {
        int never = 0;
        harness_pump_with_sink(&h, &sink, &never, 20);
        fin_seen = h.probe.raw_recv_fin;
    }
    ASSERT_EQ(fin_seen, 1);
    /* The echoed bytes must have arrived too — the sink closes AFTER
     * echoing, so a correct FIN mapping never truncates them. */
    ASSERT_EQ(h.probe.raw_recv_len, msg_len);
    ASSERT_EQ(memcmp(h.probe.raw_recv_buf, msg, msg_len), 0);

    harness_stop(&h);
    tcp_sink_close(&sink);
    free(h.probe.raw_recv_buf);
}

/* Test 3: H3 fin (client's send half) -> shutdown(fd, SHUT_WR). The probe
 * fins its OWN send direction after its bytes; the sink must observe a
 * clean half-close (read()==0) only once every byte has arrived (never a
 * premature/truncating shutdown), while the uplink direction (the sink's
 * echoed reply) still completes independently of that half-close. */
TEST(mqvpn_tcp_h3_fin_becomes_shut_wr)
{
    tcp_sink_t sink;
    ASSERT_EQ(tcp_sink_open(&sink, /*echo=*/1), 0);

    char path[64];
    snprintf(path, sizeof(path), "/.well-known/mqvpn/tcp/127.0.0.1/%d/", sink.port);

    harness_t h;
    ASSERT_EQ(harness_start(&h, "mqvpn-tcp", 9, /*auto_open=*/0, harness_cfg_allow_127),
              0);
    h.probe.path = path;
    h.probe.raw_capture = 1;

    harness_pump(&h, &h.probe.handshake_done, 10000);
    ASSERT_EQ(h.probe.handshake_done, 1);
    ASSERT_EQ(probe_open_request_with_body(&h.probe), 0);

    harness_pump_with_sink(&h, &sink, &h.probe.response_done, 10000);
    ASSERT_EQ(h.probe.response_done, 1);
    ASSERT_STREQ(h.probe.status, "200");

    const char *msg = "half close me";
    size_t msg_len = strlen(msg);
    ASSERT_EQ(probe_send_body_retry(&h, &h.probe, (const uint8_t *)msg, msg_len, 500), 0);

    /* Wait for the echo to complete BEFORE fin'ing, proving the uplink
     * direction fully works ahead of (and thus independent of) the
     * downlink half-close below. */
    int got_echo = 0;
    for (int i = 0; i < 500 && !got_echo; i++) {
        int never = 0;
        harness_pump_with_sink(&h, &sink, &never, 20);
        got_echo = h.probe.raw_recv_len >= msg_len;
    }
    ASSERT_EQ(got_echo, 1);

    ASSERT_EQ(probe_send_fin_retry(&h, &h.probe, 500), 0);

    int eof_seen = 0;
    for (int i = 0; i < 500 && !eof_seen; i++) {
        tcp_sink_pump(&sink);
        int never = 0;
        harness_pump(&h, &never, 20);
        eof_seen = sink.eof_seen;
    }
    ASSERT_EQ(eof_seen, 1);
    /* Not truncated: the sink saw every byte before EOF. */
    ASSERT_EQ((size_t)sink.echoed_bytes, msg_len);

    harness_stop(&h);
    tcp_sink_close(&sink);
    free(h.probe.raw_recv_buf);
}

/* C1 regression: standalone READ_EMPTY_FIN dispatch.
 *
 * mqvpn_tcp_h3_fin_becomes_shut_wr above sends real body bytes before its
 * fin, so xquic's h3 layer resolves that fin through the ordinary
 * XQC_REQ_NOTIFY_READ_BODY path (recv_body's *fin out-param) — it never
 * proves the OTHER wire shape exists. And critically, probe_send_fin_retry's
 * xqc_h3_request_send_body(req, NULL, 0, 1) does NOT produce that other
 * shape either: traced through xqc_h3_stream_send_data_frame
 * (third_party/xquic/src/http3/xqc_h3_stream.c), a fin-only send_body call
 * still emits a 2-byte H3 DATA frame header (type + zero-length varint)
 * carrying the transport fin — never a truly empty (0-byte) QUIC STREAM
 * frame — so xqc_h3_stream_process_request always sees data_len==2, not 0,
 * and resolves through the ordinary DATA-frame/READ_BODY path regardless of
 * how it's timed relative to prior body bytes (confirmed empirically by
 * instrumenting xqc_h3_stream_process_request while writing this test).
 *
 * The one API that produces a genuinely bare QUIC-level fin with NO H3
 * framing at all is xqc_h3_request_finish (-> xqc_h3_stream_send_finish),
 * which appends a true zero-length var_buf with only the fin bit set — no
 * DATA frame header, nothing else queued. That is what
 * xqc_h3_request_on_recv_empty_fin's data_len==0 branch is actually for, and
 * it's used here (via probe_send_finish_retry) instead of
 * probe_send_fin_retry specifically to hit XQC_REQ_NOTIFY_READ_EMPTY_FIN
 * standalone (verified: read_flag is back to XQC_REQ_NOTIFY_READ_NULL by
 * this point since the header notify already drained via recv_headers and
 * no body was ever sent, satisfying on_recv_empty_fin's "notify only if
 * nothing is still pending application consumption" guard). This is the
 * exact standalone notify C1 fixes mqvpn_server.c's cb_request_read to
 * dispatch (previously only CONNECT_TCP's READ_BODY case was wired, so this
 * notify hit the dispatcher's blanket `if (flag & XQC_REQ_NOTIFY_READ_BODY)`
 * miss and fell all the way to the trailing `return 0`, and
 * shutdown(fd, SHUT_WR) was never issued — the sink would hang waiting for
 * EOF forever). mqvpn's own production code (both client and server) always
 * uses send_body(NULL,0,1) for its uplink/downlink fin, never
 * xqc_h3_request_finish — so this test exercises the dispatch branch
 * directly at the xquic-notify level rather than reproducing a real client
 * wire trace; the de-coalesced e2e half-close test below covers the
 * production send_body(NULL,0,1) shape. */
static int
probe_send_finish_retry(harness_t *h, probe_conn_t *p, int iter_budget)
{
    for (int i = 0; i < iter_budget; i++) {
        ssize_t sent = xqc_h3_request_finish(p->req);
        if (sent >= 0) return 0;
        if (sent != -XQC_EAGAIN) return -1;
        int never = 0;
        harness_pump(h, &never, 20);
    }
    return -1;
}

TEST(mqvpn_tcp_bodiless_fin_becomes_shut_wr)
{
    tcp_sink_t sink;
    /* echo=1, not 0: tcp_sink_pump only latches eof_seen in echo mode (sink
     * mode's accept-only tick never inspects the fd for EOF — see its
     * docstring). No data is ever sent either direction here regardless. */
    ASSERT_EQ(tcp_sink_open(&sink, /*echo=*/1), 0);

    char path[64];
    snprintf(path, sizeof(path), "/.well-known/mqvpn/tcp/127.0.0.1/%d/", sink.port);

    harness_t h;
    ASSERT_EQ(harness_start(&h, "mqvpn-tcp", 9, /*auto_open=*/0, harness_cfg_allow_127),
              0);
    h.probe.path = path;

    harness_pump(&h, &h.probe.handshake_done, 10000);
    ASSERT_EQ(h.probe.handshake_done, 1);
    ASSERT_EQ(probe_open_request_with_body(&h.probe), 0);

    harness_pump_with_sink(&h, &sink, &h.probe.response_done, 10000);
    ASSERT_EQ(h.probe.response_done, 1);
    ASSERT_STREQ(h.probe.status, "200");

    /* Not a single downlink byte sent before this — the bare finish() below
     * is the ENTIRE downlink content of the stream. */
    ASSERT_EQ(probe_send_finish_retry(&h, &h.probe, 500), 0);

    int eof_seen = 0;
    for (int i = 0; i < 500 && !eof_seen; i++) {
        tcp_sink_pump(&sink);
        int never = 0;
        harness_pump(&h, &never, 20);
        eof_seen = sink.eof_seen;
    }
    ASSERT_EQ(eof_seen, 1);
    ASSERT_EQ((size_t)sink.echoed_bytes, 0); /* nothing was ever sent */

    harness_stop(&h);
    tcp_sink_close(&sink);
    free(h.probe.raw_recv_buf);
}

/* Test 4: downlink backpressure pause/resume + deferred-shutdown ordering.
 * The sink accepts but NEVER reads; the probe pumps a large payload
 * (deliberately larger than the default loopback socket buffers) so
 * send()'s EWOULDBLOCK in svr_tcp_egress_drain_body is hit for real,
 * pausing the flow — which, through ordinary QUIC stream flow control
 * (the server stops draining recv_body while paused), backpressures the
 * probe's own sends too. The probe fins its side WHILE still paused/
 * backed up (before the sink ever drains), exercising the "fin arrives
 * during pause must not shutdown ahead of the still-stashed bytes"
 * ordering. The sink then starts draining and must receive every byte,
 * in order, with nothing lost — which is only possible if the deferred
 * shutdown really waited for the stash to fully flush first. */
TEST(mqvpn_tcp_downlink_backpressure_pause_resume)
{
    tcp_sink_t sink;
    ASSERT_EQ(tcp_sink_open(&sink, /*echo=*/0), 0); /* never reads */

    char path[64];
    snprintf(path, sizeof(path), "/.well-known/mqvpn/tcp/127.0.0.1/%d/", sink.port);

    harness_t h;
    ASSERT_EQ(harness_start(&h, "mqvpn-tcp", 9, /*auto_open=*/0, harness_cfg_allow_127),
              0);
    h.probe.path = path;
    h.probe.raw_capture = 1;

    harness_pump(&h, &h.probe.handshake_done, 10000);
    ASSERT_EQ(h.probe.handshake_done, 1);
    ASSERT_EQ(probe_open_request_with_body(&h.probe), 0);

    /* tcp_sink_pump's accept-only branch (echo=0) still needs to run so the
     * server's egress connect() actually completes. */
    harness_pump_with_sink(&h, &sink, &h.probe.response_done, 10000);
    ASSERT_EQ(h.probe.response_done, 1);
    ASSERT_STREQ(h.probe.status, "200");

    size_t payload_len = 512 * 1024;
    uint8_t *payload = malloc(payload_len);
    ASSERT_EQ(payload != NULL, 1);
    for (size_t i = 0; i < payload_len; i++)
        payload[i] = (uint8_t)(i & 0xFF);

    /* Pumps via harness_pump_with_sink so the sink keeps accept()ing (it's
     * already accepted by now) without ever reading — this is what forces
     * real EWOULDBLOCK on the server's egress send(). iter_budget is
     * generous: each retry slice is 20ms and this may need many while the
     * flow is genuinely paused. */
    int sent_ok = 0;
    {
        size_t off = 0;
        for (int i = 0; i < 5000 && off < payload_len; i++) {
            while (off < payload_len) {
                ssize_t sent = xqc_h3_request_send_body(
                    h.probe.req, (unsigned char *)(payload + off), payload_len - off, 0);
                if (sent == -XQC_EAGAIN) break;
                ASSERT_EQ(sent > 0, 1);
                off += (size_t)sent;
            }
            if (off >= payload_len) break;
            tcp_sink_pump(&sink);
            int never = 0;
            harness_pump(&h, &never, 20);
        }
        sent_ok = (off == payload_len);
    }
    ASSERT_EQ(sent_ok, 1);

    /* Fin while the flow is still (very likely) paused/backed up — the
     * point of this test. */
    ASSERT_EQ(probe_send_fin_retry(&h, &h.probe, 500), 0);

    /* Now start draining the sink and keep pumping until every byte has
     * arrived (or the budget is exhausted, which fails the length assert
     * below rather than hanging). */
    uint8_t *received = malloc(payload_len);
    ASSERT_EQ(received != NULL, 1);
    size_t received_len = 0;
    for (int i = 0; i < 10000 && received_len < payload_len; i++) {
        tcp_sink_pump(&sink); /* no-op past accept in sink mode */
        if (sink.conn_fd >= 0) {
            uint8_t buf[65536];
            ssize_t n;
            while ((n = recv(sink.conn_fd, buf, sizeof(buf), MSG_DONTWAIT)) > 0) {
                if (received_len + (size_t)n <= payload_len) {
                    memcpy(received + received_len, buf, (size_t)n);
                }
                received_len += (size_t)n;
            }
        }
        int never = 0;
        harness_pump(&h, &never, 5);
    }

    ASSERT_EQ(received_len, payload_len);
    ASSERT_EQ(memcmp(received, payload, payload_len), 0);

    /* Deferred SHUT_WR must actually land: the fin above was sent while
     * the flow was paused, so the shutdown was deferred until the stash
     * drained — after the last payload byte, the sink must observe a clean
     * half-close (recv()==0). Without this, a broken deferred-shutdown
     * path (or a lost sticky-fin re-report feeding it) would leak the flow
     * half-open while every byte-count assertion above still passed. */
    int shutdown_seen = 0;
    for (int i = 0; i < 500 && !shutdown_seen; i++) {
        if (sink.conn_fd >= 0) {
            uint8_t buf[4096];
            ssize_t n = recv(sink.conn_fd, buf, sizeof(buf), MSG_DONTWAIT);
            if (n == 0) shutdown_seen = 1;
        }
        if (!shutdown_seen) {
            int never = 0;
            harness_pump(&h, &never, 20);
        }
    }
    ASSERT_EQ(shutdown_seen, 1);

    harness_stop(&h);
    tcp_sink_close(&sink);
    free(payload);
    free(received);
    free(h.probe.raw_recv_buf);
}

/* Closing-notify idempotency. (Uplink -XQC_EAGAIN coverage note: the
 * stash-WRITE half of that path — send_body backpressure parking the flow
 * via svr_tcp_egress_stash_uplink — IS exercised by
 * mqvpn_tcp_parked_flow_idle_eviction below, with real H3 window
 * exhaustion, no syscall interposition. What remains uncovered black-box
 * is the stash-FLUSH/resume half: on_h3_writable draining the stash and
 * re-arming want_read once the client reopens its window — the same
 * forcing technique never reopens the window by construction, and the
 * idle sweep collects the flow instead. The e2e/netem chunk owns that
 * resume path.) The probe RESETs its own request mid-relay; the server
 * must tear the flow down exactly once (verified indirectly — a
 * double-destroy would double-free/double-close and show up under the
 * ASan run) and must actually close its egress socket as part of that
 * teardown, which the sink observes as EOF. */
TEST(mqvpn_tcp_closing_notify_idempotent)
{
    tcp_sink_t sink;
    ASSERT_EQ(tcp_sink_open(&sink, /*echo=*/1), 0);

    char path[64];
    snprintf(path, sizeof(path), "/.well-known/mqvpn/tcp/127.0.0.1/%d/", sink.port);

    harness_t h;
    ASSERT_EQ(harness_start(&h, "mqvpn-tcp", 9, /*auto_open=*/0, harness_cfg_allow_127),
              0);
    h.probe.path = path;
    h.probe.raw_capture = 1;

    harness_pump(&h, &h.probe.handshake_done, 10000);
    ASSERT_EQ(h.probe.handshake_done, 1);
    ASSERT_EQ(probe_open_request_with_body(&h.probe), 0);

    harness_pump_with_sink(&h, &sink, &h.probe.response_done, 10000);
    ASSERT_EQ(h.probe.response_done, 1);
    ASSERT_STREQ(h.probe.status, "200");

    ASSERT_EQ(xqc_h3_request_close(h.probe.req), 0);

    int gone = 0;
    for (int i = 0; i < 500 && !gone; i++) {
        tcp_sink_pump(&sink);
        int never = 0;
        harness_pump(&h, &never, 20);
        gone = sink.eof_seen;
    }
    ASSERT_EQ(gone, 1);

    harness_stop(&h);
    tcp_sink_close(&sink);
    free(h.probe.raw_recv_buf);
}

/* ── Limits (Step 2): ACTIVE-flow idle timeout eviction ──
 *
 * TcpIdleTimeoutSec=1. A roundtrip proves the flow is genuinely ACTIVE and
 * refreshes last_activity_us (the idle clock must start counting from the
 * LAST byte moved, not from connect time); then the flow goes quiet. Once
 * idle for longer than the configured timeout, svr_tcp_egress_tick's sweep
 * must close the H3 stream (never a 5xx — a 200 already went out) AND the
 * destroy funnel must actually close() the egress socket, which the sink
 * observes as a clean EOF. */
TEST(mqvpn_tcp_active_idle_timeout_evicts)
{
    tcp_sink_t sink;
    ASSERT_EQ(tcp_sink_open(&sink, /*echo=*/1), 0);

    char path[64];
    snprintf(path, sizeof(path), "/.well-known/mqvpn/tcp/127.0.0.1/%d/", sink.port);

    harness_t h;
    ASSERT_EQ(harness_start(&h, "mqvpn-tcp", 9, /*auto_open=*/0,
                            harness_cfg_allow_127_idle_timeout_1),
              0);
    h.probe.path = path;
    h.probe.raw_capture = 1;

    harness_pump(&h, &h.probe.handshake_done, 10000);
    ASSERT_EQ(h.probe.handshake_done, 1);
    ASSERT_EQ(probe_open_request_with_body(&h.probe), 0);

    harness_pump_with_sink(&h, &sink, &h.probe.response_done, 10000);
    ASSERT_EQ(h.probe.response_done, 1);
    ASSERT_STREQ(h.probe.status, "200");

    const char *msg = "still alive";
    size_t msg_len = strlen(msg);
    ASSERT_EQ(probe_send_body_retry(&h, &h.probe, (const uint8_t *)msg, msg_len, 500), 0);
    int got_echo = 0;
    for (int i = 0; i < 500 && !got_echo; i++) {
        int never = 0;
        harness_pump_with_sink(&h, &sink, &never, 20);
        got_echo = h.probe.raw_recv_len >= msg_len;
    }
    ASSERT_EQ(got_echo, 1);

    /* Now go quiet for longer than the 1s idle timeout. Bounded to 3s of
     * wall time (150 * 20ms slices) — a working sweep fires well within
     * that; a broken one would otherwise hang the test suite. */
    int evicted = 0;
    for (int i = 0; i < 150 && !evicted; i++) {
        tcp_sink_pump(&sink);
        int never = 0;
        harness_pump(&h, &never, 20);
        evicted = h.probe.request_closed && sink.eof_seen;
    }
    ASSERT_EQ(h.probe.request_closed, 1);
    ASSERT_EQ(sink.eof_seen, 1);

    /* Regression, same shape as the connect-timeout/global-cap tests: the
     * evicted flow's counters must not be stuck elevated — a fresh
     * connect-tcp request on the same H3 connection still succeeds. */
    tcp_sink_t sink2;
    ASSERT_EQ(tcp_sink_open(&sink2, /*echo=*/1), 0);
    char path2[64];
    snprintf(path2, sizeof(path2), "/.well-known/mqvpn/tcp/127.0.0.1/%d/", sink2.port);
    h.probe.path = path2;
    h.probe.response_done = 0;
    h.probe.status[0] = '\0';
    ASSERT_EQ(probe_open_request_with_body(&h.probe), 0);
    harness_pump_with_sink(&h, &sink2, &h.probe.response_done, 10000);
    ASSERT_EQ(h.probe.response_done, 1);
    ASSERT_STREQ(h.probe.status, "200");

    harness_stop(&h);
    tcp_sink_close(&sink);
    tcp_sink_close(&sink2);
    free(h.probe.raw_recv_buf);
}

/* Two co-resident ACTIVE flows on the SAME H3 connection, idle clocks
 * ALIGNED to within one pump slice (one byte echoed on each, back-to-back
 * — see below), so both deadlines land inside the same 1s-timeout window
 * and one sweep pass evicts BOTH in the same walk. Walk order is
 * deterministic: the D3 list head-inserts, so the walk visits flow 2 (head)
 * then flow 1 — evicting the head with a LIVE successor is exactly the
 * mid-walk-unlink case the save-next discipline in svr_tcp_egress_tick
 * exists for (on_idle_evict's xqc_h3_request_close can synchronously
 * re-enter the close-notify funnel and unlink+free the flow mid-walk).
 * Honest caveat on "same pass": alignment is to microseconds against a >=1s
 * sweep period, so a tick landing between the two deadlines is vanishingly
 * unlikely but not impossible — what this test pins HARD is head-eviction
 * with a live successor plus both-evicted cleanliness; same-pass
 * co-eviction is the overwhelmingly common execution. Asserts both streams
 * close, both egress sockets really close (sink EOFs), and the CONNECTION
 * itself survives — a subsequent connect-tcp request on it is still
 * serviced with a 200, which also re-pins that both flows' counters were
 * released. The ASan run of this binary covers the no-UAF/no-double-free
 * half of the claim. */
TEST(mqvpn_tcp_two_flow_same_conn_idle_eviction)
{
    tcp_sink_t sink1, sink2;
    ASSERT_EQ(tcp_sink_open(&sink1, /*echo=*/1), 0);
    ASSERT_EQ(tcp_sink_open(&sink2, /*echo=*/1), 0);

    char path1[64], path2[64];
    snprintf(path1, sizeof(path1), "/.well-known/mqvpn/tcp/127.0.0.1/%d/", sink1.port);
    snprintf(path2, sizeof(path2), "/.well-known/mqvpn/tcp/127.0.0.1/%d/", sink2.port);

    harness_t h;
    ASSERT_EQ(harness_start(&h, "mqvpn-tcp", 9, /*auto_open=*/0,
                            harness_cfg_allow_127_idle_timeout_1),
              0);
    h.probe.path = path1;

    harness_pump(&h, &h.probe.handshake_done, 10000);
    ASSERT_EQ(h.probe.handshake_done, 1);

    /* Flow 1 (h.probe) and flow 2 (a second request-scoped probe_conn_t on
     * the SAME engine/connection — the global-cap test's idiom). Both reach
     * ACTIVE (200 received ⇒ svr_tcp_egress_on_connected ran). */
    h.probe.raw_capture = 1; /* echoed bytes below bypass the capsule decoder */
    ASSERT_EQ(probe_open_request_with_body(&h.probe), 0);
    harness_pump_with_sink(&h, &sink1, &h.probe.response_done, 10000);
    ASSERT_EQ(h.probe.response_done, 1);
    ASSERT_STREQ(h.probe.status, "200");

    probe_conn_t second;
    memset(&second, 0, sizeof(second));
    second.engine = h.probe.engine;
    memcpy(&second.cid, &h.probe.cid, sizeof(second.cid));
    second.protocol = h.probe.protocol;
    second.protocol_len = h.probe.protocol_len;
    snprintf(second.authority, sizeof(second.authority), "%s", h.probe.authority);
    second.path = path2;
    second.raw_capture = 1;
    ASSERT_EQ(probe_open_request_with_body(&second), 0);
    harness_pump_with_sink(&h, &sink2, &second.response_done, 10000);
    ASSERT_EQ(second.response_done, 1);
    ASSERT_STREQ(second.status, "200");

    /* Align the two idle clocks: one byte on EACH flow, submitted
     * back-to-back with no pump in between — the server relays both in the
     * same engine pass, so both last_activity_us stamps land microseconds
     * apart (the two 200s above, by contrast, are a full pump roundtrip
     * apart). A fresh post-200 stream window always accepts 1 byte. */
    ASSERT_EQ(xqc_h3_request_send_body(h.probe.req, (unsigned char *)"x", 1, 0), 1);
    ASSERT_EQ(xqc_h3_request_send_body(second.req, (unsigned char *)"y", 1, 0), 1);
    {
        int both_echoed = 0;
        for (int i = 0; i < 500 && !both_echoed; i++) {
            tcp_sink_pump(&sink1);
            tcp_sink_pump(&sink2);
            int never = 0;
            harness_pump(&h, &never, 20);
            both_echoed = sink1.echoed_bytes >= 1 && sink2.echoed_bytes >= 1;
        }
        ASSERT_EQ(both_echoed, 1); /* both flows refreshed, now aligned */
    }

    /* Quiet from here on; both deadlines expire together, so the sweep
     * evicts the head (flow 2) and then its live walk-successor (flow 1)
     * in the same pass. Wait for all four observables; keep pumping both
     * sinks so their EOFs land. */
    int all_gone = 0;
    for (int i = 0; i < 150 && !all_gone; i++) {
        tcp_sink_pump(&sink1);
        tcp_sink_pump(&sink2);
        int never = 0;
        harness_pump(&h, &never, 20);
        all_gone = h.probe.request_closed && second.request_closed && sink1.eof_seen &&
                   sink2.eof_seen;
    }
    ASSERT_EQ(h.probe.request_closed, 1);
    ASSERT_EQ(second.request_closed, 1);
    ASSERT_EQ(sink1.eof_seen, 1);
    ASSERT_EQ(sink2.eof_seen, 1);

    /* Connection survives the double eviction: a fresh request on it is
     * still serviced end-to-end. */
    tcp_sink_t sink3;
    ASSERT_EQ(tcp_sink_open(&sink3, /*echo=*/1), 0);
    char path3[64];
    snprintf(path3, sizeof(path3), "/.well-known/mqvpn/tcp/127.0.0.1/%d/", sink3.port);
    h.probe.path = path3;
    h.probe.response_done = 0;
    h.probe.status[0] = '\0';
    h.probe.request_closed = 0;
    ASSERT_EQ(probe_open_request_with_body(&h.probe), 0);
    harness_pump_with_sink(&h, &sink3, &h.probe.response_done, 10000);
    ASSERT_EQ(h.probe.response_done, 1);
    ASSERT_STREQ(h.probe.status, "200");

    harness_stop(&h);
    tcp_sink_close(&sink1);
    tcp_sink_close(&sink2);
    tcp_sink_close(&sink3);
    free(h.probe.raw_recv_buf);
    free(second.raw_recv_buf);
}

/* ── Limits (Step 2, carry-over from the relay review): parked-flow
 * eviction ──
 *
 * A flow parked by UPLINK backpressure (uplink_withheld=1: the server's
 * send_body() to the client is -XQC_EAGAIN'ing because the client's H3
 * receive window is full AND the client never reads to reopen it) has no
 * recovery path of its own — want_read is dropped for the egress fd, so the
 * server never even looks at that socket again. The ACTIVE idle sweep is
 * its ONLY collector, which is exactly what last_activity_us's "no bytes
 * moved, no refresh" rule (see that field's comment in tcp_egress.c) is for.
 *
 * Forced black-box, no syscall interposition needed: the sink floods the
 * egress connection with more data than the default initial H3 stream
 * receive window (XQC_MIN_RECV_WINDOW = 63000 bytes, third_party/xquic/src/
 * transport/xqc_conn.h) while the probe (via suppress_body_drain) never
 * calls recv_body — so xquic never sends a MAX_STREAM_DATA update and the
 * window never reopens. This is a real, not mocked, EAGAIN. */
TEST(mqvpn_tcp_parked_flow_idle_eviction)
{
    tcp_sink_t sink;
    ASSERT_EQ(tcp_sink_open(&sink, /*echo=*/0), 0); /* we drive sends manually below */

    char path[64];
    snprintf(path, sizeof(path), "/.well-known/mqvpn/tcp/127.0.0.1/%d/", sink.port);

    harness_t h;
    ASSERT_EQ(harness_start(&h, "mqvpn-tcp", 9, /*auto_open=*/0,
                            harness_cfg_allow_127_idle_timeout_1),
              0);
    h.probe.path = path;
    h.probe.suppress_body_drain = 1;

    harness_pump(&h, &h.probe.handshake_done, 10000);
    ASSERT_EQ(h.probe.handshake_done, 1);
    ASSERT_EQ(probe_open_request_with_body(&h.probe), 0);

    harness_pump_with_sink(&h, &sink, &h.probe.response_done, 10000);
    ASSERT_EQ(h.probe.response_done, 1);
    ASSERT_STREQ(h.probe.status, "200");
    ASSERT_EQ(sink.conn_fd >= 0, 1);

    /* Flood up to 256 KiB from the sink's side — comfortably more than the
     * ~63000-byte default window. Alternates send()+pump so the relay's
     * recv()/send_body() loop actually runs while data is available;
     * bails early if the sink's OWN kernel send buffer fills first (plenty
     * has already been offered by then). */
    uint8_t junk[4096];
    memset(junk, 0x5a, sizeof(junk));
    for (int i = 0; i < 64; i++) {
        ssize_t sent =
            send(sink.conn_fd, junk, sizeof(junk), MSG_DONTWAIT | MSG_NOSIGNAL);
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        int never = 0;
        harness_pump(&h, &never, 20);
    }

    /* Quiet now: no more sink sends, no probe reads. Same bounded wait as
     * the ACTIVE idle-timeout test above. Checks both sides, like that
     * test: the sink's real fd close AND the probe's H3 stream close (a
     * server-initiated stream close/reset is a control-frame operation, not
     * subject to the very stream-data flow control that's stuck full here,
     * so it isn't blocked by the probe's own non-draining). */
    int sink_eof = 0;
    for (int i = 0; i < 150 && !(sink_eof && h.probe.request_closed); i++) {
        int never = 0;
        harness_pump(&h, &never, 20);
        if (!sink_eof) {
            uint8_t buf[4096];
            ssize_t n = recv(sink.conn_fd, buf, sizeof(buf), MSG_DONTWAIT);
            if (n == 0) sink_eof = 1;
        }
    }
    ASSERT_EQ(sink_eof, 1);
    ASSERT_EQ(h.probe.request_closed, 1);

    harness_stop(&h);
    tcp_sink_close(&sink);
    free(h.probe.raw_recv_buf);
}

/* ── svr_tcp_egress_errno_to_status — pure function ── */

TEST(errno_to_status_maps_known_codes)
{
    ASSERT_EQ(svr_tcp_egress_errno_to_status(ECONNREFUSED), 502);
    ASSERT_EQ(svr_tcp_egress_errno_to_status(ETIMEDOUT), 504);
    ASSERT_EQ(svr_tcp_egress_errno_to_status(ENETUNREACH), 502);
    ASSERT_EQ(svr_tcp_egress_errno_to_status(EHOSTUNREACH), 502);
    ASSERT_EQ(svr_tcp_egress_errno_to_status(EACCES), 502); /* default bucket */
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
    run_hybrid_disabled_gets_501();
    run_mqvpn_tcp_acl_allow_hole_reaches_real_connect();
    run_mqvpn_tcp_connect_timeout_gets_504();
    run_mqvpn_tcp_global_cap_gets_503();
    run_mqvpn_tcp_invalid_hybrid_field_sanitized_acl_survives();
    run_mqvpn_tcp_echo_roundtrip();
    run_mqvpn_tcp_egress_eof_becomes_h3_fin();
    run_mqvpn_tcp_h3_fin_becomes_shut_wr();
    run_mqvpn_tcp_bodiless_fin_becomes_shut_wr();
    run_mqvpn_tcp_downlink_backpressure_pause_resume();
    run_mqvpn_tcp_closing_notify_idempotent();
    run_mqvpn_tcp_active_idle_timeout_evicts();
    run_mqvpn_tcp_two_flow_same_conn_idle_eviction();
    run_mqvpn_tcp_parked_flow_idle_eviction();
    run_errno_to_status_maps_known_codes();
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
