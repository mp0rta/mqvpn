// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_server_preaccept_dos.c — Regression for an unauthenticated,
 * pre-handshake remote DoS in the server accept path (type confusion).
 *
 * Root cause
 * ----------
 * A server QUIC connection starts life with conn->user_data == the engine
 * handle (mqvpn_server_t *), set at xqc_engine_create(). xquic sets the
 * SERVER_ACCEPT flag while parsing the *header* of the first Initial packet
 * (xqc_packet.c: xqc_conn_server_accept), i.e. BEFORE the ClientHello CRYPTO
 * is decrypted and TLS runs. From that point on, every server->client send
 * goes through transport_cbs.write_socket (== cb_write_socket), which casts
 * conn->user_data to svr_conn_t* and dereferences ->server.
 *
 * conn->user_data is only rebound to a real per-connection svr_conn_t* inside
 * cb_h3_conn_create — and that fires ONLY when a registered H3 ALPN is
 * selected. If ALPN selection never succeeds (client offers an ALPN the
 * server does not support, or no SNI makes the cert callback fail first), the
 * rebind never happens, yet TLS failure makes the server flush a
 * CONNECTION_CLOSE through cb_write_socket. cb_write_socket then treats the
 * mqvpn_server_t* as an svr_conn_t*: ->server reads the first 8 bytes of the
 * embedded mqvpn_config_t (config.server_host[0..7]) as a pointer, and
 * svr_do_send() dereferences it (->udp_fd). On a server config server_host is
 * empty (mqvpn_config_set_listen fills listen_addr, not server_host), so those
 * 8 bytes are zero and this manifests as a NULL-pointer deref; a config with a
 * non-empty server_host would deref a wild pointer instead. Either way it is a
 * remote, unauthenticated crash — a bare `:443` QUIC scanner probe triggers it.
 *
 * Reproduction
 * ------------
 * Drive a raw xquic client that offers a bogus ALPN ("mqvpn-dos-probe") at an
 * mqvpn server over loopback UDP. The server accepts the Initial but never
 * reaches cb_h3_conn_create (no H3 ALPN match), then emits a
 * no_application_protocol CONNECTION_CLOSE through the type-confused callback.
 *
 *   - Pre-fix:  the server process SIGSEGVs (ASan: SEGV on unknown address)
 *               inside svr_do_send() before this test can assert anything.
 *   - Post-fix: the server binds a real svr_conn_t at accept time, so
 *               cb_write_socket sends the CONNECTION_CLOSE cleanly and the
 *               process survives. We observe that close datagram arriving at
 *               the client socket and assert the server stayed up.
 *
 * No root, no TUN, no elevated privileges: two loopback UDP sockets only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>

#include "libmqvpn.h"

#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>

/* ─── attacker (raw xquic client) plumbing ─── */

/* The attacker's write_socket needs the client fd + server address. A
 * one-shot test keeps them at file scope rather than threading a context. */
static int g_cli_fd = -1;
static struct sockaddr_storage g_svr_addr;
static socklen_t g_svr_addrlen;

static xqc_usec_t
now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (xqc_usec_t)ts.tv_sec * 1000000 + (xqc_usec_t)ts.tv_nsec / 1000;
}

static ssize_t
atk_write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer,
                 socklen_t peerlen, void *conn_user_data)
{
    (void)conn_user_data;
    ssize_t n = sendto(g_cli_fd, buf, size, 0, peer, peerlen);
    return n < 0 ? XQC_SOCKET_ERROR : n;
}

static ssize_t
atk_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
                    const struct sockaddr *peer, socklen_t peerlen, void *conn_user_data)
{
    (void)path_id;
    return atk_write_socket(buf, size, peer, peerlen, conn_user_data);
}

static void
atk_set_event_timer(xqc_usec_t wake_after, void *engine_user_data)
{
    (void)wake_after;
    (void)engine_user_data; /* test pumps the engine manually */
}

static void
atk_log_write(xqc_log_level_t lvl, const void *buf, size_t size, void *engine_user_data)
{
    (void)lvl;
    (void)buf;
    (void)size;
    (void)engine_user_data;
}

static int
atk_cert_verify(const unsigned char *certs[], const size_t cert_len[], size_t certs_len,
                void *conn_user_data)
{
    (void)certs;
    (void)cert_len;
    (void)certs_len;
    (void)conn_user_data;
    return 0; /* accept anything — never reached; server fails ALPN first */
}

/* ─── server plumbing ─── */

static void
svr_tun_output(const uint8_t *pkt, size_t len, void *user_ctx)
{
    (void)pkt;
    (void)len;
    (void)user_ctx;
}

static void
svr_tunnel_config_ready(const mqvpn_tunnel_info_t *info, void *user_ctx)
{
    (void)info;
    (void)user_ctx;
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

int
main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    printf("test_server_preaccept_dos: unauthenticated pre-handshake DoS regression\n");

    /* 1. Loopback UDP sockets for server and attacker. */
    struct sockaddr_in svr_addr, cli_addr;
    int svr_fd = make_udp_loopback(&svr_addr);
    int cli_fd = make_udp_loopback(&cli_addr);
    if (svr_fd < 0 || cli_fd < 0) {
        printf("FAIL: socket setup\n");
        return 1;
    }
    g_cli_fd = cli_fd;
    memcpy(&g_svr_addr, &svr_addr, sizeof(svr_addr));
    g_svr_addrlen = sizeof(svr_addr);

    /* 2. mqvpn server bound to svr_fd. */
    mqvpn_config_t *cfg = mqvpn_config_new();
    mqvpn_config_set_listen(cfg, "127.0.0.1", ntohs(svr_addr.sin_port));
    mqvpn_config_set_subnet(cfg, "10.0.0.0/24");
    mqvpn_config_set_tls_cert(cfg, TEST_CERT_FILE, TEST_KEY_FILE);
    mqvpn_config_set_log_level(cfg, MQVPN_LOG_ERROR);

    mqvpn_server_callbacks_t cbs = MQVPN_SERVER_CALLBACKS_INIT;
    cbs.tun_output = svr_tun_output;
    cbs.tunnel_config_ready = svr_tunnel_config_ready;

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

    /* 3. Raw xquic client engine — the hostile probe. */
    xqc_engine_ssl_config_t engine_ssl;
    memset(&engine_ssl, 0, sizeof(engine_ssl));
    engine_ssl.ciphers = XQC_TLS_CIPHERS;
    engine_ssl.groups = XQC_TLS_GROUPS;

    xqc_engine_callback_t engine_cbs = {
        .set_event_timer = atk_set_event_timer,
        .log_callbacks =
            {
                .xqc_log_write_err = atk_log_write,
                .xqc_log_write_stat = atk_log_write,
            },
    };
    xqc_transport_callbacks_t tcbs = {
        .write_socket = atk_write_socket,
        .write_socket_ex = atk_write_socket_ex,
        .cert_verify_cb = atk_cert_verify,
    };

    xqc_config_t xconfig;
    if (xqc_engine_get_default_config(&xconfig, XQC_ENGINE_CLIENT) < 0) {
        printf("FAIL: xqc default config\n");
        return 1;
    }
    xconfig.cfg_log_level = XQC_LOG_FATAL;

    xqc_engine_t *atk = xqc_engine_create(XQC_ENGINE_CLIENT, &xconfig, &engine_ssl,
                                          &engine_cbs, &tcbs, NULL);
    if (!atk) {
        printf("FAIL: xqc_engine_create(client)\n");
        return 1;
    }

    /* The client must register the ALPN it offers so xquic can attach an
     * application-layer context to the connection. Zeroed callbacks are fine
     * — the handshake never completes. This is client-side only; the SERVER
     * still knows only "h3", so ALPN selection there fails. */
    static const char *kProbeAlpn = "mqvpn-dos-probe";
    xqc_app_proto_callbacks_t ap_cbs;
    memset(&ap_cbs, 0, sizeof(ap_cbs));
    if (xqc_engine_register_alpn(atk, kProbeAlpn, strlen(kProbeAlpn), &ap_cbs, NULL) !=
        XQC_OK) {
        printf("FAIL: register probe alpn\n");
        return 1;
    }

    /* Offer an ALPN the server does not support: the server accepts the
     * Initial but never rebinds conn->user_data (that only happens on a
     * successful H3 ALPN in cb_h3_conn_create). */
    xqc_conn_settings_t cs;
    memset(&cs, 0, sizeof(cs)); /* xquic fills internal defaults */

    xqc_conn_ssl_config_t ssl_cfg;
    memset(&ssl_cfg, 0, sizeof(ssl_cfg));
    ssl_cfg.cert_verify_flag = XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED;

    const xqc_cid_t *cid =
        xqc_connect(atk, &cs, NULL, 0, "mqvpn.invalid", 0, &ssl_cfg,
                    (struct sockaddr *)&svr_addr, sizeof(svr_addr), kProbeAlpn, NULL);
    if (!cid) {
        printf("FAIL: xqc_connect\n");
        return 1;
    }

    /* 4. Pump. The server accepts the Initial, fails ALPN selection, and
     * flushes a CONNECTION_CLOSE through cb_write_socket. Pre-fix that is a
     * type-confused deref → SIGSEGV here. Post-fix the close is sent cleanly
     * and arrives on cli_fd. */
    int svr_close_datagrams = 0;
    int svr_recv_pkts = 0;
    uint8_t buf[65536];

    for (int i = 0; i < 400; i++) {
        /* attacker flushes queued packets (Initial + retransmits) */
        xqc_engine_main_logic(atk);

        /* client -> server: feed the probe into the server engine */
        for (;;) {
            struct sockaddr_storage from;
            socklen_t flen = sizeof(from);
            ssize_t n = recvfrom(svr_fd, buf, sizeof(buf), MSG_DONTWAIT,
                                 (struct sockaddr *)&from, &flen);
            if (n <= 0) break;
            svr_recv_pkts++;
            mqvpn_server_on_socket_recv(svr, buf, (size_t)n, (struct sockaddr *)&from,
                                        flen);
        }

        /* server processes and, crucially, TRIES TO SEND its close here */
        mqvpn_server_tick(svr);

        /* server -> client: count the close datagram, then feed the attacker */
        for (;;) {
            struct sockaddr_storage from;
            socklen_t flen = sizeof(from);
            ssize_t n = recvfrom(cli_fd, buf, sizeof(buf), MSG_DONTWAIT,
                                 (struct sockaddr *)&from, &flen);
            if (n <= 0) break;
            svr_close_datagrams++;
            xqc_engine_packet_process(atk, buf, (size_t)n, (struct sockaddr *)&cli_addr,
                                      sizeof(cli_addr), (struct sockaddr *)&from, flen,
                                      now_us(), NULL);
        }

        if (svr_close_datagrams > 0) break; /* server survived the send path */

        struct pollfd pfds[2] = {
            {.fd = svr_fd, .events = POLLIN},
            {.fd = cli_fd, .events = POLLIN},
        };
        poll(pfds, 2, 5);
    }
    fprintf(stderr, "[loop done] svr_recv=%d svr->cli=%d\n", svr_recv_pkts,
            svr_close_datagrams);

    /* 5. Assert: reaching here at all means the server did NOT crash on the
     * hostile pre-accept send. The observed close datagram proves the
     * (formerly type-confused) write path ran with a valid connection. */
    int rc = 0;
    if (svr_close_datagrams > 0) {
        printf("  server survived hostile no-ALPN probe (close datagrams=%d)   PASS\n",
               svr_close_datagrams);
    } else {
        printf("  server did not emit the expected CONNECTION_CLOSE            FAIL\n");
        rc = 1;
    }

    /* Server must still be usable (not corrupted) after the probe. */
    mqvpn_stats_t stats;
    if (mqvpn_server_get_stats(svr, &stats) != MQVPN_OK) {
        printf("  server_get_stats after probe                                FAIL\n");
        rc = 1;
    }

    xqc_engine_destroy(atk);
    mqvpn_server_destroy(svr);
    close(cli_fd);
    close(svr_fd);

    printf(rc == 0 ? "test_server_preaccept_dos: PASS\n"
                   : "test_server_preaccept_dos: FAIL\n");
    return rc;
}
