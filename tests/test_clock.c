// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_clock.c — the clock of mqvpn's xquic engines (src/mqvpn_clock.c)
 *
 * Token expiry. xquic stamps the expiry of its address-validation tokens with
 * the engine clock (xqc_conn_gen_token, xqc_conn_check_token, called here
 * directly on a stand-in connection), and a token outlives the process and
 * the boot:
 *   - upgrade: a token issued by a release that timed xquic with the wall
 *     clock (gettimeofday, xquic's default) and expired since is refused,
 *     and an unexpired one is still accepted;
 *   - reboot: a token issued 8 days ago at 100 days of uptime is refused
 *     after a reboot, although CLOCK_BOOTTIME started again from zero, and
 *     one issued a day ago is still accepted.
 * The clock does not follow a step of the wall clock.
 *
 * Process clock. xquic's clock is process-wide: an injected client clock
 * goes away with its client, and an engine on another clock is refused
 * while others run.
 */

#include "libmqvpn.h"
#include "mqvpn_internal.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>

/* xquic's private connection, engine and clock declarations, for the token
 * functions and the process-wide clock pointers (the static xquic library
 * exports them; the include directories are SYSTEM, see CMakeLists.txt). */
#include "src/common/xqc_time.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"

#define SEC 1000000ULL
#define DAY (86400 * SEC)

static int g_failed;

#define CHECK(cond, what)                                               \
    do {                                                                \
        if (cond) {                                                     \
            printf("  %-66s PASS\n", what);                             \
        } else {                                                        \
            printf("  %-66s FAIL (%s:%d)\n", what, __FILE__, __LINE__); \
            g_failed = 1;                                               \
        }                                                               \
    } while (0)

static uint64_t
wall_now_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * SEC + (uint64_t)tv.tv_usec;
}

/* ─── simulated CLOCK_BOOTTIME and wall clock (mqvpn_clock_test_sources) ─── */

static uint64_t g_boot_us, g_wall_us;

static uint64_t
src_boot(void)
{
    return g_boot_us;
}

static uint64_t
src_wall(void)
{
    return g_wall_us;
}

/* A process started at `uptime_us` of uptime when the wall clock read
 * `wall_us`: the clock takes its offset again, as at a new start. */
static void
start_process_at(uint64_t uptime_us, uint64_t wall_us)
{
    g_boot_us = uptime_us;
    g_wall_us = wall_us;
    mqvpn_clock_test_sources(src_boot, src_wall);
}

/* ─── stand-in connection for xquic's token functions ─── */

static xqc_engine_t *g_eng;      /* raw server engine: holds the token keys */
static xqc_connection_t *g_conn; /* engine, log and peer address only */

static void
eng_set_event_timer(xqc_usec_t wake_after, void *user_data)
{
    (void)wake_after;
    (void)user_data;
}

static void
eng_log_write(xqc_log_level_t lvl, const void *buf, size_t size, void *user_data)
{
    (void)lvl;
    (void)buf;
    (void)size;
    (void)user_data;
}

static ssize_t
eng_write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer,
                 socklen_t peerlen, void *user_data)
{
    (void)buf;
    (void)peer;
    (void)peerlen;
    (void)user_data;
    return (ssize_t)size;
}

static int
token_setup(void)
{
    xqc_engine_ssl_config_t ssl;
    memset(&ssl, 0, sizeof(ssl));
    ssl.private_key_file = TEST_KEY_FILE;
    ssl.cert_file = TEST_CERT_FILE;
    ssl.ciphers = XQC_TLS_CIPHERS;
    ssl.groups = XQC_TLS_GROUPS;

    /* no timestamp callbacks: the engine keeps the process clock that the
     * mqvpn server installed */
    xqc_engine_callback_t cbs = {
        .set_event_timer = eng_set_event_timer,
        .log_callbacks =
            {
                .xqc_log_write_err = eng_log_write,
                .xqc_log_write_stat = eng_log_write,
            },
    };
    xqc_transport_callbacks_t tcbs = {
        .write_socket = eng_write_socket,
    };
    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_SERVER) < 0) return -1;
    config.cfg_log_level = XQC_LOG_FATAL;
    g_eng = xqc_engine_create(XQC_ENGINE_SERVER, &config, &ssl, &cbs, &tcbs, NULL);
    if (!g_eng) return -1;

    g_conn = calloc(1, sizeof(*g_conn));
    if (!g_conn) return -1;
    g_conn->engine = g_eng;
    g_conn->log = g_eng->log;
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons(40000);
    inet_pton(AF_INET, "192.0.2.7", &peer.sin_addr);
    memcpy(g_conn->peer_addr, &peer, sizeof(peer));
    g_conn->peer_addrlen = sizeof(peer);
    return 0;
}

static int
gen_token(unsigned char *tok, unsigned *len)
{
    *len = XQC_MAX_TOKEN_LEN;
    return xqc_conn_gen_token(g_conn, tok, len) == XQC_OK ? 0 : -1;
}

static int
token_accepted(const unsigned char *tok, unsigned len)
{
    unsigned char copy[XQC_MAX_TOKEN_LEN];
    memcpy(copy, tok, len); /* the check decodes in place */
    return xqc_conn_check_token(g_conn, copy, len) == XQC_OK;
}

/* A token as a release that timed xquic with its default clock
 * (gettimeofday, for both of xquic's clocks) issued it at wall time `us`. */
static uint64_t g_old_release_us;

static xqc_usec_t
old_release_clock(void)
{
    return g_old_release_us;
}

static int
gen_token_old_release(uint64_t us, unsigned char *tok, unsigned *len)
{
    xqc_timestamp_pt mono = xqc_monotonic_timestamp, real = xqc_realtime_timestamp;
    g_old_release_us = us;
    xqc_monotonic_timestamp = old_release_clock;
    xqc_realtime_timestamp = old_release_clock;
    int rc = gen_token(tok, len);
    xqc_monotonic_timestamp = mono;
    xqc_realtime_timestamp = real;
    return rc;
}

/* ─── mqvpn engines ─── */

static void
dummy_tun_output(const uint8_t *pkt, size_t len, void *user_ctx)
{
    (void)pkt;
    (void)len;
    (void)user_ctx;
}

static void
dummy_tunnel_config_ready(const mqvpn_tunnel_info_t *info, void *user_ctx)
{
    (void)info;
    (void)user_ctx;
}

static mqvpn_server_t *
new_server(void)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    mqvpn_config_set_listen(cfg, "127.0.0.1", 4433);
    mqvpn_config_set_subnet(cfg, "10.0.0.0/24");
    mqvpn_config_set_tls_cert(cfg, TEST_CERT_FILE, TEST_KEY_FILE);
    mqvpn_config_set_log_level(cfg, MQVPN_LOG_ERROR);
    mqvpn_server_callbacks_t cbs = MQVPN_SERVER_CALLBACKS_INIT;
    cbs.tun_output = dummy_tun_output;
    cbs.tunnel_config_ready = dummy_tunnel_config_ready;
    mqvpn_server_t *s = mqvpn_server_new(cfg, &cbs, NULL);
    mqvpn_config_free(cfg);
    return s;
}

static uint64_t
fake_client_clock(void *ctx)
{
    (void)ctx;
    return 42 * SEC;
}

static mqvpn_client_t *
new_client(mqvpn_clock_fn clock)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    mqvpn_config_set_server(cfg, "127.0.0.1", 4433);
    mqvpn_config_set_log_level(cfg, MQVPN_LOG_ERROR);
    if (clock) mqvpn_config_set_clock(cfg, clock, NULL);
    mqvpn_client_callbacks_t cbs = MQVPN_CLIENT_CALLBACKS_INIT;
    cbs.tun_output = dummy_tun_output;
    cbs.tunnel_config_ready = dummy_tunnel_config_ready;
    mqvpn_client_t *c = mqvpn_client_new(cfg, &cbs, NULL);
    mqvpn_config_free(cfg);
    return c;
}

/* xquic's clock reads the library clock, not an injected one */
static int
xquic_on_library_clock(void)
{
    uint64_t a = mqvpn_clock_us();
    uint64_t x = xqc_monotonic_timestamp();
    uint64_t b = mqvpn_clock_us();
    return x >= a && x <= b;
}

/* ─── cases ─── */

static void
test_wall_step(void)
{
    printf("wall clock step:\n");
    uint64_t w = wall_now_us();
    start_process_at(1000 * SEC, w);
    uint64_t t0 = mqvpn_clock_us();
    CHECK(t0 == w, "the clock reads Unix time at its first reading");
    g_boot_us += SEC;
    g_wall_us -= 60 * SEC; /* NTP steps the wall clock back */
    uint64_t t1 = mqvpn_clock_us();
    g_boot_us += SEC;
    g_wall_us += 180 * SEC; /* and forward */
    uint64_t t2 = mqvpn_clock_us();
    CHECK(t1 == t0 + SEC && t2 == t1 + SEC,
          "steps of the wall clock do not move the clock");
    mqvpn_clock_test_sources(NULL, NULL);
}

static void
test_token_upgrade(void)
{
    printf("token from a release timed with the wall clock:\n");
    unsigned char tok[XQC_MAX_TOKEN_LEN];
    unsigned len;
    uint64_t w = wall_now_us();

    CHECK(gen_token_old_release(w - 8 * DAY, tok, &len) == 0 && !token_accepted(tok, len),
          "issued 8 days ago (expired a day ago): refused");
    CHECK(gen_token_old_release(w - 1 * DAY, tok, &len) == 0 && token_accepted(tok, len),
          "issued a day ago: accepted");
}

static void
test_token_reboot(void)
{
    printf("token from before a reboot:\n");
    unsigned char tok[XQC_MAX_TOKEN_LEN];
    unsigned len;
    uint64_t w = wall_now_us();

    start_process_at(100 * DAY, w - 8 * DAY);
    int ok = gen_token(tok, &len) == 0;
    start_process_at(3600 * SEC, w); /* the reboot */
    CHECK(ok && !token_accepted(tok, len),
          "issued 8 days ago at 100 days of uptime: refused after the reboot");

    start_process_at(100 * DAY, w - 1 * DAY);
    ok = gen_token(tok, &len) == 0;
    start_process_at(3600 * SEC, w);
    CHECK(ok && token_accepted(tok, len),
          "issued a day ago at 100 days of uptime: accepted after the reboot");

    mqvpn_clock_test_sources(NULL, NULL);
}

static void
test_process_clock(mqvpn_server_t **svr)
{
    printf("process clock:\n");
    /* the token cases ran next to a server; start from no engine */
    mqvpn_server_destroy(*svr);
    *svr = NULL;

    mqvpn_client_t *a = new_client(fake_client_clock);
    CHECK(a != NULL && xqc_monotonic_timestamp() == 42 * SEC,
          "a client's injected clock is xquic's clock while it runs");
    mqvpn_server_t *s = new_server();
    CHECK(s == NULL, "a server is refused while a client runs on another clock");
    if (s) mqvpn_server_destroy(s);
    mqvpn_client_t *b = new_client(NULL);
    CHECK(b == NULL, "a client on the default clock is refused next to it");
    if (b) mqvpn_client_destroy(b);
    mqvpn_client_t *a2 = new_client(fake_client_clock);
    CHECK(a2 != NULL, "a second client on the same injected clock is accepted");
    if (a2) mqvpn_client_destroy(a2);
    mqvpn_client_destroy(a);

    b = new_client(NULL);
    CHECK(b != NULL && xquic_on_library_clock(),
          "after that client, a default client runs xquic on the library clock");
    s = new_server();
    CHECK(s != NULL && xquic_on_library_clock(),
          "a server runs next to a client on the default clock");
    a = new_client(fake_client_clock);
    CHECK(a == NULL && xquic_on_library_clock(),
          "a client with an injected clock is refused next to them");
    if (a) mqvpn_client_destroy(a);
    mqvpn_client_destroy(b);
    *svr = s;
}

int
main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("test_clock: the clock of mqvpn's xquic engines\n");

    test_wall_step();

    /* the server installs the process clock that the token functions use */
    mqvpn_server_t *svr = new_server();
    if (!svr || token_setup() != 0) {
        printf("FAIL: setup\n");
        return 1;
    }
    test_token_upgrade();
    test_token_reboot();
    test_process_clock(&svr);

    free(g_conn);
    xqc_engine_destroy(g_eng);
    if (svr) mqvpn_server_destroy(svr);
    printf(g_failed ? "test_clock: FAIL\n" : "test_clock: PASS\n");
    return g_failed;
}
