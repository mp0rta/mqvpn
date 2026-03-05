/*
 * test_server.c — libmqvpn server API lifecycle tests (M1-5)
 *
 * Tests per impl_plan:
 *   test_server_lifecycle:
 *     - server_new(config, callbacks) → handle
 *     - server_start() → MQVPN_OK
 *     - server_tick() → MQVPN_OK
 *     - server_get_interest() → valid values
 *     - server_destroy() → valgrind leak-free
 *
 *   test_server_session:
 *     - on_socket_recv() でクライアント接続
 *     - tunnel_config_ready callback 発火
 *     - set_tun_active → tun_output でパケット出力
 *     - client 切断 → セッション解放
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>

#include "libmqvpn.h"

/* ── Test infrastructure ── */

static int g_tests_run    = 0;
static int g_tests_passed = 0;

#define TEST(name) \
    static void test_##name(void); \
    static void run_##name(void) { \
        g_tests_run++; \
        printf("  %-50s ", #name); \
        test_##name(); \
        g_tests_passed++; \
        printf("PASS\n"); \
    } \
    static void test_##name(void)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        printf("FAIL\n    %s:%d: %s == %lld, expected %lld\n", \
               __FILE__, __LINE__, #a, (long long)(a), (long long)(b)); \
        exit(1); \
    } \
} while (0)

#define ASSERT_NE(a, b) do { \
    if ((a) == (b)) { \
        printf("FAIL\n    %s:%d: %s == %s (unexpected)\n", \
               __FILE__, __LINE__, #a, #b); \
        exit(1); \
    } \
} while (0)

#define ASSERT_NULL(a) do { \
    if ((a) != NULL) { \
        printf("FAIL\n    %s:%d: %s is not NULL\n", \
               __FILE__, __LINE__, #a); \
        exit(1); \
    } \
} while (0)

#define ASSERT_NOT_NULL(a) do { \
    if ((a) == NULL) { \
        printf("FAIL\n    %s:%d: %s is NULL\n", \
               __FILE__, __LINE__, #a); \
        exit(1); \
    } \
} while (0)

/* ── Mock callback state ── */

static int g_tun_output_called = 0;
static int g_tunnel_config_ready_called = 0;
static mqvpn_tunnel_info_t g_last_tunnel_info;
static int g_log_called = 0;

static void mock_tun_output(const uint8_t *pkt, size_t len, void *user_ctx)
{
    (void)pkt; (void)len; (void)user_ctx;
    g_tun_output_called++;
}

static void mock_tunnel_config_ready(const mqvpn_tunnel_info_t *info,
                                       void *user_ctx)
{
    (void)user_ctx;
    g_tunnel_config_ready_called++;
    if (info)
        memcpy(&g_last_tunnel_info, info, sizeof(g_last_tunnel_info));
}

static void mock_log(mqvpn_log_level_t level, const char *msg, void *user_ctx)
{
    (void)level; (void)msg; (void)user_ctx;
    g_log_called++;
}

static void reset_mocks(void)
{
    g_tun_output_called = 0;
    g_tunnel_config_ready_called = 0;
    memset(&g_last_tunnel_info, 0, sizeof(g_last_tunnel_info));
    g_log_called = 0;
}

/* ── Helper: create a valid server config ── */

static mqvpn_config_t *make_server_config(void)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    if (!cfg) return NULL;
    mqvpn_config_set_listen(cfg, "0.0.0.0", 443);
    mqvpn_config_set_subnet(cfg, "10.0.0.0/24");
    mqvpn_config_set_tls_cert(cfg, TEST_CERT_FILE, TEST_KEY_FILE);
    mqvpn_config_set_log_level(cfg, MQVPN_LOG_ERROR);
    return cfg;
}

/* ── server_new tests ── */

TEST(server_new_null_config)
{
    mqvpn_server_callbacks_t cbs = MQVPN_SERVER_CALLBACKS_INIT;
    cbs.tun_output = mock_tun_output;
    cbs.tunnel_config_ready = mock_tunnel_config_ready;
    mqvpn_server_t *s = mqvpn_server_new(NULL, &cbs, NULL);
    ASSERT_NULL(s);
}

TEST(server_new_null_callbacks)
{
    mqvpn_config_t *cfg = make_server_config();
    mqvpn_server_t *s = mqvpn_server_new(cfg, NULL, NULL);
    ASSERT_NULL(s);
    mqvpn_config_free(cfg);
}

TEST(server_new_bad_abi)
{
    mqvpn_config_t *cfg = make_server_config();
    mqvpn_server_callbacks_t cbs = MQVPN_SERVER_CALLBACKS_INIT;
    cbs.abi_version = 999;
    cbs.tun_output = mock_tun_output;
    cbs.tunnel_config_ready = mock_tunnel_config_ready;
    mqvpn_server_t *s = mqvpn_server_new(cfg, &cbs, NULL);
    ASSERT_NULL(s);
    mqvpn_config_free(cfg);
}

TEST(server_new_missing_tun_output)
{
    mqvpn_config_t *cfg = make_server_config();
    mqvpn_server_callbacks_t cbs = MQVPN_SERVER_CALLBACKS_INIT;
    cbs.tunnel_config_ready = mock_tunnel_config_ready;
    /* tun_output = NULL */
    mqvpn_server_t *s = mqvpn_server_new(cfg, &cbs, NULL);
    ASSERT_NULL(s);
    mqvpn_config_free(cfg);
}

TEST(server_new_missing_tunnel_config_ready)
{
    mqvpn_config_t *cfg = make_server_config();
    mqvpn_server_callbacks_t cbs = MQVPN_SERVER_CALLBACKS_INIT;
    cbs.tun_output = mock_tun_output;
    /* tunnel_config_ready = NULL */
    mqvpn_server_t *s = mqvpn_server_new(cfg, &cbs, NULL);
    ASSERT_NULL(s);
    mqvpn_config_free(cfg);
}

TEST(server_new_destroy)
{
    reset_mocks();
    mqvpn_config_t *cfg = make_server_config();
    mqvpn_server_callbacks_t cbs = MQVPN_SERVER_CALLBACKS_INIT;
    cbs.tun_output = mock_tun_output;
    cbs.tunnel_config_ready = mock_tunnel_config_ready;
    cbs.log = mock_log;

    mqvpn_server_t *s = mqvpn_server_new(cfg, &cbs, NULL);
    ASSERT_NOT_NULL(s);
    mqvpn_config_free(cfg);

    mqvpn_server_destroy(s);
}

TEST(server_destroy_null)
{
    /* Must not crash */
    mqvpn_server_destroy(NULL);
}

/* ── Lifecycle tests ── */

TEST(server_lifecycle)
{
    reset_mocks();
    mqvpn_config_t *cfg = make_server_config();
    mqvpn_server_callbacks_t cbs = MQVPN_SERVER_CALLBACKS_INIT;
    cbs.tun_output = mock_tun_output;
    cbs.tunnel_config_ready = mock_tunnel_config_ready;
    cbs.log = mock_log;

    mqvpn_server_t *s = mqvpn_server_new(cfg, &cbs, NULL);
    ASSERT_NOT_NULL(s);
    mqvpn_config_free(cfg);

    /* start() should trigger tunnel_config_ready */
    ASSERT_EQ(g_tunnel_config_ready_called, 0);
    ASSERT_EQ(mqvpn_server_start(s), MQVPN_OK);
    ASSERT_EQ(g_tunnel_config_ready_called, 1);

    /* Verify tunnel info: server gets .1 address in 10.0.0.0/24 */
    ASSERT_EQ(g_last_tunnel_info.assigned_ip[0], 10);
    ASSERT_EQ(g_last_tunnel_info.assigned_ip[1], 0);
    ASSERT_EQ(g_last_tunnel_info.assigned_ip[2], 0);
    ASSERT_EQ(g_last_tunnel_info.assigned_ip[3], 1);
    ASSERT_EQ(g_last_tunnel_info.mtu, 1280);

    /* tick() should succeed */
    ASSERT_EQ(mqvpn_server_tick(s), MQVPN_OK);

    /* get_interest() should return valid values */
    mqvpn_interest_t interest;
    ASSERT_EQ(mqvpn_server_get_interest(s, &interest), MQVPN_OK);
    ASSERT_NE(interest.next_timer_ms, 0);
    ASSERT_EQ(interest.tun_readable, 1);

    /* get_stats() should work */
    mqvpn_stats_t stats;
    ASSERT_EQ(mqvpn_server_get_stats(s, &stats), MQVPN_OK);
    ASSERT_EQ(stats.bytes_tx, 0);
    ASSERT_EQ(stats.bytes_rx, 0);

    /* stop and destroy */
    ASSERT_EQ(mqvpn_server_stop(s), MQVPN_OK);
    mqvpn_server_destroy(s);
}

TEST(server_lifecycle_with_v6)
{
    reset_mocks();
    mqvpn_config_t *cfg = make_server_config();
    mqvpn_config_set_subnet6(cfg, "fd00::/112");

    mqvpn_server_callbacks_t cbs = MQVPN_SERVER_CALLBACKS_INIT;
    cbs.tun_output = mock_tun_output;
    cbs.tunnel_config_ready = mock_tunnel_config_ready;
    cbs.log = mock_log;

    mqvpn_server_t *s = mqvpn_server_new(cfg, &cbs, NULL);
    ASSERT_NOT_NULL(s);
    mqvpn_config_free(cfg);

    ASSERT_EQ(mqvpn_server_start(s), MQVPN_OK);
    ASSERT_EQ(g_tunnel_config_ready_called, 1);
    ASSERT_EQ(g_last_tunnel_info.has_v6, 1);

    mqvpn_server_destroy(s);
}

TEST(server_double_start)
{
    reset_mocks();
    mqvpn_config_t *cfg = make_server_config();
    mqvpn_server_callbacks_t cbs = MQVPN_SERVER_CALLBACKS_INIT;
    cbs.tun_output = mock_tun_output;
    cbs.tunnel_config_ready = mock_tunnel_config_ready;

    mqvpn_server_t *s = mqvpn_server_new(cfg, &cbs, NULL);
    mqvpn_config_free(cfg);

    ASSERT_EQ(mqvpn_server_start(s), MQVPN_OK);
    /* Second start should fail */
    ASSERT_EQ(mqvpn_server_start(s), MQVPN_ERR_INVALID_ARG);

    mqvpn_server_destroy(s);
}

/* ── set_socket_fd tests ── */

TEST(server_set_socket_fd)
{
    reset_mocks();
    mqvpn_config_t *cfg = make_server_config();
    mqvpn_server_callbacks_t cbs = MQVPN_SERVER_CALLBACKS_INIT;
    cbs.tun_output = mock_tun_output;
    cbs.tunnel_config_ready = mock_tunnel_config_ready;

    mqvpn_server_t *s = mqvpn_server_new(cfg, &cbs, NULL);
    mqvpn_config_free(cfg);

    struct sockaddr_in laddr = { .sin_family = AF_INET };
    ASSERT_EQ(mqvpn_server_set_socket_fd(s, 42,
              (struct sockaddr *)&laddr, sizeof(laddr)), MQVPN_OK);
    ASSERT_EQ(mqvpn_server_set_socket_fd(s, -1, NULL, 0), MQVPN_ERR_INVALID_ARG);
    ASSERT_EQ(mqvpn_server_set_socket_fd(NULL, 42, NULL, 0), MQVPN_ERR_INVALID_ARG);

    mqvpn_server_destroy(s);
}

/* ── Query function null-safety tests ── */

TEST(server_get_stats_null)
{
    mqvpn_stats_t stats;
    ASSERT_EQ(mqvpn_server_get_stats(NULL, &stats), MQVPN_ERR_INVALID_ARG);
}

TEST(server_get_interest_null)
{
    mqvpn_interest_t interest;
    ASSERT_EQ(mqvpn_server_get_interest(NULL, &interest), MQVPN_ERR_INVALID_ARG);
}

TEST(server_tick_null)
{
    ASSERT_EQ(mqvpn_server_tick(NULL), MQVPN_ERR_INVALID_ARG);
}

TEST(server_on_tun_packet_null)
{
    uint8_t pkt[20] = {0x45};
    ASSERT_EQ(mqvpn_server_on_tun_packet(NULL, pkt, 20), MQVPN_ERR_INVALID_ARG);
}

TEST(server_on_socket_recv_null)
{
    uint8_t pkt[20];
    struct sockaddr_in addr = { .sin_family = AF_INET };
    ASSERT_EQ(mqvpn_server_on_socket_recv(NULL, pkt, 20,
              (struct sockaddr *)&addr, sizeof(addr)), MQVPN_ERR_INVALID_ARG);
}

/* ── on_tun_packet with no sessions ── */

TEST(server_on_tun_packet_no_sessions)
{
    reset_mocks();
    mqvpn_config_t *cfg = make_server_config();
    mqvpn_server_callbacks_t cbs = MQVPN_SERVER_CALLBACKS_INIT;
    cbs.tun_output = mock_tun_output;
    cbs.tunnel_config_ready = mock_tunnel_config_ready;

    mqvpn_server_t *s = mqvpn_server_new(cfg, &cbs, NULL);
    mqvpn_config_free(cfg);
    mqvpn_server_start(s);

    /* With no sessions, on_tun_packet should return OK (early return, no ICMP) */
    uint8_t pkt[40];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;  /* IPv4 */
    ASSERT_EQ(mqvpn_server_on_tun_packet(s, pkt, 40), MQVPN_OK);

    mqvpn_server_destroy(s);
}

/* ── test_server_session: session lifecycle callbacks ── */

static int g_client_connected_called = 0;
static uint32_t g_last_session_id = 0;
static int g_client_disconnected_called = 0;
static uint32_t g_last_disconnected_session_id = 0;

static void mock_on_client_connected(const mqvpn_tunnel_info_t *info,
                                       uint32_t session_id, void *user_ctx)
{
    (void)user_ctx;
    g_client_connected_called++;
    g_last_session_id = session_id;
    if (info) {
        memcpy(&g_last_tunnel_info, info, sizeof(g_last_tunnel_info));
    }
}

static void mock_on_client_disconnected(uint32_t session_id,
                                          mqvpn_error_t reason, void *user_ctx)
{
    (void)reason; (void)user_ctx;
    g_client_disconnected_called++;
    g_last_disconnected_session_id = session_id;
}

/* ── Client mock callbacks for loopback test ── */

static int g_cli_tun_output_called = 0;
static int g_cli_tunnel_ready_called = 0;
static mqvpn_tunnel_info_t g_cli_tunnel_info;

static void mock_cli_tun_output(const uint8_t *pkt, size_t len, void *user_ctx)
{
    (void)pkt; (void)len; (void)user_ctx;
    g_cli_tun_output_called++;
}

static void mock_cli_tunnel_ready(const mqvpn_tunnel_info_t *info,
                                    void *user_ctx)
{
    (void)user_ctx;
    g_cli_tunnel_ready_called++;
    if (info)
        memcpy(&g_cli_tunnel_info, info, sizeof(g_cli_tunnel_info));
}

/* ── Packet relay helper: drain sockets and tick both engines ── */

static void drain_and_tick(mqvpn_server_t *svr, int svr_fd,
                             mqvpn_client_t *cli, int cli_fd,
                             mqvpn_path_handle_t path_h)
{
    uint8_t buf[65536];
    struct sockaddr_storage from;
    socklen_t from_len;

    /* Drain server socket (packets from client) */
    for (;;) {
        from_len = sizeof(from);
        ssize_t n = recvfrom(svr_fd, buf, sizeof(buf), MSG_DONTWAIT,
                              (struct sockaddr *)&from, &from_len);
        if (n <= 0) break;
        mqvpn_server_on_socket_recv(svr, buf, (size_t)n,
                                      (struct sockaddr *)&from, from_len);
    }

    /* Drain client socket (packets from server) */
    for (;;) {
        from_len = sizeof(from);
        ssize_t n = recvfrom(cli_fd, buf, sizeof(buf), MSG_DONTWAIT,
                              (struct sockaddr *)&from, &from_len);
        if (n <= 0) break;
        mqvpn_client_on_socket_recv(cli, path_h, buf, (size_t)n,
                                      (struct sockaddr *)&from, from_len);
    }

    mqvpn_server_tick(svr);
    mqvpn_client_tick(cli);
}

/* Note: all pump loops below use poll() instead of usleep() for CI robustness.
 * This avoids timing issues on slow CI runners where QUIC PTO (1s+) can expire. */

/* ── test_server_session tests ── */

TEST(server_session_callbacks_registered)
{
    /* Verify that on_client_connected/disconnected callbacks are accepted */
    reset_mocks();
    g_client_connected_called = 0;
    g_client_disconnected_called = 0;

    mqvpn_config_t *cfg = make_server_config();
    mqvpn_server_callbacks_t cbs = MQVPN_SERVER_CALLBACKS_INIT;
    cbs.tun_output = mock_tun_output;
    cbs.tunnel_config_ready = mock_tunnel_config_ready;
    cbs.log = mock_log;
    cbs.on_client_connected = mock_on_client_connected;
    cbs.on_client_disconnected = mock_on_client_disconnected;

    mqvpn_server_t *s = mqvpn_server_new(cfg, &cbs, NULL);
    ASSERT_NOT_NULL(s);
    mqvpn_config_free(cfg);

    ASSERT_EQ(mqvpn_server_start(s), MQVPN_OK);

    /* No clients connected yet */
    ASSERT_EQ(g_client_connected_called, 0);
    ASSERT_EQ(g_client_disconnected_called, 0);

    /* Stats should show zero */
    mqvpn_stats_t stats;
    ASSERT_EQ(mqvpn_server_get_stats(s, &stats), MQVPN_OK);
    ASSERT_EQ(stats.bytes_tx, 0);
    ASSERT_EQ(stats.bytes_rx, 0);

    mqvpn_server_destroy(s);
}

TEST(server_session_set_socket_with_addr)
{
    /* Verify set_socket_fd stores local address */
    reset_mocks();
    mqvpn_config_t *cfg = make_server_config();
    mqvpn_server_callbacks_t cbs = MQVPN_SERVER_CALLBACKS_INIT;
    cbs.tun_output = mock_tun_output;
    cbs.tunnel_config_ready = mock_tunnel_config_ready;

    mqvpn_server_t *s = mqvpn_server_new(cfg, &cbs, NULL);
    mqvpn_config_free(cfg);

    struct sockaddr_in laddr;
    memset(&laddr, 0, sizeof(laddr));
    laddr.sin_family = AF_INET;
    laddr.sin_port = htons(443);
    laddr.sin_addr.s_addr = htonl(INADDR_ANY);

    ASSERT_EQ(mqvpn_server_set_socket_fd(s, 42,
              (struct sockaddr *)&laddr, sizeof(laddr)), MQVPN_OK);

    /* Verify NULL local_addr is also accepted */
    ASSERT_EQ(mqvpn_server_set_socket_fd(s, 43, NULL, 0), MQVPN_OK);

    mqvpn_server_destroy(s);
}

TEST(server_session_on_tun_v6_no_sessions)
{
    /* IPv6 packet with no sessions → early return, no ICMP */
    reset_mocks();
    mqvpn_config_t *cfg = make_server_config();
    mqvpn_config_set_subnet6(cfg, "fd00::/112");

    mqvpn_server_callbacks_t cbs = MQVPN_SERVER_CALLBACKS_INIT;
    cbs.tun_output = mock_tun_output;
    cbs.tunnel_config_ready = mock_tunnel_config_ready;

    mqvpn_server_t *s = mqvpn_server_new(cfg, &cbs, NULL);
    mqvpn_config_free(cfg);
    mqvpn_server_start(s);

    int baseline = g_tun_output_called;

    /* IPv6 packet to unknown dest within pool */
    uint8_t pkt6[60];
    memset(pkt6, 0, sizeof(pkt6));
    pkt6[0] = 0x60;  /* IPv6 */
    pkt6[4] = 0; pkt6[5] = 20;  /* payload length */
    pkt6[6] = 59;  /* next header: no next */
    pkt6[7] = 64;  /* hop limit */
    /* src: fd00::100 */
    pkt6[8] = 0xfd; pkt6[23] = 0x01;
    /* dst: fd00::50 (no session) */
    pkt6[24] = 0xfd; pkt6[39] = 0x32;

    /* n_sessions == 0 → early return, no ICMP generated */
    ASSERT_EQ(mqvpn_server_on_tun_packet(s, pkt6, 60), MQVPN_OK);
    ASSERT_EQ(g_tun_output_called, baseline);

    mqvpn_server_destroy(s);
}

/* ── test_server_session: QUIC loopback integration test ──
 *
 * Per impl_plan M1-5:
 *   - on_socket_recv() でクライアント接続
 *   - tunnel_config_ready callback 発火
 *   - set_tun_active → tun_output でパケット出力
 *   - client 切断 → セッション解放
 */
TEST(server_session_quic_loopback)
{
    /* Reset all mocks */
    reset_mocks();
    g_client_connected_called = 0;
    g_client_disconnected_called = 0;
    g_cli_tun_output_called = 0;
    g_cli_tunnel_ready_called = 0;
    memset(&g_cli_tunnel_info, 0, sizeof(g_cli_tunnel_info));

    /* ── Create UDP sockets ── */
    int svr_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    ASSERT_NE(svr_fd, -1);
    int cli_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    ASSERT_NE(cli_fd, -1);

    struct sockaddr_in svr_addr, cli_addr;
    memset(&svr_addr, 0, sizeof(svr_addr));
    svr_addr.sin_family = AF_INET;
    svr_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    svr_addr.sin_port = htons(0); /* OS picks port */
    /* Do NOT use assert() for calls with side effects — NDEBUG removes them */
    ASSERT_EQ(bind(svr_fd, (struct sockaddr *)&svr_addr, sizeof(svr_addr)), 0);

    memset(&cli_addr, 0, sizeof(cli_addr));
    cli_addr.sin_family = AF_INET;
    cli_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    cli_addr.sin_port = htons(0);
    ASSERT_EQ(bind(cli_fd, (struct sockaddr *)&cli_addr, sizeof(cli_addr)), 0);

    /* Get actual bound addresses */
    socklen_t alen = sizeof(svr_addr);
    getsockname(svr_fd, (struct sockaddr *)&svr_addr, &alen);
    alen = sizeof(cli_addr);
    getsockname(cli_fd, (struct sockaddr *)&cli_addr, &alen);

    /* ── Server setup ── */
    mqvpn_config_t *svr_cfg = make_server_config();
    mqvpn_server_callbacks_t svr_cbs = MQVPN_SERVER_CALLBACKS_INIT;
    svr_cbs.tun_output = mock_tun_output;
    svr_cbs.tunnel_config_ready = mock_tunnel_config_ready;
    svr_cbs.on_client_connected = mock_on_client_connected;
    svr_cbs.on_client_disconnected = mock_on_client_disconnected;

    mqvpn_server_t *svr = mqvpn_server_new(svr_cfg, &svr_cbs, NULL);
    ASSERT_NOT_NULL(svr);
    mqvpn_config_free(svr_cfg);

    ASSERT_EQ(mqvpn_server_set_socket_fd(svr, svr_fd,
              (struct sockaddr *)&svr_addr, sizeof(svr_addr)), MQVPN_OK);
    ASSERT_EQ(mqvpn_server_start(svr), MQVPN_OK);

    /* ── Client setup ── */
    mqvpn_config_t *cli_cfg = mqvpn_config_new();
    mqvpn_config_set_server(cli_cfg, "127.0.0.1", ntohs(svr_addr.sin_port));
    mqvpn_config_set_insecure(cli_cfg, 1);
    mqvpn_config_set_log_level(cli_cfg, MQVPN_LOG_ERROR);

    mqvpn_client_callbacks_t cli_cbs = MQVPN_CLIENT_CALLBACKS_INIT;
    cli_cbs.tun_output = mock_cli_tun_output;
    cli_cbs.tunnel_config_ready = mock_cli_tunnel_ready;
    /* send_packet = NULL → fd-only mode */

    mqvpn_client_t *cli = mqvpn_client_new(cli_cfg, &cli_cbs, NULL);
    ASSERT_NOT_NULL(cli);
    mqvpn_config_free(cli_cfg);

    /* Add path with client socket */
    mqvpn_path_desc_t desc;
    memset(&desc, 0, sizeof(desc));
    desc.struct_size = sizeof(desc);
    memcpy(desc.local_addr, &cli_addr, sizeof(cli_addr));
    desc.local_addr_len = sizeof(cli_addr);

    mqvpn_path_handle_t path_h = mqvpn_client_add_path_fd(cli, cli_fd, &desc);
    ASSERT_NE(path_h, (mqvpn_path_handle_t)-1);

    /* Set server address and connect */
    mqvpn_client_set_server_addr(cli,
        (struct sockaddr *)&svr_addr, sizeof(svr_addr));
    ASSERT_EQ(mqvpn_client_connect(cli), MQVPN_OK);

    /* ── Phase 1: QUIC handshake + MASQUE tunnel setup ── */
    /* Use poll-based pump with 10s timeout for slow CI runners.
     * QUIC retransmission PTO can be 1s+, so 500ms was too tight. */
    for (int elapsed = 0; elapsed < 10000; elapsed++) {
        drain_and_tick(svr, svr_fd, cli, cli_fd, path_h);
        if (g_client_connected_called > 0 && g_cli_tunnel_ready_called > 0)
            break;

        mqvpn_interest_t svr_int = {0}, cli_int = {0};
        mqvpn_server_get_interest(svr, &svr_int);
        mqvpn_client_get_interest(cli, &cli_int);
        int wait_ms = 50;
        if (svr_int.next_timer_ms > 0 && svr_int.next_timer_ms < wait_ms)
            wait_ms = svr_int.next_timer_ms;
        if (cli_int.next_timer_ms > 0 && cli_int.next_timer_ms < wait_ms)
            wait_ms = cli_int.next_timer_ms;
        if (wait_ms < 1) wait_ms = 1;

        struct pollfd pfds[2] = {
            { .fd = svr_fd, .events = POLLIN },
            { .fd = cli_fd, .events = POLLIN },
        };
        poll(pfds, 2, wait_ms);
        elapsed += wait_ms;
    }

    /* Verify: on_socket_recv() でクライアント接続 */
    ASSERT_EQ(g_client_connected_called, 1);
    /* Verify: tunnel_config_ready callback 発火 */
    ASSERT_EQ(g_cli_tunnel_ready_called, 1);
    /* Client assigned IP should be 10.0.0.2 (first allocation in /24) */
    ASSERT_EQ(g_cli_tunnel_info.assigned_ip[0], 10);
    ASSERT_EQ(g_cli_tunnel_info.assigned_ip[1], 0);
    ASSERT_EQ(g_cli_tunnel_info.assigned_ip[2], 0);
    ASSERT_EQ(g_cli_tunnel_info.assigned_ip[3], 2);

    /* Activate TUN → ESTABLISHED */
    mqvpn_client_set_tun_active(cli, 1, -1);
    ASSERT_EQ(mqvpn_client_get_state(cli), MQVPN_STATE_ESTABLISHED);

    /* ── Phase 2: set_tun_active → tun_output でパケット出力 ── */
    /* Build IPv4 packet destined for client's assigned IP */
    uint8_t tun_pkt[40];
    memset(tun_pkt, 0, sizeof(tun_pkt));
    tun_pkt[0] = 0x45;                         /* IPv4, IHL=5 */
    tun_pkt[2] = 0; tun_pkt[3] = 40;          /* total length = 40 */
    tun_pkt[8] = 64;                           /* TTL */
    tun_pkt[9] = 17;                           /* UDP */
    /* Source: 8.8.8.8 */
    tun_pkt[12] = 8; tun_pkt[13] = 8; tun_pkt[14] = 8; tun_pkt[15] = 8;
    /* Destination: client's assigned IP */
    memcpy(tun_pkt + 16, g_cli_tunnel_info.assigned_ip, 4);

    int baseline = g_cli_tun_output_called;
    ASSERT_EQ(mqvpn_server_on_tun_packet(svr, tun_pkt, sizeof(tun_pkt)),
              MQVPN_OK);

    /* Pump to deliver the MASQUE DATAGRAM */
    for (int i = 0; i < 5000; i++) {
        drain_and_tick(svr, svr_fd, cli, cli_fd, path_h);
        if (g_cli_tun_output_called > baseline) break;
        struct pollfd pfds[2] = {
            { .fd = svr_fd, .events = POLLIN },
            { .fd = cli_fd, .events = POLLIN },
        };
        int w = poll(pfds, 2, 5);
        i += (w == 0) ? 5 : 1;
    }
    ASSERT_EQ(g_cli_tun_output_called, baseline + 1);

    /* ── Phase 2b: DL TTL=1 → dropped, ICMP Time Exceeded via tun_output ── */
    uint8_t ttl1_pkt[40];
    memset(ttl1_pkt, 0, sizeof(ttl1_pkt));
    ttl1_pkt[0] = 0x45;
    ttl1_pkt[2] = 0; ttl1_pkt[3] = 40;
    ttl1_pkt[8] = 1;  /* TTL = 1 → expires */
    ttl1_pkt[9] = 17;
    ttl1_pkt[12] = 8; ttl1_pkt[13] = 8; ttl1_pkt[14] = 8; ttl1_pkt[15] = 8;
    memcpy(ttl1_pkt + 16, g_cli_tunnel_info.assigned_ip, 4);

    int tun_baseline = g_tun_output_called;
    int cli_baseline = g_cli_tun_output_called;
    ASSERT_EQ(mqvpn_server_on_tun_packet(svr, ttl1_pkt, sizeof(ttl1_pkt)),
              MQVPN_OK);
    /* ICMP Time Exceeded should be sent via tun_output (not to client) */
    ASSERT_EQ(g_tun_output_called, tun_baseline + 1);
    /* Client should NOT receive the expired packet */
    for (int i = 0; i < 30; i++) {
        drain_and_tick(svr, svr_fd, cli, cli_fd, path_h);
        struct pollfd pfds[2] = {
            { .fd = svr_fd, .events = POLLIN },
            { .fd = cli_fd, .events = POLLIN },
        };
        poll(pfds, 2, 2);
    }
    ASSERT_EQ(g_cli_tun_output_called, cli_baseline);

    /* ── Phase 3: client 切断 → セッション解放 ── */
    mqvpn_client_disconnect(cli);

    /* Pump to deliver CONNECTION_CLOSE to server */
    for (int i = 0; i < 5000; i++) {
        drain_and_tick(svr, svr_fd, cli, cli_fd, path_h);
        if (g_client_disconnected_called > 0) break;
        struct pollfd pfds[2] = {
            { .fd = svr_fd, .events = POLLIN },
            { .fd = cli_fd, .events = POLLIN },
        };
        int w = poll(pfds, 2, 5);
        i += (w == 0) ? 5 : 1;
    }
    ASSERT_EQ(g_client_disconnected_called, 1);
    ASSERT_EQ(g_last_disconnected_session_id, g_last_session_id);

    /* ── Cleanup ── */
    mqvpn_client_destroy(cli);
    mqvpn_server_destroy(svr);
    close(svr_fd);
    close(cli_fd);
}

/* ── Main ── */

int main(void)
{
    printf("test_server: libmqvpn server API tests\n");

    /* server_new validation */
    run_server_new_null_config();
    run_server_new_null_callbacks();
    run_server_new_bad_abi();
    run_server_new_missing_tun_output();
    run_server_new_missing_tunnel_config_ready();
    run_server_new_destroy();
    run_server_destroy_null();

    /* Lifecycle */
    run_server_lifecycle();
    run_server_lifecycle_with_v6();
    run_server_double_start();

    /* set_socket_fd */
    run_server_set_socket_fd();

    /* Null safety */
    run_server_get_stats_null();
    run_server_get_interest_null();
    run_server_tick_null();
    run_server_on_tun_packet_null();
    run_server_on_socket_recv_null();

    /* TUN packet with no sessions */
    run_server_on_tun_packet_no_sessions();

    /* Session lifecycle (test_server_session per impl_plan) */
    run_server_session_callbacks_registered();
    run_server_session_set_socket_with_addr();
    run_server_session_on_tun_v6_no_sessions();

    /* QUIC loopback integration test (test_server_session per impl_plan) */
    run_server_session_quic_loopback();

    printf("\n  %d/%d tests passed\n", g_tests_passed, g_tests_run);
    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
