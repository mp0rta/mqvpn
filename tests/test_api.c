/*
 * test_api.c — libmqvpn public API lifecycle tests
 *
 * Tests: config builder, client create/destroy, error codes, callbacks ABI.
 * Does NOT require xquic or network — all engine creation is mocked or skipped.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

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

#define ASSERT_STR_EQ(a, b) do { \
    if (strcmp((a), (b)) != 0) { \
        printf("FAIL\n    %s:%d: \"%s\" != \"%s\"\n", \
               __FILE__, __LINE__, (a), (b)); \
        exit(1); \
    } \
} while (0)

/* ── Config tests ── */

TEST(config_new_free)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    ASSERT_NOT_NULL(cfg);
    mqvpn_config_free(cfg);
}

TEST(config_free_null)
{
    /* Must not crash */
    mqvpn_config_free(NULL);
}

TEST(config_set_server)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    ASSERT_EQ(mqvpn_config_set_server(cfg, "1.2.3.4", 443), MQVPN_OK);
    ASSERT_EQ(mqvpn_config_set_server(NULL, "1.2.3.4", 443), MQVPN_ERR_INVALID_ARG);
    ASSERT_EQ(mqvpn_config_set_server(cfg, NULL, 443), MQVPN_ERR_INVALID_ARG);
    mqvpn_config_free(cfg);
}

TEST(config_set_auth_key)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    ASSERT_EQ(mqvpn_config_set_auth_key(cfg, "testkey123"), MQVPN_OK);
    ASSERT_EQ(mqvpn_config_set_auth_key(NULL, "key"), MQVPN_ERR_INVALID_ARG);
    mqvpn_config_free(cfg);
}

TEST(config_set_insecure)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    ASSERT_EQ(mqvpn_config_set_insecure(cfg, 1), MQVPN_OK);
    ASSERT_EQ(mqvpn_config_set_insecure(cfg, 0), MQVPN_OK);
    mqvpn_config_free(cfg);
}

TEST(config_set_scheduler)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    ASSERT_EQ(mqvpn_config_set_scheduler(cfg, MQVPN_SCHED_MINRTT), MQVPN_OK);
    ASSERT_EQ(mqvpn_config_set_scheduler(cfg, MQVPN_SCHED_WLB), MQVPN_OK);
    mqvpn_config_free(cfg);
}

TEST(config_set_log_level)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    ASSERT_EQ(mqvpn_config_set_log_level(cfg, MQVPN_LOG_DEBUG), MQVPN_OK);
    ASSERT_EQ(mqvpn_config_set_log_level(cfg, MQVPN_LOG_ERROR), MQVPN_OK);
    mqvpn_config_free(cfg);
}

TEST(config_set_reconnect)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    ASSERT_EQ(mqvpn_config_set_reconnect(cfg, 1, 5), MQVPN_OK);
    ASSERT_EQ(mqvpn_config_set_reconnect(cfg, 0, 0), MQVPN_OK);
    mqvpn_config_free(cfg);
}

TEST(config_set_killswitch_hint)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    ASSERT_EQ(mqvpn_config_set_killswitch_hint(cfg, 1), MQVPN_OK);
    ASSERT_EQ(mqvpn_config_set_killswitch_hint(cfg, 0), MQVPN_OK);
    mqvpn_config_free(cfg);
}

TEST(config_set_listen)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    ASSERT_EQ(mqvpn_config_set_listen(cfg, "0.0.0.0", 443), MQVPN_OK);
    mqvpn_config_free(cfg);
}

TEST(config_set_subnet)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    ASSERT_EQ(mqvpn_config_set_subnet(cfg, "10.0.0.0/24"), MQVPN_OK);
    ASSERT_EQ(mqvpn_config_set_subnet6(cfg, "fd00::/112"), MQVPN_OK);
    mqvpn_config_free(cfg);
}

TEST(config_set_tls_cert)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    ASSERT_EQ(mqvpn_config_set_tls_cert(cfg, "/path/cert.pem", "/path/key.pem"),
              MQVPN_OK);
    mqvpn_config_free(cfg);
}

TEST(config_set_max_clients)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    ASSERT_EQ(mqvpn_config_set_max_clients(cfg, 128), MQVPN_OK);
    mqvpn_config_free(cfg);
}

TEST(config_set_multipath)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    ASSERT_EQ(mqvpn_config_set_multipath(cfg, 1), MQVPN_OK);
    ASSERT_EQ(mqvpn_config_set_multipath(cfg, 0), MQVPN_OK);
    mqvpn_config_free(cfg);
}

/* ── Callback ABI tests ── */

TEST(callbacks_abi_init)
{
    mqvpn_client_callbacks_t cbs = MQVPN_CLIENT_CALLBACKS_INIT;
    ASSERT_EQ(cbs.abi_version, MQVPN_CALLBACKS_ABI_VERSION);
    ASSERT_EQ(cbs.struct_size, sizeof(mqvpn_client_callbacks_t));
    ASSERT_NULL(cbs.tun_output);
    ASSERT_NULL(cbs.tunnel_config_ready);
}

TEST(server_callbacks_abi_init)
{
    mqvpn_server_callbacks_t cbs = MQVPN_SERVER_CALLBACKS_INIT;
    ASSERT_EQ(cbs.abi_version, MQVPN_CALLBACKS_ABI_VERSION);
    ASSERT_EQ(cbs.struct_size, sizeof(mqvpn_server_callbacks_t));
}

/* ── Error string tests ── */

TEST(error_string)
{
    ASSERT_STR_EQ(mqvpn_error_string(MQVPN_OK), "OK");
    ASSERT_STR_EQ(mqvpn_error_string(MQVPN_ERR_INVALID_ARG), "invalid argument");
    ASSERT_STR_EQ(mqvpn_error_string(MQVPN_ERR_NO_MEMORY), "out of memory");
    ASSERT_STR_EQ(mqvpn_error_string(MQVPN_ERR_ENGINE), "engine error");
    ASSERT_STR_EQ(mqvpn_error_string(MQVPN_ERR_AGAIN), "back-pressure");
    ASSERT_STR_EQ(mqvpn_error_string(MQVPN_ERR_ABI_MISMATCH), "ABI mismatch");
    /* Unknown error code */
    ASSERT_NOT_NULL(mqvpn_error_string((mqvpn_error_t)-99));
}

/* ── Version string test ── */

TEST(version_string)
{
    const char *v = mqvpn_version_string();
    ASSERT_NOT_NULL(v);
    /* Should contain major.minor.patch */
    ASSERT_NOT_NULL(strstr(v, "0.5.0"));
}

/* ── Client lifecycle (without xquic — expects NULL due to engine init failure) ── */

/* ── Mock callbacks ── */

static int g_state_change_count = 0;
static mqvpn_client_state_t g_last_old_state;
static mqvpn_client_state_t g_last_new_state;

static void dummy_tun_output(const uint8_t *p, size_t l, void *u) { (void)p; (void)l; (void)u; }
static void dummy_config_ready(const mqvpn_tunnel_info_t *i, void *u) { (void)i; (void)u; }
static void mock_state_changed(mqvpn_client_state_t old_s, mqvpn_client_state_t new_s, void *u) {
    (void)u;
    g_state_change_count++;
    g_last_old_state = old_s;
    g_last_new_state = new_s;
}

/* Helper: create a valid client for lifecycle tests */
static mqvpn_client_t *make_test_client(void)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    mqvpn_config_set_server(cfg, "1.2.3.4", 443);

    mqvpn_client_callbacks_t cbs = MQVPN_CLIENT_CALLBACKS_INIT;
    cbs.tun_output = dummy_tun_output;
    cbs.tunnel_config_ready = dummy_config_ready;
    cbs.state_changed = mock_state_changed;

    mqvpn_client_t *c = mqvpn_client_new(cfg, &cbs, NULL);
    mqvpn_config_free(cfg);
    return c;
}

TEST(client_new_null_args)
{
    mqvpn_client_callbacks_t cbs = MQVPN_CLIENT_CALLBACKS_INIT;
    cbs.tun_output = dummy_tun_output;
    cbs.tunnel_config_ready = dummy_config_ready;

    /* NULL config */
    ASSERT_NULL(mqvpn_client_new(NULL, &cbs, NULL));

    /* NULL callbacks */
    mqvpn_config_t *cfg = mqvpn_config_new();
    mqvpn_config_set_server(cfg, "1.2.3.4", 443);
    ASSERT_NULL(mqvpn_client_new(cfg, NULL, NULL));
    mqvpn_config_free(cfg);
}

TEST(client_new_missing_required_callbacks)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    mqvpn_config_set_server(cfg, "1.2.3.4", 443);

    /* Missing tun_output */
    mqvpn_client_callbacks_t cbs = MQVPN_CLIENT_CALLBACKS_INIT;
    cbs.tunnel_config_ready = dummy_config_ready;
    ASSERT_NULL(mqvpn_client_new(cfg, &cbs, NULL));

    /* Missing tunnel_config_ready */
    cbs = (mqvpn_client_callbacks_t)MQVPN_CLIENT_CALLBACKS_INIT;
    cbs.tun_output = dummy_tun_output;
    ASSERT_NULL(mqvpn_client_new(cfg, &cbs, NULL));

    mqvpn_config_free(cfg);
}

TEST(client_new_abi_mismatch)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    mqvpn_config_set_server(cfg, "1.2.3.4", 443);

    mqvpn_client_callbacks_t cbs = MQVPN_CLIENT_CALLBACKS_INIT;
    cbs.tun_output = dummy_tun_output;
    cbs.tunnel_config_ready = dummy_config_ready;
    cbs.abi_version = 99;  /* wrong version */

    ASSERT_NULL(mqvpn_client_new(cfg, &cbs, NULL));

    mqvpn_config_free(cfg);
}

TEST(client_destroy_null)
{
    /* Must not crash */
    mqvpn_client_destroy(NULL);
}

/* ── Client lifecycle: connect / state / disconnect ── */

TEST(client_new_creates_idle)
{
    mqvpn_client_t *c = make_test_client();
    ASSERT_NOT_NULL(c);
    ASSERT_EQ(mqvpn_client_get_state(c), MQVPN_STATE_IDLE);
    mqvpn_client_destroy(c);
}

TEST(client_connect_transitions_to_connecting)
{
    mqvpn_client_t *c = make_test_client();
    g_state_change_count = 0;

    ASSERT_EQ(mqvpn_client_connect(c), MQVPN_OK);
    ASSERT_EQ(mqvpn_client_get_state(c), MQVPN_STATE_CONNECTING);
    ASSERT_EQ(g_state_change_count, 1);
    ASSERT_EQ(g_last_old_state, MQVPN_STATE_IDLE);
    ASSERT_EQ(g_last_new_state, MQVPN_STATE_CONNECTING);

    mqvpn_client_destroy(c);
}

TEST(client_connect_from_invalid_state)
{
    mqvpn_client_t *c = make_test_client();

    /* connect once → CONNECTING */
    ASSERT_EQ(mqvpn_client_connect(c), MQVPN_OK);
    /* connect again from CONNECTING → invalid */
    ASSERT_EQ(mqvpn_client_connect(c), MQVPN_ERR_INVALID_ARG);

    mqvpn_client_destroy(c);
}

TEST(client_disconnect_from_connecting)
{
    mqvpn_client_t *c = make_test_client();
    mqvpn_client_connect(c);
    g_state_change_count = 0;

    ASSERT_EQ(mqvpn_client_disconnect(c), MQVPN_OK);
    ASSERT_EQ(mqvpn_client_get_state(c), MQVPN_STATE_CLOSED);
    ASSERT_EQ(g_state_change_count, 1);
    ASSERT_EQ(g_last_new_state, MQVPN_STATE_CLOSED);

    mqvpn_client_destroy(c);
}

TEST(client_disconnect_from_idle)
{
    mqvpn_client_t *c = make_test_client();
    /* disconnect from IDLE is no-op (already stopped) */
    ASSERT_EQ(mqvpn_client_disconnect(c), MQVPN_OK);
    ASSERT_EQ(mqvpn_client_get_state(c), MQVPN_STATE_IDLE);
    mqvpn_client_destroy(c);
}

TEST(client_tick_null_safety)
{
    ASSERT_EQ(mqvpn_client_tick(NULL), MQVPN_ERR_INVALID_ARG);
}

TEST(client_tick_ok)
{
    mqvpn_client_t *c = make_test_client();
    ASSERT_EQ(mqvpn_client_tick(c), MQVPN_OK);
    mqvpn_client_destroy(c);
}

/* ── Query functions ── */

TEST(client_get_state_null)
{
    ASSERT_EQ(mqvpn_client_get_state(NULL), MQVPN_STATE_CLOSED);
}

TEST(client_get_stats)
{
    mqvpn_client_t *c = make_test_client();
    mqvpn_stats_t stats;

    ASSERT_EQ(mqvpn_client_get_stats(c, &stats), MQVPN_OK);
    ASSERT_EQ(stats.struct_size, sizeof(mqvpn_stats_t));
    ASSERT_EQ(stats.bytes_tx, 0);
    ASSERT_EQ(stats.bytes_rx, 0);

    /* NULL args */
    ASSERT_EQ(mqvpn_client_get_stats(NULL, &stats), MQVPN_ERR_INVALID_ARG);
    ASSERT_EQ(mqvpn_client_get_stats(c, NULL), MQVPN_ERR_INVALID_ARG);

    mqvpn_client_destroy(c);
}

TEST(client_get_interest)
{
    mqvpn_client_t *c = make_test_client();
    mqvpn_interest_t interest;

    ASSERT_EQ(mqvpn_client_get_interest(c, &interest), MQVPN_OK);
    ASSERT_EQ(interest.struct_size, sizeof(mqvpn_interest_t));
    /* next_timer_ms >= 1 */
    ASSERT_EQ(interest.next_timer_ms >= 1, 1);
    /* tun not active yet */
    ASSERT_EQ(interest.tun_readable, 0);
    /* idle since not established */
    ASSERT_EQ(interest.is_idle, 1);

    /* NULL args */
    ASSERT_EQ(mqvpn_client_get_interest(NULL, &interest), MQVPN_ERR_INVALID_ARG);
    ASSERT_EQ(mqvpn_client_get_interest(c, NULL), MQVPN_ERR_INVALID_ARG);

    mqvpn_client_destroy(c);
}

/* ── Path management ── */

TEST(client_add_path)
{
    mqvpn_client_t *c = make_test_client();
    mqvpn_path_desc_t desc = {0};
    desc.fd = 42;
    snprintf(desc.iface, sizeof(desc.iface), "eth0");

    mqvpn_path_handle_t h = mqvpn_client_add_path_fd(c, 42, &desc);
    ASSERT_NE(h, (mqvpn_path_handle_t)-1);

    /* Query paths */
    mqvpn_path_info_t info[4];
    int n = 0;
    ASSERT_EQ(mqvpn_client_get_paths(c, info, 4, &n), MQVPN_OK);
    ASSERT_EQ(n, 1);
    ASSERT_EQ(info[0].handle, h);
    ASSERT_EQ(info[0].status, MQVPN_PATH_PENDING);
    ASSERT_STR_EQ(info[0].name, "eth0");

    mqvpn_client_destroy(c);
}

TEST(path_initial_stats_zero)
{
    mqvpn_client_t *c = make_test_client();
    mqvpn_path_desc_t desc = {0};
    desc.fd = 42;
    snprintf(desc.iface, sizeof(desc.iface), "wlan0");
    mqvpn_client_add_path_fd(c, 42, &desc);

    mqvpn_path_info_t info[4];
    int n = 0;
    ASSERT_EQ(mqvpn_client_get_paths(c, info, 4, &n), MQVPN_OK);
    ASSERT_EQ(n, 1);
    ASSERT_EQ(info[0].bytes_tx, 0);
    ASSERT_EQ(info[0].bytes_rx, 0);
    ASSERT_EQ(info[0].srtt_ms, 0);

    mqvpn_client_destroy(c);
}

TEST(path_stats_after_recv)
{
    mqvpn_client_t *c = make_test_client();
    mqvpn_path_desc_t desc = {0};
    desc.fd = 42;
    snprintf(desc.iface, sizeof(desc.iface), "wlan0");
    mqvpn_path_handle_t h = mqvpn_client_add_path_fd(c, 42, &desc);

    /* Feed some bytes — xquic won't parse this, but bytes_rx should count */
    uint8_t pkt[100];
    memset(pkt, 0xAB, sizeof(pkt));
    mqvpn_client_on_socket_recv(c, h, pkt, sizeof(pkt), NULL, 0);

    mqvpn_path_info_t info[4];
    int n = 0;
    ASSERT_EQ(mqvpn_client_get_paths(c, info, 4, &n), MQVPN_OK);
    ASSERT_EQ(n, 1);
    ASSERT_EQ(info[0].bytes_rx, 100);

    mqvpn_client_destroy(c);
}

TEST(get_paths_null_safety)
{
    mqvpn_client_t *c = make_test_client();
    mqvpn_path_info_t info[4];
    int n = 0;

    ASSERT_EQ(mqvpn_client_get_paths(NULL, info, 4, &n), MQVPN_ERR_INVALID_ARG);
    ASSERT_EQ(mqvpn_client_get_paths(c, NULL, 4, &n), MQVPN_ERR_INVALID_ARG);
    ASSERT_EQ(mqvpn_client_get_paths(c, info, 4, NULL), MQVPN_ERR_INVALID_ARG);

    mqvpn_client_destroy(c);
}

TEST(client_remove_path)
{
    mqvpn_client_t *c = make_test_client();
    mqvpn_path_handle_t h = mqvpn_client_add_path_fd(c, 42, NULL);

    ASSERT_EQ(mqvpn_client_remove_path(c, h), MQVPN_OK);

    /* Remove nonexistent */
    ASSERT_EQ(mqvpn_client_remove_path(c, 999), MQVPN_ERR_INVALID_ARG);

    mqvpn_client_destroy(c);
}

TEST(client_add_path_max)
{
    mqvpn_client_t *c = make_test_client();
    /* Add MQVPN_MAX_PATHS (4) paths */
    for (int i = 0; i < 4; i++) {
        mqvpn_path_handle_t h = mqvpn_client_add_path_fd(c, 10 + i, NULL);
        ASSERT_NE(h, (mqvpn_path_handle_t)-1);
    }
    /* 5th path should fail */
    ASSERT_EQ(mqvpn_client_add_path_fd(c, 99, NULL), (mqvpn_path_handle_t)-1);

    mqvpn_client_destroy(c);
}

/* ── TUN control ── */

TEST(client_set_tun_active)
{
    mqvpn_client_t *c = make_test_client();
    ASSERT_EQ(mqvpn_client_set_tun_active(c, 1, 5), MQVPN_OK);

    /* Interest should reflect tun_readable */
    mqvpn_interest_t interest;
    mqvpn_client_get_interest(c, &interest);
    /* tun_readable = 1 since tun_active=1 and no backpressure */
    ASSERT_EQ(interest.tun_readable, 1);

    ASSERT_EQ(mqvpn_client_set_tun_active(c, 0, -1), MQVPN_OK);
    mqvpn_client_get_interest(c, &interest);
    ASSERT_EQ(interest.tun_readable, 0);

    mqvpn_client_destroy(c);
}

/* ── I/O feed null safety ── */

TEST(client_on_tun_packet_null)
{
    uint8_t pkt[] = {0x45, 0x00};
    ASSERT_EQ(mqvpn_client_on_tun_packet(NULL, pkt, 2), MQVPN_ERR_INVALID_ARG);
}

TEST(client_on_socket_recv_null)
{
    uint8_t pkt[] = {0x01};
    ASSERT_EQ(mqvpn_client_on_socket_recv(NULL, 1, pkt, 1, NULL, 0),
              MQVPN_ERR_INVALID_ARG);
}

/* ── Key generation ── */

TEST(generate_key)
{
    char buf[64];
    ASSERT_EQ(mqvpn_generate_key(buf, sizeof(buf)), MQVPN_OK);
    /* Should be 44 chars (base64 of 32 bytes) */
    ASSERT_EQ(strlen(buf), 44);

    /* Buffer too small */
    char small[10];
    ASSERT_EQ(mqvpn_generate_key(small, sizeof(small)), MQVPN_ERR_INVALID_ARG);

    /* NULL */
    ASSERT_EQ(mqvpn_generate_key(NULL, 64), MQVPN_ERR_INVALID_ARG);
}

/* ── Main ── */

int main(void)
{
    printf("test_api:\n");

    /* Config tests */
    run_config_new_free();
    run_config_free_null();
    run_config_set_server();
    run_config_set_auth_key();
    run_config_set_insecure();
    run_config_set_scheduler();
    run_config_set_log_level();
    run_config_set_reconnect();
    run_config_set_killswitch_hint();
    run_config_set_listen();
    run_config_set_subnet();
    run_config_set_tls_cert();
    run_config_set_max_clients();
    run_config_set_multipath();

    /* ABI tests */
    run_callbacks_abi_init();
    run_server_callbacks_abi_init();

    /* Error/version tests */
    run_error_string();
    run_version_string();

    /* Client lifecycle tests */
    run_client_new_null_args();
    run_client_new_missing_required_callbacks();
    run_client_new_abi_mismatch();
    run_client_destroy_null();

    /* State machine tests */
    run_client_new_creates_idle();
    run_client_connect_transitions_to_connecting();
    run_client_connect_from_invalid_state();
    run_client_disconnect_from_connecting();
    run_client_disconnect_from_idle();
    run_client_tick_null_safety();
    run_client_tick_ok();

    /* Query tests */
    run_client_get_state_null();
    run_client_get_stats();
    run_client_get_interest();

    /* Path management tests */
    run_client_add_path();
    run_path_initial_stats_zero();
    run_path_stats_after_recv();
    run_get_paths_null_safety();
    run_client_remove_path();
    run_client_add_path_max();

    /* TUN control tests */
    run_client_set_tun_active();

    /* I/O feed tests */
    run_client_on_tun_packet_null();
    run_client_on_socket_recv_null();

    /* Utility tests */
    run_generate_key();

    printf("\n  %d/%d tests passed\n", g_tests_passed, g_tests_run);
    return g_tests_passed == g_tests_run ? 0 : 1;
}
