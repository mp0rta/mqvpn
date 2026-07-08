// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_control_socket.c — unit tests for the control-API command dispatch
 * (src/platform/linux/control_socket.c::dispatch).
 *
 * dispatch()'s command routing, argument validation, error codes, and response
 * JSON shape had no unit-level test — test_control_response_bound.c only checks
 * the worst-case get_status buffer bound and never calls dispatch(). This test
 * drives dispatch() end to end with the server-facing API mocked, covering
 * handler logic (missing-arg handling, failure propagation, JSON shape) without
 * sudo/netns.
 *
 * dispatch() is static, so — following the test_reorder_rx / test_tcp_lane
 * idiom — this file #include's the .c directly and satisfies the mqvpn_server_*
 * / mqvpn_* symbols the handlers call with configurable stubs (no mqvpn_server.c
 * linked). Uses an always-active CHECK (not assert()) so a Release build cannot
 * no-op the assertions.
 */

#include "libmqvpn.h"
#include "mqvpn_internal.h" /* mqvpn_internal_fec_stats_t / _entry_t, reorder.h */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ── Configurable stub state ──────────────────────────────────────────────── */

static int g_add_user_rc = MQVPN_OK;
static int g_remove_user_rc = MQVPN_OK;

static int g_list_users_n = 0;
static char g_list_users_names[MQVPN_MAX_USERS][64];

static int g_n_clients = 0;
static uint64_t g_uptime = 0;

static int g_client_info_n = 0;
static mqvpn_client_info_t g_client_info_tmpl;

static int g_fec_rc = 1;
static mqvpn_internal_fec_stats_t g_fec_tmpl;

static int g_all_fec_rc = 0;
static int g_all_fec_n = 0;

static int g_reorder_rc = 0;

/* ── Stubs for the server-facing API the handlers call ────────────────────── */

int
mqvpn_server_add_user(mqvpn_server_t *s, const char *u, const char *k)
{
    (void)s;
    (void)u;
    (void)k;
    return g_add_user_rc;
}

int
mqvpn_server_remove_user(mqvpn_server_t *s, const char *u)
{
    (void)s;
    (void)u;
    return g_remove_user_rc;
}

int
mqvpn_server_list_users(const mqvpn_server_t *s, char names[][64], int max)
{
    (void)s;
    int n = g_list_users_n < max ? g_list_users_n : max;
    for (int i = 0; i < n; i++) {
        strncpy(names[i], g_list_users_names[i], 63);
        names[i][63] = '\0';
    }
    return n;
}

int
mqvpn_server_get_stats(const mqvpn_server_t *s, mqvpn_stats_t *out)
{
    (void)s;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->bytes_tx = 111;
    out->tcp_flows_total = 7;
    return 0;
}

int
mqvpn_server_get_n_clients(const mqvpn_server_t *s)
{
    (void)s;
    return g_n_clients;
}

uint64_t
mqvpn_server_uptime_seconds(const mqvpn_server_t *s)
{
    (void)s;
    return g_uptime;
}

int
mqvpn_server_get_client_info(const mqvpn_server_t *s, mqvpn_client_info_t *out,
                             int max_clients, int *n_clients)
{
    (void)s;
    int n = g_client_info_n < max_clients ? g_client_info_n : max_clients;
    for (int i = 0; i < n; i++)
        out[i] = g_client_info_tmpl;
    *n_clients = n;
    return 0;
}

const char *
mqvpn_server_scheduler_label(const mqvpn_server_t *s)
{
    (void)s;
    return "wlb";
}

const char *
mqvpn_path_state_label(int state)
{
    return state == 2 ? "active" : "validating";
}

const char *
mqvpn_version_string(void)
{
    return "9.9.9-test";
}

int
mqvpn_server_get_client_fec_stats(const mqvpn_server_t *s, const char *user,
                                  mqvpn_internal_fec_stats_t *out)
{
    (void)s;
    (void)user;
    if (g_fec_rc == 1) *out = g_fec_tmpl;
    return g_fec_rc;
}

int
mqvpn_server_get_all_fec_stats(const mqvpn_server_t *s, mqvpn_internal_fec_entry_t *out,
                               int max)
{
    (void)s;
    if (g_all_fec_rc < 0) return -1;
    int n = g_all_fec_n < max ? g_all_fec_n : max;
    for (int i = 0; i < n; i++) {
        snprintf(out[i].user, sizeof(out[i].user), "user%d", i);
        out[i].stats = g_fec_tmpl;
    }
    return n;
}

int
mqvpn_server_get_reorder_stats(const mqvpn_server_t *s, mqvpn_reorder_stats_t *out)
{
    (void)s;
    memset(out, 0, sizeof(*out));
    out->delivered_count = 55;
    return g_reorder_rc;
}

double
mqvpn_reorder_latency_percentile(const mqvpn_reorder_stats_t *st, double q)
{
    (void)st;
    (void)q;
    return 1.5;
}

double
mqvpn_reorder_latency_buffered_percentile(const mqvpn_reorder_stats_t *st, double q)
{
    (void)st;
    (void)q;
    return 2.5;
}

/* Pull in dispatch() + the command handlers (all static). */
#include "control_socket.c"

/* ── Harness ──────────────────────────────────────────────────────────────── */

static int g_failed = 0;
static char g_resp[CTRL_MAX_RESP_BYTES];
static int g_dummy_server; /* opaque sentinel — stubs never dereference it */

#define CHECK(cond)                                                         \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            g_failed++;                                                     \
        }                                                                   \
    } while (0)

/* CHECK a substring is present, printing the actual response on mismatch. */
#define CHECK_HAS(needle)                                                       \
    do {                                                                        \
        if (strstr(g_resp, (needle)) == NULL) {                                 \
            fprintf(stderr, "FAIL %s:%d: response missing \"%s\"\n  got: %s\n", \
                    __FILE__, __LINE__, (needle), g_resp);                      \
            g_failed++;                                                         \
        }                                                                       \
    } while (0)

#define CHECK_EQ_STR(expected)                                                       \
    do {                                                                             \
        if (strcmp(g_resp, (expected)) != 0) {                                       \
            fprintf(stderr, "FAIL %s:%d: response != \"%s\"\n  got: %s\n", __FILE__, \
                    __LINE__, (expected), g_resp);                                   \
            g_failed++;                                                              \
        }                                                                            \
    } while (0)

static void
call(const char *req)
{
    memset(g_resp, 0, sizeof(g_resp));
    dispatch(req, g_resp, sizeof(g_resp) - 2, (mqvpn_server_t *)&g_dummy_server);
}

/* ── Envelope / routing ───────────────────────────────────────────────────── */

static void
test_missing_cmd(void)
{
    call("{}");
    CHECK_EQ_STR("{\"ok\":false,\"error\":\"missing cmd\"}");
}

static void
test_unknown_cmd(void)
{
    call("{\"cmd\":\"frobnicate\"}");
    CHECK_EQ_STR("{\"ok\":false,\"error\":\"unknown cmd\"}");
}

/* ── add_user ─────────────────────────────────────────────────────────────── */

static void
test_add_user_success(void)
{
    g_add_user_rc = MQVPN_OK;
    call("{\"cmd\":\"add_user\",\"name\":\"alice\",\"key\":\"secret\"}");
    CHECK_EQ_STR("{\"ok\":true}");
}

static void
test_add_user_missing_name(void)
{
    call("{\"cmd\":\"add_user\",\"key\":\"secret\"}");
    CHECK_HAS("name and key required");
}

static void
test_add_user_missing_key(void)
{
    call("{\"cmd\":\"add_user\",\"name\":\"alice\"}");
    CHECK_HAS("name and key required");
}

static void
test_add_user_server_failure(void)
{
    g_add_user_rc = -5;
    call("{\"cmd\":\"add_user\",\"name\":\"alice\",\"key\":\"secret\"}");
    CHECK_HAS("add_user failed (-5)");
}

/* ── remove_user ──────────────────────────────────────────────────────────── */

static void
test_remove_user_success(void)
{
    g_remove_user_rc = MQVPN_OK;
    call("{\"cmd\":\"remove_user\",\"name\":\"alice\"}");
    CHECK_EQ_STR("{\"ok\":true}");
}

static void
test_remove_user_missing_name(void)
{
    call("{\"cmd\":\"remove_user\"}");
    CHECK_HAS("name required");
}

static void
test_remove_user_not_found(void)
{
    g_remove_user_rc = -1;
    call("{\"cmd\":\"remove_user\",\"name\":\"ghost\"}");
    CHECK_HAS("user not found");
}

/* ── list_users ───────────────────────────────────────────────────────────── */

static void
test_list_users_empty(void)
{
    g_list_users_n = 0;
    call("{\"cmd\":\"list_users\"}");
    CHECK_EQ_STR("{\"ok\":true,\"users\":[]}");
}

static void
test_list_users_two_entries(void)
{
    g_list_users_n = 2;
    strcpy(g_list_users_names[0], "alice");
    strcpy(g_list_users_names[1], "bob");
    call("{\"cmd\":\"list_users\"}");
    CHECK_EQ_STR("{\"ok\":true,\"users\":[\"alice\",\"bob\"]}");
}

/* ── get_stats ────────────────────────────────────────────────────────────── */

static void
test_get_stats(void)
{
    g_n_clients = 3;
    g_uptime = 4242;
    call("{\"cmd\":\"get_stats\"}");
    CHECK_HAS("\"ok\":true");
    CHECK_HAS("\"n_clients\":3");
    CHECK_HAS("\"bytes_tx\":111");
    CHECK_HAS("\"tcp_flows_total\":7");
    CHECK_HAS("\"uptime_sec\":4242");
}

/* ── get_status ───────────────────────────────────────────────────────────── */

static void
test_get_status_empty(void)
{
    g_client_info_n = 0;
    call("{\"cmd\":\"get_status\"}");
    CHECK_EQ_STR("{\"ok\":true,\"n_clients\":0,\"clients\":[]}");
}

static void
test_get_status_one_client_with_path(void)
{
    memset(&g_client_info_tmpl, 0, sizeof(g_client_info_tmpl));
    strcpy(g_client_info_tmpl.username, "alice");
    strcpy(g_client_info_tmpl.endpoint, "1.2.3.4:443");
    g_client_info_tmpl.n_paths = 1;
    g_client_info_tmpl.paths[0].path_id = 7;
    g_client_info_tmpl.paths[0].state = 2; /* -> "active" */
    g_client_info_n = 1;

    call("{\"cmd\":\"get_status\"}");
    CHECK_HAS("\"n_clients\":1");
    CHECK_HAS("\"user\":\"alice\"");
    CHECK_HAS("\"endpoint\":\"1.2.3.4:443\"");
    CHECK_HAS("\"path_id\":7");
    CHECK_HAS("\"state_label\":\"active\"");
}

/* ── get_build_info ───────────────────────────────────────────────────────── */

static void
test_get_build_info(void)
{
    call("{\"cmd\":\"get_build_info\"}");
    CHECK_HAS("\"version\":\"9.9.9-test\"");
    CHECK_HAS("\"scheduler\":\"wlb\"");
    CHECK_HAS("\"fec_enabled\":");
}

/* ── get_fec_stats ────────────────────────────────────────────────────────── */

static void
seed_fec_tmpl(void)
{
    memset(&g_fec_tmpl, 0, sizeof(g_fec_tmpl));
    g_fec_tmpl.enable_fec = 1;
    g_fec_tmpl.mp_state = 1;
    g_fec_tmpl.mp_state_label = "active_with_standby";
    g_fec_tmpl.fec_send_cnt = 142;
    g_fec_tmpl.fec_recover_cnt = 17;
}

static void
test_get_fec_stats_missing_user(void)
{
    call("{\"cmd\":\"get_fec_stats\"}");
    CHECK_HAS("user required");
}

static void
test_get_fec_stats_user_not_found(void)
{
    g_fec_rc = 0;
    call("{\"cmd\":\"get_fec_stats\",\"user\":\"ghost\"}");
    CHECK_HAS("user not found");
}

static void
test_get_fec_stats_not_built(void)
{
    g_fec_rc = -1;
    call("{\"cmd\":\"get_fec_stats\",\"user\":\"alice\"}");
    CHECK_HAS("fec not built");
}

static void
test_get_fec_stats_success(void)
{
    seed_fec_tmpl();
    g_fec_rc = 1;
    call("{\"cmd\":\"get_fec_stats\",\"user\":\"alice\"}");
    CHECK_HAS("\"user\":\"alice\"");
    CHECK_HAS("\"mp_state_label\":\"active_with_standby\"");
    CHECK_HAS("\"fec_send_cnt\":142");
    CHECK_HAS("\"fec_recover_cnt\":17");
}

/* ── get_all_fec_stats ────────────────────────────────────────────────────── */

static void
test_get_all_fec_stats(void)
{
    seed_fec_tmpl();
    g_all_fec_rc = 0;
    g_all_fec_n = 2;
    call("{\"cmd\":\"get_all_fec_stats\"}");
    CHECK_HAS("\"n_clients\":2");
    CHECK_HAS("\"user\":\"user0\"");
    CHECK_HAS("\"user\":\"user1\"");
    CHECK_HAS("\"mp_state_label\":\"active_with_standby\"");
}

static void
test_get_all_fec_stats_not_built(void)
{
    g_all_fec_rc = -1;
    call("{\"cmd\":\"get_all_fec_stats\"}");
    CHECK_HAS("fec not built");
}

/* ── get_reorder_stats ────────────────────────────────────────────────────── */

static void
test_get_reorder_stats(void)
{
    g_reorder_rc = 0;
    call("{\"cmd\":\"get_reorder_stats\"}");
    CHECK_HAS("\"reorder\":{");
    CHECK_HAS("\"delivered_count\":55");
    CHECK_HAS("\"added_latency_p99_ms\":");
}

static void
test_get_reorder_stats_internal_error(void)
{
    /* Failure-branch parity with get_fec_stats / get_all_fec_stats: a negative
     * getter return must surface {"error":"internal error"}, not a malformed
     * or half-built reorder object. */
    g_reorder_rc = -1;
    call("{\"cmd\":\"get_reorder_stats\"}");
    CHECK_HAS("\"ok\":false");
    CHECK_HAS("internal error");
}

int
main(void)
{
    test_missing_cmd();
    test_unknown_cmd();

    test_add_user_success();
    test_add_user_missing_name();
    test_add_user_missing_key();
    test_add_user_server_failure();

    test_remove_user_success();
    test_remove_user_missing_name();
    test_remove_user_not_found();

    test_list_users_empty();
    test_list_users_two_entries();

    test_get_stats();

    test_get_status_empty();
    test_get_status_one_client_with_path();

    test_get_build_info();

    test_get_fec_stats_missing_user();
    test_get_fec_stats_user_not_found();
    test_get_fec_stats_not_built();
    test_get_fec_stats_success();

    test_get_all_fec_stats();
    test_get_all_fec_stats_not_built();

    test_get_reorder_stats();
    test_get_reorder_stats_internal_error();

    if (g_failed) {
        fprintf(stderr, "test_control_socket: %d CHECK(s) FAILED\n", g_failed);
        return 1;
    }
    printf("test_control_socket: all OK\n");
    return 0;
}
