// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_control_socket.c — unit tests for the control-API command dispatch
 * (src/platform/linux/control_socket.c::dispatch).
 *
 * Drives dispatch() end to end with the server-facing API mocked, covering
 * command routing, argument validation, error codes and the response JSON
 * (shape, escaping, the worst-case get_status size bound, the too-large
 * envelope) without sudo/netns.
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
static char g_last_add_name[64]; /* name the add_user stub last received */
static int g_remove_user_rc = MQVPN_OK;

static int g_list_users_n = 0;
static char g_list_users_names[MQVPN_MAX_USERS][64];

static int g_n_clients = 0;
static uint64_t g_uptime = 0;

static int g_client_info_n = 0;
static mqvpn_client_info_t g_client_info_tmpl;

static mqvpn_internal_client_reinject_t g_reinject_tmpl; /* configured per test */
static int g_reinject_n = 1;           /* copies the reinject getter returns */
static int g_sched_n = 1;              /* entries the sched getter returns */
static char g_sched_label[16] = "wlb"; /* scheduler name each entry carries */

static int g_fec_rc = 1;
static mqvpn_internal_fec_stats_t g_fec_tmpl;

static int g_all_fec_rc = 0;
static int g_all_fec_n = 0;

static int g_reorder_rc = 0;
static double g_reorder_p99 = 1.5;

/* ── Stubs for the server-facing API the handlers call ────────────────────── */

int
mqvpn_server_add_user(mqvpn_server_t *s, const char *u, const char *k)
{
    (void)s;
    (void)k;
    snprintf(g_last_add_name, sizeof(g_last_add_name), "%s", u);
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
    out->udp_tx_sends = 1234;
    out->udp_tx_datagrams = 5678;
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
mqvpn_server_get_client_reinject(const mqvpn_server_t *s,
                                 mqvpn_internal_client_reinject_t *out, int max)
{
    (void)s;
    int n = g_reinject_n < max ? g_reinject_n : max;
    for (int i = 0; i < n; i++)
        out[i] = g_reinject_tmpl;
    return n;
}

int
mqvpn_server_get_client_sched(const mqvpn_server_t *s, mqvpn_internal_client_sched_t *out,
                              int max)
{
    (void)s;
    if (g_sched_n < 0) return -1;
    int n = g_sched_n < max ? g_sched_n : max;
    for (int i = 0; i < n; i++)
        snprintf(out[i].scheduler, sizeof(out[i].scheduler), "%s", g_sched_label);
    return n;
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
    return g_reorder_p99;
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

/* Stand-in for the platform's transport getter (ctrl_rx_stats_fn). Non-zero
 * and unequal so a get_stats regression that hardcodes 0 or swaps the pair
 * cannot pass. */
static void
test_rx_stats(void *ctx, uint64_t *receives, uint64_t *datagrams)
{
    (void)ctx;
    *receives = 61;
    *datagrams = 83;
}

static void
call(const char *req)
{
    memset(g_resp, 0, sizeof(g_resp));
    /* Stack-built context: dispatch and the handlers only read ->server and
     * the RX-counter getter, never the libevent members. */
    ctrl_socket_t cs = {
        .server = (mqvpn_server_t *)&g_dummy_server,
        .rx_stats = test_rx_stats,
        .rx_ctx = NULL,
    };
    dispatch(req, g_resp, sizeof(g_resp) - 2, &cs);
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

/* A request whose first JSON value is not a complete object with a top-level
 * string "cmd" gets "missing cmd": truncated documents (incl. the EOF-closed
 * {"cmd":"add_user" of e2e D5a), a non-object root, a cmd only in a nested
 * object, a non-string cmd, and empty input. */
static void
test_missing_cmd_variants(void)
{
    static const char *reqs[] = {
        "{\"cmd\":",     "{\"cmd\":\"add_user\"",
        "[1]",           "{\"x\":{\"cmd\":\"get_stats\"}}",
        "{\"cmd\":123}", "",
        "  \n",
    };
    for (size_t i = 0; i < sizeof(reqs) / sizeof(reqs[0]); i++) {
        call(reqs[i]);
        CHECK_EQ_STR("{\"ok\":false,\"error\":\"missing cmd\"}");
    }
}

static void
test_duplicate_cmd_first_wins(void)
{
    call("{\"cmd\":\"get_stats\",\"cmd\":\"list_users\"}");
    CHECK_HAS("\"bytes_tx\":111");
}

/* Bytes after the first complete object (same read as the request) are
 * ignored, matching the brace framing in ctrl_on_read(). */
static void
test_trailing_bytes_ignored(void)
{
    call("{\"cmd\":\"get_stats\"} junk");
    CHECK_HAS("\"bytes_tx\":111");
    call("{\"cmd\":\"get_stats\"}\n");
    CHECK_HAS("\"bytes_tx\":111");
}

static void
test_escaped_cmd_decoded(void)
{
    call("{\"cmd\":\"get\\u005fstats\"}");
    CHECK_HAS("\"bytes_tx\":111");
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

/* The handler passes the decoded name, cut to name[64] (63 bytes). */
static void
test_add_user_name_decoded_and_truncated(void)
{
    g_add_user_rc = MQVPN_OK;
    call("{\"cmd\":\"add_user\",\"name\":\"a}b\\\"c\",\"key\":\"k\"}");
    CHECK_EQ_STR("{\"ok\":true}");
    CHECK(strcmp(g_last_add_name, "a}b\"c") == 0);

    char name[101];
    char req[192];
    memset(name, 'n', 100);
    name[100] = '\0';
    snprintf(req, sizeof(req), "{\"cmd\":\"add_user\",\"name\":\"%s\",\"key\":\"k\"}",
             name);
    call(req);
    CHECK_EQ_STR("{\"ok\":true}");
    CHECK(strlen(g_last_add_name) == 63);
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
    /* Offload counters reach the JSON from BOTH sources: udp_tx_* through
     * mqvpn_stats_t (the library issues those sends), udp_rx_* from the
     * platform's transport getter (RX offload never crosses the library ABI).
     * The get_stats body is a hand-written field-by-field list, so a new
     * mqvpn_stats_t field silently reads 0 here unless it is added in both
     * places — that is exactly the failure this pins. */
    CHECK_HAS("\"udp_tx_sends\":1234");
    CHECK_HAS("\"udp_tx_datagrams\":5678");
    CHECK_HAS("\"udp_rx_receives\":61");
    CHECK_HAS("\"udp_rx_datagrams\":83");
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
    memset(&g_reinject_tmpl, 0, sizeof(g_reinject_tmpl));

    call("{\"cmd\":\"get_status\"}");
    CHECK_HAS("\"n_clients\":1");
    CHECK_HAS("\"user\":\"alice\"");
    CHECK_HAS("\"endpoint\":\"1.2.3.4:443\"");
    CHECK_HAS("\"path_id\":7");
    CHECK_HAS("\"state_label\":\"active\"");
    CHECK_HAS("\"endpoint\":\"1.2.3.4:443\",\"scheduler\":\"wlb\"");
}

/* Sched getter shorter than the client list (or failing): unknown. */
static void
test_get_status_scheduler_missing(void)
{
    memset(&g_client_info_tmpl, 0, sizeof(g_client_info_tmpl));
    strcpy(g_client_info_tmpl.username, "alice");
    strcpy(g_client_info_tmpl.endpoint, "1.2.3.4:443");
    g_client_info_n = 1;
    for (int n = 0; n >= -1; n--) {
        g_sched_n = n;
        call("{\"cmd\":\"get_status\"}");
        CHECK_HAS("\"scheduler\":\"unknown\"");
    }
    g_sched_n = 1;
}

/* Alignment semantics (a): a reinject snapshot entry whose path_id matches
 * the client-info path emits its nonzero value. */
static void
test_get_status_reinject_matched_path_id(void)
{
    memset(&g_client_info_tmpl, 0, sizeof(g_client_info_tmpl));
    strcpy(g_client_info_tmpl.username, "alice");
    strcpy(g_client_info_tmpl.endpoint, "1.2.3.4:443");
    g_client_info_tmpl.n_paths = 1;
    g_client_info_tmpl.paths[0].path_id = 7;
    g_client_info_tmpl.paths[0].state = 2;
    g_client_info_n = 1;

    memset(&g_reinject_tmpl, 0, sizeof(g_reinject_tmpl));
    g_reinject_tmpl.n_paths = 1;
    g_reinject_tmpl.paths[0].path_id = 7;
    g_reinject_tmpl.paths[0].reinject_tx_bytes = 99999;

    call("{\"cmd\":\"get_status\"}");
    CHECK_HAS("\"path_id\":7");
    CHECK_HAS("\"reinject_tx_bytes\":99999");
}

/* Alignment semantics (b): a mismatched or wholly absent path_id in the
 * reinject snapshot both emit "reinject_tx_bytes":0 — the field is always
 * present so the JSON shape stays constant regardless of match. Two phases
 * pin the same constant-shape outcome from two different snapshot states. */
static void
test_get_status_reinject_mismatched_path_id(void)
{
    memset(&g_client_info_tmpl, 0, sizeof(g_client_info_tmpl));
    strcpy(g_client_info_tmpl.username, "alice");
    strcpy(g_client_info_tmpl.endpoint, "1.2.3.4:443");
    g_client_info_tmpl.n_paths = 1;
    g_client_info_tmpl.paths[0].path_id = 7;
    g_client_info_tmpl.paths[0].state = 2;
    g_client_info_n = 1;

    /* Phase 1: reinject snapshot has an entry, but its path_id mismatches. */
    memset(&g_reinject_tmpl, 0, sizeof(g_reinject_tmpl));
    g_reinject_tmpl.n_paths = 1;
    g_reinject_tmpl.paths[0].path_id = 42; /* mismatch vs client path_id 7 */
    g_reinject_tmpl.paths[0].reinject_tx_bytes = 99999;

    call("{\"cmd\":\"get_status\"}");
    CHECK_HAS("\"path_id\":7");
    CHECK_HAS("\"reinject_tx_bytes\":0");

    /* Phase 2: reinject snapshot has no entry at all (n_paths == 0). */
    memset(&g_reinject_tmpl, 0, sizeof(g_reinject_tmpl)); /* n_paths = 0 */

    call("{\"cmd\":\"get_status\"}");
    CHECK_HAS("\"path_id\":7");
    CHECK_HAS("\"reinject_tx_bytes\":0");
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

/* ── Response encoding ────────────────────────────────────────────────────── */

/* g_resp as one JSON document (invalid UTF-8 accepted: the server passes name
 * bytes through), or NULL. Free with yyjson_doc_free. */
static yyjson_doc *
parse_resp(void)
{
    return yyjson_read(g_resp, strlen(g_resp), YYJSON_READ_ALLOW_INVALID_UNICODE);
}

static void
test_response_strings_escaped(void)
{
    g_list_users_n = 1;
    strcpy(g_list_users_names[0], "a\"b\\c");
    call("{\"cmd\":\"list_users\"}");
    CHECK_EQ_STR("{\"ok\":true,\"users\":[\"a\\\"b\\\\c\"]}");
    yyjson_doc *d = parse_resp();
    yyjson_val *root = yyjson_doc_get_root(d);
    CHECK(yyjson_equals_str(yyjson_arr_get(yyjson_obj_get(root, "users"), 0), "a\"b\\c"));
    yyjson_doc_free(d);

    memset(&g_client_info_tmpl, 0, sizeof(g_client_info_tmpl));
    strcpy(g_client_info_tmpl.username, "alice");
    strcpy(g_client_info_tmpl.endpoint, "1.2.3.4:5\"\\");
    g_client_info_n = 1;
    call("{\"cmd\":\"get_status\"}");
    d = parse_resp();
    root = yyjson_doc_get_root(d);
    yyjson_val *c0 = yyjson_arr_get(yyjson_obj_get(root, "clients"), 0);
    CHECK(yyjson_equals_str(yyjson_obj_get(c0, "endpoint"), "1.2.3.4:5\"\\"));
    yyjson_doc_free(d);

    seed_fec_tmpl();
    g_fec_rc = 1;
    call("{\"cmd\":\"get_fec_stats\",\"user\":\"x\\\"y\"}");
    d = parse_resp();
    CHECK(yyjson_equals_str(yyjson_obj_get(yyjson_doc_get_root(d), "user"), "x\"y"));
    yyjson_doc_free(d);
}

/* A name cut mid-character by name[64] is passed through byte for byte, not
 * turned into an error envelope for the whole list. */
static void
test_response_invalid_utf8_passthrough(void)
{
    char name[64];
    memset(name, 'a', 62);
    name[62] = '\xC3'; /* first byte of a 2-byte UTF-8 sequence */
    name[63] = '\0';
    g_list_users_n = 1;
    memcpy(g_list_users_names[0], name, sizeof(name));
    call("{\"cmd\":\"list_users\"}");
    CHECK_HAS("\"ok\":true");
    CHECK(strstr(g_resp, name) != NULL);
    yyjson_doc *d = parse_resp();
    yyjson_val *u0 = yyjson_arr_get(yyjson_obj_get(yyjson_doc_get_root(d), "users"), 0);
    CHECK(yyjson_get_len(u0) == 63 && memcmp(yyjson_get_str(u0), name, 63) == 0);
    yyjson_doc_free(d);
}

/* added_latency_*_ms keep at most 3 decimals; compared as a value, not text. */
static void
test_reorder_stats_fixed3(void)
{
    g_reorder_rc = 0;
    g_reorder_p99 = 1.23456;
    call("{\"cmd\":\"get_reorder_stats\"}");
    yyjson_doc *d = parse_resp();
    yyjson_val *reorder = yyjson_obj_get(yyjson_doc_get_root(d), "reorder");
    yyjson_val *p99 = yyjson_obj_get(reorder, "added_latency_p99_ms");
    CHECK(yyjson_is_real(p99) && yyjson_get_real(p99) == 1.235);
    yyjson_doc_free(d);
}

/* MQVPN_MAX_USERS clients x MQVPN_MAX_PATHS paths, every number at its widest
 * and every string at its longest. */
static void
seed_worst_case(void)
{
    memset(&g_client_info_tmpl, 0, sizeof(g_client_info_tmpl));
    memset(g_client_info_tmpl.username, 'u', 63);
    memset(g_client_info_tmpl.endpoint, 'e', 63);
    g_client_info_tmpl.connected_at_us = UINT64_MAX;
    g_client_info_tmpl.bytes_tx = UINT64_MAX;
    g_client_info_tmpl.bytes_rx = UINT64_MAX;
    g_client_info_tmpl.n_paths = MQVPN_MAX_PATHS;
    memset(&g_reinject_tmpl, 0, sizeof(g_reinject_tmpl));
    g_reinject_tmpl.n_paths = MQVPN_MAX_PATHS;
    for (int p = 0; p < MQVPN_MAX_PATHS; p++) {
        mqvpn_path_stats_t *ps = &g_client_info_tmpl.paths[p];
        ps->path_id = (uint64_t)p;
        ps->srtt_us = ps->min_rtt_us = ps->cwnd = ps->bytes_in_flight = UINT64_MAX;
        ps->bytes_tx = ps->bytes_rx = UINT64_MAX;
        ps->pkt_sent = ps->pkt_recv = ps->pkt_lost = UINT64_MAX;
        ps->state = UINT8_MAX; /* 3 digits, and the stub's longer label */
        g_reinject_tmpl.paths[p].path_id = (uint64_t)p;
        g_reinject_tmpl.paths[p].reinject_tx_bytes = UINT64_MAX;
    }
    g_client_info_n = MQVPN_MAX_USERS;
    g_reinject_n = MQVPN_MAX_USERS;
    g_sched_n = MQVPN_MAX_USERS;
    memset(g_sched_label, 's', 15);
    g_sched_label[15] = '\0';
}

static void
test_get_status_worst_case_fits(void)
{
    seed_worst_case();
    call("{\"cmd\":\"get_status\"}");
    CHECK_HAS("\"ok\":true");
    CHECK(strlen(g_resp) < CTRL_MAX_RESP_BYTES - 2);
    printf("worst-case get_status: %zu bytes (limit %d)\n", strlen(g_resp),
           CTRL_MAX_RESP_BYTES - 2);

    yyjson_doc *d = parse_resp();
    yyjson_val *root = yyjson_doc_get_root(d);
    CHECK(yyjson_get_int(yyjson_obj_get(root, "n_clients")) == MQVPN_MAX_USERS);
    yyjson_val *last =
        yyjson_arr_get(yyjson_obj_get(root, "clients"), MQVPN_MAX_USERS - 1);
    yyjson_val *paths = yyjson_obj_get(last, "paths");
    for (int p = 0; p < MQVPN_MAX_PATHS; p++) {
        yyjson_val *rb =
            yyjson_obj_get(yyjson_arr_get(paths, (size_t)p), "reinject_tx_bytes");
        CHECK(yyjson_is_uint(rb) && yyjson_get_uint(rb) == UINT64_MAX);
    }
    yyjson_doc_free(d);
}

/* A response that does not fit resp_len is the fixed envelope, never a cut
 * JSON prefix. */
static void
test_get_status_too_large_envelope(void)
{
    seed_worst_case();
    char small[64];
    ctrl_socket_t cs = {
        .server = (mqvpn_server_t *)&g_dummy_server,
        .rx_stats = test_rx_stats,
        .rx_ctx = NULL,
    };
    dispatch("{\"cmd\":\"get_status\"}", small, sizeof(small), &cs);
    CHECK(strcmp(small, "{\"ok\":false,\"error\":\"response too large\"}") == 0);
}

/* Byte-exact fixed-shape replies (OMR clients parse these). */
static void
test_exact_shapes(void)
{
    g_add_user_rc = MQVPN_OK;
    call("{\"cmd\":\"add_user\",\"name\":\"alice\",\"key\":\"secret\"}");
    CHECK_EQ_STR("{\"ok\":true}");

    call("{\"cmd\":\"remove_user\"}");
    CHECK_EQ_STR("{\"ok\":false,\"error\":\"name required\"}");

#ifdef XQC_ENABLE_FEC
    const int fec_enabled = 1;
#else
    const int fec_enabled = 0;
#endif
    char want[128];
    snprintf(want, sizeof(want),
             "{\"ok\":true,\"version\":\"%s\",\"scheduler\":\"%s\",\"fec_enabled\":%d}",
             mqvpn_version_string(), mqvpn_server_scheduler_label(NULL), fec_enabled);
    call("{\"cmd\":\"get_build_info\"}");
    CHECK_EQ_STR(want);
}

int
main(void)
{
    test_missing_cmd();
    test_unknown_cmd();
    test_missing_cmd_variants();
    test_duplicate_cmd_first_wins();
    test_trailing_bytes_ignored();
    test_escaped_cmd_decoded();

    test_add_user_success();
    test_add_user_missing_name();
    test_add_user_missing_key();
    test_add_user_server_failure();
    test_add_user_name_decoded_and_truncated();

    test_remove_user_success();
    test_remove_user_missing_name();
    test_remove_user_not_found();

    test_list_users_empty();
    test_list_users_two_entries();

    test_get_stats();

    test_get_status_empty();
    test_get_status_one_client_with_path();
    test_get_status_scheduler_missing();
    test_get_status_reinject_matched_path_id();
    test_get_status_reinject_mismatched_path_id();

    test_get_build_info();

    test_get_fec_stats_missing_user();
    test_get_fec_stats_user_not_found();
    test_get_fec_stats_not_built();
    test_get_fec_stats_success();

    test_get_all_fec_stats();
    test_get_all_fec_stats_not_built();

    test_get_reorder_stats();
    test_get_reorder_stats_internal_error();

    test_response_strings_escaped();
    test_response_invalid_utf8_passthrough();
    test_reorder_stats_fixed3();
    test_get_status_worst_case_fits();
    test_get_status_too_large_envelope();
    test_exact_shapes();

    if (g_failed) {
        fprintf(stderr, "test_control_socket: %d CHECK(s) FAILED\n", g_failed);
        return 1;
    }
    printf("test_control_socket: all OK\n");
    return 0;
}
