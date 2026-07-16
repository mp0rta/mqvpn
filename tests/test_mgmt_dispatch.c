// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_mgmt_dispatch.c — unit tests for the CMP request dispatcher
 * (src/mgmt/mgmt_dispatch.c): handshake gating, system.* methods, and
 * malformed-input / overflow safety.
 *
 * Uses an always-active CHECK (not assert()) so a Release / -DNDEBUG build
 * cannot silently no-op the assertions (see AGENTS.md: build.sh forces
 * CMAKE_BUILD_TYPE=Release which defines NDEBUG).
 */

#include "cmp_error.h"
#include "cmp_types.h"
#include "mgmt_dispatch.h"

#include <stdio.h>
#include <string.h>

static int g_failed = 0;

#define CHECK(cond)                                                         \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            g_failed++;                                                     \
        }                                                                   \
    } while (0)

#define TEST_ENDPOINT_VERSION "0.12.0-test"

static const char *const g_no_caps[1] = {NULL}; /* unused, n_capabilities==0 */

static mgmt_ctx_t
make_ctx(void)
{
    mgmt_ctx_t ctx;
    ctx.endpoint_version = TEST_ENDPOINT_VERSION;
    ctx.capabilities = g_no_caps;
    ctx.n_capabilities = 0;
    return ctx;
}

static mgmt_conn_t
make_conn(void)
{
    mgmt_conn_t conn;
    conn.handshake_done = 0;
    return conn;
}

/* Runs mgmt_dispatch_request into a CMP_MAX_RESPONSE_BYTES-sized scratch
 * buffer (the normal-caller size) and returns its return value (the
 * response's cmp_error_code_t; CMP_E_OK for ok:true responses). `out` must
 * be at least that large. */
static int
dispatch(const mgmt_ctx_t *ctx, mgmt_conn_t *conn, const char *line, char *out,
         size_t out_cap)
{
    return mgmt_dispatch_request(ctx, conn, line, strlen(line), out, out_cap);
}

/* ── helpers to sanity-check the envelope shape ── */

static int
has_substr(const char *hay, const char *needle)
{
    return strstr(hay, needle) != NULL;
}

static void
check_single_trailing_lf(const char *resp)
{
    size_t n = strlen(resp);
    CHECK(n > 0);
    CHECK(n > 0 && resp[n - 1] == '\n');
    /* no other raw LF anywhere, including at the very end counted once */
    size_t lf_count = 0;
    for (size_t i = 0; i < n; i++) {
        if (resp[i] == '\n') lf_count++;
    }
    CHECK(lf_count == 1);
}

/* ── A. hello success ── */
static void
test_hello_success(void)
{
    mgmt_ctx_t ctx = make_ctx();
    mgmt_conn_t conn = make_conn();
    char out[CMP_MAX_RESPONSE_BYTES];

    int rc = dispatch(&ctx, &conn,
                      "{\"id\":1,\"protocol\":\"1.0\",\"method\":\"system.hello\","
                      "\"params\":{\"client_name\":\"t\",\"client_version\":\"0\","
                      "\"supported_protocols\":[\"1.0\"]}}",
                      out, sizeof(out));

    CHECK(rc == (int)CMP_E_OK);
    CHECK(has_substr(out, "\"ok\":true"));
    CHECK(has_substr(out, "\"protocol\":\"1.0\""));
    CHECK(has_substr(out, "\"endpoint_name\":\"mqvpn-client\""));
    CHECK(has_substr(out, "\"selected_protocol\":\"1.0\""));
    CHECK(has_substr(out, "\"capabilities\":[]"));
    CHECK(has_substr(out, "\"id\":1"));
    CHECK(conn.handshake_done == 1);
    check_single_trailing_lf(out);
}

/* ── B. system.version before hello ── */
static void
test_version_before_hello_requires_handshake(void)
{
    mgmt_ctx_t ctx = make_ctx();
    mgmt_conn_t conn = make_conn();
    char out[CMP_MAX_RESPONSE_BYTES];

    dispatch(
        &ctx, &conn,
        "{\"id\":2,\"protocol\":\"1.0\",\"method\":\"system.version\",\"params\":{}}",
        out, sizeof(out));

    CHECK(has_substr(out, "\"ok\":false"));
    CHECK(has_substr(out, "\"protocol\":\"1.0\""));
    CHECK(has_substr(out, "\"code\":\"MQVPN_CLIENT_HANDSHAKE_REQUIRED\""));
    CHECK(has_substr(out, "\"retryable\":false"));
    CHECK(conn.handshake_done == 0);
    check_single_trailing_lf(out);
}

/* ── C. incompatible protocol list ── */
static void
test_hello_incompatible_protocol(void)
{
    mgmt_ctx_t ctx = make_ctx();
    mgmt_conn_t conn = make_conn();
    char out[CMP_MAX_RESPONSE_BYTES];

    dispatch(&ctx, &conn,
             "{\"id\":3,\"protocol\":\"1.0\",\"method\":\"system.hello\","
             "\"params\":{\"supported_protocols\":[\"2.0\"]}}",
             out, sizeof(out));

    CHECK(has_substr(out, "\"ok\":false"));
    CHECK(has_substr(out, "\"protocol\":\"1.0\""));
    CHECK(has_substr(out, "\"code\":\"MQVPN_CLIENT_PROTOCOL_INCOMPATIBLE\""));
    CHECK(has_substr(out, "\"retryable\":false"));
    CHECK(has_substr(out, "\"details\""));
    CHECK(has_substr(out, "\"supported_protocols\":[\"1.0\"]"));
    CHECK(conn.handshake_done == 0);
    check_single_trailing_lf(out);
}

/* ── D. duplicate hello after success is idempotent ── */
static void
test_duplicate_hello_idempotent(void)
{
    mgmt_ctx_t ctx = make_ctx();
    mgmt_conn_t conn = make_conn();
    char out[CMP_MAX_RESPONSE_BYTES];
    const char *hello_req = "{\"id\":1,\"protocol\":\"1.0\",\"method\":\"system.hello\","
                            "\"params\":{\"supported_protocols\":[\"1.0\"]}}";

    dispatch(&ctx, &conn, hello_req, out, sizeof(out));
    CHECK(has_substr(out, "\"ok\":true"));
    CHECK(conn.handshake_done == 1);

    dispatch(&ctx, &conn, hello_req, out, sizeof(out));
    CHECK(has_substr(out, "\"ok\":true"));
    CHECK(conn.handshake_done == 1);
    check_single_trailing_lf(out);
}

/* ── E. version after hello ── */
static void
test_version_after_hello(void)
{
    mgmt_ctx_t ctx = make_ctx();
    mgmt_conn_t conn = make_conn();
    char out[CMP_MAX_RESPONSE_BYTES];

    dispatch(&ctx, &conn,
             "{\"id\":1,\"protocol\":\"1.0\",\"method\":\"system.hello\","
             "\"params\":{\"supported_protocols\":[\"1.0\"]}}",
             out, sizeof(out));
    CHECK(conn.handshake_done == 1);

    dispatch(
        &ctx, &conn,
        "{\"id\":4,\"protocol\":\"1.0\",\"method\":\"system.version\",\"params\":{}}",
        out, sizeof(out));
    CHECK(has_substr(out, "\"ok\":true"));
    CHECK(has_substr(out, "\"version\":\"" TEST_ENDPOINT_VERSION "\""));
    check_single_trailing_lf(out);
}

/* ── F. capabilities after hello ── */
static void
test_capabilities_after_hello(void)
{
    mgmt_ctx_t ctx = make_ctx();
    mgmt_conn_t conn = make_conn();
    char out[CMP_MAX_RESPONSE_BYTES];

    dispatch(&ctx, &conn,
             "{\"id\":1,\"protocol\":\"1.0\",\"method\":\"system.hello\","
             "\"params\":{\"supported_protocols\":[\"1.0\"]}}",
             out, sizeof(out));

    dispatch(&ctx, &conn,
             "{\"id\":5,\"protocol\":\"1.0\",\"method\":\"system.capabilities\","
             "\"params\":{}}",
             out, sizeof(out));
    CHECK(has_substr(out, "\"ok\":true"));
    CHECK(has_substr(out, "\"capabilities\":[]"));
    check_single_trailing_lf(out);
}

/* ── G. ping after hello ── */
static void
test_ping_after_hello(void)
{
    mgmt_ctx_t ctx = make_ctx();
    mgmt_conn_t conn = make_conn();
    char out[CMP_MAX_RESPONSE_BYTES];

    dispatch(&ctx, &conn,
             "{\"id\":1,\"protocol\":\"1.0\",\"method\":\"system.hello\","
             "\"params\":{\"supported_protocols\":[\"1.0\"]}}",
             out, sizeof(out));

    dispatch(&ctx, &conn,
             "{\"id\":6,\"protocol\":\"1.0\",\"method\":\"system.ping\",\"params\":{}}",
             out, sizeof(out));
    CHECK(has_substr(out, "\"ok\":true"));
    CHECK(has_substr(out, "\"result\":{}"));
    check_single_trailing_lf(out);
}

/* ── H. unknown method after hello ── */
static void
test_unknown_method(void)
{
    mgmt_ctx_t ctx = make_ctx();
    mgmt_conn_t conn = make_conn();
    char out[CMP_MAX_RESPONSE_BYTES];

    dispatch(&ctx, &conn,
             "{\"id\":1,\"protocol\":\"1.0\",\"method\":\"system.hello\","
             "\"params\":{\"supported_protocols\":[\"1.0\"]}}",
             out, sizeof(out));

    dispatch(&ctx, &conn,
             "{\"id\":7,\"protocol\":\"1.0\",\"method\":\"status.get\",\"params\":{}}",
             out, sizeof(out));
    CHECK(has_substr(out, "\"ok\":false"));
    CHECK(has_substr(out, "\"code\":\"MQVPN_CLIENT_METHOD_NOT_FOUND\""));
    check_single_trailing_lf(out);
}

/* ── I. malformed JSON: no id in response ── */
static void
test_malformed_json_no_id(void)
{
    mgmt_ctx_t ctx = make_ctx();
    mgmt_conn_t conn = make_conn();
    char out[CMP_MAX_RESPONSE_BYTES];

    int rc = dispatch(&ctx, &conn, "{oops", out, sizeof(out));
    CHECK(rc == (int)CMP_E_INVALID_ARGUMENT);
    CHECK(has_substr(out, "\"ok\":false"));
    CHECK(has_substr(out, "\"code\":\"MQVPN_CLIENT_INVALID_ARGUMENT\""));
    CHECK(!has_substr(out, "\"id\":"));
    check_single_trailing_lf(out);
}

/* ── J. id:0 forbidden, no id in response ── */
static void
test_id_zero_forbidden(void)
{
    mgmt_ctx_t ctx = make_ctx();
    mgmt_conn_t conn = make_conn();
    char out[CMP_MAX_RESPONSE_BYTES];

    dispatch(&ctx, &conn,
             "{\"id\":0,\"protocol\":\"1.0\",\"method\":\"system.hello\","
             "\"params\":{\"supported_protocols\":[\"1.0\"]}}",
             out, sizeof(out));
    CHECK(has_substr(out, "\"ok\":false"));
    CHECK(has_substr(out, "\"code\":\"MQVPN_CLIENT_INVALID_ARGUMENT\""));
    CHECK(!has_substr(out, "\"id\":"));
    check_single_trailing_lf(out);
}

/* ── K. missing required top-level fields ── */
static void
test_missing_required_fields(void)
{
    mgmt_ctx_t ctx = make_ctx();
    char out[CMP_MAX_RESPONSE_BYTES];

    {
        mgmt_conn_t conn = make_conn();
        dispatch(&ctx, &conn,
                 "{\"id\":8,\"protocol\":\"1.0\",\"params\":{}}", /* missing method */
                 out, sizeof(out));
        CHECK(has_substr(out, "\"code\":\"MQVPN_CLIENT_INVALID_ARGUMENT\""));
        check_single_trailing_lf(out);
    }
    {
        mgmt_conn_t conn = make_conn();
        dispatch(
            &ctx, &conn,
            "{\"id\":9,\"protocol\":\"1.0\",\"method\":\"system.hello\"}", /* missing
                                                                              params */
            out, sizeof(out));
        CHECK(has_substr(out, "\"code\":\"MQVPN_CLIENT_INVALID_ARGUMENT\""));
        check_single_trailing_lf(out);
    }
    {
        mgmt_conn_t conn = make_conn();
        dispatch(&ctx, &conn,
                 "{\"id\":10,\"method\":\"system.hello\",\"params\":{}}", /* missing
                                                                             protocol */
                 out, sizeof(out));
        CHECK(has_substr(out, "\"code\":\"MQVPN_CLIENT_INVALID_ARGUMENT\""));
        check_single_trailing_lf(out);
    }
}

/* ── M. embedded quote via endpoint_version stays one valid JSON line ── */
static void
test_quote_in_endpoint_version_escaped(void)
{
    mgmt_ctx_t ctx = make_ctx();
    ctx.endpoint_version = "v1.0\"beta\\x";
    mgmt_conn_t conn = make_conn();
    char out[CMP_MAX_RESPONSE_BYTES];

    dispatch(&ctx, &conn,
             "{\"id\":1,\"protocol\":\"1.0\",\"method\":\"system.hello\","
             "\"params\":{\"supported_protocols\":[\"1.0\"]}}",
             out, sizeof(out));
    CHECK(has_substr(out, "\"ok\":true"));
    CHECK(has_substr(out, "\\\"beta\\\\x"));
    check_single_trailing_lf(out);

    dispatch(
        &ctx, &conn,
        "{\"id\":11,\"protocol\":\"1.0\",\"method\":\"system.version\",\"params\":{}}",
        out, sizeof(out));
    CHECK(has_substr(out, "\"ok\":true"));
    check_single_trailing_lf(out);
}

/* ── N. out_cap == CMP_MIN_RESPONSE_BUF forces the RESPONSE_TOO_LARGE
 * fallback when the real response would not fit ── */
static void
test_response_too_large_fallback(void)
{
    char big_version[301];
    memset(big_version, 'a', sizeof(big_version) - 1);
    big_version[sizeof(big_version) - 1] = '\0';

    mgmt_ctx_t ctx = make_ctx();
    ctx.endpoint_version = big_version;
    mgmt_conn_t conn = make_conn();
    char out[CMP_MIN_RESPONSE_BUF];

    int rc = mgmt_dispatch_request(
        &ctx, &conn,
        "{\"id\":1,\"protocol\":\"1.0\",\"method\":\"system.hello\","
        "\"params\":{\"supported_protocols\":[\"1.0\"]}}",
        strlen("{\"id\":1,\"protocol\":\"1.0\",\"method\":\"system.hello\","
               "\"params\":{\"supported_protocols\":[\"1.0\"]}}"),
        out, sizeof(out));
    CHECK(rc == (int)CMP_E_RESPONSE_TOO_LARGE);
    CHECK(strlen(out) < sizeof(out));
    CHECK(has_substr(out, "\"code\":\"MQVPN_CLIENT_RESPONSE_TOO_LARGE\""));
    CHECK(has_substr(out, "\"ok\":false"));
    CHECK(has_substr(out, "\"protocol\":\"1.0\""));
    check_single_trailing_lf(out);
}

/* ── O. nested "method" inside params must not shadow the top-level one ──
 * Regression: json_find_key's flat text scan used to pick up
 * params.method ("system.hello") and dispatch it. The top-level method is
 * system.ping — before handshake that must yield HANDSHAKE_REQUIRED and
 * must NOT run the hello handler. */
static void
test_nested_method_key_ignored(void)
{
    mgmt_ctx_t ctx = make_ctx();
    mgmt_conn_t conn = make_conn();
    char out[CMP_MAX_RESPONSE_BYTES];

    dispatch(&ctx, &conn,
             "{\"id\":1,\"protocol\":\"1.0\","
             "\"params\":{\"method\":\"system.hello\","
             "\"supported_protocols\":[\"1.0\"]},"
             "\"method\":\"system.ping\"}",
             out, sizeof(out));

    CHECK(has_substr(out, "\"ok\":false"));
    CHECK(has_substr(out, "\"code\":\"MQVPN_CLIENT_HANDSHAKE_REQUIRED\""));
    CHECK(!has_substr(out, "endpoint_name")); /* hello handler did not run */
    CHECK(conn.handshake_done == 0);
    check_single_trailing_lf(out);
}

/* ── P. nested "id" inside a sibling object must not shadow the real id ── */
static void
test_nested_id_key_ignored(void)
{
    mgmt_ctx_t ctx = make_ctx();
    mgmt_conn_t conn = make_conn();
    char out[CMP_MAX_RESPONSE_BYTES];

    dispatch(&ctx, &conn,
             "{\"id\":1,\"protocol\":\"1.0\",\"method\":\"system.hello\","
             "\"params\":{\"supported_protocols\":[\"1.0\"]}}",
             out, sizeof(out));
    CHECK(conn.handshake_done == 1);

    dispatch(&ctx, &conn,
             "{\"a\":{\"id\":777},\"id\":2,\"protocol\":\"1.0\","
             "\"method\":\"system.ping\",\"params\":{}}",
             out, sizeof(out));
    CHECK(has_substr(out, "\"ok\":true"));
    CHECK(has_substr(out, "\"id\":2"));
    CHECK(!has_substr(out, "777"));
    check_single_trailing_lf(out);
}

/* ── Q. supported_protocols lookup is bounded to the params object ──
 * Regression: a second JSON object trailing the request on the same line
 * used to satisfy the unbounded supported_protocols search. */
static void
test_params_search_bounded_to_request(void)
{
    mgmt_ctx_t ctx = make_ctx();
    mgmt_conn_t conn = make_conn();
    char out[CMP_MAX_RESPONSE_BYTES];

    dispatch(&ctx, &conn,
             "{\"id\":1,\"protocol\":\"1.0\",\"method\":\"system.hello\","
             "\"params\":{\"client_name\":\"x\"}} "
             "{\"supported_protocols\":[\"1.0\"]}",
             out, sizeof(out));

    CHECK(has_substr(out, "\"ok\":false"));
    CHECK(has_substr(out, "\"code\":\"MQVPN_CLIENT_PROTOCOL_INCOMPATIBLE\""));
    CHECK(conn.handshake_done == 0);
    check_single_trailing_lf(out);
}

/* ── R. result-buffer overflow guard: oversized endpoint_version with a
 * LARGE out_cap must yield a clean INTERNAL_ERROR response, never a spliced
 * truncated result fragment ── */
static void
test_result_overflow_internal_error(void)
{
    static char huge_version[3001];
    memset(huge_version, 'a', sizeof(huge_version) - 1);
    huge_version[sizeof(huge_version) - 1] = '\0';

    mgmt_ctx_t ctx = make_ctx();
    ctx.endpoint_version = huge_version;
    mgmt_conn_t conn = make_conn();
    char out[CMP_MAX_RESPONSE_BYTES];

    dispatch(&ctx, &conn,
             "{\"id\":1,\"protocol\":\"1.0\",\"method\":\"system.hello\","
             "\"params\":{\"supported_protocols\":[\"1.0\"]}}",
             out, sizeof(out));

    CHECK(has_substr(out, "\"ok\":false"));
    CHECK(has_substr(out, "\"code\":\"MQVPN_CLIENT_INTERNAL_ERROR\""));
    CHECK(!has_substr(out, "endpoint_name")); /* no truncated fragment */
    CHECK(!has_substr(out, "aaaa"));
    check_single_trailing_lf(out);
}

/* ── S. method field that is not a string (number) ── */
static void
test_method_as_number(void)
{
    mgmt_ctx_t ctx = make_ctx();
    mgmt_conn_t conn = make_conn();
    char out[CMP_MAX_RESPONSE_BYTES];

    dispatch(&ctx, &conn, "{\"id\":1,\"protocol\":\"1.0\",\"method\":123,\"params\":{}}",
             out, sizeof(out));
    CHECK(has_substr(out, "\"ok\":false"));
    CHECK(has_substr(out, "\"code\":\"MQVPN_CLIENT_INVALID_ARGUMENT\""));
    check_single_trailing_lf(out);
}

/* ── T. hello with a non-string protocol field (false) ── */
static void
test_hello_protocol_not_string(void)
{
    mgmt_ctx_t ctx = make_ctx();
    mgmt_conn_t conn = make_conn();
    char out[CMP_MAX_RESPONSE_BYTES];

    dispatch(&ctx, &conn,
             "{\"id\":1,\"protocol\":false,\"method\":\"system.hello\","
             "\"params\":{\"supported_protocols\":[\"1.0\"]}}",
             out, sizeof(out));
    CHECK(has_substr(out, "\"ok\":false"));
    CHECK(has_substr(out, "\"code\":\"MQVPN_CLIENT_PROTOCOL_INCOMPATIBLE\""));
    CHECK(has_substr(out, "\"supported_protocols\":[\"1.0\"]"));
    CHECK(conn.handshake_done == 0);
    check_single_trailing_lf(out);
}

/* ── U. hello with an unknown protocol version string ── */
static void
test_hello_protocol_wrong_version(void)
{
    mgmt_ctx_t ctx = make_ctx();
    mgmt_conn_t conn = make_conn();
    char out[CMP_MAX_RESPONSE_BYTES];

    dispatch(&ctx, &conn,
             "{\"id\":1,\"protocol\":\"9.9\",\"method\":\"system.hello\","
             "\"params\":{\"supported_protocols\":[\"1.0\"]}}",
             out, sizeof(out));
    CHECK(has_substr(out, "\"ok\":false"));
    CHECK(has_substr(out, "\"code\":\"MQVPN_CLIENT_PROTOCOL_INCOMPATIBLE\""));
    CHECK(has_substr(out, "\"supported_protocols\":[\"1.0\"]"));
    CHECK(conn.handshake_done == 0);
    check_single_trailing_lf(out);
}

/* ── V. post-handshake requests stay presence-only on protocol (pinned) ── */
static void
test_post_handshake_protocol_presence_only(void)
{
    mgmt_ctx_t ctx = make_ctx();
    mgmt_conn_t conn = make_conn();
    char out[CMP_MAX_RESPONSE_BYTES];

    dispatch(&ctx, &conn,
             "{\"id\":1,\"protocol\":\"1.0\",\"method\":\"system.hello\","
             "\"params\":{\"supported_protocols\":[\"1.0\"]}}",
             out, sizeof(out));
    CHECK(conn.handshake_done == 1);

    dispatch(&ctx, &conn,
             "{\"id\":2,\"protocol\":\"9.9\",\"method\":\"system.ping\",\"params\":{}}",
             out, sizeof(out));
    CHECK(has_substr(out, "\"ok\":true"));
    CHECK(has_substr(out, "\"id\":2"));
    check_single_trailing_lf(out);
}

/* ── W. nested object inside params must not shadow supported_protocols ──
 * Regression: a flat key scan inside params let
 * {"x":{"supported_protocols":["1.0"]},...} satisfy the hello check even
 * though the real depth-1 supported_protocols is ["9.9"]. */
static void
test_params_nested_supported_protocols_ignored(void)
{
    mgmt_ctx_t ctx = make_ctx();
    mgmt_conn_t conn = make_conn();
    char out[CMP_MAX_RESPONSE_BYTES];

    dispatch(&ctx, &conn,
             "{\"id\":1,\"protocol\":\"1.0\",\"method\":\"system.hello\","
             "\"params\":{\"x\":{\"supported_protocols\":[\"1.0\"]},"
             "\"supported_protocols\":[\"9.9\"]}}",
             out, sizeof(out));
    CHECK(has_substr(out, "\"ok\":false"));
    CHECK(has_substr(out, "\"code\":\"MQVPN_CLIENT_PROTOCOL_INCOMPATIBLE\""));
    CHECK(conn.handshake_done == 0);
    check_single_trailing_lf(out);
}

int
main(void)
{
    test_hello_success();
    test_version_before_hello_requires_handshake();
    test_hello_incompatible_protocol();
    test_duplicate_hello_idempotent();
    test_version_after_hello();
    test_capabilities_after_hello();
    test_ping_after_hello();
    test_unknown_method();
    test_malformed_json_no_id();
    test_id_zero_forbidden();
    test_missing_required_fields();
    test_quote_in_endpoint_version_escaped();
    test_response_too_large_fallback();
    test_nested_method_key_ignored();
    test_nested_id_key_ignored();
    test_params_search_bounded_to_request();
    test_result_overflow_internal_error();
    test_method_as_number();
    test_hello_protocol_not_string();
    test_hello_protocol_wrong_version();
    test_post_handshake_protocol_presence_only();
    test_params_nested_supported_protocols_ignored();

    if (g_failed) {
        fprintf(stderr, "%d check(s) failed\n", g_failed);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
