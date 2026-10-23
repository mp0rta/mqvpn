// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#undef NDEBUG
#include "mgmt_dispatch.h"
#include "mgmt_rpc.h"
#include "cmp_error.h"
#include "cmp_proto.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failed = 0;

#define CHECK(cond)                                                         \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            g_failed++;                                                     \
        }                                                                   \
    } while (0)

static const char *const k_caps[] = {"a", "b"};
static const mgmt_endpoint_ctx_t g_ep = {"9.9.9-test", k_caps, 2};

static int g_last_rc;
static int g_last_err_code;
static mgmt_line_t g_line; /* last response, freed by the next run() */
static int g_handler_calls;

/* Dispatch via table (NULL = built-in) and parse the reply; NULL if none. */
static yyjson_doc *
run_ex(const mgmt_method_t *tbl, size_t n, const char *line, mgmt_conn_state_t *conn)
{
    free(g_line.buf);
    memset(&g_line, 0, sizeof(g_line));
    g_last_err_code = 0;
    if (tbl)
        g_last_rc = mgmt_dispatch_line_ex(tbl, n, &g_ep, conn, line, strlen(line),
                                          &g_line, &g_last_err_code);
    else
        g_last_rc = mgmt_dispatch_line(&g_ep, conn, line, strlen(line), &g_line,
                                       &g_last_err_code);
    if (g_last_rc != 0 || !g_line.buf) return NULL;
    return yyjson_read(g_line.buf, g_line.len, YYJSON_READ_NOFLAG);
}

static yyjson_doc *
run(const char *line, mgmt_conn_state_t *conn)
{
    return run_ex(NULL, 0, line, conn);
}

static yyjson_val *
get(yyjson_doc *d, const char *k)
{
    return yyjson_obj_get(yyjson_doc_get_root(d), k);
}

static int
err_code(yyjson_doc *d)
{
    yyjson_val *c = yyjson_obj_get(get(d, "error"), "code");
    return yyjson_is_int(c) ? (int)yyjson_get_sint(c) : 0;
}

/* Run `line`, expect an error reply with `code`; has_id 0 = id must be null. */
static void
expect_err(const char *line, int code, int has_id, int64_t id)
{
    mgmt_conn_state_t conn = {MGMT_ROLE_ADMIN, 1};
    yyjson_doc *d = run(line, &conn);
    CHECK(d != NULL);
    if (!d) return;
    CHECK(err_code(d) == code);
    CHECK(g_last_err_code == code);
    CHECK(get(d, "result") == NULL);
    yyjson_val *i = get(d, "id");
    if (has_id) {
        CHECK(yyjson_is_int(i));
        CHECK(yyjson_get_sint(i) == id);
    } else {
        CHECK(yyjson_is_null(i));
    }
    yyjson_doc_free(d);
}

static void
dispatch_batch_rejected(void)
{
    puts("dispatch_batch_rejected");
    mgmt_conn_state_t conn = {MGMT_ROLE_ADMIN, 1};
    yyjson_doc *d =
        run("[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system.ping\"}]", &conn);
    CHECK(d != NULL);
    if (!d) return;
    CHECK(err_code(d) == -32600);
    CHECK(yyjson_is_null(get(d, "id")));
    yyjson_val *nm = yyjson_obj_get(yyjson_obj_get(get(d, "error"), "data"), "name");
    CHECK(nm && strcmp(yyjson_get_str(nm), "MQVPN_CLIENT_INVALID_REQUEST") == 0);
    yyjson_doc_free(d);
}

static void
dispatch_parse_error(void)
{
    puts("dispatch_parse_error");
    expect_err("{\"jsonrpc\":", -32700, 0, 0);
    expect_err("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system.ping\"} trailing",
               -32700, 0, 0);
}

static void
dispatch_invalid_envelope(void)
{
    puts("dispatch_invalid_envelope");
    expect_err("{\"id\":1,\"method\":\"system.ping\"}", -32600, 1, 1);
    expect_err("{\"jsonrpc\":\"2\",\"id\":1,\"method\":\"system.ping\"}", -32600, 1, 1);
    expect_err("{\"jsonrpc\":\"2.0\",\"id\":1.5,\"method\":\"system.ping\"}", -32600, 0,
               0);
    expect_err("{\"jsonrpc\":\"2.0\",\"id\":{\"a\":1},\"method\":\"system.ping\"}",
               -32600, 0, 0);
    expect_err("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":5}", -32600, 1, 1);
    expect_err("{\"jsonrpc\":\"2.0\",\"id\":1}", -32600, 1, 1);
    expect_err("\"not an object\"", -32600, 0, 0);
    expect_err("42", -32600, 0, 0);
}

static void
dispatch_params_array_invalid(void)
{
    puts("dispatch_params_array_invalid");
    expect_err(
        "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"system.hello\",\"params\":[1]}",
        -32602, 1, 7);
}

static void
dispatch_notification_no_reply(void)
{
    puts("dispatch_notification_no_reply");
    const char *lines[] = {
        "{\"jsonrpc\":\"2.0\",\"method\":\"system.ping\"}",
        "{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"system.ping\"}"};
    for (int i = 0; i < 2; i++) {
        mgmt_conn_state_t conn = {MGMT_ROLE_ADMIN, 1};
        yyjson_doc *d = run(lines[i], &conn);
        CHECK(d == NULL);
        CHECK(g_last_rc == 1);
        CHECK(g_line.buf == NULL);
    }
}

static void
dispatch_nested_keys_ignored(void)
{
    puts("dispatch_nested_keys_ignored");
    mgmt_conn_state_t conn = {MGMT_ROLE_ADMIN, 1};
    yyjson_doc *d = run("{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"system.ping\","
                        "\"params\":{\"id\":9,\"method\":\"system.hello\","
                        "\"cmp_versions\":[\"1.0\"]}}",
                        &conn);
    CHECK(d != NULL);
    if (!d) return;
    CHECK(yyjson_get_sint(get(d, "id")) == 3);
    CHECK(yyjson_is_obj(get(d, "result")) && yyjson_obj_size(get(d, "result")) == 0);
    yyjson_doc_free(d);
}

static void
dispatch_hello_ok(void)
{
    puts("dispatch_hello_ok");
    mgmt_conn_state_t conn = {MGMT_ROLE_ADMIN, 0};
    yyjson_doc *d = run("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system.hello\","
                        "\"params\":{\"client_name\":\"t\",\"client_version\":\"0\","
                        "\"cmp_versions\":[\"0.9\",\"1.0\"]}}",
                        &conn);
    CHECK(d != NULL);
    if (!d) return;
    yyjson_val *r = get(d, "result");
    CHECK(strcmp(yyjson_get_str(yyjson_obj_get(r, "cmp_version")), "1.0") == 0);
    CHECK(strcmp(yyjson_get_str(yyjson_obj_get(r, "role")), "admin") == 0);
    CHECK(strcmp(yyjson_get_str(yyjson_obj_get(r, "endpoint_name")), "mqvpn-client") ==
          0);
    CHECK(strcmp(yyjson_get_str(yyjson_obj_get(r, "endpoint_version")),
                 g_ep.endpoint_version) == 0);
    yyjson_val *caps = yyjson_obj_get(r, "capabilities");
    CHECK(yyjson_is_arr(caps) && yyjson_arr_size(caps) == g_ep.n_capabilities);
    CHECK(conn.handshake_done == 1);
    yyjson_doc_free(d);
}

static void
dispatch_hello_incompatible(void)
{
    puts("dispatch_hello_incompatible");
    mgmt_conn_state_t conn = {MGMT_ROLE_ADMIN, 0};
    yyjson_doc *d = run("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system.hello\","
                        "\"params\":{\"cmp_versions\":[\"2.0\"]}}",
                        &conn);
    CHECK(d != NULL);
    if (d) {
        CHECK(err_code(d) == -32002);
        yyjson_val *sup = yyjson_obj_get(
            yyjson_obj_get(yyjson_obj_get(get(d, "error"), "data"), "details"),
            "supported");
        CHECK(yyjson_is_arr(sup) && yyjson_arr_size(sup) == 1);
        CHECK(sup && strcmp(yyjson_get_str(yyjson_arr_get_first(sup)), "1.0") == 0);
        yyjson_doc_free(d);
    }
    CHECK(conn.handshake_done == 0);

    d = run("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system.hello\",\"params\":{}}",
            &conn);
    CHECK(d && err_code(d) == -32602);
    yyjson_doc_free(d);
    d = run("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system.hello\","
            "\"params\":{\"cmp_versions\":\"1.0\"}}",
            &conn);
    CHECK(d && err_code(d) == -32602);
    yyjson_doc_free(d);
    CHECK(conn.handshake_done == 0);
}

static void
dispatch_hello_idempotent(void)
{
    puts("dispatch_hello_idempotent");
    mgmt_conn_state_t conn = {MGMT_ROLE_ADMIN, 0};
    const char *hello = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system.hello\","
                        "\"params\":{\"cmp_versions\":[\"1.0\"]}}";
    for (int i = 0; i < 2; i++) {
        yyjson_doc *d = run(hello, &conn);
        CHECK(d && get(d, "result") != NULL);
        CHECK(conn.handshake_done == 1);
        yyjson_doc_free(d);
    }
}

static void
dispatch_hello_second_incompatible_still_ok(void)
{
    puts("dispatch_hello_second_incompatible_still_ok");
    mgmt_conn_state_t conn = {MGMT_ROLE_ADMIN, 0};
    yyjson_doc *d = run("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system.hello\","
                        "\"params\":{\"cmp_versions\":[\"1.0\"]}}",
                        &conn);
    CHECK(d && get(d, "result") != NULL);
    yyjson_doc_free(d);
    d = run("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"system.hello\","
            "\"params\":{\"cmp_versions\":[\"2.0\"]}}",
            &conn);
    CHECK(d && get(d, "result") != NULL && get(d, "error") == NULL);
    CHECK(conn.handshake_done == 1);
    yyjson_doc_free(d);
}

static int
h_unknown_code(mgmt_call_t *call, yyjson_mut_val **result, const char **err_msg,
               yyjson_mut_val **err_data)
{
    (void)call;
    (void)result;
    (void)err_msg;
    (void)err_data;
    return 424242;
}

static void
dispatch_unknown_handler_code_is_internal_error(void)
{
    puts("dispatch_unknown_handler_code_is_internal_error");
    const mgmt_method_t tbl[] = {{"t.odd", 0, MGMT_ROLE_USER, h_unknown_code}};
    mgmt_conn_state_t conn = {MGMT_ROLE_ADMIN, 1};
    yyjson_doc *d =
        run_ex(tbl, 1, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"t.odd\"}", &conn);
    CHECK(d && err_code(d) == -32603);
    CHECK(g_last_err_code == -32603);
    yyjson_val *nm =
        d ? yyjson_obj_get(yyjson_obj_get(get(d, "error"), "data"), "name") : NULL;
    CHECK(nm && strcmp(yyjson_get_str(nm), "MQVPN_CLIENT_INTERNAL_ERROR") == 0);
    yyjson_doc_free(d);
}

static void
dispatch_notification_line_shape(void)
{
    puts("dispatch_notification_line_shape");
    yyjson_mut_doc *md = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *params = yyjson_mut_obj(md);
    CHECK(md && params && yyjson_mut_obj_add_int(md, params, "a", 1));
    mgmt_line_t line = {0};
    CHECK(mgmt_rpc_notification_line(md, "event.x", params, &line) == 0);
    CHECK(line.buf && line.len > 1 && line.buf[line.len - 1] == '\n');
    CHECK(line.buf && memchr(line.buf, '\n', line.len) == line.buf + line.len - 1);
    yyjson_doc *d = line.buf ? yyjson_read(line.buf, line.len, YYJSON_READ_NOFLAG) : NULL;
    CHECK(d != NULL);
    if (d) {
        CHECK(strcmp(yyjson_get_str(get(d, "jsonrpc")), "2.0") == 0);
        CHECK(strcmp(yyjson_get_str(get(d, "method")), "event.x") == 0);
        yyjson_val *p = get(d, "params");
        CHECK(yyjson_is_obj(p) && yyjson_obj_size(p) == 1 &&
              yyjson_get_int(yyjson_obj_get(p, "a")) == 1);
        CHECK(get(d, "id") == NULL);
        yyjson_doc_free(d);
    }
    free(line.buf);
    yyjson_mut_doc_free(md);
}

static void
dispatch_handshake_required(void)
{
    puts("dispatch_handshake_required");
    mgmt_conn_state_t conn = {MGMT_ROLE_ADMIN, 0};
    const char *ver = "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"system.version\"}";
    yyjson_doc *d = run(ver, &conn);
    CHECK(d && err_code(d) == -32001 && yyjson_get_sint(get(d, "id")) == 4);
    yyjson_doc_free(d);
    d = run("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system.hello\","
            "\"params\":{\"cmp_versions\":[\"1.0\"]}}",
            &conn);
    CHECK(d && get(d, "result"));
    yyjson_doc_free(d);
    d = run(ver, &conn);
    CHECK(d != NULL);
    if (!d) return;
    yyjson_val *r = get(d, "result");
    CHECK(strcmp(yyjson_get_str(yyjson_obj_get(r, "cmp_version")), "1.0") == 0);
    CHECK(strcmp(yyjson_get_str(yyjson_obj_get(r, "endpoint_version")),
                 g_ep.endpoint_version) == 0);
    yyjson_doc_free(d);
}

static void
dispatch_method_not_found(void)
{
    puts("dispatch_method_not_found");
    expect_err("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"rpc.x\"}", -32601, 1, 2);
    expect_err("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"status.get\"}", -32601, 1, 2);
}

static int
h_counts(mgmt_call_t *call, yyjson_mut_val **result, const char **err_msg,
         yyjson_mut_val **err_data)
{
    (void)err_msg;
    (void)err_data;
    g_handler_calls++;
    *result = yyjson_mut_obj(call->doc);
    return 0;
}

static void
dispatch_role_denied_handler_not_called(void)
{
    puts("dispatch_role_denied_handler_not_called");
    const mgmt_method_t tbl[] = {{"t.admin", 1, MGMT_ROLE_ADMIN, h_counts}};
    const char *req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"t.admin\"}";
    mgmt_conn_state_t conn = {MGMT_ROLE_USER, 1};
    g_handler_calls = 0;
    yyjson_doc *d = run_ex(tbl, 1, req, &conn);
    CHECK(d && err_code(d) == -32003);
    CHECK(g_handler_calls == 0);
    yyjson_doc_free(d);
    conn.role = MGMT_ROLE_ADMIN;
    d = run_ex(tbl, 1, req, &conn);
    CHECK(d && get(d, "result"));
    CHECK(g_handler_calls == 1);
    yyjson_doc_free(d);
    /* built-in table: a user-role connection may say hello (system.hello is USER). */
    mgmt_conn_state_t uc = {MGMT_ROLE_USER, 0};
    d = run("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system.hello\","
            "\"params\":{\"cmp_versions\":[\"1.0\"]}}",
            &uc);
    CHECK(d && get(d, "result"));
    CHECK(d &&
          strcmp(yyjson_get_str(yyjson_obj_get(get(d, "result"), "role")), "user") == 0);
    yyjson_doc_free(d);
}

static void
dispatch_echoes_id_type(void)
{
    puts("dispatch_echoes_id_type");
    mgmt_conn_state_t conn = {MGMT_ROLE_ADMIN, 1};
    yyjson_doc *d =
        run("{\"jsonrpc\":\"2.0\",\"id\":\"abc\",\"method\":\"system.ping\"}", &conn);
    CHECK(d && yyjson_is_str(get(d, "id")) &&
          strcmp(yyjson_get_str(get(d, "id")), "abc") == 0);
    yyjson_doc_free(d);
    d = run("{\"jsonrpc\":\"2.0\",\"id\":-5,\"method\":\"system.ping\"}", &conn);
    CHECK(d && yyjson_is_sint(get(d, "id")) && yyjson_get_sint(get(d, "id")) == -5);
    yyjson_doc_free(d);
    d = run(
        "{\"jsonrpc\":\"2.0\",\"id\":18446744073709551615,\"method\":\"system.ping\"}",
        &conn);
    CHECK(d && yyjson_is_uint(get(d, "id")) &&
          yyjson_get_uint(get(d, "id")) == UINT64_MAX);
    yyjson_doc_free(d);
    d = run("{\"jsonrpc\":\"2.0\",\"id\":\"\",\"method\":\"system.ping\"}", &conn);
    CHECK(d && yyjson_is_str(get(d, "id")) && yyjson_get_len(get(d, "id")) == 0);
    yyjson_doc_free(d);
}

static int
h_huge(mgmt_call_t *call, yyjson_mut_val **result, const char **err_msg,
       yyjson_mut_val **err_data)
{
    (void)err_msg;
    (void)err_data;
    size_t n = 300 * 1024;
    char *s = malloc(n);
    if (!s) return CMP_E_INTERNAL_ERROR;
    memset(s, 'a', n);
    *result = yyjson_mut_obj(call->doc);
    yyjson_mut_obj_add_val(call->doc, *result, "s", yyjson_mut_strncpy(call->doc, s, n));
    free(s);
    return 0;
}

static void
dispatch_response_too_large(void)
{
    puts("dispatch_response_too_large");
    const mgmt_method_t tbl[] = {{"t.huge", 0, MGMT_ROLE_USER, h_huge}};
    mgmt_conn_state_t conn = {MGMT_ROLE_ADMIN, 1};
    yyjson_doc *d =
        run_ex(tbl, 1, "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"t.huge\"}", &conn);
    CHECK(d != NULL);
    if (!d) return;
    CHECK(err_code(d) == -32000);
    CHECK(g_last_err_code == -32000);
    CHECK(yyjson_get_sint(get(d, "id")) == 8);
    CHECK(g_line.len <= 1024);
    yyjson_doc_free(d);
}

static const char k_esc[] = "q\"b\\c\x01\n";

static int
h_esc(mgmt_call_t *call, yyjson_mut_val **result, const char **err_msg,
      yyjson_mut_val **err_data)
{
    (void)err_msg;
    (void)err_data;
    *result = yyjson_mut_obj(call->doc);
    yyjson_mut_obj_add_val(call->doc, *result, "s", yyjson_mut_strcpy(call->doc, k_esc));
    return 0;
}

static void
dispatch_string_escapes(void)
{
    puts("dispatch_string_escapes");
    const mgmt_method_t tbl[] = {{"t.esc", 0, MGMT_ROLE_USER, h_esc}};
    mgmt_conn_state_t conn = {MGMT_ROLE_ADMIN, 1};
    yyjson_doc *d =
        run_ex(tbl, 1, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"t.esc\"}", &conn);
    CHECK(d != NULL);
    if (!d) return;
    CHECK(g_line.len > 1 && g_line.buf[g_line.len - 1] == '\n');
    CHECK(memchr(g_line.buf, '\n', g_line.len - 1) == NULL);
    yyjson_val *s = yyjson_obj_get(get(d, "result"), "s");
    CHECK(s && yyjson_get_len(s) == strlen(k_esc) &&
          strcmp(yyjson_get_str(s), k_esc) == 0);
    yyjson_doc_free(d);
}

static int
h_badutf8(mgmt_call_t *call, yyjson_mut_val **result, const char **err_msg,
          yyjson_mut_val **err_data)
{
    (void)err_msg;
    (void)err_data;
    *result = yyjson_mut_obj(call->doc);
    yyjson_mut_obj_add_val(call->doc, *result, "s",
                           yyjson_mut_strcpy(call->doc, "\xff\xfe"));
    return 0;
}

static void
dispatch_invalid_utf8_is_internal_error(void)
{
    puts("dispatch_invalid_utf8_is_internal_error");
    const mgmt_method_t tbl[] = {{"t.bad", 0, MGMT_ROLE_USER, h_badutf8}};
    mgmt_conn_state_t conn = {MGMT_ROLE_ADMIN, 1};
    yyjson_doc *d =
        run_ex(tbl, 1, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"t.bad\"}", &conn);
    CHECK(d && err_code(d) == -32603);
    CHECK(g_last_err_code == -32603);
    yyjson_doc_free(d);
}

static void
dispatch_exact_shape_ping(void)
{
    puts("dispatch_exact_shape_ping");
    mgmt_conn_state_t conn = {MGMT_ROLE_ADMIN, 1};
    yyjson_doc *d =
        run("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system.ping\"}", &conn);
    const char *want = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n";
    CHECK(g_line.len == strlen(want) && memcmp(g_line.buf, want, g_line.len) == 0);
    yyjson_doc_free(d);
}

static void
dispatch_table_sanity(void)
{
    puts("dispatch_table_sanity");
    size_t n = 0;
    const mgmt_method_t *t = mgmt_method_table(&n);
    CHECK(t != NULL && n == 4);
    for (size_t i = 0; t && i < n; i++) {
        CHECK(strncmp(t[i].name, "rpc.", 4) != 0);
        CHECK((t[i].requires_handshake == 0) == (strcmp(t[i].name, "system.hello") == 0));
        for (size_t j = i + 1; j < n; j++)
            CHECK(strcmp(t[i].name, t[j].name) != 0);
    }
}

static void
dispatch_never_crashes_fuzzish(void)
{
    puts("dispatch_never_crashes_fuzzish");
    unsigned seed = 12345;
    for (int i = 0; i < 256; i++) {
        char buf[200];
        size_t len = (size_t)(rand_r(&seed) % 201);
        for (size_t k = 0; k < len; k++)
            buf[k] = (char)(rand_r(&seed) & 0xff);
        mgmt_conn_state_t conn = {MGMT_ROLE_ADMIN, (i & 1)};
        mgmt_line_t out = {0};
        int ec = 0;
        int rc = mgmt_dispatch_line(&g_ep, &conn, buf, len, &out, &ec);
        CHECK(rc == 0 || rc == 1);
        if (rc == 0) {
            CHECK(out.len > 0 && out.buf[out.len - 1] == '\n');
            free(out.buf);
        }
    }
}

int
main(void)
{
    dispatch_batch_rejected();
    dispatch_parse_error();
    dispatch_invalid_envelope();
    dispatch_params_array_invalid();
    dispatch_notification_no_reply();
    dispatch_nested_keys_ignored();
    dispatch_hello_ok();
    dispatch_hello_incompatible();
    dispatch_hello_idempotent();
    dispatch_hello_second_incompatible_still_ok();
    dispatch_unknown_handler_code_is_internal_error();
    dispatch_notification_line_shape();
    dispatch_handshake_required();
    dispatch_method_not_found();
    dispatch_role_denied_handler_not_called();
    dispatch_echoes_id_type();
    dispatch_response_too_large();
    dispatch_string_escapes();
    dispatch_invalid_utf8_is_internal_error();
    dispatch_exact_shape_ping();
    dispatch_table_sanity();
    dispatch_never_crashes_fuzzish();
    free(g_line.buf);
    return g_failed ? 1 : 0;
}
