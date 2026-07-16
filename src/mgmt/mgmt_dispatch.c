// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* src/mgmt/mgmt_dispatch.c — OS-neutral CMP request dispatcher.
 *
 * No libevent, no libmqvpn includes. Only cmp_* + json_mini.h + libc. This
 * file processes one already-framed NDJSON request line and always writes
 * exactly one response line (see mgmt_dispatch_request's contract in the
 * header) — it never touches a socket or an event loop.
 */
#include "mgmt_dispatch.h"

#include "cmp_error.h"
#include "cmp_json.h"
#include "cmp_types.h"
#include "json_mini.h"

#include <stdint.h>
#include <string.h>

/* Result of a method handler. On success (code == CMP_E_OK) the handler has
 * already written the result-object body into the `result` cmp_buf_t passed
 * to it and the other fields are ignored. On error the handler leaves
 * `result` untouched and fills message/details/retryable instead. */
typedef struct {
    cmp_error_code_t code;
    const char *message;      /* fixed literal; ignored when code == CMP_E_OK */
    const char *details_json; /* raw JSON object literal, or NULL */
    int retryable;
} mgmt_result_t;

typedef void (*mgmt_handler_fn)(const mgmt_ctx_t *ctx, mgmt_conn_t *conn,
                                const char *params, cmp_buf_t *result,
                                mgmt_result_t *out);

typedef struct {
    const char *name;
    int requires_handshake;
    mgmt_handler_fn fn;
} mgmt_method_t;

/* ── result-body helpers shared by handlers ─────────────────────────────── */

static void
write_capabilities_array(const mgmt_ctx_t *ctx, cmp_buf_t *b)
{
    cmp_buf_appendf(b, "[");
    for (size_t i = 0; i < ctx->n_capabilities; i++) {
        if (i > 0) cmp_buf_appendf(b, ",");
        cmp_json_append_str(b, ctx->capabilities[i]);
    }
    cmp_buf_appendf(b, "]");
}

static void
write_hello_result(const mgmt_ctx_t *ctx, cmp_buf_t *b)
{
    cmp_buf_appendf(b, "{\"endpoint_name\":");
    cmp_json_append_str(b, CMP_ENDPOINT_NAME);
    cmp_buf_appendf(b, ",\"endpoint_version\":");
    cmp_json_append_str(b, ctx->endpoint_version);
    cmp_buf_appendf(
        b, ",\"selected_protocol\":\"%s\",\"capabilities\":", CMP_PROTOCOL_VERSION);
    write_capabilities_array(ctx, b);
    cmp_buf_appendf(b, "}");
}

/* ── method handlers ─────────────────────────────────────────────────────
 * `params` points at the value of the request's "params" key (still inside
 * the original request-line buffer, NUL-terminated at the buffer's end —
 * not bounded to the params object itself, mirroring json_find_key's
 * existing unbounded-search idiom elsewhere in the codebase). */

static void
h_hello(const mgmt_ctx_t *ctx, mgmt_conn_t *conn, const char *params, cmp_buf_t *result,
        mgmt_result_t *out)
{
    /* Negotiation is fixed at the first successful hello: a duplicate hello
     * on an already-handshaken connection is an idempotent success and does
     * not re-check supported_protocols. */
    if (conn->handshake_done) {
        write_hello_result(ctx, result);
        out->code = CMP_E_OK;
        return;
    }

    if (!cmp_json_array_contains_str(params, "supported_protocols",
                                     CMP_PROTOCOL_VERSION)) {
        out->code = CMP_E_PROTOCOL_INCOMPATIBLE;
        out->message = "no compatible protocol version";
        out->details_json = "{\"supported_protocols\":[\"" CMP_PROTOCOL_VERSION "\"]}";
        out->retryable = 0;
        return;
    }

    write_hello_result(ctx, result);
    conn->handshake_done = 1;
    out->code = CMP_E_OK;
}

static void
h_version(const mgmt_ctx_t *ctx, mgmt_conn_t *conn, const char *params, cmp_buf_t *result,
          mgmt_result_t *out)
{
    (void)conn;
    (void)params;
    cmp_buf_appendf(result, "{\"version\":");
    cmp_json_append_str(result, ctx->endpoint_version);
    cmp_buf_appendf(result, "}");
    out->code = CMP_E_OK;
}

static void
h_capabilities(const mgmt_ctx_t *ctx, mgmt_conn_t *conn, const char *params,
               cmp_buf_t *result, mgmt_result_t *out)
{
    (void)conn;
    (void)params;
    cmp_buf_appendf(result, "{\"capabilities\":");
    write_capabilities_array(ctx, result);
    cmp_buf_appendf(result, "}");
    out->code = CMP_E_OK;
}

static void
h_ping(const mgmt_ctx_t *ctx, mgmt_conn_t *conn, const char *params, cmp_buf_t *result,
       mgmt_result_t *out)
{
    (void)ctx;
    (void)conn;
    (void)params;
    cmp_buf_appendf(result, "{}");
    out->code = CMP_E_OK;
}

/* Phase 1 method table. Keep in sync with the AGENTS.md/spec method list —
 * system.ping is pulled forward from Phase 2 deliberately (trivial, useful
 * for socket-layer testing). */
static const mgmt_method_t mgmt_methods[] = {
    {"system.hello", 0, h_hello},
    {"system.version", 1, h_version},
    {"system.capabilities", 1, h_capabilities},
    {"system.ping", 1, h_ping},
};

static const mgmt_method_t *
find_method(const char *name)
{
    for (size_t i = 0; i < sizeof(mgmt_methods) / sizeof(mgmt_methods[0]); i++) {
        if (strcmp(mgmt_methods[i].name, name) == 0) return &mgmt_methods[i];
    }
    return NULL;
}

/* ── envelope writers ────────────────────────────────────────────────────
 * `msg` goes through cmp_json_append_str (escaped) since it is not
 * guaranteed control-character-free even though every current call site
 * passes a fixed literal; `details_json`, when non-NULL, is always a
 * pre-formed literal JSON fragment authored by this file, so it is safe to
 * splice in raw. */

static void
mgmt_write_error(cmp_buf_t *b, uint64_t id, int has_id, cmp_error_code_t code,
                 const char *msg, const char *details_json, int retryable)
{
    cmp_buf_appendf(b, "{");
    if (has_id) {
        cmp_buf_appendf(b, "\"id\":%llu,", (unsigned long long)id);
    }
    cmp_buf_appendf(
        b, "\"protocol\":\"%s\",\"ok\":false,\"error\":{\"code\":\"%s\",\"message\":",
        CMP_PROTOCOL_VERSION, cmp_error_code_str(code));
    cmp_json_append_str(b, msg);
    cmp_buf_appendf(b, ",\"retryable\":%s", retryable ? "true" : "false");
    if (details_json) {
        cmp_buf_appendf(b, ",\"details\":%s", details_json);
    }
    cmp_buf_appendf(b, "}}\n");
}

int
mgmt_dispatch_request(const mgmt_ctx_t *ctx, mgmt_conn_t *conn, const char *line,
                      size_t len, char *out, size_t out_cap)
{
    (void)len; /* line is NUL-terminated by the caller; len is advisory only */

    cmp_buf_t out_buf;
    cmp_buf_init(&out_buf, out, out_cap);

    const char *p = json_skip_ws(line);
    const char *obj_end = (*p == '{') ? json_object_end(p) : NULL;

    uint64_t id = 0;
    int has_id = 0;

    if (!obj_end) {
        mgmt_write_error(&out_buf, 0, 0, CMP_E_INVALID_ARGUMENT, "malformed JSON request",
                         NULL, 0);
        goto finalize;
    }

    {
        const char *idv = json_find_key_bounded(p, obj_end, "id");
        uint64_t v;
        if (idv && json_read_u64_strict(idv, &v) == 0 && v != 0) {
            id = v;
            has_id = 1;
        }
    }
    if (!has_id) {
        mgmt_write_error(&out_buf, 0, 0, CMP_E_INVALID_ARGUMENT, "missing or invalid id",
                         NULL, 0);
        goto finalize;
    }

    {
        const char *protov = json_find_key_bounded(p, obj_end, "protocol");
        const char *methodv = json_find_key_bounded(p, obj_end, "method");
        const char *paramsv = json_find_key_bounded(p, obj_end, "params");

        if (!protov || !methodv || !paramsv) {
            mgmt_write_error(&out_buf, id, 1, CMP_E_INVALID_ARGUMENT,
                             "missing required field (protocol/method/params)", NULL, 0);
            goto finalize;
        }

        char method_name[64];
        if (json_read_string(methodv, method_name, sizeof(method_name)) != 0) {
            mgmt_write_error(&out_buf, id, 1, CMP_E_INVALID_ARGUMENT,
                             "invalid method field", NULL, 0);
            goto finalize;
        }

        const mgmt_method_t *m = find_method(method_name);
        if (!m) {
            mgmt_write_error(&out_buf, id, 1, CMP_E_METHOD_NOT_FOUND, "unknown method",
                             NULL, 0);
            goto finalize;
        }

        if (m->requires_handshake && !conn->handshake_done) {
            mgmt_write_error(&out_buf, id, 1, CMP_E_HANDSHAKE_REQUIRED,
                             "handshake required before this method", NULL, 0);
            goto finalize;
        }

        /* Result bodies are small and fixed-shape for every Phase 1 method
         * (endpoint name/version/capabilities/{}); 2048 bytes is generous
         * headroom even for a long endpoint_version string. */
        char result_storage[2048];
        cmp_buf_t result_buf;
        cmp_buf_init(&result_buf, result_storage, sizeof(result_storage));

        mgmt_result_t res;
        res.code = CMP_E_OK;
        res.message = NULL;
        res.details_json = NULL;
        res.retryable = 0;

        m->fn(ctx, conn, paramsv, &result_buf, &res);

        if (res.code != CMP_E_OK) {
            mgmt_write_error(&out_buf, id, 1, res.code, res.message, res.details_json,
                             res.retryable);
            goto finalize;
        }

        if (result_buf.overflow) {
            mgmt_write_error(&out_buf, id, 1, CMP_E_INTERNAL_ERROR,
                             "internal result buffer overflow", NULL, 0);
            goto finalize;
        }

        cmp_buf_appendf(&out_buf,
                        "{\"id\":%llu,\"protocol\":\"%s\",\"ok\":true,\"result\":",
                        (unsigned long long)id, CMP_PROTOCOL_VERSION);
        /* result_buf.buf is JSON we constructed ourselves via
         * cmp_json_append_str/cmp_buf_appendf above, not an externally
         * sourced string, so splicing it via %s does not bypass escaping. */
        cmp_buf_appendf(&out_buf, "%s", result_buf.buf);
        cmp_buf_appendf(&out_buf, "}\n");
    }

finalize:
    /* Fixed short fallback when the real response does not fit out_cap.
     * Guaranteed (by construction; spot-checked in tests) to fit in
     * CMP_MIN_RESPONSE_BUF. No id: whatever was written above may itself be
     * why out_buf overflowed, so it cannot be trusted to recover one. */
    if (out_buf.overflow) {
        cmp_buf_init(&out_buf, out, out_cap);
        cmp_buf_appendf(&out_buf,
                        "{\"ok\":false,\"error\":{\"code\":\"%s\","
                        "\"message\":\"response exceeded size limit\","
                        "\"retryable\":false}}\n",
                        cmp_error_code_str(CMP_E_RESPONSE_TOO_LARGE));
    }
    return 0;
}
