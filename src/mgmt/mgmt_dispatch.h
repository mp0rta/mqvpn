// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* src/mgmt/mgmt_dispatch.h — OS-neutral CMP request dispatcher.
 *
 * No OS / libevent / libmqvpn dependencies allowed here (mirrors
 * cmp_types.h / cmp_json.h). The socket layer (mgmt_socket.h, a later task)
 * owns the fd/libevent plumbing and calls mgmt_dispatch_request() once per
 * complete NDJSON request line.
 */
#ifndef MQVPN_MGMT_DISPATCH_H
#define MQVPN_MGMT_DISPATCH_H
#include <stddef.h>

/* Immutable endpoint-side context (built once at startup, then read-only).
 * Tagged struct — mgmt_socket.h forward-declares `struct mgmt_ctx`. */
typedef struct mgmt_ctx {
    const char *endpoint_version;    /* real wiring passes mqvpn_version_string();
                                      * test hosts pass a fixed string */
    const char *const *capabilities; /* Phase 1: empty array */
    size_t n_capabilities;
} mgmt_ctx_t;

/* Per-connection state. Single writer: the socket layer's read callback. */
typedef struct {
    int handshake_done;
} mgmt_conn_t;

/* Process one request line (no LF/CR) and write exactly one response line
 * (trailing LF included) to out. A response line is ALWAYS written for any
 * input (never crashing is the contract). The return value is the
 * response's error code (a cmp_error_code_t; CMP_E_OK for ok:true
 * responses) — informational only, so the socket layer can log e.g.
 * invalid requests without re-parsing the response it just wrote.
 * Caller contract: `line` MUST be NUL-terminated at line[len] (the json_mini
 * helpers walk C strings); `len` is the string length. evbuffer_readln and
 * the CLI both naturally provide this.
 * Requires out_cap >= CMP_MIN_RESPONSE_BUF (256 — the fixed short
 * RESPONSE_TOO_LARGE fallback always fits; defined in cmp_types.h). If the
 * real response does not fit in out_cap, it is replaced by that fallback
 * (and the return value becomes CMP_E_RESPONSE_TOO_LARGE). */
int mgmt_dispatch_request(const mgmt_ctx_t *ctx, mgmt_conn_t *conn, const char *line,
                          size_t len, char *out, size_t out_cap);

#endif
