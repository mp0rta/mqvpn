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
 * (trailing LF included) to out. Always returns 0 and always produces a
 * response for any input (never crashing is the contract).
 * Requires out_cap >= CMP_MIN_RESPONSE_BUF (256 — the fixed short
 * RESPONSE_TOO_LARGE fallback always fits; defined in cmp_types.h). If the
 * real response does not fit in out_cap, it is replaced by that fallback.
 * Normal callers (the socket layer) pass a CMP_MAX_RESPONSE_BYTES scratch. */
int mgmt_dispatch_request(const mgmt_ctx_t *ctx, mgmt_conn_t *conn, const char *line,
                          size_t len, char *out, size_t out_cap);

#endif
