// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef MGMT_DISPATCH_H
#define MGMT_DISPATCH_H

#include "mgmt_rpc.h"

typedef enum { MGMT_ROLE_USER = 0, MGMT_ROLE_ADMIN = 1 } mgmt_role_t;
const char *mgmt_role_name(mgmt_role_t r); /* "user" / "admin" */

typedef struct mgmt_endpoint_ctx {
    const char *endpoint_version;
    const char *const *capabilities;
    size_t n_capabilities;
} mgmt_endpoint_ctx_t;

typedef struct {
    mgmt_role_t role;   /* stamped by the listener */
    int handshake_done; /* 1 after a successful system.hello */
} mgmt_conn_state_t;

typedef struct {
    const mgmt_endpoint_ctx_t *ep;
    mgmt_conn_state_t *conn;
    yyjson_val *params;  /* object; an empty object when the request had none */
    yyjson_mut_doc *doc; /* build result / err_data here */
} mgmt_call_t;

/* 0 = ok (*result set); non-zero = error code (err_msg / err_data optional). */
typedef int (*mgmt_handler_fn)(mgmt_call_t *call, yyjson_mut_val **result,
                               const char **err_msg, yyjson_mut_val **err_data);

typedef struct {
    const char *name;
    int requires_handshake;
    mgmt_role_t min_role;
    mgmt_handler_fn fn;
} mgmt_method_t;

/* Handle one request line (no LF). 0 = *out holds one reply line (malloc'd,
 * LF-terminated); 1 = notification, no reply (*out untouched); -1 = even the
 * INTERNAL_ERROR line could not be allocated. *err_code = the reply's error code (0 for a
 * result). Never crashes. */
int mgmt_dispatch_line(const mgmt_endpoint_ctx_t *ep, mgmt_conn_state_t *conn,
                       const char *line, size_t len, mgmt_line_t *out, int *err_code);
int mgmt_dispatch_line_ex(const mgmt_method_t *table, size_t n_methods,
                          const mgmt_endpoint_ctx_t *ep, mgmt_conn_state_t *conn,
                          const char *line, size_t len, mgmt_line_t *out, int *err_code);
const mgmt_method_t *mgmt_method_table(size_t *n); /* built-in table */

#endif /* MGMT_DISPATCH_H */
