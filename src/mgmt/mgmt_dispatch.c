// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#include "mgmt_dispatch.h"

#include "cmp_error.h"

#include <stdlib.h>

/* params stand-in when the request omitted them: yyjson readers treat a zero-length
 * object as empty without touching it. */
static yyjson_val g_empty_params = {YYJSON_TYPE_OBJ | YYJSON_SUBTYPE_NONE, {0}};

const char *
mgmt_role_name(mgmt_role_t r)
{
    return r == MGMT_ROLE_ADMIN ? "admin" : "user";
}

int
mgmt_dispatch_line_ex(const mgmt_method_t *table, size_t n_methods,
                      const mgmt_endpoint_ctx_t *ep, mgmt_conn_state_t *conn,
                      const char *line, size_t len, mgmt_line_t *out, int *err_code)
{
    mgmt_request_t req;
    yyjson_val *eid = NULL;
    int code = 0;
    *err_code = 0;

    int pr = mgmt_rpc_parse(line, len, &req, &code, &eid);
    if (pr == 1) return 1;

    int rc = -1;
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    if (!doc) goto done;

    const mgmt_method_t *m = NULL;
    yyjson_mut_val *result = NULL, *edata = NULL;
    const char *emsg = NULL;

    if (pr < 0) {
        /* code/eid already set by the parser */
    } else {
        for (size_t i = 0; i < n_methods; i++)
            if (strcmp(table[i].name, req.method) == 0) m = &table[i];
        eid = req.id;
        if (!m)
            code = CMP_E_METHOD_NOT_FOUND;
        else if (m->requires_handshake && !conn->handshake_done)
            code = CMP_E_HANDSHAKE_REQUIRED;
        else if (conn->role < m->min_role)
            code = CMP_E_PERMISSION_DENIED;
        else {
            mgmt_call_t call = {ep, conn, req.params ? req.params : &g_empty_params, doc};
            code = m->fn(&call, &result, &emsg, &edata);
            if (code == 0 && !result) code = CMP_E_INTERNAL_ERROR;
        }
    }

    if (code == 0) {
        int r = mgmt_rpc_result_line(doc, eid, result, out);
        rc = r < 0 ? -1 : 0;
        if (r == 1) code = CMP_E_RESPONSE_TOO_LARGE;
        if (r == 2) code = CMP_E_INTERNAL_ERROR;
    } else if (mgmt_rpc_error_line(doc, eid, code, emsg, edata, out) == 0) {
        rc = 0;
    } else {
        /* error body not serializable (e.g. invalid UTF-8 message): plain internal error
         */
        yyjson_mut_doc *d2 = yyjson_mut_doc_new(NULL);
        code = CMP_E_INTERNAL_ERROR;
        if (d2 && mgmt_rpc_error_line(d2, eid, code, NULL, NULL, out) == 0) rc = 0;
        yyjson_mut_doc_free(d2);
    }
    if (rc == 0) *err_code = code;

done:
    yyjson_mut_doc_free(doc);
    mgmt_rpc_request_free(&req);
    return rc;
}

int
mgmt_dispatch_line(const mgmt_endpoint_ctx_t *ep, mgmt_conn_state_t *conn,
                   const char *line, size_t len, mgmt_line_t *out, int *err_code)
{
    size_t n = 0;
    const mgmt_method_t *t = mgmt_method_table(&n);
    return mgmt_dispatch_line_ex(t, n, ep, conn, line, len, out, err_code);
}
