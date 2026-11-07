// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#include "ctl_rpc.h"

#include "cmp_error.h"
#include "cmp_proto.h"

#include <stdlib.h>

int
ctl_rpc_connect(ctl_sock_t *s, const char *path, int timeout_ms, ctl_sock_err_t *sock_err)
{
    int e = ctl_sock_connect(s, path, timeout_ms);
    if (e == CTL_SOCK_OK) return 0;
    if (sock_err) *sock_err = (ctl_sock_err_t)e;
    return CTL_RPC_E_CONNECT;
}

void
ctl_reply_free(ctl_reply_t *r)
{
    if (r->doc) yyjson_doc_free(r->doc); /* tolerates an already-zeroed reply */
    memset(r, 0, sizeof(*r));
}

/* Request line (with trailing LF) as an exact-size malloc buffer. */
static char *
build_request(int id, const char *method, yyjson_mut_doc *pdoc, yyjson_mut_val *params,
              size_t *len)
{
    yyjson_mut_doc *own = NULL;
    yyjson_mut_doc *d = pdoc;
    if (!d) d = own = yyjson_mut_doc_new(NULL);
    if (!d) return NULL;
    char *out = NULL;
    yyjson_mut_val *root = yyjson_mut_obj(d);
    if (root && yyjson_mut_obj_add_str(d, root, "jsonrpc", "2.0") &&
        yyjson_mut_obj_add_int(d, root, "id", id) &&
        yyjson_mut_obj_add_str(d, root, "method", method) &&
        (!params || yyjson_mut_obj_add_val(d, root, "params", params))) {
        yyjson_mut_doc_set_root(d, root);
        size_t n = 0;
        out = yyjson_mut_write_opts(d, 0, NULL, &n, NULL);
        if (out) {
            out[n] = '\n'; /* yyjson allocated n + 1 bytes for the NUL */
            *len = n + 1;
        }
    }
    yyjson_mut_doc_free(own);
    return out;
}

/* Fills *reply only on OK / E_REMOTE; the caller frees the doc on any other status. */
static int
validate_reply(yyjson_doc *doc, int id, ctl_reply_t *reply)
{
    yyjson_val *root = yyjson_doc_get_root(doc);
    if (!yyjson_is_obj(root)) return CTL_RPC_E_PROTOCOL;
    yyjson_val *ver = yyjson_obj_get(root, "jsonrpc");
    if (!yyjson_is_str(ver) || strcmp(yyjson_get_str(ver), "2.0") != 0)
        return CTL_RPC_E_PROTOCOL;
    yyjson_val *res = yyjson_obj_get(root, "result");
    yyjson_val *err = yyjson_obj_get(root, "error");
    if ((res != NULL) == (err != NULL)) return CTL_RPC_E_PROTOCOL;
    yyjson_val *idv = yyjson_obj_get(root, "id");
    int ecode = 0;
    if (err && (!yyjson_is_obj(err) || json_get_int(yyjson_obj_get(err, "code"), &ecode)))
        return CTL_RPC_E_PROTOCOL;
    /* a connection-level error (BUSY, unparsable line) carries "id": null */
    if (!err || !yyjson_is_null(idv)) {
        int rid;
        if (json_get_int(idv, &rid) != 0 || rid != id) return CTL_RPC_E_PROTOCOL;
    }
    memset(reply, 0, sizeof(*reply));
    reply->doc = doc;
    if (res) {
        reply->result = res;
        return CTL_RPC_OK;
    }
    reply->error = err;
    reply->error_code = ecode;
    return CTL_RPC_E_REMOTE;
}

int
ctl_rpc_call(ctl_sock_t *s, int id, const char *method, yyjson_mut_doc *pdoc,
             yyjson_mut_val *params, int timeout_ms, ctl_reply_t *reply,
             ctl_sock_err_t *sock_err)
{
    memset(reply, 0, sizeof(*reply));
    size_t len = 0;
    char *req = build_request(id, method, pdoc, params, &len);
    if (!req) {
        *sock_err = CTL_SOCK_E_IO;
        return CTL_RPC_E_SOCK;
    }
    int se = ctl_sock_send_all(s, req, len, timeout_ms);
    free(req);
    int e = se;
    /* A full endpoint answers BUSY and closes at accept, so the request can fail with
     * EPIPE while that reply is already waiting: read it before reporting the error. */
    if (se == CTL_SOCK_OK || se == CTL_SOCK_E_IO) {
        const char *line;
        size_t line_len;
        e = ctl_sock_recv_line(s, CMP_MAX_RESPONSE_LINE, timeout_ms, &line, &line_len);
        if (e != CTL_SOCK_OK && se != CTL_SOCK_OK) e = se;
        if (e == CTL_SOCK_OK) {
            yyjson_doc *doc = yyjson_read(line, line_len, 0);
            if (!doc) return CTL_RPC_E_PROTOCOL;
            int st = validate_reply(doc, id, reply);
            if (st == CTL_RPC_E_PROTOCOL) yyjson_doc_free(doc);
            return st;
        }
    }
    *sock_err = (ctl_sock_err_t)e;
    return e == CTL_SOCK_E_TIMEOUT ? CTL_RPC_E_TIMEOUT : CTL_RPC_E_SOCK;
}

int
ctl_rpc_hello(ctl_sock_t *s, int timeout_ms, ctl_reply_t *reply, ctl_sock_err_t *sock_err)
{
    yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *p = d ? yyjson_mut_obj(d) : NULL;
    yyjson_mut_val *vers = d ? yyjson_mut_arr(d) : NULL;
    if (!p || !vers || !yyjson_mut_arr_add_str(d, vers, CMP_VERSION) ||
        !yyjson_mut_obj_add_str(d, p, "client_name", "mqvpnctl") ||
        !yyjson_mut_obj_add_str(d, p, "client_version", CTL_VERSION_STR) ||
        !yyjson_mut_obj_add_val(d, p, "cmp_versions", vers)) {
        yyjson_mut_doc_free(d);
        memset(reply, 0, sizeof(*reply));
        *sock_err = CTL_SOCK_E_IO;
        return CTL_RPC_E_SOCK;
    }
    int st = ctl_rpc_call(s, 1, "system.hello", d, p, timeout_ms, reply, sock_err);
    yyjson_mut_doc_free(d);
    return st;
}

int
ctl_exit_code_for(ctl_rpc_status_t st, ctl_sock_err_t sock_err, int remote_code)
{
    switch (st) {
    case CTL_RPC_OK: return 0;
    case CTL_RPC_E_CONNECT:
        if (sock_err == CTL_SOCK_E_ACCESS) return 4;
        if (sock_err == CTL_SOCK_E_TIMEOUT) return 8;
        return 5;
    case CTL_RPC_E_SOCK: return 1;
    case CTL_RPC_E_TIMEOUT: return 8;
    case CTL_RPC_E_PROTOCOL: return 9;
    case CTL_RPC_E_REMOTE:
        if (remote_code == CMP_E_PERMISSION_DENIED) return 4;
        if (remote_code == CMP_E_PROTOCOL_INCOMPATIBLE) return 9;
        if (remote_code >= 1000 && remote_code <= 1999) return 6;
        return 1;
    }
    return 1;
}
