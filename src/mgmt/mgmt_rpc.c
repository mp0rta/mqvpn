// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#include "mgmt_rpc.h"

#include "cmp_error.h"
#include "cmp_proto.h"

#include <stdlib.h>

int
mgmt_rpc_parse(const char *line, size_t len, mgmt_request_t *req, int *err_code,
               yyjson_val **err_id)
{
    memset(req, 0, sizeof(*req));
    *err_id = NULL;
    req->doc = yyjson_read_opts((char *)line, len, YYJSON_READ_NOFLAG, NULL, NULL);
    if (!req->doc) {
        *err_code = CMP_E_PARSE_ERROR;
        return -1;
    }
    yyjson_val *root = yyjson_doc_get_root(req->doc);
    if (!yyjson_is_obj(root)) {
        *err_code = CMP_E_INVALID_REQUEST;
        return -1;
    }
    yyjson_val *id = yyjson_obj_get(root, "id");
    if (!id || yyjson_is_null(id)) {
        mgmt_rpc_request_free(req);
        return 1;
    }
    if (!yyjson_is_int(id) && !yyjson_is_str(id)) {
        *err_code = CMP_E_INVALID_REQUEST;
        return -1;
    }
    *err_id = id;
    req->id = id;

    yyjson_val *ver = yyjson_obj_get(root, "jsonrpc");
    yyjson_val *m = yyjson_obj_get(root, "method");
    if (!yyjson_is_str(ver) || strcmp(yyjson_get_str(ver), "2.0") != 0 ||
        yyjson_get_len(ver) != 3 || !yyjson_is_str(m) ||
        strlen(yyjson_get_str(m)) != yyjson_get_len(m)) {
        *err_code = CMP_E_INVALID_REQUEST;
        return -1;
    }
    req->method = yyjson_get_str(m);

    yyjson_val *p = yyjson_obj_get(root, "params");
    if (p && !yyjson_is_obj(p)) {
        *err_code = CMP_E_INVALID_PARAMS;
        return -1;
    }
    req->params = p;
    return 0;
}

void
mgmt_rpc_request_free(mgmt_request_t *req)
{
    yyjson_doc_free(req->doc);
    memset(req, 0, sizeof(*req));
}

/* Serialize doc's root into out (+ LF). Invalid UTF-8 fails the write. */
static int
write_line(yyjson_mut_doc *doc, mgmt_line_t *out)
{
    size_t len = 0;
    char *s = yyjson_mut_write_opts(doc, YYJSON_WRITE_NOFLAG, NULL, &len, NULL);
    if (!s) return -1;
    char *t = realloc(s, len + 2);
    if (!t) {
        free(s);
        return -1;
    }
    t[len] = '\n';
    t[len + 1] = '\0';
    out->buf = t;
    out->len = len + 1;
    return 0;
}

/* Start the reply object: {"jsonrpc":"2.0"}. */
static yyjson_mut_val *
begin_object(yyjson_mut_doc *doc)
{
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    if (!root || !yyjson_mut_obj_add_str(doc, root, "jsonrpc", "2.0")) return NULL;
    yyjson_mut_doc_set_root(doc, root);
    return root;
}

static int
build_with_id(yyjson_mut_doc *doc, yyjson_val *id, const char *key, yyjson_mut_val *val,
              mgmt_line_t *out)
{
    yyjson_mut_val *root = begin_object(doc);
    yyjson_mut_val *idv = id ? yyjson_val_mut_copy(doc, id) : yyjson_mut_null(doc);
    if (!root || !idv || !val || !yyjson_mut_obj_add_val(doc, root, "id", idv) ||
        !yyjson_mut_obj_add_val(doc, root, key, val))
        return -1;
    return write_line(doc, out);
}

int
mgmt_rpc_error_line(yyjson_mut_doc *doc, yyjson_val *id, int code, const char *message,
                    yyjson_mut_val *data_extra, mgmt_line_t *out)
{
    const char *name = cmp_error_name(code);
    if (!message) message = cmp_error_message(code);
    yyjson_mut_val *err = yyjson_mut_obj(doc);
    yyjson_mut_val *data = yyjson_mut_obj(doc);
    if (!err || !data || !yyjson_mut_obj_add_int(doc, err, "code", code) ||
        !yyjson_mut_obj_add_strcpy(doc, err, "message", message ? message : "") ||
        !yyjson_mut_obj_add_strcpy(doc, data, "name", name ? name : ""))
        return -1;
    if (yyjson_mut_is_obj(data_extra)) {
        yyjson_mut_obj_iter it = yyjson_mut_obj_iter_with(data_extra);
        yyjson_mut_val *k;
        while ((k = yyjson_mut_obj_iter_next(&it)) != NULL) {
            /* copy: a node cannot live in two containers */
            yyjson_mut_val *kc = yyjson_mut_val_mut_copy(doc, k);
            yyjson_mut_val *vc =
                yyjson_mut_val_mut_copy(doc, yyjson_mut_obj_iter_get_val(k));
            if (!kc || !vc || !yyjson_mut_obj_add(data, kc, vc)) return -1;
        }
    }
    if (!yyjson_mut_obj_add_val(doc, err, "data", data)) return -1;
    return build_with_id(doc, id, "error", err, out);
}

/* Fresh-doc error line used when the original reply cannot be sent. */
static int
replacement_error(yyjson_val *id, int code, mgmt_line_t *out)
{
    yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
    if (!d) return -1;
    int rc = mgmt_rpc_error_line(d, id, code, NULL, NULL, out);
    yyjson_mut_doc_free(d);
    return rc;
}

int
mgmt_rpc_result_line(yyjson_mut_doc *doc, yyjson_val *id, yyjson_mut_val *result,
                     mgmt_line_t *out)
{
    mgmt_line_t line = {0};
    if (build_with_id(doc, id, "result", result, &line) != 0)
        return replacement_error(id, CMP_E_INTERNAL_ERROR, out) == 0 ? 2 : -1;
    if (line.len > CMP_MAX_RESPONSE_LINE) {
        free(line.buf);
        return replacement_error(id, CMP_E_RESPONSE_TOO_LARGE, out) == 0 ? 1 : -1;
    }
    *out = line;
    return 0;
}

int
mgmt_rpc_notification_line(yyjson_mut_doc *doc, const char *method,
                           yyjson_mut_val *params, mgmt_line_t *out)
{
    yyjson_mut_val *root = begin_object(doc);
    if (!root || !yyjson_mut_obj_add_strcpy(doc, root, "method", method)) return -1;
    if (params && !yyjson_mut_obj_add_val(doc, root, "params", params)) return -1;
    return write_line(doc, out);
}
