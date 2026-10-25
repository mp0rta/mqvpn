// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef MGMT_RPC_H
#define MGMT_RPC_H

#include "json_util.h"

#include <stddef.h>

/* One response line: malloc'd, LF-terminated. */
typedef struct {
    char *buf;
    size_t len;
} mgmt_line_t;

typedef struct {
    yyjson_doc *doc;    /* parsed request; release with mgmt_rpc_request_free() */
    yyjson_val *id;     /* integer or string */
    const char *method; /* NUL-terminated inside doc */
    yyjson_val *params; /* object, or NULL when absent */
} mgmt_request_t;

/* 0 = request (req valid); 1 = notification (no reply; req->doc already freed);
 * -1 = error: *err_code is PARSE_ERROR / INVALID_REQUEST / INVALID_PARAMS and *err_id
 * the recovered id (NULL if none; it points into req->doc, so free req after use). */
int mgmt_rpc_parse(const char *line, size_t len, mgmt_request_t *req, int *err_code,
                   yyjson_val **err_id);
void mgmt_rpc_request_free(mgmt_request_t *req);

/* Build one reply line in doc (id copied, NULL -> null). result_line returns 0 = ok,
 * 1 = replaced by a RESPONSE_TOO_LARGE error line, 2 = replaced by an INTERNAL_ERROR
 * line (result not serializable, e.g. invalid UTF-8), -1 = allocation failure.
 * error_line: message NULL = default; data_extra (object or NULL) is merged into
 * error.data next to "name"; 0 = ok, -1 = failure. */
int mgmt_rpc_result_line(yyjson_mut_doc *doc, yyjson_val *id, yyjson_mut_val *result,
                         mgmt_line_t *out);
int mgmt_rpc_error_line(yyjson_mut_doc *doc, yyjson_val *id, int code,
                        const char *message, yyjson_mut_val *data_extra,
                        mgmt_line_t *out);
/* Server -> client notification line. 0 = ok, -1 = failure. */
int mgmt_rpc_notification_line(yyjson_mut_doc *doc, const char *method,
                               yyjson_mut_val *params, mgmt_line_t *out);

#endif /* MGMT_RPC_H */
