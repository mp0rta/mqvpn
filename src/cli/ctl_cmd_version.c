// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#include "ctl_cmd.h"

#include "cmp_endpoint.h"
#include "cmp_error.h"

#include <stdio.h>
#include <stdlib.h>

void
ctl_emit_error(const ctl_opts_t *o, int code, const char *message,
               yyjson_val *remote_error)
{
    const char *text = message;
    if (remote_error) {
        const char *m = yyjson_get_str(yyjson_obj_get(remote_error, "message"));
        if (m) text = m;
    }
    if (!o->json) {
        fprintf(stderr, "mqvpnctl: %s\n", text);
        return;
    }

    yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = d ? yyjson_mut_obj(d) : NULL;
    yyjson_mut_val *err = NULL;
    if (root) {
        yyjson_mut_doc_set_root(d, root);
        if (remote_error) {
            err = yyjson_val_mut_copy(d, remote_error);
        } else {
            const char *name = cmp_error_name(code);
            err = yyjson_mut_obj(d);
            yyjson_mut_val *data = yyjson_mut_obj(d);
            if (!err || !data || !yyjson_mut_obj_add_int(d, err, "code", code) ||
                !yyjson_mut_obj_add_str(d, err, "message", message) ||
                !yyjson_mut_obj_add_str(d, data, "name", name ? name : "") ||
                !yyjson_mut_obj_add_val(d, err, "data", data))
                err = NULL;
        }
    }
    char *out = err && yyjson_mut_obj_add_val(d, root, "error", err)
                    ? yyjson_mut_write_opts(d, 0, NULL, NULL, NULL)
                    : NULL;
    if (out)
        printf("%s\n", out);
    else
        fprintf(stderr, "mqvpnctl: %s\n", text); /* out of memory */
    free(out);
    yyjson_mut_doc_free(d);
}

/* Maps a failed call onto the CLI exit codes (remote errors pass through) and returns
 * the exit code. */
static int
fail(const ctl_opts_t *o, ctl_rpc_status_t st, ctl_sock_err_t se, ctl_reply_t *reply,
     const char *what)
{
    char msg[CMP_ENDPOINT_MAX + 96];
    int code;
    if (st == CTL_RPC_E_REMOTE) {
        ctl_emit_error(o, reply->error_code, "remote error", reply->error);
        return ctl_exit_code_for(st, se, reply->error_code);
    }
    switch (st) {
    case CTL_RPC_E_CONNECT:
        if (se == CTL_SOCK_E_ACCESS) {
            code = CMP_E_PERMISSION_DENIED;
            snprintf(msg, sizeof(msg), "permission denied connecting to %s", what);
        } else if (se == CTL_SOCK_E_TIMEOUT) {
            code = CMP_E_TIMEOUT;
            snprintf(msg, sizeof(msg), "timed out connecting to %s", what);
        } else {
            code = CMP_E_UNAVAILABLE;
            snprintf(msg, sizeof(msg), "cannot connect to %s (client not running?)",
                     what);
        }
        break;
    case CTL_RPC_E_TIMEOUT:
        code = CMP_E_TIMEOUT;
        snprintf(msg, sizeof(msg), "timed out waiting for the client");
        break;
    case CTL_RPC_E_PROTOCOL:
        code = CMP_E_PROTOCOL_INCOMPATIBLE;
        snprintf(msg, sizeof(msg), "invalid reply from the client");
        break;
    default:
        code = CMP_E_UNAVAILABLE;
        snprintf(msg, sizeof(msg), "connection to the client failed");
        break;
    }
    ctl_emit_error(o, code, msg, NULL);
    return ctl_exit_code_for(st, se, 0);
}

static const char *
str_of(yyjson_val *obj, const char *key)
{
    return yyjson_get_str(yyjson_obj_get(obj, key));
}

/* The caps array as "a, b" or "(none)". Caller frees. */
static char *
caps_text(yyjson_val *caps)
{
    size_t total = 8, idx, max;
    yyjson_val *v;
    yyjson_arr_foreach(caps, idx, max, v) total += yyjson_get_len(v) + 2;
    char *out = malloc(total);
    if (!out) return NULL;
    out[0] = '\0';
    yyjson_arr_foreach(caps, idx, max, v)
    {
        if (idx) strcat(out, ", ");
        strcat(out, yyjson_get_str(v));
    }
    if (!out[0]) strcpy(out, "(none)");
    return out;
}

static int
print_json(const ctl_opts_t *o, yyjson_val *hello)
{
    yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = d ? yyjson_mut_obj(d) : NULL;
    yyjson_mut_val *cl = d ? yyjson_mut_obj(d) : NULL;
    yyjson_mut_val *ep = d ? yyjson_mut_obj(d) : NULL;
    int ok = root && cl && ep;
    if (ok) {
        yyjson_mut_doc_set_root(d, root);
        ok = yyjson_mut_obj_add_str(d, root, "schema_version", "1.0") &&
             yyjson_mut_obj_add_str(d, cl, "name", "mqvpnctl") &&
             yyjson_mut_obj_add_str(d, cl, "version", CTL_VERSION_STR) &&
             yyjson_mut_obj_add_val(d, root, "client", cl) &&
             yyjson_mut_obj_add_strcpy(d, ep, "name", str_of(hello, "endpoint_name")) &&
             yyjson_mut_obj_add_strcpy(d, ep, "version",
                                       str_of(hello, "endpoint_version")) &&
             yyjson_mut_obj_add_strcpy(d, ep, "cmp_version",
                                       str_of(hello, "cmp_version")) &&
             yyjson_mut_obj_add_strcpy(d, ep, "role", str_of(hello, "role")) &&
             yyjson_mut_obj_add_val(
                 d, ep, "capabilities",
                 yyjson_val_mut_copy(d, yyjson_obj_get(hello, "capabilities"))) &&
             yyjson_mut_obj_add_val(d, root, "endpoint", ep);
    }
    char *out = ok ? yyjson_mut_write_opts(d, 0, NULL, NULL, NULL) : NULL;
    yyjson_mut_doc_free(d);
    if (!out) {
        ctl_emit_error(o, CMP_E_INTERNAL_ERROR, "out of memory", NULL);
        return 1;
    }
    printf("%s\n", out);
    free(out);
    return 0;
}

int
ctl_cmd_version(const ctl_opts_t *o)
{
    int ov = o->timeout_ms_override;
    ctl_sock_t s;
    ctl_sock_err_t se = CTL_SOCK_OK;
    ctl_reply_t reply;
    memset(&reply, 0, sizeof(reply));

    int st = ctl_rpc_connect(&s, o->endpoint, ov ? ov : CTL_TIMEOUT_CONNECT_MS, &se);
    if (st != 0) return fail(o, (ctl_rpc_status_t)st, se, &reply, o->endpoint);

    st = ctl_rpc_hello(&s, ov ? ov : CTL_TIMEOUT_HELLO_MS, &reply, &se);
    int rc;
    if (st != CTL_RPC_OK) {
        rc = fail(o, (ctl_rpc_status_t)st, se, &reply, o->endpoint);
        goto out;
    }

    yyjson_val *r = reply.result;
    yyjson_val *caps = yyjson_obj_get(r, "capabilities");
    yyjson_val *c;
    size_t i, n;
    int shape = str_of(r, "endpoint_name") && str_of(r, "endpoint_version") &&
                str_of(r, "cmp_version") && str_of(r, "role") && yyjson_is_arr(caps);
    if (shape) yyjson_arr_foreach(caps, i, n, c) shape = shape && yyjson_is_str(c);
    if (!shape) {
        rc = fail(o, CTL_RPC_E_PROTOCOL, 0, &reply, o->endpoint);
        goto out;
    }

    if (o->json) {
        rc = print_json(o, r);
    } else {
        char *ct = caps_text(caps);
        if (!ct) {
            ctl_emit_error(o, CMP_E_INTERNAL_ERROR, "out of memory", NULL);
            rc = 1;
        } else {
            printf("mqvpnctl %s\nendpoint: %s %s (CMP %s, role %s)\ncapabilities: %s\n",
                   CTL_VERSION_STR, str_of(r, "endpoint_name"),
                   str_of(r, "endpoint_version"), str_of(r, "cmp_version"),
                   str_of(r, "role"), ct);
            free(ct);
            rc = 0;
        }
    }
out:
    ctl_reply_free(&reply);
    ctl_sock_close(&s);
    return rc;
}
