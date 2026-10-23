// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#include "mgmt_dispatch.h"

#include "cmp_error.h"
#include "cmp_proto.h"

static yyjson_mut_val *
identity(mgmt_call_t *c, int with_role)
{
    yyjson_mut_doc *d = c->doc;
    yyjson_mut_val *r = yyjson_mut_obj(d);
    if (!r || !yyjson_mut_obj_add_str(d, r, "endpoint_name", CMP_ENDPOINT_NAME) ||
        !yyjson_mut_obj_add_strcpy(d, r, "endpoint_version", c->ep->endpoint_version) ||
        !yyjson_mut_obj_add_str(d, r, "cmp_version", CMP_VERSION))
        return NULL;
    if (with_role && !yyjson_mut_obj_add_str(d, r, "role", mgmt_role_name(c->conn->role)))
        return NULL;
    return r;
}

static yyjson_mut_val *
caps_array(mgmt_call_t *c)
{
    yyjson_mut_val *a = yyjson_mut_arr(c->doc);
    for (size_t i = 0; a && i < c->ep->n_capabilities; i++)
        if (!yyjson_mut_arr_add_strcpy(c->doc, a, c->ep->capabilities[i])) return NULL;
    return a;
}

static int
sys_hello(mgmt_call_t *c, yyjson_mut_val **result, const char **err_msg,
          yyjson_mut_val **err_data)
{
    (void)err_msg;
    yyjson_val *vers = yyjson_obj_get(c->params, "cmp_versions");
    if (!yyjson_is_arr(vers)) return CMP_E_INVALID_PARAMS;
    int found = 0;
    yyjson_arr_iter it = yyjson_arr_iter_with(vers);
    yyjson_val *v;
    while ((v = yyjson_arr_iter_next(&it)) != NULL) {
        if (!yyjson_is_str(v)) return CMP_E_INVALID_PARAMS;
        if (strcmp(yyjson_get_str(v), CMP_VERSION) == 0) found = 1;
    }
    if (!found) {
        yyjson_mut_doc *d = c->doc;
        yyjson_mut_val *extra = yyjson_mut_obj(d), *det = yyjson_mut_obj(d),
                       *sup = yyjson_mut_arr(d);
        if (extra && det && sup && yyjson_mut_arr_add_str(d, sup, CMP_VERSION) &&
            yyjson_mut_obj_add_val(d, det, "supported", sup) &&
            yyjson_mut_obj_add_val(d, extra, "details", det))
            *err_data = extra;
        return CMP_E_PROTOCOL_INCOMPATIBLE;
    }
    yyjson_mut_val *r = identity(c, 1);
    yyjson_mut_val *caps = caps_array(c);
    if (!r || !caps || !yyjson_mut_obj_add_val(c->doc, r, "capabilities", caps))
        return CMP_E_INTERNAL_ERROR;
    c->conn->handshake_done = 1;
    *result = r;
    return 0;
}

static int
sys_version(mgmt_call_t *c, yyjson_mut_val **result, const char **err_msg,
            yyjson_mut_val **err_data)
{
    (void)err_msg;
    (void)err_data;
    *result = identity(c, 0);
    return *result ? 0 : CMP_E_INTERNAL_ERROR;
}

static int
sys_capabilities(mgmt_call_t *c, yyjson_mut_val **result, const char **err_msg,
                 yyjson_mut_val **err_data)
{
    (void)err_msg;
    (void)err_data;
    yyjson_mut_val *r = yyjson_mut_obj(c->doc);
    yyjson_mut_val *caps = caps_array(c);
    if (!r || !caps || !yyjson_mut_obj_add_val(c->doc, r, "capabilities", caps))
        return CMP_E_INTERNAL_ERROR;
    *result = r;
    return 0;
}

static int
sys_ping(mgmt_call_t *c, yyjson_mut_val **result, const char **err_msg,
         yyjson_mut_val **err_data)
{
    (void)err_msg;
    (void)err_data;
    *result = yyjson_mut_obj(c->doc);
    return *result ? 0 : CMP_E_INTERNAL_ERROR;
}

static const mgmt_method_t k_table[] = {
    {"system.hello", 0, MGMT_ROLE_USER, sys_hello},
    {"system.version", 1, MGMT_ROLE_ADMIN, sys_version},
    {"system.capabilities", 1, MGMT_ROLE_ADMIN, sys_capabilities},
    {"system.ping", 1, MGMT_ROLE_ADMIN, sys_ping},
};

const mgmt_method_t *
mgmt_method_table(size_t *n)
{
    *n = sizeof(k_table) / sizeof(k_table[0]);
    return k_table;
}
