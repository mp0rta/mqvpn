// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * json_util.h — small yyjson helpers shared by the JSON readers (static inline)
 *
 * Every helper returns -1 for a NULL value, so the result of yyjson_obj_get()
 * for an absent key can be passed straight in.
 */
#ifndef MQVPN_JSON_UTIL_H
#define MQVPN_JSON_UTIL_H

#include "yyjson.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if YYJSON_VERSION_MAJOR != 0 || YYJSON_VERSION_MINOR != 13 || YYJSON_VERSION_PATCH != 0
#  error "mqvpn expects the vendored yyjson 0.13.0 (third_party/yyjson)"
#endif

/* String without an embedded NUL: copy at most out_len - 1 bytes into out,
 * NUL-terminate it and return 0. Anything else (or out_len 0): -1, out
 * unchanged. */
static inline int
json_copy_str(const yyjson_val *val, char *out, size_t out_len)
{
    const char *s = yyjson_get_str(val);
    size_t len = yyjson_get_len(val);
    if (!s || strlen(s) != len || out_len == 0) return -1;
    if (len > out_len - 1) len = out_len - 1;
    memcpy(out, s, len);
    out[len] = '\0';
    return 0;
}

/* Integer within INT_MIN..INT_MAX: store it and return 0. Anything else
 * (real, string, bool, out of range): -1. */
static inline int
json_get_int(const yyjson_val *val, int *out)
{
    if (yyjson_is_sint(val)) {
        int64_t v = yyjson_get_sint(val);
        if (v < INT_MIN || v > INT_MAX) return -1;
        *out = (int)v;
        return 0;
    }
    if (yyjson_is_uint(val)) {
        uint64_t v = yyjson_get_uint(val);
        if (v > (uint64_t)INT_MAX) return -1;
        *out = (int)v;
        return 0;
    }
    return -1;
}

/* Non-negative integer: store it and return 0. Negative, real or string: -1. */
static inline int
json_get_u64(const yyjson_val *val, uint64_t *out)
{
    if (!yyjson_is_uint(val)) return -1;
    *out = yyjson_get_uint(val);
    return 0;
}

/* "users" array shared by the file config and the Config API. Elements are
 * "name:key" strings (split at the first ':', the pair capped at 359 bytes
 * like the INI User= parser) or {"name":"..","key":".."} objects. Each pair
 * goes to add_user(ctx, name, key). Returns -1 if arr is not an array, an
 * element has the wrong shape, or add_user returns non-zero; elements before
 * the failing one stay applied. */
static inline int
mqvpn_json_parse_users(yyjson_val *arr, void *ctx,
                       int (*add_user)(void *, const char *, const char *))
{
    if (!yyjson_is_arr(arr) || !add_user) return -1;

    yyjson_arr_iter it = yyjson_arr_iter_with(arr);
    yyjson_val *el;
    while ((el = yyjson_arr_iter_next(&it)) != NULL) {
        char name[64];
        char key[256];
        if (yyjson_is_str(el)) {
            char pair[360];
            if (json_copy_str(el, pair, sizeof(pair)) < 0) return -1;
            char *sep = strchr(pair, ':');
            if (!sep || (size_t)(sep - pair) >= sizeof(name)) return -1;
            *sep = '\0';
            snprintf(name, sizeof(name), "%.*s", (int)(sizeof(name) - 1), pair);
            snprintf(key, sizeof(key), "%.*s", (int)(sizeof(key) - 1), sep + 1);
        } else if (yyjson_is_obj(el)) {
            if (yyjson_get_len(yyjson_obj_get(el, "name")) >= sizeof(name) ||
                json_copy_str(yyjson_obj_get(el, "name"), name, sizeof(name)) < 0 ||
                json_copy_str(yyjson_obj_get(el, "key"), key, sizeof(key)) < 0)
                return -1;
        } else {
            return -1;
        }
        if (add_user(ctx, name, key) != 0) return -1;
    }
    return 0;
}

#endif /* MQVPN_JSON_UTIL_H */
