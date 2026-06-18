// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * json_mini.h — Minimal JSON parsing helpers (static inline)
 *
 * Shared across config.c, mqvpn_config.c, control_socket.c, status.c.
 * No dependencies beyond libc.
 */
#ifndef MQVPN_JSON_MINI_H
#define MQVPN_JSON_MINI_H

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static inline const char *
json_skip_ws(const char *p)
{
    while (*p && isspace((unsigned char)*p))
        p++;
    return p;
}

/* Find a key in a JSON object. Returns pointer to the value, or NULL. */
static inline const char *
json_find_key(const char *json, const char *key)
{
    size_t key_len = strlen(key);
    const char *p = json;

    while ((p = strchr(p, '"')) != NULL) {
        const char *k = p + 1;
        const char *e = k;
        while (*e && *e != '"') {
            if (*e == '\\' && e[1]) e++;
            e++;
        }
        if (*e != '"') return NULL;

        if ((size_t)(e - k) == key_len && strncmp(k, key, key_len) == 0) {
            const char *c = json_skip_ws(e + 1);
            if (*c == ':') {
                return json_skip_ws(c + 1);
            }
        }
        p = e + 1;
    }
    return NULL;
}

/* Pointer to the '}' that closes the object beginning at `obj` (must point at
 * '{'), accounting for nesting and braces inside string literals. NULL if
 * unterminated. */
static inline const char *
json_object_end(const char *obj)
{
    if (!obj || *obj != '{') return NULL;
    int depth = 0, in_str = 0;
    for (const char *p = obj; *p; p++) {
        if (in_str) {
            if (*p == '\\' && p[1]) {
                p++;
                continue;
            }
            if (*p == '"') in_str = 0;
            continue;
        }
        if (*p == '"')
            in_str = 1;
        else if (*p == '{')
            depth++;
        else if (*p == '}' && --depth == 0)
            return p;
    }
    return NULL;
}

/* json_find_key bounded to [obj, obj_end): returns the value pointer only if it
 * lies before obj_end (i.e. belongs to this object, not a sibling). */
static inline const char *
json_find_key_bounded(const char *obj, const char *obj_end, const char *key)
{
    const char *v = json_find_key(obj, key);
    return (v && obj_end && v < obj_end) ? v : NULL;
}

/* Read a JSON string value. Returns 0 on success, -1 on error. */
static inline int
json_read_string(const char *p, char *out, size_t out_len)
{
    if (!p || !out || out_len == 0 || *p != '"') return -1;
    p++;
    size_t j = 0;
    while (*p && *p != '"') {
        if (*p == '\\' && p[1]) p++;
        if (j + 1 < out_len) out[j++] = *p;
        p++;
    }
    if (*p != '"') return -1;
    out[j] = '\0';
    return 0;
}

/* Read a JSON boolean value. Returns 0 on success, -1 on error. */
static inline int
json_read_bool(const char *p, int *out)
{
    if (!p || !out) return -1;
    if (strncmp(p, "true", 4) == 0) {
        *out = 1;
        return 0;
    }
    if (strncmp(p, "false", 5) == 0) {
        *out = 0;
        return 0;
    }
    return -1;
}

/* Read a JSON integer value (int). Returns 0 on success, -1 on error. */
static inline int
json_read_int(const char *p, int *out)
{
    if (!p || !out) return -1;
    char *end = NULL;
    long v = strtol(p, &end, 10);
    if (end == p) return -1;
    *out = (int)v;
    return 0;
}

/* Read a JSON integer value (int64_t). Returns 0 or the value itself. */
static inline int64_t
json_read_int64(const char *p)
{
    if (!p) return 0;
    return strtoll(p, NULL, 10);
}

/* True when a parsed JSON scalar stops before a legal delimiter. */
static inline int
json_value_has_valid_end(const char *p)
{
    p = json_skip_ws(p);
    return *p == '\0' || *p == ',' || *p == '}' || *p == ']';
}

/* Strict JSON integer reader: returns 0 on success, -1 on error. Rejects
 * non-numeric prefixes, overflow, and trailing junk such as `123abc`. */
static inline int
json_read_int_strict(const char *p, int *out)
{
    if (!p || !out) return -1;
    p = json_skip_ws(p);
    if (*p != '-' && (*p < '0' || *p > '9')) return -1;

    errno = 0;
    char *end = NULL;
    long v = strtol(p, &end, 10);
    if (end == p || errno == ERANGE || v < INT_MIN || v > INT_MAX ||
        !json_value_has_valid_end(end)) {
        return -1;
    }

    *out = (int)v;
    return 0;
}

static inline int
json_read_u64_strict(const char *p, uint64_t *out)
{
    if (!p || !out) return -1;
    p = json_skip_ws(p);
    if (*p < '0' || *p > '9') return -1;

    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(p, &end, 10);
    if (end == p || errno == ERANGE || !json_value_has_valid_end(end)) {
        return -1;
    }

    *out = (uint64_t)v;
    return 0;
}

/* Safe string copy with NUL termination. */
static inline void
mqvpn_copy_str(char *dst, size_t dst_len, const char *src)
{
    if (!dst || dst_len == 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    strncpy(dst, src, dst_len - 1);
    dst[dst_len - 1] = '\0';
}

#endif /* MQVPN_JSON_MINI_H */
