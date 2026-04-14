/*
 * json_mini.h — Minimal JSON parsing helpers (static inline)
 *
 * Shared across config.c, mqvpn_config.c, control_socket.c, status.c.
 * No dependencies beyond libc.
 */
#ifndef MQVPN_JSON_MINI_H
#define MQVPN_JSON_MINI_H

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>

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
