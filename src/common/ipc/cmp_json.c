// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* src/common/ipc/cmp_json.c — bounded append-only JSON writer + minimal
 * array-membership helper for CMP.
 */
#include "cmp_json.h"

#include "json_mini.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

void
cmp_buf_init(cmp_buf_t *b, char *storage, size_t cap)
{
    b->buf = storage;
    b->cap = cap;
    b->len = 0;
    b->overflow = 0;
    if (cap > 0) {
        storage[0] = '\0';
    }
}

/* Append raw bytes, honoring the overflow gate: once set (or once the write
 * would not fit), no further bytes are copied and overflow stays latched. */
static void
cmp_buf_append_raw(cmp_buf_t *b, const char *data, size_t n)
{
    if (b->overflow) return;
    /* Reserve 1 byte for the NUL terminator so buf is always a valid
     * C string after any successful append. */
    if (b->len + n >= b->cap) {
        b->overflow = 1;
        return;
    }
    memcpy(b->buf + b->len, data, n);
    b->len += n;
    b->buf[b->len] = '\0';
}

void
cmp_buf_appendf(cmp_buf_t *b, const char *fmt, ...)
{
    if (b->overflow) return;

    va_list ap;
    va_start(ap, fmt);
    /* Snapshot remaining space (cap always leaves room for NUL). */
    size_t avail = (b->len < b->cap) ? (b->cap - b->len) : 0;
    int n = vsnprintf(b->buf + b->len, avail, fmt, ap);
    va_end(ap);

    if (n < 0) {
        b->overflow = 1;
        return;
    }
    if ((size_t)n >= avail) {
        /* Would have been truncated by vsnprintf: treat as overflow and
         * discard the partial write so we never emit truncated JSON. */
        b->overflow = 1;
        if (b->len < b->cap) {
            b->buf[b->len] = '\0';
        }
        return;
    }
    b->len += (size_t)n;
}

void
cmp_json_append_str(cmp_buf_t *b, const char *s)
{
    if (b->overflow) return;

    cmp_buf_append_raw(b, "\"", 1);
    if (b->overflow) return;

    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (b->overflow) return;
        switch (*p) {
        case '"': cmp_buf_append_raw(b, "\\\"", 2); break;
        case '\\': cmp_buf_append_raw(b, "\\\\", 2); break;
        case '\n': cmp_buf_append_raw(b, "\\n", 2); break;
        case '\r': cmp_buf_append_raw(b, "\\r", 2); break;
        case '\t': cmp_buf_append_raw(b, "\\t", 2); break;
        default:
            if (*p < 0x20) {
                char esc[8];
                int n = snprintf(esc, sizeof(esc), "\\u%04x", (unsigned)*p);
                cmp_buf_append_raw(b, esc, (size_t)n);
            } else {
                char c = (char)*p;
                cmp_buf_append_raw(b, &c, 1);
            }
            break;
        }
    }
    if (b->overflow) return;
    cmp_buf_append_raw(b, "\"", 1);
}

int
cmp_json_array_contains_str(const char *json, const char *key, const char *want)
{
    const char *v = json_find_key(json, key);
    if (!v) return 0;
    v = json_skip_ws(v);
    if (*v != '[') return 0;

    size_t want_len = strlen(want);
    const char *p = v + 1;
    for (;;) {
        p = json_skip_ws(p);
        if (*p == ']' || *p == '\0') break;
        if (*p != '"') {
            /* Non-string element: not supported, skip to next comma/']'. */
            while (*p && *p != ',' && *p != ']')
                p++;
        } else {
            const char *start = p + 1;
            const char *e = start;
            while (*e && *e != '"') {
                if (*e == '\\' && e[1]) e++;
                e++;
            }
            if (*e != '"') break; /* unterminated string */
            if ((size_t)(e - start) == want_len && strncmp(start, want, want_len) == 0) {
                return 1;
            }
            p = e + 1;
        }
        p = json_skip_ws(p);
        if (*p == ',') {
            p++;
            continue;
        }
        break;
    }
    return 0;
}
