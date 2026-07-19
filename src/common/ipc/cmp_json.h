// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* src/common/ipc/cmp_json.h — bounded append-only JSON writer + minimal
 * array-membership helper for CMP.
 *
 * No OS / libevent / libmqvpn dependencies allowed here (mirrors
 * cmp_types.h). Emission-side counterpart to src/json_mini.h's parsing
 * helpers.
 */
#ifndef MQVPN_CMP_JSON_H
#define MQVPN_CMP_JSON_H
#include <stddef.h>

/* Bounded append-only writer. Writes after an overflow are ignored and the
 * overflow flag latches — the mechanism that guarantees truncated JSON is
 * never sent on the wire. */
typedef struct {
    char *buf;
    size_t cap;
    size_t len;
    int overflow;
} cmp_buf_t;

void cmp_buf_init(cmp_buf_t *b, char *storage, size_t cap);
/* printf-style append. Passing externally sourced strings through %s is
 * forbidden (they would bypass escaping) — use cmp_json_append_str for
 * string values. */
void cmp_buf_appendf(cmp_buf_t *b, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
/* Append a JSON string literal, including the surrounding quotes.
 * Escapes ", \, and U+0000-U+001F as \n/\r/\t/\uXXXX; every other byte
 * (including UTF-8 continuation bytes) passes through unmodified.
 * Limitation: `s` is a NUL-terminated C string, so embedded NUL bytes
 * cannot be represented — the string is emitted up to the first NUL. */
void cmp_json_append_str(cmp_buf_t *b, const char *s);

/* json_mini.h has no array parser, so the minimal helper Phase 1 needs
 * lives here: does the value of `key` parse as a JSON array containing the
 * string element `want`?
 * Example: cmp_json_array_contains_str(req, "supported_protocols", "1.0").
 * Returns 0 when the key is missing or the value is not an array. Elements
 * are compared against the raw JSON bytes (no unescaping), so a `want`
 * containing " or \ never matches. Nested arrays and object elements are
 * skipped, never matched into (they do not occur in CMP). */
int cmp_json_array_contains_str(const char *json, const char *key, const char *want);

/* Bounded variant: the key lookup and the array scan never consider bytes at
 * or beyond `json_end`. Used when `json` points into a larger buffer (e.g. a
 * params object inside a request line) so that keys/elements in sibling or
 * trailing JSON can never satisfy the search. */
int cmp_json_array_contains_str_bounded(const char *json, const char *json_end,
                                        const char *key, const char *want);

/* Value-level companion for callers that have already located the key (e.g.
 * with a depth-aware scanner): does the JSON value starting at `v` parse as
 * an array containing the string element `want`? `v_end` only has to bound
 * the enclosing buffer, not the value itself — the element scan stops at the
 * array's own closing ']' (nested containers are skipped with a depth walk),
 * so it never reads sibling values even when v_end lies past them. Returns 0
 * when the value is not an array. */
int cmp_json_array_value_contains_str(const char *v, const char *v_end, const char *want);

#endif
