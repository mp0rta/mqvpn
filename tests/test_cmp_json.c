// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_cmp_json.c — unit tests for the bounded CMP JSON writer
 * (src/common/ipc/cmp_json.c): control-char escaping, overflow safety, and
 * the minimal array-membership helper.
 *
 * Uses an always-active CHECK (not assert()) so a Release / -DNDEBUG build
 * cannot silently no-op the assertions (see AGENTS.md: build.sh forces
 * CMAKE_BUILD_TYPE=Release which defines NDEBUG).
 */

#include "cmp_error.h"
#include "cmp_json.h"

#include <stdio.h>
#include <string.h>

static int g_failed = 0;

#define CHECK(cond)                                                         \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            g_failed++;                                                     \
        }                                                                   \
    } while (0)

/* ── 1. plain string -> quoted verbatim ── */
static void
test_plain_string(void)
{
    char storage[64];
    cmp_buf_t b;
    cmp_buf_init(&b, storage, sizeof(storage));
    cmp_json_append_str(&b, "hello");
    CHECK(!b.overflow);
    CHECK(b.len == strlen("\"hello\""));
    CHECK(memcmp(storage, "\"hello\"", b.len) == 0);
}

/* ── 2. "a\nb" -> "a\\nb" (no raw LF anywhere in output) ── */
static void
test_newline_escape(void)
{
    char storage[64];
    cmp_buf_t b;
    cmp_buf_init(&b, storage, sizeof(storage));
    cmp_json_append_str(&b, "a\nb");
    CHECK(!b.overflow);
    CHECK(memcmp(storage, "\"a\\nb\"", b.len) == 0);
    CHECK(memchr(storage, '\n', b.len) == NULL);
}

/* ── 3. \r, \t, ", backslash escapes ── */
static void
test_other_escapes(void)
{
    char storage[64];
    cmp_buf_t b;

    cmp_buf_init(&b, storage, sizeof(storage));
    cmp_json_append_str(&b, "a\rb");
    CHECK(memcmp(storage, "\"a\\rb\"", b.len) == 0);

    cmp_buf_init(&b, storage, sizeof(storage));
    cmp_json_append_str(&b, "a\tb");
    CHECK(memcmp(storage, "\"a\\tb\"", b.len) == 0);

    cmp_buf_init(&b, storage, sizeof(storage));
    cmp_json_append_str(&b, "a\"b");
    CHECK(memcmp(storage, "\"a\\\"b\"", b.len) == 0);

    cmp_buf_init(&b, storage, sizeof(storage));
    cmp_json_append_str(&b, "a\\b");
    CHECK(memcmp(storage, "\"a\\\\b\"", b.len) == 0);
}

/* ── 4. input byte 0x01 -> \\u0001 (6 chars) ── */
static void
test_control_char_uescape(void)
{
    char storage[64];
    cmp_buf_t b;
    cmp_buf_init(&b, storage, sizeof(storage));
    char in[2] = {0x01, '\0'};
    cmp_json_append_str(&b, in);
    CHECK(!b.overflow);
    /* quote + \\u0001 (6 chars) + quote == 8 */
    CHECK(b.len == 8);
    CHECK(memcmp(storage, "\"\\u0001\"", b.len) == 0);
}

/* ── 5. UTF-8 multibyte passes through unmodified ── */
static void
test_utf8_passthrough(void)
{
    char storage[64];
    cmp_buf_t b;
    cmp_buf_init(&b, storage, sizeof(storage));
    const char *in = "\xe6\x97\xa5\xe6\x9c\xac"; /* UTF-8: U+65E5 U+672C */
    cmp_json_append_str(&b, in);
    CHECK(!b.overflow);
    char expected[64];
    snprintf(expected, sizeof(expected), "\"%s\"", in);
    CHECK(b.len == strlen(expected));
    CHECK(memcmp(storage, expected, b.len) == 0);
}

/* ── 6. overflow: cap-8 buffer + long string -> overflow==1, len<=cap ── */
static void
test_overflow_sets_flag(void)
{
    char storage[8];
    cmp_buf_t b;
    cmp_buf_init(&b, storage, sizeof(storage));
    cmp_json_append_str(&b, "this string is definitely too long for 8 bytes");
    CHECK(b.overflow == 1);
    CHECK(b.len <= b.cap);
    /* buf must remain a valid NUL-terminated C string after overflow */
    CHECK(b.len < b.cap);
    CHECK(storage[b.len] == '\0');
    CHECK(strlen(storage) == b.len);
}

/* ── 7. appendf after overflow does not advance len ── */
static void
test_appendf_after_overflow_noop(void)
{
    char storage[8];
    cmp_buf_t b;
    cmp_buf_init(&b, storage, sizeof(storage));
    cmp_json_append_str(&b, "this string is definitely too long for 8 bytes");
    CHECK(b.overflow == 1);
    size_t len_at_overflow = b.len;
    cmp_buf_appendf(&b, "%s", "more");
    CHECK(b.overflow == 1);
    CHECK(b.len == len_at_overflow);
}

/* ── 7b. appendf success path: exact content + len ── */
static void
test_appendf_success(void)
{
    char storage[64];
    cmp_buf_t b;
    cmp_buf_init(&b, storage, sizeof(storage));
    cmp_buf_appendf(&b, "{\"id\":%d,\"ok\":%s}", 42, "true");
    CHECK(!b.overflow);
    CHECK(b.len == strlen("{\"id\":42,\"ok\":true}"));
    CHECK(strcmp(storage, "{\"id\":42,\"ok\":true}") == 0);
}

/* ── 7c. appendf boundary pair: exact fit succeeds, one over overflows ── */
static void
test_appendf_boundary(void)
{
    /* cap 8: 7 payload bytes + NUL is the exact fit */
    char storage[8];
    cmp_buf_t b;

    cmp_buf_init(&b, storage, sizeof(storage));
    cmp_buf_appendf(&b, "%s", "1234567");
    CHECK(!b.overflow);
    CHECK(b.len == 7);
    CHECK(strcmp(storage, "1234567") == 0);

    /* one byte over: truncation-discard branch — overflow latches and the
     * partial vsnprintf write is discarded (len unchanged, buf still a
     * valid C string of the old content) */
    cmp_buf_init(&b, storage, sizeof(storage));
    cmp_buf_appendf(&b, "%s", "abc");
    CHECK(!b.overflow);
    CHECK(b.len == 3);
    cmp_buf_appendf(&b, "%s", "12345"); /* 3 + 5 == 8 > 7 usable */
    CHECK(b.overflow == 1);
    CHECK(b.len == 3);
    CHECK(strcmp(storage, "abc") == 0);
}

/* ── 8. helper applied to all cases above: memchr(buf,'\n',len)==NULL ── */
static void
test_no_raw_newline_in_any_case(void)
{
    char storage[64];
    cmp_buf_t b;
    const char *cases[] = {"hello", "a\nb", "a\rb", "a\tb", "a\"b", "a\\b"};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        cmp_buf_init(&b, storage, sizeof(storage));
        cmp_json_append_str(&b, cases[i]);
        CHECK(memchr(storage, '\n', b.len) == NULL);
    }
}

/* ── 9. cmp_json_array_contains_str ── */
static void
test_array_contains_str(void)
{
    CHECK(cmp_json_array_contains_str("{\"supported_protocols\":[\"1.0\"]}",
                                      "supported_protocols", "1.0") == 1);
    CHECK(cmp_json_array_contains_str("{\"supported_protocols\":[\"2.0\"]}",
                                      "supported_protocols", "1.0") == 0);
    CHECK(cmp_json_array_contains_str("{\"supported_protocols\":[\"a\",\"1.0\"]}",
                                      "supported_protocols", "1.0") == 1);
    /* key missing -> 0 */
    CHECK(cmp_json_array_contains_str("{\"other\":[\"1.0\"]}", "supported_protocols",
                                      "1.0") == 0);
    /* value not an array -> 0 */
    CHECK(cmp_json_array_contains_str("{\"supported_protocols\":\"1.0\"}",
                                      "supported_protocols", "1.0") == 0);
    /* an escaped \" inside an element must not break element boundaries */
    CHECK(cmp_json_array_contains_str("{\"supported_protocols\":[\"a\\\"b\",\"1.0\"]}",
                                      "supported_protocols", "1.0") == 1);
    /* a string key inside an object element must not match as an array
     * element; a real element after the object still must */
    CHECK(cmp_json_array_contains_str("{\"supported_protocols\":[{\"a\":1,\"1.0\":2}]}",
                                      "supported_protocols", "1.0") == 0);
    CHECK(cmp_json_array_contains_str(
              "{\"supported_protocols\":[{\"a\":1,\"1.0\":2},\"1.0\"]}",
              "supported_protocols", "1.0") == 1);
}

/* ── 9b. cmp_json_array_contains_str_bounded: bytes at/after json_end are
 * invisible to both the key lookup and the array scan ── */
static void
test_array_contains_str_bounded(void)
{
    /* two objects on one line; the span covers only the first */
    const char *line = "{\"client_name\":\"x\"} {\"supported_protocols\":[\"1.0\"]}";
    const char *end1 = strchr(line, '}') + 1;
    CHECK(cmp_json_array_contains_str_bounded(line, end1, "supported_protocols", "1.0") ==
          0);
    /* the full line still matches (sanity: the key is really there) */
    CHECK(cmp_json_array_contains_str_bounded(line, line + strlen(line),
                                              "supported_protocols", "1.0") == 1);

    /* array truncated by the bound: the wanted element lies past json_end */
    const char *arr = "{\"supported_protocols\":[\"2.0\",\"1.0\"]}";
    const char *cut = strstr(arr, ",\"1.0\"");
    CHECK(cmp_json_array_contains_str_bounded(arr, cut, "supported_protocols", "1.0") ==
          0);
    CHECK(cmp_json_array_contains_str_bounded(arr, arr + strlen(arr),
                                              "supported_protocols", "1.0") == 1);

    /* unbounded wrapper still behaves as before */
    CHECK(cmp_json_array_contains_str("{\"supported_protocols\":[\"1.0\"]}",
                                      "supported_protocols", "1.0") == 1);
}

/* ── 9c. cmp_json_array_value_contains_str: value-level scan stops at the
 * array's own ']' even when the bound lies past sibling values ── */
static void
test_array_value_contains_str(void)
{
    /* v points at the array; a sibling array with the wanted element follows
     * before the bound — it must never be scanned into */
    const char *obj = "{\"a\":[\"9.9\"],\"b\":[\"1.0\"]}";
    const char *v = strchr(obj, '[');
    const char *end = obj + strlen(obj);
    CHECK(cmp_json_array_value_contains_str(v, end, "1.0") == 0);
    CHECK(cmp_json_array_value_contains_str(v, end, "9.9") == 1);
    /* non-array value -> 0 */
    const char *str_val = "\"1.0\"";
    CHECK(cmp_json_array_value_contains_str(str_val, str_val + strlen(str_val), "1.0") ==
          0);
}

/* ── 10. cmp_error_code_str: every code maps to a non-NULL wire string ── */
static void
test_error_code_str_table(void)
{
    for (int c = 0; c < CMP_E__COUNT; c++) {
        const char *s = cmp_error_code_str((cmp_error_code_t)c);
        CHECK(s != NULL);
        CHECK(s != NULL && strncmp(s, "MQVPN_CLIENT_", 13) == 0);
    }
    /* out-of-range values map to the internal-error string, never NULL */
    CHECK(strcmp(cmp_error_code_str((cmp_error_code_t)-1),
                 "MQVPN_CLIENT_INTERNAL_ERROR") == 0);
    CHECK(strcmp(cmp_error_code_str(CMP_E__COUNT), "MQVPN_CLIENT_INTERNAL_ERROR") == 0);
    /* spot-check two stable wire strings */
    CHECK(strcmp(cmp_error_code_str(CMP_E_OK), "MQVPN_CLIENT_OK") == 0);
    CHECK(strcmp(cmp_error_code_str(CMP_E_NO_ACTIVE_PATH),
                 "MQVPN_CLIENT_NO_ACTIVE_PATH") == 0);
}

int
main(void)
{
    test_plain_string();
    test_newline_escape();
    test_other_escapes();
    test_control_char_uescape();
    test_utf8_passthrough();
    test_overflow_sets_flag();
    test_appendf_after_overflow_noop();
    test_appendf_success();
    test_appendf_boundary();
    test_no_raw_newline_in_any_case();
    test_array_contains_str();
    test_array_contains_str_bounded();
    test_array_value_contains_str();
    test_error_code_str_table();

    if (g_failed) {
        fprintf(stderr, "%d check(s) failed\n", g_failed);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
