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

/* ── 4. input byte 0x01 ->  (6 chars) ── */
static void
test_control_char_uescape(void)
{
    char storage[64];
    cmp_buf_t b;
    cmp_buf_init(&b, storage, sizeof(storage));
    char in[2] = {0x01, '\0'};
    cmp_json_append_str(&b, in);
    CHECK(!b.overflow);
    /* quote +  (6 chars) + quote == 8 */
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
    const char *in = "\xe6\x97\xa5\xe6\x9c\xac"; /* "日本" */
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
    test_no_raw_newline_in_any_case();
    test_array_contains_str();

    if (g_failed) {
        fprintf(stderr, "%d check(s) failed\n", g_failed);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
