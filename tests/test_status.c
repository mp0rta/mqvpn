/*
 * test_status.c — Tests for status.c formatting and JSON parsing
 *
 * Include status.c directly to access static functions.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Pull in static functions from status.c */
#include "../src/platform/linux/status.c"

/* ── Test infrastructure ── */

static int g_tests_run    = 0;
static int g_tests_passed = 0;

#define TEST(name) \
    static void test_##name(void); \
    static void run_##name(void) { \
        g_tests_run++; \
        printf("  %-50s ", #name); \
        test_##name(); \
        g_tests_passed++; \
        printf("PASS\n"); \
    } \
    static void test_##name(void)

#define ASSERT_STR_EQ(a, b) \
    do { if (strcmp((a), (b)) != 0) { \
        printf("FAIL\n    %s:%d: \"%s\" != \"%s\"\n", __FILE__, __LINE__, (a), (b)); \
        exit(1); \
    }} while (0)

#define ASSERT_EQ(a, b) \
    do { if ((a) != (b)) { \
        printf("FAIL\n    %s:%d: %lld != %lld\n", __FILE__, __LINE__, \
               (long long)(a), (long long)(b)); \
        exit(1); \
    }} while (0)

/* ── format_bytes tests ── */

TEST(format_bytes_zero)
{
    char buf[32];
    format_bytes(0, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "0 B");
}

TEST(format_bytes_small)
{
    char buf[32];
    format_bytes(512, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "512 B");
}

TEST(format_bytes_kib)
{
    char buf[32];
    format_bytes(1024, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "1.0 KiB");
}

TEST(format_bytes_mib)
{
    char buf[32];
    format_bytes(1048576, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "1.0 MiB");
}

TEST(format_bytes_gib)
{
    char buf[32];
    format_bytes(1073741824ULL, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "1.0 GiB");
}

TEST(format_bytes_fractional)
{
    char buf[32];
    format_bytes(1536, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "1.5 KiB");
}

/* ── format_duration tests ── */

TEST(format_duration_seconds)
{
    char buf[32];
    format_duration(42, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "42s ago");
}

TEST(format_duration_minutes)
{
    char buf[32];
    format_duration(90, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "1m 30s ago");
}

TEST(format_duration_hours)
{
    char buf[32];
    format_duration(3661, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "1h 1m ago");
}

TEST(format_duration_days)
{
    char buf[32];
    format_duration(90000, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "1d 1h ago");
}

TEST(format_duration_zero)
{
    char buf[32];
    format_duration(0, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "0s ago");
}

/* ── format_size tests ── */

TEST(format_size_bytes)
{
    char buf[32];
    format_size(512, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "512");
}

TEST(format_size_kilo)
{
    char buf[32];
    format_size(65536, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "64K");
}

TEST(format_size_mega)
{
    char buf[32];
    format_size(2097152, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "2M");
}

/* ── JSON helper tests ── */

TEST(jfind_simple)
{
    const char *json = "{\"name\":\"alice\",\"age\":30}";
    const char *v = jfind(json, "name");
    assert(v != NULL);
    char out[32];
    ASSERT_EQ(jstr(v, out, sizeof(out)), 0);
    ASSERT_STR_EQ(out, "alice");
}

TEST(jfind_int)
{
    const char *json = "{\"count\":42}";
    ASSERT_EQ(jint(jfind(json, "count")), 42);
}

TEST(jfind_missing)
{
    const char *json = "{\"name\":\"alice\"}";
    assert(jfind(json, "missing") == NULL);
}

TEST(jfind_nested_value)
{
    /* jfind does flat search, so it finds "key" inside nested obj too */
    const char *json = "{\"user\":{\"key\":\"val\"},\"key\":\"top\"}";
    const char *v = jfind(json, "key");
    char out[32];
    ASSERT_EQ(jstr(v, out, sizeof(out)), 0);
    /* Flat search finds first occurrence */
    ASSERT_STR_EQ(out, "val");
}

TEST(jstr_null)
{
    char out[32];
    ASSERT_EQ(jstr(NULL, out, sizeof(out)), -1);
}

TEST(jint_null)
{
    ASSERT_EQ(jint(NULL), 0);
}

/* ── skip_json_value tests ── */

TEST(skip_string)
{
    const char *s = "\"hello\",next";
    const char *end = skip_json_value(s);
    assert(end != NULL);
    ASSERT_EQ(*end, ',');
}

TEST(skip_object)
{
    const char *s = "{\"a\":1},next";
    const char *end = skip_json_value(s);
    assert(end != NULL);
    ASSERT_EQ(*end, ',');
}

TEST(skip_array)
{
    const char *s = "[1,2,3],next";
    const char *end = skip_json_value(s);
    assert(end != NULL);
    ASSERT_EQ(*end, ',');
}

TEST(skip_number)
{
    const char *s = "42,next";
    const char *end = skip_json_value(s);
    assert(end != NULL);
    ASSERT_EQ(*end, ',');
}

TEST(skip_nested)
{
    const char *s = "{\"a\":{\"b\":[1,{\"c\":2}]}},next";
    const char *end = skip_json_value(s);
    assert(end != NULL);
    ASSERT_EQ(*end, ',');
}

/* ── Main ── */

int main(void)
{
    printf("test_status:\n");

    /* format_bytes */
    run_format_bytes_zero();
    run_format_bytes_small();
    run_format_bytes_kib();
    run_format_bytes_mib();
    run_format_bytes_gib();
    run_format_bytes_fractional();

    /* format_duration */
    run_format_duration_seconds();
    run_format_duration_minutes();
    run_format_duration_hours();
    run_format_duration_days();
    run_format_duration_zero();

    /* format_size */
    run_format_size_bytes();
    run_format_size_kilo();
    run_format_size_mega();

    /* JSON helpers */
    run_jfind_simple();
    run_jfind_int();
    run_jfind_missing();
    run_jfind_nested_value();
    run_jstr_null();
    run_jint_null();

    /* skip_json_value */
    run_skip_string();
    run_skip_object();
    run_skip_array();
    run_skip_number();
    run_skip_nested();

    printf("\n  %d/%d tests passed\n", g_tests_passed, g_tests_run);
    return g_tests_passed == g_tests_run ? 0 : 1;
}
