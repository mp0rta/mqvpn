// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_status.c — Tests for status.c formatting and JSON parsing
 *
 * Include status.c directly to access static functions.
 */

/* Keep assert() live even in Release builds: CI runs ctest on Release too,
 * where NDEBUG would silently no-op every assertion in this file. */
#undef NDEBUG
#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <sys/wait.h>

/* Pull in static functions from status.c */
#include "../src/platform/posix/status.c"

/* ── Test infrastructure ── */

static int g_tests_run = 0;
static int g_tests_passed = 0;

#define TEST(name)                 \
    static void test_##name(void); \
    static void run_##name(void)   \
    {                              \
        g_tests_run++;             \
        printf("  %-50s ", #name); \
        test_##name();             \
        g_tests_passed++;          \
        printf("PASS\n");          \
    }                              \
    static void test_##name(void)

#define ASSERT_STR_EQ(a, b)                                                              \
    do {                                                                                 \
        if (strcmp((a), (b)) != 0) {                                                     \
            printf("FAIL\n    %s:%d: \"%s\" != \"%s\"\n", __FILE__, __LINE__, (a), (b)); \
            exit(1);                                                                     \
        }                                                                                \
    } while (0)

#define ASSERT_EQ(a, b)                                                   \
    do {                                                                  \
        if ((a) != (b)) {                                                 \
            printf("FAIL\n    %s:%d: %lld != %lld\n", __FILE__, __LINE__, \
                   (long long)(a), (long long)(b));                       \
            exit(1);                                                      \
        }                                                                 \
    } while (0)

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
    const char *v = json_find_key(json, "name");
    assert(v != NULL);
    char out[32];
    ASSERT_EQ(json_read_string(v, out, sizeof(out)), 0);
    ASSERT_STR_EQ(out, "alice");
}

TEST(jfind_int)
{
    const char *json = "{\"count\":42}";
    ASSERT_EQ(json_read_int64(json_find_key(json, "count")), 42);
}

TEST(jfind_missing)
{
    const char *json = "{\"name\":\"alice\"}";
    assert(json_find_key(json, "missing") == NULL);
}

TEST(jfind_nested_value)
{
    /* json_find_key does flat search, so it finds "key" inside nested obj too */
    const char *json = "{\"user\":{\"key\":\"val\"},\"key\":\"top\"}";
    const char *v = json_find_key(json, "key");
    char out[32];
    ASSERT_EQ(json_read_string(v, out, sizeof(out)), 0);
    /* Flat search finds first occurrence */
    ASSERT_STR_EQ(out, "val");
}

TEST(jstr_null)
{
    char out[32];
    ASSERT_EQ(json_read_string(NULL, out, sizeof(out)), -1);
}

TEST(jint_null)
{
    ASSERT_EQ(json_read_int64(NULL), 0);
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

/* ── format_bytes threshold tests ── */

TEST(format_bytes_thresholds)
{
    char buf[32];
    format_bytes(1023, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "1023 B");
    format_bytes(1024, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "1.0 KiB");
    format_bytes(1048575, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "1024.0 KiB");
    format_bytes(1048576, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "1.0 MiB");
}

/* ── format_duration threshold tests ── */

TEST(format_duration_thresholds)
{
    char buf[32];
    format_duration(59, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "59s ago");
    format_duration(60, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "1m 0s ago");
    format_duration(3599, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "59m 59s ago");
    format_duration(3600, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "1h 0m ago");
    format_duration(86400, buf, sizeof(buf));
    ASSERT_STR_EQ(buf, "1d 0h ago");
}

/* ── JSON edge case tests ── */

TEST(json_find_key_escaped_quotes)
{
    const char *json = "{\"key\": \"hello\\\"world\"}";
    const char *val = json_find_key(json, "key");
    /* json_find_key must find the key — escaped quotes in value don't break it */
    ASSERT_EQ(val != NULL, 1);
    char str[64];
    ASSERT_EQ(json_read_string(val, str, sizeof(str)), 0);
}

TEST(json_find_key_empty_object)
{
    const char *json = "{}";
    const char *val = json_find_key(json, "key");
    ASSERT_EQ((long long)(uintptr_t)val, 0);
}

/* ── ctrl_query reads the whole reply ── */

/* Serve one connection on 127.0.0.1: read the request to EOF, answer with
 * reply_len bytes ('x' * (reply_len - 1) + '\n'), close. Returns the child
 * pid, and the port through *port. */
static pid_t
serve_one_reply(size_t reply_len, int *port)
{
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(lfd >= 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = 0};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(lfd, (struct sockaddr *)&a, sizeof(a)) == 0);
    assert(listen(lfd, 1) == 0);
    socklen_t alen = sizeof(a);
    assert(getsockname(lfd, (struct sockaddr *)&a, &alen) == 0);
    *port = ntohs(a.sin_port);

    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        signal(SIGPIPE, SIG_IGN); /* the cap test stops reading early */
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) _exit(1);
        char req[256];
        while (read(cfd, req, sizeof(req)) > 0) {}
        char *reply = malloc(reply_len);
        if (!reply) _exit(1);
        memset(reply, 'x', reply_len - 1);
        reply[reply_len - 1] = '\n';
        size_t off = 0;
        while (off < reply_len) {
            ssize_t n = write(cfd, reply + off, reply_len - off);
            if (n <= 0) break;
            off += (size_t)n;
        }
        close(cfd);
        _exit(0);
    }
    close(lfd);
    return pid;
}

/* A get_status reply above the old fixed 32 KiB read buffer (the server
 * allows up to 256 KiB) must come back whole, not cut mid-JSON. */
TEST(ctrl_query_reads_reply_past_32k)
{
    int port = 0;
    size_t len = 200 * 1024;
    pid_t pid = serve_one_reply(len, &port);
    char *buf = ctrl_query("127.0.0.1", port, "{\"cmd\":\"get_status\"}\n");
    waitpid(pid, NULL, 0);
    assert(buf != NULL);
    ASSERT_EQ(strlen(buf), len);
    ASSERT_EQ(buf[len - 1], '\n');
    free(buf);
}

/* A reply past STATUS_BUF_MAX is reported as an error, not truncated. */
TEST(ctrl_query_rejects_reply_past_max)
{
    int port = 0;
    pid_t pid = serve_one_reply((size_t)STATUS_BUF_MAX + 4096, &port);
    char *buf = ctrl_query("127.0.0.1", port, "{\"cmd\":\"get_status\"}\n");
    waitpid(pid, NULL, 0);
    assert(buf == NULL);
}

/* ── Main ── */

int
main(void)
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

    /* threshold boundary tests */
    run_format_bytes_thresholds();
    run_format_duration_thresholds();

    /* JSON edge case tests */
    run_json_find_key_escaped_quotes();
    run_json_find_key_empty_object();

    /* control-API reply reading */
    run_ctrl_query_reads_reply_past_32k();
    run_ctrl_query_rejects_reply_past_max();

    printf("\n  %d/%d tests passed\n", g_tests_passed, g_tests_run);
    return g_tests_passed == g_tests_run ? 0 : 1;
}
