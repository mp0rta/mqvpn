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

/* ── JSON reading ── */

/* A key inside a nested object is not a top-level key. */
TEST(json_nested_key_not_lifted)
{
    const char *json = "{\"user\":{\"key\":\"val\"},\"key\":\"top\"}";
    yyjson_doc *doc = yyjson_read(json, strlen(json), 0);
    assert(doc != NULL);
    char out[32];
    ASSERT_EQ(
        json_copy_str(yyjson_obj_get(yyjson_doc_get_root(doc), "key"), out, sizeof(out)),
        0);
    ASSERT_STR_EQ(out, "top");
    yyjson_doc_free(doc);
}

TEST(jget_u64_cases)
{
    const char *json = "{\"a\":18446744073709551615,\"b\":9223372036854775808,"
                       "\"c\":18446744073709551616,\"d\":-5,\"e\":\"7\"}";
    yyjson_doc *doc = yyjson_read(json, strlen(json), 0);
    assert(doc != NULL);
    yyjson_val *root = yyjson_doc_get_root(doc);
    assert(jget_u64(root, "a") == UINT64_MAX);
    assert(jget_u64(root, "b") == 9223372036854775808ULL);
    ASSERT_EQ(jget_u64(root, "c"), 0);
    ASSERT_EQ(jget_u64(root, "d"), 0);
    ASSERT_EQ(jget_u64(root, "e"), 0);
    ASSERT_EQ(jget_u64(root, "zz"), 0);
    yyjson_doc_free(doc);
}

/* ── Control-API fixtures ── */

/* Serve n connections on 127.0.0.1 in order: read each request to EOF,
 * answer with the lens[i] bytes of bodies[i], close. Returns the child pid,
 * and the port through *port. */
static pid_t
serve_bodies(const char *const bodies[], const size_t lens[], int n, int *port)
{
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(lfd >= 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = 0};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(lfd, (struct sockaddr *)&a, sizeof(a)) == 0);
    assert(listen(lfd, n) == 0);
    socklen_t alen = sizeof(a);
    assert(getsockname(lfd, (struct sockaddr *)&a, &alen) == 0);
    *port = ntohs(a.sin_port);

    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        alarm(30); /* if the client never connects, die (reap fails) instead of hanging */
        signal(SIGPIPE, SIG_IGN); /* the cap test stops reading early */
        for (int i = 0; i < n; i++) {
            int cfd = accept(lfd, NULL, NULL);
            if (cfd < 0) _exit(1);
            char req[256];
            while (read(cfd, req, sizeof(req)) > 0) {}
            size_t off = 0;
            while (off < lens[i]) {
                ssize_t w = write(cfd, bodies[i] + off, lens[i] - off);
                if (w <= 0) break;
                off += (size_t)w;
            }
            close(cfd);
        }
        _exit(0);
    }
    close(lfd);
    return pid;
}

/* Serve one connection answering with reply_len bytes
 * ('x' * (reply_len - 1) + '\n'). */
static pid_t
serve_one_reply(size_t reply_len, int *port)
{
    char *reply = malloc(reply_len);
    assert(reply != NULL);
    memset(reply, 'x', reply_len - 1);
    reply[reply_len - 1] = '\n';
    const char *const bodies[] = {reply};
    pid_t pid = serve_bodies(bodies, &reply_len, 1, port);
    free(reply); /* the child has its own copy */
    return pid;
}

static void
read_back(int fd, char *buf, size_t cap)
{
    ssize_t n = pread(fd, buf, cap - 1, 0);
    buf[n > 0 ? n : 0] = '\0';
}

/* Run run_status() against 127.0.0.1:port with stdout and stderr captured
 * into out / err (NUL-terminated, cut at the capacity). Returns its rc. */
static int
capture_run_status(int port, char *out, size_t out_cap, char *err, size_t err_cap)
{
    char opath[] = "/tmp/test_status_out_XXXXXX";
    char epath[] = "/tmp/test_status_err_XXXXXX";
    int ofd = mkstemp(opath);
    int efd = mkstemp(epath);
    assert(ofd >= 0 && efd >= 0);

    fflush(stdout);
    fflush(stderr);
    int saved_out = dup(STDOUT_FILENO);
    int saved_err = dup(STDERR_FILENO);
    assert(saved_out >= 0 && saved_err >= 0);
    assert(dup2(ofd, STDOUT_FILENO) >= 0 && dup2(efd, STDERR_FILENO) >= 0);
    int rc = run_status("127.0.0.1", port);
    /* stdout is fully buffered when ctest pipes it: flush before restoring */
    fflush(stdout);
    fflush(stderr);
    assert(dup2(saved_out, STDOUT_FILENO) >= 0 && dup2(saved_err, STDERR_FILENO) >= 0);
    close(saved_out);
    close(saved_err);

    read_back(ofd, out, out_cap);
    read_back(efd, err, err_cap);
    close(ofd);
    close(efd);
    unlink(opath);
    unlink(epath);
    return rc;
}

static int
count_substr(const char *hay, const char *needle)
{
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += strlen(needle))
        n++;
    return n;
}

static void
reap(pid_t pid)
{
    int st = 0;
    ASSERT_EQ(waitpid(pid, &st, 0), pid);
    assert(WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

/* ── ctrl_query reads the whole reply ── */

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

/* ── run_status end to end ── */

#define STATS_BODY                                                             \
    "{\"ok\":true,\"n_clients\":2,\"pkts_lane_tcp\":1,\"pkts_lane_dgram\":2,"  \
    "\"pkts_lane_raw\":3,\"pkts_lane_tcp_dropped\":4,\"tcp_flows_active\":5,"  \
    "\"tcp_flows_total\":6,\"tcp_flows_rejected\":7,\"raw_markers_active\":8," \
    "\"udp_tx_sends\":10,\"udp_tx_datagrams\":20,\"udp_rx_receives\":30,"      \
    "\"udp_rx_datagrams\":60}\n"
#define BOB_CLIENT                                                                      \
    "{\"user\":\"bob\",\"endpoint\":\"10.0.0.3:2\",\"connected_sec\":0,\"bytes_tx\":0," \
    "\"bytes_rx\":0,\"n_paths\":0}"

TEST(run_status_prints_clients)
{
    char pad[601];
    memset(pad, 'x', 600);
    pad[600] = '\0';
    char status[2048];
    int len = snprintf(
        status, sizeof(status),
        "{\"ok\":true,\"n_clients\":2,\"clients\":["
        "{\"user\":\"al\\\"ice\",\"endpoint\":\"10.0.0.2:1\",\"connected_sec\":5,"
        "\"bytes_tx\":1024,\"bytes_rx\":2048,\"n_paths\":2,\"paths\":["
        "{\"path_id\":0,\"srtt_ms\":12,\"min_rtt_ms\":10,\"cwnd\":2048,\"state_label\":"
        "\"active\"},"
        "{\"path_id\":1,\"srtt_ms\":30,\"min_rtt_ms\":20,\"cwnd\":4096,\"state_label\":"
        "\"active\","
        "\"pad\":\"%s\"}]}," BOB_CLIENT "]}\n",
        pad);
    assert(len > 0 && (size_t)len < sizeof(status));
    const char *const bodies[] = {STATS_BODY, status};
    const size_t lens[] = {strlen(STATS_BODY), (size_t)len};
    int port = 0;
    pid_t pid = serve_bodies(bodies, lens, 2, &port);
    char out[4096], err[512];
    int rc = capture_run_status(port, out, sizeof(out), err, sizeof(err));
    reap(pid);

    ASSERT_EQ(rc, 0);
    ASSERT_STR_EQ(out, "server: lanes tcp/dgram/raw=1/2/3 (tcp_dropped=4) flows "
                       "act/tot/rej=5/6/7 raw_markers=8\n"
                       "server: udp tx=20/10 (x2.00) rx=60/30 (x2.00)\n"
                       "mqvpn server  clients: 2\n"
                       "\nclient: al\"ice\n"
                       "  endpoint: 10.0.0.2:1\n"
                       "  connected: 5s ago\n"
                       "  transfer: 2.0 KiB received, 1.0 KiB sent\n"
                       "  path 0: srtt=12ms min_rtt=10ms cwnd=2K active\n"
                       "  path 1: srtt=30ms min_rtt=20ms cwnd=4K active\n"
                       "\nclient: bob\n"
                       "  endpoint: 10.0.0.3:2\n"
                       "  connected: 0s ago\n"
                       "  transfer: 0 B received, 0 B sent\n");
    ASSERT_STR_EQ(err, "");
}

/* An older server rejects get_stats: skip the summary lines silently. */
TEST(run_status_stats_error_is_silent)
{
    const char *const bodies[] = {"{\"ok\":false,\"error\":\"unknown cmd\"}\n",
                                  "{\"ok\":true,\"n_clients\":1,\"clients\":[" BOB_CLIENT
                                  "]}\n"};
    const size_t lens[] = {strlen(bodies[0]), strlen(bodies[1])};
    int port = 0;
    pid_t pid = serve_bodies(bodies, lens, 2, &port);
    char out[4096], err[512];
    int rc = capture_run_status(port, out, sizeof(out), err, sizeof(err));
    reap(pid);

    ASSERT_EQ(rc, 0);
    assert(strstr(out, "server:") == NULL);
    assert(strstr(out, "\nclient: bob\n") != NULL);
    ASSERT_STR_EQ(err, "");
}

TEST(run_status_bad_json_reports_unknown_error)
{
    const char *const bodies[] = {STATS_BODY, "{\"ok\":tru\n"};
    const size_t lens[] = {strlen(bodies[0]), strlen(bodies[1])};
    int port = 0;
    pid_t pid = serve_bodies(bodies, lens, 2, &port);
    char out[4096], err[512];
    int rc = capture_run_status(port, out, sizeof(out), err, sizeof(err));
    reap(pid);

    ASSERT_EQ(rc, 1);
    ASSERT_STR_EQ(err, "error: unknown error\n");
}

/* The server cuts a name at 63 bytes, which can split a UTF-8 sequence; that
 * one name must not turn the whole reply into "unknown error". */
TEST(run_status_invalid_utf8_user_passthrough)
{
    char name[64];
    memset(name, 'a', 62);
    name[62] = '\xC3';
    name[63] = '\0';
    char status[512];
    int len =
        snprintf(status, sizeof(status),
                 "{\"ok\":true,\"n_clients\":1,\"clients\":[{\"user\":\"%s\"}]}\n", name);
    assert(len > 0 && (size_t)len < sizeof(status));
    const char *const bodies[] = {STATS_BODY, status};
    const size_t lens[] = {strlen(STATS_BODY), (size_t)len};
    int port = 0;
    pid_t pid = serve_bodies(bodies, lens, 2, &port);
    char out[4096], err[512];
    int rc = capture_run_status(port, out, sizeof(out), err, sizeof(err));
    reap(pid);

    ASSERT_EQ(rc, 0);
    char line[80];
    snprintf(line, sizeof(line), "\nclient: %s\n", name);
    assert(strstr(out, line) != NULL);
    ASSERT_STR_EQ(err, "");
}

TEST(run_status_skips_non_object_entries)
{
    const char *const bodies[] = {
        STATS_BODY,
        "{\"ok\":true,\"n_clients\":1,\"clients\":[1,{\"user\":\"bob\",\"n_paths\":1,"
        "\"paths\":[7,{\"srtt_ms\":1,\"min_rtt_ms\":1,\"cwnd\":0,\"state_label\":"
        "\"active\"}]}]}\n"};
    const size_t lens[] = {strlen(bodies[0]), strlen(bodies[1])};
    int port = 0;
    pid_t pid = serve_bodies(bodies, lens, 2, &port);
    char out[4096], err[512];
    int rc = capture_run_status(port, out, sizeof(out), err, sizeof(err));
    reap(pid);

    ASSERT_EQ(rc, 0);
    assert(strstr(out, "\nclient: bob\n") != NULL);
    const char *p0 = strstr(out, "  path 0:");
    assert(p0 != NULL && strstr(p0 + 1, "  path 0:") == NULL);
    assert(strstr(out, "  path 1:") == NULL);
    /* A non-object client prints no heading (bob's endpoint line has "(unknown)"). */
    ASSERT_EQ(count_substr(out, "client: "), 1);
    assert(strstr(out, "client: (unknown)") == NULL);
    ASSERT_STR_EQ(err, "");
}

/* Display edges of the integers a reply can carry: a signed n_clients prints
 * as is, an out-of-int-range one reads as 0, an RTT above INT64_MAX prints
 * negative and one above UINT64_MAX reads as 0. */
TEST(run_status_numeric_display_edges)
{
    const char *const neg_status =
        "{\"ok\":true,\"n_clients\":-5,\"clients\":["
        "{\"user\":\"bob\",\"endpoint\":\"10.0.0.3:2\",\"connected_sec\":0,"
        "\"bytes_tx\":0,\"bytes_rx\":0,\"n_paths\":1,\"paths\":["
        "{\"srtt_ms\":9223372036854775808,\"min_rtt_ms\":18446744073709551616,"
        "\"cwnd\":2048,\"state_label\":\"active\"}]}]}\n";
    const char *const big_status =
        "{\"ok\":true,\"n_clients\":2147483648,\"clients\":[]}\n";
    const char *const stats_lines = "server: lanes tcp/dgram/raw=1/2/3 (tcp_dropped=4) "
                                    "flows act/tot/rej=5/6/7 raw_markers=8\n"
                                    "server: udp tx=20/10 (x2.00) rx=60/30 (x2.00)\n";

    const char *const bodies[] = {STATS_BODY, neg_status};
    const size_t lens[] = {strlen(bodies[0]), strlen(bodies[1])};
    int port = 0;
    pid_t pid = serve_bodies(bodies, lens, 2, &port);
    char out[4096], err[512];
    int rc = capture_run_status(port, out, sizeof(out), err, sizeof(err));
    reap(pid);

    ASSERT_EQ(rc, 0);
    char want[1024];
    snprintf(want, sizeof(want),
             "%smqvpn server  clients: -5\n"
             "\nclient: bob\n"
             "  endpoint: 10.0.0.3:2\n"
             "  connected: 0s ago\n"
             "  transfer: 0 B received, 0 B sent\n"
             "  path 0: srtt=-9223372036854775808ms min_rtt=0ms cwnd=2K active\n",
             stats_lines);
    ASSERT_STR_EQ(out, want);
    ASSERT_STR_EQ(err, "");

    const char *const bodies2[] = {STATS_BODY, big_status};
    const size_t lens2[] = {strlen(bodies2[0]), strlen(bodies2[1])};
    pid = serve_bodies(bodies2, lens2, 2, &port);
    rc = capture_run_status(port, out, sizeof(out), err, sizeof(err));
    reap(pid);

    ASSERT_EQ(rc, 0);
    snprintf(want, sizeof(want),
             "%smqvpn server  clients: 0\n\n  (no connected clients)\n", stats_lines);
    ASSERT_STR_EQ(out, want);
    ASSERT_STR_EQ(err, "");
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

    /* threshold boundary tests */
    run_format_bytes_thresholds();
    run_format_duration_thresholds();

    /* control-API reply reading */
    run_ctrl_query_reads_reply_past_32k();
    run_ctrl_query_rejects_reply_past_max();

    /* JSON reading */
    run_json_nested_key_not_lifted();
    run_jget_u64_cases();

    /* run_status end to end */
    run_run_status_prints_clients();
    run_run_status_stats_error_is_silent();
    run_run_status_bad_json_reports_unknown_error();
    run_run_status_invalid_utf8_user_passthrough();
    run_run_status_skips_non_object_entries();
    run_run_status_numeric_display_edges();

    printf("\n  %d/%d tests passed\n", g_tests_passed, g_tests_run);
    return g_tests_passed == g_tests_run ? 0 : 1;
}
