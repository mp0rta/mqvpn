// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_mgmt_conn.c — libevent connection layer of the management IPC.
 * POSIX-only for now; the socket helpers are kept in one block at the top.
 */

#undef NDEBUG
#ifdef _WIN32
#  include <stdio.h>
int
main(void)
{
    puts("test_mgmt_conn: skipped on Windows");
    return 0;
}
#else

#  include "mgmt_conn.h"
#  include "cmp_error.h"
#  include "cmp_proto.h"
#  include "log.h"

#  include <arpa/inet.h>
#  include <errno.h>
#  include <fcntl.h>
#  include <netinet/in.h>
#  include <signal.h>
#  include <stdint.h>
#  include <stdio.h>
#  include <stdlib.h>
#  include <string.h>
#  include <sys/socket.h>
#  include <sys/stat.h>
#  include <sys/un.h>
#  include <time.h>
#  include <unistd.h>

static int g_failed = 0;

#  define CHECK(cond)                                                         \
      do {                                                                    \
          if (!(cond)) {                                                      \
              fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
              g_failed++;                                                     \
          }                                                                   \
      } while (0)

/* ---- POSIX socket helpers (the only OS-specific block) ---- */
static int
sock_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    return fl < 0 ? -1 : fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void
sock_close(int fd)
{
    close(fd);
}

static int
sock_send(int fd, const void *b, size_t n)
{
    return (int)send(fd, b, n, MSG_NOSIGNAL);
}

static int
sock_recv(int fd, void *b, size_t n)
{
    return (int)recv(fd, b, n, 0);
}

static int
sock_would_block(void)
{
    return errno == EAGAIN || errno == EWOULDBLOCK;
}

static int
unix_listen(const char *path)
{
    struct sockaddr_un sa;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
    if (fd < 0 || bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
        listen(fd, 16) != 0)
        return -1;
    return fd;
}

static int
unix_connect(const char *path)
{
    struct sockaddr_un sa;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
    if (fd < 0 || connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) return -1;
    sock_nonblock(fd);
    return fd;
}

static uint64_t
now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* ---- fixture ---- */
static const char *const k_caps[] = {"a"};
static const mgmt_endpoint_ctx_t k_ctx = {"9.9.9-test", k_caps, 1};

static struct event_base *g_eb;
static mgmt_endpoint_t *g_ep;
static mgmt_listener_t *g_l;
static int g_lfd = -1;
static char g_dir[128];
static char g_path[256];

/* UDP pair + periodic tick: proof the loop keeps serving the VPN's own events. */
static int g_utx = -1, g_urx = -1;
static struct event *g_uev, *g_tick, *g_guard;
static uint64_t g_udp_tx, g_udp_rx, g_ticks;

/* Checks applied to every EVLOOP_ONCE the pumps run. */
static uint32_t g_chk_budget; /* 0 = off */
static int g_chk_udp, g_chk_tick;

static void
udp_cb(evutil_socket_t fd, short what, void *arg)
{
    char b[8];
    (void)what;
    (void)arg;
    while (recv(fd, b, sizeof(b), MSG_DONTWAIT) > 0)
        g_udp_rx++;
}

/* Periodic wake-up so a pump's EVLOOP_ONCE can never block for long. */
static void
guard_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    (void)arg;
}

static void
tick_cb(evutil_socket_t fd, short what, void *arg)
{
    static const struct timeval zero = {0, 0};
    (void)fd;
    (void)what;
    (void)arg;
    g_ticks++;
    evtimer_add(g_tick, &zero);
}

static uint64_t
disp_count(void)
{
    mgmt_listener_counters_t c;
    if (!g_l) return 0;
    mgmt_listener_counters(g_l, &c);
    return c.dispatched;
}

static mgmt_listener_counters_t
counters(void)
{
    mgmt_listener_counters_t c;
    memset(&c, 0, sizeof(c));
    if (g_l) mgmt_listener_counters(g_l, &c);
    return c;
}

static void
loop_once(void)
{
    uint64_t d0 = disp_count(), t0 = g_ticks;
    if (g_chk_udp) {
        (void)sock_send(g_utx, "x", 1);
        g_udp_tx++;
    }
    event_base_loop(g_eb, EVLOOP_ONCE);
    if (g_chk_budget) CHECK(disp_count() - d0 <= g_chk_budget);
    if (g_chk_udp) CHECK(g_udp_rx == g_udp_tx);
    if (g_chk_tick) CHECK(g_ticks > t0);
}

/* Turn the per-iteration checks on/off. The periodic tick (VPN tick stand-in) only
 * runs while on: a self-re-arming 0 ms timer would keep EVLOOP_NONBLOCK from returning.
 */
static void
checks_on(uint32_t budget, int udp, int tick)
{
    static const struct timeval zero = {0, 0};
    g_chk_budget = budget;
    g_chk_udp = udp;
    g_chk_tick = tick;
    if (tick) evtimer_add(g_tick, &zero);
}

static void
checks_off(void)
{
    g_chk_budget = 0;
    g_chk_udp = g_chk_tick = 0;
    evtimer_del(g_tick);
}

static void
run_for_ms(unsigned ms)
{
    uint64_t end = now_ms() + ms;
    while (now_ms() < end) {
        event_base_loop(g_eb, EVLOOP_NONBLOCK);
        usleep(1000);
    }
}

static void
fixture_start(const mgmt_conn_limits_t *lim)
{
    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);

    snprintf(g_dir, sizeof(g_dir), "/tmp/mqvpn-mc-XXXXXX");
    CHECK(mkdtemp(g_dir) != NULL);
    snprintf(g_path, sizeof(g_path), "%s/s", g_dir);
    g_eb = event_base_new();
    g_lfd = unix_listen(g_path);
    CHECK(g_eb && g_lfd >= 0);
    g_ep = mgmt_endpoint_new(g_eb, &k_ctx, lim);
    CHECK(g_ep != NULL);
    g_l = mgmt_endpoint_add_listener(g_ep, g_lfd, MGMT_ROLE_ADMIN, g_path);
    CHECK(g_l != NULL);

    g_urx = socket(AF_INET, SOCK_DGRAM, 0);
    g_utx = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(g_urx, (struct sockaddr *)&sa, sizeof(sa)) == 0);
    CHECK(getsockname(g_urx, (struct sockaddr *)&sa, &sl) == 0);
    CHECK(connect(g_utx, (struct sockaddr *)&sa, sizeof(sa)) == 0);
    sock_nonblock(g_urx);
    sock_nonblock(g_utx);
    g_uev = event_new(g_eb, g_urx, EV_READ | EV_PERSIST, udp_cb, NULL);
    event_add(g_uev, NULL);
    g_tick = evtimer_new(g_eb, tick_cb, NULL); /* armed by checks_on() */
    g_guard = event_new(g_eb, -1, EV_PERSIST, guard_cb, NULL);
    {
        static const struct timeval fifty_ms = {0, 50000};
        evtimer_add(g_guard, &fifty_ms);
    }
    g_udp_tx = g_udp_rx = g_ticks = 0;
    g_chk_budget = 0;
    g_chk_udp = g_chk_tick = 0;
}

static void
fixture_stop(void)
{
    if (g_ep) mgmt_endpoint_free(g_ep);
    g_ep = NULL;
    g_l = NULL;
    event_free(g_uev);
    event_free(g_tick);
    event_free(g_guard);
    sock_close(g_urx);
    sock_close(g_utx);
    if (g_lfd >= 0) sock_close(g_lfd);
    g_lfd = -1;
    unlink(g_path);
    rmdir(g_dir);
    event_base_free(g_eb);
}

static void
small_limits(mgmt_conn_limits_t *l)
{
    mgmt_conn_limits_default(l);
}

/* ---- client side ---- */
typedef struct {
    int fd;
    size_t len;
    char buf[4096];
} cl_t;

static cl_t *
cl_new(void)
{
    cl_t *c = calloc(1, sizeof(*c));
    c->fd = unix_connect(g_path);
    CHECK(c->fd >= 0);
    return c;
}

static void
cl_free(cl_t *c)
{
    if (c->fd >= 0) sock_close(c->fd);
    free(c);
}

/* Send everything, running the loop on every EAGAIN (a blocking send would stall
 * on small AF_UNIX buffers). 2 s deadline. */
static int
pump_send(cl_t *c, const char *b, size_t n)
{
    uint64_t end = now_ms() + 2000;
    while (n) {
        int r = sock_send(c->fd, b, n);
        if (r > 0) {
            b += r;
            n -= (size_t)r;
        } else if (r < 0 && sock_would_block()) {
            loop_once();
        } else {
            return -1;
        }
        if (now_ms() > end) {
            CHECK(!"pump_send deadline");
            return -1;
        }
    }
    return 0;
}

static int
cl_take_line(cl_t *c, char *out, size_t cap)
{
    char *lf = memchr(c->buf, '\n', c->len);
    size_t n;
    if (!lf) return 0;
    n = (size_t)(lf - c->buf);
    CHECK(n < cap);
    memcpy(out, c->buf, n);
    out[n] = 0;
    memmove(c->buf, lf + 1, c->len - n - 1);
    c->len -= n + 1;
    return 1;
}

/* >0 bytes, 0 EOF, -1 would block, -2 error */
static int
cl_fill(cl_t *c)
{
    int r = sock_recv(c->fd, c->buf + c->len, sizeof(c->buf) - c->len);
    if (r > 0) c->len += (size_t)r;
    if (r < 0) return sock_would_block() ? -1 : -2;
    return r;
}

/* One buffered/recv'd line without running the loop. */
static int
cl_try_line(cl_t *c, char *out, size_t cap)
{
    if (cl_take_line(c, out, cap)) return 1;
    if (cl_fill(c) > 0) return cl_take_line(c, out, cap);
    return 0;
}

/* 1 = line, 0 = EOF, -1 = deadline/error. Never runs the loop when a line is buffered. */
static int
pump_recv_line(cl_t *c, char *out, size_t cap)
{
    uint64_t end = now_ms() + 2000;
    for (;;) {
        int r;
        if (cl_take_line(c, out, cap)) return 1;
        r = cl_fill(c);
        if (r == 0) return 0;
        if (r == -2) return -1;
        if (r == -1) loop_once();
        if (now_ms() > end) {
            CHECK(!"pump_recv_line deadline");
            return -1;
        }
    }
}

/* 1 = clean EOF (recv == 0), -1 = reset or deadline. Discards stray bytes. */
static int
pump_wait_eof(cl_t *c)
{
    uint64_t end = now_ms() + 2000;
    char b[256];
    for (;;) {
        int r = sock_recv(c->fd, b, sizeof(b));
        if (r == 0) return 1;
        if (r < 0 && !sock_would_block()) return -1;
        if (r < 0) loop_once();
        if (now_ms() > end) {
            CHECK(!"pump_wait_eof deadline");
            return -1;
        }
    }
}

/* ---- JSON helpers ---- */
#  define L_HELLO(id)                    \
      "{\"jsonrpc\":\"2.0\",\"id\":" #id \
      ",\"method\":\"system.hello\",\"params\":{\"cmp_versions\":[\"1.0\"]}}\n"

static int64_t
resp_id(const char *line)
{
    yyjson_doc *d = yyjson_read(line, strlen(line), 0);
    yyjson_val *id = d ? yyjson_obj_get(yyjson_doc_get_root(d), "id") : NULL;
    int64_t v = (id && yyjson_is_int(id)) ? yyjson_get_sint(id) : -1;
    yyjson_doc_free(d);
    return v;
}

static int
resp_id_is_null(const char *line)
{
    yyjson_doc *d = yyjson_read(line, strlen(line), 0);
    yyjson_val *id = d ? yyjson_obj_get(yyjson_doc_get_root(d), "id") : NULL;
    int r = id && yyjson_is_null(id);
    yyjson_doc_free(d);
    return r;
}

/* error code, or 0 for a result reply, or 1 if unparsable */
static int
resp_err(const char *line)
{
    yyjson_doc *d = yyjson_read(line, strlen(line), 0);
    yyjson_val *root = d ? yyjson_doc_get_root(d) : NULL;
    yyjson_val *e = root ? yyjson_obj_get(root, "error") : NULL;
    int code = !root ? 1 : 0;
    if (e) code = (int)yyjson_get_sint(yyjson_obj_get(e, "code"));
    yyjson_doc_free(d);
    return code;
}

static int
resp_is_hello_ok(const char *line)
{
    yyjson_doc *d = yyjson_read(line, strlen(line), 0);
    yyjson_val *res = d ? yyjson_obj_get(yyjson_doc_get_root(d), "result") : NULL;
    const char *v = res ? yyjson_get_str(yyjson_obj_get(res, "cmp_version")) : NULL;
    int ok = v && strcmp(v, "1.0") == 0;
    yyjson_doc_free(d);
    return ok;
}

static void
fmt_ping(char *out, size_t cap, int id)
{
    snprintf(out, cap, "{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"system.ping\"}\n",
             id);
}

/* hello over c and check the result */
static void
do_hello(cl_t *c, int id)
{
    char req[200], line[1024];
    snprintf(req, sizeof(req),
             "{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"system.hello\","
             "\"params\":{\"cmp_versions\":[\"1.0\"]}}\n",
             id);
    CHECK(pump_send(c, req, strlen(req)) == 0);
    CHECK(pump_recv_line(c, line, sizeof(line)) == 1);
    CHECK(resp_is_hello_ok(line) && resp_id(line) == id);
}

/* ---- tests ---- */
static void
conn_hello_then_version(void)
{
    mgmt_conn_limits_t lim;
    cl_t *c;
    char line[1024];
    puts("conn_hello_then_version");
    small_limits(&lim);
    fixture_start(&lim);
    c = cl_new();
    do_hello(c, 1);
    CHECK(pump_send(c, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"system.version\"}\n",
                    52) == 0);
    CHECK(pump_recv_line(c, line, sizeof(line)) == 1);
    CHECK(resp_err(line) == 0 && resp_id(line) == 2);
    CHECK(counters().accepted == 1);
    cl_free(c);
    fixture_stop();
}

static void
conn_pipelined_in_order(void)
{
    mgmt_conn_limits_t lim;
    cl_t *c;
    char req[1024], p[100], line[1024];
    int i;
    puts("conn_pipelined_in_order");
    small_limits(&lim);
    fixture_start(&lim);
    c = cl_new();
    snprintf(req, sizeof(req), "%s", L_HELLO(1));
    for (i = 2; i <= 4; i++) {
        fmt_ping(p, sizeof(p), i);
        strcat(req, p);
    }
    CHECK(pump_send(c, req, strlen(req)) == 0);
    for (i = 1; i <= 4; i++) {
        CHECK(pump_recv_line(c, line, sizeof(line)) == 1);
        CHECK(resp_id(line) == i && resp_err(line) == 0);
    }
    cl_free(c);
    fixture_stop();
}

static void
conn_two_lines_one_segment(void)
{
    mgmt_conn_limits_t lim;
    cl_t *c;
    char req[600], p[100], line[1024];
    puts("conn_two_lines_one_segment");
    small_limits(&lim);
    fixture_start(&lim);
    c = cl_new();
    fmt_ping(p, sizeof(p), 2);
    snprintf(req, sizeof(req), "%s%s", L_HELLO(1), p);
    CHECK(pump_send(c, req, strlen(req)) == 0);
    CHECK(pump_recv_line(c, line, sizeof(line)) == 1);
    CHECK(resp_id(line) == 1 && resp_is_hello_ok(line));
    CHECK(pump_recv_line(c, line, sizeof(line)) == 1);
    CHECK(resp_id(line) == 2 && resp_err(line) == 0);
    cl_free(c);
    fixture_stop();
}

static void
conn_stops_dispatching_when_peer_does_not_read(void)
{
    mgmt_conn_limits_t lim;
    cl_t *c;
    char line[1024], pend[100];
    size_t pend_off = 0, pend_len = 0;
    uint64_t sent = 0, last_disp = (uint64_t)-1, d;
    int steady = 0, round, i;
    puts("conn_stops_dispatching_when_peer_does_not_read");
    small_limits(&lim);
    lim.request_budget_per_loop = 4;
    fixture_start(&lim);
    c = cl_new();
    do_hello(c, 1);

    for (round = 0; round < 2000 && steady < 3; round++) {
        uint64_t sent_before = sent;
        for (;;) {
            int r;
            if (pend_off == pend_len) {
                fmt_ping(pend, sizeof(pend), (int)sent + 2);
                pend_len = strlen(pend);
                pend_off = 0;
                r = sock_send(c->fd, pend, pend_len);
                if (r > 0) {
                    sent++;
                    pend_off = (size_t)r;
                } else {
                    pend_len = 0; /* nothing went out: drop the line */
                    break;
                }
            } else {
                r = sock_send(c->fd, pend + pend_off, pend_len - pend_off);
                if (r > 0)
                    pend_off += (size_t)r;
                else
                    break;
            }
        }
        for (i = 0; i < 20; i++)
            event_base_loop(g_eb, EVLOOP_NONBLOCK);
        d = disp_count();
        if (sent == sent_before && d == last_disp)
            steady++;
        else
            steady = 0;
        last_disp = d;
    }
    CHECK(steady >= 3);
    CHECK(sent > 0);
    CHECK(disp_count() < sent + 1); /* the server really stopped reading */

    /* Read everything while finishing the half-written request (sending first would
     * stall: the server only resumes once the client reads). */
    {
        uint64_t got = 0;
        int ordered = 1;
        uint64_t end = now_ms() + 2000;
        while (got < sent && now_ms() < end) {
            int progress = 0;
            if (pend_off < pend_len) {
                int r = sock_send(c->fd, pend + pend_off, pend_len - pend_off);
                if (r > 0) {
                    pend_off += (size_t)r;
                    progress = 1;
                }
            }
            while (got < sent && cl_try_line(c, line, sizeof(line))) {
                if (resp_id(line) != (int64_t)got + 2) ordered = 0;
                got++;
                progress = 1;
            }
            if (!progress) loop_once();
        }
        CHECK(got == sent);
        CHECK(ordered);
    }
    CHECK(disp_count() == sent + 1);
    cl_free(c);
    fixture_stop();
}

static void
conn_oversized_error_then_eof(void)
{
    mgmt_conn_limits_t lim;
    cl_t *c;
    char *junk, line[1024];
    puts("conn_oversized_error_then_eof");
    small_limits(&lim);
    fixture_start(&lim);
    c = cl_new();
    junk = malloc(70000);
    memset(junk, 'a', 70000);
    CHECK(pump_send(c, junk, 70000) == 0);
    free(junk);
    CHECK(pump_recv_line(c, line, sizeof(line)) == 1);
    CHECK(resp_err(line) == CMP_E_INVALID_REQUEST && resp_id_is_null(line));
    CHECK(pump_wait_eof(c) == 1);
    CHECK(counters().oversized == 1);
    cl_free(c);
    fixture_stop();
}

/* hello line with `pad` filler chars, without the LF; returns malloc'd */
static char *
hello_with_pad(size_t pad, size_t *len)
{
    static const char pre[] =
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system.hello\",\"params\":"
        "{\"cmp_versions\":[\"1.0\"],\"pad\":\"";
    static const char post[] = "\"}}";
    char *s = malloc(sizeof(pre) + pad + sizeof(post));
    memcpy(s, pre, sizeof(pre) - 1);
    memset(s + sizeof(pre) - 1, 'p', pad);
    memcpy(s + sizeof(pre) - 1 + pad, post, sizeof(post));
    *len = sizeof(pre) - 1 + pad + sizeof(post) - 1;
    return s;
}

static void
conn_oversized_with_lf_rejected(void)
{
    mgmt_conn_limits_t lim;
    cl_t *c;
    char *s, line[1024];
    size_t n, base;
    int variant;
    puts("conn_oversized_with_lf_rejected");
    small_limits(&lim);

    for (variant = 0; variant < 2; variant++) { /* 0: one send, 1: split before the LF */
        fixture_start(&lim);
        c = cl_new();
        s = hello_with_pad(66000, &n);
        CHECK(n > CMP_MAX_REQUEST_LINE);
        if (variant == 0) {
            s[n] = '\n';
            CHECK(pump_send(c, s, n + 1) == 0);
        } else {
            CHECK(pump_send(c, s, 40000) == 0);
            run_for_ms(20);
            s[n] = '\n';
            CHECK(pump_send(c, s + 40000, n + 1 - 40000) == 0);
        }
        free(s);
        CHECK(pump_recv_line(c, line, sizeof(line)) == 1);
        CHECK(resp_err(line) == CMP_E_INVALID_REQUEST && resp_id_is_null(line));
        CHECK(pump_wait_eof(c) == 1);
        CHECK(counters().dispatched == 0);
        cl_free(c);
        fixture_stop();
    }

    /* exactly max_request_line bytes before the LF passes */
    fixture_start(&lim);
    c = cl_new();
    s = hello_with_pad(0, &base);
    free(s);
    s = hello_with_pad(CMP_MAX_REQUEST_LINE - base, &n);
    CHECK(n == CMP_MAX_REQUEST_LINE);
    s[n] = '\n';
    CHECK(pump_send(c, s, n + 1) == 0);
    free(s);
    CHECK(pump_recv_line(c, line, sizeof(line)) == 1);
    CHECK(resp_is_hello_ok(line));
    CHECK(counters().dispatched == 1);
    cl_free(c);
    fixture_stop();
}

static void
conn_handshake_deadline(void)
{
    mgmt_conn_limits_t lim;
    cl_t *c, *h;
    char line[1024], p[100];
    puts("conn_handshake_deadline");
    small_limits(&lim);
    lim.handshake_deadline_ms = 200;
    fixture_start(&lim);
    c = cl_new();
    run_for_ms(300);
    CHECK(pump_wait_eof(c) == 1);
    CHECK(counters().handshake_timeouts == 1);
    CHECK(counters().open == 0);
    cl_free(c);

    h = cl_new();
    do_hello(h, 1);
    run_for_ms(500);
    fmt_ping(p, sizeof(p), 2);
    CHECK(pump_send(h, p, strlen(p)) == 0);
    CHECK(pump_recv_line(h, line, sizeof(line)) == 1);
    CHECK(resp_id(line) == 2 && resp_err(line) == 0);
    CHECK(counters().handshake_timeouts == 1);
    cl_free(h);
    fixture_stop();
}

static void
conn_connection_limit_busy(void)
{
    mgmt_conn_limits_t lim;
    cl_t *c[3], *d, *e;
    char line[1024];
    int i;
    puts("conn_connection_limit_busy");
    small_limits(&lim);
    lim.max_connections = 3;
    fixture_start(&lim);
    for (i = 0; i < 3; i++)
        c[i] = cl_new();
    run_for_ms(20);
    CHECK(counters().open == 3);
    d = cl_new();
    CHECK(pump_recv_line(d, line, sizeof(line)) == 1);
    CHECK(resp_err(line) == CMP_E_BUSY && resp_id_is_null(line));
    CHECK(pump_wait_eof(d) == 1);
    CHECK(counters().rejected_limit == 1);
    cl_free(d);
    for (i = 0; i < 3; i++)
        cl_free(c[i]);
    run_for_ms(50);
    CHECK(counters().open == 0);
    e = cl_new();
    do_hello(e, 1);
    cl_free(e);
    fixture_stop();
}

static void
conn_budget_defers_and_resumes(void)
{
    enum { N = 8 };
    mgmt_conn_limits_t lim;
    cl_t *c[N];
    char line[1024];
    int i, iters = 0, got[N] = {0}, total = 0;
    puts("conn_budget_defers_and_resumes");
    small_limits(&lim);
    lim.request_budget_per_loop = 2;
    fixture_start(&lim);
    for (i = 0; i < N; i++)
        c[i] = cl_new();
    run_for_ms(20); /* accept them all */
    for (i = 0; i < N; i++)
        CHECK(pump_send(c[i], L_HELLO(1), strlen(L_HELLO(1))) == 0);
    checks_on(2, 1, 1);
    while (total < N && iters < 200) {
        loop_once();
        iters++;
        for (i = 0; i < N; i++)
            while (cl_try_line(c[i], line, sizeof(line))) {
                CHECK(resp_is_hello_ok(line));
                got[i]++;
                total++;
            }
    }
    CHECK(total == N);
    CHECK(iters >= 4);
    CHECK(counters().budget_deferrals >= 6);
    checks_off();
    for (i = 0; i < N; i++)
        cl_free(c[i]);
    fixture_stop();
}

static void
conn_32_connections_hammer_keeps_loop_alive(void)
{
    enum { N = 32, PINGS = 200 };
    mgmt_conn_limits_t lim;
    cl_t *c[N];
    char *req[N];
    size_t req_len[N], req_off[N];
    int next_id[N], done = 0, i;
    char line[1024], p[100];
    uint64_t idle_end;
    puts("conn_32_connections_hammer_keeps_loop_alive");
    small_limits(&lim); /* defaults: budget 4, 32 connections */
    fixture_start(&lim);
    checks_on(lim.request_budget_per_loop, 1, 1);
    for (i = 0; i < N; i++) {
        c[i] = cl_new();
        do_hello(c[i], 1);
    }
    for (i = 0; i < N; i++) {
        size_t k;
        req[i] = malloc((size_t)PINGS * 64);
        req_len[i] = 0;
        for (k = 0; k < PINGS; k++) {
            fmt_ping(p, sizeof(p), (int)k + 2);
            memcpy(req[i] + req_len[i], p, strlen(p));
            req_len[i] += strlen(p);
        }
        req_off[i] = 0;
        next_id[i] = 2;
    }
    idle_end = now_ms() + 2000;
    while (done < N * PINGS) {
        int progress = 0;
        for (i = 0; i < N; i++) {
            if (req_off[i] < req_len[i]) {
                int r = sock_send(c[i]->fd, req[i] + req_off[i], req_len[i] - req_off[i]);
                if (r > 0) {
                    req_off[i] += (size_t)r;
                    progress = 1;
                }
            }
            while (cl_try_line(c[i], line, sizeof(line))) {
                CHECK(resp_id(line) == next_id[i] && resp_err(line) == 0);
                next_id[i]++;
                done++;
                progress = 1;
            }
        }
        if (!progress) loop_once();
        if (progress) idle_end = now_ms() + 2000;
        if (now_ms() > idle_end) {
            CHECK(!"hammer made no progress");
            break;
        }
        if (progress && (done & 7) == 0) loop_once();
    }
    CHECK(done == N * PINGS);
    checks_off();
    for (i = 0; i < N; i++) {
        free(req[i]);
        cl_free(c[i]);
    }
    fixture_stop();
}

static void
conn_accept_flood_is_budgeted(void)
{
    enum { N = 10 };
    mgmt_conn_limits_t lim;
    cl_t *c[N];
    int i, iters = 0;
    puts("conn_accept_flood_is_budgeted");
    small_limits(&lim);
    lim.accept_budget_per_loop = 3;
    lim.max_connections = 32;
    fixture_start(&lim);
    checks_on(0, 1, 1);
    for (i = 0; i < N; i++)
        c[i] = cl_new();
    loop_once();
    CHECK(counters().accepted == 3);
    CHECK(counters().accept_deferrals == 1);
    while (counters().accepted < N && iters++ < 100)
        loop_once();
    CHECK(counters().accepted == N);
    for (i = 0; i < N; i++)
        do_hello(c[i], 1);
    checks_off();
    for (i = 0; i < N; i++)
        cl_free(c[i]);
    fixture_stop();
}

#  define MAX_CAP_LINES 8
static char g_cap[MAX_CAP_LINES][1024];
static int g_cap_n;

static void
cap_sink(mqvpn_log_level_t level, const char *msg, void *ctx)
{
    (void)level;
    (void)ctx;
    if (g_cap_n < MAX_CAP_LINES) snprintf(g_cap[g_cap_n], sizeof(g_cap[0]), "%s", msg);
    g_cap_n++;
}

static void
conn_invalid_requests_log_budget(void)
{
    mgmt_conn_limits_t lim;
    char line[1024];
    int i;
    puts("conn_invalid_requests_log_budget");
    small_limits(&lim);
    lim.log_interval_ms = 200;
    g_cap_n = 0;
    mqvpn_log_set_level(MQVPN_LOG_WARN);
    mqvpn_log_set_sink(cap_sink, NULL);
    fixture_start(&lim);
    for (i = 0; i < 50; i++) {
        cl_t *c = cl_new();
        CHECK(pump_send(c, "{not json}\n", 11) == 0);
        CHECK(pump_recv_line(c, line, sizeof(line)) == 1);
        CHECK(resp_err(line) == CMP_E_PARSE_ERROR);
        cl_free(c);
    }
    run_for_ms(100);
    CHECK(counters().invalid_requests == 50);
    CHECK(counters().log_lines == 0);
    CHECK(g_cap_n == 0);
    run_for_ms(300);
    CHECK(counters().log_lines == 1);
    CHECK(g_cap_n == 1);
    CHECK(strstr(g_cap[0], "mgmt ipc [") != NULL);
    CHECK(strstr(g_cap[0], "invalid=50") != NULL);
    run_for_ms(500);
    CHECK(counters().log_lines == 1);
    CHECK(g_cap_n == 1);
    fixture_stop();
    mqvpn_log_set_sink(NULL, NULL);
}

static void
conn_notification_no_reply(void)
{
    mgmt_conn_limits_t lim;
    cl_t *c;
    char req[400], line[1024];
    puts("conn_notification_no_reply");
    small_limits(&lim);
    fixture_start(&lim);
    c = cl_new();
    snprintf(req, sizeof(req), "%s%s",
             "{\"jsonrpc\":\"2.0\",\"method\":\"system.ping\"}\n", L_HELLO(1));
    CHECK(pump_send(c, req, strlen(req)) == 0);
    CHECK(pump_recv_line(c, line, sizeof(line)) == 1);
    CHECK(resp_id(line) == 1 && resp_is_hello_ok(line));
    run_for_ms(50);
    CHECK(cl_try_line(c, line, sizeof(line)) == 0);
    CHECK(counters().dispatched == 2);
    cl_free(c);
    fixture_stop();
}

static void
conn_peer_closes_mid_response(void)
{
    mgmt_conn_limits_t lim;
    cl_t *c, *d;
    puts("conn_peer_closes_mid_response");
    small_limits(&lim);
    fixture_start(&lim);
    c = cl_new();
    CHECK(pump_send(c, L_HELLO(1), strlen(L_HELLO(1))) == 0);
    cl_free(c); /* close without reading the reply */
    run_for_ms(50);
    CHECK(counters().open == 0);
    d = cl_new();
    do_hello(d, 1);
    CHECK(counters().open == 1);
    cl_free(d);
    fixture_stop();
}

static void
conn_endpoint_free_with_open_connections(void)
{
    mgmt_conn_limits_t lim;
    cl_t *c[3];
    char b[16];
    int i;
    puts("conn_endpoint_free_with_open_connections");
    small_limits(&lim);
    fixture_start(&lim);
    for (i = 0; i < 3; i++)
        c[i] = cl_new();
    run_for_ms(20);
    CHECK(counters().open == 3);
    mgmt_endpoint_free(g_ep);
    g_ep = NULL;
    g_l = NULL;
    /* libevent closes a freed bufferevent's fd from its finalizer, in the next loop pass
     */
    event_base_loop(g_eb, EVLOOP_NONBLOCK);
    for (i = 0; i < 3; i++) {
        CHECK(sock_recv(c[i]->fd, b, sizeof(b)) == 0);
        cl_free(c[i]);
    }
    fixture_stop();
}

static void
conn_crlf_tolerated(void)
{
    mgmt_conn_limits_t lim;
    cl_t *c;
    char req[300], line[1024];
    size_t n;
    puts("conn_crlf_tolerated");
    small_limits(&lim);
    fixture_start(&lim);
    c = cl_new();
    snprintf(req, sizeof(req), "%s", L_HELLO(1));
    n = strlen(req);
    req[n - 1] = '\r';
    req[n] = '\n';
    CHECK(pump_send(c, req, n + 1) == 0);
    CHECK(pump_recv_line(c, line, sizeof(line)) == 1);
    CHECK(resp_is_hello_ok(line));
    cl_free(c);
    fixture_stop();
}

int
main(void)
{
    signal(SIGPIPE, SIG_IGN); /* the CLI process ignores it too; libevent writes without
                                 MSG_NOSIGNAL */
    conn_hello_then_version();
    conn_pipelined_in_order();
    conn_two_lines_one_segment();
    conn_stops_dispatching_when_peer_does_not_read();
    conn_oversized_error_then_eof();
    conn_oversized_with_lf_rejected();
    conn_handshake_deadline();
    conn_connection_limit_busy();
    conn_budget_defers_and_resumes();
    conn_32_connections_hammer_keeps_loop_alive();
    conn_accept_flood_is_budgeted();
    conn_invalid_requests_log_budget();
    conn_notification_no_reply();
    conn_peer_closes_mid_response();
    conn_endpoint_free_with_open_connections();
    conn_crlf_tolerated();
    if (g_failed) {
        fprintf(stderr, "%d check(s) failed\n", g_failed);
        return 1;
    }
    puts("test_mgmt_conn: all passed");
    return 0;
}

#endif /* _WIN32 */
