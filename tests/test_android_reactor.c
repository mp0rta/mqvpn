// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* tests/test_android_reactor.c — the Android platform's poll()/eventfd
 * reactor (src/platform/android/reactor.c) over real loopback sockets, a real
 * unconnected client and the real posix bind. Linux only (eventfd). Own
 * CHECK, not assert(): ctest also runs this in Release builds.
 *
 * Every drain ends in mqvpn_client_on_socket_recv(), which feeds xquic junk
 * it drops but counts the bytes on the path first — so the public
 * mqvpn_client_get_paths().bytes_rx is the delivery evidence, without any
 * accessor into the bind ctx. gro_policy is 0 everywhere a count matters
 * (one receive = one datagram, so the 64-unit drain budget is exact). */

#include "reactor.h"

#include "log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c)                                                                  \
    do {                                                                          \
        if (!(c)) {                                                               \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #c); \
            exit(1);                                                              \
        }                                                                         \
    } while (0)

#define DGRAM_LEN 100 /* bytes per test datagram; bytes_rx / DGRAM_LEN = datagrams */

/* ── capturing log sink ── */

#define SINK_LINES 256
static struct {
    int n;
    mqvpn_log_level_t level[SINK_LINES];
    char msg[SINK_LINES][256];
} g_sink;

static void
sink_fn(mqvpn_log_level_t level, const char *msg, void *ctx)
{
    (void)ctx;
    if (g_sink.n >= SINK_LINES) return;
    g_sink.level[g_sink.n] = level;
    snprintf(g_sink.msg[g_sink.n], sizeof(g_sink.msg[0]), "%s", msg);
    g_sink.n++;
}

static int
sink_count(const char *needle)
{
    int c = 0;
    for (int i = 0; i < g_sink.n; i++)
        if (strstr(g_sink.msg[i], needle)) c++;
    return c;
}

static void
sink_reset(void)
{
    g_sink.n = 0;
}

/* ── helpers ── */

static int64_t
now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Blocking loopback UDP socket, like the ones Kotlin's PathBinder creates
 * (DatagramSocket): the bind receives with MSG_DONTWAIT, so blocking is fine. */
static int
udp_socket(struct sockaddr_in *addr)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    CHECK(fd >= 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(fd, (struct sockaddr *)&a, sizeof(a)) == 0);
    socklen_t len = sizeof(a);
    CHECK(getsockname(fd, (struct sockaddr *)&a, &len) == 0);
    if (addr) *addr = a;
    return fd;
}

static int
fd_is_open(int fd)
{
    return fcntl(fd, F_GETFD) != -1;
}

static void
send_n(int from, const struct sockaddr_in *to, int n)
{
    uint8_t buf[DGRAM_LEN];
    memset(buf, 0x5a, sizeof(buf));
    for (int i = 0; i < n; i++)
        CHECK(sendto(from, buf, sizeof(buf), 0, (const struct sockaddr *)to,
                     sizeof(*to)) == DGRAM_LEN);
}

/* Loopback delivery is fast but not synchronous everywhere. */
static void
settle(void)
{
    struct timespec ts = {0, 100 * 1000 * 1000};
    nanosleep(&ts, NULL);
}

static void
noop_tun_output(const uint8_t *pkt, size_t len, void *ctx)
{
    (void)pkt;
    (void)len;
    (void)ctx;
}

static void
noop_config_ready(const mqvpn_tunnel_info_t *info, void *ctx)
{
    (void)info;
    (void)ctx;
}

/* An unconnected client: add_path allocates a PENDING slot, on_socket_recv
 * counts bytes and hands the datagram to the engine (which drops junk). */
static mqvpn_client_t *
make_client(void)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    CHECK(cfg);
    mqvpn_client_callbacks_t cbs = MQVPN_CLIENT_CALLBACKS_INIT;
    cbs.tun_output = noop_tun_output;
    cbs.tunnel_config_ready = noop_config_ready;
    mqvpn_client_t *c = mqvpn_client_new(cfg, &cbs, NULL);
    CHECK(c);
    mqvpn_config_free(cfg);
    return c;
}

static uint64_t
path_bytes_rx(mqvpn_client_t *c, mqvpn_path_handle_t h)
{
    mqvpn_path_info_t out[MQVPN_MAX_PATHS];
    memset(out, 0, sizeof(out));
    for (int i = 0; i < MQVPN_MAX_PATHS; i++)
        out[i].struct_size = sizeof(out[i]);
    int n = 0;
    CHECK(mqvpn_client_get_paths(c, out, MQVPN_MAX_PATHS, &n) == MQVPN_OK);
    for (int i = 0; i < n; i++)
        if (out[i].handle == h) return out[i].bytes_rx;
    CHECK(!"handle not listed by get_paths");
    return 0;
}

/* ── tests ── */

static void
test_new_free_and_timeout(void)
{
    mqvpn_android_reactor_t *r = mqvpn_android_reactor_new();
    CHECK(r);
    /* Empty table: NULL client is legal and the wait runs to its timeout
     * (monotonic clock, wide window). */
    int64_t t0 = now_ms();
    CHECK(mqvpn_android_reactor_wait(r, NULL, 50) == 0);
    int64_t el = now_ms() - t0;
    CHECK(el >= 30 && el < 500);
    CHECK(mqvpn_android_reactor_take_bad_fd(r) == -1);
    /* No client: destroy only clears the (already empty) table, logs nothing. */
    sink_reset();
    mqvpn_android_reactor_client_destroy(r, NULL);
    CHECK(g_sink.n == 0);
    CHECK(mqvpn_android_reactor_wait(r, NULL, 0) == 0);
    mqvpn_android_reactor_free(r);
    printf("  test_new_free_and_timeout: OK\n");
}

static void *
waker_thread(void *arg)
{
    mqvpn_android_reactor_t *r = arg;
    struct timespec ts = {0, 20 * 1000 * 1000};
    nanosleep(&ts, NULL); /* let the waiter reach poll() */
    CHECK(mqvpn_android_reactor_wake(r) == 0);
    return NULL;
}

static void
test_wake(void)
{
    mqvpn_android_reactor_t *r = mqvpn_android_reactor_new();
    CHECK(r);

    /* A wake issued BEFORE the wait is not lost. */
    CHECK(mqvpn_android_reactor_wake(r) == 0);
    int64_t t0 = now_ms();
    CHECK(mqvpn_android_reactor_wait(r, NULL, 2000) == 0);
    CHECK(now_ms() - t0 < 500);

    /* A wake from another thread returns a long wait promptly. */
    pthread_t th;
    CHECK(pthread_create(&th, NULL, waker_thread, r) == 0);
    t0 = now_ms();
    CHECK(mqvpn_android_reactor_wait(r, NULL, 2000) == 0);
    CHECK(now_ms() - t0 < 500);
    CHECK(pthread_join(th, NULL) == 0);

    /* Coalescing: several wakes, one prompt return, then nothing pending —
     * shown by a second timed wait running to its timeout (wait(0) could not
     * tell "found a wake" from "timed out"; both return 0 drains). */
    CHECK(mqvpn_android_reactor_wake(r) == 0);
    CHECK(mqvpn_android_reactor_wake(r) == 0);
    CHECK(mqvpn_android_reactor_wake(r) == 0);
    t0 = now_ms();
    CHECK(mqvpn_android_reactor_wait(r, NULL, 2000) == 0);
    CHECK(now_ms() - t0 < 500);
    t0 = now_ms();
    CHECK(mqvpn_android_reactor_wait(r, NULL, 50) == 0);
    CHECK(now_ms() - t0 >= 30);

    mqvpn_android_reactor_free(r);
    printf("  test_wake: OK\n");
}

static void
test_rx_delivery_and_budget(void)
{
    sink_reset();
    mqvpn_android_reactor_t *r = mqvpn_android_reactor_new();
    CHECK(r);
    mqvpn_client_t *c = make_client();
    struct sockaddr_in addr;
    int fd = udp_socket(&addr);
    int peer = udp_socket(NULL);

    mqvpn_path_handle_t h = mqvpn_android_reactor_add_path(r, c, fd, "test0", 1, 0);
    CHECK(h >= 0);
    CHECK(mqvpn_android_reactor_entry_state(r, h) == MQVPN_REACTOR_ENTRY_ATTACHED);
    /* The bind's construction line reaches the sink (global logger). */
    CHECK(sink_count("bind-posix: socket buffers on test0") == 1);
    /* Attached entry: a NULL client is a contract violation. */
    CHECK(mqvpn_android_reactor_wait(r, NULL, 0) == -1);

    /* N datagrams (<= the 64 budget) -> one wait -> all delivered. */
    send_n(peer, &addr, 10);
    settle();
    CHECK(mqvpn_android_reactor_wait(r, c, 2000) == 1);
    CHECK(path_bytes_rx(c, h) == 10 * DGRAM_LEN);
    /* Nothing left: the next wait times out. */
    int64_t t0 = now_ms();
    CHECK(mqvpn_android_reactor_wait(r, c, 50) == 0);
    CHECK(now_ms() - t0 >= 30);

    /* A pending wake and a readable UDP fd together: the SAME wait drains
     * the UDP (no early return on the eventfd) and consumes the wake. */
    CHECK(mqvpn_android_reactor_wake(r) == 0);
    send_n(peer, &addr, 3);
    settle();
    CHECK(mqvpn_android_reactor_wait(r, c, 2000) == 1);
    CHECK(path_bytes_rx(c, h) == 13 * DGRAM_LEN);
    t0 = now_ms();
    CHECK(mqvpn_android_reactor_wait(r, c, 50) == 0);
    CHECK(now_ms() - t0 >= 30);

    /* Two paths readable: A has 65 (one over the budget), B has 1 — one pass
     * advances both; the second pass finishes A. */
    struct sockaddr_in addr_b;
    int fd_b = udp_socket(&addr_b);
    mqvpn_path_handle_t hb = mqvpn_android_reactor_add_path(r, c, fd_b, "test1", 1, 0);
    CHECK(hb >= 0 && hb != h);
    send_n(peer, &addr, 65);
    send_n(peer, &addr_b, 1);
    settle();
    CHECK(mqvpn_android_reactor_wait(r, c, 2000) == 2);
    CHECK(path_bytes_rx(c, h) == (13 + 64) * DGRAM_LEN);
    CHECK(path_bytes_rx(c, hb) == 1 * DGRAM_LEN);
    CHECK(mqvpn_android_reactor_wait(r, c, 2000) == 1);
    CHECK(path_bytes_rx(c, h) == (13 + 65) * DGRAM_LEN);

    /* Orderly removal: remove -> not polled -> close -> released -> FREE. */
    send_n(peer, &addr, 1); /* queued but must not be drained after remove */
    settle();
    CHECK(mqvpn_android_reactor_remove_path(r, c, h) == MQVPN_OK);
    CHECK(mqvpn_android_reactor_entry_state(r, h) == MQVPN_REACTOR_ENTRY_DETACHED);
    CHECK(mqvpn_android_reactor_wait(r, c, 50) == 0);
    CHECK(path_bytes_rx(c, h) == (13 + 65) * DGRAM_LEN);
    CHECK(close(fd) == 0);
    sink_reset();
    CHECK(mqvpn_android_reactor_path_released(r, c, h) == MQVPN_OK);
    CHECK(mqvpn_android_reactor_entry_state(r, h) == -1);
    /* gro 0: one receive per datagram. 10 + 3 + 64 + 1 = 78 were drained; the
     * one queued after remove never was. */
    CHECK(sink_count("released: receives=78 datagrams=78") == 1);
    /* A second released on the freed entry: argument error from the reactor. */
    CHECK(mqvpn_android_reactor_path_released(r, c, h) == MQVPN_ERR_INVALID_ARG);

    /* Teardown with hb still attached: harvest line, destroy, empty table. */
    sink_reset();
    mqvpn_android_reactor_client_destroy(r, c);
    /* The released path's 78 (added on OK) plus hb's 1, harvested at destroy. */
    CHECK(sink_count("android-reactor: udp-rx: receives=79 datagrams=79") == 1);
    CHECK(mqvpn_android_reactor_entry_state(r, hb) == -1);
    CHECK(fd_is_open(fd_b)); /* destroy never closes: the platform does */
    CHECK(close(fd_b) == 0);
    CHECK(close(peer) == 0);
    int64_t t1 = now_ms();
    CHECK(mqvpn_android_reactor_wait(r, NULL, 50) == 0);
    CHECK(now_ms() - t1 >= 30);
    mqvpn_android_reactor_free(r);
    printf("  test_rx_delivery_and_budget: OK\n");
}

static void
test_add_failure_ownership(void)
{
    sink_reset();
    mqvpn_android_reactor_t *r1 = mqvpn_android_reactor_new();
    mqvpn_android_reactor_t *r2 = mqvpn_android_reactor_new();
    CHECK(r1 && r2);
    mqvpn_client_t *c = make_client();
    int fds[MQVPN_MAX_PATHS];
    mqvpn_path_handle_t hs[MQVPN_MAX_PATHS];
    for (int i = 0; i < MQVPN_MAX_PATHS; i++) {
        fds[i] = udp_socket(NULL);
        hs[i] = mqvpn_android_reactor_add_path(r1, c, fds[i], "full", 0, 0);
        CHECK(hs[i] >= 0);
    }
    /* Reactor table full: -1, nothing built, fd untouched. */
    int extra = udp_socket(NULL);
    CHECK(mqvpn_android_reactor_add_path(r1, c, extra, "extra", 0, 0) == -1);
    CHECK(fd_is_open(extra));
    CHECK(sink_count("table full") == 1);
    CHECK(sink_count("bind-posix: socket buffers on extra") == 0); /* nothing built */
    /* Library table full, reactor table with room (a second reactor over
     * the same client): the bind ctx is built, mqvpn_client_add_path refuses,
     * the ctx is freed here (ASan proves it), the reservation is released
     * and the fd is untouched. */
    sink_reset();
    CHECK(mqvpn_android_reactor_add_path(r2, c, extra, "ninth", 0, 0) == -1);
    CHECK(fd_is_open(extra));
    CHECK(sink_count("bind-posix: socket buffers on ninth") == 1); /* ctx was built */
    CHECK(sink_count("library refused the path") == 1);
    /* r2 has no live entry (the refused add released its reservation): its
     * free neither asserts nor WARNs. A zero count needs a sink with room. */
    mqvpn_android_reactor_free(r2);
    CHECK(g_sink.n < SINK_LINES);
    CHECK(sink_count("freed with") == 0);
    CHECK(close(extra) == 0);
    mqvpn_android_reactor_client_destroy(r1, c);
    for (int i = 0; i < MQVPN_MAX_PATHS; i++)
        CHECK(close(fds[i]) == 0);
    mqvpn_android_reactor_free(r1);
    printf("  test_add_failure_ownership: OK\n");
}

static void
test_released_state_errors(void)
{
    sink_reset();
    mqvpn_android_reactor_t *r = mqvpn_android_reactor_new();
    CHECK(r);
    mqvpn_client_t *c = make_client();
    int fd = udp_socket(NULL);
    mqvpn_path_handle_t h = mqvpn_android_reactor_add_path(r, c, fd, "st", 0, 0);
    CHECK(h >= 0);
    /* Released on an ATTACHED entry: reactor argument error, nothing called. */
    CHECK(mqvpn_android_reactor_path_released(r, c, h) == MQVPN_ERR_INVALID_ARG);
    CHECK(mqvpn_android_reactor_entry_state(r, h) == MQVPN_REACTOR_ENTRY_ATTACHED);
    /* Unknown handle. */
    CHECK(mqvpn_android_reactor_remove_path(r, c, 12345) == MQVPN_ERR_INVALID_ARG);
    CHECK(mqvpn_android_reactor_path_released(r, c, 12345) == MQVPN_ERR_INVALID_ARG);

    /* Bad-fd chain WITHOUT remove_path: take_bad_fd detaches in the table
     * only, so the library slot is still PENDING and refuses the release
     * with INVALID_STATE; the entry stays DETACHED, ctx library-owned, and
     * destroy harvests + finalises it (no leak under ASan). */
    CHECK(close(fd) == 0);
    CHECK(mqvpn_android_reactor_wait(r, c, 50) == 0);
    CHECK(mqvpn_android_reactor_entry_state(r, h) == MQVPN_REACTOR_ENTRY_INVALID);
    CHECK(mqvpn_android_reactor_take_bad_fd(r) == h);
    CHECK(mqvpn_android_reactor_entry_state(r, h) == MQVPN_REACTOR_ENTRY_DETACHED);
    CHECK(mqvpn_android_reactor_path_released(r, c, h) == MQVPN_ERR_INVALID_STATE);
    CHECK(mqvpn_android_reactor_entry_state(r, h) == MQVPN_REACTOR_ENTRY_DETACHED);
    CHECK(sink_count("transport stays library-owned") == 1);
    mqvpn_android_reactor_client_destroy(r, c);
    CHECK(mqvpn_android_reactor_entry_state(r, h) == -1);
    mqvpn_android_reactor_free(r);
    printf("  test_released_state_errors: OK\n");
}

static void
test_bad_fd_reuse(void)
{
    sink_reset();
    mqvpn_android_reactor_t *r = mqvpn_android_reactor_new();
    CHECK(r);
    mqvpn_client_t *c = make_client();
    int fd = udp_socket(NULL);
    int peer = udp_socket(NULL);
    mqvpn_path_handle_t h = mqvpn_android_reactor_add_path(r, c, fd, "bad", 0, 0);
    CHECK(h >= 0);

    /* 1. Closed behind the platform: the next wait sees POLLNVAL -> INVALID. */
    CHECK(close(fd) == 0);
    CHECK(mqvpn_android_reactor_wait(r, c, 50) == 0);
    CHECK(mqvpn_android_reactor_entry_state(r, h) == MQVPN_REACTOR_ENTRY_INVALID);
    CHECK(sink_count("is not open (POLLNVAL)") == 1);

    /* 2. The number is reused by a foreign socket that has an unread
     *    datagram. The lowest-free rule usually hands the closed number
     *    straight back; if it did not, dup2 forces the reuse. Either way
     *    `fd` now names the foreign socket. */
    struct sockaddr_in faddr;
    int foreign = udp_socket(&faddr);
    if (foreign != fd) {
        CHECK(dup2(foreign, fd) == fd);
        CHECK(close(foreign) == 0);
    }
    send_n(peer, &faddr, 1);
    settle();
    /* 3. The reactor neither polls nor drains it: the datagram is still there. */
    CHECK(mqvpn_android_reactor_wait(r, c, 50) == 0);
    struct pollfd p = {.fd = fd, .events = POLLIN, .revents = 0};
    CHECK(poll(&p, 1, 0) == 1 && (p.revents & POLLIN));
    CHECK(path_bytes_rx(c, h) == 0);

    /* 4. The platform learns the handle once, removes, does NOT close the
     *    number, reports the release. */
    CHECK(mqvpn_android_reactor_take_bad_fd(r) == h);
    CHECK(mqvpn_android_reactor_take_bad_fd(r) == -1);
    CHECK(mqvpn_android_reactor_remove_path(r, c, h) == MQVPN_OK);
    CHECK(mqvpn_android_reactor_path_released(r, c, h) == MQVPN_OK);
    CHECK(mqvpn_android_reactor_entry_state(r, h) == -1);
    /* 5. The foreign socket is untouched and still works. */
    CHECK(fd_is_open(fd));
    uint8_t buf[DGRAM_LEN];
    CHECK(recv(fd, buf, sizeof(buf), MSG_DONTWAIT) == DGRAM_LEN);
    CHECK(close(fd) == 0);
    CHECK(close(peer) == 0);
    mqvpn_android_reactor_client_destroy(r, c);
    mqvpn_android_reactor_free(r);
    printf("  test_bad_fd_reuse: OK\n");
}

static void
test_poisoned(void)
{
    sink_reset();
    mqvpn_android_reactor_t *r = mqvpn_android_reactor_new();
    CHECK(r);
    mqvpn_client_t *a = make_client();
    mqvpn_client_t *b = make_client(); /* never saw the handle */
    int fd = udp_socket(NULL);
    mqvpn_path_handle_t h = mqvpn_android_reactor_add_path(r, a, fd, "poison", 0, 0);
    CHECK(h >= 0);
    CHECK(mqvpn_android_reactor_remove_path(r, a, h) == MQVPN_OK);
    /* Released against the wrong client: the library answers INVALID_ARG ->
     * ledger corruption -> POISONED, session-fatal code. */
    CHECK(mqvpn_android_reactor_path_released(r, b, h) == MQVPN_REACTOR_POISONED);
    CHECK(mqvpn_android_reactor_entry_state(r, h) == MQVPN_REACTOR_ENTRY_POISONED);
    CHECK(sink_count("entry poisoned") == 1);
    /* Never reused, polled or released again. */
    CHECK(mqvpn_android_reactor_path_released(r, a, h) == MQVPN_ERR_INVALID_ARG);
    CHECK(mqvpn_android_reactor_remove_path(r, a, h) == MQVPN_ERR_INVALID_ARG);
    CHECK(mqvpn_android_reactor_wait(r, a, 0) == 0);
    /* The owning client still holds the ctx (slot CLOSED_DROPPED) and
     * finalises it in destroy; the table is cleared without a dereference. */
    mqvpn_android_reactor_client_destroy(r, a);
    CHECK(mqvpn_android_reactor_entry_state(r, h) == -1);
    mqvpn_client_destroy(b);
    CHECK(close(fd) == 0);
    mqvpn_android_reactor_free(r);
    printf("  test_poisoned: OK\n");
}

static void
test_error_branches(void)
{
    /* (i) Bind construction failure: fd -1 fails getsockname (WARN) and the
     *     bind refuses it before building anything. -1, and the reservation
     *     is released: an 8th real path still fits the table. */
    sink_reset();
    mqvpn_android_reactor_t *r = mqvpn_android_reactor_new();
    CHECK(r);
    mqvpn_client_t *c = make_client();
    int fds[MQVPN_MAX_PATHS];
    for (int i = 0; i < MQVPN_MAX_PATHS - 1; i++) {
        fds[i] = udp_socket(NULL);
        CHECK(mqvpn_android_reactor_add_path(r, c, fds[i], "err", 0, 0) >= 0);
    }
    sink_reset();
    CHECK(mqvpn_android_reactor_add_path(r, c, -1, "badfd", 0, 0) == -1);
    CHECK(sink_count("transport setup failed") == 1);
    CHECK(sink_count("getsockname") == 1);
    fds[MQVPN_MAX_PATHS - 1] = udp_socket(NULL);
    CHECK(mqvpn_android_reactor_add_path(r, c, fds[MQVPN_MAX_PATHS - 1], "last", 0, 0) >=
          0);
    mqvpn_android_reactor_client_destroy(r, c);
    for (int i = 0; i < MQVPN_MAX_PATHS; i++)
        CHECK(close(fds[i]) == 0);
    mqvpn_android_reactor_free(r);

    /* (ii) INVALID, then remove_path BEFORE take_bad_fd: the library is
     *      called and the entry detaches; the handle is never delivered by
     *      take_bad_fd afterwards; the release completes. */
    r = mqvpn_android_reactor_new();
    CHECK(r);
    c = make_client();
    int fd = udp_socket(NULL);
    mqvpn_path_handle_t h = mqvpn_android_reactor_add_path(r, c, fd, "inv", 0, 0);
    CHECK(h >= 0);
    CHECK(close(fd) == 0); /* behind the reactor; nothing opened before the wait */
    CHECK(mqvpn_android_reactor_wait(r, c, 50) == 0);
    CHECK(mqvpn_android_reactor_entry_state(r, h) == MQVPN_REACTOR_ENTRY_INVALID);
    CHECK(mqvpn_android_reactor_remove_path(r, c, h) == MQVPN_OK);
    CHECK(mqvpn_android_reactor_entry_state(r, h) == MQVPN_REACTOR_ENTRY_DETACHED);
    CHECK(mqvpn_android_reactor_take_bad_fd(r) == -1);
    CHECK(mqvpn_android_reactor_path_released(r, c, h) == MQVPN_OK);
    CHECK(mqvpn_android_reactor_entry_state(r, h) == -1);
    mqvpn_android_reactor_client_destroy(r, c);
    mqvpn_android_reactor_free(r);

    /* (iii) INVALID at destroy: the harvest still reads the entry's RX
     *       counters (its ctx stays library-owned until destroy finalises it). */
    r = mqvpn_android_reactor_new();
    CHECK(r);
    c = make_client();
    struct sockaddr_in addr;
    fd = udp_socket(&addr);
    int peer = udp_socket(NULL);
    h = mqvpn_android_reactor_add_path(r, c, fd, "inv2", 0, 0);
    CHECK(h >= 0);
    send_n(peer, &addr, 2);
    settle();
    CHECK(mqvpn_android_reactor_wait(r, c, 2000) == 1);
    CHECK(path_bytes_rx(c, h) == 2 * DGRAM_LEN);
    CHECK(close(fd) == 0); /* behind the reactor; nothing opened before the wait */
    CHECK(mqvpn_android_reactor_wait(r, c, 50) == 0);
    CHECK(mqvpn_android_reactor_entry_state(r, h) == MQVPN_REACTOR_ENTRY_INVALID);
    sink_reset();
    mqvpn_android_reactor_client_destroy(r, c);
    CHECK(sink_count("android-reactor: udp-rx: receives=2 datagrams=2") == 1);
    CHECK(mqvpn_android_reactor_entry_state(r, h) == -1);
    CHECK(close(peer) == 0);
    mqvpn_android_reactor_free(r);
    printf("  test_error_branches: OK\n");
}

int
main(void)
{
    mqvpn_log_set_sink(sink_fn, NULL);
    test_new_free_and_timeout();
    test_wake();
    test_rx_delivery_and_budget();
    test_add_failure_ownership();
    test_released_state_errors();
    test_bad_fd_reuse();
    test_poisoned();
    test_error_branches();
    mqvpn_log_set_sink(NULL, NULL); /* stderr again */
    printf("test_android_reactor: all OK\n");
    return 0;
}
