// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* tests/test_bind_posix_socket.c — mqvpn_bind_posix over real loopback UDP
 * sockets, with no seam: whatever the host kernel does is what the bind
 * sees. Portable POSIX (built on Linux and Darwin): on Darwin it is the only
 * test of the bind's non-Linux branch (one syscall per datagram), which
 * macOS and iOS run in production. Links the bind alone — the two delivery
 * targets below are stubs, so no core, xquic or TLS is involved. Own CHECK,
 * not assert(): the verdict must not depend on NDEBUG. */

#include "mqvpn_bind_posix.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stddef.h>
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

/* ── delivery stubs (the bind's only calls into libmqvpn) ── */

#define MAX_RX        16
#define SERVER_HANDLE (-1000) /* marks a delivery through the server entry point */
static struct {
    int n;
    mqvpn_path_handle_t handle[MAX_RX];
    size_t len[MAX_RX];
    uint8_t first[MAX_RX];
    uint16_t peer_port[MAX_RX];
} g_rx;

static void
rx_record(mqvpn_path_handle_t h, const uint8_t *pkt, size_t len,
          const struct sockaddr *peer)
{
    CHECK(g_rx.n < MAX_RX);
    g_rx.handle[g_rx.n] = h;
    g_rx.len[g_rx.n] = len;
    g_rx.first[g_rx.n] = len ? pkt[0] : 0;
    g_rx.peer_port[g_rx.n] =
        peer->sa_family == AF_INET
            ? ntohs(((const struct sockaddr_in *)(const void *)peer)->sin_port)
            : 0;
    g_rx.n++;
}

int
mqvpn_client_on_socket_recv(mqvpn_client_t *client, mqvpn_path_handle_t path,
                            const uint8_t *pkt, size_t len, const struct sockaddr *peer,
                            socklen_t peer_len)
{
    (void)client;
    (void)peer_len;
    rx_record(path, pkt, len, peer);
    return MQVPN_OK;
}

int
mqvpn_server_on_socket_recv(mqvpn_server_t *server, const uint8_t *pkt, size_t len,
                            const struct sockaddr *peer, socklen_t peer_len)
{
    (void)server;
    (void)peer_len;
    rx_record(SERVER_HANDLE, pkt, len, peer);
    return MQVPN_OK;
}

/* ── helpers ── */

/* Non-blocking UDP socket on 127.0.0.1:<ephemeral>, like path_mgr's. */
static int
udp_socket(struct sockaddr_in *addr)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(fd >= 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(fd, (struct sockaddr *)&a, sizeof(a)) == 0);
    socklen_t len = sizeof(a);
    CHECK(getsockname(fd, (struct sockaddr *)&a, &len) == 0);
    int fl = fcntl(fd, F_GETFL, 0);
    CHECK(fl >= 0 && fcntl(fd, F_SETFL, fl | O_NONBLOCK) == 0);
    if (addr) *addr = a;
    return fd;
}

static int
fd_is_open(int fd)
{
    return fcntl(fd, F_GETFD) != -1;
}

static void
wait_readable(int fd)
{
    struct pollfd p = {.fd = fd, .events = POLLIN};
    CHECK(poll(&p, 1, 2000) == 1);
}

/* Loopback delivery is fast but not synchronous everywhere: give a burst
 * time to land before asserting on what one drain call picks up. */
static void
settle(void)
{
    struct timespec ts = {0, 200 * 1000 * 1000};
    nanosleep(&ts, NULL);
}

static mqvpn_bind_posix_opts_t
opts_default(void)
{
    mqvpn_bind_posix_opts_t o;
    memset(&o, 0, sizeof(o));
    o.struct_size = sizeof(o);
    o.socket_buf_bytes = -1; /* leave the test sockets alone unless a test says so */
    snprintf(o.tag, sizeof(o.tag), "test");
    return o;
}

static mqvpn_bind_posix_stats_t
path_stats(const void *ctx)
{
    mqvpn_bind_posix_stats_t st;
    memset(&st, 0, sizeof(st));
    st.struct_size = sizeof(st);
    mqvpn_bind_posix_path_get_stats(ctx, &st);
    return st;
}

/* ── tests ── */

static void
test_ctor_rejects_bad_args_and_leaves_fd_open(void)
{
    int fd = udp_socket(NULL);
    mqvpn_bind_posix_opts_t o = opts_default();
    void *sentinel = &o;
    void *ctx = sentinel;
    CHECK(mqvpn_bind_posix_path_new(-1, &o, &ctx) == MQVPN_ERR_INVALID_ARG);
    CHECK(mqvpn_bind_posix_path_new(fd, NULL, &ctx) == MQVPN_ERR_INVALID_ARG);
    CHECK(mqvpn_bind_posix_path_new(fd, &o, NULL) == MQVPN_ERR_INVALID_ARG);
    /* a struct_size that stops short of udp_gso */
    o.struct_size = (uint32_t)offsetof(mqvpn_bind_posix_opts_t, udp_gso);
    CHECK(mqvpn_bind_posix_path_new(fd, &o, &ctx) == MQVPN_ERR_INVALID_ARG);
    CHECK(ctx == sentinel); /* never written on failure */
    CHECK(fd_is_open(fd));  /* never closed on failure */
    close(fd);
}

static void
test_socket_buffers_untouched_and_explicit(void)
{
    int fd = udp_socket(NULL);
    int before = 0;
    socklen_t ol = sizeof(before);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &before, &ol) == 0);

    mqvpn_bind_posix_opts_t o = opts_default(); /* -1: untouched */
    void *ctx = NULL;
    CHECK(mqvpn_bind_posix_path_new(fd, &o, &ctx) == MQVPN_OK);
    int after = 0;
    ol = sizeof(after);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &after, &ol) == 0);
    CHECK(after == before);
    mqvpn_bind_posix_path_free(ctx);

    /* An explicit request moves the buffer up from the default on both
     * kernels (Linux reports twice the clamped request, macOS reports it as
     * set). */
    o.socket_buf_bytes = before * 4;
    CHECK(mqvpn_bind_posix_path_new(fd, &o, &ctx) == MQVPN_OK);
    ol = sizeof(after);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &after, &ol) == 0);
    CHECK(after > before);
    mqvpn_bind_posix_path_free(ctx);
    close(fd);
}

static void
test_send_one_and_burst_reach_the_peer(void)
{
    struct sockaddr_in dst;
    int rx = udp_socket(&dst);
    int tx = udp_socket(NULL);
    mqvpn_bind_posix_opts_t o = opts_default();
    void *ctx = NULL;
    CHECK(mqvpn_bind_posix_path_new(tx, &o, &ctx) == MQVPN_OK);
    const mqvpn_path_ops_t *ops = mqvpn_bind_posix_path_ops();
    const struct sockaddr *to = (const struct sockaddr *)&dst;

    uint8_t a[100], b[200], c[300];
    memset(a, 'a', sizeof(a));
    memset(b, 'b', sizeof(b));
    memset(c, 'c', sizeof(c));
    mqvpn_datagram_t one[1] = {{a, sizeof(a)}};
    CHECK(ops->send(ctx, one, 1, to, sizeof(dst)) == 1);
    mqvpn_bind_posix_stats_t s1 = path_stats(ctx);
    CHECK(s1.tx.tx_sends == 1 && s1.tx.tx_datagrams == 1);

    mqvpn_datagram_t three[3] = {{a, sizeof(a)}, {b, sizeof(b)}, {c, sizeof(c)}};
    CHECK(ops->send(ctx, three, 3, to, sizeof(dst)) == 3);
    mqvpn_bind_posix_stats_t s2 = path_stats(ctx);
    CHECK(s2.tx.tx_datagrams == 4);
    /* Linux may batch the burst into one sendmmsg; elsewhere one sendto each. */
    CHECK(s2.tx.tx_sends >= 2 && s2.tx.tx_sends <= 4);

    const size_t want[4] = {100, 100, 200, 300};
    const uint8_t first[4] = {'a', 'a', 'b', 'c'};
    for (int i = 0; i < 4; i++) {
        uint8_t buf[512];
        wait_readable(rx);
        ssize_t n = recv(rx, buf, sizeof(buf), 0);
        CHECK(n == (ssize_t)want[i] && buf[0] == first[i]);
    }

    /* ops.get_stats reports the same TX numbers as the bind accessor */
    mqvpn_transport_stats_t via_ops;
    memset(&via_ops, 0, sizeof(via_ops));
    CHECK(ops->get_stats(ctx, &via_ops) == MQVPN_OK);
    CHECK(via_ops.tx_sends == s2.tx.tx_sends &&
          via_ops.tx_datagrams == s2.tx.tx_datagrams);
    ops->release(ctx);
    close(tx);
    close(rx);
}

static void
test_hard_send_error_is_failed_and_uncounted(void)
{
    int tx = udp_socket(NULL);
    mqvpn_bind_posix_opts_t o = opts_default();
    void *ctx = NULL;
    CHECK(mqvpn_bind_posix_path_new(tx, &o, &ctx) == MQVPN_OK);
    /* An IPv6 destination on an IPv4 socket is refused by every POSIX kernel
     * (EAFNOSUPPORT / EINVAL) — never EAGAIN. */
    struct sockaddr_in6 v6;
    memset(&v6, 0, sizeof(v6));
    v6.sin6_family = AF_INET6;
    v6.sin6_addr = in6addr_loopback;
    v6.sin6_port = htons(9);
    uint8_t d[10] = {0};
    mqvpn_datagram_t one[1] = {{d, sizeof(d)}};
    CHECK(mqvpn_bind_posix_path_ops()->send(ctx, one, 1, (const struct sockaddr *)&v6,
                                            sizeof(v6)) == MQVPN_TX_FAILED);
    mqvpn_bind_posix_stats_t s = path_stats(ctx);
    CHECK(s.tx.tx_sends == 0 && s.tx.tx_datagrams == 0);
    mqvpn_bind_posix_path_free(ctx);
    close(tx);
}

static void
test_drain_delivers_counts_and_honours_budget(void)
{
    struct sockaddr_in dst, src;
    int rx = udp_socket(&dst);
    int tx = udp_socket(&src);
    mqvpn_bind_posix_opts_t o = opts_default();
    void *ctx = NULL;
    CHECK(mqvpn_bind_posix_path_new(rx, &o, &ctx) == MQVPN_OK);
    mqvpn_client_t *client = (mqvpn_client_t *)(void *)&g_rx; /* opaque to the stub */

    for (int i = 0; i < 5; i++) {
        uint8_t d[64];
        memset(d, 'A' + i, sizeof(d));
        CHECK(sendto(tx, d, (size_t)(10 + i), 0, (struct sockaddr *)&dst, sizeof(dst)) ==
              10 + i);
    }
    settle();
    memset(&g_rx, 0, sizeof(g_rx));
    CHECK(mqvpn_bind_posix_path_drain(ctx, client, 7, 2) == 2); /* the budget stops it */
    CHECK(g_rx.n == 2);
    CHECK(mqvpn_bind_posix_path_drain(ctx, client, 7, 64) == 3);
    CHECK(g_rx.n == 5);
    for (int i = 0; i < 5; i++) {
        CHECK(g_rx.handle[i] == 7);
        CHECK(g_rx.len[i] == (size_t)(10 + i) && g_rx.first[i] == 'A' + i);
        CHECK(g_rx.peer_port[i] == ntohs(src.sin_port));
    }
    /* empty socket: nothing performed, nothing delivered */
    CHECK(mqvpn_bind_posix_path_drain(ctx, client, 7, 64) == 0);
    CHECK(mqvpn_bind_posix_path_recv_one(ctx, client, 7) == 0);
    mqvpn_bind_posix_stats_t st = path_stats(ctx);
    CHECK(st.rx_receives == 5 && st.rx_datagrams == 5); /* udp_gro = 0: one per receive */
    mqvpn_bind_posix_path_free(ctx);
    close(tx);
    close(rx);
}

static void
test_negative_handle_drains_without_delivering(void)
{
    struct sockaddr_in dst;
    int rx = udp_socket(&dst);
    int tx = udp_socket(NULL);
    mqvpn_bind_posix_opts_t o = opts_default();
    void *ctx = NULL;
    CHECK(mqvpn_bind_posix_path_new(rx, &o, &ctx) == MQVPN_OK);
    mqvpn_client_t *client = (mqvpn_client_t *)(void *)&g_rx;
    uint8_t d[20] = {0};
    for (int i = 0; i < 2; i++)
        CHECK(sendto(tx, d, sizeof(d), 0, (struct sockaddr *)&dst, sizeof(dst)) ==
              (ssize_t)sizeof(d));
    settle();
    memset(&g_rx, 0, sizeof(g_rx));
    CHECK(mqvpn_bind_posix_path_drain(ctx, client, -1, 64) == 2); /* consumed... */
    CHECK(g_rx.n == 0);                                           /* ...not delivered */
    mqvpn_bind_posix_stats_t st = path_stats(ctx);
    CHECK(st.rx_receives == 0 && st.rx_datagrams == 0); /* ...and not counted */
    CHECK(mqvpn_bind_posix_path_drain(NULL, client, 1, 64) == -1);
    CHECK(mqvpn_bind_posix_path_drain(ctx, NULL, 1, 64) == -1);
    mqvpn_bind_posix_path_free(ctx);
    close(tx);
    close(rx);
}

static void
test_free_and_release_leave_the_fd_open(void)
{
    struct sockaddr_in dst;
    int rx = udp_socket(&dst);
    int tx = udp_socket(NULL);
    mqvpn_bind_posix_opts_t o = opts_default();
    void *c1 = NULL, *c2 = NULL;
    CHECK(mqvpn_bind_posix_path_new(tx, &o, &c1) == MQVPN_OK);
    mqvpn_bind_posix_path_free(c1);
    CHECK(fd_is_open(tx));
    CHECK(mqvpn_bind_posix_path_new(tx, &o, &c2) == MQVPN_OK);
    mqvpn_bind_posix_path_ops()->release(c2);
    CHECK(fd_is_open(tx));
    /* still a working socket */
    uint8_t d[8] = {0};
    CHECK(sendto(tx, d, sizeof(d), 0, (struct sockaddr *)&dst, sizeof(dst)) ==
          (ssize_t)sizeof(d));
    close(tx);
    close(rx);
}

static void
test_server_ctx_send_scope_and_drain(void)
{
    struct sockaddr_in srv_addr, cli_addr;
    int srv = udp_socket(&srv_addr);
    int cli = udp_socket(&cli_addr);
    mqvpn_bind_posix_opts_t o = opts_default();
    void *sctx = NULL;
    CHECK(mqvpn_bind_posix_server_new(srv, &o, &sctx) == MQVPN_OK);
    const mqvpn_server_transport_ops_t *ops = mqvpn_bind_posix_server_ops();
    const struct sockaddr *to = (const struct sockaddr *)&cli_addr;
    uint8_t d[40];
    memset(d, 'S', sizeof(d));
    mqvpn_datagram_t one[1] = {{d, sizeof(d)}};
    CHECK(ops->send(sctx, 7, one, 1, to, sizeof(cli_addr)) == 1); /* a connection scope */
    CHECK(ops->send(sctx, 0, one, 1, to, sizeof(cli_addr)) == 1); /* scope 0: transient */
    ops->release_scope(sctx, 7);
    for (int i = 0; i < 2; i++) {
        uint8_t b[64];
        wait_readable(cli);
        CHECK(recv(cli, b, sizeof(b), 0) == (ssize_t)sizeof(d) && b[0] == 'S');
    }

    CHECK(sendto(cli, d, 17, 0, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) == 17);
    settle();
    memset(&g_rx, 0, sizeof(g_rx));
    mqvpn_server_t *server = (mqvpn_server_t *)(void *)&g_rx;
    CHECK(mqvpn_bind_posix_server_drain(sctx, server, 64) == 1);
    CHECK(g_rx.n == 1 && g_rx.handle[0] == SERVER_HANDLE && g_rx.len[0] == 17);
    CHECK(g_rx.peer_port[0] == ntohs(cli_addr.sin_port));

    mqvpn_bind_posix_stats_t st;
    memset(&st, 0, sizeof(st));
    st.struct_size = sizeof(st);
    mqvpn_bind_posix_server_get_stats(sctx, &st);
    CHECK(st.tx.tx_datagrams == 2 && st.rx_receives == 1 && st.rx_datagrams == 1);
    ops->release(sctx);
    CHECK(fd_is_open(srv));
    close(srv);
    close(cli);
}

int
main(void)
{
    test_ctor_rejects_bad_args_and_leaves_fd_open();
    test_socket_buffers_untouched_and_explicit();
    test_send_one_and_burst_reach_the_peer();
    test_hard_send_error_is_failed_and_uncounted();
    test_drain_delivers_counts_and_honours_budget();
    test_negative_handle_drains_without_delivering();
    test_free_and_release_leave_the_fd_open();
    test_server_ctx_send_scope_and_drain();
    printf("test_bind_posix_socket: all passed\n");
    return 0;
}
