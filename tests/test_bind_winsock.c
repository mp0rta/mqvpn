// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* tests/test_bind_winsock.c — mqvpn_bind_winsock: the constructor contract,
 * the send error mapping (through a sendto/calloc seam — a healthy loopback
 * socket does not fail here) and the send/drain round trip over real loopback
 * sockets. Windows CI only. Links the bind alone: the delivery target below
 * is a stub, so no core, xquic or TLS is involved. Own CHECK, not assert():
 * the Windows job builds Release. */

#include "mqvpn_bind_winsock.h"

#include <windows.h> /* Sleep; after winsock2.h, which libmqvpn.h includes */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c)                                                                  \
    do {                                                                          \
        if (!(c)) {                                                               \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #c); \
            exit(1);                                                              \
        }                                                                         \
    } while (0)

/* ── seam (declared in src/bind/winsock.c under MQVPN_WINSOCK_TEST_SEAM) ── */

static int g_fail_calloc; /* 1 = the next calloc fails */
static int g_script[8];   /* per sendto call: WSA error to fail with, 0 = real call */
static int g_script_len;
static int g_sendto_calls;

void *
mqvpn_seam_ws_calloc(size_t n, size_t sz)
{
    if (g_fail_calloc) {
        g_fail_calloc = 0;
        return NULL;
    }
    return calloc(n, sz);
}

int
mqvpn_seam_ws_sendto(SOCKET s, const char *buf, int len, int flags,
                     const struct sockaddr *to, int tolen)
{
    int i = g_sendto_calls++;
    if (i < g_script_len && g_script[i] != 0) {
        WSASetLastError(g_script[i]);
        return SOCKET_ERROR;
    }
    return sendto(s, buf, len, flags, to, tolen);
}

static void
script(int n, const int *errs)
{
    memset(g_script, 0, sizeof(g_script));
    for (int i = 0; i < n; i++)
        g_script[i] = errs[i];
    g_script_len = n;
    g_sendto_calls = 0;
}

/* ── delivery stub (the bind's only call into the core) ── */

#define MAX_RX 16
static struct {
    int n;
    mqvpn_path_handle_t handle[MAX_RX];
    int len[MAX_RX];
    unsigned char first[MAX_RX];
    unsigned short peer_port[MAX_RX];
} g_rx;

int
mqvpn_client_on_socket_recv(mqvpn_client_t *client, mqvpn_path_handle_t path,
                            const uint8_t *pkt, size_t len, const struct sockaddr *peer,
                            socklen_t peer_len)
{
    (void)client;
    (void)peer_len;
    CHECK(g_rx.n < MAX_RX);
    g_rx.handle[g_rx.n] = path;
    g_rx.len[g_rx.n] = (int)len;
    g_rx.first[g_rx.n] = len ? pkt[0] : 0;
    g_rx.peer_port[g_rx.n] =
        peer->sa_family == AF_INET
            ? ntohs(((const struct sockaddr_in *)(const void *)peer)->sin_port)
            : 0;
    g_rx.n++;
    return MQVPN_OK;
}

/* ── helpers ── */

/* Non-blocking UDP socket on 127.0.0.1:<ephemeral>, like path_mgr's. */
static SOCKET
udp_socket(struct sockaddr_in *addr)
{
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    CHECK(s != INVALID_SOCKET);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(s, (struct sockaddr *)&a, (int)sizeof(a)) == 0);
    int len = (int)sizeof(a);
    CHECK(getsockname(s, (struct sockaddr *)&a, &len) == 0);
    u_long nb = 1;
    CHECK(ioctlsocket(s, FIONBIO, &nb) == 0);
    if (addr) *addr = a;
    return s;
}

static int
socket_usable(SOCKET s)
{
    int type = 0, len = (int)sizeof(type);
    return getsockopt(s, SOL_SOCKET, SO_TYPE, (char *)&type, &len) == 0 &&
           type == SOCK_DGRAM;
}

static void
wait_readable(SOCKET s)
{
    fd_set rf;
    FD_ZERO(&rf);
    FD_SET(s, &rf);
    struct timeval tv = {2, 0};
    CHECK(select(0, &rf, NULL, NULL, &tv) == 1);
}

static mqvpn_bind_winsock_opts_t
opts_default(void)
{
    mqvpn_bind_winsock_opts_t o;
    memset(&o, 0, sizeof(o));
    o.struct_size = sizeof(o);
    o.socket_buf_bytes = -1; /* leave the test sockets alone unless a test says so */
    snprintf(o.tag, sizeof(o.tag), "test");
    return o;
}

static mqvpn_transport_stats_t
tx_stats(void *ctx)
{
    mqvpn_transport_stats_t st;
    memset(&st, 0, sizeof(st));
    CHECK(mqvpn_bind_winsock_path_ops()->get_stats(ctx, &st) == MQVPN_OK);
    return st;
}

/* ── tests ── */

static void
test_ctor_contract(void)
{
    SOCKET s = udp_socket(NULL);
    mqvpn_bind_winsock_opts_t o = opts_default();
    void *sentinel = &o;
    void *ctx = sentinel;
    CHECK(mqvpn_bind_winsock_path_new(INVALID_SOCKET, &o, &ctx) == MQVPN_ERR_INVALID_ARG);
    CHECK(mqvpn_bind_winsock_path_new(s, NULL, &ctx) == MQVPN_ERR_INVALID_ARG);
    CHECK(mqvpn_bind_winsock_path_new(s, &o, NULL) == MQVPN_ERR_INVALID_ARG);
    o.struct_size = (uint32_t)offsetof(mqvpn_bind_winsock_opts_t, socket_buf_bytes);
    CHECK(mqvpn_bind_winsock_path_new(s, &o, &ctx) == MQVPN_ERR_INVALID_ARG);
    o = opts_default();
    g_fail_calloc = 1;
    CHECK(mqvpn_bind_winsock_path_new(s, &o, &ctx) == MQVPN_ERR_NO_MEMORY);
    CHECK(ctx == sentinel);  /* never written on failure */
    CHECK(socket_usable(s)); /* never closed on failure */

    /* A newer caller's larger struct is accepted by prefix copy, and the opts
     * storage is not retained past the call. */
    struct {
        mqvpn_bind_winsock_opts_t o;
        unsigned char newer_fields[32];
    } big;
    memset(&big, 0, sizeof(big));
    big.o = opts_default();
    big.o.struct_size = (uint32_t)sizeof(big);
    CHECK(mqvpn_bind_winsock_path_new(s, &big.o, &ctx) == MQVPN_OK);
    memset(&big, 0xA5, sizeof(big));
    CHECK(ctx != sentinel);
    mqvpn_bind_winsock_path_free(ctx);
    CHECK(socket_usable(s)); /* the destructor does not close it either */
    closesocket(s);
}

static void
test_socket_buffers(void)
{
    SOCKET s = udp_socket(NULL);
    int before = 0, len = (int)sizeof(before);
    CHECK(getsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&before, &len) == 0);

    mqvpn_bind_winsock_opts_t o = opts_default(); /* -1: untouched */
    void *ctx = NULL;
    CHECK(mqvpn_bind_winsock_path_new(s, &o, &ctx) == MQVPN_OK);
    int after = 0;
    len = (int)sizeof(after);
    CHECK(getsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&after, &len) == 0);
    CHECK(after == before);
    mqvpn_bind_winsock_path_free(ctx);

    o.socket_buf_bytes = 262144;
    CHECK(mqvpn_bind_winsock_path_new(s, &o, &ctx) == MQVPN_OK);
    int snd = 0, rcv = 0;
    len = (int)sizeof(snd);
    CHECK(getsockopt(s, SOL_SOCKET, SO_SNDBUF, (char *)&snd, &len) == 0);
    len = (int)sizeof(rcv);
    CHECK(getsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&rcv, &len) == 0);
    CHECK(snd >= 262144 && rcv >= 262144);
    mqvpn_bind_winsock_path_free(ctx);
    closesocket(s);
}

static void
test_send_error_mapping(void)
{
    struct sockaddr_in dst;
    SOCKET rx = udp_socket(&dst);
    SOCKET s = udp_socket(NULL);
    mqvpn_bind_winsock_opts_t o = opts_default();
    void *ctx = NULL;
    CHECK(mqvpn_bind_winsock_path_new(s, &o, &ctx) == MQVPN_OK);
    const mqvpn_path_ops_t *ops = mqvpn_bind_winsock_path_ops();
    unsigned char d[3][50];
    memset(d, 'x', sizeof(d));
    mqvpn_datagram_t three[3] = {{d[0], 50}, {d[1], 50}, {d[2], 50}};
    const struct sockaddr *to = (const struct sockaddr *)&dst;
    const int tolen = (int)sizeof(dst);

    const int wouldblock[] = {WSAEWOULDBLOCK};
    script(1, wouldblock);
    CHECK(ops->send(ctx, three, 1, to, tolen) == MQVPN_TX_WOULD_BLOCK);
    const int unreach[] = {WSAENETUNREACH};
    script(1, unreach);
    CHECK(ops->send(ctx, three, 1, to, tolen) == MQVPN_TX_FAILED);
    const int nobufs[] = {WSAENOBUFS};
    script(1, nobufs);
    CHECK(ops->send(ctx, three, 1, to, tolen) == MQVPN_TX_FAILED);
    mqvpn_transport_stats_t st = tx_stats(ctx);
    /* nothing accepted, nothing counted */
    CHECK(st.tx_sends == 0 && st.tx_datagrams == 0);

    const int intr_then_ok[] = {WSAEINTR, 0};
    script(2, intr_then_ok);
    CHECK(ops->send(ctx, three, 1, to, tolen) == 1); /* retried, then sent */
    CHECK(g_sendto_calls == 2);

    const int second_blocks[] = {0, WSAEWOULDBLOCK};
    script(2, second_blocks);
    CHECK(ops->send(ctx, three, 3, to, tolen) == 1); /* contiguous prefix */
    const int third_fails[] = {0, 0, WSAENETUNREACH};
    script(3, third_fails);
    CHECK(ops->send(ctx, three, 3, to, tolen) == 2);
    st = tx_stats(ctx);
    CHECK(st.tx_sends == 4 && st.tx_datagrams == 4);

    script(0, NULL);
    CHECK(ops->send(ctx, three, 0, to, tolen) == MQVPN_TX_FAILED); /* n == 0 */
    CHECK(ops->send(NULL, three, 1, to, tolen) == MQVPN_TX_FAILED);
    mqvpn_transport_stats_t unused;
    CHECK(ops->get_stats(NULL, &unused) != MQVPN_OK);
    ops->release(ctx);
    closesocket(s);
    closesocket(rx);
}

static void
test_real_round_trip_and_drain(void)
{
    struct sockaddr_in dst, src;
    SOCKET rx = udp_socket(&dst);
    SOCKET tx = udp_socket(&src);
    mqvpn_bind_winsock_opts_t o = opts_default();
    void *tctx = NULL, *rctx = NULL;
    CHECK(mqvpn_bind_winsock_path_new(tx, &o, &tctx) == MQVPN_OK);
    CHECK(mqvpn_bind_winsock_path_new(rx, &o, &rctx) == MQVPN_OK);
    const mqvpn_path_ops_t *ops = mqvpn_bind_winsock_path_ops();
    mqvpn_client_t *client = (mqvpn_client_t *)(void *)&g_rx; /* opaque to the stub */
    script(0, NULL);

    unsigned char d[5][40];
    mqvpn_datagram_t five[5];
    for (int i = 0; i < 5; i++) {
        memset(d[i], 'A' + i, sizeof(d[i]));
        five[i].data = d[i];
        five[i].len = (size_t)(10 + i);
    }
    CHECK(ops->send(tctx, five, 5, (const struct sockaddr *)&dst, (int)sizeof(dst)) == 5);
    mqvpn_transport_stats_t st = tx_stats(tctx);
    CHECK(st.tx_sends == 5 && st.tx_datagrams == 5); /* one sendto per datagram */
    Sleep(200);                                      /* let loopback deliver all five */

    memset(&g_rx, 0, sizeof(g_rx));
    wait_readable(rx);
    /* the budget stops the first drain after two of the five */
    CHECK(mqvpn_bind_winsock_path_drain(rctx, client, 7, 2) == 2);
    CHECK(g_rx.n == 2);
    CHECK(mqvpn_bind_winsock_path_drain(rctx, client, 7, 64) == 3);
    CHECK(g_rx.n == 5);
    for (int i = 0; i < 5; i++) {
        CHECK(g_rx.handle[i] == 7);
        CHECK(g_rx.len[i] == 10 + i && g_rx.first[i] == 'A' + i);
        CHECK(g_rx.peer_port[i] == ntohs(src.sin_port));
    }
    /* empty socket: would block, nothing performed */
    CHECK(mqvpn_bind_winsock_path_drain(rctx, client, 7, 64) == 0);

    /* handle < 0 drains without delivering */
    CHECK(ops->send(tctx, five, 2, (const struct sockaddr *)&dst, (int)sizeof(dst)) == 2);
    Sleep(200);
    memset(&g_rx, 0, sizeof(g_rx));
    CHECK(mqvpn_bind_winsock_path_drain(rctx, client, -1, 64) == 2);
    CHECK(g_rx.n == 0);
    CHECK(mqvpn_bind_winsock_path_drain(NULL, client, 7, 64) == -1);
    CHECK(mqvpn_bind_winsock_path_drain(rctx, NULL, 7, 64) == -1);

    ops->release(tctx);
    mqvpn_bind_winsock_path_free(rctx);
    CHECK(socket_usable(tx) && socket_usable(rx)); /* the bind never closes */
    closesocket(tx);
    closesocket(rx);
}

int
main(void)
{
    WSADATA wsa;
    CHECK(WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
    test_ctor_contract();
    test_socket_buffers();
    test_send_error_mapping();
    test_real_round_trip_and_drain();
    WSACleanup();
    printf("test_bind_winsock: all passed\n");
    return 0;
}
