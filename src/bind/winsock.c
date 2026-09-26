// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* src/bind/winsock.c — bundled Winsock transport (see
 * include/mqvpn_bind_winsock.h). With src/bind/posix*.c, the only place in
 * the library that issues socket calls, apart from the Linux-only hybrid
 * server egress lane src/hybrid/tcp_egress.c (by design; the sans-I/O gate's
 * named exclusion). */

#include "mqvpn_bind_winsock.h"
#include "log.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef MQVPN_WINSOCK_TEST_SEAM
/* Unit-test seam (tests/test_bind_winsock.c): the error mapping and the
 * NO_MEMORY constructor path need failures a healthy loopback socket never
 * produces. */
int mqvpn_seam_ws_sendto(SOCKET s, const char *buf, int len, int flags,
                         const struct sockaddr *to, int tolen);
void *mqvpn_seam_ws_calloc(size_t n, size_t sz);
#  define WS_SENDTO mqvpn_seam_ws_sendto
#  define WS_CALLOC mqvpn_seam_ws_calloc
#else
#  define WS_SENDTO sendto
#  define WS_CALLOC calloc
#endif

/* what the core applied to every Windows path before ABI 3 */
#define BIND_WINSOCK_DEFAULT_SOCKBUF (7 * 1024 * 1024)
/* largest UDP payload; the platform's pre-bind read loop used the same */
#define BIND_WINSOCK_RX_BUF 65536

typedef struct {
    SOCKET sock; /* borrowed */
    char tag[64];
    mqvpn_transport_stats_t tx;
} bind_winsock_ctx_t;

static const char *
ws_label(const bind_winsock_ctx_t *c, char *buf, size_t buflen)
{
    if (c->tag[0]) return c->tag;
    snprintf(buf, buflen, "socket=%llu", (unsigned long long)c->sock);
    return buf;
}

static void
ws_apply_sockbuf(SOCKET s, int bytes, const char *label)
{
    if (bytes < 0) return; /* -1: leave untouched */
    if (bytes == 0) bytes = BIND_WINSOCK_DEFAULT_SOCKBUF;
    const char *val = (const char *)&bytes;
    int err = 0;
    if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, val, (int)sizeof(bytes)) != 0)
        err = WSAGetLastError();
    if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, val, (int)sizeof(bytes)) != 0 && err == 0)
        err = WSAGetLastError();
    if (err != 0) LOG_WRN("bind-winsock: socket buffers on %s: WSA %d", label, err);
    int snd = 0, rcv = 0;
    int snd_len = (int)sizeof(snd), rcv_len = (int)sizeof(rcv);
    if (getsockopt(s, SOL_SOCKET, SO_SNDBUF, (char *)&snd, &snd_len) == 0 &&
        getsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&rcv, &rcv_len) == 0)
        LOG_INF("bind-winsock: socket buffers on %s: SO_SNDBUF=%d SO_RCVBUF=%d", label,
                snd, rcv);
}

/* ── ops ── */

static int
ws_ops_send(void *vctx, const mqvpn_datagram_t *bufs, unsigned n,
            const struct sockaddr *peer, socklen_t peer_len)
{
    bind_winsock_ctx_t *c = (bind_winsock_ctx_t *)vctx;
    if (!c || n == 0) return MQVPN_TX_FAILED; /* n == 0 violates the precondition */
    unsigned sent = 0;
    int err = 0;
    for (; sent < n; sent++) {
        int r;
        do {
            /* a datagram is at most one MTU, so the int length cannot truncate */
            r = WS_SENDTO(c->sock, (const char *)bufs[sent].data, (int)bufs[sent].len, 0,
                          peer, peer_len);
        } while (r == SOCKET_ERROR && (err = WSAGetLastError()) == WSAEINTR);
        if (r == SOCKET_ERROR) break;
        c->tx.tx_sends++;
        c->tx.tx_datagrams++;
    }
    if (sent > 0) return (int)sent;
    /* Nothing accepted. No log line: the core logged none for this before
     * ABI 3, and a dead interface would otherwise print one per packet. */
    return err == WSAEWOULDBLOCK ? MQVPN_TX_WOULD_BLOCK : MQVPN_TX_FAILED;
}

static int
ws_ops_get_stats(void *vctx, mqvpn_transport_stats_t *out)
{
    bind_winsock_ctx_t *c = (bind_winsock_ctx_t *)vctx;
    if (!c || !out) return MQVPN_ERR_INVALID_ARG;
    *out = c->tx;
    return MQVPN_OK;
}

static void
ws_ops_release(void *vctx)
{
    free(vctx); /* never closes the borrowed socket */
}

/* The caller's struct_size covers field f whole (prefix-copy rule). */
#define WS_OPT_HAS(opts, f) \
    ((opts)->struct_size >= offsetof(mqvpn_bind_winsock_opts_t, f) + sizeof((opts)->f))

int
mqvpn_bind_winsock_path_new(SOCKET sock, const mqvpn_bind_winsock_opts_t *opts,
                            void **out_ctx)
{
    if (sock == INVALID_SOCKET || !opts || !out_ctx) return MQVPN_ERR_INVALID_ARG;
    if (!WS_OPT_HAS(opts, socket_buf_bytes)) return MQVPN_ERR_INVALID_ARG;
    bind_winsock_ctx_t *c = WS_CALLOC(1, sizeof(*c));
    if (!c) return MQVPN_ERR_NO_MEMORY;
    c->sock = sock;
    /* Prefix copy: a field is read only when the caller's struct_size covers
     * it whole, and opts is never retained. An uncovered tag stays "". */
    if (WS_OPT_HAS(opts, tag)) {
        memcpy(c->tag, opts->tag, sizeof(c->tag));
        c->tag[sizeof(c->tag) - 1] = '\0';
    }
    char lbl[32];
    ws_apply_sockbuf(sock, opts->socket_buf_bytes, ws_label(c, lbl, sizeof(lbl)));
    *out_ctx = c;
    return MQVPN_OK;
}

const mqvpn_path_ops_t *
mqvpn_bind_winsock_path_ops(void)
{
    static const mqvpn_path_ops_t ops = {
        .struct_size = sizeof(mqvpn_path_ops_t),
        .send = ws_ops_send,
        .get_stats = ws_ops_get_stats,
        .release = ws_ops_release,
    };
    return &ops;
}

void
mqvpn_bind_winsock_path_free(void *ctx)
{
    ws_ops_release(ctx);
}

/* ── RX ── */

int
mqvpn_bind_winsock_path_drain(void *vctx, mqvpn_client_t *client,
                              mqvpn_path_handle_t handle, int budget)
{
    bind_winsock_ctx_t *c = (bind_winsock_ctx_t *)vctx;
    if (!c || !client) return -1;
    char buf[BIND_WINSOCK_RX_BUF];
    int receives = 0;
    while (receives < budget) {
        struct sockaddr_storage peer;
        int peer_len = (int)sizeof(peer);
        int r = recvfrom(c->sock, buf, (int)sizeof(buf), 0, (struct sockaddr *)&peer,
                         &peer_len);
        if (r == SOCKET_ERROR) {
            int e = WSAGetLastError();
            if (e == WSAEINTR) continue;
            if (e == WSAEWOULDBLOCK) break;
            /* Anything else ends the drain — WSAECONNRESET (an ICMP
             * port-unreachable reported against an earlier send) included,
             * exactly as the platform's pre-bind loop stopped on n <= 0. The
             * level-triggered event re-fires for whatever is still queued. */
            return -1;
        }
        if (r == 0) break; /* zero-length datagram: stop, as the old loop did */
        receives++;
        if (handle >= 0)
            mqvpn_client_on_socket_recv(client, handle, (const uint8_t *)buf, (size_t)r,
                                        (const struct sockaddr *)&peer, peer_len);
    }
    return receives;
}
