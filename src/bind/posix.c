// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* src/bind/posix.c — bundled POSIX transport (see include/mqvpn_bind_posix.h).
 * The ONLY place in the library, together with posix_offload.c, that issues
 * socket syscalls, apart from the Linux-only hybrid server egress lane
 * src/hybrid/tcp_egress.c (by design; the sans-I/O gate's named exclusion). */

#define _GNU_SOURCE /* sendmmsg / struct mmsghdr via posix_offload.h (Linux) */
#include "mqvpn_bind_posix.h"
#include "bind/posix_offload.h"
#include "mqvpn_internal.h" /* mqvpn_tx_batch_enabled — the single batching rule */
#include "log.h"

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#ifdef MQVPN_OFFLOAD_TEST_SEAM
/* Allocation seam for the unit tests (NO_MEMORY constructor paths). */
void *mqvpn_seam_calloc(size_t n, size_t sz);
#  define BIND_CALLOC mqvpn_seam_calloc
#else
#  define BIND_CALLOC calloc
#endif

/* was mqvpn_client.c SOCKET_BUF_SIZE */
#define BIND_POSIX_DEFAULT_SOCKBUF (7 * 1024 * 1024)
/* was platform SOCK_BUF_SIZE */
#define BIND_POSIX_RX_BUF 65536
/* accepted-prefix cap; the core re-offers the rest */
#define BIND_POSIX_MAX_BATCH 32

/* ── shared ctx state ── */

typedef struct {
    int fd; /* borrowed */
    char tag[16];
    int gso_allowed; /* mqvpn_tx_batch_enabled(opts.udp_gso) on Linux, else 0 */
    int gro_enabled;
    int gro_errno;
    mqvpn_transport_stats_t tx;
    uint64_t rx_receives;
    uint64_t rx_datagrams;
    int send_err_logged; /* one-shot guard for the single-datagram errno log */
} bind_common_t;

typedef struct {
    bind_common_t c;
    int gso_disabled; /* sticky classifying errno; per path (one destination) */
} bind_path_ctx_t;

/* Open-addressed hash (linear probing, power-of-two capacity, backward-shift
 * deletion so no tombstones accumulate) of scopes that hit a GSO-class
 * failure. Only DISABLED scopes are stored, so scope 0 (transient) can never
 * leave an entry behind, the common case (every client fine) costs one
 * probe, and the hot path stays O(1) even when every client is
 * narrow-PMTU. Keys are never 0 (0 = empty slot). */
typedef struct {
    mqvpn_server_tx_scope_t scope;
    int gso_disabled;
} bind_scope_entry_t;

typedef struct {
    bind_common_t c;
    bind_scope_entry_t *tab;
    size_t cap; /* power of two; 0 until the first insert */
    size_t n;
    /* OOM fallback: sticky for EVERY scope (never retries a known-bad path) */
    int gso_disabled_all;
    int scope0_warned; /* scope 0 never goes sticky, so its WARN needs its own one-shot */
} bind_server_ctx_t;

#if defined(__linux__)
/* Process-wide UDP_SEGMENT capability. Probed once, by the first ctx whose
 * policy allows GSO, on the tick thread. */
static int g_gso_probed;
static int g_gso_available;
#endif

static const char *
bind_label(const bind_common_t *c, char *buf, size_t buflen)
{
    if (c->tag[0]) return c->tag;
    snprintf(buf, buflen, "fd=%d", c->fd);
    return buf;
}

static void
bind_apply_sockbuf(int fd, int bytes, const char *label)
{
    if (bytes < 0) return; /* -1: leave untouched */
    if (bytes == 0) bytes = BIND_POSIX_DEFAULT_SOCKBUF;
    int rc = 0;
    rc |= setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char *)&bytes, sizeof(bytes));
    rc |= setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&bytes, sizeof(bytes));
#ifdef SO_SNDBUFFORCE
    /* Privileged raise past net.core.*mem_max; failure is expected unprivileged. */
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, (const char *)&bytes, sizeof(bytes));
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, (const char *)&bytes, sizeof(bytes));
#endif
    if (rc != 0) LOG_WRN("bind-posix: socket buffers on %s: %s", label, strerror(errno));
    int snd = 0, rcv = 0;
    socklen_t optlen = sizeof(snd);
    if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &snd, &optlen) == 0 &&
        (optlen = sizeof(rcv), getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, &optlen) == 0))
        LOG_INF("bind-posix: socket buffers on %s: SO_SNDBUF=%d SO_RCVBUF=%d", label, snd,
                rcv);
}

/* GRO segment walk on Linux; a single-iteration walk elsewhere (seg == 0). */
static size_t
gro_seg_len_portable(size_t len, size_t seg, size_t off)
{
#if defined(__linux__)
    return mqvpn_gro_seg_len(len, seg, off);
#else
    (void)seg;
    return off >= len ? 0 : len - off;
#endif
}

static void
bind_common_init(bind_common_t *c, int fd, const mqvpn_bind_posix_opts_t *opts_in)
{
    /* Field-guarded prefix copy: a field is taken only when the caller's
     * struct_size covers it whole (udp_gso presence is validated earlier). */
    mqvpn_bind_posix_opts_t o;
    memset(&o, 0, sizeof(o));
#define OPT_HAS(f) \
    (opts_in->struct_size >= offsetof(mqvpn_bind_posix_opts_t, f) + sizeof(opts_in->f))
    o.udp_gso = opts_in->udp_gso;
    if (OPT_HAS(udp_gro)) o.udp_gro = opts_in->udp_gro;
    if (OPT_HAS(socket_buf_bytes)) o.socket_buf_bytes = opts_in->socket_buf_bytes;
    if (OPT_HAS(tag)) memcpy(o.tag, opts_in->tag, sizeof(o.tag));
#undef OPT_HAS

    c->fd = fd;
    memcpy(c->tag, o.tag, sizeof(c->tag));
    c->tag[sizeof(c->tag) - 1] = '\0';
    char lbl[32];
    const char *label = bind_label(c, lbl, sizeof(lbl));

    bind_apply_sockbuf(fd, o.socket_buf_bytes, label);
#if defined(__linux__)
    if (o.udp_gro) {
        if (mqvpn_udp_gro_enable(fd) == 0)
            c->gro_enabled = 1;
        else
            c->gro_errno = errno;
    }
    c->gso_allowed = mqvpn_tx_batch_enabled(o.udp_gso);
    if (c->gso_allowed && !g_gso_probed) {
        g_gso_probed = 1;
        g_gso_available = mqvpn_udp_gso_probe();
        /* Startup capability marker; only ever emitted when the policy
         * allows GSO, so its ABSENCE with UdpGso=false stays assertable. */
        LOG_INF("%s", g_gso_available ? MQVPN_UDP_GSO_MARKER_ENABLED
                                      : MQVPN_UDP_GSO_MARKER_UNAVAILABLE);
    }
#else
    (void)label;
#endif
}

static int
bind_opts_valid(int fd, const mqvpn_bind_posix_opts_t *opts, void **out_ctx)
{
    if (fd < 0 || !opts || !out_ctx) return 0;
    if (opts->struct_size < offsetof(mqvpn_bind_posix_opts_t, udp_gso) + sizeof(int))
        return 0;
    return 1;
}

/* ── TX ── */

/* Send up to BIND_POSIX_MAX_BATCH datagrams; contiguous-prefix contract.
 * gso_disabled is the caller's sticky slot (per path / per scope). warned
 * (nullable) gates the fallback WARN for callers whose slot is NOT sticky
 * (server scope 0): NULL = the sticky flag itself makes the log one-shot. */
static int
bind_send(bind_common_t *c, int *gso_disabled, int *warned, const mqvpn_datagram_t *bufs,
          unsigned n, const struct sockaddr *peer, socklen_t peer_len)
{
    if (n == 0) return MQVPN_TX_FAILED; /* precondition violated */
    if (n > BIND_POSIX_MAX_BATCH) n = BIND_POSIX_MAX_BATCH;
#if defined(__linux__)
    int use_gso = c->gso_allowed && g_gso_available;
    if (n == 1) {
        /* Single datagram: plain sendto(), the syscall the core issued for
         * this case before the refactor. A run of one never carries a
         * UDP_SEGMENT cmsg and never classifies as a GSO failure, so this is
         * behaviourally identical to send_batch for n == 1 on every arm and
         * keeps the syscall mix (and CPU/packet) exactly as before. */
        ssize_t r;
        do {
            r = sendto(c->fd, bufs[0].data, bufs[0].len, MSG_DONTWAIT, peer, peer_len);
        } while (r < 0 && errno == EINTR);
        if (r >= 0) {
            c->tx.tx_sends++;
            c->tx.tx_datagrams++;
            return 1;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) return MQVPN_TX_WOULD_BLOCK;
        /* Hard failure. The server logged this errno before the refactor
         * (its single-datagram helper owned a sendto()); the client did not,
         * because this arm carries every non-batched datagram and a dead
         * interface would emit one line per packet. One-shot per ctx gives
         * both sides the errno without the spam. */
        if (!c->send_err_logged) {
            int e = errno;
            c->send_err_logged = 1;
            char lbl1[32];
            LOG_ERR("bind-posix: send on %s: %s", bind_label(c, lbl1, sizeof(lbl1)),
                    strerror(e));
        }
        return MQVPN_TX_FAILED;
    }
    struct iovec iov[BIND_POSIX_MAX_BATCH];
    for (unsigned i = 0; i < n; i++) {
        iov[i].iov_base = (void *)bufs[i].data;
        iov[i].iov_len = bufs[i].len;
    }
    mqvpn_tx_counters_t tx = {0};
    int was_gso = use_gso && !*gso_disabled;
    ssize_t r =
        mqvpn_udp_send_batch(c->fd, iov, n, peer, peer_len, use_gso, gso_disabled, &tx);
    /* Captured before any LOG_* call: the log write path can clobber errno,
     * and the hard-error branch below is the only diagnostic that reports
     * it. Meaningful only when r == MQVPN_SEND_ERR. */
    int send_errno = errno;
    if (was_gso && *gso_disabled && !(warned && *warned)) {
        /* One-shot per sticky slot (or per ctx for scope 0). Keeps the
         * "udp-gso: " prefix; cannot fire when the policy disallows GSO
         * (use_gso == 0 never sets the flag), so the Arm-B absence contract
         * holds. */
        if (warned) *warned = 1;
        char lbl[32];
        LOG_WRN("udp-gso: runtime GSO failure (%s), sticky fallback to sendmmsg on %s",
                strerror(*gso_disabled), bind_label(c, lbl, sizeof(lbl)));
    }
    c->tx.tx_sends += tx.sends;
    c->tx.tx_datagrams += tx.datagrams;
    if (r > 0) return (int)r;
    if (r == MQVPN_SEND_EAGAIN) return MQVPN_TX_WOULD_BLOCK;
    /* The errno home for a hard batch failure: xquic's own |error send mmsg|
     * log carries none, and MQVPN_TX_FAILED can escalate to a connection
     * close. GSO-class errors are absorbed by the sticky fallback inside
     * mqvpn_udp_send_batch, so this branch is rare — no spam guard needed. */
    char errlbl[32];
    LOG_ERR("bind-posix: batch send on %s: %s", bind_label(c, errlbl, sizeof(errlbl)),
            strerror(send_errno));
    return MQVPN_TX_FAILED;
#else
    (void)gso_disabled;
    (void)warned;
    unsigned sent = 0;
    for (; sent < n; sent++) {
        ssize_t r;
        do {
            r = sendto(c->fd, bufs[sent].data, bufs[sent].len, MSG_DONTWAIT, peer,
                       peer_len);
        } while (r < 0 && errno == EINTR);
        if (r < 0) break;
        c->tx.tx_sends++;
        c->tx.tx_datagrams++;
    }
    if (sent > 0) return (int)sent;
    return (errno == EAGAIN || errno == EWOULDBLOCK) ? MQVPN_TX_WOULD_BLOCK
                                                     : MQVPN_TX_FAILED;
#endif
}

/* ── RX ── */

typedef void (*bind_deliver_fn)(void *arg, const uint8_t *pkt, size_t len,
                                const struct sockaddr *peer, socklen_t peer_len);

/* One receive; deliver == NULL drains without delivering. Returns 1/0/-1 per
 * the header contract and reports the delivered-datagram count for the
 * caller's budget accounting. Truncated aggregates are dropped (counted as
 * one unit of work, delivered 0) exactly as the platform loop did. */
static int
bind_recv_one(bind_common_t *c, bind_deliver_fn deliver, void *arg, unsigned *delivered)
{
    uint8_t buf[BIND_POSIX_RX_BUF];
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);
    size_t seg = 0;
    ssize_t n;
    *delivered = 0;
#if defined(__linux__)
    // codeql[cpp/uncontrolled-allocation-size] stack buffer bounded by sizeof(buf)
    n = mqvpn_udp_recv_segmented(c->fd, buf, sizeof(buf), (struct sockaddr *)&peer,
                                 &peer_len, &seg);
    if (n == MQVPN_RECV_DROP) {
        char dlbl[32];
        LOG_DBG("bind-posix: truncated datagram dropped on %s",
                bind_label(c, dlbl, sizeof(dlbl)));
        return 1;
    }
#else
    do {
        n = recvfrom(c->fd, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *)&peer,
                     &peer_len);
    } while (n < 0 && errno == EINTR);
#endif
    if (n < 0) return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
    if (n == 0) return 0;
    if (!deliver) return 1; /* consumed, not delivered: one unit of work, no counters */

    c->rx_receives++;
    size_t sl;
    for (size_t off = 0; (sl = gro_seg_len_portable((size_t)n, seg, off)) > 0;
         off += sl) {
        deliver(arg, buf + off, sl, (const struct sockaddr *)&peer, peer_len);
        c->rx_datagrams++;
        (*delivered)++;
    }
    return 1;
}

static int
bind_drain(bind_common_t *c, bind_deliver_fn deliver, void *arg, int budget)
{
    int receives = 0;
    while (budget > 0) {
        unsigned delivered = 0;
        int r = bind_recv_one(c, deliver, arg, &delivered);
        if (r < 0) return -1;
        if (r == 0) break;
        receives++;
        budget -= delivered > 0 ? (int)delivered : 1;
    }
    return receives;
}

/* ── client path ops ── */

typedef struct {
    mqvpn_client_t *client;
    mqvpn_path_handle_t handle;
} path_deliver_arg_t;

static void
path_deliver(void *arg, const uint8_t *pkt, size_t len, const struct sockaddr *peer,
             socklen_t peer_len)
{
    path_deliver_arg_t *a = (path_deliver_arg_t *)arg;
    mqvpn_client_on_socket_recv(a->client, a->handle, pkt, len, peer, peer_len);
}

static int
path_ops_send(void *vctx, const mqvpn_datagram_t *bufs, unsigned n,
              const struct sockaddr *peer, socklen_t peer_len)
{
    bind_path_ctx_t *ctx = (bind_path_ctx_t *)vctx;
    if (!ctx) return MQVPN_TX_FAILED;
    return bind_send(&ctx->c, &ctx->gso_disabled, NULL, bufs, n, peer, peer_len);
}

static int
path_ops_get_stats(void *vctx, mqvpn_transport_stats_t *out)
{
    bind_path_ctx_t *ctx = (bind_path_ctx_t *)vctx;
    if (!ctx) return MQVPN_ERR_INVALID_ARG;
    *out = ctx->c.tx;
    return MQVPN_OK;
}

static void
path_ops_release(void *vctx)
{
    free(vctx); /* never closes the borrowed fd */
}

int
mqvpn_bind_posix_path_new(int fd, const mqvpn_bind_posix_opts_t *opts, void **out_ctx)
{
    if (!bind_opts_valid(fd, opts, out_ctx)) return MQVPN_ERR_INVALID_ARG;
    bind_path_ctx_t *ctx = BIND_CALLOC(1, sizeof(*ctx));
    if (!ctx) return MQVPN_ERR_NO_MEMORY;
    bind_common_init(&ctx->c, fd, opts);
    *out_ctx = ctx;
    return MQVPN_OK;
}

const mqvpn_path_ops_t *
mqvpn_bind_posix_path_ops(void)
{
    static const mqvpn_path_ops_t ops = {
        .struct_size = sizeof(mqvpn_path_ops_t),
        .send = path_ops_send,
        .get_stats = path_ops_get_stats,
        .release = path_ops_release,
    };
    return &ops;
}

void
mqvpn_bind_posix_path_free(void *ctx)
{
    path_ops_release(ctx);
}

int
mqvpn_bind_posix_path_gro_enabled(const void *ctx)
{
    return ctx ? ((const bind_path_ctx_t *)ctx)->c.gro_enabled : 0;
}

int
mqvpn_bind_posix_path_gro_errno(const void *ctx)
{
    return ctx ? ((const bind_path_ctx_t *)ctx)->c.gro_errno : 0;
}

static void
bind_fill_stats(const bind_common_t *c, mqvpn_bind_posix_stats_t *out)
{
    /* NULL is a programming error with no sane recovery: assert.
     * struct_size is ABI input from a possibly older caller, so it is
     * validated, not asserted — below sizeof(uint32_t) the write-back at the
     * end would run past a buffer that small, so return without touching it. */
    assert(c != NULL && out != NULL && "bind-posix: get_stats called with NULL");
    if (!c || !out || out->struct_size < sizeof(uint32_t)) return;
    mqvpn_bind_posix_stats_t full = {
        .struct_size = sizeof(full),
        .tx = c->tx,
        .rx_receives = c->rx_receives,
        .rx_datagrams = c->rx_datagrams,
    };
    size_t copy = out->struct_size < sizeof(full) ? out->struct_size : sizeof(full);
    memcpy(out, &full, copy);
    out->struct_size = (uint32_t)copy;
}

void
mqvpn_bind_posix_path_get_stats(const void *ctx, mqvpn_bind_posix_stats_t *out)
{
    bind_fill_stats(ctx ? &((const bind_path_ctx_t *)ctx)->c : NULL, out);
}

int
mqvpn_bind_posix_path_recv_one(void *vctx, mqvpn_client_t *client,
                               mqvpn_path_handle_t handle)
{
    bind_path_ctx_t *ctx = (bind_path_ctx_t *)vctx;
    if (!ctx || !client) return -1;
    path_deliver_arg_t a = {client, handle};
    unsigned delivered;
    return bind_recv_one(&ctx->c, handle >= 0 ? path_deliver : NULL, &a, &delivered);
}

int
mqvpn_bind_posix_path_drain(void *vctx, mqvpn_client_t *client,
                            mqvpn_path_handle_t handle, int budget)
{
    bind_path_ctx_t *ctx = (bind_path_ctx_t *)vctx;
    if (!ctx || !client) return -1;
    path_deliver_arg_t a = {client, handle};
    return bind_drain(&ctx->c, handle >= 0 ? path_deliver : NULL, &a, budget);
}

/* ── server transport ops ── */

static size_t
scope_hash(uint64_t k, size_t cap)
{
    k ^= k >> 33; /* splitmix-style finaliser: scopes are sequential integers */
    k *= 0xff51afd7ed558ccdULL;
    k ^= k >> 33;
    return (size_t)k & (cap - 1);
}

static bind_scope_entry_t *
scope_find(bind_server_ctx_t *s, mqvpn_server_tx_scope_t scope)
{
    if (!s->cap) return NULL;
    for (size_t i = scope_hash(scope, s->cap);; i = (i + 1) & (s->cap - 1)) {
        if (s->tab[i].scope == 0) return NULL;
        if (s->tab[i].scope == scope) return &s->tab[i];
    }
}

static int
scope_grow(bind_server_ctx_t *s)
{
    size_t ncap = s->cap ? s->cap * 2 : 16;
    bind_scope_entry_t *nt = BIND_CALLOC(ncap, sizeof(*nt));
    if (!nt) return -1;
    for (size_t i = 0; i < s->cap; i++) {
        if (s->tab[i].scope == 0) continue;
        size_t j = scope_hash(s->tab[i].scope, ncap);
        while (nt[j].scope)
            j = (j + 1) & (ncap - 1);
        nt[j] = s->tab[i];
    }
    free(s->tab);
    s->tab = nt;
    s->cap = ncap;
    return 0;
}

static void
scope_insert(bind_server_ctx_t *s, mqvpn_server_tx_scope_t scope, int gso_disabled)
{
    if ((s->n + 1) * 2 > s->cap && scope_grow(s) < 0) {
        /* Out of memory: degrade conservatively — GSO off for every scope
         * from now on — rather than forgetting the failure and re-probing a
         * known-bad path on every send. */
        s->gso_disabled_all = gso_disabled;
        LOG_WRN("udp-gso: scope table allocation failed, GSO disabled for all peers");
        return;
    }
    /* 0 is the empty-slot marker, so it can never be a key: inserting it would
     * bump s->n while leaving the slot indistinguishable from free, inflating
     * the load factor and truncating later probe runs. Callers gate on
     * scope != 0; this pins that they keep doing so. */
    assert(scope != 0);
    size_t i = scope_hash(scope, s->cap);
    while (s->tab[i].scope)
        i = (i + 1) & (s->cap - 1);
    s->tab[i].scope = scope;
    s->tab[i].gso_disabled = gso_disabled;
    s->n++;
}

static void
scope_remove(bind_server_ctx_t *s, mqvpn_server_tx_scope_t scope)
{
    if (!s->cap) return;
    size_t i = scope_hash(scope, s->cap);
    while (s->tab[i].scope != scope) {
        if (s->tab[i].scope == 0) return;
        i = (i + 1) & (s->cap - 1);
    }
    /* Backward-shift deletion: pull later entries of the same probe run
     * back so lookups never cross an empty slot they must not. */
    size_t j = i;
    for (;;) {
        j = (j + 1) & (s->cap - 1);
        if (s->tab[j].scope == 0) break;
        size_t h = scope_hash(s->tab[j].scope, s->cap);
        int home_in_gap = (i <= j) ? (h > i && h <= j) : (h > i || h <= j);
        if (!home_in_gap) {
            s->tab[i] = s->tab[j];
            i = j;
        }
    }
    s->tab[i].scope = 0;
    s->tab[i].gso_disabled = 0;
    s->n--;
}

static int
server_ops_send(void *vctx, mqvpn_server_tx_scope_t scope, const mqvpn_datagram_t *bufs,
                unsigned n, const struct sockaddr *peer, socklen_t peer_len)
{
    bind_server_ctx_t *s = (bind_server_ctx_t *)vctx;
    if (!s) return MQVPN_TX_FAILED;
    bind_scope_entry_t *e = scope != 0 ? scope_find(s, scope) : NULL;
    int disabled = s->gso_disabled_all ? s->gso_disabled_all : (e ? e->gso_disabled : 0);
    int r = bind_send(&s->c, &disabled, scope == 0 ? &s->scope0_warned : NULL, bufs, n,
                      peer, peer_len);
    /* Persist a new sticky failure ONLY for a real scope; scope 0 gets the
     * per-call fallback and no entry (release_scope(0) is never called). */
    if (disabled && !e && scope != 0 && !s->gso_disabled_all)
        scope_insert(s, scope, disabled);
    return r;
}

static void
server_ops_release_scope(void *vctx, mqvpn_server_tx_scope_t scope)
{
    bind_server_ctx_t *s = (bind_server_ctx_t *)vctx;
    if (!s || scope == 0) return;
    scope_remove(s, scope);
}

static int
server_ops_get_stats(void *vctx, mqvpn_transport_stats_t *out)
{
    bind_server_ctx_t *s = (bind_server_ctx_t *)vctx;
    if (!s) return MQVPN_ERR_INVALID_ARG;
    *out = s->c.tx;
    return MQVPN_OK;
}

static void
server_ops_release(void *vctx)
{
    bind_server_ctx_t *s = (bind_server_ctx_t *)vctx;
    if (!s) return;
    free(s->tab);
    free(s);
}

int
mqvpn_bind_posix_server_new(int fd, const mqvpn_bind_posix_opts_t *opts, void **out_ctx)
{
    if (!bind_opts_valid(fd, opts, out_ctx)) return MQVPN_ERR_INVALID_ARG;
    bind_server_ctx_t *s = BIND_CALLOC(1, sizeof(*s));
    if (!s) return MQVPN_ERR_NO_MEMORY;
    bind_common_init(&s->c, fd, opts);
    *out_ctx = s;
    return MQVPN_OK;
}

const mqvpn_server_transport_ops_t *
mqvpn_bind_posix_server_ops(void)
{
    static const mqvpn_server_transport_ops_t ops = {
        .struct_size = sizeof(mqvpn_server_transport_ops_t),
        .send = server_ops_send,
        .release_scope = server_ops_release_scope,
        .get_stats = server_ops_get_stats,
        .release = server_ops_release,
    };
    return &ops;
}

void
mqvpn_bind_posix_server_free(void *ctx)
{
    server_ops_release(ctx);
}

int
mqvpn_bind_posix_server_gro_enabled(const void *ctx)
{
    return ctx ? ((const bind_server_ctx_t *)ctx)->c.gro_enabled : 0;
}

int
mqvpn_bind_posix_server_gro_errno(const void *ctx)
{
    return ctx ? ((const bind_server_ctx_t *)ctx)->c.gro_errno : 0;
}

void
mqvpn_bind_posix_server_get_stats(const void *ctx, mqvpn_bind_posix_stats_t *out)
{
    bind_fill_stats(ctx ? &((const bind_server_ctx_t *)ctx)->c : NULL, out);
}

static void
server_deliver(void *arg, const uint8_t *pkt, size_t len, const struct sockaddr *peer,
               socklen_t peer_len)
{
    mqvpn_server_on_socket_recv((mqvpn_server_t *)arg, pkt, len, peer, peer_len);
}

int
mqvpn_bind_posix_server_recv_one(void *vctx, mqvpn_server_t *server)
{
    bind_server_ctx_t *s = (bind_server_ctx_t *)vctx;
    if (!s || !server) return -1;
    unsigned delivered;
    return bind_recv_one(&s->c, server_deliver, server, &delivered);
}

int
mqvpn_bind_posix_server_drain(void *vctx, mqvpn_server_t *server, int budget)
{
    bind_server_ctx_t *s = (bind_server_ctx_t *)vctx;
    if (!s || !server) return -1;
    return bind_drain(&s->c, server_deliver, server, budget);
}
