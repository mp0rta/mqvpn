// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#include "fake_transport.h"
#include <string.h>

void
fake_transport_init(fake_transport_t *t)
{
    memset(t, 0, sizeof(*t));
    t->mode = FAKE_ACCEPT_ALL;
    t->stats_rc = MQVPN_OK;
}

static void
capture(fake_transport_t *t, const mqvpn_datagram_t *bufs, unsigned k)
{
    for (unsigned i = 0; i < k; i++) {
        if (t->n_captured < FAKE_MAX_CAPTURED) {
            size_t len = bufs[i].len < FAKE_MAX_DGRAM ? bufs[i].len : FAKE_MAX_DGRAM;
            memcpy(t->captured[t->n_captured], bufs[i].data, len);
            t->captured_len[t->n_captured] = len;
            t->n_captured++;
        }
        t->datagrams_accepted++;
    }
}

static int
fake_send_common(fake_transport_t *t, const mqvpn_datagram_t *bufs, unsigned n)
{
    t->send_calls++;
    if (t->release_calls) t->send_after_release++;
    t->datagrams_offered += n;
    switch (t->mode) {
    case FAKE_ACCEPT_ALL:
        capture(t, bufs, n);
        if (n > 0) t->sends_accepted++;
        return (int)n;
    case FAKE_WOULD_BLOCK: return MQVPN_TX_WOULD_BLOCK;
    case FAKE_FAILED: return MQVPN_TX_FAILED;
    case FAKE_ZERO: return 0;
    case FAKE_BOGUS_NEGATIVE: return -99;
    case FAKE_PARTIAL: {
        unsigned k = (unsigned)t->partial_k < n ? (unsigned)t->partial_k : n;
        capture(t, bufs, k);
        if (k > 0) t->sends_accepted++;
        return (int)k;
    }
    }
    return MQVPN_TX_FAILED;
}

static int
fake_path_send(void *ctx, const mqvpn_datagram_t *bufs, unsigned n,
               const struct sockaddr *peer, socklen_t peer_len)
{
    (void)peer;
    (void)peer_len;
    return fake_send_common((fake_transport_t *)ctx, bufs, n);
}

static int
fake_get_stats(void *ctx, mqvpn_transport_stats_t *out)
{
    fake_transport_t *t = (fake_transport_t *)ctx;
    t->get_stats_calls++;
    if (t->stats_rc != MQVPN_OK) {
        /* Poison BOTH fields: a core that consumes a failed snapshot must be
         * caught whichever one it reads. */
        out->tx_sends = 12345;
        out->tx_datagrams = 12345;
        return t->stats_rc;
    }
    out->tx_sends = t->sends_accepted; /* sends that accepted >= 1 datagram */
    out->tx_datagrams = t->datagrams_accepted;
    return MQVPN_OK;
}

static void
fake_release(void *ctx)
{
    ((fake_transport_t *)ctx)->release_calls++;
}

const mqvpn_path_ops_t *
fake_path_ops(void)
{
    static const mqvpn_path_ops_t ops = {
        .struct_size = sizeof(mqvpn_path_ops_t),
        .send = fake_path_send,
        .get_stats = fake_get_stats,
        .release = fake_release,
    };
    return &ops;
}

/* Truly stateless transport: ignores ctx entirely (so ctx == NULL is a real
 * exercise, not a NULL deref waiting to happen) and counts into a global. */
unsigned g_fake_stateless_sends;

static int
fake_stateless_send(void *ctx, const mqvpn_datagram_t *bufs, unsigned n,
                    const struct sockaddr *peer, socklen_t peer_len)
{
    (void)ctx;
    (void)bufs;
    (void)peer;
    (void)peer_len;
    g_fake_stateless_sends++;
    return (int)n;
}

const mqvpn_path_ops_t *
fake_path_ops_minimal(void)
{
    static const mqvpn_path_ops_t ops = {
        .struct_size = sizeof(mqvpn_path_ops_t),
        .send = fake_stateless_send,
    };
    return &ops;
}

static int
fake_server_send(void *ctx, mqvpn_server_tx_scope_t scope, const mqvpn_datagram_t *bufs,
                 unsigned n, const struct sockaddr *peer, socklen_t peer_len)
{
    (void)peer;
    (void)peer_len;
    fake_transport_t *t = (fake_transport_t *)ctx;
    t->last_scope = scope;
    return fake_send_common(t, bufs, n);
}

static void
fake_release_scope(void *ctx, mqvpn_server_tx_scope_t scope)
{
    fake_transport_t *t = (fake_transport_t *)ctx;
    if (t->release_scope_calls < FAKE_MAX_CAPTURED)
        t->released_scopes[t->release_scope_calls] = scope;
    t->release_scope_calls++;
}

const mqvpn_server_transport_ops_t *
fake_server_ops(void)
{
    static const mqvpn_server_transport_ops_t ops = {
        .struct_size = sizeof(mqvpn_server_transport_ops_t),
        .send = fake_server_send,
        .release_scope = fake_release_scope,
        .get_stats = fake_get_stats,
        .release = fake_release,
    };
    return &ops;
}

/* ── Scope recorder (declared in fake_transport.h) ──
 *
 * A mqvpn_server_transport_ops_t that forwards every call to the bundled
 * POSIX bind and records how the core used tx scopes on the way through. The
 * ctx installed in the core is the recorder; the bind ctx it wraps is
 * `inner`, so the test still drains RX through the bind directly. */

#ifndef _WIN32

void
scope_rec_init(scope_rec_t *r, void *inner_bind_ctx)
{
    memset(r, 0, sizeof(*r));
    r->inner = inner_bind_ctx;
}

static int
rec_send(void *ctx, mqvpn_server_tx_scope_t scope, const mqvpn_datagram_t *bufs,
         unsigned n, const struct sockaddr *peer, socklen_t peer_len)
{
    scope_rec_t *r = (scope_rec_t *)ctx;
    if (r->inner_released) r->sends_after_release++;
    if (scope == 0) {
        r->scope0_sends++;
    } else {
        /* De-duplicated, so seen[] is distinct by construction and a caller's
         * pairwise-difference check cannot fail. What actually pins uniqueness
         * across accepts is n_seen: a core that reused one scope for every
         * accept would leave n_seen at 1. */
        int known = 0;
        for (int i = 0; i < r->n_seen; i++)
            if (r->seen[i] == scope) known = 1;
        if (!known && r->n_seen < 64) r->seen[r->n_seen++] = scope;
    }
    /* Do NOT forward once the shared release has run: the inner ctx is freed,
     * so forwarding would surface the violation as a use-after-free inside the
     * bind instead of as the flag the test asserts on. */
    if (r->inner_released) return MQVPN_TX_FAILED;
    return mqvpn_bind_posix_server_ops()->send(r->inner, scope, bufs, n, peer, peer_len);
}

static void
rec_release_scope(void *ctx, mqvpn_server_tx_scope_t scope)
{
    scope_rec_t *r = (scope_rec_t *)ctx;
    if (r->inner_released) r->released_after_inner = 1;
    if (r->n_released < 64) r->released[r->n_released] = scope;
    r->n_released++;
    if (r->inner_released) return; /* freed inner ctx — see rec_send */
    mqvpn_bind_posix_server_ops()->release_scope(r->inner, scope);
}

static int
rec_get_stats(void *ctx, mqvpn_transport_stats_t *out)
{
    return mqvpn_bind_posix_server_ops()->get_stats(((scope_rec_t *)ctx)->inner, out);
}

static void
rec_release(void *ctx)
{
    scope_rec_t *r = (scope_rec_t *)ctx;
    r->inner_released = 1;
    mqvpn_bind_posix_server_ops()->release(r->inner);
}

static const mqvpn_server_transport_ops_t rec_ops = {
    .struct_size = sizeof(mqvpn_server_transport_ops_t),
    .send = rec_send,
    .release_scope = rec_release_scope,
    .get_stats = rec_get_stats,
    .release = rec_release,
};

const mqvpn_server_transport_ops_t *
scope_rec_ops(void)
{
    return &rec_ops;
}

#endif /* !_WIN32 */
