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
        t->sends_accepted++;
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
        out->tx_sends = 12345; /* must be ignored by the core */
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
