// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* tests/fake_transport.h — scriptable in-memory transports implementing
 * mqvpn_path_ops_t (client) and mqvpn_server_transport_ops_t (server).
 * Every send copies the accepted prefix, so tests can also catch a core that
 * keeps pointers past the call. */
#ifndef MQVPN_FAKE_TRANSPORT_H
#define MQVPN_FAKE_TRANSPORT_H

#include "libmqvpn.h"
#include "mqvpn_bind_posix.h" /* the recorder forwards to the bundled bind;
                               * fake_transport.c therefore depends on the bind, which
                               * mqvpn_lib contains */
#include <stddef.h>
#include <stdint.h>

typedef enum {
    FAKE_ACCEPT_ALL = 0, /* return n */
    FAKE_WOULD_BLOCK,    /* return MQVPN_TX_WOULD_BLOCK */
    FAKE_FAILED,         /* return MQVPN_TX_FAILED */
    FAKE_ZERO,           /* return 0 (contract violation) */
    FAKE_PARTIAL,        /* return min(n, partial_k) */
    FAKE_BOGUS_NEGATIVE, /* return -99 (unknown negative) */
} fake_mode_t;

#define FAKE_MAX_CAPTURED 64
#define FAKE_MAX_DGRAM    2048

typedef struct {
    fake_mode_t mode;
    int partial_k; /* FAKE_PARTIAL prefix length; must be >= 0 (compared unsigned) */
    int stats_rc;  /* return value of get_stats; MQVPN_OK by default */

    /* observation */
    unsigned send_calls;     /* every ops.send invocation */
    unsigned sends_accepted; /* invocations that returned k >= 1 (what get_stats
                              * reports) */
    unsigned datagrams_offered;
    unsigned datagrams_accepted;
    unsigned send_after_release; /* sends observed after release(): must stay 0 */
    unsigned release_calls;
    unsigned get_stats_calls;
    uint64_t last_scope; /* server flavour only */
    unsigned n_captured;
    size_t captured_len[FAKE_MAX_CAPTURED];
    uint8_t captured[FAKE_MAX_CAPTURED][FAKE_MAX_DGRAM];
    /* server flavour: scopes seen released */
    unsigned release_scope_calls;
    uint64_t released_scopes[FAKE_MAX_CAPTURED];
} fake_transport_t;

void fake_transport_init(fake_transport_t *t);
const mqvpn_path_ops_t *fake_path_ops(void);
/* stateless send only: ignores ctx, counts g_fake_stateless_sends */
const mqvpn_path_ops_t *fake_path_ops_minimal(void);
extern unsigned g_fake_stateless_sends;
const mqvpn_server_transport_ops_t *fake_server_ops(void);

/* Scope-recording wrapper around the POSIX bind: observes the server core's
 * use of tx scopes on a real handshake (unique per accept, released exactly
 * once, scope 0 only before accept, all released before the shared release).
 * The struct is PUBLIC (tests read its counters directly). */
typedef struct scope_rec_s {
    void *inner;
    uint64_t seen[64];
    int n_seen;
    uint64_t released[64];
    int n_released;
    int scope0_sends; /* required: deterministic stateless-reset probe */
    int inner_released;
    int released_after_inner; /* release_scope called after release: violation */
    int sends_after_release;  /* any send after release(): violation */
} scope_rec_t;
void scope_rec_init(scope_rec_t *r, void *inner_bind_ctx); /* zero + set inner */
const mqvpn_server_transport_ops_t *scope_rec_ops(void);

#endif /* MQVPN_FAKE_TRANSPORT_H */
