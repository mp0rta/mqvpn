// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * tcp_lane.c — client-side TCP-lane flow table (H2b).
 *
 * This is the flow-table skeleton only: sticky-lane lookup, SYN-time
 * commit + cap enforcement, and idle-sweep/stats plumbing. lwIP pcb
 * wiring (Task 7), the H3 request/stream bridge (Task 8), and the
 * accept/relay/close data-plane logic (Tasks 8-12) land incrementally on
 * top of the mqvpn_tcp_flow_t fields reserved for them below.
 */

#include "hybrid/tcp_lane.h"

#include <stdlib.h>

/* Opaque outside lwip_glue.c/tcp_lane.c — this file does not include any
 * lwIP header, so the pcb pointer stays a forward declaration (same
 * convention as src/hybrid/lwip_glue.h). */
struct tcp_pcb;

typedef enum {
    TCP_FLOW_STICKY_RAW,     /* SYN-time verdict was RAW; remembered so
                              * later packets on this 5-tuple skip
                              * re-classification (§ sticky-lane). */
    TCP_FLOW_PENDING_ACCEPT, /* to_tcp verdict recorded; lwIP has not yet
                              * accepted the SYN (Task 7). */
    TCP_FLOW_PENDING_STREAM, /* lwIP accepted; H3 CONNECT-TCP stream not
                              * yet open (Task 8). */
    TCP_FLOW_ACTIVE,         /* pcb + h3 stream both live, relaying. */
    TCP_FLOW_CLOSING,        /* half- or full-close in progress. */
} mqvpn_tcp_flow_state_t;

typedef struct mqvpn_tcp_flow {
    mqvpn_flow_key_t key;
    mqvpn_tcp_flow_state_t state;
    uint64_t last_activity_us;

    struct tcp_pcb *pcb; /* set by Task 8's lwIP accept callback */
    void *h3_request;    /* opaque xqc_h3_request_t*; set by Task 8 */
    void *stream;        /* opaque cli_stream_t*; set by Task 8 */

    size_t uplink_inflight_bytes;
    int uplink_withheld;
    int downlink_paused;
    int fin_sent_to_h3;
    int fin_received_from_h3;
    int tcp_fin_seen;

    struct mqvpn_tcp_flow *next; /* hash chain */
} mqvpn_tcp_flow_t;

struct mqvpn_tcp_lane {
    mqvpn_hybrid_config_t cfg;
    uint64_t hash_seed;
    void *client_ctx;
    mqvpn_tcp_flow_t **buckets;
    uint32_t n_buckets;
    uint32_t n_flows;
    mqvpn_tcp_lane_stats_t stats;
};

/* Power-of-two bucket count from tcp_max_flows (load factor ~1), capped at
 * 2^20 buckets. Identical to reorder_tx.c's pick_buckets — kept as a
 * separate copy deliberately: TX/RX/TCP-lane have DIFFERENT eviction
 * policies (idle-only / LRU / cap+idle+abort respectively), so the
 * surrounding structs diverge even though this helper doesn't. */
static uint32_t
pick_buckets(uint32_t max_flows)
{
    uint32_t n = 16;
    while (n < max_flows && n < (1u << 20)) {
        n <<= 1;
    }
    return n;
}

mqvpn_tcp_lane_t *
mqvpn_tcp_lane_new(const mqvpn_hybrid_config_t *cfg, uint64_t hash_seed, void *client_ctx)
{
    if (!cfg) {
        return NULL;
    }
    mqvpn_tcp_lane_t *lane = calloc(1, sizeof(*lane));
    if (!lane) {
        return NULL;
    }
    lane->cfg = *cfg;
    lane->hash_seed = hash_seed;
    lane->client_ctx = client_ctx;
    lane->n_buckets = pick_buckets(cfg->tcp_max_flows ? cfg->tcp_max_flows : 16);
    lane->buckets = calloc(lane->n_buckets, sizeof(*lane->buckets));
    if (!lane->buckets) {
        free(lane);
        return NULL;
    }
    return lane;
}

void
mqvpn_tcp_lane_free(mqvpn_tcp_lane_t *lane)
{
    if (!lane) {
        return;
    }
    for (uint32_t i = 0; i < lane->n_buckets; i++) {
        mqvpn_tcp_flow_t *f = lane->buckets[i];
        while (f) {
            mqvpn_tcp_flow_t *next = f->next;
            free(f);
            f = next;
        }
    }
    free(lane->buckets);
    free(lane);
}

static mqvpn_tcp_flow_t *
find_flow(mqvpn_tcp_lane_t *lane, const mqvpn_flow_key_t *key, uint32_t *bucket_out)
{
    uint32_t b =
        (uint32_t)(mqvpn_flow_key_hash(key, lane->hash_seed) & (lane->n_buckets - 1));
    if (bucket_out) {
        *bucket_out = b;
    }
    for (mqvpn_tcp_flow_t *f = lane->buckets[b]; f; f = f->next) {
        if (mqvpn_flow_key_eq(&f->key, key)) {
            return f;
        }
    }
    return NULL;
}

int
mqvpn_tcp_lane_lookup(mqvpn_tcp_lane_t *lane, const mqvpn_flow_key_t *key, int *out_raw)
{
    if (!lane || !key) {
        return 0;
    }
    mqvpn_tcp_flow_t *f = find_flow(lane, key, NULL);
    if (!f) {
        return 0;
    }
    if (out_raw) {
        *out_raw = (f->state == TCP_FLOW_STICKY_RAW) ? 1 : 0;
    }
    return 1;
}

int
mqvpn_tcp_lane_on_syn(mqvpn_tcp_lane_t *lane, const mqvpn_flow_key_t *key, int to_tcp)
{
    if (!lane || !key) {
        return -1;
    }
    if (lane->n_flows >= lane->cfg.tcp_max_flows) {
        lane->stats.flows_rejected_cap++;
        return -1;
    }
    uint32_t bucket =
        (uint32_t)(mqvpn_flow_key_hash(key, lane->hash_seed) & (lane->n_buckets - 1));
    mqvpn_tcp_flow_t *f = calloc(1, sizeof(*f));
    if (!f) {
        lane->stats.flows_rejected_other++;
        return -1;
    }
    f->key = *key;
    f->state = to_tcp ? TCP_FLOW_PENDING_ACCEPT : TCP_FLOW_STICKY_RAW;

    f->next = lane->buckets[bucket];
    lane->buckets[bucket] = f;
    lane->n_flows++;
    lane->stats.flows_total++;
    if (to_tcp) {
        lane->stats.flows_active++;
    }
    return 0;
}

void
mqvpn_tcp_lane_tick(mqvpn_tcp_lane_t *lane, uint64_t now_us)
{
    (void)lane;
    (void)now_us;
    /* Task 13 fills this in (idle eviction sweep). */
}

void
mqvpn_tcp_lane_get_stats(const mqvpn_tcp_lane_t *lane, mqvpn_tcp_lane_stats_t *out)
{
    if (!lane || !out) {
        return;
    }
    *out = lane->stats;
}
