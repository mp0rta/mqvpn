// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * reorder_tx.c — sender-side send_flow table + peek-commit stamping
 * (design spec v2.5 §10, §14.2(a'), §15.1).
 */

#include "reorder_tx.h"

#include <stdlib.h>
#include <string.h>

/* §10.1 send_flow. Kept ~40B (key 38 + state) so the table can be sized large
 * enough that forced eviction of an active flow never happens (§14.2(a')). */
typedef struct mqvpn_send_flow {
    mqvpn_flow_key_t key;         /* 5-tuple */
    uint64_t next_seq;            /* 0-start, 48-bit, never wraps (§7) */
    uint64_t last_activity_us;    /* for idle-based eviction (§14.2(a')) */
    uint32_t reset_marks_left;    /* K on creation; FLOW_RESET budget (§10.5) */
    uint8_t eligible;             /* cached at creation (port/proto only, §10.1) */
    struct mqvpn_send_flow *next; /* hash chain */
} mqvpn_send_flow_t;

struct mqvpn_reorder_tx {
    mqvpn_reorder_config_t cfg;
    uint64_t hash_seed;
    mqvpn_send_flow_t **buckets;
    uint32_t n_buckets;
    uint32_t n_flows;
    mqvpn_reorder_tx_stats_t stats;
};

/* Power-of-two bucket count chosen from max_flows (load factor ~1).
 * Capped at 2^20 buckets: beyond that we intentionally accept load factor >1
 * (chains lengthen) rather than growing — max_flows bounds the table anyway,
 * so the cap is deliberate, not an oversight. No runtime resize. */
static uint32_t
pick_buckets(uint32_t max_flows)
{
    uint32_t n = 16;
    while (n < max_flows && n < (1u << 20)) {
        n <<= 1;
    }
    return n;
}

mqvpn_reorder_tx_t *
mqvpn_reorder_tx_new(const mqvpn_reorder_config_t *cfg, uint64_t hash_seed)
{
    if (!cfg) {
        return NULL;
    }
    mqvpn_reorder_tx_t *tx = calloc(1, sizeof(*tx));
    if (!tx) {
        return NULL;
    }
    tx->cfg = *cfg;
    tx->hash_seed = hash_seed;
    tx->n_buckets = pick_buckets(cfg->max_flows ? cfg->max_flows : 16);
    tx->buckets = calloc(tx->n_buckets, sizeof(*tx->buckets));
    if (!tx->buckets) {
        free(tx);
        return NULL;
    }
    return tx;
}

void
mqvpn_reorder_tx_free(mqvpn_reorder_tx_t *tx)
{
    if (!tx) {
        return;
    }
    for (uint32_t i = 0; i < tx->n_buckets; i++) {
        mqvpn_send_flow_t *f = tx->buckets[i];
        while (f) {
            mqvpn_send_flow_t *next = f->next;
            free(f);
            f = next;
        }
    }
    free(tx->buckets);
    free(tx);
}

/* §15.1: eligibility is port/proto rule only, evaluated bidirectionally (src OR
 * dst port match), cached at flow creation. A flow is eligible iff the first
 * matching rule's profile carries a reorder preset (shared matcher + preset
 * helper keep TX/RX in lockstep). */
static uint8_t
compute_eligible(const mqvpn_reorder_config_t *cfg, const mqvpn_flow_key_t *key)
{
    const mqvpn_reorder_rule_t *r = mqvpn_reorder_match_rule(cfg, key);
    uint32_t w, c;
    return (r && mqvpn_reorder_profile_preset(r->profile, &w, &c)) ? 1u : 0u;
}

static mqvpn_send_flow_t *
table_lookup(mqvpn_reorder_tx_t *tx, const mqvpn_flow_key_t *key, uint32_t *bucket_out)
{
    uint32_t b =
        (uint32_t)(mqvpn_flow_key_hash(key, tx->hash_seed) & (tx->n_buckets - 1));
    if (bucket_out) {
        *bucket_out = b;
    }
    for (mqvpn_send_flow_t *f = tx->buckets[b]; f; f = f->next) {
        if (mqvpn_flow_key_eq(&f->key, key)) {
            return f;
        }
    }
    return NULL;
}

/*
 * §14.2(a'): when the table is full, evict ONLY a send_flow that is idle
 * (now_us - last_activity_us > egress_idle_timeout). Returns 1 if it freed a
 * slot, 0 if no idle victim exists (caller must then send RAW). We never force-
 * evict an active flow; forced_evict_count counts the should-never-happen case
 * and stays 0 here.
 */
static int
evict_one_idle(mqvpn_reorder_tx_t *tx, uint64_t now_us)
{
    uint64_t idle_us = (uint64_t)tx->cfg.egress_idle_timeout_sec * 1000000ULL;
    mqvpn_send_flow_t *oldest = NULL;
    mqvpn_send_flow_t **oldest_link = NULL;
    for (uint32_t b = 0; b < tx->n_buckets; b++) {
        mqvpn_send_flow_t **link = &tx->buckets[b];
        for (mqvpn_send_flow_t *f = *link; f; link = &f->next, f = f->next) {
            /* §14.2(c) wrap-safe: a backwards-clock blip (now_us <
             * last_activity_us) must NOT underflow and spuriously evict a live
             * flow. Mirrors the RX-side guard. */
            if (now_us > f->last_activity_us && now_us - f->last_activity_us > idle_us) {
                if (!oldest || f->last_activity_us < oldest->last_activity_us) {
                    oldest = f;
                    oldest_link = link;
                }
            }
        }
    }
    if (!oldest) {
        return 0; /* no idle victim */
    }
    *oldest_link = oldest->next;
    free(oldest);
    tx->n_flows--;
    tx->stats.idle_evict_count++;
    return 1;
}

/* Get or create a send_flow for key. Returns NULL if the table is full and no
 * idle flow can be evicted (§14.2(a') → caller sends RAW). */
static mqvpn_send_flow_t *
get_or_create(mqvpn_reorder_tx_t *tx, const mqvpn_flow_key_t *key, uint64_t now_us)
{
    uint32_t bucket;
    mqvpn_send_flow_t *f = table_lookup(tx, key, &bucket);
    if (f) {
        return f;
    }
    if (tx->cfg.max_flows && tx->n_flows >= tx->cfg.max_flows) {
        if (!evict_one_idle(tx, now_us)) {
            tx->stats.table_full_raw++;
            return NULL; /* full, all active → caller sends RAW */
        }
        /* bucket index unchanged (same n_buckets); re-fetch head below. */
    }
    f = calloc(1, sizeof(*f));
    if (!f) {
        return NULL;
    }
    f->key = *key;
    f->next_seq = 0;
    f->reset_marks_left = tx->cfg.reset_mark_packets;
    f->eligible = compute_eligible(&tx->cfg, key);
    f->last_activity_us = now_us;
    f->next = tx->buckets[bucket];
    tx->buckets[bucket] = f;
    tx->n_flows++;
    tx->stats.flows_created++;
    return f;
}

mqvpn_reorder_tx_action_t
mqvpn_reorder_tx_peek(mqvpn_reorder_tx_t *tx, const uint8_t *pkt, size_t len,
                      uint64_t now_us, uint32_t max_inner_without_reorder,
                      mqvpn_reorder_tx_peek_t *out)
{
    memset(out, 0, sizeof(*out));
    out->flow = NULL;

    /* §10.2: master gate off → RAW. */
    if (tx->cfg.mode == MQVPN_REORDER_OFF) {
        out->action = MQVPN_REORDER_TX_RAW;
        return out->action;
    }

    /* parse fail / fragment / non-UDP (§4.1) → RAW. */
    mqvpn_flow_key_t key;
    if (mqvpn_reorder_parse_5tuple(pkt, len, &key) != 0) {
        out->action = MQVPN_REORDER_TX_RAW;
        return out->action;
    }

    mqvpn_send_flow_t *flow = get_or_create(tx, &key, now_us);
    if (!flow || !flow->eligible) {
        /* not eligible, or table full + no idle victim → RAW (§15.1/§14.2(a')). */
        out->action = MQVPN_REORDER_TX_RAW;
        return out->action;
    }

    /* §9 MTU guard: header-inclusive size must fit the DATAGRAM payload.
     * Compare 8+len against max_inner_without_reorder (NO double -8). */
    if ((uint64_t)MQVPN_REORDER_HDR_LEN + len > (uint64_t)max_inner_without_reorder) {
        out->action = MQVPN_REORDER_TX_DROP_MTU;
        out->flow = flow;
        return out->action;
    }

    /* Build header. FLOW_RESET on the first K packets (§10.5). peek only — do
     * NOT advance next_seq / reset_marks_left (§10.3); commit does. */
    uint8_t flags = 0;
    if (flow->reset_marks_left > 0) {
        flags |= MQVPN_REORDER_FLAG_RESET;
    }
    mqvpn_reorder_wire_encode(out->hdr, MQVPN_REORDER_TYPE_V1, flags, flow->next_seq);
    out->action = MQVPN_REORDER_TX_STAMP;
    out->flow = flow;
    return out->action;
}

void
mqvpn_reorder_tx_commit(mqvpn_reorder_tx_t *tx, mqvpn_reorder_tx_peek_t *peek,
                        uint64_t now_us)
{
    (void)tx;
    if (!peek || peek->action != MQVPN_REORDER_TX_STAMP || !peek->flow) {
        return;
    }
    mqvpn_send_flow_t *flow = (mqvpn_send_flow_t *)peek->flow;
    /* §10.3 peek-commit: advance only on successful send. */
    flow->next_seq++;
    if (flow->reset_marks_left > 0) {
        flow->reset_marks_left--;
    }
    flow->last_activity_us = now_us;
}

const mqvpn_reorder_tx_stats_t *
mqvpn_reorder_tx_stats(const mqvpn_reorder_tx_t *tx)
{
    return &tx->stats;
}

uint32_t
mqvpn_reorder_tx_flow_reset_marks_left(const void *flow)
{
    return ((const mqvpn_send_flow_t *)flow)->reset_marks_left;
}
