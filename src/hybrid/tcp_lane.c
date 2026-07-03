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
#include <string.h>

/* Task 8: the accept callback below wires real pcbs (tcp_arg/tcp_recv/...),
 * so this TU now needs full lwIP types. tcp_lane.h's PUBLIC surface stays
 * lwIP-opaque (err_t + forward-declared struct tcp_pcb only) — the "opaque
 * pcb" rule was always about the header, not this .c. */
#include "lwip/ip_addr.h"
#include "lwip/tcp.h"

/* The accept callback memcpy's pcb local_ip/remote_ip as the flow key's raw
 * 4 network-order bytes — only valid while ip_addr_t IS the bare ip4_addr_t
 * (one u32_t). Pin the LWIP_IPV6=0 assumption (lwip_port/lwipopts.h). */
_Static_assert(sizeof(ip_addr_t) == 4,
               "TCP lane assumes LWIP_IPV6=0: ip_addr_t must be the bare "
               "network-order ip4_addr_t");

/* Sticky-RAW markers are capped separately from tcp_max_flows: they are
 * never idle-evicted (Task 13 sweeps TCP-lane flows only), so counting
 * them against tcp_max_flows would let a tcp=auto client on a single path
 * permanently exhaust the TCP lane with markers — exactly the scenario
 * tcp=auto exists for. This cap only bounds memory: a marker entry is one
 * mqvpn_tcp_flow_t (~120 B, key 38 B) so 4096 markers ≈ 0.5 MB worst
 * case; the keys alone are 38 B × 4096 ≈ 156 KB. On cap hit the flow just
 * stays unsticky and re-evaluates per SYN (harmless per Task 7).
 * #ifndef so tests can override it small to exercise the cap branch. */
#ifndef TCP_LANE_RAW_MARKER_CAP
#  define TCP_LANE_RAW_MARKER_CAP 4096u
#endif

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

    struct tcp_pcb *pcb;  /* set by the lwIP accept callback */
    ip4_addr_t target_ip; /* original inner dst (== pcb->local_ip at accept —
                           * wildcard intercept), network byte order */
    uint16_t target_port; /* host order, same as the flow key's ports */
    void *h3_request;     /* opaque xqc_h3_request_t*; set by bind_h3_request */
    void *stream;         /* opaque cli_stream_t*; set by bind_h3_request */

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
    mqvpn_lwip_clock_fn clock_fn; /* nullable; last_activity_us stays 0 then */
    void *clock_ctx;
    mqvpn_tcp_flow_t **buckets;
    uint32_t n_buckets;
    uint32_t n_tcp_flows;   /* to_tcp=1 entries; capped by cfg.tcp_max_flows */
    uint32_t n_raw_markers; /* sticky-RAW entries; capped by
                             * TCP_LANE_RAW_MARKER_CAP */
    mqvpn_tcp_lane_stats_t stats;
};

/* Power-of-two bucket count from the table's total capacity (load factor
 * ~1), capped at 2^20 buckets. Identical to reorder_tx.c's pick_buckets —
 * kept as a
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
mqvpn_tcp_lane_new(const mqvpn_hybrid_config_t *cfg, uint64_t hash_seed, void *client_ctx,
                   mqvpn_lwip_clock_fn clock_fn, void *clock_ctx)
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
    lane->clock_fn = clock_fn;
    lane->clock_ctx = clock_ctx;
    /* Size for BOTH populations sharing the table: up to tcp_max_flows
     * TCP-lane flows plus up to TCP_LANE_RAW_MARKER_CAP sticky-RAW markers
     * (which are exactly what accumulates in the tcp=auto single-path hot
     * case). Defaults: 256 + 4096 → 8192 buckets = 64 KB of pointers. */
    lane->n_buckets = pick_buckets(cfg->tcp_max_flows + TCP_LANE_RAW_MARKER_CAP);
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
    if (to_tcp) {
        /* Reject-before-side-effect: this runs BEFORE lwIP sees the SYN. */
        if (lane->n_tcp_flows >= lane->cfg.tcp_max_flows) {
            lane->stats.flows_rejected_cap++;
            return -1;
        }
    } else {
        /* Marker-cap hit is NOT a TCP-lane rejection (no flows_rejected_cap):
         * the flow simply stays unsticky and re-evaluates on each SYN. */
        if (lane->n_raw_markers >= TCP_LANE_RAW_MARKER_CAP) {
            return -1;
        }
    }
    uint32_t bucket;
    if (find_flow(lane, key, &bucket)) {
        /* Duplicate commit is a caller bug: the protocol is lookup-then-
         * commit, so on_syn must only ever see brand-new keys. Refuse
         * rather than insert a shadowing duplicate. */
        lane->stats.flows_rejected_other++;
        return -1;
    }
    mqvpn_tcp_flow_t *f = calloc(1, sizeof(*f));
    if (!f) {
        lane->stats.flows_rejected_other++;
        return -1;
    }
    f->key = *key;
    f->state = to_tcp ? TCP_FLOW_PENDING_ACCEPT : TCP_FLOW_STICKY_RAW;

    f->next = lane->buckets[bucket];
    lane->buckets[bucket] = f;
    lane->stats.flows_total++;
    if (to_tcp) {
        lane->n_tcp_flows++;
    } else {
        lane->n_raw_markers++;
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
    /* Gauges are DERIVED from the live counters, not tracked in parallel:
     * removal sites (Tasks 12/13) only maintain n_tcp_flows/n_raw_markers
     * and can never leave the stats snapshot out of sync. */
    out->flows_active = lane->n_tcp_flows;
    out->raw_markers_active = lane->n_raw_markers;
}

/* ─── lwIP accept → H3 stream open (Task 8; relay/teardown stubbed) ─── */

/* Relay/teardown stubs — Tasks 10/12 replace these; the accept path below
 * only needs their addresses. recv: pbuf_free without tcp_recved means zero
 * receive-window growth — inert but safe for the no-relay checkpoint
 * (p == NULL is FIN, also ignored for now). */
static err_t
mqvpn_tcp_lane_on_lwip_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    (void)arg;
    (void)pcb;
    (void)err;
    if (p) {
        pbuf_free(p);
    }
    return ERR_OK;
}

static err_t
mqvpn_tcp_lane_on_lwip_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    (void)arg;
    (void)pcb;
    (void)len;
    return ERR_OK;
}

static void
mqvpn_tcp_lane_on_lwip_err(void *arg, err_t err)
{
    (void)arg;
    (void)err;
}

/* Task 12 stub: will unlink + free the flow and maintain n_tcp_flows. */
static void
tcp_lane_remove_flow(mqvpn_tcp_lane_t *lane, mqvpn_tcp_flow_t *f)
{
    (void)lane;
    (void)f;
}

void
mqvpn_tcp_lane_bind_h3_request(void *flow_handle, void *h3_request, void *stream)
{
    mqvpn_tcp_flow_t *f = (mqvpn_tcp_flow_t *)flow_handle;
    f->h3_request = h3_request;
    f->stream = stream;
    f->state = TCP_FLOW_ACTIVE; /* Task 9 inserts real 2xx/4xx gating */
}

void
mqvpn_tcp_lane_abort_pending(void *flow_handle)
{
    (void)flow_handle; /* Task 12: tcp_abort(f->pcb) + remove_flow */
}

err_t
mqvpn_tcp_lane_lwip_accept(void *arg, struct tcp_pcb *newpcb, err_t err)
{
    mqvpn_tcp_lane_t *lane = (mqvpn_tcp_lane_t *)arg;

    /* pcb-pool exhaustion: tcp_listen_input invokes the accept callback with
     * (NULL, ERR_MEM) and ignores the return value (tcp_in.c). Nothing to
     * track or abort — the peer's SYN retransmit retries, and the flow entry
     * stays PENDING_ACCEPT so the retransmit is re-fed into lwIP. */
    if (!newpcb || err != ERR_OK) {
        return ERR_MEM;
    }

    /* Rebuild the SYN-time flow key from the accepted pcb — the fork's
     * wildcard bind means local_ip/local_port ARE the true original
     * destination. Byte-order contract (must be byte-identical to the key
     * mqvpn_hybrid_classify built from the raw SYN, or find_flow below
     * misses every time; pinned by test_tcp_lane's correspondence test):
     *   - pcb ports are HOST order (tcp_input ntohs's the header before
     *     tcp_listen_input copies src/dest — tcp_in.c), matching the key's
     *     documented host-order ports (reorder.h);
     *   - LWIP_IPV6=0 makes ip_addr_t the bare ip4_addr_t: one u32_t in
     *     NETWORK order, i.e. the same 4 raw header bytes the classifier
     *     memcpy'd (pinned by the _Static_assert at the top). */
    mqvpn_flow_key_t key;
    memset(&key, 0, sizeof(key));
    key.ip_version = 4;
    key.proto = MQVPN_IPPROTO_TCP;
    key.src_port = newpcb->remote_port;
    key.dst_port = newpcb->local_port;
    memcpy(key.src_ip, &newpcb->remote_ip, sizeof(newpcb->remote_ip));
    memcpy(key.dst_ip, &newpcb->local_ip, sizeof(newpcb->local_ip));

    mqvpn_tcp_flow_t *f = find_flow(lane, &key, NULL);
    if (!f || f->state != TCP_FLOW_PENDING_ACCEPT) {
        /* Shouldn't happen — every lwIP-fed SYN was committed by on_syn
         * first. Refuse rather than leak an untracked pcb. Post-SYN-ACK, so
         * NEVER a RAW fallback. Return convention (vendored tcp_in.c,
         * tcp_process SYN_RCVD): any non-ERR_OK return other than ERR_ABRT
         * makes the stack tcp_abort() the pcb itself (RST + free); ERR_ABRT
         * would instead claim WE already called tcp_abort — we didn't. */
        return ERR_VAL;
    }

    if (lane->n_tcp_flows > lane->cfg.tcp_max_flows) {
        /* Defense only — the cap is enforced pre-lwIP in on_syn; strict >
         * because this flow itself is already counted in n_tcp_flows. Same
         * abort-not-RAW return convention as above. */
        lane->stats.flows_rejected_cap++;
        tcp_lane_remove_flow(lane, f);
        return ERR_MEM;
    }

    f->pcb = newpcb;
    f->target_ip = *ip_2_ip4(&newpcb->local_ip);
    f->target_port = newpcb->local_port;
    f->state = TCP_FLOW_PENDING_STREAM;
    f->last_activity_us = lane->clock_fn ? lane->clock_fn(lane->clock_ctx) : 0;

    tcp_arg(newpcb, f);
    tcp_recv(newpcb, mqvpn_tcp_lane_on_lwip_recv);
    tcp_sent(newpcb, mqvpn_tcp_lane_on_lwip_sent);
    tcp_err(newpcb, mqvpn_tcp_lane_on_lwip_err);

    /* Direct .c-to-.c call — see the prototype's comment in tcp_lane.h. */
    cli_tcp_lane_open_stream(lane->client_ctx, f, &key);
    return ERR_OK;
}
