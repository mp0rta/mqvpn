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

/* One queued uplink delivery. p is a whole recv-callback pbuf (possibly a
 * CHAIN — pbuf->next is the intra-packet chain pointer and must NOT be
 * reused for queueing, hence this separate node). offset counts the leading
 * bytes xquic already accepted (partial-accept resume point): re-delivering
 * from 0 after a partial send would DUPLICATE bytes on the stream. */
typedef struct mqvpn_tcp_uplink_node {
    struct pbuf *p;  /* owned; freed when fully sent (or on queue teardown) */
    uint16_t offset; /* bytes of p already handed to H3; < p->tot_len */
    struct mqvpn_tcp_uplink_node *next;
} mqvpn_tcp_uplink_node_t;

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

    /* Uplink queue — ONE mechanism serving both pre-2xx buffering
     * (PENDING_STREAM: nothing may be sent before the gate opens) and
     * EAGAIN/partial-accept retry (ACTIVE: xquic backpressure). FIFO; flushed
     * by the writable notify and by the 2xx transition. uplink_queued_bytes
     * counts UNSENT bytes only (sum of tot_len - offset), which is the
     * watermark metric: what xquic has not yet taken from us.
     * (Task 6 reserved a uplink_inflight_bytes field here; it was never
     * decremented anywhere in the plan and its "accepted by xquic" meaning
     * has no completion signal to drive it, so it is replaced by
     * uplink_queued_bytes — see tcp_lane.h's watermark comment.) */
    mqvpn_tcp_uplink_node_t *uplink_q_head;
    mqvpn_tcp_uplink_node_t *uplink_q_tail;
    uint32_t uplink_queued_bytes;    /* unsent bytes across the queue */
    uint32_t uplink_withheld_recved; /* delivered bytes whose tcp_recved is
                                      * deferred until the low-water resume */
    int uplink_withheld;
    int downlink_paused;
    int fin_sent_to_h3;
    int fin_received_from_h3;
    int tcp_fin_seen;

    /* Downlink stash (Task 11): the ONE chunk already pulled out of the H3
     * response body (recv_body is destructive — a re-read is not possible)
     * but not yet accepted by tcp_write, because sndbuf/ERR_MEM said no.
     * Exactly one slot always suffices: the pump stops consuming recv_body
     * the INSTANT a write can't be queued, so at most one just-read chunk
     * is ever awaiting a retry. Lazily malloc'd (most flows never pause) and
     * kept for the flow's lifetime once allocated — freed by
     * tcp_lane_downlink_stash_free (relay error, lane teardown). */
    uint8_t *downlink_stash;
    uint16_t downlink_stash_len;

    /* Back-pointer to the owning lane, set at accept time. Needed because
     * the lwIP callbacks (on_lwip_recv/on_lwip_sent) receive only the flow
     * as tcp_arg, not the lane — this is how they reach lane->clock_fn for
     * last_activity_us stamping and how on_lwip_sent's resume path can call
     * the public mqvpn_tcp_lane_downlink_pump(lane, stream) API. NULL for
     * sticky-RAW markers (they never reach the accept callback). */
    mqvpn_tcp_lane_t *lane;

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

/* Defined with the Task 10 uplink-relay machinery below; needed by
 * mqvpn_tcp_lane_free's teardown loop above it. */
static void tcp_lane_uplink_queue_free(mqvpn_tcp_flow_t *f);
/* Defined with the Task 11 downlink-relay machinery below; same reason. */
static void tcp_lane_downlink_stash_free(mqvpn_tcp_flow_t *f);
/* Defined further below (Task 9); mqvpn_tcp_lane_downlink_pump (Task 11)
 * needs it before that point in the file, same forward-reference reason as
 * the other two declarations here. */
static mqvpn_tcp_flow_t *find_flow_by_stream(mqvpn_tcp_lane_t *lane, void *stream);

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
            if (f->pcb) {
                /* Glue teardown contract (lwip_glue.h): the lane owns every
                 * accepted pcb and must abort them all BEFORE the caller
                 * frees the lwip ctx — lwIP's pcb lists are process-global,
                 * so an orphaned pcb would survive into a reconnect's new
                 * ctx with callback_arg pointing at freed flow memory.
                 * Vendored tcp_abort → tcp_abandon (tcp.c) sends the RST,
                 * frees the pcb, and THEN invokes the snapshotted err
                 * callback with ERR_ABRT — clearing the callbacks first
                 * (TCP_EVENT_ERR is NULL-guarded, tcp_priv.h) makes the
                 * abort silent and sidesteps that post-free re-entrancy. */
                tcp_arg(f->pcb, NULL);
                tcp_recv(f->pcb, NULL);
                tcp_sent(f->pcb, NULL);
                tcp_err(f->pcb, NULL);
                tcp_abort(f->pcb);
            }
            tcp_lane_uplink_queue_free(f);
            tcp_lane_downlink_stash_free(f);
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

/* ─── Uplink relay: lwIP recv → H3 send_body (Task 10) ─── */

/* tcp_recved() indirection: the unit test (which #include's this TU) defines
 * MQVPN_TCP_LANE_TEST_RECVED before the #include to observe recved calls on
 * its fake pcbs (calling the REAL tcp_recved on a calloc'd pcb would corrupt
 * rcv_wnd internals). Compile-time substitution — zero production cost. */
#ifndef MQVPN_TCP_LANE_TEST_RECVED
#  define MQVPN_TCP_LANE_TEST_RECVED(pcb, len) tcp_recved((pcb), (len))
#endif

/* Task 11 downlink hooks: same compile-time substitution idiom as
 * MQVPN_TCP_LANE_TEST_RECVED above — the unit test (which links real
 * lwip_core but drives hand-built stack-fake `struct tcp_pcb`s, not ones
 * from tcp_new()/the pcb pool) defines scriptable/recording versions of all
 * four before the #include of this TU, exactly like the h3_send/h3_recv
 * test doubles. Calling the real tcp_write/tcp_shutdown/tcp_output on a
 * stack-fake pcb would touch send-queue/pbuf internals never initialized by
 * a real accept. tcp_sndbuf is a pure field read (`(pcb)->snd_buf`, see
 * lwip/tcp.h) so it would technically be safe on a fake pcb too, but the
 * hook is kept for symmetry and so tests can script sndbuf sequences
 * independently of mutating the fake pcb's field. Zero production cost. */
#ifndef MQVPN_TCP_LANE_TCP_WRITE
#  define MQVPN_TCP_LANE_TCP_WRITE(pcb, buf, len, flags) \
      tcp_write((pcb), (buf), (len), (flags))
#endif
#ifndef MQVPN_TCP_LANE_TCP_SNDBUF
#  define MQVPN_TCP_LANE_TCP_SNDBUF(pcb) tcp_sndbuf(pcb)
#endif
#ifndef MQVPN_TCP_LANE_TCP_SHUTDOWN
#  define MQVPN_TCP_LANE_TCP_SHUTDOWN(pcb, rx, tx) tcp_shutdown((pcb), (rx), (tx))
#endif
#ifndef MQVPN_TCP_LANE_TCP_OUTPUT
#  define MQVPN_TCP_LANE_TCP_OUTPUT(pcb) tcp_output(pcb)
#endif

/* tcp_recved takes a u16_t; the deferred resume total can exceed 65535
 * (bounded by TCP_WND ~2 MiB), so re-open the window in u16-sized steps. */
static void
tcp_lane_recved(struct tcp_pcb *pcb, uint32_t len)
{
    while (len > 0) {
        u16_t chunk = (len > 0xFFFFu) ? (u16_t)0xFFFFu : (u16_t)len;
        MQVPN_TCP_LANE_TEST_RECVED(pcb, chunk);
        len -= chunk;
    }
}

static void
tcp_lane_uplink_queue_free(mqvpn_tcp_flow_t *f)
{
    mqvpn_tcp_uplink_node_t *n = f->uplink_q_head;
    while (n) {
        mqvpn_tcp_uplink_node_t *next = n->next;
        pbuf_free(n->p);
        free(n);
        n = next;
    }
    f->uplink_q_head = NULL;
    f->uplink_q_tail = NULL;
    f->uplink_queued_bytes = 0;
}

/* Fatal relay failure (H3 send error, or an allocation failure that would
 * otherwise force dropping already-ACKed TCP bytes — silent data loss).
 * Routes the flow to CLOSING and releases the queue; Task 12 does the real
 * teardown (tcp_abort(f->pcb) RST + H3 request close + flow removal),
 * mirroring on_stream_rejected's routing-only contract. */
static void
mqvpn_tcp_lane_on_relay_error(mqvpn_tcp_flow_t *f)
{
    f->state = TCP_FLOW_CLOSING;
    tcp_lane_uplink_queue_free(f);
    /* Clear the withholding bookkeeping too: a CLOSING flow never runs the
     * low-water resume, so leaving these set would hand Task 12's teardown
     * stale "recved still owed" state. The never-sent tcp_recved is moot —
     * Task 12 tcp_abort()s the pcb (RST), discarding the window accounting
     * wholesale. */
    f->uplink_withheld = 0;
    f->uplink_withheld_recved = 0;
    /* Task 11: the downlink stash holds a chunk already destructively pulled
     * out of xquic's recv_body (a re-read is impossible) — free it here too,
     * same "teardown owns every buffer" contract as the uplink queue above.
     * downlink_paused would otherwise wedge Task 12's view of the flow: a
     * CLOSING flow must never look "paused" (nothing will ever resume it). */
    tcp_lane_downlink_stash_free(f);
    f->downlink_paused = 0;
}

/* Hand p's bytes [offset, tot_len) to the H3 stream. Returns the new offset
 * (== tot_len when fully accepted, < tot_len on EAGAIN/partial-accept
 * backpressure) or -1 on a fatal send error. A contiguous pbuf is sent
 * straight from its payload (no copy); a CHAINED pbuf (ooseq coalescing can
 * hand chains whose tot_len exceeds any single segment) is flattened through
 * a TCP_MSS-sized stack slice via pbuf_copy_partial — the loop slices until
 * done, never truncates. Partial accepts advance offset by exactly the
 * accepted byte count so nothing is ever resent. */
static int32_t
tcp_lane_uplink_send_from(mqvpn_tcp_flow_t *f, struct pbuf *p, uint16_t offset)
{
    uint8_t slice[TCP_MSS];

    while (offset < p->tot_len) {
        const uint8_t *ptr;
        uint16_t chunk;
        if (p->next == NULL) {
            ptr = (const uint8_t *)p->payload + offset;
            chunk = (uint16_t)(p->tot_len - offset);
        } else {
            uint16_t want = (uint16_t)(p->tot_len - offset);
            if (want > sizeof(slice)) {
                want = (uint16_t)sizeof(slice);
            }
            chunk = pbuf_copy_partial(p, slice, want, offset);
            if (chunk == 0) {
                return -1; /* offset out of range — internal invariant broken */
            }
            ptr = slice;
        }
        ssize_t sent = cli_tcp_lane_h3_send(f->h3_request, ptr, chunk, 0);
        if (sent == MQVPN_TCP_LANE_H3_SEND_AGAIN) {
            break;
        }
        if (sent < 0) {
            return -1;
        }
        offset = (uint16_t)(offset + (uint16_t)sent);
        if ((size_t)sent < (size_t)chunk) {
            break; /* partial accept == backpressure; resume from offset */
        }
    }
    return (int32_t)offset;
}

/* Append a (possibly partially sent) delivery to the flow's uplink queue.
 * Takes ownership of p on success; on failure the caller still owns p. */
static int
tcp_lane_uplink_stash(mqvpn_tcp_flow_t *f, struct pbuf *p, uint16_t offset)
{
    mqvpn_tcp_uplink_node_t *n = malloc(sizeof(*n));
    if (!n) {
        return -1;
    }
    n->p = p;
    n->offset = offset;
    n->next = NULL;
    if (f->uplink_q_tail) {
        f->uplink_q_tail->next = n;
    } else {
        f->uplink_q_head = n;
    }
    f->uplink_q_tail = n;
    f->uplink_queued_bytes += (uint32_t)(p->tot_len - offset);
    return 0;
}

/* KQ 8 close mapping, uplink direction (minimal Task 10 slice): lwIP
 * recv(NULL) == peer FIN → half-close the H3 stream (zero-length body with
 * fin=1) once every queued uplink byte has drained. FIN-after-EAGAIN needs
 * no dedicated retry entry: tcp_fin_seen && !fin_sent_to_h3 IS the pending
 * state, re-checked at the end of every flush (writable notifies keep
 * arriving while the stream has anything pending). Task 12 completes the
 * full close-mapping matrix (both orderings, downlink FIN, RST paths). */
static void
tcp_lane_uplink_maybe_fin(mqvpn_tcp_flow_t *f)
{
    if (f->state != TCP_FLOW_ACTIVE || !f->h3_request || !f->tcp_fin_seen ||
        f->fin_sent_to_h3 || f->uplink_q_head) {
        return;
    }
    ssize_t r = cli_tcp_lane_h3_send(f->h3_request, NULL, 0, 1);
    if (r == MQVPN_TCP_LANE_H3_SEND_ERR) {
        /* Fatal — mirror on_relay_error's contract (CLOSING, Task 12 does the
         * real teardown) rather than leaving the flow ACTIVE with a FIN that
         * can now never be sent. */
        mqvpn_tcp_lane_on_relay_error(f);
        return;
    }
    if (r >= 0) {
        f->fin_sent_to_h3 = 1;
    }
    /* AGAIN: stays pending, retried on the next writable notify / flush. */
}

/* Drain the uplink queue FIFO, stopping at the first EAGAIN/partial (later
 * entries MUST wait — ordering). Idempotent under repeated all-EAGAIN
 * writable notifies: nothing is popped until fully accepted, offsets only
 * advance. After a full drain, sends the pending H3 FIN (see above); then,
 * once the unsent backlog is below low-water, re-opens the lwIP receive
 * window withheld under backpressure. */
static void
tcp_lane_uplink_flush(mqvpn_tcp_flow_t *f)
{
    if (f->state != TCP_FLOW_ACTIVE || !f->h3_request) {
        return;
    }
    while (f->uplink_q_head) {
        mqvpn_tcp_uplink_node_t *n = f->uplink_q_head;
        int32_t off = tcp_lane_uplink_send_from(f, n->p, n->offset);
        if (off < 0) {
            mqvpn_tcp_lane_on_relay_error(f);
            return;
        }
        f->uplink_queued_bytes -= ((uint32_t)off - n->offset);
        n->offset = (uint16_t)off;
        if (n->offset < n->p->tot_len) {
            break; /* backpressure — retry from here on the next notify */
        }
        f->uplink_q_head = n->next;
        if (!f->uplink_q_head) {
            f->uplink_q_tail = NULL;
        }
        pbuf_free(n->p);
        free(n);
    }

    tcp_lane_uplink_maybe_fin(f);

    if (f->uplink_withheld && f->uplink_queued_bytes < MQVPN_TCP_LANE_BP_LOW_WATER) {
        f->uplink_withheld = 0;
        if (f->uplink_withheld_recved > 0 && f->pcb) {
            tcp_lane_recved(f->pcb, f->uplink_withheld_recved);
        }
        f->uplink_withheld_recved = 0;
    }
}

static err_t
mqvpn_tcp_lane_on_lwip_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    mqvpn_tcp_flow_t *f = (mqvpn_tcp_flow_t *)arg;
    (void)pcb;
    (void)err;

    /* Activity signal (Task 13's idle sweep target) — any recv notify,
     * data or peer FIN, counts. f->lane is set at accept time; NULL-guarded
     * the same way the accept/establish stamps already are. */
    if (f->lane && f->lane->clock_fn) {
        f->last_activity_us = f->lane->clock_fn(f->lane->clock_ctx);
    }

    if (!p) {
        /* Peer FIN from the lwIP side (KQ 8: recv(NULL) → H3 half-close).
         * flush() drains queued data first and sends the FIN only after; if
         * still PENDING_STREAM there is nothing to FIN yet — the
         * established-flush completes it (Task 12 owns both orderings). */
        f->tcp_fin_seen = 1;
        tcp_lane_uplink_flush(f);
        return ERR_OK;
    }

    if (f->state != TCP_FLOW_ACTIVE && f->state != TCP_FLOW_PENDING_STREAM) {
        pbuf_free(p);
        return ERR_OK; /* CLOSING etc. — drop; the close mapping owns teardown */
    }

    uint16_t tot = p->tot_len;
    uint16_t off = 0;

    /* Fast path: ACTIVE with an empty queue → hand straight to xquic.
     * A non-empty queue forces the stash path even when ACTIVE (FIFO
     * ordering: new bytes must ride behind the backlog). */
    if (f->state == TCP_FLOW_ACTIVE && !f->uplink_q_head && f->h3_request) {
        int32_t r = tcp_lane_uplink_send_from(f, p, 0);
        if (r < 0) {
            pbuf_free(p);
            mqvpn_tcp_lane_on_relay_error(f);
            return ERR_OK;
        }
        off = (uint16_t)r;
    }

    if (off == tot) {
        pbuf_free(p);
        tcp_lane_recved(f->pcb, tot); /* fully accepted — window re-opens */
        return ERR_OK;
    }

    /* Withhold/pre-2xx buffer — the SAME queue (one code path, not two). */
    if (tcp_lane_uplink_stash(f, p, off) < 0) {
        /* Alloc failure: these bytes are already ACKed at the TCP level —
         * dropping them would silently corrupt the relayed stream. Fail the
         * flow instead (Task 12 turns CLOSING into an RST). */
        pbuf_free(p);
        mqvpn_tcp_lane_on_relay_error(f);
        return ERR_OK;
    }

    /* recved-withholding policy (tcp_lane.h watermark comment):
     *  - ACTIVE + anything queued  = xquic said EAGAIN/partial → withhold
     *    immediately (backpressure signal, no threshold);
     *  - PENDING_STREAM            = no xquic signal exists yet → buffer
     *    freely up to high-water, withhold beyond it.
     * Withheld deliveries accumulate in uplink_withheld_recved and are
     * recved in one batch at the low-water resume in flush(). */
    if (f->state == TCP_FLOW_ACTIVE ||
        f->uplink_queued_bytes >= MQVPN_TCP_LANE_BP_HIGH_WATER) {
        f->uplink_withheld = 1;
    }
    if (f->uplink_withheld) {
        f->uplink_withheld_recved += tot;
    } else {
        tcp_lane_recved(f->pcb, tot);
    }
    return ERR_OK;
}

/* ─── Downlink relay: H3 recv_body → lwIP tcp_write (Task 11) ─── */

/* Save one just-read, not-yet-writable chunk. Lazily allocates the flow's
 * single stash slot (kept for the flow's lifetime once allocated — see the
 * field comment on mqvpn_tcp_flow_t). Returns -1 only on malloc failure,
 * which the caller must treat as fatal: these bytes were already
 * destructively pulled out of xquic's recv_body and cannot be re-fetched,
 * so losing them here would silently corrupt the relayed stream (same
 * "already-committed, cannot undo" hazard the uplink side's alloc-failure
 * path documents). */
static int
tcp_lane_downlink_stash(mqvpn_tcp_flow_t *f, const uint8_t *buf, uint16_t len)
{
    if (!f->downlink_stash) {
        f->downlink_stash = malloc(TCP_MSS);
        if (!f->downlink_stash) {
            return -1;
        }
    }
    memcpy(f->downlink_stash, buf, len);
    f->downlink_stash_len = len;
    return 0;
}

static void
tcp_lane_downlink_stash_free(mqvpn_tcp_flow_t *f)
{
    free(f->downlink_stash);
    f->downlink_stash = NULL;
    f->downlink_stash_len = 0;
}

/* Fin observed from cli_tcp_lane_h3_recv (with or without accompanying data
 * in the same call — see the MQVPN_TCP_LANE_H3_RECV_* contract). TX-side
 * half-close only (shut_rx=0): the inner app's peer may still have more to
 * say in the OTHER direction; Task 12 fully closes both ends together on
 * flow teardown. Idempotent via fin_received_from_h3 — tcp_shutdown must
 * fire exactly once per pcb (vendored tcp.c's tcp_close_shutdown switches on
 * pcb->state, which tcp_shutdown itself transitions away from FIN-capable
 * states). Returns -1 if on_relay_error ran (tcp_shutdown's tx path can
 * return ERR_MEM on a FIN-enqueue allocation failure, or ERR_CONN if the pcb
 * is no longer in a shutdown-eligible state — vendored tcp.c/tcp_out.c;
 * both leave the FIN permanently undeliverable with no local retry hook,
 * unlike our own H3 FIN send which retries on the next writable notify, so
 * this is treated as fatal like the uplink's own alloc-failure convention). */
static int
tcp_lane_downlink_maybe_shutdown(mqvpn_tcp_flow_t *f)
{
    if (f->fin_received_from_h3) {
        return 0;
    }
    f->fin_received_from_h3 = 1;
    err_t err = MQVPN_TCP_LANE_TCP_SHUTDOWN(f->pcb, 0, 1);
    if (err != ERR_OK) {
        mqvpn_tcp_lane_on_relay_error(f);
        return -1;
    }
    return 0;
}

/* Drain the flow's H3 response body into lwIP. Stops at the first
 * would-block (MQVPN_TCP_LANE_H3_RECV_AGAIN — nothing more buffered right
 * now; the next READ_BODY/EMPTY_FIN notify re-fires) or the first
 * sndbuf/ERR_MEM backpressure signal (stash the chunk, latch
 * downlink_paused, stop — mirrors the uplink's EAGAIN-stops-the-loop
 * design). A fatal recv or write error routes through on_relay_error and
 * returns -1; see mqvpn_tcp_lane_downlink_pump's header comment for why
 * callers must not propagate that into an xquic stream/connection error.
 * tcp_output is called AT MOST ONCE, after the loop — lwIP defers actual
 * segment transmission to tcp_output/tcp_tmr (vendored tcp_out.c: tcp_write
 * only appends to the unsent list), and with LWIP_TIMERS=0 the manual
 * tcp_tmr cadence (lwip_glue.c, every 250 ms) would otherwise sit on
 * freshly-written downlink data for up to that long. */
static int
tcp_lane_downlink_drain(mqvpn_tcp_flow_t *f)
{
    uint8_t buf[TCP_MSS];
    int wrote_any = 0;

    for (;;) {
        int fin = 0;
        ssize_t n = cli_tcp_lane_h3_recv(f->h3_request, buf, sizeof(buf), &fin);
        if (n == MQVPN_TCP_LANE_H3_RECV_AGAIN) {
            break;
        }
        if (n == MQVPN_TCP_LANE_H3_RECV_ERR) {
            mqvpn_tcp_lane_on_relay_error(f);
            return -1;
        }
        if (n > 0) {
            if ((size_t)MQVPN_TCP_LANE_TCP_SNDBUF(f->pcb) < (size_t)n) {
                if (tcp_lane_downlink_stash(f, buf, (uint16_t)n) < 0) {
                    mqvpn_tcp_lane_on_relay_error(f);
                    return -1;
                }
                f->downlink_paused = 1;
                break;
            }
            err_t werr =
                MQVPN_TCP_LANE_TCP_WRITE(f->pcb, buf, (uint16_t)n, TCP_WRITE_FLAG_COPY);
            if (werr == ERR_MEM) {
                /* Transient — the write_checks gate (queuelen or a stricter
                 * internal check than the sndbuf test above) said not now.
                 * Same stash-and-pause handling as the sndbuf gate. */
                if (tcp_lane_downlink_stash(f, buf, (uint16_t)n) < 0) {
                    mqvpn_tcp_lane_on_relay_error(f);
                    return -1;
                }
                f->downlink_paused = 1;
                break;
            }
            if (werr != ERR_OK) {
                mqvpn_tcp_lane_on_relay_error(f);
                return -1;
            }
            wrote_any = 1;
        }
        if (fin) {
            if (tcp_lane_downlink_maybe_shutdown(f) < 0) {
                return -1; /* on_relay_error already ran inside */
            }
            break; /* request fully consumed; nothing more to read */
        }
    }

    if (wrote_any) {
        MQVPN_TCP_LANE_TCP_OUTPUT(f->pcb);
    }
    return 0;
}

int
mqvpn_tcp_lane_downlink_pump(mqvpn_tcp_lane_t *lane, void *stream)
{
    if (!lane || !stream) {
        return 0;
    }
    mqvpn_tcp_flow_t *f = find_flow_by_stream(lane, stream);
    if (!f) {
        return 0;
    }
    /* CLOSING: the flow is on its way out (Task 12 owns the real pcb abort +
     * H3 close) — never consume recv_body for a dying flow. */
    if (f->state == TCP_FLOW_CLOSING) {
        return 0;
    }
    /* Paused: deliberately NOT draining recv_body. This is not data loss —
     * xquic's own per-stream flow control then backpressures the server (it
     * cannot deliver more body until the buffered bytes are read), a
     * bounded temporary state exactly mirroring the uplink's
     * EAGAIN/backpressure design in the other direction. The stash-flush
     * resume path (mqvpn_tcp_lane_on_lwip_sent below) clears downlink_paused
     * and re-calls this function once sndbuf recovers — including when a
     * FIN was still sitting undelivered in xquic's buffer at pause time:
     * nothing here discards or skips past it, the resumed drain loop simply
     * reaches it on its next cli_tcp_lane_h3_recv call. */
    if (f->downlink_paused) {
        return 0;
    }
    if (f->state != TCP_FLOW_ACTIVE || !f->h3_request || !f->pcb) {
        return 0;
    }
    return tcp_lane_downlink_drain(f);
}

/* Real downlink resume (Task 11): once sndbuf recovers enough to fit the
 * stashed chunk, flush it and resume draining recv_body. Task 12 still owns
 * the error callback + real flow removal. */
static err_t
mqvpn_tcp_lane_on_lwip_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    (void)len;
    mqvpn_tcp_flow_t *f = (mqvpn_tcp_flow_t *)arg;
    if (!f) {
        return ERR_OK;
    }
    (void)pcb; /* f->pcb is the same pointer; kept for signature parity */

    /* Activity signal, same rationale as on_lwip_recv's stamp. */
    if (f->lane && f->lane->clock_fn) {
        f->last_activity_us = f->lane->clock_fn(f->lane->clock_ctx);
    }

    if (!f->downlink_paused) {
        return ERR_OK;
    }
    if ((size_t)MQVPN_TCP_LANE_TCP_SNDBUF(f->pcb) < (size_t)f->downlink_stash_len) {
        return ERR_OK; /* still not enough room; wait for the next sent notify */
    }
    err_t werr = MQVPN_TCP_LANE_TCP_WRITE(f->pcb, f->downlink_stash,
                                          f->downlink_stash_len, TCP_WRITE_FLAG_COPY);
    if (werr == ERR_MEM) {
        return ERR_OK; /* transient; retry on the next sent notify */
    }
    if (werr != ERR_OK) {
        mqvpn_tcp_lane_on_relay_error(f);
        return ERR_OK;
    }
    MQVPN_TCP_LANE_TCP_OUTPUT(f->pcb);
    f->downlink_stash_len = 0;
    f->downlink_paused = 0;

    /* Resume draining recv_body via the public entry point (keeps exactly
     * one code path for "pump the downlink", same discipline as the
     * uplink's single flush() for both pre-2xx buffering and EAGAIN retry).
     * f->lane/f->stream are stable for the lifetime of an ACTIVE flow. */
    mqvpn_tcp_lane_downlink_pump(f->lane, f->stream);
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

/* O(n) walk scanning every bucket for the entry whose stored f->stream
 * back-pointer matches — see the rationale in tcp_lane.h above
 * mqvpn_tcp_lane_on_stream_established. n <= cfg.tcp_max_flows +
 * TCP_LANE_RAW_MARKER_CAP (256 + 4096 by default; markers have
 * f->stream == NULL so never false-match), and this only runs once per H3
 * response/writable event (not per-packet), so the linear scan is cheap. */
static mqvpn_tcp_flow_t *
find_flow_by_stream(mqvpn_tcp_lane_t *lane, void *stream)
{
    for (uint32_t i = 0; i < lane->n_buckets; i++) {
        for (mqvpn_tcp_flow_t *f = lane->buckets[i]; f; f = f->next) {
            if (f->stream == stream) {
                return f;
            }
        }
    }
    return NULL;
}

void
mqvpn_tcp_lane_bind_h3_request(void *flow_handle, void *h3_request, void *stream)
{
    mqvpn_tcp_flow_t *f = (mqvpn_tcp_flow_t *)flow_handle;
    f->h3_request = h3_request;
    f->stream = stream;
    /* Stay PENDING_STREAM: the request is sent but no response has arrived.
     * mqvpn_tcp_lane_on_stream_established/_rejected (Task 9) do the actual
     * 2xx/4xx-gated transition. */
}

void
mqvpn_tcp_lane_abort_pending(void *flow_handle)
{
    (void)flow_handle; /* Task 12: tcp_abort(f->pcb) + remove_flow */
}

void
mqvpn_tcp_lane_on_stream_established(mqvpn_tcp_lane_t *lane, void *stream)
{
    if (!lane || !stream) {
        return;
    }
    mqvpn_tcp_flow_t *f = find_flow_by_stream(lane, stream);
    if (!f) {
        /* Flow already gone (e.g. a race with a future Task 12/13 removal) —
         * nothing to gate. */
        return;
    }
    f->state = TCP_FLOW_ACTIVE;
    f->last_activity_us = lane->clock_fn ? lane->clock_fn(lane->clock_ctx) : 0;
    /* Flush the uplink bytes buffered while the flow sat in PENDING_STREAM
     * waiting for the 2xx gate to open — same queue + flush the writable
     * notify uses (pre-2xx buffering and EAGAIN retry are ONE mechanism),
     * including a FIN the inner app already sent. */
    tcp_lane_uplink_flush(f);
}

void
mqvpn_tcp_lane_on_stream_rejected(mqvpn_tcp_lane_t *lane, void *stream)
{
    if (!lane || !stream) {
        return;
    }
    mqvpn_tcp_flow_t *f = find_flow_by_stream(lane, stream);
    if (!f) {
        return;
    }
    /* Task 12 does the real teardown: tcp_abort(f->pcb) (RST to the local
     * app) + tcp_lane_remove_flow. This task only routes the non-2xx signal
     * to CLOSING so later code can recognize the flow is dead. */
    f->state = TCP_FLOW_CLOSING;
}

int
mqvpn_tcp_lane_on_h3_writable(mqvpn_tcp_lane_t *lane, void *stream)
{
    if (!lane || !stream) {
        return 0;
    }
    mqvpn_tcp_flow_t *f = find_flow_by_stream(lane, stream);
    if (!f) {
        return 0;
    }
    /* Retry-queue drain + low-water recved resume + pending-FIN send all
     * live in flush (see its comment). */
    tcp_lane_uplink_flush(f);
    return 0;
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
    /* Task 11: back-pointer so the lwIP callbacks below (which only receive
     * f as tcp_arg, never the lane) can reach lane->clock_fn and re-enter
     * mqvpn_tcp_lane_downlink_pump(lane, stream). */
    f->lane = lane;

    tcp_arg(newpcb, f);
    tcp_recv(newpcb, mqvpn_tcp_lane_on_lwip_recv);
    tcp_sent(newpcb, mqvpn_tcp_lane_on_lwip_sent);
    tcp_err(newpcb, mqvpn_tcp_lane_on_lwip_err);

    /* Direct .c-to-.c call — see the prototype's comment in tcp_lane.h. */
    cli_tcp_lane_open_stream(lane->client_ctx, f, &key);
    return ERR_OK;
}
