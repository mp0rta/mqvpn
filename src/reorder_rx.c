// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * reorder_rx.c — receiver-side engine for the flow-aware reorder-only datagram
 * shim (design spec v2.5 §11, §12, §13).
 *
 * This translation unit owns:
 *   - the elastic seq-indexed ring (§13), file-local;
 *   - (part B/C) the reorder_flow table, dispatch, process, timeout, eviction.
 *
 * TX and RX are zero-coupled: only reorder.h is shared. No tx header is included.
 *
 * The ring is a private detail of the engine: its functions are file-local and
 * only reachable from this TU. Unit tests exercise it by #include-ing this .c.
 */

#include "reorder_rx.h"

#include <stdlib.h>
#include <string.h>

/* ───────────────────────────── §13: elastic ring ──────────────────────────
 *
 * Receive buffer is always within the window [expected, expected + cap). A
 * seq-indexed ring makes contains/insert/remove O(1). The ring grows by SPAN
 * (not count): when (seq - expected) >= size it doubles + rehashes, capped at
 * cap (§13.1). slots is lazily allocated on the first out-of-order insert; until
 * then slots==NULL and the ring reports empty / not-contains (§13.2).
 */

struct slot {
    uint64_t seq; /* sequence number occupying this slot */
    uint16_t len; /* inner packet length */
    void *pkt;    /* shared-pool packet reference (caller-owned) */
};

struct ring {
    struct slot *slots; /* `size` entries, lazily allocated */
    uint32_t size;      /* power of two; grows to cover span, up to cap */
    uint32_t cap;       /* upper bound (power of two); window = [expected, +cap) */
    uint32_t count;     /* occupied slots */
    uint64_t bytes;     /* sum of buffered packet lengths */
};

#define RING_IDX(r, s) ((uint32_t)((s) & ((uint64_t)((r)->size) - 1)))

/* Initialize a ring from config cap (§13.2): cap pinned, slots lazy. cap is
 * assumed a non-zero power of two (validated by mqvpn_reorder_config_validate). */
static void
ring_init(struct ring *r, uint32_t cap)
{
    r->slots = NULL;
    r->size = 0;
    r->cap = cap;
    r->count = 0;
    r->bytes = 0;
}

/* Release the slots array (does NOT free the referenced packets — those are
 * caller/pool owned). After free the ring is empty and slots==NULL. */
static void
ring_free(struct ring *r)
{
    free(r->slots);
    r->slots = NULL;
    r->size = 0;
    r->count = 0;
    r->bytes = 0;
}

/* §13.2: slots==NULL (never grown) is treated as empty. */
static int
ring_empty(const struct ring *r)
{
    return r->count == 0;
}

/* §13.4 off-by-one: window is [expected, expected+cap); seq is far-ahead (drop)
 * when (seq - expected) >= cap. Works with slots==NULL (pure cap arithmetic,
 * §24.9 "lazy alloc 前でも seq - expected >= cap 判定が動く"). Callers gate this
 * before insert; ahead packets only (seq >= expected). */
static int
ring_far_ahead(const struct ring *r, uint64_t seq, uint64_t expected)
{
    return (seq - expected) >= r->cap;
}

/* §13: O(1) membership test. slots==NULL → not present. */
static int
ring_contains(const struct ring *r, uint64_t seq)
{
    if (r->slots == NULL) {
        return 0;
    }
    const struct slot *s = &r->slots[RING_IDX(r, seq)];
    return s->pkt != NULL && s->seq == seq;
}

/* Allocate a fresh slots array of `new_size` (power of two). Returns 0/-1. */
static int
ring_alloc_slots(struct ring *r, uint32_t new_size)
{
    struct slot *ns = (struct slot *)calloc(new_size, sizeof(struct slot));
    if (ns == NULL) {
        return -1;
    }
    r->slots = ns;
    r->size = new_size;
    return 0;
}

/* Grow the ring so size > span (i.e. (seq-expected) < size), doubling and
 * rehashing, capped at cap. Returns 0 on success, -1 on OOM. The caller has
 * already ensured the seq is in-window (span < cap), so a fitting size <= cap
 * always exists. */
static int
ring_grow_to_cover(struct ring *r, uint64_t span)
{
    /* smallest power of two strictly greater than span, but never below 1 and
     * never above cap. */
    uint32_t want = r->size ? r->size : 1;
    while (want <= span && want < r->cap) {
        want <<= 1;
    }
    if (want < r->size) {
        want = r->size; /* never shrink */
    }
    if (want == r->size && r->slots != NULL) {
        return 0; /* already big enough */
    }

    struct slot *old = r->slots;
    uint32_t old_size = r->size;
    if (ring_alloc_slots(r, want) != 0) {
        r->slots = old;
        r->size = old_size;
        return -1;
    }
    /* rehash occupied entries into the new array. */
    if (old != NULL) {
        for (uint32_t i = 0; i < old_size; i++) {
            if (old[i].pkt != NULL) {
                r->slots[RING_IDX(r, old[i].seq)] = old[i];
            }
        }
        free(old);
    }
    return 0;
}

/* Insert (seq, pkt, len) into the ring (§13.1). Grows by span when needed.
 * Caller guarantees seq is in-window (ring_far_ahead == 0) and not a duplicate.
 * `expected` defines the window origin for span computation. Returns 0 on
 * success, -1 on OOM. */
static int
ring_insert(struct ring *r, uint64_t seq, void *pkt, uint16_t len, uint64_t expected)
{
    uint64_t span = seq - expected;
    /* grow when slots unallocated or span >= size (§13.1). */
    if (r->slots == NULL || span >= r->size) {
        if (ring_grow_to_cover(r, span) != 0) {
            return -1;
        }
    }
    struct slot *s = &r->slots[RING_IDX(r, seq)];
    s->seq = seq;
    s->len = len;
    s->pkt = pkt;
    r->count++;
    r->bytes += len;
    return 0;
}

/* Remove the exact seq and return its packet pointer (or NULL if absent).
 * On success *out_len receives the stored length. */
static void *
ring_remove(struct ring *r, uint64_t seq, uint16_t *out_len)
{
    if (r->slots == NULL) {
        return NULL;
    }
    struct slot *s = &r->slots[RING_IDX(r, seq)];
    if (s->pkt == NULL || s->seq != seq) {
        return NULL;
    }
    void *pkt = s->pkt;
    if (out_len != NULL) {
        *out_len = s->len;
    }
    s->pkt = NULL;
    s->seq = 0;
    r->count--;
    r->bytes -= s->len;
    s->len = 0;
    return pkt;
}

/* §13.3: bounded forward scan from `expected`, returns the lowest occupied seq.
 * The window guarantees lowest < expected + size, so the scan is bounded by
 * size. Caller must ensure the ring is non-empty. */
static uint64_t
ring_lowest_seq(const struct ring *r, uint64_t expected)
{
    for (uint32_t i = 0; i < r->size; i++) {
        uint64_t seq = expected + i;
        const struct slot *s = &r->slots[RING_IDX(r, seq)];
        if (s->pkt != NULL && s->seq == seq) {
            return seq;
        }
    }
    return expected; /* defensive: empty ring (caller should not reach here) */
}

/* ─────────────────────── §11.2: reorder_flow + stats ──────────────────────
 *
 * Per-flow receiver state. Buffered packets are heap-copied on admit (the
 * caller's datagram buffer is reused after on_packet returns) and owned by the
 * ring until delivered or discarded. A real shared pool with byte accounting is
 * part B; for part A each buffered slot owns its own malloc'd copy.
 */

/* §17 RX statistics (subset implemented in part A; the rest land in part B/C). */
typedef struct {
    uint64_t delivered_count;
    uint64_t too_late_drop_count;
    uint64_t too_far_ahead_drop_count;
    uint64_t duplicate_drop_count;
    uint64_t per_flow_limit_drop_count;
    uint64_t pool_drop_count;
    uint64_t gap_count;        /* gap episodes opened (buffer went empty→nonempty) */
    uint64_t gap_filled_count; /* gap episodes closed by the missing seq arriving */
} mqvpn_reorder_stats_t;

typedef struct mqvpn_reorder_flow {
    mqvpn_flow_key_t key;
    uint64_t expected;
    int initialized;
    struct ring buffer; /* §13 elastic ring */

    int gap_timer_active;
    uint64_t gap_deadline_us;
    uint64_t gap_armed_us;
    uint32_t wait_ms; /* receiver-local; v1 = max_wait_ms (§16.3) */

    uint64_t last_seen_us;     /* observation time (stats) */
    uint64_t last_progress_us; /* deliver/buffer/advance time (eviction) */

    /* ACK-direction demotion (§11.6) — INERT in part A (see ACK demotion seam). */
    int pass_through;
    uint16_t classify_seen;
    uint16_t classify_large;

    mqvpn_reorder_stats_t stats;
    struct mqvpn_reorder_flow *next; /* hash chain */
} mqvpn_reorder_flow_t;

/* §11.3 process result enum (source of truth: spec §11.3). */
typedef enum {
    REORDER_DELIVERED,         /* in-order / cold-start: delivered immediately */
    REORDER_BUFFERED,          /* ahead: buffered */
    REORDER_DROPPED_LATE,      /* seq < expected */
    REORDER_DROPPED_FAR_AHEAD, /* seq - expected >= cap */
    REORDER_DROPPED_LIMIT,     /* per-flow limit / pool exhaustion / duplicate */
} reorder_process_result;

struct mqvpn_reorder_rx {
    mqvpn_reorder_config_t cfg;
    uint64_t hash_seed;
    mqvpn_reorder_deliver_fn deliver;
    void *deliver_ctx;

    mqvpn_reorder_flow_t **buckets;
    uint32_t n_buckets;
    uint32_t n_flows;
};

/* ─────────────────────────── flow table (§14.1) ───────────────────────────
 *
 * 5-tuple-keyed hash table with chaining. LRU eviction + idle sweep are part B;
 * part A only creates and looks up flows.
 */

#define MQVPN_RX_BUCKETS 1024 /* power of two */

static mqvpn_reorder_flow_t *
flow_lookup(mqvpn_reorder_rx_t *rx, const mqvpn_flow_key_t *key, uint32_t *out_idx)
{
    uint64_t h = mqvpn_flow_key_hash(key, rx->hash_seed);
    uint32_t idx = (uint32_t)(h & (rx->n_buckets - 1));
    if (out_idx) {
        *out_idx = idx;
    }
    for (mqvpn_reorder_flow_t *f = rx->buckets[idx]; f; f = f->next) {
        if (mqvpn_flow_key_eq(&f->key, key)) {
            return f;
        }
    }
    return NULL;
}

/* Find or create the reorder_flow for `key`. New flows have ring.cap initialized
 * from config (§13.2) but uninitialized seq state (cold-start on first packet,
 * §11.3). Returns NULL on OOM. */
static mqvpn_reorder_flow_t *
flow_get_or_create(mqvpn_reorder_rx_t *rx, const mqvpn_flow_key_t *key)
{
    uint32_t idx = 0;
    mqvpn_reorder_flow_t *f = flow_lookup(rx, key, &idx);
    if (f) {
        return f;
    }
    f = (mqvpn_reorder_flow_t *)calloc(1, sizeof(*f));
    if (!f) {
        return NULL;
    }
    f->key = *key;
    f->initialized = 0;
    ring_init(&f->buffer, rx->cfg.cap_packets_per_flow);
    f->wait_ms = rx->cfg.max_wait_ms;
    f->next = rx->buckets[idx];
    rx->buckets[idx] = f;
    rx->n_flows++;
    return f;
}

/* ─────────────────────────── timer helpers (§12) ──────────────────────────
 *
 * Maintains the §11.1 invariant: gap_timer_active is set exactly when the buffer
 * is non-empty. The deadline is informational in part A (the real timeout
 * handler + tick driver land in part B).
 */

static void
arm_gap_timer(mqvpn_reorder_flow_t *f, uint64_t now_us, uint32_t wait_ms)
{
    f->gap_timer_active = 1;
    f->gap_armed_us = now_us;
    f->gap_deadline_us = now_us + (uint64_t)wait_ms * 1000ULL;
}

static void
stop_gap_timer(mqvpn_reorder_flow_t *f)
{
    f->gap_timer_active = 0;
}

/* ───────────────── deliver helpers + contiguous drain (§11.3) ──────────────
 */

static void
deliver_pkt(mqvpn_reorder_rx_t *rx, const uint8_t *pkt, size_t len,
            mqvpn_reorder_flow_t *f)
{
    rx->deliver(pkt, len, rx->deliver_ctx);
    f->stats.delivered_count++;
}

/* Deliver every contiguously-buffered packet starting at flow->expected,
 * advancing expected and freeing each delivered heap copy (§11.3 drain). */
static void
drain_contiguous(mqvpn_reorder_rx_t *rx, mqvpn_reorder_flow_t *f)
{
    uint16_t len = 0;
    void *pkt;
    while ((pkt = ring_remove(&f->buffer, f->expected, &len)) != NULL) {
        deliver_pkt(rx, (const uint8_t *)pkt, len, f);
        free(pkt);
        f->expected++;
    }
}

/* ─────────────────────── §11.3 buffer_admit + process ─────────────────────
 */

/* §11.3 buffer_admit: the current packet is ahead and in-window. Duplicate →
 * drop (no replace). Otherwise heap-copy into the ring, arming the gap timer on
 * the empty→non-empty transition. Per-flow byte limit + global pool + overflow
 * flush are part B (see overflow seam); part A enforces only the duplicate and
 * count==cap-equivalent already handled by the far-ahead gate. */
static reorder_process_result
buffer_admit(mqvpn_reorder_rx_t *rx, mqvpn_reorder_flow_t *f, uint64_t seq,
             const uint8_t *pkt, uint16_t len, uint64_t now_us)
{
    if (ring_contains(&f->buffer, seq)) { /* duplicate */
        f->stats.duplicate_drop_count++;
        return REORDER_DROPPED_LIMIT; /* believe the first arrival; not classified */
    }

    /* per-flow byte limit + global pool accounting + overflow_flush: part B */
    void *copy = malloc(len);
    if (!copy) {
        /* Treat allocation failure as a pool drop (real shared-pool accounting +
         * overflow_flush is part B). */
        f->stats.pool_drop_count++;
        return REORDER_DROPPED_LIMIT;
    }
    memcpy(copy, pkt, len);

    int was_empty = ring_empty(&f->buffer);
    if (ring_insert(&f->buffer, seq, copy, len, f->expected) != 0) {
        free(copy);
        f->stats.pool_drop_count++;
        return REORDER_DROPPED_LIMIT;
    }
    f->last_progress_us = now_us;
    if (was_empty) {
        arm_gap_timer(f, now_us, f->wait_ms);
        f->stats.gap_count++;
    }
    return REORDER_BUFFERED;
}

/* §11.3 process_reorder_packet: cold-start init / in-order + drain / late drop /
 * ahead admit. Returns the result enum. */
static reorder_process_result
process_reorder_packet(mqvpn_reorder_rx_t *rx, mqvpn_reorder_flow_t *f, uint64_t seq,
                       const uint8_t *pkt, uint16_t len, uint64_t now_us)
{
    if (!f->initialized) { /* cold start (FLOW_RESET-all-loss fallback) */
        f->initialized = 1;
        f->expected = seq;
        deliver_pkt(rx, pkt, len, f);
        f->expected++;
        f->last_progress_us = now_us;
        return REORDER_DELIVERED;
    }

    if (seq == f->expected) { /* in-order */
        deliver_pkt(rx, pkt, len, f);
        f->expected++;
        f->last_progress_us = now_us;
        drain_contiguous(rx, f);
        if (ring_empty(&f->buffer) && f->gap_timer_active) {
            stop_gap_timer(f);
            f->stats.gap_filled_count++;
        }
        return REORDER_DELIVERED; /* non-empty → keep anchored timer (§12.2) */
    }

    if (seq < f->expected) { /* late */
        f->stats.too_late_drop_count++;
        return REORDER_DROPPED_LATE; /* last_progress NOT updated */
    }

    /* --- ahead --- §13.4 off-by-one; works even when slots==NULL (§24.9). */
    if (ring_far_ahead(&f->buffer, seq, f->expected)) {
        f->stats.too_far_ahead_drop_count++;
        return REORDER_DROPPED_FAR_AHEAD;
    }
    return buffer_admit(rx, f, seq, pkt, len, now_us);
}

/* §11.3 on_reordered dispatch. Step ordering is fixed by the spec:
 *   1. FLOW_RESET honor   — part B seam (INERT no-op here)
 *   2. pass_through        — part C seam (INERT; never set in part A)
 *   3. process_reorder_packet (fully implemented here)
 *   4. classify + demote   — part C seam (INERT no-op here)
 */
static void
on_reordered(mqvpn_reorder_rx_t *rx, mqvpn_reorder_flow_t *f, uint64_t seq, uint8_t flags,
             const uint8_t *pkt, uint16_t len, uint64_t now_us)
{
    f->last_seen_us = now_us;

    /* 1. FLOW_RESET honor: part B
     *    (flags & MQVPN_REORDER_FLAG_RESET handling — idle-grace + reset, §11.3
     *    step 1 — is added in part B). For now the flag is ignored and the
     *    packet falls through to the normal reorder path. */
    (void)flags;

    /* 2. pass_through (ACK demotion fast path): part C.
     *    pass_through is never set in part A, so this branch is structurally
     *    unreachable; left unwired (not a half-branch) per the seam contract. */

    /* 3. process the current packet through the normal reorder logic. */
    process_reorder_packet(rx, f, seq, pkt, len, now_us);

    /* 4. ACK demotion: part C
     *    classify_update + flush_buffer_for_demote on real traffic (DELIVERED /
     *    BUFFERED / DROPPED_LATE) is added in part C. */
}

/* ───────────────────────────── public API ─────────────────────────────── */

mqvpn_reorder_rx_t *
mqvpn_reorder_rx_new(const mqvpn_reorder_config_t *cfg, uint64_t hash_seed,
                     mqvpn_reorder_deliver_fn deliver, void *deliver_ctx)
{
    if (!cfg || !deliver || mqvpn_reorder_config_validate(cfg) != 0) {
        return NULL;
    }
    mqvpn_reorder_rx_t *rx = (mqvpn_reorder_rx_t *)calloc(1, sizeof(*rx));
    if (!rx) {
        return NULL;
    }
    rx->cfg = *cfg;
    rx->hash_seed = hash_seed;
    rx->deliver = deliver;
    rx->deliver_ctx = deliver_ctx;
    rx->n_buckets = MQVPN_RX_BUCKETS;
    rx->buckets = (mqvpn_reorder_flow_t **)calloc(rx->n_buckets, sizeof(*rx->buckets));
    if (!rx->buckets) {
        free(rx);
        return NULL;
    }
    return rx;
}

void
mqvpn_reorder_rx_free(mqvpn_reorder_rx_t *rx)
{
    if (!rx) {
        return;
    }
    for (uint32_t i = 0; i < rx->n_buckets; i++) {
        mqvpn_reorder_flow_t *f = rx->buckets[i];
        while (f) {
            mqvpn_reorder_flow_t *next = f->next;
            /* free any buffered heap copies still owned by the ring. */
            if (f->buffer.slots) {
                for (uint32_t j = 0; j < f->buffer.size; j++) {
                    if (f->buffer.slots[j].pkt) {
                        free(f->buffer.slots[j].pkt);
                    }
                }
            }
            ring_free(&f->buffer);
            free(f);
            f = next;
        }
    }
    free(rx->buckets);
    free(rx);
}

void
mqvpn_reorder_rx_on_packet(mqvpn_reorder_rx_t *rx, const uint8_t *payload, size_t len,
                           uint64_t now_us)
{
    uint8_t type = 0, flags = 0;
    uint64_t seq = 0;
    if (mqvpn_reorder_wire_decode(payload, len, &type, &flags, &seq) != 0) {
        return; /* datagram shorter than header (§21) */
    }
    if (type != MQVPN_REORDER_TYPE_V1) {
        return; /* not a reorder datagram (caller should route RAW elsewhere) */
    }
    const uint8_t *inner = payload + MQVPN_REORDER_HDR_LEN;
    size_t inner_len = len - MQVPN_REORDER_HDR_LEN;
    if (inner_len == 0 || inner_len > UINT16_MAX) {
        return; /* nothing to deliver / oversized */
    }

    /* §6: flow key is the inner-IP 5-tuple. If the inner packet is not a
     * parseable UDP 5-tuple it should not have been stamped REORDERED; drop. */
    mqvpn_flow_key_t key;
    if (mqvpn_reorder_parse_5tuple(inner, inner_len, &key) != 0) {
        return;
    }

    mqvpn_reorder_flow_t *f = flow_get_or_create(rx, &key);
    if (!f) {
        return; /* OOM: drop */
    }
    on_reordered(rx, f, seq, flags, inner, (uint16_t)inner_len, now_us);
}

void
mqvpn_reorder_rx_tick(mqvpn_reorder_rx_t *rx, uint64_t now_us)
{
    /* STUB (part A). The real gap-timeout handler (§12.1) + idle/LRU eviction
     * (§14) land in part B. Kept as a no-op so callers can wire the driver now
     * without behaviour change; the §11.1 invariant is unaffected. */
    (void)rx;
    (void)now_us;
}
