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

/* §17 RX statistics (subset implemented in part A/B; the rest land in part C). */
typedef struct {
    uint64_t delivered_count;
    uint64_t too_late_drop_count;
    uint64_t too_far_ahead_drop_count;
    uint64_t duplicate_drop_count;
    uint64_t per_flow_limit_drop_count;
    uint64_t pool_drop_count;
    uint64_t reset_discard_count; /* §17: old-epoch buffered packets discarded on reset */
    uint64_t gap_count;           /* gap episodes opened (buffer went empty→nonempty) */
    uint64_t gap_filled_count;    /* gap episodes closed by the missing seq arriving */
    uint64_t gap_timeout_count;   /* §17: periods ended by timeout skip (§12.1) */
    uint64_t gap_overflow_count;  /* §17: periods ended by overflow_flush (§12.3) */
    uint64_t gap_reset_count;     /* §17: periods ended by FLOW_RESET discard (§11.6) */
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

    /* §13.2 shared packet pool: a global byte budget enforced across all flows.
     * Buffered packets are still individually heap-allocated, but every admit is
     * charged against this counter and rejected when it would exceed
     * cfg.global_max_buffer_bytes (pool exhaustion). */
    uint64_t pool_bytes_used;
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

/* §13.2 pool accounting: a buffered heap copy is leaving the ring (delivered or
 * discarded). Uncharge its bytes from the shared pool and free the copy. */
static void
pool_release(mqvpn_reorder_rx_t *rx, void *pkt, uint16_t len)
{
    if (rx->pool_bytes_used >= len) {
        rx->pool_bytes_used -= len;
    } else {
        rx->pool_bytes_used = 0; /* defensive: never underflow */
    }
    free(pkt);
}

/* Release all resources owned by a reorder_flow (buffered copies + slots), then
 * free the flow itself. Pool bytes are uncharged via pool_release. Used by both
 * idle eviction (§14) and teardown. */
static void
flow_destroy(mqvpn_reorder_rx_t *rx, mqvpn_reorder_flow_t *f)
{
    if (f->buffer.slots != NULL) {
        for (uint32_t j = 0; j < f->buffer.size; j++) {
            if (f->buffer.slots[j].pkt != NULL) {
                pool_release(rx, f->buffer.slots[j].pkt, f->buffer.slots[j].len);
            }
        }
    }
    ring_free(&f->buffer);
    free(f);
}

/* Deliver every contiguously-buffered packet starting at flow->expected,
 * advancing expected and releasing each delivered heap copy (§11.3 drain). */
static void
drain_contiguous(mqvpn_reorder_rx_t *rx, mqvpn_reorder_flow_t *f)
{
    uint16_t len = 0;
    void *pkt;
    while ((pkt = ring_remove(&f->buffer, f->expected, &len)) != NULL) {
        deliver_pkt(rx, (const uint8_t *)pkt, len, f);
        pool_release(rx, pkt, len);
        f->expected++;
    }
}

/* ───────────────── §12: timeout handler + overflow flush ───────────────────
 *
 * Both share the same skip-then-drain core: jump `expected` to the lowest
 * occupied seq (§13.3 bounded scan), deliver the now-contiguous run, and update
 * last_progress. They differ only in (a) which §17 period counter they charge
 * and (b) whether they rearm the timer afterwards.
 */

/* Skip the current gap: advance expected to the lowest buffered seq, then drain
 * the contiguous run from there. Caller guarantees buffer non-empty. */
static void
skip_to_lowest_and_drain(mqvpn_reorder_rx_t *rx, mqvpn_reorder_flow_t *f, uint64_t now_us)
{
    uint64_t lowest = ring_lowest_seq(&f->buffer, f->expected);
    if (lowest > f->expected) {
        f->expected = lowest; /* O(1) skip past the missing seq(s) */
    }
    drain_contiguous(rx, f);
    f->last_progress_us = now_us;
}

/* §12.1 gap-timeout handler. Precondition: timer armed (⟺ buffer non-empty,
 * §11.1). Skip the missing seq, drain, then either stop (buffer drained) or
 * rearm (timeout-skip advanced expected → a fresh period may start, §12.2). */
static void
on_gap_timeout(mqvpn_reorder_rx_t *rx, mqvpn_reorder_flow_t *f, uint64_t now_us)
{
    if (ring_empty(&f->buffer)) { /* §12.1: invariant says unreachable; defensive */
        stop_gap_timer(f);
        return;
    }
    f->stats.gap_timeout_count++; /* §17: this period ends by timeout */

    skip_to_lowest_and_drain(rx, f, now_us);

    if (ring_empty(&f->buffer)) {
        stop_gap_timer(f);
    } else {
        /* §12.2: timeout-skip made forward progress, so a new period may arm. */
        arm_gap_timer(f, now_us, f->wait_ms);
        f->stats.gap_count++;
    }
}

/* §12.3 overflow_flush: force-skip the current gap to free buffer space without
 * halting processing. Precondition: buffer non-empty (§11.3/§13.5 — empty-buffer
 * limit/pool exhaustion is a drop, never a flush).
 *
 * §17 accounting: gap_overflow_count is charged only when the flush actually
 * ENDS the armed period — i.e. it drains the buffer to empty and stops the
 * timer. A partial flush that leaves a higher gap exposed keeps the SAME
 * anchored period alive (no rearm, §12.3 unlike §12.1), so it has not ended a
 * period and must not be counted; counting it would make the §17 identity
 * gap_count = filled + timeout + overflow (+ open) over-count by one. */
static void
overflow_flush(mqvpn_reorder_rx_t *rx, mqvpn_reorder_flow_t *f, uint64_t now_us)
{
    int was_armed = f->gap_timer_active;
    skip_to_lowest_and_drain(rx, f, now_us);
    if (ring_empty(&f->buffer)) {
        if (was_armed) {
            f->stats.gap_overflow_count++; /* §17: period ended by this flush */
        }
        stop_gap_timer(f);
    }
    /* else: buffer still non-empty → the anchored period continues unbroken (no
     * rearm, no terminator); the §11.1 invariant is held by the timer staying
     * active. */
}

/* ─────────────────── §11.6: FLOW_RESET buffer discard + reset ──────────────
 *
 * FLOW_RESET is a seq-space discontinuity: the old epoch's buffered packets must
 * NOT be delivered (their seqs are meaningless in the new epoch). This is
 * distinct from overflow_flush (same seq space, advances one period) and from
 * the part-C demote flush (delivers ascending then stops reordering). Here we
 * DISCARD (drop + free) the old buffer.
 */

/* §11.6 discard_buffer_for_reset: drop every old-epoch buffered packet (count
 * them via reset_discard_count), charging gap_reset_count if an armed period is
 * being ended, then free the ring and stop the timer. Normally the buffer is
 * already empty at a genuine reset (the gap timer drained it long ago), so this
 * usually does nothing beyond stopping an inactive timer. */
static void
discard_buffer_for_reset(mqvpn_reorder_rx_t *rx, mqvpn_reorder_flow_t *f)
{
    if (f->gap_timer_active) {
        f->stats.gap_reset_count++; /* §17: armed period ended by reset (usually 0) */
    }
    if (f->buffer.slots != NULL) {
        for (uint32_t i = 0; i < f->buffer.size; i++) {
            struct slot *s = &f->buffer.slots[i];
            if (s->pkt != NULL) {
                pool_release(rx, s->pkt, s->len); /* drop, NOT deliver (§11.6) */
                f->stats.reset_discard_count++;
                s->pkt = NULL;
            }
        }
    }
    stop_gap_timer(f);
    ring_free(&f->buffer); /* frees slots, zeroes size/count/bytes; cap preserved */
}

/* §11.6 reset_reorder_flow: discard the old epoch buffer and reinitialize the
 * classifier / pass_through state (reused 5-tuple / epoch reset re-classify).
 * expected / initialized are set by the caller (§11.3 step 1). */
static void
reset_reorder_flow(mqvpn_reorder_rx_t *rx, mqvpn_reorder_flow_t *f)
{
    discard_buffer_for_reset(rx, f);
    f->pass_through = 0;
    f->classify_seen = 0;
    f->classify_large = 0;
}

/* ─────────────────────── §11.3 buffer_admit + process ─────────────────────
 */

/* §13.5 per-flow limit predicate: would admitting `len` more bytes push the flow
 * past its packet-count cap or byte budget? count == cap is the §13.5 packet
 * limit (the window already bounds span via the far-ahead gate; this bounds
 * occupancy). bytes is checked against max_buffer_bytes_per_flow. */
static int
would_exceed_per_flow_limits(const mqvpn_reorder_rx_t *rx, const mqvpn_reorder_flow_t *f,
                             uint16_t len)
{
    if (f->buffer.count >= f->buffer.cap) {
        return 1;
    }
    if (f->buffer.bytes + len > rx->cfg.max_buffer_bytes_per_flow) {
        return 1;
    }
    return 0;
}

/* §13.2 global pool: would charging `len` bytes exceed the shared byte budget? */
static int
pool_would_exhaust(const mqvpn_reorder_rx_t *rx, uint16_t len)
{
    return rx->pool_bytes_used + len > rx->cfg.global_max_buffer_bytes;
}

/* Commit an in-window, non-duplicate, within-limits ahead packet to the ring:
 * heap-copy, charge the pool, insert, arm the gap timer on empty→non-empty
 * (§11.1/§11.3). Returns REORDER_BUFFERED, or REORDER_DROPPED_LIMIT on a
 * (defensive) copy/insert allocation failure. */
static reorder_process_result
buffer_insert_committed(mqvpn_reorder_rx_t *rx, mqvpn_reorder_flow_t *f, uint64_t seq,
                        const uint8_t *pkt, uint16_t len, uint64_t now_us)
{
    void *copy = malloc(len);
    if (!copy) {
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
    rx->pool_bytes_used += len; /* §13.2 charge after a successful insert */
    f->last_progress_us = now_us;
    if (was_empty) {
        arm_gap_timer(f, now_us, f->wait_ms);
        f->stats.gap_count++;
    }
    return REORDER_BUFFERED;
}

/* §11.3 reclassify after an overflow_flush moved `expected`: the current packet
 * must be re-checked against the new window (late / in-order+drain / far-ahead /
 * duplicate). Returns the post-flush result. Caller has already flushed. */
static reorder_process_result
reclassify_after_flush(mqvpn_reorder_rx_t *rx, mqvpn_reorder_flow_t *f, uint64_t seq,
                       const uint8_t *pkt, uint16_t len, uint64_t now_us)
{
    if (seq < f->expected) {
        f->stats.too_late_drop_count++;
        return REORDER_DROPPED_LATE;
    }
    if (seq == f->expected) {
        deliver_pkt(rx, pkt, len, f);
        f->expected++;
        f->last_progress_us = now_us;
        drain_contiguous(rx, f);
        if (ring_empty(&f->buffer) && f->gap_timer_active) {
            stop_gap_timer(f);
            f->stats.gap_filled_count++;
        }
        return REORDER_DELIVERED;
    }
    if (ring_far_ahead(&f->buffer, seq, f->expected)) {
        f->stats.too_far_ahead_drop_count++;
        return REORDER_DROPPED_FAR_AHEAD;
    }
    if (ring_contains(&f->buffer, seq)) {
        f->stats.duplicate_drop_count++;
        return REORDER_DROPPED_LIMIT;
    }
    return REORDER_BUFFERED; /* caller falls through to a fresh limit/pool admit */
}

/* §11.3 buffer_admit: the current packet is ahead and in-window. Duplicate →
 * drop (no replace, §11.3). Otherwise enforce the per-flow limit and global pool
 * (§13.2/§13.5): on a limit/pool hit with a NON-empty buffer, overflow_flush to
 * free space then RECLASSIFY the packet against the advanced window; with an
 * EMPTY buffer there is nothing to flush, so drop (per_flow_limit / pool). */
static reorder_process_result
buffer_admit(mqvpn_reorder_rx_t *rx, mqvpn_reorder_flow_t *f, uint64_t seq,
             const uint8_t *pkt, uint16_t len, uint64_t now_us)
{
    if (ring_contains(&f->buffer, seq)) { /* duplicate */
        f->stats.duplicate_drop_count++;
        return REORDER_DROPPED_LIMIT; /* believe the first arrival; not classified */
    }

    /* --- per-flow limit (count / bytes), §13.5 --- */
    if (would_exceed_per_flow_limits(rx, f, len)) {
        if (ring_empty(&f->buffer)) { /* overflow_flush needs a non-empty buffer */
            f->stats.per_flow_limit_drop_count++;
            return REORDER_DROPPED_LIMIT;
        }
        overflow_flush(rx, f, now_us);
        reorder_process_result r = reclassify_after_flush(rx, f, seq, pkt, len, now_us);
        if (r != REORDER_BUFFERED) {
            return r; /* late / in-order+drain / far-ahead / duplicate resolved it */
        }
        /* still an in-window ahead packet → fall through to pool + insert below */
    }

    /* --- global pool (§13.2) --- */
    if (pool_would_exhaust(rx, len)) {
        if (ring_empty(&f->buffer)) { /* no room to free by flushing self */
            f->stats.pool_drop_count++;
            return REORDER_DROPPED_LIMIT;
        }
        overflow_flush(rx, f, now_us); /* collapse self to free pool → reclassify */
        reorder_process_result r = reclassify_after_flush(rx, f, seq, pkt, len, now_us);
        if (r != REORDER_BUFFERED) {
            return r;
        }
        if (pool_would_exhaust(rx, len)) { /* still no space → drop */
            f->stats.pool_drop_count++;
            return REORDER_DROPPED_LIMIT;
        }
    }

    return buffer_insert_committed(rx, f, seq, pkt, len, now_us);
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
 *   1. FLOW_RESET honor   — WIRED (§11.3 step 1, idle-grace + reset)
 *   2. pass_through        — part C seam (INERT; never set in parts A/B)
 *   3. process_reorder_packet (fully implemented here)
 *   4. classify + demote   — part C seam (INERT no-op here)
 */
static void
on_reordered(mqvpn_reorder_rx_t *rx, mqvpn_reorder_flow_t *f, uint64_t seq, uint8_t flags,
             const uint8_t *pkt, uint16_t len, uint64_t now_us)
{
    f->last_seen_us = now_us;

    /* 1. FLOW_RESET honor (§11.3 step 1 / §14.2(a)). Honor only when the flow is
     *    uninitialized OR has been idle longer than the idle-grace window: a
     *    genuine sender-eviction reset arrives after egress_idle silence so the
     *    receiver's last_progress is stale; an intra-burst late packet of a fresh
     *    epoch (now - last_progress < grace) is NOT honored and falls through —
     *    becoming a late drop if seq < expected, with no rollback (§14.2(a)). */
    if (flags & MQVPN_REORDER_FLAG_RESET) {
        uint64_t grace_us = (uint64_t)rx->cfg.reset_idle_grace_ms * 1000ULL;
        if (!f->initialized || (now_us - f->last_progress_us) > grace_us) {
            reset_reorder_flow(rx, f); /* discard old buffer (NOT deliver) + reinit */
            f->initialized = 1;
            f->expected = seq;
            deliver_pkt(rx, pkt, len, f);
            f->expected++;
            f->last_progress_us = now_us;
            return;
        }
        /* idle-grace not met → ignore the flag and fall through to normal path. */
    }

    /* 2. pass_through (ACK demotion fast path): part C.
     *    pass_through is never set in parts A/B, so this branch is structurally
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
            flow_destroy(rx, f);
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
    /* §12.1: (a) fire gap timeouts for flows whose deadline has passed. */
    for (uint32_t i = 0; i < rx->n_buckets; i++) {
        for (mqvpn_reorder_flow_t *f = rx->buckets[i]; f; f = f->next) {
            if (f->gap_timer_active && f->gap_deadline_us <= now_us) {
                on_gap_timeout(rx, f, now_us);
            }
        }
    }

    /* §14 / §14.2(c): (b) idle eviction sweep on last_progress_us. A flow that
     * makes no progress (e.g. all K reset packets lost → stuck blackhole) goes
     * stale and is evicted here; its next packet re-inits via cold-start
     * (first-observed). This is the guaranteed reset backstop. */
    uint64_t idle_us = (uint64_t)rx->cfg.ingress_idle_timeout_sec * 1000000ULL;
    for (uint32_t i = 0; i < rx->n_buckets; i++) {
        mqvpn_reorder_flow_t **pp = &rx->buckets[i];
        while (*pp != NULL) {
            mqvpn_reorder_flow_t *f = *pp;
            if ((now_us - f->last_progress_us) > idle_us) {
                *pp = f->next; /* unlink from the chain */
                flow_destroy(rx, f);
                rx->n_flows--;
            } else {
                pp = &f->next;
            }
        }
    }
}
