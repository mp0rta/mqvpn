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
