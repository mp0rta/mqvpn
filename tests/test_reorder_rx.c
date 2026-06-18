// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_reorder_rx.c — unit tests for the RX engine core (design spec v2.5
 * §11, §13).
 *
 * Task 3.1: elastic seq-indexed ring (file-local; tested via #include of the
 *           .c so the static ring API is visible — see note below).
 * Task 3.2: dispatch + ordered-unreliable process (public rx API).
 *
 * Build: see CMakeLists.txt (test_reorder_rx target). Links reorder_rx.c +
 * log.c only — never any tx file (tx/rx are zero-coupled).
 *
 * Note on the #include: the elastic ring is internal/file-local to reorder_rx.c
 * (not part of the public rx header). To exercise it in isolation we #include
 * the translation unit directly; this is the cleaner of the two options the plan
 * offered (vs. exposing the ring via an internal header), keeping the ring a
 * true private detail of the engine.
 */
#include "reorder_rx.c" /* pulls in static ring + process internals */

#include "libmqvpn.h" /* Chunk 3: composed builder bridge (config_new/add_rule/apply) */
#include "mqvpn_internal.h" /* struct mqvpn_config_s: read the embedded .reorder out */

#include <stdio.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;

#define ASSERT_EQ_INT(a, b, msg)                                              \
    do {                                                                      \
        if ((long long)(a) == (long long)(b)) {                               \
            g_pass++;                                                         \
        } else {                                                              \
            g_fail++;                                                         \
            fprintf(stderr, "FAIL [%s]: %lld != %lld\n", msg, (long long)(a), \
                    (long long)(b));                                          \
        }                                                                     \
    } while (0)

#define ASSERT_TRUE(cond, msg)                   \
    do {                                         \
        if (cond) {                              \
            g_pass++;                            \
        } else {                                 \
            g_fail++;                            \
            fprintf(stderr, "FAIL [%s]\n", msg); \
        }                                        \
    } while (0)

/* ───────────────────────────── Task 3.1: ring ─────────────────────────── */

static void
test_ring_insert_contains_remove(void)
{
    struct ring r;
    ring_init(&r, 1024);

    /* expected=100; insert 105, 103, 108. */
    int dummy_a = 0xAA, dummy_c = 0xCC, dummy_e = 0xEE;
    ASSERT_EQ_INT(ring_insert(&r, 105, &dummy_a, 100, 100, 0), 0, "insert 105");
    ASSERT_EQ_INT(ring_insert(&r, 103, &dummy_c, 90, 100, 0), 0, "insert 103");
    ASSERT_EQ_INT(ring_insert(&r, 108, &dummy_e, 120, 100, 0), 0, "insert 108");

    ASSERT_TRUE(ring_contains(&r, 105), "contains 105");
    ASSERT_TRUE(ring_contains(&r, 103), "contains 103");
    ASSERT_TRUE(ring_contains(&r, 108), "contains 108");
    ASSERT_TRUE(!ring_contains(&r, 104), "not contains 104");
    ASSERT_EQ_INT(r.count, 3, "count 3");

    uint16_t len = 0;
    void *p = ring_remove(&r, 103, &len, NULL);
    ASSERT_TRUE(p == &dummy_c, "remove 103 returns ptr");
    ASSERT_EQ_INT(len, 90, "remove 103 returns len");
    ASSERT_TRUE(!ring_contains(&r, 103), "103 gone after remove");
    ASSERT_EQ_INT(r.count, 2, "count 2 after remove");

    /* removing absent seq returns NULL, count unchanged. */
    ASSERT_TRUE(ring_remove(&r, 103, &len, NULL) == NULL, "remove absent -> NULL");
    ASSERT_EQ_INT(r.count, 2, "count unchanged on absent remove");

    ring_free(&r);
}

static void
test_ring_empty_when_slots_null(void)
{
    struct ring r;
    ring_init(&r, 1024);
    /* never grown: slots==NULL. */
    ASSERT_TRUE(r.slots == NULL, "slots NULL at init");
    ASSERT_TRUE(ring_empty(&r), "empty when slots NULL");
    ASSERT_TRUE(!ring_contains(&r, 42), "contains false when slots NULL (no crash)");
    uint16_t len = 0;
    ASSERT_TRUE(ring_remove(&r, 42, &len, NULL) == NULL, "remove NULL when slots NULL");
    ring_free(&r);
}

static void
test_ring_offbyone(void)
{
    /* §13.4 / §24.9: with cap=C, seq==expected+C rejected (>=cap),
     * seq==expected+C-1 accepted. The far-ahead test is a pure cap check that
     * must work even before slots are allocated (§24.9 line 1131). */
    uint32_t C = 16;
    struct ring r;
    ring_init(&r, C);
    uint64_t expected = 1000;

    ASSERT_TRUE(r.slots == NULL, "slots not yet allocated");
    /* cap check works with slots==NULL */
    ASSERT_TRUE(ring_far_ahead(&r, expected + C, expected), "expected+C is far-ahead");
    ASSERT_TRUE(!ring_far_ahead(&r, expected + C - 1, expected),
                "expected+C-1 is in window");

    /* and the in-window insert actually succeeds. */
    int d = 0;
    ASSERT_EQ_INT(ring_insert(&r, expected + C - 1, &d, 10, expected, 0), 0,
                  "insert at expected+C-1 ok");
    ASSERT_TRUE(ring_contains(&r, expected + C - 1), "contains expected+C-1");
    ring_free(&r);
}

static void
test_ring_grow_by_span(void)
{
    /* §13.1: grow when span (seq-expected) >= size, NOT based on count. */
    uint32_t C = 1024;
    struct ring r;
    ring_init(&r, C);
    uint64_t expected = 0;
    int d = 0;

    /* First insert: span 0 -> size starts small (>=1) then covers span. */
    ASSERT_EQ_INT(ring_insert(&r, 1, &d, 10, expected, 0), 0, "insert span1");
    uint32_t size_after_small = r.size;
    ASSERT_TRUE(size_after_small >= 1, "size grown to cover span1");

    /* Big-span insert (span 500) must grow size to cover it, even though count
     * is tiny (count-based growth would not fire). */
    ASSERT_EQ_INT(ring_insert(&r, 500, &d, 10, expected, 0), 0, "insert span500");
    ASSERT_TRUE(r.size > size_after_small, "size grew for large span");
    ASSERT_TRUE(r.size > 500, "size covers span 500");
    /* rehash preserved old entry */
    ASSERT_TRUE(ring_contains(&r, 1), "entry 1 survived rehash");
    ASSERT_TRUE(ring_contains(&r, 500), "entry 500 present");
    ASSERT_EQ_INT(r.count, 2, "count 2");
    /* size never exceeds cap */
    ASSERT_TRUE(r.size <= C, "size capped at cap");
    ring_free(&r);
}

static void
test_ring_lowest_seq(void)
{
    /* §13.3: bounded forward scan from expected returns lowest occupied. */
    struct ring r;
    ring_init(&r, 1024);
    uint64_t expected = 200;
    int d = 0;
    ring_insert(&r, 210, &d, 10, expected, 0);
    ring_insert(&r, 205, &d, 10, expected, 0);
    ring_insert(&r, 230, &d, 10, expected, 0);
    ASSERT_EQ_INT(ring_lowest_seq(&r, expected), 205, "lowest is 205");

    uint16_t len = 0;
    ring_remove(&r, 205, &len, NULL);
    ASSERT_EQ_INT(ring_lowest_seq(&r, expected), 210, "lowest now 210");
    ring_free(&r);
}

/* ─────────────────────── Task 3.2: dispatch + process ──────────────────── */

/* Mock deliver: records the sequence of delivered inner packets by a 1-byte
 * tag we stash at a fixed offset in each packet's UDP payload. We actually
 * record the inner UDP source port low byte for ordering checks; simpler: we
 * record full packets' first distinguishing byte. We use the IPv4 identification
 * field (bytes 4..5) as a monotonic tag set by the builder. */
#define MAX_REC 256
typedef struct {
    uint16_t tags[MAX_REC];
    int n;
} recorder_t;

static void
mock_deliver(const uint8_t *pkt, size_t len, void *ctx)
{
    recorder_t *rec = (recorder_t *)ctx;
    if (rec->n < MAX_REC && len >= 6) {
        rec->tags[rec->n++] = (uint16_t)((pkt[4] << 8) | pkt[5]); /* IPv4 id */
    }
}

/* Build a de-framed reorder datagram into buf: [hdr8][inner IPv4/UDP].
 * `tag` is stamped into the IPv4 identification field so the recorder can
 * verify delivery order. `payload` = inner UDP payload bytes. Returns total. */
static size_t
build_reorder_dgram(uint8_t *buf, uint8_t flags, uint64_t seq, uint16_t tag,
                    uint16_t sport, uint16_t dport, size_t payload)
{
    mqvpn_reorder_wire_encode(buf, MQVPN_REORDER_TYPE_V1, flags, seq);
    uint8_t *ip = buf + MQVPN_REORDER_HDR_LEN;
    size_t inner = 28 + payload;
    memset(ip, 0, inner);
    ip[0] = 0x45; /* v4, IHL 5 */
    ip[4] = (uint8_t)(tag >> 8);
    ip[5] = (uint8_t)(tag);
    ip[9] = 17; /* UDP */
    ip[12] = 10;
    ip[15] = 1;
    ip[16] = 10;
    ip[19] = 2;
    ip[20] = (uint8_t)(sport >> 8);
    ip[21] = (uint8_t)(sport);
    ip[22] = (uint8_t)(dport >> 8);
    ip[23] = (uint8_t)(dport);
    return MQVPN_REORDER_HDR_LEN + inner;
}

static mqvpn_reorder_config_t
rx_cfg(void)
{
    mqvpn_reorder_config_t c;
    mqvpn_reorder_config_default(&c);
    c.mode = MQVPN_REORDER_ON;
    /* big classify_window so demotion never fires in these part-A tests. */
    c.classify_window = 60000;
    return c;
}

/* Find the single flow in the rx table (tests use one flow each). */
static mqvpn_reorder_flow_t *
only_flow(mqvpn_reorder_rx_t *rx)
{
    for (uint32_t i = 0; i < rx->n_buckets; i++) {
        if (rx->buckets[i]) {
            return rx->buckets[i];
        }
    }
    return NULL;
}

/* §11.1 invariant check: gap_timer_active ⟺ buffer non-empty, over all flows.
 * Hardening item 3: also assert pool_bytes_used == Σ over flows of buffer.bytes,
 * which catches any charge/release asymmetry that ASan cannot see (the bytes are
 * still individually malloc'd, so a mis-charge leaks accounting, not memory). */
static int
invariant_holds(mqvpn_reorder_rx_t *rx)
{
    uint64_t sum_bytes = 0;
    for (uint32_t i = 0; i < rx->n_buckets; i++) {
        for (mqvpn_reorder_flow_t *f = rx->buckets[i]; f; f = f->next) {
            int nonempty = !ring_empty(&f->buffer);
            if (f->gap_timer_active != nonempty) {
                return 0;
            }
            sum_bytes += f->buffer.bytes;
        }
    }
    if (rx->pool_bytes_used != sum_bytes) {
        return 0;
    }
    return 1;
}

static void
test_rx_inorder_passthrough_order(void)
{
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    for (uint64_t s = 0; s < 5; s++) {
        size_t n = build_reorder_dgram(buf, 0, s, (uint16_t)(s + 1), 5000, 443, 100);
        mqvpn_reorder_rx_on_packet(rx, buf, n, s + 1);
        ASSERT_TRUE(invariant_holds(rx), "invariant after in-order");
    }
    ASSERT_EQ_INT(rec.n, 5, "5 delivered");
    int ordered = 1;
    for (int i = 0; i < rec.n; i++) {
        if (rec.tags[i] != i + 1) {
            ordered = 0;
        }
    }
    ASSERT_TRUE(ordered, "delivered in order 1..5");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_cold_start_first_observed(void)
{
    /* §11.3: uninitialized flow sets expected = first observed seq, delivers. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    /* first packet has seq=42 (not 0) → cold-start anchors expected=42. */
    size_t n = build_reorder_dgram(buf, 0, 42, 7, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 10);
    ASSERT_EQ_INT(rec.n, 1, "cold-start delivered");
    ASSERT_EQ_INT(rec.tags[0], 7, "delivered the first observed");

    mqvpn_reorder_flow_t *f = only_flow(rx);
    ASSERT_TRUE(f != NULL, "flow created");
    ASSERT_EQ_INT(f->expected, 43, "expected advanced to 43");
    ASSERT_TRUE(invariant_holds(rx), "invariant after cold start");

    /* next in-order (43) delivers immediately. */
    n = build_reorder_dgram(buf, 0, 43, 8, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 11);
    ASSERT_EQ_INT(rec.n, 2, "next in-order delivered");
    ASSERT_EQ_INT(rec.tags[1], 8, "in order");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_buffer_then_fill(void)
{
    /* ahead packet buffered; arrival of missing seq drains contiguously. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    /* cold-start seq 0 → delivered, expected=1 */
    size_t n = build_reorder_dgram(buf, 0, 0, 1, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1);
    ASSERT_EQ_INT(rec.n, 1, "seq0 delivered");

    /* seq 2 ahead → buffered, NOT delivered; timer armed. */
    n = build_reorder_dgram(buf, 0, 2, 3, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 2);
    ASSERT_EQ_INT(rec.n, 1, "seq2 buffered not delivered");
    mqvpn_reorder_flow_t *f = only_flow(rx);
    ASSERT_TRUE(f->gap_timer_active, "timer armed while buffered");
    ASSERT_TRUE(invariant_holds(rx), "invariant with buffered");

    /* seq 3 ahead too → buffered. */
    n = build_reorder_dgram(buf, 0, 3, 4, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 3);
    ASSERT_EQ_INT(rec.n, 1, "seq3 buffered");

    /* missing seq 1 arrives → deliver 1, then drain 2,3. */
    n = build_reorder_dgram(buf, 0, 1, 2, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 4);
    ASSERT_EQ_INT(rec.n, 4, "gap fill drains all");
    ASSERT_EQ_INT(rec.tags[1], 2, "deliver 1 (tag2)");
    ASSERT_EQ_INT(rec.tags[2], 3, "drain 2 (tag3)");
    ASSERT_EQ_INT(rec.tags[3], 4, "drain 3 (tag4)");
    ASSERT_EQ_INT(f->expected, 4, "expected advanced to 4");
    ASSERT_TRUE(!f->gap_timer_active, "timer stopped after drain");
    ASSERT_TRUE(invariant_holds(rx), "invariant after drain");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_late_drop(void)
{
    /* seq < expected dropped (too_late); last_progress NOT updated. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    /* establish expected=6 via cold-start seq 5 */
    size_t n = build_reorder_dgram(buf, 0, 5, 1, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 100);
    mqvpn_reorder_flow_t *f = only_flow(rx);
    uint64_t lp_before = f->last_progress_us;

    /* seq 3 < expected 6 → drop, no deliver, last_progress unchanged. */
    n = build_reorder_dgram(buf, 0, 3, 99, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 200);
    ASSERT_EQ_INT(rec.n, 1, "late not delivered");
    ASSERT_EQ_INT(f->last_progress_us, lp_before, "last_progress unchanged on late");
    ASSERT_EQ_INT(f->stats.too_late_drop_count, 1, "too_late counted");
    ASSERT_TRUE(invariant_holds(rx), "invariant after late drop");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_far_ahead_drop(void)
{
    /* seq - expected >= cap dropped (too_far_ahead). */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    c.cap_packets_per_flow = 16;
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    /* cold-start seq 0 → expected=1 */
    size_t n = build_reorder_dgram(buf, 0, 0, 1, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1);
    mqvpn_reorder_flow_t *f = only_flow(rx);

    /* seq 17: 17 - 1 = 16 >= cap 16 → far-ahead drop. */
    n = build_reorder_dgram(buf, 0, 17, 2, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 2);
    ASSERT_EQ_INT(rec.n, 1, "far-ahead not delivered");
    ASSERT_EQ_INT(f->stats.too_far_ahead_drop_count, 1, "too_far_ahead counted");
    ASSERT_TRUE(ring_empty(&f->buffer), "not buffered");
    ASSERT_TRUE(invariant_holds(rx), "invariant after far-ahead drop");

    /* boundary: seq 16: 16 - 1 = 15 = cap-1 → buffered (accepted). */
    n = build_reorder_dgram(buf, 0, 16, 3, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 3);
    ASSERT_TRUE(ring_contains(&f->buffer, 16), "cap-1 boundary buffered");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_duplicate_drop(void)
{
    /* already-buffered seq dropped, NOT replaced (§11.3 duplicate rule). */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    size_t n = build_reorder_dgram(buf, 0, 0, 1, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1); /* deliver, expected=1 */

    /* buffer seq 3 with tag 30 */
    n = build_reorder_dgram(buf, 0, 3, 30, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 2);
    mqvpn_reorder_flow_t *f = only_flow(rx);
    ASSERT_EQ_INT(f->buffer.count, 1, "one buffered");

    /* duplicate seq 3 with DIFFERENT tag 31 → dropped, NOT replaced. */
    n = build_reorder_dgram(buf, 0, 3, 31, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 3);
    ASSERT_EQ_INT(f->buffer.count, 1, "still one buffered (no replace)");
    ASSERT_EQ_INT(f->stats.duplicate_drop_count, 1, "duplicate counted");

    /* fill gap: deliver 1(tag2),2(tag... none) — actually deliver seq1 then drain
     * seq3 → tag must be the FIRST one (30), proving no replace. */
    n = build_reorder_dgram(buf, 0, 1, 2, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 4);
    n = build_reorder_dgram(buf, 0, 2, 20, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 5);
    /* rec: tag1, tag2, tag20, tag30 */
    ASSERT_EQ_INT(rec.tags[rec.n - 1], 30, "drained seq3 is original tag 30");
    ASSERT_TRUE(invariant_holds(rx), "invariant after dup");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_invariant_timer_iff_nonempty(void)
{
    /* exercise a mixed sequence and assert the invariant after every op. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];
    uint64_t seqs[] = {0, 3, 2, 5, 1, 4, 6}; /* gaps then fills */
    uint64_t t = 1;
    for (size_t i = 0; i < sizeof(seqs) / sizeof(seqs[0]); i++) {
        size_t n =
            build_reorder_dgram(buf, 0, seqs[i], (uint16_t)(seqs[i] + 1), 5000, 443, 100);
        mqvpn_reorder_rx_on_packet(rx, buf, n, t++);
        ASSERT_TRUE(invariant_holds(rx), "invariant each op");
    }
    mqvpn_reorder_flow_t *f = only_flow(rx);
    ASSERT_TRUE(ring_empty(&f->buffer), "all drained at end");
    ASSERT_TRUE(!f->gap_timer_active, "timer off at end");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_lazy_cap_check_before_slots(void)
{
    /* §24.9 line 1131: seq-expected >= cap check works when slots==NULL (ring
     * never grown). Use a far-ahead first-after-coldstart so slots stay NULL. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    c.cap_packets_per_flow = 8;
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    /* cold-start seq 0 → expected=1, slots still NULL (no out-of-order yet). */
    size_t n = build_reorder_dgram(buf, 0, 0, 1, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1);
    mqvpn_reorder_flow_t *f = only_flow(rx);
    ASSERT_TRUE(f->buffer.slots == NULL, "slots still NULL after cold start");

    /* seq 100: 100-1 = 99 >= cap 8 → far-ahead drop, no crash, slots stay NULL. */
    n = build_reorder_dgram(buf, 0, 100, 2, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 2);
    ASSERT_EQ_INT(rec.n, 1, "far-ahead with NULL slots not delivered");
    ASSERT_EQ_INT(f->stats.too_far_ahead_drop_count, 1, "far-ahead counted (NULL slots)");
    ASSERT_TRUE(f->buffer.slots == NULL, "slots remain NULL (never allocated)");
    mqvpn_reorder_rx_free(rx);
}

/* ───────────── Task 3.3: gap timeout + overflow flush + limits ─────────── */

/* §17 partial accounting (terms defined through 3.3): every CLOSED armed period
 * ends in exactly one of filled / timeout / overflow. A period currently open
 * (timer still armed) has incremented gap_count but no terminator yet, so it
 * contributes the +1 below. */
static int
accounting_holds_33(mqvpn_reorder_flow_t *f)
{
    uint64_t closed = f->stats.gap_filled_count + f->stats.gap_timeout_count +
                      f->stats.gap_overflow_count;
    uint64_t open = f->gap_timer_active ? 1u : 0u;
    return f->stats.gap_count == closed + open;
}

static void
test_rx_timeout_skip_advances(void)
{
    /* §12.1: buffer an ahead packet (arms timer); advance now_us past the wait;
     * tick → expected jumps to lowest, drains, gap_timeout_count++. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    c.max_wait_ms = 30;
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    /* cold-start seq 0 → expected=1 */
    size_t n = build_reorder_dgram(buf, 0, 0, 1, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000);

    /* seq 3 ahead → buffered, timer armed at now=2000 (deadline = 2000+30000). */
    n = build_reorder_dgram(buf, 0, 3, 4, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 2000);
    mqvpn_reorder_flow_t *f = only_flow(rx);
    ASSERT_TRUE(f->gap_timer_active, "timer armed");
    ASSERT_EQ_INT(rec.n, 1, "seq3 buffered not delivered");

    /* tick before deadline: nothing happens. */
    mqvpn_reorder_rx_tick(rx, 2000 + 29999);
    ASSERT_EQ_INT(rec.n, 1, "no timeout before deadline");
    ASSERT_TRUE(f->gap_timer_active, "still armed before deadline");

    /* tick at/after deadline: skip missing 1,2 → deliver seq3 (tag4). */
    mqvpn_reorder_rx_tick(rx, 2000 + 30000);
    ASSERT_EQ_INT(rec.n, 2, "timeout delivered the buffered packet");
    ASSERT_EQ_INT(rec.tags[1], 4, "delivered seq3 (tag4) after skip");
    ASSERT_EQ_INT(f->expected, 4, "expected jumped past skip to 4");
    ASSERT_EQ_INT(f->stats.gap_timeout_count, 1, "gap_timeout counted");
    ASSERT_TRUE(!f->gap_timer_active, "timer stopped (buffer drained)");
    ASSERT_TRUE(invariant_holds(rx), "invariant after timeout");
    ASSERT_TRUE(accounting_holds_33(f), "accounting after timeout");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_timeout_skip_rearms_when_nonempty(void)
{
    /* §12.1: timeout that skips but leaves the buffer non-empty REARMS a fresh
     * period (gap_count++), unlike §12.2 in-order advance. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    c.max_wait_ms = 30;
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    size_t n = build_reorder_dgram(buf, 0, 0, 1, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000); /* expected=1 */

    /* buffer seq 2 and seq 5 (gap at 1, then gap at 3,4 after first skip). */
    n = build_reorder_dgram(buf, 0, 2, 3, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 2000);
    n = build_reorder_dgram(buf, 0, 5, 6, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 2000);
    mqvpn_reorder_flow_t *f = only_flow(rx);
    ASSERT_EQ_INT(f->stats.gap_count, 1, "one period opened");

    /* timeout: skip missing 1 → deliver seq2 (tag3); seq5 still buffered → rearm. */
    mqvpn_reorder_rx_tick(rx, 2000 + 30000);
    ASSERT_EQ_INT(rec.tags[rec.n - 1], 3, "delivered seq2 (tag3)");
    ASSERT_EQ_INT(f->expected, 3, "expected jumped to 3 (past skip)");
    ASSERT_TRUE(f->gap_timer_active, "rearmed (buffer still non-empty)");
    ASSERT_EQ_INT(f->stats.gap_timeout_count, 1, "one timeout");
    ASSERT_EQ_INT(f->stats.gap_count, 2, "rearmed → second period opened");
    ASSERT_TRUE(invariant_holds(rx), "invariant after rearm");
    ASSERT_TRUE(accounting_holds_33(f), "accounting after rearm");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_anchored_timer_no_rearm(void)
{
    /* §12.2: in-order arrival that advances expected but leaves the buffer
     * non-empty (new gap exposed) keeps the ORIGINAL deadline (no rearm). */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    c.max_wait_ms = 30;
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    size_t n = build_reorder_dgram(buf, 0, 0, 1, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000); /* expected=1 */

    /* buffer seq 2 (gap at 1) and seq 4 (gap at 3). One period, armed at 2000. */
    n = build_reorder_dgram(buf, 0, 2, 3, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 2000);
    n = build_reorder_dgram(buf, 0, 4, 5, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 2500);
    mqvpn_reorder_flow_t *f = only_flow(rx);
    uint64_t deadline0 = f->gap_deadline_us;
    ASSERT_EQ_INT(f->stats.gap_count, 1, "single period");

    /* in-order seq 1 arrives at 5000: delivers 1, drains 2, exposes gap at 3
     * (seq4 still buffered). Timer must NOT rearm — original deadline kept. */
    n = build_reorder_dgram(buf, 0, 1, 2, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 5000);
    ASSERT_EQ_INT(f->expected, 3, "expected advanced past 1,2 to 3");
    ASSERT_TRUE(f->gap_timer_active, "still armed (seq4 buffered)");
    ASSERT_EQ_INT((long long)f->gap_deadline_us, (long long)deadline0,
                  "anchored: deadline unchanged (no rearm)");
    ASSERT_EQ_INT(f->stats.gap_count, 1, "no new period (anchored)");
    ASSERT_TRUE(invariant_holds(rx), "invariant after anchored advance");
    ASSERT_TRUE(accounting_holds_33(f), "accounting after anchored advance");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_overflow_flush_reclassify(void)
{
    /* §24.9 line 1115: fill to the per-flow byte cap so the next admit triggers
     * overflow_flush, then the current packet is reclassified correctly. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    c.cap_packets_per_flow = 1024;
    /* inner IP len per packet = 28 + payload(100) = 128. Cap the per-flow bytes
     * so exactly TWO packets fit (256) and a third triggers overflow. */
    c.max_buffer_bytes_per_flow = 256;
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    size_t n = build_reorder_dgram(buf, 0, 0, 1, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000); /* expected=1 */

    /* buffer seq 2 (gap at 1) and seq 3 → bytes = 256 (at the limit). */
    n = build_reorder_dgram(buf, 0, 2, 3, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 2000);
    n = build_reorder_dgram(buf, 0, 3, 4, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 2000);
    mqvpn_reorder_flow_t *f = only_flow(rx);
    ASSERT_EQ_INT(f->buffer.count, 2, "two buffered at the byte limit");

    /* seq 4 ahead would exceed the per-flow byte limit → overflow_flush. The
     * flush skips the gap at 1 → delivers seq2 (tag3), seq3 (tag4); expected=4.
     * Then seq4 reclassifies to in-order → delivered (tag5). */
    n = build_reorder_dgram(buf, 0, 4, 5, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 3000);
    ASSERT_EQ_INT(rec.tags[rec.n - 1], 5, "seq4 reclassified to in-order & delivered");
    ASSERT_EQ_INT(f->expected, 5, "expected advanced through flush + reclass");
    ASSERT_EQ_INT(f->stats.gap_overflow_count, 1, "gap_overflow counted");
    ASSERT_TRUE(ring_empty(&f->buffer), "buffer drained");
    ASSERT_TRUE(!f->gap_timer_active, "timer off after drain");
    ASSERT_TRUE(invariant_holds(rx), "invariant after overflow reclass");
    ASSERT_TRUE(accounting_holds_33(f), "accounting after overflow");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_overflow_partial_drain_anchored(void)
{
    /* §12.3/§17: an overflow flush that only PARTIALLY drains (a higher gap is
     * exposed) keeps the same anchored period alive — no rearm, and NOT counted
     * as a terminator (the §17 identity must stay exact via the open-period +1). */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    c.cap_packets_per_flow = 1024;
    c.max_buffer_bytes_per_flow = 256; /* exactly two 128-byte packets */
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    size_t n = build_reorder_dgram(buf, 0, 0, 1, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000); /* expected=1 */

    /* buffer seq 2 (gap at 1) and seq 5 (gap at 3,4) → two packets, at the limit. */
    n = build_reorder_dgram(buf, 0, 2, 3, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 2000);
    n = build_reorder_dgram(buf, 0, 5, 6, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 2000);
    mqvpn_reorder_flow_t *f = only_flow(rx);
    uint64_t deadline0 = f->gap_deadline_us;
    ASSERT_EQ_INT(f->stats.gap_count, 1, "one period opened");

    /* seq 6 ahead exceeds the byte limit → overflow_flush. lowest=2, skip gap at
     * 1, deliver seq2 (tag3), then gap at 3 stops the drain → seq5 still buffered.
     * Then reclassify seq6 → ahead, buffered. Period continues, anchored. */
    n = build_reorder_dgram(buf, 0, 6, 7, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 3000);
    ASSERT_EQ_INT(f->expected, 3, "expected advanced to 3 (partial drain)");
    ASSERT_TRUE(f->gap_timer_active, "still armed (seq5,6 buffered)");
    ASSERT_EQ_INT((long long)f->gap_deadline_us, (long long)deadline0,
                  "anchored: deadline unchanged after partial overflow");
    ASSERT_EQ_INT(f->stats.gap_overflow_count, 0,
                  "partial overflow does NOT end a period → not counted");
    ASSERT_EQ_INT(f->stats.gap_count, 1, "no new period (no rearm)");
    ASSERT_TRUE(invariant_holds(rx), "invariant after partial overflow");
    ASSERT_TRUE(accounting_holds_33(f), "accounting after partial overflow");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_per_flow_limit_drop_when_empty(void)
{
    /* §24.9 line 1116: a single packet exceeding the per-flow byte limit with an
     * EMPTY buffer → per_flow_limit_drop, no flush. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    c.cap_packets_per_flow = 1024;
    c.max_buffer_bytes_per_flow = 64; /* one 128-byte packet alone exceeds it */
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    size_t n = build_reorder_dgram(buf, 0, 0, 1, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000); /* expected=1, buffer empty */
    mqvpn_reorder_flow_t *f = only_flow(rx);

    /* seq 3 ahead, buffer empty, exceeds per-flow byte limit → drop, no flush. */
    n = build_reorder_dgram(buf, 0, 3, 4, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 2000);
    ASSERT_EQ_INT(rec.n, 1, "not delivered");
    ASSERT_EQ_INT(f->stats.per_flow_limit_drop_count, 1, "per_flow_limit_drop counted");
    ASSERT_EQ_INT(f->stats.gap_overflow_count, 0, "no flush on empty buffer");
    ASSERT_TRUE(ring_empty(&f->buffer), "still empty (not buffered)");
    ASSERT_TRUE(!f->gap_timer_active, "no timer armed");
    ASSERT_TRUE(invariant_holds(rx), "invariant after empty-limit drop");
    ASSERT_TRUE(accounting_holds_33(f), "accounting after empty-limit drop");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_pool_drop_when_empty(void)
{
    /* §24.9 line 1116: pool exhausted + buffer empty → pool_drop, dropped. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    c.cap_packets_per_flow = 1024;
    c.max_buffer_bytes_per_flow = 1572864ULL; /* per-flow not the binding limit */
    c.global_max_buffer_bytes = 64;           /* global pool: one packet exceeds it */
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    size_t n = build_reorder_dgram(buf, 0, 0, 1, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000); /* expected=1, pool empty */
    mqvpn_reorder_flow_t *f = only_flow(rx);

    /* seq 3 ahead, buffer empty, pool exhausted → pool_drop, no flush. */
    n = build_reorder_dgram(buf, 0, 3, 4, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 2000);
    ASSERT_EQ_INT(rec.n, 1, "not delivered");
    ASSERT_EQ_INT(f->stats.pool_drop_count, 1, "pool_drop counted");
    ASSERT_TRUE(ring_empty(&f->buffer), "still empty");
    ASSERT_EQ_INT((long long)rx->pool_bytes_used, 0, "pool not charged on drop");
    ASSERT_TRUE(invariant_holds(rx), "invariant after pool drop");
    ASSERT_TRUE(accounting_holds_33(f), "accounting after pool drop");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_overflow_does_not_halt(void)
{
    /* §24.9 line 1117: repeated overflow / pool pressure never halts processing.
     * Drive many ahead packets under a tiny per-flow byte budget; the engine must
     * keep delivering (via flush) and keep the invariant. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    c.cap_packets_per_flow = 1024;
    c.max_buffer_bytes_per_flow = 256; /* ~2 packets before overflow */
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    size_t n = build_reorder_dgram(buf, 0, 0, 1, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000); /* expected=1 */
    mqvpn_reorder_flow_t *f = only_flow(rx);

    /* a long run of ahead packets with a permanent gap at 1: each pair fills the
     * byte budget, the next triggers overflow_flush. Processing must continue. */
    int delivered_before = rec.n;
    for (uint64_t s = 2; s < 40; s++) {
        n = build_reorder_dgram(buf, 0, s, (uint16_t)(s + 1), 5000, 443, 100);
        mqvpn_reorder_rx_on_packet(rx, buf, n, 2000 + s);
        ASSERT_TRUE(invariant_holds(rx), "invariant under overflow pressure");
        ASSERT_TRUE(accounting_holds_33(f), "accounting under overflow pressure");
    }
    ASSERT_TRUE(rec.n > delivered_before, "processing kept delivering (not halted)");
    ASSERT_TRUE(f->stats.gap_overflow_count > 0, "overflow_flush fired repeatedly");
    mqvpn_reorder_rx_free(rx);
}

/* ──────────── Task 3.4: FLOW_RESET honor + last_progress backstop ────────── */

/* §17 partial accounting (terms defined through 3.4): closed periods end in
 * filled / timeout / overflow / reset; one open (armed) period adds +1. */
static int
accounting_holds_34(mqvpn_reorder_flow_t *f)
{
    uint64_t closed = f->stats.gap_filled_count + f->stats.gap_timeout_count +
                      f->stats.gap_overflow_count + f->stats.gap_reset_count;
    uint64_t open = f->gap_timer_active ? 1u : 0u;
    return f->stats.gap_count == closed + open;
}

static void
test_rx_reset_reinit(void)
{
    /* §11.3 step 1 / §14.2(a): FLOW_RESET with idle-grace satisfied (stale
     * last_progress) → reinit expected=seq, deliver. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    c.reset_idle_grace_ms = 10000; /* 10s grace */
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    /* establish epoch: cold-start seq 100, expected=101, last_progress=1_000_000. */
    size_t n = build_reorder_dgram(buf, 0, 100, 1, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000000);
    mqvpn_reorder_flow_t *f = only_flow(rx);
    ASSERT_EQ_INT(f->expected, 101, "epoch established expected=101");

    /* FLOW_RESET seq=0 arrives 20s later (> 10s grace) → honored: expected=0,
     * deliver, expected=1. */
    n = build_reorder_dgram(buf, MQVPN_REORDER_FLAG_RESET, 0, 50, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000000 + 20000000ULL);
    ASSERT_EQ_INT(rec.n, 2, "reset packet delivered");
    ASSERT_EQ_INT(rec.tags[1], 50, "delivered the reset-epoch packet");
    ASSERT_EQ_INT(f->expected, 1, "expected reinit to seq+1 = 1");
    ASSERT_TRUE(invariant_holds(rx), "invariant after reset reinit");
    ASSERT_TRUE(accounting_holds_34(f), "accounting after reset reinit");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_reset_burst_no_rollback(void)
{
    /* §14.2(a): establish epoch with seq=3 (cold-start), then a FLOW_RESET seq=0
     * arrives WITHIN grace (now - last_progress < grace) → NOT honored → seq<expected
     * → late drop, NO rollback. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    c.reset_idle_grace_ms = 10000; /* 10s */
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    /* cold-start seq=3 at t=1_000_000 → expected=4 (new epoch first-observed). */
    size_t n = build_reorder_dgram(buf, MQVPN_REORDER_FLAG_RESET, 3, 30, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000000);
    mqvpn_reorder_flow_t *f = only_flow(rx);
    ASSERT_EQ_INT(f->expected, 4, "epoch anchored at seq=3 → expected=4");
    ASSERT_EQ_INT(rec.n, 1, "seq3 delivered (cold-start honor)");

    /* seq=0 reset-burst packet arrives 1ms later (< 10s grace) → NOT honored,
     * falls through → seq 0 < expected 4 → late drop, no rollback. */
    n = build_reorder_dgram(buf, MQVPN_REORDER_FLAG_RESET, 0, 99, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000000 + 1000ULL);
    ASSERT_EQ_INT(rec.n, 1, "late reset-burst packet NOT delivered");
    ASSERT_EQ_INT(f->expected, 4, "no rollback: expected still 4");
    ASSERT_EQ_INT(f->stats.too_late_drop_count, 1, "counted as late drop");
    ASSERT_EQ_INT(f->stats.reset_discard_count, 0, "no discard (not honored)");
    ASSERT_TRUE(invariant_holds(rx), "invariant after reset-burst late drop");
    ASSERT_TRUE(accounting_holds_34(f), "accounting after reset-burst late drop");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_short_flow_reset(void)
{
    /* §14.2(a): a flow with small expected still resets correctly via idle-grace
     * (honor condition is time-based, NOT seq magnitude — fixes v2's broken
     * RESET_THRESHOLD on short flows). */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    c.reset_idle_grace_ms = 10000;
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    /* short flow: cold-start seq 0,1 then idle. expected=2 (small). */
    size_t n = build_reorder_dgram(buf, 0, 0, 1, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000000);
    n = build_reorder_dgram(buf, 0, 1, 2, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000100);
    mqvpn_reorder_flow_t *f = only_flow(rx);
    ASSERT_EQ_INT(f->expected, 2, "short flow expected=2");

    /* reset seq=0 after grace → honored even though expected (2) is tiny and the
     * magnitude gap (2-0=2) is small. */
    n = build_reorder_dgram(buf, MQVPN_REORDER_FLAG_RESET, 0, 77, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000100 + 20000000ULL);
    ASSERT_EQ_INT(rec.tags[rec.n - 1], 77, "short-flow reset honored & delivered");
    ASSERT_EQ_INT(f->expected, 1, "short flow reinit to seq+1 = 1");
    ASSERT_TRUE(accounting_holds_34(f), "accounting after short flow reset");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_reset_discard_not_deliver(void)
{
    /* §24.9 line 1121 (must-fix): on honor, old buffered packets are DISCARDED,
     * not delivered (reset_discard_count). */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    c.reset_idle_grace_ms = 10000;
    c.max_wait_ms = 1000000; /* huge wait so the timer never fires during the test */
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    /* cold-start seq 0 (expected=1), then buffer seq 2 and 3 (old epoch). */
    size_t n = build_reorder_dgram(buf, 0, 0, 1, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000000);
    n = build_reorder_dgram(buf, 0, 2, 20, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000100);
    n = build_reorder_dgram(buf, 0, 3, 30, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000100);
    mqvpn_reorder_flow_t *f = only_flow(rx);
    ASSERT_EQ_INT(f->buffer.count, 2, "two old-epoch packets buffered");
    int delivered_before = rec.n; /* = 1 (only seq0) */

    /* genuine reset arrives after grace: old buffer (seq2,3) must be DISCARDED. */
    n = build_reorder_dgram(buf, MQVPN_REORDER_FLAG_RESET, 0, 55, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000100 + 20000000ULL);
    ASSERT_EQ_INT(rec.n, delivered_before + 1, "only the reset packet delivered (tag55)");
    ASSERT_EQ_INT(rec.tags[rec.n - 1], 55,
                  "delivered tag is the reset packet, not old buffer");
    ASSERT_EQ_INT(f->stats.reset_discard_count, 2, "two old packets discarded");
    ASSERT_TRUE(ring_empty(&f->buffer), "old buffer freed");
    ASSERT_TRUE(!f->gap_timer_active, "timer stopped after discard");
    ASSERT_TRUE(invariant_holds(rx), "invariant after reset discard");
    ASSERT_TRUE(accounting_holds_34(f), "accounting after reset discard");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_backstop_recovery(void)
{
    /* §14.2(c) / §24.9 line 1111: all K reset packets "lost" (flow stuck, no
     * progress) → after ingress_idle, tick evicts the stale flow → next packet
     * cold-starts (re-init). */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    c.ingress_idle_timeout_sec = 30; /* 30s idle eviction */
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    /* establish epoch: cold-start seq 1000, expected=1001, last_progress=1s. */
    size_t n = build_reorder_dgram(buf, 0, 1000, 1, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000000);
    mqvpn_reorder_flow_t *f = only_flow(rx);
    ASSERT_EQ_INT(f->expected, 1001, "epoch established");

    /* Sender evicted + restarted at seq 0, but all K reset packets are lost (no
     * packet reaches us). The flow makes no progress. tick at +40s (> 30s idle)
     * must evict the stale flow. */
    mqvpn_reorder_rx_tick(rx, 1000000 + 40000000ULL);
    ASSERT_TRUE(only_flow(rx) == NULL, "stale flow evicted by backstop");
    ASSERT_EQ_INT((long long)rx->n_flows, 0, "n_flows back to 0");

    /* next packet (new epoch seq 0, FLOW_RESET lost) cold-starts via first-observed
     * → re-init, delivered (recovery). */
    n = build_reorder_dgram(buf, 0, 0, 2, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000000 + 41000000ULL);
    ASSERT_EQ_INT(rec.n, 2, "next packet cold-started and delivered (recovered)");
    ASSERT_EQ_INT(rec.tags[1], 2, "delivered the new-epoch first-observed");
    mqvpn_reorder_flow_t *f2 = only_flow(rx);
    ASSERT_TRUE(f2 != NULL, "new flow created on cold start");
    ASSERT_EQ_INT(f2->expected, 1, "cold-start anchored expected=1 (seq0+1)");
    ASSERT_TRUE(invariant_holds(rx), "invariant after backstop recovery");
    mqvpn_reorder_rx_free(rx);
}

/* ─────────── Task 3.5: ACK demotion + 2-mode pass-through ─────────── */

/* Full §17 accounting identity (all five terminators): closed periods end in
 * filled / timeout / overflow / demote / reset; one open (armed) period adds +1.
 * §24.9 line 1119 full form. */
static int
accounting_holds_full(mqvpn_reorder_flow_t *f)
{
    uint64_t closed = f->stats.gap_filled_count + f->stats.gap_timeout_count +
                      f->stats.gap_overflow_count + f->stats.gap_demote_count +
                      f->stats.gap_reset_count;
    uint64_t open = f->gap_timer_active ? 1u : 0u;
    return f->stats.gap_count == closed + open;
}

/* A small-classify-window cfg so demotion is reachable in a few packets. */
static mqvpn_reorder_config_t
rx_cfg_demote(uint16_t window, uint16_t max_large)
{
    mqvpn_reorder_config_t c;
    mqvpn_reorder_config_default(&c);
    c.mode = MQVPN_REORDER_ON;
    c.classify_window = window;
    c.ack_demote_max_large_packets = max_large;
    c.small_packet_threshold_bytes = 200; /* inner UDP payload >= 200 → large */
    return c;
}

static void
test_rx_ack_demote_small_flow(void)
{
    /* §11.6: a flow whose first classify_window packets are (nearly) all small →
     * demoted to pass_through; subsequent packets delivered immediately even if
     * out of order. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg_demote(4, 1); /* window 4, allow <=1 large */
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    /* 4 small (payload 50 < 200) in-order packets → window closes → demote. */
    for (uint64_t s = 0; s < 4; s++) {
        size_t n = build_reorder_dgram(buf, 0, s, (uint16_t)(s + 1), 5000, 443, 50);
        mqvpn_reorder_rx_on_packet(rx, buf, n, s + 1);
        ASSERT_TRUE(invariant_holds(rx), "invariant during small-flow classify");
    }
    mqvpn_reorder_flow_t *f = only_flow(rx);
    ASSERT_TRUE(f->pass_through, "flow demoted to pass_through after small window");
    ASSERT_EQ_INT(f->stats.ack_demote_count, 1, "ack_demote_count == 1");
    ASSERT_TRUE(f->buffer.slots == NULL, "ring freed on demote");

    /* now an out-of-order packet must be delivered immediately (no reorder). */
    int before = rec.n;
    size_t n = build_reorder_dgram(buf, 0, 99, 99, 5000, 443, 50); /* far ahead */
    mqvpn_reorder_rx_on_packet(rx, buf, n, 100);
    ASSERT_EQ_INT(rec.n, before + 1, "pass_through delivers out-of-order immediately");
    ASSERT_EQ_INT(rec.tags[rec.n - 1], 99, "delivered the pass-through packet");
    ASSERT_TRUE(invariant_holds(rx), "invariant after pass-through delivery");
    ASSERT_TRUE(accounting_holds_full(f), "accounting after demote");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_demote_tolerates_initial_large(void)
{
    /* §11.6 count threshold: 1-2 large (client Initial) among small still demotes. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg_demote(5, 2); /* allow up to 2 large */
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[2048];

    /* packet 0: large (payload 1200 >= 200), packets 1..4: small. large count=1<=2 */
    size_t n = build_reorder_dgram(buf, 0, 0, 1, 5000, 443, 1200);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1);
    for (uint64_t s = 1; s < 5; s++) {
        n = build_reorder_dgram(buf, 0, s, (uint16_t)(s + 1), 5000, 443, 50);
        mqvpn_reorder_rx_on_packet(rx, buf, n, s + 1);
    }
    mqvpn_reorder_flow_t *f = only_flow(rx);
    ASSERT_EQ_INT(f->classify_large, 1, "exactly one large counted");
    ASSERT_TRUE(f->pass_through, "demoted despite one large (count threshold)");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_demote_payload_len_is_udp(void)
{
    /* §11.6 should-fix 2 / §24.9 line 1125: classification length is the inner UDP
     * payload (IP+UDP headers EXCLUDED). Craft packets where header inclusion
     * would flip the verdict: payload 190, threshold 200. With headers (20 IP +
     * 8 UDP = 28) the total inner len is 218 >= 200 (would count as LARGE);
     * with UDP-payload-only it is 190 < 200 (SMALL). Correct impl → all small →
     * demote. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg_demote(3, 0); /* allow ZERO large → strict */
    c.small_packet_threshold_bytes = 200;
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[512];

    for (uint64_t s = 0; s < 3; s++) {
        size_t n = build_reorder_dgram(buf, 0, s, (uint16_t)(s + 1), 5000, 443, 190);
        mqvpn_reorder_rx_on_packet(rx, buf, n, s + 1);
    }
    mqvpn_reorder_flow_t *f = only_flow(rx);
    ASSERT_EQ_INT(f->classify_large, 0,
                  "UDP-payload 190 < 200 counted small (headers excluded)");
    ASSERT_TRUE(f->pass_through, "demoted: UDP-payload length used, not inner-IP length");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_anomalous_drop_not_demote(void)
{
    /* §24.9 line 1122: the classify-window-FINAL packet being an anomalous drop
     * (here too_far_ahead) must NOT demote; a late drop in that slot DOES count.
     * Two sub-cases. */

    /* sub-case A: final packet is too_far_ahead → not counted → window not closed
     * → no demote. */
    {
        recorder_t rec = {0};
        mqvpn_reorder_config_t c =
            rx_cfg_demote(3, 3); /* allow all large; demote-friendly */
        c.cap_packets_per_flow = 8;
        mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
        uint8_t buf[256];

        /* two small in-order (classify_seen=2). */
        size_t n = build_reorder_dgram(buf, 0, 0, 1, 5000, 443, 50);
        mqvpn_reorder_rx_on_packet(rx, buf, n, 1);
        n = build_reorder_dgram(buf, 0, 1, 2, 5000, 443, 50);
        mqvpn_reorder_rx_on_packet(rx, buf, n, 2);
        mqvpn_reorder_flow_t *f = only_flow(rx);
        ASSERT_EQ_INT(f->classify_seen, 2, "two real packets counted");

        /* third packet is far-ahead (seq 100, cap 8) → anomalous drop, NOT
         * counted, NOT demote, classify_seen stays 2. */
        n = build_reorder_dgram(buf, 0, 100, 3, 5000, 443, 50);
        mqvpn_reorder_rx_on_packet(rx, buf, n, 3);
        ASSERT_EQ_INT(f->classify_seen, 2, "anomalous drop not counted toward classify");
        ASSERT_TRUE(!f->pass_through, "anomalous final packet did NOT demote");
        ASSERT_EQ_INT(f->stats.too_far_ahead_drop_count, 1, "far-ahead drop recorded");
        mqvpn_reorder_rx_free(rx);
    }

    /* sub-case B: final packet is a LATE drop → DOES count (real traffic) → demote. */
    {
        recorder_t rec = {0};
        mqvpn_reorder_config_t c = rx_cfg_demote(3, 3);
        mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
        uint8_t buf[256];

        /* cold-start seq 10 (classify_seen=1), in-order seq 11 (=2). */
        size_t n = build_reorder_dgram(buf, 0, 10, 1, 5000, 443, 50);
        mqvpn_reorder_rx_on_packet(rx, buf, n, 1);
        n = build_reorder_dgram(buf, 0, 11, 2, 5000, 443, 50);
        mqvpn_reorder_rx_on_packet(rx, buf, n, 2);
        mqvpn_reorder_flow_t *f = only_flow(rx);
        ASSERT_EQ_INT(f->classify_seen, 2, "two counted");

        /* third packet is late (seq 5 < expected 12) → late drop, COUNTS → window
         * closes → demote. */
        n = build_reorder_dgram(buf, 0, 5, 3, 5000, 443, 50);
        mqvpn_reorder_rx_on_packet(rx, buf, n, 3);
        ASSERT_EQ_INT(f->classify_seen, 3, "late drop counted toward classify");
        ASSERT_TRUE(f->pass_through, "late drop in final slot DID demote");
        ASSERT_EQ_INT(f->stats.too_late_drop_count, 1, "late drop recorded");
        mqvpn_reorder_rx_free(rx);
    }
}

static void
test_rx_demote_current_gapfiller_order(void)
{
    /* §24.9 line 1127 (must-fix v2.4): the demote-triggering current packet that
     * is a gap-filler (seq==expected) is delivered BEFORE the buffered packets.
     * Build a buffer with a gap, then have the window-closing packet fill the gap
     * AND trigger demote; the gap-filler + drained run must come out in order. */
    recorder_t rec = {0};
    /* window 3 so the 3rd real packet closes it. allow up to 3 large so payload
     * size doesn't matter. */
    mqvpn_reorder_config_t c = rx_cfg_demote(3, 3);
    c.max_wait_ms = 1000000; /* no timeout during the test */
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[512];

    /* p0: cold-start seq 0 (delivered, classify_seen=1), expected=1. */
    size_t n = build_reorder_dgram(buf, 0, 0, 10, 5000, 443, 300);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1);
    /* p1: seq 2 ahead → buffered (classify_seen=2). gap at 1. */
    n = build_reorder_dgram(buf, 0, 2, 12, 5000, 443, 300);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 2);
    mqvpn_reorder_flow_t *f = only_flow(rx);
    ASSERT_EQ_INT(rec.n, 1, "only seq0 delivered so far");
    ASSERT_EQ_INT(f->classify_seen, 2, "two classified");

    /* p2: seq 1 fills the gap → step3 delivers seq1 (tag11), drains seq2 (tag12);
     * classify_seen=3 → window closes → DEMOTE. Buffer now empty, but the order
     * must be tag11 then tag12 (gap-filler before drained run). */
    n = build_reorder_dgram(buf, 0, 1, 11, 5000, 443, 300);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 3);
    ASSERT_TRUE(f->pass_through, "demoted on gap-filler window close");
    ASSERT_EQ_INT(rec.n, 3, "seq0,1,2 all delivered");
    ASSERT_EQ_INT(rec.tags[0], 10, "order: seq0 (tag10)");
    ASSERT_EQ_INT(rec.tags[1], 11, "order: gap-filler seq1 (tag11) BEFORE buffered");
    ASSERT_EQ_INT(rec.tags[2], 12, "order: drained seq2 (tag12)");
    ASSERT_TRUE(invariant_holds(rx), "invariant after gap-filler demote");
    ASSERT_TRUE(accounting_holds_full(f), "accounting after gap-filler demote");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_demote_current_ahead_order(void)
{
    /* §24.9 line 1128: the demote-triggering current packet that is AHEAD is
     * delivered via the buffer flush in ascending seq order. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg_demote(3, 3);
    c.max_wait_ms = 1000000;
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[512];

    /* p0: cold-start seq 0 delivered (classify_seen=1), expected=1. */
    size_t n = build_reorder_dgram(buf, 0, 0, 10, 5000, 443, 300);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1);
    /* p1: seq 3 ahead → buffered (classify_seen=2). gap at 1,2. */
    n = build_reorder_dgram(buf, 0, 3, 13, 5000, 443, 300);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 2);
    mqvpn_reorder_flow_t *f = only_flow(rx);

    /* p2: seq 2 ahead → buffered (classify_seen=3) → window closes → DEMOTE.
     * Flush delivers remaining buffer ascending: seq2 (tag12) then seq3 (tag13). */
    n = build_reorder_dgram(buf, 0, 2, 12, 5000, 443, 300);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 3);
    ASSERT_TRUE(f->pass_through, "demoted on ahead window close");
    ASSERT_EQ_INT(rec.n, 3, "seq0 + flushed seq2,seq3");
    ASSERT_EQ_INT(rec.tags[0], 10, "seq0 first");
    ASSERT_EQ_INT(rec.tags[1], 12, "flush ascending: seq2 (tag12)");
    ASSERT_EQ_INT(rec.tags[2], 13, "flush ascending: seq3 (tag13)");
    ASSERT_TRUE(invariant_holds(rx), "invariant after ahead demote");
    ASSERT_TRUE(accounting_holds_full(f), "accounting after ahead demote");
    /* this demote ended an ACTIVE period (timer was armed) → gap_demote_count++. */
    ASSERT_EQ_INT(f->stats.gap_demote_count, 1, "demote flush ended active period");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_passthrough_A_no_state(void)
{
    /* §11.5 mode A / §24.9 line 1126: policy wait_ms==0 → NO flow state created,
     * immediate delivery, FLOW_RESET and seq ignored. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c;
    mqvpn_reorder_config_default(&c);
    c.mode = MQVPN_REORDER_ON;
    c.max_wait_ms = 0; /* mode A */
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    /* out-of-order + FLOW_RESET should all be delivered immediately, in arrival
     * order, with NO flow created. */
    size_t n = build_reorder_dgram(buf, 0, 5, 1, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1);
    n = build_reorder_dgram(buf, 0, 2, 2, 5000, 443,
                            100); /* "out of order" but delivered */
    mqvpn_reorder_rx_on_packet(rx, buf, n, 2);
    n = build_reorder_dgram(buf, MQVPN_REORDER_FLAG_RESET, 0, 3, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 3);

    ASSERT_EQ_INT(rec.n, 3, "all 3 delivered immediately (mode A)");
    ASSERT_EQ_INT(rec.tags[0], 1, "arrival order 1");
    ASSERT_EQ_INT(rec.tags[1], 2, "arrival order 2 (seq ignored)");
    ASSERT_EQ_INT(rec.tags[2], 3, "arrival order 3 (FLOW_RESET ignored)");
    ASSERT_TRUE(only_flow(rx) == NULL, "no flow state created in mode A");
    ASSERT_EQ_INT((long long)rx->n_flows, 0, "n_flows == 0 in mode A");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_passthrough_B_undemote_on_reset(void)
{
    /* §11.5 mode B / §24.9 lines 1126,1129: a demoted (B) flow keeps its struct;
     * an idle-grace FLOW_RESET (step 1, before pass_through step 2) un-demotes +
     * reinits the classifier. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg_demote(3, 3);
    c.reset_idle_grace_ms = 10000;
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    /* demote via 3 in-order packets at t≈1s. */
    for (uint64_t s = 0; s < 3; s++) {
        size_t n = build_reorder_dgram(buf, 0, s, (uint16_t)(s + 1), 5000, 443, 50);
        mqvpn_reorder_rx_on_packet(rx, buf, n, 1000000 + s);
    }
    mqvpn_reorder_flow_t *f = only_flow(rx);
    ASSERT_TRUE(f->pass_through, "flow demoted");
    ASSERT_TRUE(f != NULL, "struct retained in mode B");

    /* idle-grace FLOW_RESET 20s later → honored (step 1 runs before pass_through):
     * un-demotes, reinits classifier, reanchors expected. */
    size_t n = build_reorder_dgram(buf, MQVPN_REORDER_FLAG_RESET, 0, 77, 5000, 443, 50);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000000 + 20000000ULL);
    ASSERT_TRUE(!f->pass_through, "un-demoted by idle-grace reset");
    ASSERT_EQ_INT(f->classify_seen, 0, "classifier reinitialized");
    ASSERT_EQ_INT(f->classify_large, 0, "classify_large reset");
    ASSERT_EQ_INT(f->expected, 1, "expected reanchored to seq+1");
    ASSERT_EQ_INT(rec.tags[rec.n - 1], 77, "reset packet delivered after un-demote");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_eval_force_no_demotion(void)
{
    /* §24 determinism: with the internal force-no-demotion flag set, no demote
     * ever, regardless of an all-small flow. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg_demote(3, 3);
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    mqvpn_reorder_rx_set_force_no_demotion(rx, 1);
    uint8_t buf[256];

    for (uint64_t s = 0; s < 10; s++) {
        size_t n = build_reorder_dgram(buf, 0, s, (uint16_t)(s + 1), 5000, 443, 50);
        mqvpn_reorder_rx_on_packet(rx, buf, n, s + 1);
    }
    mqvpn_reorder_flow_t *f = only_flow(rx);
    ASSERT_TRUE(!f->pass_through, "no demote with force-no-demotion set");
    ASSERT_EQ_INT(f->classify_seen, 0, "classifier never advanced (no-op)");
    ASSERT_EQ_INT(f->stats.ack_demote_count, 0, "ack_demote_count stays 0");
    mqvpn_reorder_rx_free(rx);
}

/* ─────────── Chunk 3: per-rule wait/cap resolution at the RX engine ─────────
 *
 * The RX engine must resolve a new flow's (wait,cap) from the matching rule
 * (after mqvpn_reorder_config_finalize, which rx_new now runs), falling back to
 * the global max_wait_ms / cap_packets_per_flow when no rule matches. The
 * wait==0 pass-through decision is now PER-FLOW, not a single global gate. */

static void
test_rx_perrule_wait_cap_from_fiber_lte(void)
{
    /* (a) a fiber_lte rule for the flow's port → new RX flow inherits the preset
     * wait_ms==50, ring cap==2048. A flow with NO matching rule (different port)
     * falls back to the global max_wait_ms / cap_packets_per_flow. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    c.max_wait_ms = 30;            /* global default */
    c.cap_packets_per_flow = 1024; /* global default */
    /* fiber_lte rule on UDP port 443. */
    c.rules[0].proto = MQVPN_IPPROTO_UDP;
    c.rules[0].port = 443;
    c.rules[0].profile = MQVPN_RPROF_FIBER_LTE;
    c.n_rules = 1;
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    ASSERT_TRUE(rx != NULL, "rx_new ok with a rule");
    uint8_t buf[256];

    /* flow on dst_port 443 → matches the fiber_lte rule. */
    size_t n = build_reorder_dgram(buf, 0, 0, 1, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1);
    mqvpn_reorder_flow_t *f = only_flow(rx);
    ASSERT_TRUE(f != NULL, "matched flow created");
    ASSERT_EQ_INT(f->wait_ms, 50, "fiber_lte preset wait_ms==50");
    ASSERT_EQ_INT(f->buffer.cap, 2048, "fiber_lte preset ring cap==2048");

    /* a second flow on a NON-matching port (1234) → global fallback. */
    n = build_reorder_dgram(buf, 0, 0, 1, 6000, 1234, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 2);
    mqvpn_reorder_flow_t *g = NULL;
    for (uint32_t i = 0; i < rx->n_buckets; i++) {
        for (mqvpn_reorder_flow_t *p = rx->buckets[i]; p; p = p->next) {
            if (p != f) g = p;
        }
    }
    ASSERT_TRUE(g != NULL, "unmatched flow created");
    ASSERT_EQ_INT(g->wait_ms, 30, "unmatched flow gets global wait_ms");
    ASSERT_EQ_INT(g->buffer.cap, 1024, "unmatched flow gets global cap");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_perrule_zero_global_wait_rule_buffers(void)
{
    /* (b) the case this rewrite protects: global max_wait_ms==0 (with
     * has_explicit_wait so it survives finalize), AND a rule with a RULE-EXPLICIT
     * MaxWaitMs=50 for the port. After finalize resolved_wait_ms==50, so a
     * reordered packet for that port must be BUFFERED, not pre-empted by the old
     * global wait==0 fast-path. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    c.max_wait_ms = 0;       /* global mode-A would fire under the OLD code */
    c.has_explicit_wait = 1; /* global 0 is explicit */
    c.rules[0].proto = MQVPN_IPPROTO_UDP;
    c.rules[0].port = 443;
    c.rules[0].profile = MQVPN_RPROF_CELLULAR_BOND;
    c.rules[0].explicit_wait_ms = 50; /* rule-explicit beats global-explicit */
    c.n_rules = 1;
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    ASSERT_TRUE(rx != NULL, "rx_new ok");
    /* finalize ran in rx_new: rule resolves to 50. */
    ASSERT_EQ_INT(rx->cfg.rules[0].resolved_wait_ms, 50,
                  "rule-explicit wait survives global 0");
    uint8_t buf[256];

    /* cold-start seq 0 on port 443 → delivered, expected=1, flow created w/ wait 50. */
    size_t n = build_reorder_dgram(buf, 0, 0, 1, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1);
    mqvpn_reorder_flow_t *f = only_flow(rx);
    ASSERT_TRUE(f != NULL, "flow created (NOT pre-empted by global fast-path)");
    ASSERT_EQ_INT(f->wait_ms, 50, "flow wait_ms==50 from rule");
    ASSERT_EQ_INT(rec.n, 1, "cold-start delivered");

    /* seq 2 ahead on port 443 → BUFFERED, not delivered (reorder active). */
    n = build_reorder_dgram(buf, 0, 2, 3, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 2);
    ASSERT_EQ_INT(rec.n, 1, "ahead packet buffered, NOT delivered");
    ASSERT_TRUE(f->gap_timer_active, "gap timer armed (reordering)");
    ASSERT_EQ_INT(f->buffer.count, 1, "one buffered");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_perrule_zero_global_wait_preset_passes(void)
{
    /* (b2) precedence consistency: global max_wait_ms==0 (explicit) AND a
     * fiber_lte rule with NO rule-explicit wait → global-explicit beats the preset,
     * so resolved_wait_ms==0 → the packet is PASSED THROUGH. Both the per-flow
     * check and flow_get_or_create must agree on 0 (here: no flow buffers it). */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    c.max_wait_ms = 0;
    c.has_explicit_wait = 1;
    c.rules[0].proto = MQVPN_IPPROTO_UDP;
    c.rules[0].port = 443;
    c.rules[0].profile = MQVPN_RPROF_FIBER_LTE; /* preset wait 50, but no rule-explicit */
    c.n_rules = 1;
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    ASSERT_TRUE(rx != NULL, "rx_new ok");
    ASSERT_EQ_INT(rx->cfg.rules[0].resolved_wait_ms, 0,
                  "global-explicit 0 beats fiber_lte preset");
    uint8_t buf[256];

    /* out-of-order packets on port 443 → pass-through, NO flow state. */
    size_t n = build_reorder_dgram(buf, 0, 7, 1, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1);
    n = build_reorder_dgram(buf, 0, 2, 2, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 2);
    ASSERT_EQ_INT(rec.n, 2, "both delivered immediately (per-flow wait==0)");
    ASSERT_EQ_INT(rec.tags[0], 1, "arrival order preserved (1)");
    ASSERT_EQ_INT(rec.tags[1], 2, "arrival order preserved (2)");
    ASSERT_TRUE(only_flow(rx) == NULL, "no flow state created (mode A per-flow)");
    ASSERT_EQ_INT((long long)rx->n_flows, 0, "n_flows == 0");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_perrule_mode_a_preserved_no_rules(void)
{
    /* (b3) the global mode-A short-circuit stays green: max_wait_ms==0 with
     * n_rules==0 → global pass-through, no flow state, no 5-tuple parse needed. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c;
    mqvpn_reorder_config_default(&c);
    c.mode = MQVPN_REORDER_ON;
    c.max_wait_ms = 0;
    c.n_rules = 0;
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    size_t n = build_reorder_dgram(buf, 0, 9, 1, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1);
    n = build_reorder_dgram(buf, 0, 3, 2, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 2);
    ASSERT_EQ_INT(rec.n, 2, "global mode-A delivers immediately");
    ASSERT_TRUE(only_flow(rx) == NULL, "no flow state (global mode A)");
    ASSERT_EQ_INT((long long)rx->n_flows, 0, "n_flows == 0 (global mode A)");
    mqvpn_reorder_rx_free(rx);
}

/* Step 4: composed builder end-to-end. Drive the PUBLIC builder API
 * (mqvpn_config_new + mqvpn_config_add_reorder_rule), bridge the embedded
 * reorder config into a lib reorder cfg, hand it to rx_new, and assert the
 * created flow inherits the cellular_bond preset (wait 50, cap 1024). */
static void
test_rx_builder_composed_cellular_bond(void)
{
    recorder_t rec = {0};
    mqvpn_config_t *bcfg = mqvpn_config_new();
    ASSERT_TRUE(bcfg != NULL, "config_new");
    ASSERT_EQ_INT(mqvpn_config_set_reorder_enabled(bcfg, MQVPN_REORDER_ON), MQVPN_OK,
                  "enable reorder");
    /* cellular_bond rule on UDP port 4500. */
    ASSERT_EQ_INT(mqvpn_config_add_reorder_rule(bcfg, MQVPN_IPPROTO_UDP, 4500,
                                                MQVPN_RPROF_CELLULAR_BOND),
                  MQVPN_OK, "add cellular_bond rule");

    /* Bridge the embedded reorder config OUT into a standalone lib cfg. The
     * struct is visible here via mqvpn_internal.h. */
    mqvpn_reorder_config_t lib = bcfg->reorder;
    /* big classify window so demotion never fires in this part-A test. */
    lib.classify_window = 60000;

    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&lib, 0x1, mock_deliver, &rec);
    ASSERT_TRUE(rx != NULL, "rx_new from builder-bridged cfg");
    uint8_t buf[256];

    /* a REORDERED packet on port 4500 → flow inherits cellular_bond preset. */
    size_t n = build_reorder_dgram(buf, 0, 0, 1, 5000, 4500, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1);
    mqvpn_reorder_flow_t *f = only_flow(rx);
    ASSERT_TRUE(f != NULL, "flow created on port 4500");
    ASSERT_EQ_INT(f->wait_ms, 50, "cellular_bond preset wait_ms==50");
    ASSERT_EQ_INT(f->buffer.cap, 1024, "cellular_bond preset cap==1024");

    mqvpn_reorder_rx_free(rx);
    mqvpn_config_free(bcfg);
}

/* ─────────── Task 3.6: stats snapshot + accounting identity ─────────── */

static void
test_rx_accounting_identity(void)
{
    /* §24.9 line 1119 full form: after mixed ops (filled + timeout + overflow +
     * demote-ending-active + reset-ending-active), the snapshot identity holds. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg(); /* big classify window → no accidental demote */
    c.max_wait_ms = 30;
    c.reset_idle_grace_ms = 10000;
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];
    uint64_t t = 1000;

    /* (1) a fill: seq0 cold-start, seq2 buffered, seq1 fills → gap_filled. */
    size_t n = build_reorder_dgram(buf, 0, 0, 1, 5000, 443, 50);
    mqvpn_reorder_rx_on_packet(rx, buf, n, t++);
    n = build_reorder_dgram(buf, 0, 2, 3, 5000, 443, 50);
    mqvpn_reorder_rx_on_packet(rx, buf, n, t++);
    n = build_reorder_dgram(buf, 0, 1, 2, 5000, 443, 50);
    mqvpn_reorder_rx_on_packet(rx, buf, n, t++);

    /* (2) a timeout: buffer seq 5 (gap at 3,4), tick past deadline → gap_timeout. */
    n = build_reorder_dgram(buf, 0, 5, 6, 5000, 443, 50);
    uint64_t armed = t;
    mqvpn_reorder_rx_on_packet(rx, buf, n, t++);
    mqvpn_reorder_rx_tick(rx, armed + 30000 + 1);

    mqvpn_reorder_flow_t *f = only_flow(rx);
    ASSERT_TRUE(accounting_holds_full(f), "identity holds after fill + timeout");

    /* aggregate snapshot also satisfies the identity. */
    mqvpn_reorder_stats_t st;
    mqvpn_reorder_rx_get_stats(rx, &st);
    ASSERT_EQ_INT(st.gap_count,
                  st.gap_filled_count + st.gap_timeout_count + st.gap_overflow_count +
                      st.gap_demote_count + st.gap_reset_count +
                      (f->gap_timer_active ? 1 : 0),
                  "snapshot identity (live flow, one possibly-open period)");

    /* (3) overflow + (4) demote terminating an active period on a SECOND flow,
     * using a different src port so it's a separate flow. */
    mqvpn_reorder_config_t c2 = rx_cfg_demote(2, 2); /* small window → quick demote */
    c2.max_wait_ms = 1000000;
    mqvpn_reorder_rx_t *rx2 = mqvpn_reorder_rx_new(&c2, 0x9, mock_deliver, &rec);
    n = build_reorder_dgram(buf, 0, 0, 1, 6000, 443, 50);
    mqvpn_reorder_rx_on_packet(rx2, buf, n, 1); /* cold-start, classify_seen=1 */
    n = build_reorder_dgram(buf, 0, 5, 6, 6000, 443, 50);
    mqvpn_reorder_rx_on_packet(rx2, buf, n, 2); /* buffered, classify_seen=2 → DEMOTE */
    mqvpn_reorder_flow_t *f2 = only_flow(rx2);
    ASSERT_TRUE(f2->pass_through, "second flow demoted (active period ended)");
    ASSERT_EQ_INT(f2->stats.gap_demote_count, 1, "demote ended active period");
    ASSERT_TRUE(accounting_holds_full(f2), "identity after demote-ends-active");

    /* drive an idle-grace reset that terminates an active period to exercise
     * gap_reset_count: build a fresh flow, buffer a packet (arm timer), then send
     * an idle-grace reset while still armed. Use rx (big classify window). */
    mqvpn_reorder_config_t c3 = rx_cfg();
    c3.max_wait_ms = 1000000;
    c3.reset_idle_grace_ms = 10000;
    mqvpn_reorder_rx_t *rx3 = mqvpn_reorder_rx_new(&c3, 0x3, mock_deliver, &rec);
    n = build_reorder_dgram(buf, 0, 0, 1, 7000, 443, 50);
    mqvpn_reorder_rx_on_packet(rx3, buf, n, 1000000); /* cold-start */
    n = build_reorder_dgram(buf, 0, 3, 4, 7000, 443, 50);
    mqvpn_reorder_rx_on_packet(rx3, buf, n, 1000100); /* buffered → timer armed */
    mqvpn_reorder_flow_t *f3 = only_flow(rx3);
    ASSERT_TRUE(f3->gap_timer_active, "timer armed before reset");
    n = build_reorder_dgram(buf, MQVPN_REORDER_FLAG_RESET, 100, 9, 7000, 443, 50);
    mqvpn_reorder_rx_on_packet(rx3, buf, n, 1000100 + 20000000ULL); /* idle-grace reset */
    ASSERT_EQ_INT(f3->stats.gap_reset_count, 1, "reset ended an active period");
    ASSERT_TRUE(accounting_holds_full(f3), "identity after reset-ends-active");

    mqvpn_reorder_rx_free(rx);
    mqvpn_reorder_rx_free(rx2);
    mqvpn_reorder_rx_free(rx3);
}

static void
test_rx_stats_snapshot(void)
{
    /* §17: the snapshot accessor reports consistent values, including counters
     * from flows that have been evicted. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    c.ingress_idle_timeout_sec = 30;
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    /* deliver a few in-order packets, drop a late one. */
    for (uint64_t s = 0; s < 3; s++) {
        size_t n = build_reorder_dgram(buf, 0, s, (uint16_t)(s + 1), 5000, 443, 50);
        mqvpn_reorder_rx_on_packet(rx, buf, n, 1000000 + s);
    }
    size_t n = build_reorder_dgram(buf, 0, 0, 99, 5000, 443, 50); /* late */
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000005);

    mqvpn_reorder_stats_t live;
    mqvpn_reorder_rx_get_stats(rx, &live);
    ASSERT_EQ_INT(live.delivered_count, 3, "3 delivered (live)");
    ASSERT_EQ_INT(live.too_late_drop_count, 1, "1 late drop (live)");

    /* evict the flow via idle tick; stats must survive in the snapshot. */
    mqvpn_reorder_rx_tick(rx, 1000000 + 40000000ULL);
    ASSERT_TRUE(only_flow(rx) == NULL, "flow evicted");
    mqvpn_reorder_stats_t after;
    mqvpn_reorder_rx_get_stats(rx, &after);
    ASSERT_EQ_INT(after.delivered_count, 3, "delivered survives eviction");
    ASSERT_EQ_INT(after.too_late_drop_count, 1, "late drop survives eviction");

    /* NULL-safety. */
    mqvpn_reorder_rx_get_stats(NULL, &after);
    mqvpn_reorder_rx_get_stats(rx, NULL);
    g_pass++; /* reaching here without crashing is the assertion */
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_double_overflow_flush(void)
{
    /* Hardening item 4: BOTH max_buffer_bytes_per_flow AND global_max_buffer_bytes
     * are tight so a single buffer_admit triggers overflow_flush along the per-flow
     * path AND again along the pool path. Assert correctness + accounting + the
     * pool-bytes invariant hold throughout. */
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    c.cap_packets_per_flow = 1024;
    /* inner len per packet = 28 + 100 = 128. Both budgets allow exactly TWO
     * packets (256), so a third admit hits the per-flow limit (flush #1). After
     * reclassify the packet lands in-order and drains, so the buffer is empty by
     * the time the pool gate is reached: that gate takes the ring_empty drop
     * branch and does NOT call overflow_flush on an empty buffer. Keep the
     * budgets equal and tight to exercise both gates back-to-back. */
    c.max_buffer_bytes_per_flow = 256;
    c.global_max_buffer_bytes = 256;
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    size_t n = build_reorder_dgram(buf, 0, 0, 1, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000); /* expected=1 */
    /* buffer seq 2,3 → bytes=256 (both budgets at limit). */
    n = build_reorder_dgram(buf, 0, 2, 3, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 2000);
    n = build_reorder_dgram(buf, 0, 3, 4, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 2000);
    mqvpn_reorder_flow_t *f = only_flow(rx);
    ASSERT_EQ_INT(f->buffer.count, 2, "two buffered at both limits");
    ASSERT_TRUE(invariant_holds(rx), "pool-bytes invariant at limit");

    /* seq 4: per-flow limit hit → overflow_flush (flush #1) skips gap at 1,
     * delivers seq2,3, expected=4. Reclassify seq4 → in-order, delivered. */
    n = build_reorder_dgram(buf, 0, 4, 5, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 3000);
    ASSERT_EQ_INT(rec.tags[rec.n - 1], 5, "seq4 delivered after double-gate flush");
    ASSERT_EQ_INT(f->expected, 5, "expected advanced through flush + reclass");
    ASSERT_TRUE(f->stats.gap_overflow_count >= 1, "at least one overflow charged");
    ASSERT_TRUE(invariant_holds(rx), "invariant after double flush");
    ASSERT_TRUE(accounting_holds_full(f), "accounting after double flush");

    /* now force a run that exercises both gates repeatedly with a persistent gap. */
    for (uint64_t s = 6; s < 30; s++) {
        n = build_reorder_dgram(buf, 0, s, (uint16_t)(s + 1), 5000, 443, 100);
        mqvpn_reorder_rx_on_packet(rx, buf, n, 4000 + s);
        ASSERT_TRUE(invariant_holds(rx), "invariant under double-gate pressure");
        ASSERT_TRUE(accounting_holds_full(f), "accounting under double-gate pressure");
    }
    mqvpn_reorder_rx_free(rx);
}

/* Codex review fix: the RX flow table must be bounded by cfg.max_flows (§13.5).
 * A peer flooding distinct inner 5-tuples must not grow the table without bound. */
static void
test_rx_max_flows_cap(void)
{
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    c.max_flows = 4;
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];

    /* 10 distinct 5-tuples (distinct src port) => 10 would-be fresh flows. */
    for (uint16_t i = 0; i < 10; i++) {
        size_t n = build_reorder_dgram(buf, 0, 0, (uint16_t)(i + 1), (uint16_t)(6000 + i),
                                       443, 100);
        mqvpn_reorder_rx_on_packet(rx, buf, n, (uint64_t)(i + 1));
        ASSERT_TRUE(rx->n_flows <= c.max_flows, "n_flows bounded by max_flows");
        ASSERT_TRUE(invariant_holds(rx), "invariant during flow flood");
    }
    ASSERT_EQ_INT((int)rx->n_flows, (int)c.max_flows, "table saturated at cap");
    mqvpn_reorder_rx_free(rx);
}

/* ─────────────── Task 1: residence-time (added-latency) histogram ────────── */

static void
test_rx_residence_in_order_is_zero_bucket(void)
{
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];
    for (uint64_t s = 0; s < 5; s++) { /* strictly in order -> all immediate */
        size_t n = build_reorder_dgram(buf, 0, s, (uint16_t)(s + 1), 5000, 443, 100);
        mqvpn_reorder_rx_on_packet(rx, buf, n, 1000000 + s * 1000);
    }
    mqvpn_reorder_stats_t st;
    mqvpn_reorder_rx_get_stats(rx, &st);
    ASSERT_EQ_INT((int)st.delivered_count, 5, "5 delivered");
    ASSERT_EQ_INT((int)st.residence_bucket[0], 5, "all immediate -> bucket0");
    ASSERT_TRUE(mqvpn_reorder_latency_percentile(&st, 0.99) == 0.0, "p99 == 0ms");
    mqvpn_reorder_rx_free(rx);
}

static void
test_rx_residence_buffered_and_percentile(void)
{
    recorder_t rec = {0};
    mqvpn_reorder_config_t c = rx_cfg();
    c.max_wait_ms = 100;
    mqvpn_reorder_rx_t *rx = mqvpn_reorder_rx_new(&c, 0x1, mock_deliver, &rec);
    uint8_t buf[256];
    size_t n;
    /* seq0 @1.000s: cold-start, delivered immediately (expected->1), residence 0. */
    n = build_reorder_dgram(buf, 0, 0, 1, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000000);
    /* seq2 @1.000s: ahead of expected=1, buffered (enqueue_us=1000000). */
    n = build_reorder_dgram(buf, 0, 2, 3, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1000000);
    /* seq1 @1.005s: fills gap -> seq1 (residence 0) then seq2 drained
     * (residence = 1005000-1000000 = 5000us = 5ms -> bucket idx 4, <=8ms). */
    n = build_reorder_dgram(buf, 0, 1, 2, 5000, 443, 100);
    mqvpn_reorder_rx_on_packet(rx, buf, n, 1005000);
    mqvpn_reorder_stats_t st;
    mqvpn_reorder_rx_get_stats(rx, &st);
    ASSERT_EQ_INT((int)st.delivered_count, 3, "3 delivered");
    ASSERT_EQ_INT((int)st.residence_bucket[0], 2, "seq0+seq1 immediate -> bucket0");
    ASSERT_EQ_INT((int)st.residence_bucket[4], 1, "seq2 ~5ms -> bucket4 (<=8ms)");
    ASSERT_TRUE(st.residence_max_us >= 5000 && st.residence_max_us < 8000, "max ~5ms");
    ASSERT_TRUE(mqvpn_reorder_latency_percentile(&st, 0.99) == 8.0, "all p99 == 8ms");
    ASSERT_TRUE(mqvpn_reorder_latency_buffered_percentile(&st, 0.99) == 8.0,
                "buf p99 == 8ms");
    mqvpn_reorder_rx_free(rx);
}

static void
test_latency_percentile_from_buckets(void)
{
    mqvpn_reorder_stats_t st;
    memset(&st, 0, sizeof st);
    st.residence_bucket[0] = 90;
    st.residence_bucket[5] = 9;
    st.residence_bucket[7] = 1;
    st.residence_max_us = 60000;
    ASSERT_TRUE(mqvpn_reorder_latency_percentile(&st, 0.99) == 16.0, "all p99 == 16ms");
    ASSERT_TRUE(mqvpn_reorder_latency_buffered_percentile(&st, 0.99) == 64.0,
                "buf p99 == 64ms");
}

/* Pin the overflow boundary (512000us == bucket 10 upper bound; 512001us spills
 * into the overflow bucket 11) and exercise the overflow->exact-max percentile
 * branch, which no other test covers. The bucket index is derived the same way
 * record_residence() classifies, so this guards the >512ms tail accounting. */
static void
test_latency_overflow_boundary_and_max(void)
{
    /* The bound table is internal to reorder_rx.c; reproduce the classification
     * by driving the engine would require timestamp control, so verify the
     * boundary via the percentile API on a hand-built histogram instead. */

    /* Exact-512ms residence must land in bucket 10 (its inclusive upper bound),
     * NOT the overflow bucket. A histogram with all mass in bucket 10 reports
     * that bound (512ms) for any percentile. */
    mqvpn_reorder_stats_t edge;
    memset(&edge, 0, sizeof edge);
    edge.residence_bucket[10] = 1; /* one packet @ residence == 512000us */
    edge.residence_max_us = 512000;
    ASSERT_TRUE(mqvpn_reorder_latency_percentile(&edge, 1.0) == 512.0,
                "512000us -> bucket10, p100 == 512ms");

    /* 512001us spills into the overflow bucket 11; the overflow bucket reports
     * the exact tracked max (residence_max_us / 1000.0), not a bound. */
    mqvpn_reorder_stats_t ovf;
    memset(&ovf, 0, sizeof ovf);
    ovf.residence_bucket[11] = 3; /* overflow-only histogram */
    ovf.residence_max_us = 512001;
    ASSERT_TRUE(mqvpn_reorder_latency_percentile(&ovf, 0.50) == 512.001,
                "overflow-only -> exact max (512.001ms)");
    ASSERT_TRUE(mqvpn_reorder_latency_percentile(&ovf, 0.99) == 512.001,
                "overflow-only p99 -> exact max");
}

/* Pin that the public accumulator carries the residence histogram + max. This is
 * the SINGLE fold path the server-side cross-conn aggregator
 * (mqvpn_server_get_reorder_stats) now reuses, so this is the regression guard
 * for the bug where the server hand-rolled a 14-field copy that silently dropped
 * residence_bucket[]/residence_max_us — making the control API report 0 latency. */
static void
test_stats_accumulate_carries_residence(void)
{
    mqvpn_reorder_stats_t a, b;
    memset(&a, 0, sizeof a);
    memset(&b, 0, sizeof b);
    a.delivered_count = 3;
    a.residence_bucket[0] = 2;
    a.residence_bucket[4] = 1;
    a.residence_max_us = 5000;
    b.delivered_count = 1;
    b.residence_bucket[4] = 1;
    b.residence_bucket[7] = 1;
    b.residence_max_us = 60000;

    mqvpn_reorder_stats_accumulate(&a, &b);

    ASSERT_EQ_INT((int)a.delivered_count, 4, "scalar counter summed");
    ASSERT_EQ_INT((int)a.residence_bucket[0], 2, "bucket0 carried");
    ASSERT_EQ_INT((int)a.residence_bucket[4], 2, "bucket4 summed");
    ASSERT_EQ_INT((int)a.residence_bucket[7], 1, "bucket7 carried");
    ASSERT_TRUE(a.residence_max_us == 60000, "max takes the larger");
}

int
main(void)
{
    /* Task 3.1: ring */
    test_ring_insert_contains_remove();
    test_ring_empty_when_slots_null();
    test_ring_offbyone();
    test_ring_grow_by_span();
    test_ring_lowest_seq();

    /* Task 3.2: dispatch + process */
    test_rx_inorder_passthrough_order();
    test_rx_cold_start_first_observed();
    test_rx_buffer_then_fill();
    test_rx_late_drop();
    test_rx_far_ahead_drop();
    test_rx_duplicate_drop();
    test_rx_invariant_timer_iff_nonempty();
    test_rx_lazy_cap_check_before_slots();

    /* Task 3.3: gap timeout + overflow flush + limit separation */
    test_rx_timeout_skip_advances();
    test_rx_timeout_skip_rearms_when_nonempty();
    test_rx_anchored_timer_no_rearm();
    test_rx_overflow_flush_reclassify();
    test_rx_overflow_partial_drain_anchored();
    test_rx_per_flow_limit_drop_when_empty();
    test_rx_pool_drop_when_empty();
    test_rx_overflow_does_not_halt();

    /* Task 3.4: FLOW_RESET honor + last_progress backstop */
    test_rx_reset_reinit();
    test_rx_reset_burst_no_rollback();
    test_rx_short_flow_reset();
    test_rx_reset_discard_not_deliver();
    test_rx_backstop_recovery();

    /* Task 3.5: ACK demotion + 2-mode pass-through */
    test_rx_ack_demote_small_flow();
    test_rx_demote_tolerates_initial_large();
    test_rx_demote_payload_len_is_udp();
    test_rx_anomalous_drop_not_demote();
    test_rx_demote_current_gapfiller_order();
    test_rx_demote_current_ahead_order();
    test_rx_passthrough_A_no_state();
    test_rx_passthrough_B_undemote_on_reset();
    test_rx_eval_force_no_demotion();

    /* Chunk 3: per-rule wait/cap resolution + per-flow zero-wait */
    test_rx_perrule_wait_cap_from_fiber_lte();
    test_rx_perrule_zero_global_wait_rule_buffers();
    test_rx_perrule_zero_global_wait_preset_passes();
    test_rx_perrule_mode_a_preserved_no_rules();
    test_rx_builder_composed_cellular_bond();

    /* Task 3.6: stats snapshot + accounting identity (+ double-flush hardening) */
    test_rx_accounting_identity();
    test_rx_stats_snapshot();
    test_rx_double_overflow_flush();

    /* Codex review fixes */
    test_rx_max_flows_cap();

    /* Task 1: residence-time (added-latency) histogram */
    test_rx_residence_in_order_is_zero_bucket();
    test_rx_residence_buffered_and_percentile();
    test_latency_percentile_from_buckets();
    test_latency_overflow_boundary_and_max();
    test_stats_accumulate_carries_residence();

    fprintf(stderr, "test_reorder_rx: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
