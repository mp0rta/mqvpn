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
    ASSERT_EQ_INT(ring_insert(&r, 105, &dummy_a, 100, 100), 0, "insert 105");
    ASSERT_EQ_INT(ring_insert(&r, 103, &dummy_c, 90, 100), 0, "insert 103");
    ASSERT_EQ_INT(ring_insert(&r, 108, &dummy_e, 120, 100), 0, "insert 108");

    ASSERT_TRUE(ring_contains(&r, 105), "contains 105");
    ASSERT_TRUE(ring_contains(&r, 103), "contains 103");
    ASSERT_TRUE(ring_contains(&r, 108), "contains 108");
    ASSERT_TRUE(!ring_contains(&r, 104), "not contains 104");
    ASSERT_EQ_INT(r.count, 3, "count 3");

    uint16_t len = 0;
    void *p = ring_remove(&r, 103, &len);
    ASSERT_TRUE(p == &dummy_c, "remove 103 returns ptr");
    ASSERT_EQ_INT(len, 90, "remove 103 returns len");
    ASSERT_TRUE(!ring_contains(&r, 103), "103 gone after remove");
    ASSERT_EQ_INT(r.count, 2, "count 2 after remove");

    /* removing absent seq returns NULL, count unchanged. */
    ASSERT_TRUE(ring_remove(&r, 103, &len) == NULL, "remove absent -> NULL");
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
    ASSERT_TRUE(ring_remove(&r, 42, &len) == NULL, "remove NULL when slots NULL");
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
    ASSERT_EQ_INT(ring_insert(&r, expected + C - 1, &d, 10, expected), 0,
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
    ASSERT_EQ_INT(ring_insert(&r, 1, &d, 10, expected), 0, "insert span1");
    uint32_t size_after_small = r.size;
    ASSERT_TRUE(size_after_small >= 1, "size grown to cover span1");

    /* Big-span insert (span 500) must grow size to cover it, even though count
     * is tiny (count-based growth would not fire). */
    ASSERT_EQ_INT(ring_insert(&r, 500, &d, 10, expected), 0, "insert span500");
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
    ring_insert(&r, 210, &d, 10, expected);
    ring_insert(&r, 205, &d, 10, expected);
    ring_insert(&r, 230, &d, 10, expected);
    ASSERT_EQ_INT(ring_lowest_seq(&r, expected), 205, "lowest is 205");

    uint16_t len = 0;
    ring_remove(&r, 205, &len);
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

/* §11.1 invariant check: gap_timer_active ⟺ buffer non-empty, over all flows. */
static int
invariant_holds(mqvpn_reorder_rx_t *rx)
{
    for (uint32_t i = 0; i < rx->n_buckets; i++) {
        for (mqvpn_reorder_flow_t *f = rx->buckets[i]; f; f = f->next) {
            int nonempty = !ring_empty(&f->buffer);
            if (f->gap_timer_active != nonempty) {
                return 0;
            }
        }
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

    fprintf(stderr, "test_reorder_rx: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
