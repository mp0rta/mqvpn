// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_reorder_rx.c — unit tests for the RX engine core (design spec v2.5
 * §11, §13).
 *
 * Task 3.1: elastic seq-indexed ring (file-local; tested via #include of the
 *           .c so the static ring API is visible — see note below).
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

    /* First insert: span 1 -> size starts small (>=1) then covers span. */
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

int
main(void)
{
    /* Task 3.1: ring */
    test_ring_insert_contains_remove();
    test_ring_empty_when_slots_null();
    test_ring_offbyone();
    test_ring_grow_by_span();
    test_ring_lowest_seq();

    fprintf(stderr, "test_reorder_rx: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
