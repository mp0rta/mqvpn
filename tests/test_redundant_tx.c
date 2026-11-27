// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_redundant_tx.c — unit tests for the redundant-mode TX module
 * (port-list parsing, packet matching, per-path queue gate, overload mode).
 */

/* Keep assert() live even in Release builds (CI-checked). */
#undef NDEBUG
#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "redundant_tx.h"

static int g_run = 0;
#define RUN(fn)                  \
    do {                         \
        printf("  %-40s ", #fn); \
        fn();                    \
        g_run++;                 \
        printf("PASS\n");        \
    } while (0)

static uint64_t g_next_id = 1;

/* ---- packet helpers ---- */

static size_t
mk_udp4(uint8_t *p, uint16_t dport, uint16_t frag_off)
{
    memset(p, 0, 28);
    p[0] = 0x45;
    p[6] = (uint8_t)(frag_off >> 8);
    p[7] = (uint8_t)frag_off;
    p[9] = 17;
    p[22] = (uint8_t)(dport >> 8);
    p[23] = (uint8_t)dport;
    return 28;
}

static size_t
mk_tcp4(uint8_t *p, uint16_t dport)
{
    size_t n = mk_udp4(p, dport, 0);
    p[9] = 6;
    return n;
}

static size_t
mk_udp6(uint8_t *p, uint8_t next_hdr, uint16_t dport)
{
    memset(p, 0, 48);
    p[0] = 0x60;
    p[6] = next_hdr;
    p[42] = (uint8_t)(dport >> 8);
    p[43] = (uint8_t)dport;
    return 48;
}

/* ---- state helpers ---- */

/* One unresolved single-copy original on `path`; returns its dgram id. */
static uint64_t
add_copy(mqvpn_redundant_tx_t *t, int path, uint64_t now_us)
{
    uint64_t id = g_next_id++;
    mqvpn_redundant_tx_commit(t, &id, &path, 1, now_us, 1400);
    return id;
}

/* select over u[0..n) at now_us returns exactly the paths in want[0..nw), in order */
static int
sel_is(mqvpn_redundant_tx_t *t, const int *u, int n, uint64_t now_us, const int *want,
       int nw)
{
    int out[8];
    if (mqvpn_redundant_tx_select(t, u, n, out, now_us) != nw) return 0;
    for (int i = 0; i < nw; i++)
        if (out[i] != want[i]) return 0;
    return 1;
}

/* Mirror the client at 1000 pps from from_ms to to_ms (inclusive, 1 ms apart)
 * on paths {0, 1}. Each ms, first the packet: if overload_bypass() returns 0,
 * select + commit (ids from g_next_id), acking path 1's copy at once when
 * (path-1 copies so far in this call % 100) < ack_pct; then, when ms % 100 == 0,
 * update_mode(). Stops at the first non-zero update result, returns it and
 * its time in *at_ms (0 if none). */
static int
drive(mqvpn_redundant_tx_t *t, uint64_t from_ms, uint64_t to_ms, int ack_pct,
      uint64_t *at_ms)
{
    const int usable[2] = {0, 1};
    uint64_t n1 = 0;
    *at_ms = 0;
    for (uint64_t ms = from_ms; ms <= to_ms; ms++) {
        uint64_t now = ms * 1000;
        if (!mqvpn_redundant_tx_overload_bypass(t, now)) {
            int paths[2], k = mqvpn_redundant_tx_select(t, usable, 2, paths, now);
            uint64_t ids[2];
            for (int i = 0; i < k; i++)
                ids[i] = g_next_id++;
            mqvpn_redundant_tx_commit(t, ids, paths, k, now, 1400);
            for (int i = 0; i < k; i++)
                if (paths[i] == 1 && n1++ % 100 < (uint64_t)ack_pct)
                    mqvpn_redundant_tx_on_acked(t, ids[i]);
        }
        if (ms % 100 == 0) {
            int r = mqvpn_redundant_tx_update_mode(t, usable, 2, now);
            if (r) {
                *at_ms = ms;
                return r;
            }
        }
    }
    return 0;
}

/* An all-short stream (nothing acked) enters overload mode at 2900 ms: five
 * judgements from 2100 ms, the first outside the grace. */
static void
enter_overload(mqvpn_redundant_tx_t *t)
{
    uint64_t at;
    assert(drive(t, 1, 6000, 0, &at) == 1);
    assert(at == 2900);
}

/* A stream of one original every step_ms from step_ms to to_ms, copies on paths
 * {0, 1} (no select, nothing acked), update_mode() at every multiple of 100 ms.
 * Stops at the first non-zero update result, returns it and its time in *at_ms
 * (0 if none). */
static int
drive_every(mqvpn_redundant_tx_t *t, uint64_t step_ms, uint64_t to_ms, uint64_t *at_ms)
{
    const int paths[2] = {0, 1};
    *at_ms = 0;
    for (uint64_t ms = step_ms; ms <= to_ms; ms += step_ms) {
        uint64_t ids[2];
        ids[0] = g_next_id++;
        ids[1] = g_next_id++;
        mqvpn_redundant_tx_commit(t, ids, paths, 2, ms * 1000, 1400);
        if (ms % 100 == 0) {
            int r = mqvpn_redundant_tx_update_mode(t, paths, 2, ms * 1000);
            if (r) {
                *at_ms = ms;
                return r;
            }
        }
    }
    return 0;
}

/* ---- parse ---- */

static void
test_parse_port_list_ok(void)
{
    uint16_t o[16];
    assert(mqvpn_redundant_parse_ports(" 4200 , 9000 ", o, 16) == 2);
    assert(o[0] == 4200 && o[1] == 9000);
    assert(mqvpn_redundant_parse_ports("4200,4200", o, 16) == 1);
    assert(mqvpn_redundant_parse_ports("", o, 16) == 0);
    assert(mqvpn_redundant_parse_ports(NULL, o, 16) == 0);
    assert(mqvpn_redundant_parse_ports("  ", o, 16) == 0);
    assert(mqvpn_redundant_parse_ports("4200,4200,4200,4200,4200,4200,4200,4200,4200,"
                                       "4200,4200,4200,4200,4200,4200,4200",
                                       o, 16) == 1);
    assert(o[0] == 4200);
    assert(mqvpn_redundant_parse_ports("65535,1", o, 16) == 2);
}

static void
test_parse_port_list_rejects(void)
{
    uint16_t o[16];
    const char *bad[] = {"4200,abc", "0",    "70000",     "-1", "4200,",
                         ",4200",    "42x0", "4200 9000", "+5"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        assert(mqvpn_redundant_parse_ports(bad[i], o, 16) == -1);
    assert(mqvpn_redundant_parse_ports("4200,4200,4200,4200,4200,4200,4200,4200,4200,"
                                       "4200,4200,4200,4200,4200,4200,4200,4200",
                                       o, 16) == -1);
}

/* ---- match ---- */

static void
test_match_all_udp(void)
{
    uint8_t p[64];
    size_t n = mk_udp4(p, 5000, 0);
    assert(mqvpn_redundant_match(NULL, 0, p, n) == 1);
    n = mk_udp6(p, 17, 5000);
    assert(mqvpn_redundant_match(NULL, 0, p, n) == 1);
    n = mk_tcp4(p, 5000);
    assert(mqvpn_redundant_match(NULL, 0, p, n) == 0);
    n = mk_udp4(p, 5000, 100);
    assert(mqvpn_redundant_match(NULL, 0, p, n) == 1);
    mk_udp4(p, 5000, 0);
    assert(mqvpn_redundant_match(NULL, 0, p, 19) == 0);
}

static void
test_match_ports(void)
{
    uint16_t ports[1] = {4200};
    uint8_t p[64];
    size_t n = mk_udp4(p, 4200, 0);
    assert(mqvpn_redundant_match(ports, 1, p, n) == 1);
    n = mk_udp4(p, 4201, 0);
    assert(mqvpn_redundant_match(ports, 1, p, n) == 0);
    n = mk_udp4(p, 4200, 100);
    assert(mqvpn_redundant_match(ports, 1, p, n) == 0);
    n = mk_udp6(p, 17, 4200);
    assert(mqvpn_redundant_match(ports, 1, p, n) == 1);
    n = mk_udp6(p, 0, 4200);
    assert(mqvpn_redundant_match(ports, 1, p, n) == 0);
}

/* ---- select / queue gate ---- */

static const int U01[2] = {0, 1}, P0[1] = {0}, P1[1] = {1};

static void
test_select_all_fresh(void)
{
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    const int u[3] = {0, 1, 2};
    assert(sel_is(t, u, 3, 0, u, 3));
    mqvpn_redundant_tx_free(t);
}

static void
test_select_skips_queued_path(void)
{
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    mqvpn_redundant_tx_set_path_metrics(t, 0, 20000, 0, 0);
    add_copy(t, 0, 1000000);
    assert(sel_is(t, U01, 2, 1270000, U01, 2)); /* queued 250 ms: inclusive */
    assert(sel_is(t, U01, 2, 1270001, P1, 1));
    assert(sel_is(t, U01, 2, 500000, U01, 2)); /* clock behind the hand-over */
    /* each path's own min RTT: path 1 waited as long as path 0 but queued 0 */
    mqvpn_redundant_tx_set_path_metrics(t, 1, 500000, 0, 0);
    add_copy(t, 1, 1000000);
    const int u3[3] = {0, 1, 2}, w12[2] = {1, 2};
    assert(sel_is(t, u3, 3, 1270001, w12, 2));
    mqvpn_redundant_tx_free(t);
}

static void
test_select_relative_to_least_queued(void)
{
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    add_copy(t, 0, 0);
    add_copy(t, 1, 100000);
    /* path 0 queued 300 ms, but only 100 ms behind path 1: both */
    assert(sel_is(t, U01, 2, 300000, U01, 2));
    assert(sel_is(t, U01, 2, 350000, U01, 2)); /* path 1 queued 250 ms: inclusive */
    assert(sel_is(t, U01, 2, 350001, P1, 1));  /* both too far behind: path 1 alone */
    mqvpn_redundant_tx_free(t);
}

static void
test_select_all_queued_least_queued(void)
{
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    add_copy(t, 0, 0);
    for (int i = 0; i < 5; i++)
        add_copy(t, 1, 100000);
    assert(sel_is(t, U01, 2, 1000000, P1, 1)); /* less queued although it holds more */
    mqvpn_redundant_tx_free(t);
}

static void
test_select_tie_fewer_outstanding(void)
{
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    uint64_t ids[2];
    ids[0] = g_next_id++;
    ids[1] = g_next_id++;
    mqvpn_redundant_tx_commit(t, ids, U01, 2, 0, 1400);
    add_copy(t, 0, 0);
    assert(sel_is(t, U01, 2, 1000000, P1, 1)); /* equal queues: fewer copies */
    add_copy(t, 1, 0);
    assert(sel_is(t, U01, 2, 1000000, P0, 1)); /* and equal counts: lowest index */
    mqvpn_redundant_tx_free(t);
}

static void
test_select_single_path(void)
{
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    assert(sel_is(t, P1, 1, 0, P1, 1));
    add_copy(t, 1, 0);
    assert(sel_is(t, P1, 1, 1000000, P1, 1)); /* queued, but the only path */
    mqvpn_redundant_tx_free(t);
}

static void
test_select_burst_not_skipped_for_size(void)
{
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    for (int i = 0; i < 1000; i++)
        add_copy(t, 0, 5000000);
    assert(sel_is(t, U01, 2, 5000000, U01, 2)); /* fresh copies do not queue a path */
    mqvpn_redundant_tx_free(t);
}

static void
test_queue_follows_resolution(void)
{
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    uint64_t a = add_copy(t, 0, 0);
    uint64_t b = add_copy(t, 0, 100000);
    uint64_t c = add_copy(t, 0, 200000);
    assert(sel_is(t, U01, 2, 400000, P1, 1));
    assert(mqvpn_redundant_tx_on_lost(t, a) == 1);
    assert(sel_is(t, U01, 2, 400000, P1, 1)); /* oldest now b: queued 300 ms */
    assert(mqvpn_redundant_tx_on_acked(t, b) == 1);
    assert(sel_is(t, U01, 2, 400000, U01, 2)); /* oldest now c: queued 200 ms */
    assert(mqvpn_redundant_tx_on_lost(t, c) == 1);
    assert(sel_is(t, U01, 2, 10000000, U01, 2)); /* none left */
    mqvpn_redundant_tx_free(t);
}

static void
test_queue_unknown_min_rtt(void)
{
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    mqvpn_redundant_tx_set_path_metrics(t, 0, 4294967295u, 0, 0); /* xquic: no sample */
    add_copy(t, 0, 0);
    assert(sel_is(t, U01, 2, 250001, P1, 1)); /* counts as 0 */
    mqvpn_redundant_tx_free(t);
}

static void
test_stream_pps(void)
{
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    for (int i = 0; i < 1000; i++)
        add_copy(t, 1, 500000);
    int none = 0;
    uint64_t id = g_next_id++;
    mqvpn_redundant_tx_commit(t, &id, &none, 0, 600000, 1400); /* k == 0: not counted */
    assert(mqvpn_redundant_tx_stream_pps(t) == 0);
    add_copy(t, 1, 1500000); /* second 1 */
    assert(mqvpn_redundant_tx_stream_pps(t) == 1000);
    mqvpn_redundant_tx_free(t);
}

static void
test_stream_pps_first_second(void)
{
    mqvpn_redundant_tx_t *t;
    t = mqvpn_redundant_tx_new(); /* trickle lead-in, then the real flow */
    add_copy(t, 1, 5000000);
    add_copy(t, 1, 5120000);
    for (int i = 0; i < 200; i++)
        add_copy(t, 1, 5300000 + (uint64_t)i * 500);
    add_copy(t, 1, 5400000);
    assert(mqvpn_redundant_tx_stream_pps(t) == 2000);
    mqvpn_redundant_tx_free(t);

    t = mqvpn_redundant_tx_new(); /* only the adjacent bucket counts */
    for (int i = 0; i < 200; i++)
        add_copy(t, 1, 6000000 + (uint64_t)i * 500);
    add_copy(t, 1, 6200000);
    assert(mqvpn_redundant_tx_stream_pps(t) == 0);
    mqvpn_redundant_tx_free(t);

    t = mqvpn_redundant_tx_new(); /* no complete bucket yet */
    for (int i = 0; i < 150; i++)
        add_copy(t, 1, 7000000 + (uint64_t)i * 500);
    assert(mqvpn_redundant_tx_stream_pps(t) == 0);
    mqvpn_redundant_tx_free(t);

    t = mqvpn_redundant_tx_new(); /* 20 pkt/s */
    for (int i = 0; i < 20; i++)
        add_copy(t, 1, (uint64_t)i * 50000);
    assert(mqvpn_redundant_tx_stream_pps(t) == 20);
    mqvpn_redundant_tx_free(t);

    t = mqvpn_redundant_tx_new(); /* clock stepped back: window and bucket restart */
    for (int i = 0; i < 1710; i++)
        add_copy(t, 1, 8000000 + (uint64_t)i * 900000 / 1709);
    add_copy(t, 1, 8100000);
    assert(mqvpn_redundant_tx_stream_pps(t) == 0);
    mqvpn_redundant_tx_free(t);

    t = mqvpn_redundant_tx_new(); /* the previous second's count wins when larger */
    for (int i = 0; i < 1900; i++)
        add_copy(t, 1, 9000000 + (uint64_t)i * 500);
    add_copy(t, 1, 10000000);
    assert(mqvpn_redundant_tx_stream_pps(t) == 1900);
    mqvpn_redundant_tx_free(t);

    /* step back inside the open bucket resets the bucket too */
    t = mqvpn_redundant_tx_new();
    for (int i = 0; i < 1900; i++)
        add_copy(t, 1, 9000000 + (uint64_t)i * 500);
    add_copy(t, 1, 10000000);
    add_copy(t, 1, 10050000);
    add_copy(t, 1, 10049999);
    assert(mqvpn_redundant_tx_stream_pps(t) == 0);
    mqvpn_redundant_tx_free(t);
}

static void
test_ack_lost_accounting(void)
{
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    uint64_t a[2] = {1, 2}, b[2] = {3, 4}, c[2] = {5, 6};
    int p[2] = {0, 1};
    mqvpn_redundant_tx_commit(t, a, p, 2, 0, 1400);
    mqvpn_redundant_tx_commit(t, b, p, 2, 0, 1400);
    mqvpn_redundant_tx_commit(t, c, p, 2, 0, 1400);
    assert(mqvpn_redundant_tx_outstanding(t, 0) == 3);
    assert(mqvpn_redundant_tx_on_acked(t, 1) == 1);
    assert(mqvpn_redundant_tx_on_acked(t, 2) == 0);
    assert(mqvpn_redundant_tx_on_lost(t, 3) == 0);
    assert(mqvpn_redundant_tx_on_lost(t, 4) == 1);
    assert(mqvpn_redundant_tx_on_lost(t, 5) == 0);
    assert(mqvpn_redundant_tx_on_acked(t, 6) == 1);
    assert(mqvpn_redundant_tx_on_acked(t, 99) == -1);
    assert(mqvpn_redundant_tx_on_lost(t, 99) == -1);
    assert(mqvpn_redundant_tx_outstanding(t, 0) == 0);
    assert(mqvpn_redundant_tx_outstanding(t, 1) == 0);
    mqvpn_redundant_tx_free(t);
}

static void
test_no_eviction_of_live_copies(void)
{
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    uint64_t stalled[300];
    for (int i = 0; i < 300; i++)
        stalled[i] = add_copy(t, 0, 0);
    for (int i = 0; i < 20000; i++) {
        uint64_t id = add_copy(t, 1, 0);
        assert(mqvpn_redundant_tx_on_acked(t, id) == 1);
    }
    assert(mqvpn_redundant_tx_outstanding(t, 0) == 300);
    assert(sel_is(t, U01, 2, 1000000, P1, 1));
    for (int i = 0; i < 300; i++) {
        int r = (i & 1) ? mqvpn_redundant_tx_on_acked(t, stalled[i])
                        : mqvpn_redundant_tx_on_lost(t, stalled[i]);
        assert(r == 1);
    }
    assert(mqvpn_redundant_tx_outstanding(t, 0) == 0);
    mqvpn_redundant_tx_free(t);
}

static void
test_capacity_truncates(void)
{
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    for (int i = 0; i < 16383; i++)
        add_copy(t, 2, 1000000);
    const int u[3] = {0, 1, 2};
    assert(sel_is(t, u, 3, 1000000, u, 1)); /* three paths, room for one copy */
    add_copy(t, 2, 1000000);
    assert(sel_is(t, u, 3, 1000000, u, 0));
    mqvpn_redundant_tx_free(t);
}

static void
test_full_table_unknown_lookup(void)
{
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    for (int i = 0; i < 16384; i++)
        add_copy(t, 2, 0);
    assert(mqvpn_redundant_tx_on_acked(t, 999999999ull) == -1);
    assert(mqvpn_redundant_tx_on_lost(t, 999999999ull) == -1);
    mqvpn_redundant_tx_free(t);
}

static void
test_detach_and_rebind(void)
{
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    mqvpn_redundant_tx_bind_path(t, 2, 7);
    uint64_t x[2] = {1, 2}, y[2] = {3, 4};
    int p[2] = {0, 2};
    mqvpn_redundant_tx_commit(t, x, p, 2, 0, 1400);
    mqvpn_redundant_tx_commit(t, y, p, 2, 0, 1400);
    assert(mqvpn_redundant_tx_outstanding(t, 2) == 2);
    mqvpn_redundant_tx_bind_path(t, 2, 7); /* same id: no detach */
    assert(mqvpn_redundant_tx_outstanding(t, 2) == 2);
    mqvpn_redundant_tx_bind_path(t, 2, 8);
    assert(mqvpn_redundant_tx_outstanding(t, 2) == 0);
    assert(mqvpn_redundant_tx_on_acked(t, 1) == 1);
    assert(mqvpn_redundant_tx_on_acked(t, 2) == 0);
    assert(mqvpn_redundant_tx_outstanding(t, 2) == 0);
    assert(mqvpn_redundant_tx_on_lost(t, 3) == 0);
    assert(mqvpn_redundant_tx_on_lost(t, 4) == 1);
    /* explicit detach */
    uint64_t z = add_copy(t, 2, 0);
    mqvpn_redundant_tx_detach_path(t, 2);
    assert(mqvpn_redundant_tx_outstanding(t, 2) == 0);
    const int u12[2] = {1, 2};
    assert(sel_is(t, u12, 2, 1000000, u12, 2)); /* z no longer queues path 2 */
    add_copy(t, 2, 1000000);
    /* z was detached: resolving it leaves path 2's queue alone */
    assert(mqvpn_redundant_tx_on_lost(t, z) == 1);
    assert(mqvpn_redundant_tx_outstanding(t, 2) == 1);
    assert(sel_is(t, u12, 2, 1000001, u12, 2));
    mqvpn_redundant_tx_free(t);
}

static void
test_queue_ring_wraps(void)
{
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    uint64_t prev = add_copy(t, 0, 0);
    for (uint64_t i = 1; i <= 20000; i++) { /* one copy outstanding; the ring wraps */
        uint64_t id = add_copy(t, 0, i * 1000);
        assert(mqvpn_redundant_tx_on_acked(t, prev) == 1);
        prev = id;
        assert(sel_is(t, U01, 2, i * 1000 + 250000, U01, 2)); /* queued 250 ms */
    }
    mqvpn_redundant_tx_free(t);
}

/* ---- overload mode ---- */

static void
test_overload_enters_when_every_path_short(void)
{
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    enter_overload(t);
    int o0 = mqvpn_redundant_tx_outstanding(t, 0);
    int o1 = mqvpn_redundant_tx_outstanding(t, 1);
    assert(mqvpn_redundant_tx_overload_bypass(t, 2901000) == 1);
    assert(mqvpn_redundant_tx_outstanding(t, 0) == o0);
    assert(mqvpn_redundant_tx_outstanding(t, 1) == o1);
    mqvpn_redundant_tx_free(t);
}

static void
test_overload_not_while_one_path_keeps_up(void)
{
    uint64_t at;
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    assert(drive(t, 1, 6000, 100, &at) == 0);
    mqvpn_redundant_tx_free(t);

    t = mqvpn_redundant_tx_new();
    assert(drive(t, 1, 6000, 97, &at) == 0); /* 970 pps: not under 95% of the stream */
    mqvpn_redundant_tx_free(t);

    t = mqvpn_redundant_tx_new();
    assert(drive(t, 1, 6000, 90, &at) == 1); /* 900 pps: short */
    assert(at == 2900);
    mqvpn_redundant_tx_free(t);
}

static void
test_overload_bypass_counts_rate(void)
{
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    enter_overload(t);
    assert(mqvpn_redundant_tx_stream_pps(t) == 1000);
    for (uint64_t i = 1; i <= 4000; i++) /* 2000 pps for 2 s, none committed */
        assert(mqvpn_redundant_tx_overload_bypass(t, 2900000 + i * 500) == 1);
    /* an uncounted bypass would leave 1000 */
    assert(mqvpn_redundant_tx_stream_pps(t) == 2000);
    mqvpn_redundant_tx_free(t);
}

static void
test_probe_needs_hold_and_fit(void)
{
    uint64_t at;
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    /* 1000 pps worth of bytes: under 1.05 x the stream's lowest second */
    mqvpn_redundant_tx_set_path_metrics(t, 1, 0, 1400000, 0);
    enter_overload(t);
    assert(drive(t, 2901, 32900, 0, &at) == 0); /* the hold ended at 12900 */
    mqvpn_redundant_tx_set_path_metrics(t, 1, 0, 1500000, 0);
    assert(drive(t, 32901, 40000, 0, &at) == -1);
    assert(at == 33100);
    mqvpn_redundant_tx_free(t);
}

static void
test_probe_base_is_lowest_second(void)
{
    const int u[2] = {0, 1};
    uint64_t at;
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    /* 1000 pps worth of bytes: no fit at base 999 or 1000, a fit at base 900 */
    mqvpn_redundant_tx_set_path_metrics(t, 1, 0, 1400000, 0);
    enter_overload(t);
    assert(drive(t, 2901, 4999, 0, &at) == 0);
    for (uint64_t ms = 5000; ms < 6000; ms++) { /* second 5 carries 900 packets */
        if (ms % 10) assert(mqvpn_redundant_tx_overload_bypass(t, ms * 1000) == 1);
        if (ms % 100 == 0)
            assert(mqvpn_redundant_tx_update_mode(t, u, 2, ms * 1000) == 0);
    }
    /* the hold ends at 12900, when the history holds seconds 2-11: base 900, not the
     * 1000 of the last second */
    assert(drive(t, 6000, 13000, 0, &at) == -1);
    assert(at == 12900);
    mqvpn_redundant_tx_free(t);
}

static void
test_failed_probe_backs_off(void)
{
    static const struct {
        uint64_t to_ms;
        int r;
        uint64_t at;
    } step[] = {
        {6000, 1, 2900},    /* entry */
        {13000, -1, 12900}, /* probe after the 10 s hold */
        {14000, 1, 13300},  /* two short judgements: hold 20 s */
        {34000, -1, 33300}, /* probe */
        {35000, 1, 33700},  /* hold 40 s, capped at 32 s */
        {66000, -1, 65700}, /* probe */
        {67000, 1, 66100},  /* hold stays 32 s */
        {99000, -1, 98100}, /* probe */
    };
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    mqvpn_redundant_tx_set_path_metrics(t, 1, 0, 1500000, 0); /* fits from the start */
    uint64_t from = 1, at;
    for (size_t i = 0; i < sizeof(step) / sizeof(step[0]); i++) {
        assert(drive(t, from, step[i].to_ms, 0, &at) == step[i].r);
        assert(at == step[i].at);
        from = at + 1;
    }
    mqvpn_redundant_tx_free(t);
}

static void
test_probe_held_resets_hold(void)
{
    uint64_t at;
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    mqvpn_redundant_tx_set_path_metrics(t, 1, 0, 1500000, 0);
    enter_overload(t);
    assert(drive(t, 2901, 13000, 0, &at) == -1 && at == 12900);
    assert(drive(t, 12901, 14000, 0, &at) == 1 && at == 13300); /* hold 20 s */
    assert(drive(t, 13301, 34000, 0, &at) == -1 && at == 33300);
    /* path 1 carries the stream; at 43300 the probe has lasted 10 s: hold 10 s */
    assert(drive(t, 33301, 43300, 100, &at) == 0);
    assert(drive(t, 43301, 45000, 0, &at) == 1 && at == 44300);  /* five judgements */
    assert(drive(t, 44301, 55000, 0, &at) == -1 && at == 54300); /* 64300 at hold 20 s */
    mqvpn_redundant_tx_free(t);
}

static void
test_mode_resets_when_stream_stops(void)
{
    const int u[2] = {0, 1};
    uint64_t at;
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    enter_overload(t); /* the last packet is at 2900 ms */
    for (uint64_t ms = 3000; ms < 3900; ms += 100)
        assert(mqvpn_redundant_tx_update_mode(t, u, 2, ms * 1000) == 0);
    assert(mqvpn_redundant_tx_update_mode(t, u, 2, 3900000) == -1);
    assert(drive(t, 3901, 10000, 0, &at) == 1);
    assert(at == 6800); /* the grace starts again */
    mqvpn_redundant_tx_free(t);

    t = mqvpn_redundant_tx_new();
    enter_overload(t);
    /* the clock is below the last counted packet */
    assert(mqvpn_redundant_tx_update_mode(t, u, 2, 2800000) == -1);
    mqvpn_redundant_tx_free(t);

    t = mqvpn_redundant_tx_new();
    enter_overload(t);
    /* a judgement restarts the window at 3100; 3000 is below it, not below the packet */
    assert(mqvpn_redundant_tx_update_mode(t, u, 2, 3100000) == 0);
    assert(mqvpn_redundant_tx_update_mode(t, u, 2, 3000000) == -1);
    mqvpn_redundant_tx_free(t);
}

static void
test_mode_resets_after_total_outage(void)
{
    const int u[2] = {0, 1};
    uint64_t at;
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    enter_overload(t); /* the last packet is at 2900 ms */
    /* no path until 6000: nothing is counted and no update runs, and the first packet
     * of the returning path is counted before the next update */
    assert(mqvpn_redundant_tx_overload_bypass(t, 6001000) == 1); /* still overload */
    assert(mqvpn_redundant_tx_update_mode(t, u, 2, 6100000) == -1);
    assert(drive(t, 6101, 12000, 0, &at) == 1);
    assert(at == 9000); /* the window restarts at 6200, the grace ends at 8200 */
    mqvpn_redundant_tx_free(t);

    t = mqvpn_redundant_tx_new();
    assert(drive(t, 1, 3000, 100, &at) == 0); /* path 1 keeps up: normal mode */
    /* the same outage; the returning path has nothing acked yet */
    assert(drive(t, 6001, 12000, 0, &at) == 1);
    assert(at == 9000); /* a fresh grace */
    mqvpn_redundant_tx_free(t);
}

static void
test_short_needs_fed(void)
{
    uint64_t at;
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    for (int p = 0; p < 2; p++) /* in flight covers the outstanding copies */
        mqvpn_redundant_tx_set_path_metrics(t, p, 0, 0, 100000000);
    assert(drive_every(t, 1, 3000, &at) == 0); /* no select: no path is left out */
    assert(drive(t, 3001, 6000, 0, &at) == 1); /* select leaves each path out: fed */
    assert(at == 3900);
    mqvpn_redundant_tx_free(t);
}

static void
test_left_out_by_bound_is_fed(void)
{
    uint64_t at;
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    /* path 0's bytes never look queued, so only being left out makes it fed */
    mqvpn_redundant_tx_set_path_metrics(t, 0, 0, 0, 100000000);
    assert(drive(t, 1, 6000, 90, &at) == 1); /* path 0 falls 250 ms behind path 1 */
    assert(at == 2900);
    mqvpn_redundant_tx_free(t);
}

static void
test_fallback_path_not_fed(void)
{
    uint64_t at;
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    for (int p = 0; p < 2; p++) /* bytes never look queued: only being left out feeds */
        mqvpn_redundant_tx_set_path_metrics(t, p, 0, 0, 100000000);
    /* path 1 is queued past RTX_LAG from ~2.5 s; from then on it gets every packet
     * as the fallback */
    assert(drive(t, 1, 6000, 90, &at) == 0);
    mqvpn_redundant_tx_free(t);
}

static void
test_overload_needs_enough_copies(void)
{
    uint64_t at;
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    assert(drive_every(t, 20, 6000, &at) == 0); /* 50 pps: 10 copies per window */
    mqvpn_redundant_tx_free(t);

    t = mqvpn_redundant_tx_new();
    assert(drive_every(t, 4, 6000, &at) == 1); /* 250 pps: 50 copies per window */
    assert(at == 2900);
    mqvpn_redundant_tx_free(t);
}

static void
test_fed_counts_bytes(void)
{
    const int paths[2] = {0, 1};
    uint64_t at = 0;
    int r = 0;
    mqvpn_redundant_tx_t *t = mqvpn_redundant_tx_new();
    /* 100 unresolved copies per path, then a detach: it must drop their bytes */
    for (int p = 0; p < 2; p++) {
        for (int i = 0; i < 100; i++)
            add_copy(t, p, 1000);
        mqvpn_redundant_tx_detach_path(t, p);
    }
    /* 500 pps of 200 B copies, 9 in 10 acked: short by rate. Through 6000 ms all their
     * bytes are in flight, so none is queued and nothing enters; after, half are. */
    for (uint64_t ms = 2; ms <= 8000 && !r; ms += 2) {
        uint64_t ids[2];
        ids[0] = g_next_id++;
        ids[1] = g_next_id++;
        mqvpn_redundant_tx_commit(t, ids, paths, 2, ms * 1000, 200);
        if (ms % 20)
            for (int p = 0; p < 2; p++)
                mqvpn_redundant_tx_on_acked(t, ids[p]);
        if (ms % 100 == 0) {
            for (int p = 0; p < 2; p++) {
                uint64_t unresolved =
                    (uint64_t)mqvpn_redundant_tx_outstanding(t, p) * 200;
                mqvpn_redundant_tx_set_path_metrics(
                    t, p, 0, 0, ms <= 6000 ? unresolved : unresolved / 2);
            }
            r = mqvpn_redundant_tx_update_mode(t, paths, 2, ms * 1000);
            if (r) at = ms;
        }
    }
    assert(r == 1);
    assert(at == 6900); /* five fed judgements from 6100 ms, past the grace */
    mqvpn_redundant_tx_free(t);
}

int
main(void)
{
    RUN(test_parse_port_list_ok);
    RUN(test_parse_port_list_rejects);
    RUN(test_match_all_udp);
    RUN(test_match_ports);
    RUN(test_select_all_fresh);
    RUN(test_select_skips_queued_path);
    RUN(test_select_relative_to_least_queued);
    RUN(test_select_all_queued_least_queued);
    RUN(test_select_tie_fewer_outstanding);
    RUN(test_select_single_path);
    RUN(test_select_burst_not_skipped_for_size);
    RUN(test_queue_follows_resolution);
    RUN(test_queue_unknown_min_rtt);
    RUN(test_stream_pps);
    RUN(test_stream_pps_first_second);
    RUN(test_ack_lost_accounting);
    RUN(test_no_eviction_of_live_copies);
    RUN(test_capacity_truncates);
    RUN(test_full_table_unknown_lookup);
    RUN(test_detach_and_rebind);
    RUN(test_queue_ring_wraps);
    RUN(test_overload_enters_when_every_path_short);
    RUN(test_overload_not_while_one_path_keeps_up);
    RUN(test_overload_bypass_counts_rate);
    RUN(test_probe_needs_hold_and_fit);
    RUN(test_probe_base_is_lowest_second);
    RUN(test_failed_probe_backs_off);
    RUN(test_probe_held_resets_hold);
    RUN(test_mode_resets_when_stream_stops);
    RUN(test_mode_resets_after_total_outage);
    RUN(test_short_needs_fed);
    RUN(test_left_out_by_bound_is_fed);
    RUN(test_fallback_path_not_fed);
    RUN(test_fed_counts_bytes);
    RUN(test_overload_needs_enough_copies);
    printf("\n=== test_redundant_tx: %d passed ===\n", g_run);
    return 0;
}
