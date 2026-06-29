// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_reorder_tx.c — unit tests for the TX send_flow table + peek-commit
 * stamping (design spec v2.5 §10, §14.2, §15.1).
 *
 * Build: see CMakeLists.txt (test_reorder_tx target). Links reorder_tx.c +
 * log.c only — never any rx file (tx/rx are zero-coupled).
 */
#include "reorder_tx.h"
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

/* ─────────────────────────── packet builders ──────────────────────────── */

/* Build a minimal IPv4 UDP packet with `payload` bytes of UDP payload after the
 * 8-byte UDP header. Returns total length. */
static size_t
build_v4_udp(uint8_t *buf, uint16_t sport, uint16_t dport, size_t payload)
{
    size_t total = 28 + payload;
    memset(buf, 0, total);
    buf[0] = 0x45; /* v4, IHL 5 */
    buf[9] = 17;   /* UDP */
    buf[12] = 10;
    buf[15] = 1;
    buf[16] = 10;
    buf[19] = 2;
    buf[20] = (uint8_t)(sport >> 8);
    buf[21] = (uint8_t)(sport);
    buf[22] = (uint8_t)(dport >> 8);
    buf[23] = (uint8_t)(dport);
    return total;
}

static mqvpn_reorder_config_t
base_cfg(void)
{
    mqvpn_reorder_config_t c;
    mqvpn_reorder_config_default(&c);
    c.mode = MQVPN_REORDER_ON;
    /* default rule set: udp/443 → quic_bulk (eligible both directions). */
    c.rules[0].proto = 17;
    c.rules[0].port = 443;
    c.rules[0].profile = MQVPN_RPROF_QUIC_BULK;
    c.n_rules = 1;
    return c;
}

/* ─────────────────────────── Task 2.1: table ──────────────────────────── */

static void
test_tx_flow_create_and_get(void)
{
    mqvpn_reorder_config_t c = base_cfg();
    mqvpn_reorder_tx_t *tx = mqvpn_reorder_tx_new(&c, 0x1234);
    ASSERT_TRUE(tx != NULL, "tx_new");

    uint8_t pkt[256];
    size_t n = build_v4_udp(pkt, 1111, 443, 8);
    mqvpn_reorder_tx_peek_t p1, p2;
    mqvpn_reorder_tx_peek(tx, pkt, n, 1000, 1400, &p1);
    mqvpn_reorder_tx_peek(tx, pkt, n, 1000, 1400, &p2);
    /* Same key twice → same flow object (created once). */
    ASSERT_TRUE(p1.flow == p2.flow, "same key returns same flow");
    ASSERT_TRUE(p1.flow != NULL, "flow non-null");
    mqvpn_reorder_tx_free(tx);
}

static void
test_tx_eligibility_443_bidir(void)
{
    mqvpn_reorder_config_t c = base_cfg();
    mqvpn_reorder_tx_t *tx = mqvpn_reorder_tx_new(&c, 0x1);
    uint8_t pkt[256];
    mqvpn_reorder_tx_peek_t p;

    /* dst_port == 443 */
    size_t n = build_v4_udp(pkt, 5000, 443, 100);
    ASSERT_EQ_INT(mqvpn_reorder_tx_peek(tx, pkt, n, 1, 1400, &p), MQVPN_REORDER_TX_STAMP,
                  "dst 443 eligible");

    /* src_port == 443 (reverse direction) */
    n = build_v4_udp(pkt, 443, 5000, 100);
    ASSERT_EQ_INT(mqvpn_reorder_tx_peek(tx, pkt, n, 1, 1400, &p), MQVPN_REORDER_TX_STAMP,
                  "src 443 eligible");
    mqvpn_reorder_tx_free(tx);
}

static void
test_tx_eligibility_dns_ineligible(void)
{
    mqvpn_reorder_config_t c = base_cfg();
    c.rules[1].proto = 17;
    c.rules[1].port = 53;
    c.rules[1].profile = MQVPN_RPROF_LOW_LATENCY;
    c.n_rules = 2;
    mqvpn_reorder_tx_t *tx = mqvpn_reorder_tx_new(&c, 0x1);
    uint8_t pkt[256];
    mqvpn_reorder_tx_peek_t p;
    size_t n = build_v4_udp(pkt, 5000, 53, 40);
    ASSERT_EQ_INT(mqvpn_reorder_tx_peek(tx, pkt, n, 1, 1400, &p), MQVPN_REORDER_TX_RAW,
                  "dns low_latency ineligible -> RAW");
    mqvpn_reorder_tx_free(tx);
}

static void
test_tx_eligibility_unknown_ineligible(void)
{
    mqvpn_reorder_config_t c = base_cfg();
    mqvpn_reorder_tx_t *tx = mqvpn_reorder_tx_new(&c, 0x1);
    uint8_t pkt[256];
    mqvpn_reorder_tx_peek_t p;
    /* No rule matches port 9999 → default_udp → RAW. */
    size_t n = build_v4_udp(pkt, 5000, 9999, 100);
    ASSERT_EQ_INT(mqvpn_reorder_tx_peek(tx, pkt, n, 1, 1400, &p), MQVPN_REORDER_TX_RAW,
                  "unknown udp ineligible -> RAW");
    mqvpn_reorder_tx_free(tx);
}

static void
test_tx_eligibility_preset_profiles(void)
{
    /* cellular_bond and fiber_lte carry presets → matching flows are eligible;
     * default_udp and low_latency carry no preset → RAW. */
    mqvpn_reorder_config_t c = base_cfg();
    c.rules[0].port = 443;
    c.rules[0].profile = MQVPN_RPROF_CELLULAR_BOND;
    c.rules[1].proto = 17;
    c.rules[1].port = 8443;
    c.rules[1].profile = MQVPN_RPROF_FIBER_LTE;
    c.rules[2].proto = 17;
    c.rules[2].port = 5000;
    c.rules[2].profile = MQVPN_RPROF_DEFAULT_UDP;
    c.rules[3].proto = 17;
    c.rules[3].port = 6000;
    c.rules[3].profile = MQVPN_RPROF_LOW_LATENCY;
    c.n_rules = 4;

    mqvpn_reorder_tx_t *tx = mqvpn_reorder_tx_new(&c, 0x1);
    uint8_t pkt[256];
    mqvpn_reorder_tx_peek_t p;

    size_t n = build_v4_udp(pkt, 5001, 443, 100);
    ASSERT_EQ_INT(mqvpn_reorder_tx_peek(tx, pkt, n, 1, 1400, &p), MQVPN_REORDER_TX_STAMP,
                  "cellular_bond eligible");

    n = build_v4_udp(pkt, 5002, 8443, 100);
    ASSERT_EQ_INT(mqvpn_reorder_tx_peek(tx, pkt, n, 1, 1400, &p), MQVPN_REORDER_TX_STAMP,
                  "fiber_lte eligible");

    n = build_v4_udp(pkt, 5003, 5000, 100);
    ASSERT_EQ_INT(mqvpn_reorder_tx_peek(tx, pkt, n, 1, 1400, &p), MQVPN_REORDER_TX_RAW,
                  "default_udp ineligible -> RAW");

    n = build_v4_udp(pkt, 5004, 6000, 100);
    ASSERT_EQ_INT(mqvpn_reorder_tx_peek(tx, pkt, n, 1, 1400, &p), MQVPN_REORDER_TX_RAW,
                  "low_latency ineligible -> RAW");

    mqvpn_reorder_tx_free(tx);
}

static void
test_tx_evict_only_idle(void)
{
    mqvpn_reorder_config_t c = base_cfg();
    c.max_flows = 2;
    c.egress_idle_timeout_sec = 10; /* idle threshold = 10s */
    mqvpn_reorder_tx_t *tx = mqvpn_reorder_tx_new(&c, 0x1);
    uint8_t pkt[256];
    mqvpn_reorder_tx_peek_t p;

    uint64_t t0 = 1000ULL * 1000ULL; /* 1s in us */
    /* Create + commit two active flows at t0. */
    size_t n = build_v4_udp(pkt, 1001, 443, 100);
    mqvpn_reorder_tx_peek(tx, pkt, n, t0, 1400, &p);
    mqvpn_reorder_tx_commit(tx, &p, t0);
    n = build_v4_udp(pkt, 1002, 443, 100);
    mqvpn_reorder_tx_peek(tx, pkt, n, t0, 1400, &p);
    mqvpn_reorder_tx_commit(tx, &p, t0);

    /* Table full (2/2), both active. A new flow arrives only 1s later (idle of
     * existing flows = 1s <= 10s): must NOT evict → caller sends RAW. */
    uint64_t t_active = t0 + 1ULL * 1000ULL * 1000ULL;
    n = build_v4_udp(pkt, 1003, 443, 100);
    ASSERT_EQ_INT(mqvpn_reorder_tx_peek(tx, pkt, n, t_active, 1400, &p),
                  MQVPN_REORDER_TX_RAW, "table full all active -> RAW");
    ASSERT_EQ_INT(mqvpn_reorder_tx_stats(tx)->forced_evict_count, 0,
                  "no forced eviction of active flow");

    /* Now advance well past egress_idle so existing flows are idle; a new flow
     * CAN evict one and be created. */
    uint64_t t_idle = t0 + 20ULL * 1000ULL * 1000ULL; /* 20s later */
    n = build_v4_udp(pkt, 1004, 443, 100);
    ASSERT_EQ_INT(mqvpn_reorder_tx_peek(tx, pkt, n, t_idle, 1400, &p),
                  MQVPN_REORDER_TX_STAMP, "idle flow evictable -> new flow STAMP");
    ASSERT_EQ_INT(mqvpn_reorder_tx_stats(tx)->forced_evict_count, 0,
                  "idle eviction does not count as forced");
    mqvpn_reorder_tx_free(tx);
}

/* §14.2(c): a backwards-clock blip (now_us < a flow's last_activity_us) must NOT
 * make the unsigned (now_us - last_activity_us) underflow to a huge value and
 * spuriously evict a live flow. Mirrors the RX-side wrap-safe guard. */
static void
test_tx_evict_backwards_clock_no_evict(void)
{
    mqvpn_reorder_config_t c = base_cfg();
    c.max_flows = 2;
    c.egress_idle_timeout_sec = 10; /* idle threshold = 10s */
    mqvpn_reorder_tx_t *tx = mqvpn_reorder_tx_new(&c, 0x1);
    uint8_t pkt[256];
    mqvpn_reorder_tx_peek_t p;

    uint64_t t0 = 100ULL * 1000ULL * 1000ULL; /* 100s in us */
    /* Two active flows established at t0. */
    size_t n = build_v4_udp(pkt, 1001, 443, 100);
    mqvpn_reorder_tx_peek(tx, pkt, n, t0, 1400, &p);
    mqvpn_reorder_tx_commit(tx, &p, t0);
    n = build_v4_udp(pkt, 1002, 443, 100);
    mqvpn_reorder_tx_peek(tx, pkt, n, t0, 1400, &p);
    mqvpn_reorder_tx_commit(tx, &p, t0);

    /* A new flow arrives with now_us BEFORE t0 (clock went backwards). The two
     * existing flows are NOT idle; the underflow must not evict them → RAW. */
    uint64_t t_back = t0 - 5ULL * 1000ULL * 1000ULL; /* 5s before t0 */
    n = build_v4_udp(pkt, 1003, 443, 100);
    ASSERT_EQ_INT(mqvpn_reorder_tx_peek(tx, pkt, n, t_back, 1400, &p),
                  MQVPN_REORDER_TX_RAW,
                  "backwards clock must not evict live flow -> RAW");
    ASSERT_EQ_INT(mqvpn_reorder_tx_stats(tx)->idle_evict_count, 0,
                  "no idle eviction on backwards-clock blip");
    mqvpn_reorder_tx_free(tx);
}

/* ─────────────────────────── Task 2.2: stamping ───────────────────────── */

static uint64_t
hdr_seq(const uint8_t *h)
{
    return ((uint64_t)h[2] << 40) | ((uint64_t)h[3] << 32) | ((uint64_t)h[4] << 24) |
           ((uint64_t)h[5] << 16) | ((uint64_t)h[6] << 8) | ((uint64_t)h[7]);
}

static void
test_tx_peek_commit_success(void)
{
    mqvpn_reorder_config_t c = base_cfg();
    mqvpn_reorder_tx_t *tx = mqvpn_reorder_tx_new(&c, 0x1);
    uint8_t pkt[256];
    size_t n = build_v4_udp(pkt, 5000, 443, 100);
    mqvpn_reorder_tx_peek_t p;

    ASSERT_EQ_INT(mqvpn_reorder_tx_peek(tx, pkt, n, 1, 1400, &p), MQVPN_REORDER_TX_STAMP,
                  "peek1 STAMP");
    ASSERT_EQ_INT(hdr_seq(p.hdr), 0, "peek1 seq 0");
    mqvpn_reorder_tx_commit(tx, &p, 1);

    ASSERT_EQ_INT(mqvpn_reorder_tx_peek(tx, pkt, n, 2, 1400, &p), MQVPN_REORDER_TX_STAMP,
                  "peek2 STAMP");
    ASSERT_EQ_INT(hdr_seq(p.hdr), 1, "peek2 seq 1 after commit");
    mqvpn_reorder_tx_free(tx);
}

static void
test_tx_peek_commit_failure(void)
{
    mqvpn_reorder_config_t c = base_cfg();
    mqvpn_reorder_tx_t *tx = mqvpn_reorder_tx_new(&c, 0x1);
    uint8_t pkt[256];
    size_t n = build_v4_udp(pkt, 5000, 443, 100);
    mqvpn_reorder_tx_peek_t p;

    mqvpn_reorder_tx_peek(tx, pkt, n, 1, 1400, &p);
    ASSERT_EQ_INT(hdr_seq(p.hdr), 0, "peek seq 0");
    /* Simulate send failure: do NOT commit. */
    mqvpn_reorder_tx_peek(tx, pkt, n, 2, 1400, &p);
    ASSERT_EQ_INT(hdr_seq(p.hdr), 0, "no artificial gap: still seq 0");
    mqvpn_reorder_tx_free(tx);
}

static void
test_tx_reset_marks_on_success_only(void)
{
    mqvpn_reorder_config_t c = base_cfg();
    c.reset_mark_packets = 3;
    mqvpn_reorder_tx_t *tx = mqvpn_reorder_tx_new(&c, 0x1);
    uint8_t pkt[256];
    size_t n = build_v4_udp(pkt, 5000, 443, 100);
    mqvpn_reorder_tx_peek_t p;

    /* Peek K times WITHOUT committing → reset_marks_left unchanged. */
    for (int i = 0; i < 5; i++) {
        mqvpn_reorder_tx_peek(tx, pkt, n, 1, 1400, &p);
        ASSERT_EQ_INT(mqvpn_reorder_tx_flow_reset_marks_left(p.flow), 3,
                      "reset_marks unchanged on peek-only");
    }
    /* One commit → decrement to 2. */
    mqvpn_reorder_tx_peek(tx, pkt, n, 1, 1400, &p);
    mqvpn_reorder_tx_commit(tx, &p, 1);
    ASSERT_EQ_INT(mqvpn_reorder_tx_flow_reset_marks_left(p.flow), 2,
                  "reset_marks decremented on commit");
    mqvpn_reorder_tx_free(tx);
}

static void
test_tx_first_k_have_reset_flag(void)
{
    mqvpn_reorder_config_t c = base_cfg();
    c.reset_mark_packets = 2; /* first 2 committed get FLOW_RESET */
    mqvpn_reorder_tx_t *tx = mqvpn_reorder_tx_new(&c, 0x1);
    uint8_t pkt[256];
    size_t n = build_v4_udp(pkt, 5000, 443, 100);
    mqvpn_reorder_tx_peek_t p;

    /* packet 1 */
    mqvpn_reorder_tx_peek(tx, pkt, n, 1, 1400, &p);
    ASSERT_TRUE(p.hdr[1] & MQVPN_REORDER_FLAG_RESET, "pkt1 has FLOW_RESET");
    mqvpn_reorder_tx_commit(tx, &p, 1);
    /* packet 2 */
    mqvpn_reorder_tx_peek(tx, pkt, n, 2, 1400, &p);
    ASSERT_TRUE(p.hdr[1] & MQVPN_REORDER_FLAG_RESET, "pkt2 has FLOW_RESET");
    mqvpn_reorder_tx_commit(tx, &p, 2);
    /* packet 3 → no FLOW_RESET */
    mqvpn_reorder_tx_peek(tx, pkt, n, 3, 1400, &p);
    ASSERT_TRUE(!(p.hdr[1] & MQVPN_REORDER_FLAG_RESET), "pkt3 no FLOW_RESET");
    mqvpn_reorder_tx_free(tx);
}

static void
test_tx_mtu_guard_boundary(void)
{
    mqvpn_reorder_config_t c = base_cfg();
    mqvpn_reorder_tx_t *tx = mqvpn_reorder_tx_new(&c, 0x1);
    uint8_t pkt[2048];
    mqvpn_reorder_tx_peek_t p;
    uint32_t N = 200; /* max_inner_without_reorder */

    /* inner length N-8 → 8+(N-8)==N, not > N → STAMP. */
    size_t n = (size_t)(N - 8);
    /* total inner IP packet length must equal `n`; payload = n - 28. */
    size_t built = build_v4_udp(pkt, 5000, 443, n - 28);
    ASSERT_EQ_INT(built, n, "built == N-8");
    ASSERT_EQ_INT(mqvpn_reorder_tx_peek(tx, pkt, built, 1, N, &p), MQVPN_REORDER_TX_STAMP,
                  "inner N-8 fits (no double -8)");

    /* inner length N-7 → 8+(N-7) > N → DROP_MTU. */
    n = (size_t)(N - 7);
    built = build_v4_udp(pkt, 5000, 443, n - 28);
    ASSERT_EQ_INT(built, n, "built == N-7");
    ASSERT_EQ_INT(mqvpn_reorder_tx_peek(tx, pkt, built, 1, N, &p),
                  MQVPN_REORDER_TX_DROP_MTU, "inner N-7 exceeds MTU");
    mqvpn_reorder_tx_free(tx);
}

/* n_rules==0, mode==ON → all UDP flows implicitly eligible (§15.1 fallback). */
static void
test_tx_no_rules_enabled_eligible(void)
{
    mqvpn_reorder_config_t c;
    mqvpn_reorder_config_default(&c);
    c.mode = MQVPN_REORDER_ON;
    mqvpn_reorder_tx_t *tx = mqvpn_reorder_tx_new(&c, 0x1);
    uint8_t pkt[256];
    mqvpn_reorder_tx_peek_t p;
    size_t n = build_v4_udp(pkt, 5000, 443, 100);
    ASSERT_EQ_INT(mqvpn_reorder_tx_peek(tx, pkt, n, 1, 1400, &p), MQVPN_REORDER_TX_STAMP,
                  "n_rules==0 mode==ON -> eligible STAMP");
    mqvpn_reorder_tx_free(tx);
}

/* n_rules==0, mode==OFF → master gate returns RAW. */
static void
test_tx_no_rules_disabled_raw(void)
{
    mqvpn_reorder_config_t c;
    mqvpn_reorder_config_default(&c);
    /* mode stays OFF (default). */
    mqvpn_reorder_tx_t *tx = mqvpn_reorder_tx_new(&c, 0x1);
    uint8_t pkt[256];
    mqvpn_reorder_tx_peek_t p;
    size_t n = build_v4_udp(pkt, 5000, 443, 100);
    ASSERT_EQ_INT(mqvpn_reorder_tx_peek(tx, pkt, n, 1, 1400, &p), MQVPN_REORDER_TX_RAW,
                  "n_rules==0 mode==OFF -> RAW");
    mqvpn_reorder_tx_free(tx);
}

int
main(void)
{
    test_tx_flow_create_and_get();
    test_tx_eligibility_443_bidir();
    test_tx_eligibility_dns_ineligible();
    test_tx_eligibility_unknown_ineligible();
    test_tx_eligibility_preset_profiles();
    test_tx_evict_only_idle();
    test_tx_evict_backwards_clock_no_evict();

    test_tx_peek_commit_success();
    test_tx_peek_commit_failure();
    test_tx_reset_marks_on_success_only();
    test_tx_first_k_have_reset_flag();
    test_tx_mtu_guard_boundary();
    test_tx_no_rules_enabled_eligible();
    test_tx_no_rules_disabled_raw();

    fprintf(stderr, "test_reorder_tx: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
