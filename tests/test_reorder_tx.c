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

int
main(void)
{
    test_tx_flow_create_and_get();
    test_tx_eligibility_443_bidir();
    test_tx_eligibility_dns_ineligible();
    test_tx_eligibility_unknown_ineligible();
    test_tx_evict_only_idle();

    fprintf(stderr, "test_reorder_tx: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
