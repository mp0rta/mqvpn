// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_reorder_gate.c — unit tests for src/reorder_gate.h: the shared
 * STAMP/RAW/DROP_MTU decision (mqvpn_rgate_decide) and the PTB token-bucket
 * rate limiter (mqvpn_ptb_bucket_*), extracted from the near-identical
 * TUN-ingress blocks in mqvpn_client.c and mqvpn_server.c.
 *
 * Build: see CMakeLists.txt (test_reorder_gate target). Links reorder_tx.c
 * (for the peek mqvpn_rgate_decide wraps) + icmp.c (for the PTB packet
 * mqvpn_rgate_send_ptb emits) + log.c.
 */
#include "reorder_gate.h"

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

/* Build a minimal IPv4 UDP packet with `payload` bytes of UDP payload after
 * the 8-byte UDP header (mirrors test_reorder_tx.c's build_v4_udp). */
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
    c.rules[0].proto = 17;
    c.rules[0].port = 443;
    c.rules[0].profile = MQVPN_RPROF_QUIC_BULK;
    c.n_rules = 1;
    return c;
}

/* ─────────────────────────── mqvpn_rgate_decide ────────────────────────── */

/* No reorder engine at all (reorder_tx==NULL): falls straight to the RAW /
 * oversize check, same as "reorder disabled" callers. */
static void
test_decide_no_reorder_tx_raw(void)
{
    uint8_t pkt[256];
    size_t n = build_v4_udp(pkt, 5000, 443, 100);
    mqvpn_reorder_tx_peek_t peek = {0};
    size_t mtu = 0;
    mqvpn_rgate_verdict_t v =
        mqvpn_rgate_decide(NULL, 1, MQVPN_REORDER_ON, pkt, n, 1, 1400, &peek, &mtu);
    ASSERT_EQ_INT(v, MQVPN_RGATE_RAW, "no reorder_tx -> RAW");
}

/* Peer hasn't advertised reorder support: stays RAW even with a live engine
 * and an eligible flow (§19.3/§19.4 peer gate). */
static void
test_decide_peer_unsupported_raw(void)
{
    mqvpn_reorder_config_t c = base_cfg();
    mqvpn_reorder_tx_t *tx = mqvpn_reorder_tx_new(&c, 0x1);
    uint8_t pkt[256];
    size_t n = build_v4_udp(pkt, 5000, 443, 100);
    mqvpn_reorder_tx_peek_t peek = {0};
    size_t mtu = 0;
    mqvpn_rgate_verdict_t v = mqvpn_rgate_decide(tx, /*peer_reorder_supported=*/0, c.mode,
                                                 pkt, n, 1, 1400, &peek, &mtu);
    ASSERT_EQ_INT(v, MQVPN_RGATE_RAW, "peer unsupported -> RAW");
    mqvpn_reorder_tx_free(tx);
}

/* Eligible flow, everything gated open, fits budget: STAMP verdict (the
 * caller derives do_stamp from it), peek->hdr filled (passthrough of
 * mqvpn_reorder_tx_peek's own STAMP path). */
static void
test_decide_stamp_passthrough(void)
{
    mqvpn_reorder_config_t c = base_cfg();
    mqvpn_reorder_tx_t *tx = mqvpn_reorder_tx_new(&c, 0x1);
    uint8_t pkt[256];
    size_t n = build_v4_udp(pkt, 5000, 443, 100);
    mqvpn_reorder_tx_peek_t peek = {0};
    size_t mtu = 0;
    mqvpn_rgate_verdict_t v =
        mqvpn_rgate_decide(tx, 1, c.mode, pkt, n, 1, 1400, &peek, &mtu);
    ASSERT_EQ_INT(v, MQVPN_RGATE_STAMP, "eligible + fits budget -> STAMP");
    ASSERT_EQ_INT(peek.action, MQVPN_REORDER_TX_STAMP, "peek.action STAMP");
    mqvpn_reorder_tx_free(tx);
}

/* Stamped form would exceed the DATAGRAM budget (8+len > udp_mss):
 * MQVPN_RGATE_DROP_REORDER_MTU with out_mtu = udp_mss - HDR_LEN. */
static void
test_decide_drop_reorder_mtu(void)
{
    mqvpn_reorder_config_t c = base_cfg();
    mqvpn_reorder_tx_t *tx = mqvpn_reorder_tx_new(&c, 0x1);
    uint32_t N = 200;
    uint8_t pkt[2048];
    /* inner length N-7 -> 8+(N-7) > N -> DROP_MTU (mirrors
     * test_reorder_tx.c's test_tx_mtu_guard_boundary). */
    size_t n = (size_t)(N - 7);
    size_t built = build_v4_udp(pkt, 5000, 443, n - 28);
    ASSERT_EQ_INT(built, n, "built == N-7");

    mqvpn_reorder_tx_peek_t peek = {0};
    size_t mtu = 0;
    mqvpn_rgate_verdict_t v =
        mqvpn_rgate_decide(tx, 1, c.mode, pkt, built, 1, N, &peek, &mtu);
    ASSERT_EQ_INT(v, MQVPN_RGATE_DROP_REORDER_MTU,
                  "over stamped budget -> DROP_REORDER_MTU");
    ASSERT_EQ_INT(mtu, N - MQVPN_REORDER_HDR_LEN, "out_mtu == udp_mss - HDR_LEN");
    mqvpn_reorder_tx_free(tx);
}

/* Reorder disabled (mode OFF) but the bare packet itself exceeds udp_mss:
 * MQVPN_RGATE_DROP_RAW_MTU with out_mtu = udp_mss (RAW-oversize branch). */
static void
test_decide_drop_raw_mtu(void)
{
    uint8_t pkt[2048];
    size_t n = build_v4_udp(pkt, 5000, 443, 300); /* total len 328 */
    mqvpn_reorder_tx_peek_t peek = {0};
    size_t mtu = 0;
    mqvpn_rgate_verdict_t v = mqvpn_rgate_decide(NULL, 0, MQVPN_REORDER_OFF, pkt, n, 1,
                                                 200 /* udp_mss < n */, &peek, &mtu);
    ASSERT_EQ_INT(v, MQVPN_RGATE_DROP_RAW_MTU,
                  "len > udp_mss, no reorder -> DROP_RAW_MTU");
    ASSERT_EQ_INT(mtu, 200, "out_mtu == udp_mss");

    /* Boundary: len == udp_mss is NOT oversize — must proceed RAW with no
     * PTB (strict `len > udp_mss` comparison, same as the old inline code). */
    peek = (mqvpn_reorder_tx_peek_t){0};
    mtu = 0;
    v = mqvpn_rgate_decide(NULL, 0, MQVPN_REORDER_OFF, pkt, n, 1, (uint32_t)n, &peek,
                           &mtu);
    ASSERT_EQ_INT(v, MQVPN_RGATE_RAW, "len == udp_mss boundary -> RAW, no PTB");
}

/* udp_mss==0 (e.g. dgram_mss not yet known): both gates are udp_mss>0
 * guarded, so this always falls through to plain RAW regardless of len. */
static void
test_decide_zero_mss_raw(void)
{
    uint8_t pkt[2048];
    size_t n = build_v4_udp(pkt, 5000, 443, 300);
    mqvpn_reorder_tx_peek_t peek = {0};
    size_t mtu = 0;
    mqvpn_rgate_verdict_t v =
        mqvpn_rgate_decide(NULL, 0, MQVPN_REORDER_OFF, pkt, n, 1, 0, &peek, &mtu);
    ASSERT_EQ_INT(v, MQVPN_RGATE_RAW, "udp_mss==0 -> RAW (no MTU gate possible)");
}

/* ─────────────────────────── PTB token bucket ──────────────────────────── */

static void
test_bucket_init_starts_full(void)
{
    mqvpn_ptb_bucket_t b;
    mqvpn_ptb_bucket_init(&b);
    int allowed = 0;
    for (int i = 0; i < MQVPN_PTB_RATE_LIMIT; i++)
        if (mqvpn_ptb_bucket_allow(&b, 5000)) allowed++;
    ASSERT_EQ_INT(allowed, MQVPN_PTB_RATE_LIMIT, "bucket starts with RATE_LIMIT tokens");
}

/* Exhausting the bucket within the same 1000ms window denies further sends;
 * a later now_ms crossing the 1000ms boundary refills it. */
static void
test_bucket_exhaustion_and_refill(void)
{
    mqvpn_ptb_bucket_t b;
    mqvpn_ptb_bucket_init(&b);
    int64_t t0 = 10000;
    for (int i = 0; i < MQVPN_PTB_RATE_LIMIT; i++)
        ASSERT_TRUE(mqvpn_ptb_bucket_allow(&b, t0), "token available within budget");
    ASSERT_TRUE(!mqvpn_ptb_bucket_allow(&b, t0), "exhausted: same instant denied");
    ASSERT_TRUE(!mqvpn_ptb_bucket_allow(&b, t0 + 999),
                "exhausted: still within window denied");
    ASSERT_TRUE(mqvpn_ptb_bucket_allow(&b, t0 + 1000),
                "window elapsed: refilled, allowed");
}

/* ─────────────────────── mqvpn_rgate_send_ptb gating ────────────────────── */

static struct {
    int called;
    uint8_t buf[2048];
    size_t len;
} g_cap;

static void
capture(const uint8_t *pkt, size_t len, void *ctx)
{
    (void)ctx;
    g_cap.called++;
    g_cap.len = len;
    if (len <= sizeof(g_cap.buf)) memcpy(g_cap.buf, pkt, len);
}

static void
reset_cap(void)
{
    memset(&g_cap, 0, sizeof(g_cap));
}

/* addr_ok==0 must skip the send AND not consume a token (mirrors the
 * historical `addr_assigned && ptb_rate_allow(...)` short-circuit). */
static void
test_send_ptb_addr_not_ok_no_token_consumed(void)
{
    mqvpn_ptb_bucket_t b;
    mqvpn_ptb_bucket_init(&b);
    uint8_t pkt[64];
    size_t n = build_v4_udp(pkt, 5000, 443, 10);
    uint8_t src4[4] = {10, 0, 0, 1};

    reset_cap();
    int sent = mqvpn_rgate_send_ptb(&b, 1000, 4, /*addr_ok=*/0, src4, 1200, capture, NULL,
                                    pkt, n);
    ASSERT_EQ_INT(sent, 0, "addr_ok==0 -> not sent");
    ASSERT_EQ_INT(g_cap.called, 0, "tun_output not invoked");

    /* Bucket must be untouched: still MQVPN_PTB_RATE_LIMIT tokens available. */
    int allowed = 0;
    for (int i = 0; i < MQVPN_PTB_RATE_LIMIT; i++)
        if (mqvpn_ptb_bucket_allow(&b, 1000)) allowed++;
    ASSERT_EQ_INT(allowed, MQVPN_PTB_RATE_LIMIT,
                  "no token consumed by the skipped attempt");
}

/* addr_ok==1 sends via mqvpn_icmp_send_v4 (type 3 code 4, RFC 792 PTB) and
 * consumes exactly one token. */
static void
test_send_ptb_v4_sends_and_consumes_token(void)
{
    mqvpn_ptb_bucket_t b;
    mqvpn_ptb_bucket_init(&b);
    uint8_t pkt[64];
    size_t n = build_v4_udp(pkt, 5000, 443, 10);
    uint8_t src4[4] = {10, 0, 0, 1};

    reset_cap();
    int sent = mqvpn_rgate_send_ptb(&b, 1000, 4, 1, src4, 1200, capture, NULL, pkt, n);
    ASSERT_EQ_INT(sent, 1, "addr_ok=1 within budget -> sent");
    ASSERT_EQ_INT(g_cap.called, 1, "tun_output invoked once");
    ASSERT_TRUE(g_cap.len >= 20 + 8, "ICMP packet has IP+ICMP headers");
    ASSERT_EQ_INT(g_cap.buf[9], 1, "IP protocol == ICMP(1)");
    ASSERT_EQ_INT(g_cap.buf[20], 3, "ICMP type == 3 (Dest Unreachable)");
    ASSERT_EQ_INT(g_cap.buf[21], 4, "ICMP code == 4 (Frag Needed / PTB)");

    /* MQVPN_PTB_RATE_LIMIT - 1 tokens should remain. */
    int allowed = 0;
    for (int i = 0; i < MQVPN_PTB_RATE_LIMIT; i++)
        if (mqvpn_ptb_bucket_allow(&b, 1000)) allowed++;
    ASSERT_EQ_INT(allowed, MQVPN_PTB_RATE_LIMIT - 1, "exactly one token consumed");
}

/* v6 path: mqvpn_icmp_send_v6 with type 2 code 0 (Packet Too Big). */
static void
test_send_ptb_v6_sends(void)
{
    mqvpn_ptb_bucket_t b;
    mqvpn_ptb_bucket_init(&b);
    uint8_t pkt[64];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x60;
    pkt[6] = 17; /* next header UDP */
    pkt[7] = 64; /* hop limit */
    size_t n = 48;
    uint8_t src6[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

    reset_cap();
    int sent = mqvpn_rgate_send_ptb(&b, 1000, 6, 1, src6, 1200, capture, NULL, pkt, n);
    ASSERT_EQ_INT(sent, 1, "v6 addr_ok=1 -> sent");
    ASSERT_EQ_INT(g_cap.called, 1, "tun_output invoked once");
    ASSERT_EQ_INT(g_cap.buf[6], 58, "next header == ICMPv6(58)");
    ASSERT_EQ_INT(g_cap.buf[40], 2, "ICMPv6 type == 2 (Packet Too Big)");
    ASSERT_EQ_INT(g_cap.buf[41], 0, "ICMPv6 code == 0");
}

/* Exhausted bucket: returns 0 and never touches the output sink (the ICMP
 * builder must not run at all when rate-limited). */
static void
test_send_ptb_exhausted_bucket_no_send(void)
{
    mqvpn_ptb_bucket_t b;
    mqvpn_ptb_bucket_init(&b);
    uint8_t pkt[64];
    size_t n = build_v4_udp(pkt, 5000, 443, 10);
    uint8_t src4[4] = {10, 0, 0, 1};

    /* Drain all tokens within one window. */
    for (int i = 0; i < MQVPN_PTB_RATE_LIMIT; i++)
        (void)mqvpn_ptb_bucket_allow(&b, 1000);

    reset_cap();
    int sent = mqvpn_rgate_send_ptb(&b, 1000, 4, 1, src4, 1200, capture, NULL, pkt, n);
    ASSERT_EQ_INT(sent, 0, "exhausted bucket -> not sent");
    ASSERT_EQ_INT(g_cap.called, 0, "tun_output NOT invoked when rate-limited");
}

/* v4 mtu above the 16-bit ICMP field silently clamps to 0xFFFF (bytes 6-7 of
 * the ICMP header); v6 carries the full 32-bit value so no clamp there. */
static void
test_send_ptb_v4_mtu_clamp(void)
{
    mqvpn_ptb_bucket_t b;
    mqvpn_ptb_bucket_init(&b);
    uint8_t pkt[64];
    size_t n = build_v4_udp(pkt, 5000, 443, 10);
    uint8_t src4[4] = {10, 0, 0, 1};

    reset_cap();
    int sent = mqvpn_rgate_send_ptb(&b, 1000, 4, 1, src4, 0x10000 /* > 0xFFFF */, capture,
                                    NULL, pkt, n);
    ASSERT_EQ_INT(sent, 1, "oversized mtu still sends");
    ASSERT_EQ_INT(g_cap.called, 1, "tun_output invoked once");
    /* ICMP header starts at offset 20; MTU is ICMP bytes 6-7. */
    ASSERT_EQ_INT(g_cap.buf[20 + 6], 0xFF, "clamped MTU hi byte == 0xFF");
    ASSERT_EQ_INT(g_cap.buf[20 + 7], 0xFF, "clamped MTU lo byte == 0xFF");
}

int
main(void)
{
    test_decide_no_reorder_tx_raw();
    test_decide_peer_unsupported_raw();
    test_decide_stamp_passthrough();
    test_decide_drop_reorder_mtu();
    test_decide_drop_raw_mtu();
    test_decide_zero_mss_raw();

    test_bucket_init_starts_full();
    test_bucket_exhaustion_and_refill();

    test_send_ptb_addr_not_ok_no_token_consumed();
    test_send_ptb_v4_sends_and_consumes_token();
    test_send_ptb_v6_sends();
    test_send_ptb_exhausted_bucket_no_send();
    test_send_ptb_v4_mtu_clamp();

    fprintf(stderr, "test_reorder_gate: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
