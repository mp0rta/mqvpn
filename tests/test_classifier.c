// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_classifier.c — unit tests for the hybrid-mode ingress classifier (H1):
 * lane selection (TCP / DGRAM / RAW) + hybrid config default/validate.
 *
 * Build: see CMakeLists.txt (test_classifier target)
 */
#include "hybrid/classifier.h"
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

/* ── packet builders (local copies; deliberately not shared with the reorder
 *    tests — each suite owns its fixtures) ─────────────────────────────── */

/* Build a minimal IPv4 UDP packet into buf; returns total length. */
static size_t
build_v4_udp(uint8_t *buf, uint16_t sport, uint16_t dport, uint16_t frag_field,
             uint8_t proto)
{
    memset(buf, 0, 28);
    buf[0] = 0x45; /* version 4, IHL 5 */
    buf[6] = (uint8_t)(frag_field >> 8);
    buf[7] = (uint8_t)(frag_field);
    buf[9] = proto; /* protocol */
    buf[12] = 10;
    buf[13] = 0;
    buf[14] = 0;
    buf[15] = 1; /* src 10.0.0.1 */
    buf[16] = 10;
    buf[17] = 0;
    buf[18] = 0;
    buf[19] = 2; /* dst 10.0.0.2 */
    buf[20] = (uint8_t)(sport >> 8);
    buf[21] = (uint8_t)(sport); /* UDP sport */
    buf[22] = (uint8_t)(dport >> 8);
    buf[23] = (uint8_t)(dport); /* UDP dport */
    return 28;
}

/* Build a minimal IPv4 TCP packet (20 IP + 20 TCP = 40 bytes). */
static size_t
build_v4_tcp(uint8_t *buf, uint16_t sport, uint16_t dport, uint16_t frag_field)
{
    memset(buf, 0, 40);
    buf[0] = 0x45; /* version 4, IHL 5 */
    buf[6] = (uint8_t)(frag_field >> 8);
    buf[7] = (uint8_t)(frag_field);
    buf[9] = 6; /* protocol = TCP */
    buf[12] = 10;
    buf[13] = 0;
    buf[14] = 0;
    buf[15] = 1; /* src 10.0.0.1 */
    buf[16] = 10;
    buf[17] = 0;
    buf[18] = 0;
    buf[19] = 2; /* dst 10.0.0.2 */
    buf[20] = (uint8_t)(sport >> 8);
    buf[21] = (uint8_t)(sport); /* TCP sport */
    buf[22] = (uint8_t)(dport >> 8);
    buf[23] = (uint8_t)(dport); /* TCP dport */
    buf[32] = 0x50;             /* data offset = 5 (20-byte TCP header) */
    return 40;
}

/* Build a minimal IPv6 packet with the given next-header; L4 bytes zeroed
 * except ports at offset 40. Returns a length that fits a 20-byte TCP header. */
static size_t
build_v6(uint8_t *buf, uint8_t next_header, uint16_t sport, uint16_t dport)
{
    memset(buf, 0, 60);
    buf[0] = 0x60; /* version 6 */
    buf[6] = next_header;
    buf[8] = 0x20;
    buf[9] = 0x01; /* src starts 2001:... */
    buf[24] = 0x20;
    buf[25] = 0x02;
    buf[40] = (uint8_t)(sport >> 8);
    buf[41] = (uint8_t)(sport);
    buf[42] = (uint8_t)(dport >> 8);
    buf[43] = (uint8_t)(dport);
    buf[52] = 0x50; /* TCP data offset = 5, harmless for UDP */
    return 60;
}

static mqvpn_hybrid_config_t
make_pol(int enabled, mqvpn_hybrid_tcp_mode_t mode)
{
    mqvpn_hybrid_config_t pol;
    mqvpn_hybrid_config_default(&pol);
    pol.enabled = enabled;
    pol.tcp_mode = mode;
    return pol;
}

/* ── lane selection ────────────────────────────────────────────────────── */

static void
test_classify_udp_always_dgram(void)
{
    uint8_t buf[64];
    mqvpn_flow_key_t k;

    /* v4 UDP → DGRAM regardless of enabled/tcp_mode. */
    size_t n = build_v4_udp(buf, 1111, 443, 0, 17);
    mqvpn_hybrid_config_t pol = make_pol(0, MQVPN_HYBRID_TCP_RAW);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_DGRAM,
                  "v4 udp disabled+raw -> dgram");
    pol = make_pol(1, MQVPN_HYBRID_TCP_STREAM);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_DGRAM,
                  "v4 udp enabled+stream -> dgram");
    ASSERT_EQ_INT(k.proto, 17, "v4 udp key proto");
    ASSERT_EQ_INT(k.src_port, 1111, "v4 udp key sport");

    /* v6 UDP → DGRAM too. */
    n = build_v6(buf, 17, 2222, 443);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_DGRAM,
                  "v6 udp -> dgram");
    ASSERT_EQ_INT(k.ip_version, 6, "v6 udp key version");
}

static void
test_classify_v4_tcp_gates(void)
{
    uint8_t buf[64];
    mqvpn_flow_key_t k;
    size_t n = build_v4_tcp(buf, 2222, 80, 0);

    /* enabled + STREAM → TCP lane. */
    mqvpn_hybrid_config_t pol = make_pol(1, MQVPN_HYBRID_TCP_STREAM);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_TCP,
                  "v4 tcp enabled+stream -> tcp");
    ASSERT_EQ_INT(k.proto, 6, "v4 tcp key proto");
    ASSERT_EQ_INT(k.ip_version, 4, "v4 tcp key version");
    ASSERT_EQ_INT(k.src_port, 2222, "v4 tcp key sport");

    /* enabled + AUTO → TCP lane (static gate passes; per-flow auto is later). */
    pol = make_pol(1, MQVPN_HYBRID_TCP_AUTO);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_TCP,
                  "v4 tcp enabled+auto -> tcp");

    /* enabled + RAW → RAW. */
    pol = make_pol(1, MQVPN_HYBRID_TCP_RAW);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_RAW,
                  "v4 tcp enabled+raw -> raw");

    /* disabled + STREAM → RAW. */
    pol = make_pol(0, MQVPN_HYBRID_TCP_STREAM);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_RAW,
                  "v4 tcp disabled+stream -> raw");
}

static void
test_classify_v6_tcp_raw_v1(void)
{
    uint8_t buf[64];
    mqvpn_flow_key_t k;
    size_t n = build_v6(buf, 6, 4444, 8080);
    mqvpn_hybrid_config_t pol = make_pol(1, MQVPN_HYBRID_TCP_STREAM);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_RAW,
                  "v6 tcp enabled+stream -> raw (v1)");
}

static void
test_classify_fragments_and_other_raw(void)
{
    uint8_t buf[64];
    mqvpn_flow_key_t k;
    mqvpn_hybrid_config_t pol = make_pol(1, MQVPN_HYBRID_TCP_STREAM);

    /* IPv4 first fragment (MF=1) carrying TCP → RAW. */
    size_t n = build_v4_tcp(buf, 2222, 80, 0x2000);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_RAW,
                  "v4 tcp MF fragment -> raw");

    /* IPv4 non-first fragment (offset != 0) → RAW. */
    n = build_v4_tcp(buf, 2222, 80, 0x0001);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_RAW,
                  "v4 non-first fragment -> raw");

    /* IPv6 Fragment ext header → RAW. */
    n = build_v6(buf, 44, 0, 0);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_RAW,
                  "v6 fragment ext -> raw");

    /* ICMPv4 → RAW. */
    n = build_v4_udp(buf, 0, 0, 0, 1);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, &k), MQVPN_LANE_RAW,
                  "v4 icmp -> raw");
}

static void
test_classify_malformed_raw(void)
{
    uint8_t buf[64];
    mqvpn_flow_key_t k;
    mqvpn_hybrid_config_t pol = make_pol(1, MQVPN_HYBRID_TCP_STREAM);

    /* Truncated IPv4 (10 bytes) → RAW. */
    build_v4_udp(buf, 1111, 443, 0, 17);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, 10, &pol, &k), MQVPN_LANE_RAW,
                  "v4 truncated -> raw");

    /* Truncated v6 ext chain (hopopts header cut off) → RAW. */
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x60;
    buf[6] = 0; /* next header = Hop-by-Hop, but ext header truncated */
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, 41, &pol, &k), MQVPN_LANE_RAW,
                  "v6 truncated ext chain -> raw");
}

static void
test_classify_null_out_key(void)
{
    uint8_t buf[64];
    mqvpn_hybrid_config_t pol = make_pol(1, MQVPN_HYBRID_TCP_STREAM);

    /* out_key == NULL must be crash-free for both happy verdicts. */
    size_t n = build_v4_tcp(buf, 2222, 80, 0);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, NULL), MQVPN_LANE_TCP,
                  "tcp with NULL out_key");
    n = build_v4_udp(buf, 1111, 443, 0, 17);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, &pol, NULL), MQVPN_LANE_DGRAM,
                  "udp with NULL out_key");
}

static void
test_classify_null_policy(void)
{
    uint8_t buf[64];
    mqvpn_flow_key_t k;
    size_t n = build_v4_tcp(buf, 2222, 80, 0);
    ASSERT_EQ_INT(mqvpn_hybrid_classify(buf, n, NULL, &k), MQVPN_LANE_RAW,
                  "v4 tcp NULL policy -> raw (defensive)");
}

/* ── config default / validate ─────────────────────────────────────────── */

static void
test_hybrid_config_default(void)
{
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    ASSERT_EQ_INT(cfg.enabled, 0, "default enabled");
    ASSERT_EQ_INT(cfg.tcp_mode, MQVPN_HYBRID_TCP_AUTO, "default tcp_mode auto");
    ASSERT_EQ_INT(cfg.tcp_max_flows, 256, "default tcp_max_flows");
    ASSERT_EQ_INT(cfg.tcp_idle_timeout_sec, 300, "default tcp_idle_timeout_sec");
    ASSERT_EQ_INT(cfg.tcp_max_global_flows, MQVPN_TCP_MAX_GLOBAL_FLOWS_DEFAULT,
                  "default tcp_max_global_flows");
}

static void
test_hybrid_config_validate(void)
{
    mqvpn_hybrid_config_t cfg;
    mqvpn_hybrid_config_default(&cfg);
    ASSERT_EQ_INT(mqvpn_hybrid_config_validate(&cfg), 0, "validate default ok");

    cfg.tcp_max_flows = 0;
    ASSERT_EQ_INT(mqvpn_hybrid_config_validate(&cfg), -1, "validate max_flows=0 -> -1");

    mqvpn_hybrid_config_default(&cfg);
    cfg.tcp_max_global_flows = 0;
    ASSERT_EQ_INT(mqvpn_hybrid_config_validate(&cfg), -1,
                  "validate max_global_flows=0 -> -1");

    ASSERT_EQ_INT(mqvpn_hybrid_config_validate(NULL), -1, "validate NULL -> -1");

    mqvpn_hybrid_config_default(&cfg);
    cfg.tcp_mode = (mqvpn_hybrid_tcp_mode_t)(MQVPN_HYBRID_TCP_AUTO + 1);
    ASSERT_EQ_INT(mqvpn_hybrid_config_validate(&cfg), -1,
                  "validate tcp_mode out of range -> -1");
}

int
main(void)
{
    test_classify_udp_always_dgram();
    test_classify_v4_tcp_gates();
    test_classify_v6_tcp_raw_v1();
    test_classify_fragments_and_other_raw();
    test_classify_malformed_raw();
    test_classify_null_out_key();
    test_classify_null_policy();

    test_hybrid_config_default();
    test_hybrid_config_validate();

    fprintf(stderr, "test_classifier: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
