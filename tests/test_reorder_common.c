// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_reorder_common.c — unit tests for the reorder foundation header:
 *   wire header v1 codec + type dispatch (§8.1/§8.2/§8.3, §7)
 *
 * Build: see CMakeLists.txt (test_reorder_common target)
 */
#include "reorder.h"
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

#define ASSERT_EQ_U64(a, b, msg)                                                       \
    do {                                                                               \
        if ((uint64_t)(a) == (uint64_t)(b)) {                                          \
            g_pass++;                                                                  \
        } else {                                                                       \
            g_fail++;                                                                  \
            fprintf(stderr, "FAIL [%s]: %llu != %llu\n", msg, (unsigned long long)(a), \
                    (unsigned long long)(b));                                          \
        }                                                                              \
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

/* ─────────────────────────── Task 1.1: wire codec ─────────────────────────── */

static void
test_wire_roundtrip(void)
{
    uint8_t buf[MQVPN_REORDER_HDR_LEN];
    mqvpn_reorder_wire_encode(buf, MQVPN_REORDER_TYPE_V1, MQVPN_REORDER_FLAG_RESET,
                              0xFFFFFFFFFFULL);
    uint8_t type = 0, flags = 0;
    uint64_t seq = 0;
    int rc = mqvpn_reorder_wire_decode(buf, sizeof(buf), &type, &flags, &seq);
    ASSERT_EQ_INT(rc, 0, "wire_roundtrip decode rc");
    ASSERT_EQ_INT(type, MQVPN_REORDER_TYPE_V1, "wire_roundtrip type");
    ASSERT_EQ_INT(flags, MQVPN_REORDER_FLAG_RESET, "wire_roundtrip flags");
    ASSERT_EQ_U64(seq, 0xFFFFFFFFFFULL, "wire_roundtrip seq");
}

static void
test_wire_seq_48bit(void)
{
    /* seq has high 16 bits set; only the low 48 bits should survive. */
    uint8_t buf[MQVPN_REORDER_HDR_LEN];
    uint64_t in = 0xABCD123456789AULL; /* high 16 = 0xABCD */
    mqvpn_reorder_wire_encode(buf, MQVPN_REORDER_TYPE_V1, 0, in);
    uint8_t type = 0, flags = 0;
    uint64_t seq = 0;
    mqvpn_reorder_wire_decode(buf, sizeof(buf), &type, &flags, &seq);
    ASSERT_EQ_U64(seq, in & 0xFFFFFFFFFFFFULL, "wire_seq_48bit low-48");
    ASSERT_TRUE((seq >> 48) == 0, "wire_seq_48bit high bits zero");
}

static void
test_wire_dispatch_raw_v4(void)
{
    ASSERT_EQ_INT(mqvpn_reorder_classify_byte(0x45), MQVPN_REORDER_KIND_RAW,
                  "dispatch raw v4");
}

static void
test_wire_dispatch_raw_v6(void)
{
    ASSERT_EQ_INT(mqvpn_reorder_classify_byte(0x60), MQVPN_REORDER_KIND_RAW,
                  "dispatch raw v6");
}

static void
test_wire_dispatch_reorder(void)
{
    ASSERT_EQ_INT(mqvpn_reorder_classify_byte(0x01), MQVPN_REORDER_KIND_REORDER_V1,
                  "dispatch reorder v1");
}

static void
test_wire_dispatch_unknown(void)
{
    ASSERT_EQ_INT(mqvpn_reorder_classify_byte(0x02), MQVPN_REORDER_KIND_UNKNOWN,
                  "dispatch unknown");
}

static void
test_wire_decode_short(void)
{
    uint8_t buf[7] = {0};
    uint8_t type = 0, flags = 0;
    uint64_t seq = 0;
    int rc = mqvpn_reorder_wire_decode(buf, sizeof(buf), &type, &flags, &seq);
    ASSERT_EQ_INT(rc, -1, "wire_decode_short rc");
}

/* ─────────────────────── Task 1.2: 5-tuple flow key ───────────────────────── */

static mqvpn_flow_key_t
make_v4_key(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport)
{
    mqvpn_flow_key_t k;
    memset(&k, 0, sizeof(k));
    k.ip_version = 4;
    k.proto = 17;
    k.src_port = sport;
    k.dst_port = dport;
    k.src_ip[0] = (uint8_t)(saddr >> 24);
    k.src_ip[1] = (uint8_t)(saddr >> 16);
    k.src_ip[2] = (uint8_t)(saddr >> 8);
    k.src_ip[3] = (uint8_t)(saddr);
    k.dst_ip[0] = (uint8_t)(daddr >> 24);
    k.dst_ip[1] = (uint8_t)(daddr >> 16);
    k.dst_ip[2] = (uint8_t)(daddr >> 8);
    k.dst_ip[3] = (uint8_t)(daddr);
    return k;
}

static void
test_flowkey_eq(void)
{
    mqvpn_flow_key_t a = make_v4_key(0x0A000001, 0x0A000002, 1111, 443);
    mqvpn_flow_key_t b = make_v4_key(0x0A000001, 0x0A000002, 1111, 443);
    ASSERT_EQ_INT(mqvpn_flow_key_eq(&a, &b), 1, "flowkey_eq identical");

    /* swap src/dst (addr + port): forward vs reverse must be distinct */
    mqvpn_flow_key_t rev = make_v4_key(0x0A000002, 0x0A000001, 443, 1111);
    ASSERT_EQ_INT(mqvpn_flow_key_eq(&a, &rev), 0, "flowkey_eq reversed unequal");
}

static void
test_flowkey_v4_v6_distinct(void)
{
    mqvpn_flow_key_t a = make_v4_key(0x0A000001, 0x0A000002, 1111, 443);
    mqvpn_flow_key_t b = a;
    b.ip_version = 6; /* same ports, different ip_version */
    ASSERT_EQ_INT(mqvpn_flow_key_eq(&a, &b), 0, "flowkey v4 vs v6 distinct");
}

static void
test_flowkey_hash_stable(void)
{
    mqvpn_flow_key_t a = make_v4_key(0x0A000001, 0x0A000002, 1111, 443);
    uint64_t seed = 0x1234567890ABCDEFULL;
    uint64_t h1 = mqvpn_flow_key_hash(&a, seed);
    uint64_t h2 = mqvpn_flow_key_hash(&a, seed);
    ASSERT_EQ_U64(h1, h2, "flowkey_hash stable same key+seed");
}

static void
test_flowkey_hash_distinct(void)
{
    mqvpn_flow_key_t a = make_v4_key(0x0A000001, 0x0A000002, 1111, 443);
    mqvpn_flow_key_t b =
        make_v4_key(0x0A000001, 0x0A000002, 1111, 444); /* dst_port differs */
    uint64_t seed = 0x1234567890ABCDEFULL;

    /* Different keys, same seed -> different hashes. */
    ASSERT_TRUE(mqvpn_flow_key_hash(&a, seed) != mqvpn_flow_key_hash(&b, seed),
                "flowkey_hash distinct keys same seed differ");

    /* Same key, different seeds -> different hashes (seed is actually mixed in). */
    ASSERT_TRUE(mqvpn_flow_key_hash(&a, seed) != mqvpn_flow_key_hash(&a, seed ^ 0x1ULL),
                "flowkey_hash same key different seeds differ");
}

/* ─────────────────────── Task 1.3: config struct ──────────────────────────── */

static void
test_cfg_defaults(void)
{
    mqvpn_reorder_config_t c;
    mqvpn_reorder_config_default(&c);
    ASSERT_EQ_INT(c.max_wait_ms, 30, "cfg max_wait_ms");
    ASSERT_EQ_INT(c.cap_packets_per_flow, 1024, "cfg cap_packets_per_flow");
    ASSERT_EQ_INT(c.classify_window, 64, "cfg classify_window");
    ASSERT_EQ_INT(c.ack_demote_max_large_packets, 3, "cfg ack_demote_max_large");
    ASSERT_EQ_INT(c.small_packet_threshold_bytes, 200, "cfg small_threshold");
    ASSERT_EQ_INT(c.reset_mark_packets, 8, "cfg reset_mark_packets");
    ASSERT_EQ_INT(c.reset_idle_grace_ms, 10000, "cfg reset_idle_grace_ms");
    ASSERT_EQ_INT(c.max_flows, 65536, "cfg max_flows");
    ASSERT_EQ_U64(c.global_max_buffer_bytes, 67108864ULL, "cfg global_max_bytes");
    ASSERT_EQ_INT(c.ingress_idle_timeout_sec, 30, "cfg ingress_idle");
    ASSERT_EQ_INT(c.egress_idle_timeout_sec, 300, "cfg egress_idle");
    ASSERT_EQ_U64(c.max_buffer_bytes_per_flow, 1572864ULL, "cfg max_bytes_per_flow");
    ASSERT_EQ_INT(c.mode, MQVPN_REORDER_OFF, "cfg mode off");
    ASSERT_EQ_INT(c.n_rules, 0, "cfg n_rules");
    ASSERT_EQ_INT(c.eval_force_no_demotion, 0, "cfg eval_force_no_demotion");
}

static void
test_cfg_validate_idle_order(void)
{
    mqvpn_reorder_config_t c;
    mqvpn_reorder_config_default(&c);
    c.ingress_idle_timeout_sec = c.egress_idle_timeout_sec; /* >= */
    ASSERT_EQ_INT(mqvpn_reorder_config_validate(&c), -1,
                  "cfg validate ingress>=egress -> -1");
}

static void
test_cfg_validate_cap_pow2(void)
{
    mqvpn_reorder_config_t c;
    mqvpn_reorder_config_default(&c);
    c.cap_packets_per_flow = 1000; /* not a power of two */
    ASSERT_EQ_INT(mqvpn_reorder_config_validate(&c), -1, "cfg validate cap !pow2 -> -1");
}

static void
test_cfg_validate_ok(void)
{
    mqvpn_reorder_config_t c;
    mqvpn_reorder_config_default(&c);
    ASSERT_EQ_INT(mqvpn_reorder_config_validate(&c), 0, "cfg validate default ok");
}

/* ──────────────── Task 2 (shared): inner-IP 5-tuple parser ─────────────────
 *
 * mqvpn_reorder_parse_5tuple() lives in reorder.h and is used by both tx and rx,
 * so its unit tests live here with the other reorder.h coverage.
 */

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

static void
test_parse_v4_udp(void)
{
    uint8_t buf[64];
    size_t n = build_v4_udp(buf, 1111, 443, 0, 17);
    mqvpn_flow_key_t k;
    int rc = mqvpn_reorder_parse_5tuple(buf, n, &k);
    ASSERT_EQ_INT(rc, 0, "parse v4 udp rc");
    ASSERT_EQ_INT(k.ip_version, 4, "parse v4 version");
    ASSERT_EQ_INT(k.proto, 17, "parse v4 proto");
    ASSERT_EQ_INT(k.src_port, 1111, "parse v4 sport");
    ASSERT_EQ_INT(k.dst_port, 443, "parse v4 dport");
    ASSERT_EQ_INT(k.src_ip[3], 1, "parse v4 src ip");
    ASSERT_EQ_INT(k.dst_ip[3], 2, "parse v4 dst ip");
}

static void
test_parse_v4_fragment_fails(void)
{
    uint8_t buf[64];
    mqvpn_flow_key_t k;
    /* MF bit set */
    size_t n = build_v4_udp(buf, 1111, 443, 0x2000, 17);
    ASSERT_EQ_INT(mqvpn_reorder_parse_5tuple(buf, n, &k), -1, "parse v4 MF fails");
    /* fragment offset != 0 */
    n = build_v4_udp(buf, 1111, 443, 0x0001, 17);
    ASSERT_EQ_INT(mqvpn_reorder_parse_5tuple(buf, n, &k), -1, "parse v4 offset fails");
}

static void
test_parse_v4_tcp_fails(void)
{
    uint8_t buf[64];
    mqvpn_flow_key_t k;
    size_t n = build_v4_udp(buf, 1111, 443, 0, 6 /* TCP */);
    ASSERT_EQ_INT(mqvpn_reorder_parse_5tuple(buf, n, &k), -1, "parse v4 tcp fails");
}

static void
test_parse_v4_truncated_fails(void)
{
    uint8_t buf[64];
    mqvpn_flow_key_t k;
    build_v4_udp(buf, 1111, 443, 0, 17);
    /* 20-byte IP header present but UDP header truncated */
    ASSERT_EQ_INT(mqvpn_reorder_parse_5tuple(buf, 22, &k), -1,
                  "parse v4 truncated fails");
    ASSERT_EQ_INT(mqvpn_reorder_parse_5tuple(buf, 5, &k), -1, "parse v4 too short fails");
}

static void
test_parse_v6_udp(void)
{
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x60; /* version 6 */
    buf[6] = 17;   /* next header = UDP */
    buf[8] = 0x20;
    buf[9] = 0x01; /* src starts 2001:... */
    buf[24] = 0x20;
    buf[25] = 0x02;
    buf[40] = (uint8_t)(2222 >> 8);
    buf[41] = (uint8_t)(2222); /* sport */
    buf[42] = (uint8_t)(443 >> 8);
    buf[43] = (uint8_t)(443); /* dport */
    mqvpn_flow_key_t k;
    int rc = mqvpn_reorder_parse_5tuple(buf, 48, &k);
    ASSERT_EQ_INT(rc, 0, "parse v6 udp rc");
    ASSERT_EQ_INT(k.ip_version, 6, "parse v6 version");
    ASSERT_EQ_INT(k.src_port, 2222, "parse v6 sport");
    ASSERT_EQ_INT(k.dst_port, 443, "parse v6 dport");
    ASSERT_EQ_INT(k.src_ip[0], 0x20, "parse v6 src ip");
}

static void
test_parse_v6_with_hopopts_udp(void)
{
    uint8_t buf[80];
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x60;
    buf[6] = 0; /* next header = Hop-by-Hop Options */
    /* Hop-by-Hop ext header at offset 40: next=UDP, hdr_ext_len=0 → 8 bytes */
    buf[40] = 17; /* next header = UDP */
    buf[41] = 0;  /* hdr_ext_len: 8 bytes total */
    /* UDP header at offset 48 */
    buf[48] = (uint8_t)(3333 >> 8);
    buf[49] = (uint8_t)(3333);
    buf[50] = (uint8_t)(443 >> 8);
    buf[51] = (uint8_t)(443);
    mqvpn_flow_key_t k;
    int rc = mqvpn_reorder_parse_5tuple(buf, 56, &k);
    ASSERT_EQ_INT(rc, 0, "parse v6 hopopts udp rc");
    ASSERT_EQ_INT(k.src_port, 3333, "parse v6 hopopts sport");
    ASSERT_EQ_INT(k.dst_port, 443, "parse v6 hopopts dport");
}

static void
test_parse_v6_fragment_fails(void)
{
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x60;
    buf[6] = 44; /* next header = Fragment */
    mqvpn_flow_key_t k;
    ASSERT_EQ_INT(mqvpn_reorder_parse_5tuple(buf, 48, &k), -1, "parse v6 fragment fails");
}

static void
test_parse_v6_tcp_fails(void)
{
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x60;
    buf[6] = 6; /* TCP */
    mqvpn_flow_key_t k;
    ASSERT_EQ_INT(mqvpn_reorder_parse_5tuple(buf, 48, &k), -1, "parse v6 tcp fails");
}

static void
test_parse_v6_truncated_fails(void)
{
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x60;
    buf[6] = 17; /* UDP */
    mqvpn_flow_key_t k;
    /* fixed v6 header present but UDP header truncated */
    ASSERT_EQ_INT(mqvpn_reorder_parse_5tuple(buf, 42, &k), -1,
                  "parse v6 truncated fails");
    ASSERT_EQ_INT(mqvpn_reorder_parse_5tuple(buf, 10, &k), -1,
                  "parse v6 too short fails");
}

/* ─────────────────── §19: mqvpn-reorder header match ─────────────────── */

static void
test_header_match_ok(void)
{
    /* Canonical lowercase name + "v1" value matches. */
    ASSERT_EQ_INT(mqvpn_reorder_header_match("mqvpn-reorder", 13, "v1", 2), 1,
                  "header match canonical");
    /* The constants the senders use must produce a match too. */
    ASSERT_EQ_INT(mqvpn_reorder_header_match(
                      MQVPN_REORDER_HDR_NAME, sizeof(MQVPN_REORDER_HDR_NAME) - 1,
                      MQVPN_REORDER_HDR_VALUE, sizeof(MQVPN_REORDER_HDR_VALUE) - 1),
                  1, "header match via constants");
}

static void
test_header_match_rejects(void)
{
    /* Wrong value. */
    ASSERT_EQ_INT(mqvpn_reorder_header_match("mqvpn-reorder", 13, "v2", 2), 0,
                  "header reject wrong value");
    /* Wrong name. */
    ASSERT_EQ_INT(mqvpn_reorder_header_match("mqvpn-reordr", 12, "v1", 2), 0,
                  "header reject wrong name");
    /* Uppercase name must NOT match (wire name is lowercase, §19.2). */
    ASSERT_EQ_INT(mqvpn_reorder_header_match("MQVPN-REORDER", 13, "v1", 2), 0,
                  "header reject uppercase name");
    /* Length mismatch (prefix of value). */
    ASSERT_EQ_INT(mqvpn_reorder_header_match("mqvpn-reorder", 13, "v", 1), 0,
                  "header reject short value");
    /* Name length mismatch even if prefix equal. */
    ASSERT_EQ_INT(mqvpn_reorder_header_match("mqvpn-reorder-x", 15, "v1", 2), 0,
                  "header reject long name");
}

int
main(void)
{
    test_wire_roundtrip();
    test_wire_seq_48bit();
    test_wire_dispatch_raw_v4();
    test_wire_dispatch_raw_v6();
    test_wire_dispatch_reorder();
    test_wire_dispatch_unknown();
    test_wire_decode_short();

    test_flowkey_eq();
    test_flowkey_v4_v6_distinct();
    test_flowkey_hash_stable();
    test_flowkey_hash_distinct();

    test_cfg_defaults();
    test_cfg_validate_idle_order();
    test_cfg_validate_cap_pow2();
    test_cfg_validate_ok();

    test_parse_v4_udp();
    test_parse_v4_fragment_fails();
    test_parse_v4_tcp_fails();
    test_parse_v4_truncated_fails();
    test_parse_v6_udp();
    test_parse_v6_with_hopopts_udp();
    test_parse_v6_fragment_fails();
    test_parse_v6_tcp_fails();
    test_parse_v6_truncated_fails();

    test_header_match_ok();
    test_header_match_rejects();

    fprintf(stderr, "test_reorder_common: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
