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

    fprintf(stderr, "test_reorder_common: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
