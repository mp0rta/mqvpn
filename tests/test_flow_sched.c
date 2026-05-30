// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and contributors

/*
 * test_flow_sched.c — Unit tests for flow_hash_pkt (FNV-1a 5-tuple hash)
 *
 * Scheduling logic (flow table, WRR, LATE weights) lives inside xquic's
 * WLB scheduler (xqc_scheduler_wlb.c).  This file only tests the hash
 * function exposed by flow_sched.h.
 *
 * Build:  cc -o test_flow_sched tests/test_flow_sched.c src/flow_sched.c
 *             -I src
 * Run:    ./test_flow_sched
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

#include "flow_sched.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name)                 \
    do {                           \
        printf("  %-50s ", #name); \
    } while (0)

#define PASS()            \
    do {                  \
        printf("PASS\n"); \
        tests_passed++;   \
    } while (0)

#define FAIL(msg)                  \
    do {                           \
        printf("FAIL: %s\n", msg); \
        tests_failed++;            \
    } while (0)

#define ASSERT_EQ(a, b)                                                             \
    do {                                                                            \
        if ((a) != (b)) {                                                           \
            char _buf[128];                                                         \
            snprintf(_buf, sizeof(_buf), "expected %lld, got %lld", (long long)(b), \
                     (long long)(a));                                               \
            FAIL(_buf);                                                             \
            return;                                                                 \
        }                                                                           \
    } while (0)

#define ASSERT_NEQ(a, b)                  \
    do {                                  \
        if ((a) == (b)) {                 \
            FAIL("values should differ"); \
            return;                       \
        }                                 \
    } while (0)

/* ── Helper: build fake IPv4 packets ── */

static int
make_tcp_pkt(uint8_t *buf, const char *src_ip, uint16_t src_port, const char *dst_ip,
             uint16_t dst_port)
{
    memset(buf, 0, 40);
    buf[0] = 0x45; /* IPv4, IHL=5 */
    buf[9] = 6;    /* TCP */

    struct in_addr a;
    inet_pton(AF_INET, src_ip, &a);
    memcpy(buf + 12, &a, 4);
    inet_pton(AF_INET, dst_ip, &a);
    memcpy(buf + 16, &a, 4);

    /* TCP ports (network byte order) */
    buf[20] = src_port >> 8;
    buf[21] = src_port & 0xff;
    buf[22] = dst_port >> 8;
    buf[23] = dst_port & 0xff;

    return 40; /* 20 IP + 20 TCP */
}

static int
make_udp_pkt(uint8_t *buf, const char *src_ip, uint16_t src_port, const char *dst_ip,
             uint16_t dst_port)
{
    memset(buf, 0, 28);
    buf[0] = 0x45;
    buf[9] = 17; /* UDP */

    struct in_addr a;
    inet_pton(AF_INET, src_ip, &a);
    memcpy(buf + 12, &a, 4);
    inet_pton(AF_INET, dst_ip, &a);
    memcpy(buf + 16, &a, 4);

    buf[20] = src_port >> 8;
    buf[21] = src_port & 0xff;
    buf[22] = dst_port >> 8;
    buf[23] = dst_port & 0xff;

    return 28;
}

static void
set_ipv4_fragment_fields(uint8_t *buf, uint16_t ident, uint16_t frag_field)
{
    buf[4] = ident >> 8;
    buf[5] = ident & 0xff;
    buf[6] = frag_field >> 8;
    buf[7] = frag_field & 0xff;
}

static int
make_ipv4_fragment(uint8_t *buf, size_t len, uint8_t proto, const char *src_ip,
                   const char *dst_ip, uint16_t ident, uint16_t frag_field,
                   uint8_t payload_seed)
{
    memset(buf, 0, len);
    buf[0] = 0x45; /* IPv4, IHL=5 */
    buf[9] = proto;
    set_ipv4_fragment_fields(buf, ident, frag_field);

    struct in_addr a;
    inet_pton(AF_INET, src_ip, &a);
    memcpy(buf + 12, &a, 4);
    inet_pton(AF_INET, dst_ip, &a);
    memcpy(buf + 16, &a, 4);

    for (size_t i = 20; i < len; i++) {
        buf[i] = (uint8_t)(payload_seed + i);
    }

    return (int)len;
}

/* ── Tests ── */

static void
test_hash_basic(void)
{
    TEST(flow_hash_pkt basic);

    uint8_t pkt[40];
    make_tcp_pkt(pkt, "10.0.0.1", 12345, "10.0.0.2", 80);

    uint32_t h = flow_hash_pkt(pkt, 40, false);
    ASSERT_NEQ(h, 0);

    /* Same packet → same hash */
    uint32_t h2 = flow_hash_pkt(pkt, 40, false);
    ASSERT_EQ(h, h2);

    PASS();
}

static void
test_hash_different_flows(void)
{
    TEST(flow_hash_pkt different flows);

    uint8_t pkt1[40], pkt2[40];
    make_tcp_pkt(pkt1, "10.0.0.1", 12345, "10.0.0.2", 80);
    make_tcp_pkt(pkt2, "10.0.0.1", 12346, "10.0.0.2", 80);

    uint32_t h1 = flow_hash_pkt(pkt1, 40, false);
    uint32_t h2 = flow_hash_pkt(pkt2, 40, false);
    ASSERT_NEQ(h1, h2);

    PASS();
}

static void
test_hash_rejects_unknown_version(void)
{
    TEST(flow_hash_pkt rejects unknown IP version);

    /* Version 5 (invalid) → 0 */
    uint8_t pkt[40] = {0};
    pkt[0] = 0x50;
    ASSERT_EQ(flow_hash_pkt(pkt, 40, false), 0);

    /* Too short for any version */
    ASSERT_EQ(flow_hash_pkt(pkt, 0, false), 0);

    PASS();
}

static void
test_hash_ipv6_tcp(void)
{
    TEST(flow_hash_pkt IPv6 TCP returns pinned hash);

    uint8_t pkt[44] = {0};
    pkt[0] = 0x60;  /* IPv6 */
    pkt[6] = 6;     /* Next Header: TCP */
    pkt[8] = 0xfd;  /* src IP */
    pkt[24] = 0xfd; /* dst IP */
    pkt[39] = 0x02;
    pkt[40] = 0x00;
    pkt[41] = 80; /* src port */
    pkt[42] = 0x01;
    pkt[43] = 0xBB; /* dst port 443 */

    uint32_t h = flow_hash_pkt(pkt, 44, false);
    ASSERT_NEQ(h, 0);
    ASSERT_NEQ(h, MQVPN_FLOW_HASH_UNPINNED);

    PASS();
}

static void
test_hash_ipv6_udp_unpinned(void)
{
    TEST(flow_hash_pkt IPv6 UDP returns UNPINNED);

    uint8_t pkt[44] = {0};
    pkt[0] = 0x60; /* IPv6 */
    pkt[6] = 17;   /* Next Header: UDP */

    ASSERT_EQ(flow_hash_pkt(pkt, 44, false), MQVPN_FLOW_HASH_UNPINNED);

    PASS();
}

static void
test_hash_ipv6_too_short(void)
{
    TEST(flow_hash_pkt IPv6 too short returns 0);

    uint8_t pkt[39] = {0};
    pkt[0] = 0x60;

    ASSERT_EQ(flow_hash_pkt(pkt, 39, false), 0);

    PASS();
}

static void
test_hash_udp(void)
{
    TEST(flow_hash_pkt UDP returns UNPINNED);

    uint8_t pkt[28];
    make_udp_pkt(pkt, "192.168.1.1", 5000, "8.8.8.8", 53);

    uint32_t h = flow_hash_pkt(pkt, 28, false);
    ASSERT_EQ(h, MQVPN_FLOW_HASH_UNPINNED);

    PASS();
}

static void
test_hash_never_returns_zero(void)
{
    TEST(flow_hash_pkt never returns 0 for valid IPv4);

    /* Hash many different flows — none should produce 0 */
    for (int i = 0; i < 1000; i++) {
        uint8_t pkt[40];
        make_tcp_pkt(pkt, "10.0.0.1", 1000 + i, "10.0.0.2", 80);
        uint32_t h = flow_hash_pkt(pkt, 40, false);
        ASSERT_NEQ(h, 0);
    }

    PASS();
}

static void
test_hash_each_field_matters(void)
{
    TEST(flow_hash_pkt each 5 - tuple field matters);

    uint8_t base[40];
    make_tcp_pkt(base, "10.0.0.1", 1234, "10.0.0.2", 80);
    uint32_t h_base = flow_hash_pkt(base, 40, false);

    /* Change src_ip */
    uint8_t pkt[40];
    make_tcp_pkt(pkt, "10.0.0.99", 1234, "10.0.0.2", 80);
    ASSERT_NEQ(flow_hash_pkt(pkt, 40, false), h_base);

    /* Change dst_ip */
    make_tcp_pkt(pkt, "10.0.0.1", 1234, "10.0.0.99", 80);
    ASSERT_NEQ(flow_hash_pkt(pkt, 40, false), h_base);

    /* Change src_port */
    make_tcp_pkt(pkt, "10.0.0.1", 9999, "10.0.0.2", 80);
    ASSERT_NEQ(flow_hash_pkt(pkt, 40, false), h_base);

    /* Change dst_port */
    make_tcp_pkt(pkt, "10.0.0.1", 1234, "10.0.0.2", 443);
    ASSERT_NEQ(flow_hash_pkt(pkt, 40, false), h_base);

    /* Change protocol (TCP→UDP) — UDP returns UNPINNED, not a 5-tuple hash */
    make_udp_pkt(pkt, "10.0.0.1", 1234, "10.0.0.2", 80);
    ASSERT_EQ(flow_hash_pkt(pkt, 28, false), MQVPN_FLOW_HASH_UNPINNED);
    ASSERT_NEQ(MQVPN_FLOW_HASH_UNPINNED, h_base);

    PASS();
}

static void
test_hash_icmp_no_ports(void)
{
    TEST(flow_hash_pkt ICMP returns UNPINNED);

    uint8_t pkt[28];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45; /* IPv4, IHL=5 */
    pkt[9] = 1;    /* ICMP */

    struct in_addr a;
    inet_pton(AF_INET, "10.0.0.1", &a);
    memcpy(pkt + 12, &a, 4);
    inet_pton(AF_INET, "10.0.0.2", &a);
    memcpy(pkt + 16, &a, 4);

    /* Non-TCP → UNPINNED (per-packet WRR, no flow pinning) */
    uint32_t h = flow_hash_pkt(pkt, 28, false);
    ASSERT_EQ(h, MQVPN_FLOW_HASH_UNPINNED);

    /* Deterministic */
    ASSERT_EQ(flow_hash_pkt(pkt, 28, false), h);

    PASS();
}

static void
test_hash_ip_header_only(void)
{
    TEST(flow_hash_pkt IP header only(len = 20));

    /* Packet with exactly 20 bytes — no L4 data available */
    uint8_t pkt[20];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45; /* IPv4, IHL=5 */
    pkt[9] = 6;    /* TCP */

    struct in_addr a;
    inet_pton(AF_INET, "10.0.0.1", &a);
    memcpy(pkt + 12, &a, 4);
    inet_pton(AF_INET, "10.0.0.2", &a);
    memcpy(pkt + 16, &a, 4);

    /* No TCP ports available, so disable pinning for this packet. */
    uint32_t h = flow_hash_pkt(pkt, 20, false);
    ASSERT_EQ(h, MQVPN_FLOW_HASH_UNPINNED);

    PASS();
}

static void
test_hash_zero_length(void)
{
    TEST(flow_hash_pkt zero length returns 0);

    uint8_t pkt[1] = {0x45};
    ASSERT_EQ(flow_hash_pkt(pkt, 0, false), 0);
    ASSERT_EQ(flow_hash_pkt(NULL, 0, false), 0);

    PASS();
}

static void
test_hash_null_pointer_nonzero_len(void)
{
    TEST(flow_hash_pkt NULL with nonzero len returns 0);

    ASSERT_EQ(flow_hash_pkt(NULL, 40, false), 0);

    PASS();
}

static void
test_hash_invalid_ihl(void)
{
    TEST(flow_hash_pkt invalid IHL returns 0);

    uint8_t pkt[40];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x4f; /* IPv4, IHL=15 (60 bytes) */
    pkt[9] = 6;    /* TCP */

    ASSERT_EQ(flow_hash_pkt(pkt, 40, false), 0);

    pkt[0] = 0x40; /* IPv4, IHL=0 */
    ASSERT_EQ(flow_hash_pkt(pkt, 40, false), 0);

    PASS();
}

static void
test_hash_tcp_truncated_l4_unpinned(void)
{
    TEST(flow_hash_pkt truncated TCP L4 returns UNPINNED);

    uint8_t pkt[20];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45; /* IPv4, IHL=5 */
    pkt[9] = 6;    /* TCP */

    struct in_addr a;
    inet_pton(AF_INET, "10.0.0.1", &a);
    memcpy(pkt + 12, &a, 4);
    inet_pton(AF_INET, "10.0.0.2", &a);
    memcpy(pkt + 16, &a, 4);

    ASSERT_EQ(flow_hash_pkt(pkt, 20, false), MQVPN_FLOW_HASH_UNPINNED);

    PASS();
}

static void
test_hash_distribution(void)
{
    TEST(flow_hash_pkt reasonable distribution);

    /* Hash 1000 flows, check that at least 4 different low-byte values appear.
     * FNV-1a should spread well — this is a basic sanity check. */
    uint8_t seen[256] = {0};
    int distinct = 0;

    for (int i = 0; i < 1000; i++) {
        uint8_t pkt[40];
        make_tcp_pkt(pkt, "10.0.0.1", 1000 + i, "10.0.0.2", 80);
        uint32_t h = flow_hash_pkt(pkt, 40, false);
        uint8_t low = h & 0xff;
        if (!seen[low]) {
            seen[low] = 1;
            distinct++;
        }
    }

    /* With 1000 hashes, expect close to 256 distinct low bytes.
     * Use a very conservative threshold. */
    assert(distinct >= 100);

    PASS();
}

static void
test_hash_never_returns_sentinels(void)
{
    TEST(flow_hash_pkt TCP never returns 0 or UNPINNED);

    /* Hash many TCP flows — none should produce 0 or UNPINNED */
    for (int i = 0; i < 10000; i++) {
        uint8_t pkt[40];
        uint16_t port = (uint16_t)(1000 + (i % 64000));
        char src[16];
        snprintf(src, sizeof(src), "%d.%d.%d.%d", 10 + (i >> 24) % 200, (i >> 16) & 0xff,
                 (i >> 8) & 0xff, i & 0xff);
        make_tcp_pkt(pkt, src, port, "10.0.0.2", 80);
        uint32_t h = flow_hash_pkt(pkt, 40, false);
        ASSERT_NEQ(h, 0);
        ASSERT_NEQ(h, MQVPN_FLOW_HASH_UNPINNED);
    }

    PASS();
}

static void
test_hash_tcp_pinned_udp_unpinned(void)
{
    TEST(flow_hash_pkt TCP pinned vs UDP unpinned);

    uint8_t tcp[40], udp[28];
    make_tcp_pkt(tcp, "10.0.0.1", 1234, "10.0.0.2", 80);
    make_udp_pkt(udp, "10.0.0.1", 1234, "10.0.0.2", 80);

    uint32_t h_tcp = flow_hash_pkt(tcp, 40, false);
    uint32_t h_udp = flow_hash_pkt(udp, 28, false);

    /* TCP gets a real flow hash (non-zero, non-UNPINNED) */
    ASSERT_NEQ(h_tcp, 0);
    ASSERT_NEQ(h_tcp, MQVPN_FLOW_HASH_UNPINNED);

    /* UDP gets UNPINNED sentinel */
    ASSERT_EQ(h_udp, MQVPN_FLOW_HASH_UNPINNED);

    PASS();
}

static void
test_sched_mode_constants(void)
{
    TEST(scheduler mode constants);

    ASSERT_EQ(MQVPN_SCHED_MINRTT, 0);
    ASSERT_EQ(MQVPN_SCHED_WLB, 1);
    ASSERT_EQ(MQVPN_SCHED_BACKUP_FEC, 2);
    ASSERT_EQ(MQVPN_SCHED_WLB_UDP_PIN, 3);
    ASSERT_NEQ(MQVPN_SCHED_MINRTT, MQVPN_SCHED_WLB);

    PASS();
}

/* ── Helper: build fake IPv6 packets ── */

static int
make_ipv6_tcp_pkt(uint8_t *buf, const uint8_t *src_ip, uint16_t src_port,
                  const uint8_t *dst_ip, uint16_t dst_port)
{
    memset(buf, 0, 44);
    buf[0] = 0x60; /* IPv6 */
    buf[6] = 6;    /* Next Header: TCP */
    buf[7] = 64;   /* Hop Limit */

    memcpy(buf + 8, src_ip, 16);
    memcpy(buf + 24, dst_ip, 16);

    /* TCP ports (network byte order) */
    buf[40] = src_port >> 8;
    buf[41] = src_port & 0xff;
    buf[42] = dst_port >> 8;
    buf[43] = dst_port & 0xff;

    return 44;
}

/* ── IPv6 edge-case tests ── */

static void
test_hash_ipv6_icmpv6_unpinned(void)
{
    TEST(flow_hash_pkt IPv6 ICMPv6 returns UNPINNED);

    uint8_t pkt[44] = {0};
    pkt[0] = 0x60; /* IPv6 */
    pkt[6] = 58;   /* Next Header: ICMPv6 */

    struct in6_addr src, dst;
    inet_pton(AF_INET6, "fd00::1", &src);
    inet_pton(AF_INET6, "fd00::2", &dst);
    memcpy(pkt + 8, &src, 16);
    memcpy(pkt + 24, &dst, 16);

    ASSERT_EQ(flow_hash_pkt(pkt, 44, false), MQVPN_FLOW_HASH_UNPINNED);

    PASS();
}

static void
test_hash_ipv6_tcp_truncated_no_ports(void)
{
    TEST(flow_hash_pkt IPv6 TCP truncated(40 bytes, no ports) returns UNPINNED);

    /* 40 bytes = IPv6 header only, TCP next header but no L4 data */
    uint8_t pkt[40] = {0};
    pkt[0] = 0x60;
    pkt[6] = 6; /* TCP */

    struct in6_addr src, dst;
    inet_pton(AF_INET6, "fd00::1", &src);
    inet_pton(AF_INET6, "fd00::2", &dst);
    memcpy(pkt + 8, &src, 16);
    memcpy(pkt + 24, &dst, 16);

    /* len=40: header present, but no TCP ports (need 44) → UNPINNED */
    ASSERT_EQ(flow_hash_pkt(pkt, 40, false), MQVPN_FLOW_HASH_UNPINNED);

    /* len=43: still not enough for 4 bytes of ports */
    uint8_t pkt43[43] = {0};
    memcpy(pkt43, pkt, 40);
    ASSERT_EQ(flow_hash_pkt(pkt43, 43, false), MQVPN_FLOW_HASH_UNPINNED);

    PASS();
}

static void
test_hash_ipv6_each_field_matters(void)
{
    TEST(flow_hash_pkt IPv6 each field matters);

    uint8_t src1[16], src2[16], dst1[16], dst2[16];
    inet_pton(AF_INET6, "fd00::1", src1);
    inet_pton(AF_INET6, "fd00::99", src2);
    inet_pton(AF_INET6, "fd00::2", dst1);
    inet_pton(AF_INET6, "fd00::88", dst2);

    uint8_t base[44];
    make_ipv6_tcp_pkt(base, src1, 1234, dst1, 80);
    uint32_t h_base = flow_hash_pkt(base, 44, false);
    ASSERT_NEQ(h_base, 0);
    ASSERT_NEQ(h_base, MQVPN_FLOW_HASH_UNPINNED);

    /* Change src IP */
    uint8_t pkt[44];
    make_ipv6_tcp_pkt(pkt, src2, 1234, dst1, 80);
    ASSERT_NEQ(flow_hash_pkt(pkt, 44, false), h_base);

    /* Change dst IP */
    make_ipv6_tcp_pkt(pkt, src1, 1234, dst2, 80);
    ASSERT_NEQ(flow_hash_pkt(pkt, 44, false), h_base);

    /* Change src port */
    make_ipv6_tcp_pkt(pkt, src1, 9999, dst1, 80);
    ASSERT_NEQ(flow_hash_pkt(pkt, 44, false), h_base);

    /* Change dst port */
    make_ipv6_tcp_pkt(pkt, src1, 1234, dst1, 443);
    ASSERT_NEQ(flow_hash_pkt(pkt, 44, false), h_base);

    PASS();
}

static void
test_hash_ipv6_tcp_never_returns_sentinels(void)
{
    TEST(flow_hash_pkt IPv6 TCP never returns 0 or UNPINNED);

    uint8_t src[16], dst[16];
    inet_pton(AF_INET6, "fd00::1", src);
    inet_pton(AF_INET6, "fd00::2", dst);

    for (int i = 0; i < 10000; i++) {
        uint8_t pkt[44];
        uint16_t port = (uint16_t)(1000 + (i % 64000));
        /* Vary src address lower bytes */
        src[15] = (uint8_t)(i & 0xff);
        src[14] = (uint8_t)((i >> 8) & 0xff);
        make_ipv6_tcp_pkt(pkt, src, port, dst, 80);
        uint32_t h = flow_hash_pkt(pkt, 44, false);
        ASSERT_NEQ(h, 0);
        ASSERT_NEQ(h, MQVPN_FLOW_HASH_UNPINNED);
    }

    PASS();
}

static void
test_hash_ipv6_extension_header_as_next(void)
{
    TEST(flow_hash_pkt IPv6 non - TCP next header returns UNPINNED);

    uint8_t pkt[44] = {0};
    pkt[0] = 0x60;

    /* Hop-by-Hop (0) → not TCP → UNPINNED */
    pkt[6] = 0;
    ASSERT_EQ(flow_hash_pkt(pkt, 44, false), MQVPN_FLOW_HASH_UNPINNED);

    /* Routing (43) → UNPINNED */
    pkt[6] = 43;
    ASSERT_EQ(flow_hash_pkt(pkt, 44, false), MQVPN_FLOW_HASH_UNPINNED);

    /* Fragment (44) → UNPINNED */
    pkt[6] = 44;
    ASSERT_EQ(flow_hash_pkt(pkt, 44, false), MQVPN_FLOW_HASH_UNPINNED);

    /* ESP (50) → UNPINNED */
    pkt[6] = 50;
    ASSERT_EQ(flow_hash_pkt(pkt, 44, false), MQVPN_FLOW_HASH_UNPINNED);

    PASS();
}

static void
test_hash_ipv6_deterministic(void)
{
    TEST(flow_hash_pkt IPv6 TCP deterministic);

    uint8_t src[16], dst[16];
    inet_pton(AF_INET6, "2001:db8::1", src);
    inet_pton(AF_INET6, "2001:db8::2", dst);

    uint8_t pkt[44];
    make_ipv6_tcp_pkt(pkt, src, 443, dst, 50000);

    uint32_t h1 = flow_hash_pkt(pkt, 44, false);
    uint32_t h2 = flow_hash_pkt(pkt, 44, false);
    uint32_t h3 = flow_hash_pkt(pkt, 44, false);
    ASSERT_EQ(h1, h2);
    ASSERT_EQ(h2, h3);

    PASS();
}

static void
test_hash_ipv4_ihl_6_with_options(void)
{
    TEST(hash_ipv4_ihl_6_with_options);
    uint8_t pkt[28] = {0};
    pkt[0] = 0x46; /* IPv4, IHL=6 */
    pkt[9] = 6;    /* TCP */
    pkt[12] = 10;
    pkt[13] = 0;
    pkt[14] = 0;
    pkt[15] = 1;
    pkt[16] = 10;
    pkt[17] = 0;
    pkt[18] = 0;
    pkt[19] = 2;
    pkt[24] = 0x30;
    pkt[25] = 0x39; /* src port 12345 */
    pkt[26] = 0x00;
    pkt[27] = 0x50; /* dst port 80 */

    uint32_t h = flow_hash_pkt(pkt, sizeof(pkt), false);
    if (h == 0 || h == MQVPN_FLOW_HASH_UNPINNED) {
        FAIL("IHL=6 TCP should be pinned");
        return;
    }
    PASS();
}

static void
test_hash_ipv4_tcp_fragments_use_identification(void)
{
    TEST(flow_hash_pkt IPv4 TCP fragments use Identification);

    uint8_t first[40];
    make_tcp_pkt(first, "10.0.0.1", 12345, "10.0.0.2", 80);
    set_ipv4_fragment_fields(first, 0x1234, 0x2000); /* MF=1, offset=0 */

    uint8_t later[28];
    make_ipv4_fragment(later, sizeof(later), 6, "10.0.0.1", "10.0.0.2", 0x1234, 0x0001,
                       0xaa); /* offset=8 bytes, no TCP ports */

    uint32_t h_first = flow_hash_pkt(first, sizeof(first), false);
    uint32_t h_later = flow_hash_pkt(later, sizeof(later), false);
    ASSERT_NEQ(h_first, 0);
    ASSERT_NEQ(h_first, MQVPN_FLOW_HASH_UNPINNED);
    ASSERT_EQ(h_later, h_first);

    later[20] ^= 0xff; /* payload bytes must not affect fragment hash */
    ASSERT_EQ(flow_hash_pkt(later, sizeof(later), false), h_first);

    uint8_t other_id[28];
    make_ipv4_fragment(other_id, sizeof(other_id), 6, "10.0.0.1", "10.0.0.2", 0x1235,
                       0x0001, 0xaa);
    ASSERT_NEQ(flow_hash_pkt(other_id, sizeof(other_id), false), h_first);

    PASS();
}

static void
test_hash_ipv4_udp_fragments_respect_udp_pin(void)
{
    TEST(flow_hash_pkt IPv4 UDP fragments respect udp_pin);

    uint8_t first[28];
    make_udp_pkt(first, "10.0.0.1", 12345, "10.0.0.2", 53);
    set_ipv4_fragment_fields(first, 0xbeef, 0x2000); /* MF=1, offset=0 */

    uint8_t later[28];
    make_ipv4_fragment(later, sizeof(later), 17, "10.0.0.1", "10.0.0.2", 0xbeef, 0x0001,
                       0x11); /* offset=8 bytes, no UDP ports */

    ASSERT_EQ(flow_hash_pkt(first, sizeof(first), false), MQVPN_FLOW_HASH_UNPINNED);
    ASSERT_EQ(flow_hash_pkt(later, sizeof(later), false), MQVPN_FLOW_HASH_UNPINNED);

    uint32_t h_first = flow_hash_pkt(first, sizeof(first), true);
    uint32_t h_later = flow_hash_pkt(later, sizeof(later), true);
    ASSERT_NEQ(h_first, 0);
    ASSERT_NEQ(h_first, MQVPN_FLOW_HASH_UNPINNED);
    ASSERT_EQ(h_later, h_first);

    later[20] ^= 0xff; /* payload bytes must not affect fragment hash */
    ASSERT_EQ(flow_hash_pkt(later, sizeof(later), true), h_first);

    uint8_t other_id[28];
    make_ipv4_fragment(other_id, sizeof(other_id), 17, "10.0.0.1", "10.0.0.2", 0xbef0,
                       0x0001, 0x11);
    ASSERT_NEQ(flow_hash_pkt(other_id, sizeof(other_id), true), h_first);

    PASS();
}

/* ── UDP pin gate tests ── */

static void
test_udp_pin_ipv4_gate(void)
{
    TEST(flow_hash_pkt IPv4 UDP gate);

    uint8_t pkt[28];
    make_udp_pkt(pkt, "10.0.0.1", 0x1234, "8.8.8.8", 53);

    /* udp_pin=true → real FNV hash */
    uint32_t h = flow_hash_pkt(pkt, 28, true);
    ASSERT_NEQ(h, 0);
    ASSERT_NEQ(h, MQVPN_FLOW_HASH_UNPINNED);
    ASSERT_EQ(flow_hash_pkt(pkt, 28, true), h); /* deterministic */

    /* udp_pin=false → legacy UNPINNED preserved */
    ASSERT_EQ(flow_hash_pkt(pkt, 28, false), MQVPN_FLOW_HASH_UNPINNED);

    /* each 5-tuple field changes the hash (under udp_pin=true) */
    uint8_t alt[28];
    make_udp_pkt(alt, "10.0.0.2", 0x1234, "8.8.8.8", 53); /* src IP */
    ASSERT_NEQ(flow_hash_pkt(alt, 28, true), h);
    make_udp_pkt(alt, "10.0.0.1", 0x9999, "8.8.8.8", 53); /* src port */
    ASSERT_NEQ(flow_hash_pkt(alt, 28, true), h);
    make_udp_pkt(alt, "10.0.0.1", 0x1234, "8.8.4.4", 53); /* dst IP */
    ASSERT_NEQ(flow_hash_pkt(alt, 28, true), h);
    make_udp_pkt(alt, "10.0.0.1", 0x1234, "8.8.8.8", 80); /* dst port */
    ASSERT_NEQ(flow_hash_pkt(alt, 28, true), h);

    /* ICMP under udp_pin=true still UNPINNED (only UDP is gated) */
    uint8_t icmp[28];
    memset(icmp, 0, sizeof(icmp));
    icmp[0] = 0x45;
    icmp[9] = 1;
    icmp[12] = 10;
    icmp[16] = 8;
    ASSERT_EQ(flow_hash_pkt(icmp, 28, true), MQVPN_FLOW_HASH_UNPINNED);

    PASS();
}

static void
test_udp_pin_ipv6_gate(void)
{
    TEST(flow_hash_pkt IPv6 UDP gate);

    uint8_t pkt[44];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x60; /* IPv6 */
    pkt[6] = 17;   /* next_hdr UDP */
    pkt[8] = 0x20;
    pkt[24] = 0x20;
    pkt[40] = 0x12;
    pkt[41] = 0x34;
    pkt[42] = 0x00;
    pkt[43] = 0x35;

    uint32_t h = flow_hash_pkt(pkt, 44, true);
    ASSERT_NEQ(h, 0);
    ASSERT_NEQ(h, MQVPN_FLOW_HASH_UNPINNED);

    ASSERT_EQ(flow_hash_pkt(pkt, 44, false), MQVPN_FLOW_HASH_UNPINNED);

    /* truncated (< 44 bytes) under udp_pin=true → UNPINNED */
    ASSERT_EQ(flow_hash_pkt(pkt, 43, true), MQVPN_FLOW_HASH_UNPINNED);

    PASS();
}

static void
test_udp_pin_tcp_unchanged(void)
{
    TEST(flow_hash_pkt TCP hash unchanged regardless of udp_pin);

    uint8_t pkt[40];
    make_tcp_pkt(pkt, "10.0.0.1", 12345, "8.8.8.8", 80);
    ASSERT_EQ(flow_hash_pkt(pkt, 40, false), flow_hash_pkt(pkt, 40, true));

    uint8_t pkt6[44];
    uint8_t src6[16] = {0x20, 0x01};
    uint8_t dst6[16] = {0x20, 0x02};
    make_ipv6_tcp_pkt(pkt6, src6, 12345, dst6, 80);
    ASSERT_EQ(flow_hash_pkt(pkt6, 44, false), flow_hash_pkt(pkt6, 44, true));

    PASS();
}

static void
test_udp_pin_ipv4_truncated(void)
{
    TEST(flow_hash_pkt IPv4 UDP truncated under udp_pin returns UNPINNED);

    /* 23 bytes — just below the ihl + 4 = 24 boundary */
    uint8_t pkt[23];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[9] = 17;
    pkt[12] = 10;
    pkt[16] = 8;

    ASSERT_EQ(flow_hash_pkt(pkt, 23, true), MQVPN_FLOW_HASH_UNPINNED);

    PASS();
}

/* ── Main ── */

int
main(void)
{
    printf("=== flow_sched unit tests ===\n\n");

    test_hash_basic();
    test_hash_different_flows();
    test_hash_rejects_unknown_version();
    test_hash_ipv6_tcp();
    test_hash_ipv6_udp_unpinned();
    test_hash_ipv6_too_short();
    test_hash_udp();
    test_hash_never_returns_zero();
    test_hash_each_field_matters();
    test_hash_icmp_no_ports();
    test_hash_ip_header_only();
    test_hash_zero_length();
    test_hash_null_pointer_nonzero_len();
    test_hash_invalid_ihl();
    test_hash_tcp_truncated_l4_unpinned();
    test_hash_distribution();
    test_hash_never_returns_sentinels();
    test_hash_tcp_pinned_udp_unpinned();
    test_sched_mode_constants();

    /* IPv6 edge cases */
    test_hash_ipv6_icmpv6_unpinned();
    test_hash_ipv6_tcp_truncated_no_ports();
    test_hash_ipv6_each_field_matters();
    test_hash_ipv6_tcp_never_returns_sentinels();
    test_hash_ipv6_extension_header_as_next();
    test_hash_ipv6_deterministic();

    /* IPv4 IHL > 5 */
    test_hash_ipv4_ihl_6_with_options();

    /* IPv4 fragments */
    test_hash_ipv4_tcp_fragments_use_identification();
    test_hash_ipv4_udp_fragments_respect_udp_pin();

    /* UDP pin gate (Chunk 1) */
    test_udp_pin_ipv4_gate();
    test_udp_pin_ipv6_gate();
    test_udp_pin_tcp_unchanged();
    test_udp_pin_ipv4_truncated();

    printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
