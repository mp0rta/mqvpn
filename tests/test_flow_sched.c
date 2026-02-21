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

#define TEST(name) \
    do { printf("  %-50s ", #name); } while(0)

#define PASS() \
    do { printf("PASS\n"); tests_passed++; } while(0)

#define FAIL(msg) \
    do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

#define ASSERT_EQ(a, b) \
    do { if ((a) != (b)) { \
        char _buf[128]; \
        snprintf(_buf, sizeof(_buf), "expected %lld, got %lld", \
                 (long long)(b), (long long)(a)); \
        FAIL(_buf); return; \
    }} while(0)

#define ASSERT_NEQ(a, b) \
    do { if ((a) == (b)) { FAIL("values should differ"); return; }} while(0)

/* ── Helper: build fake IPv4 packets ── */

static int
make_tcp_pkt(uint8_t *buf, const char *src_ip, uint16_t src_port,
             const char *dst_ip, uint16_t dst_port)
{
    memset(buf, 0, 40);
    buf[0] = 0x45;  /* IPv4, IHL=5 */
    buf[9] = 6;     /* TCP */

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

    return 40;  /* 20 IP + 20 TCP */
}

static int
make_udp_pkt(uint8_t *buf, const char *src_ip, uint16_t src_port,
             const char *dst_ip, uint16_t dst_port)
{
    memset(buf, 0, 28);
    buf[0] = 0x45;
    buf[9] = 17;  /* UDP */

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

/* ── Tests ── */

static void
test_hash_basic(void)
{
    TEST(flow_hash_pkt basic);

    uint8_t pkt[40];
    make_tcp_pkt(pkt, "10.0.0.1", 12345, "10.0.0.2", 80);

    uint32_t h = flow_hash_pkt(pkt, 40);
    ASSERT_NEQ(h, 0);

    /* Same packet → same hash */
    uint32_t h2 = flow_hash_pkt(pkt, 40);
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

    uint32_t h1 = flow_hash_pkt(pkt1, 40);
    uint32_t h2 = flow_hash_pkt(pkt2, 40);
    ASSERT_NEQ(h1, h2);

    PASS();
}

static void
test_hash_rejects_non_ipv4(void)
{
    TEST(flow_hash_pkt rejects non-IPv4);

    uint8_t pkt[40] = {0};
    pkt[0] = 0x60;  /* IPv6 */
    ASSERT_EQ(flow_hash_pkt(pkt, 40), 0);

    /* Too short */
    ASSERT_EQ(flow_hash_pkt(pkt, 10), 0);

    PASS();
}

static void
test_hash_udp(void)
{
    TEST(flow_hash_pkt UDP);

    uint8_t pkt[28];
    make_udp_pkt(pkt, "192.168.1.1", 5000, "8.8.8.8", 53);

    uint32_t h = flow_hash_pkt(pkt, 28);
    ASSERT_NEQ(h, 0);

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
        uint32_t h = flow_hash_pkt(pkt, 40);
        ASSERT_NEQ(h, 0);
    }

    PASS();
}

static void
test_hash_each_field_matters(void)
{
    TEST(flow_hash_pkt each 5-tuple field matters);

    uint8_t base[40];
    make_tcp_pkt(base, "10.0.0.1", 1234, "10.0.0.2", 80);
    uint32_t h_base = flow_hash_pkt(base, 40);

    /* Change src_ip */
    uint8_t pkt[40];
    make_tcp_pkt(pkt, "10.0.0.99", 1234, "10.0.0.2", 80);
    ASSERT_NEQ(flow_hash_pkt(pkt, 40), h_base);

    /* Change dst_ip */
    make_tcp_pkt(pkt, "10.0.0.1", 1234, "10.0.0.99", 80);
    ASSERT_NEQ(flow_hash_pkt(pkt, 40), h_base);

    /* Change src_port */
    make_tcp_pkt(pkt, "10.0.0.1", 9999, "10.0.0.2", 80);
    ASSERT_NEQ(flow_hash_pkt(pkt, 40), h_base);

    /* Change dst_port */
    make_tcp_pkt(pkt, "10.0.0.1", 1234, "10.0.0.2", 443);
    ASSERT_NEQ(flow_hash_pkt(pkt, 40), h_base);

    /* Change protocol (TCP→UDP, same IPs/ports) */
    make_udp_pkt(pkt, "10.0.0.1", 1234, "10.0.0.2", 80);
    ASSERT_NEQ(flow_hash_pkt(pkt, 28), h_base);

    PASS();
}

static void
test_hash_icmp_no_ports(void)
{
    TEST(flow_hash_pkt ICMP (no L4 ports));

    uint8_t pkt[28];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;  /* IPv4, IHL=5 */
    pkt[9] = 1;     /* ICMP */

    struct in_addr a;
    inet_pton(AF_INET, "10.0.0.1", &a);
    memcpy(pkt + 12, &a, 4);
    inet_pton(AF_INET, "10.0.0.2", &a);
    memcpy(pkt + 16, &a, 4);

    /* Should hash on src_ip + dst_ip + proto only (no ports for ICMP) */
    uint32_t h = flow_hash_pkt(pkt, 28);
    ASSERT_NEQ(h, 0);

    /* Deterministic */
    ASSERT_EQ(flow_hash_pkt(pkt, 28), h);

    PASS();
}

static void
test_hash_ip_header_only(void)
{
    TEST(flow_hash_pkt IP header only (len=20));

    /* Packet with exactly 20 bytes — no L4 data available */
    uint8_t pkt[20];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;  /* IPv4, IHL=5 */
    pkt[9] = 6;     /* TCP */

    struct in_addr a;
    inet_pton(AF_INET, "10.0.0.1", &a);
    memcpy(pkt + 12, &a, 4);
    inet_pton(AF_INET, "10.0.0.2", &a);
    memcpy(pkt + 16, &a, 4);

    /* len < ihl + 4, so ports are skipped; still hashes IPs + proto */
    uint32_t h = flow_hash_pkt(pkt, 20);
    ASSERT_NEQ(h, 0);

    PASS();
}

static void
test_hash_zero_length(void)
{
    TEST(flow_hash_pkt zero length returns 0);

    uint8_t pkt[1] = {0x45};
    ASSERT_EQ(flow_hash_pkt(pkt, 0), 0);
    ASSERT_EQ(flow_hash_pkt(NULL, 0), 0);

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
        uint32_t h = flow_hash_pkt(pkt, 40);
        uint8_t low = h & 0xff;
        if (!seen[low]) { seen[low] = 1; distinct++; }
    }

    /* With 1000 hashes, expect close to 256 distinct low bytes.
     * Use a very conservative threshold. */
    assert(distinct >= 100);

    PASS();
}

static void
test_sched_mode_constants(void)
{
    TEST(scheduler mode constants);

    ASSERT_EQ(MQVPN_SCHED_MINRTT, 0);
    ASSERT_EQ(MQVPN_SCHED_WLB, 1);
    ASSERT_NEQ(MQVPN_SCHED_MINRTT, MQVPN_SCHED_WLB);

    PASS();
}

/* ── Main ── */

int
main(void)
{
    printf("=== flow_sched unit tests ===\n\n");

    test_hash_basic();
    test_hash_different_flows();
    test_hash_rejects_non_ipv4();
    test_hash_udp();
    test_hash_never_returns_zero();
    test_hash_each_field_matters();
    test_hash_icmp_no_ports();
    test_hash_ip_header_only();
    test_hash_zero_length();
    test_hash_distribution();
    test_sched_mode_constants();

    printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
