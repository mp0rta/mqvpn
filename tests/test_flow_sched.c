/*
 * test_flow_sched.c — Unit tests for the WLB flow scheduler
 *
 * Build:  cc -o test_flow_sched tests/test_flow_sched.c src/flow_sched.c src/log.c
 *             -I src -I third_party/xquic/include -lrt
 * Run:    ./test_flow_sched
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

/* Need xqc_path_metrics_t definition */
#include <xquic/xquic.h>
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

/* ── Helper: build a fake IPv4/TCP packet ── */

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
test_init_disabled(void)
{
    TEST(flow_sched_init disabled);

    flow_sched_t fs;
    flow_sched_init(&fs, MQVPN_SCHED_MINRTT);
    ASSERT_EQ(fs.enabled, 0);
    ASSERT_EQ(fs.n_paths, 0);

    PASS();
}

static void
test_init_enabled(void)
{
    TEST(flow_sched_init enabled);

    flow_sched_t fs;
    flow_sched_init(&fs, MQVPN_SCHED_WLB);
    ASSERT_EQ(fs.enabled, 1);

    PASS();
}

static void
test_disabled_returns_max(void)
{
    TEST(disabled scheduler returns UINT64_MAX);

    flow_sched_t fs;
    flow_sched_init(&fs, MQVPN_SCHED_MINRTT);
    flow_sched_add_path(&fs, 0);
    flow_sched_add_path(&fs, 1);

    uint8_t pkt[40];
    make_tcp_pkt(pkt, "10.0.0.1", 1234, "10.0.0.2", 80);
    ASSERT_EQ(flow_sched_get_path(&fs, pkt, 40), UINT64_MAX);

    PASS();
}

static void
test_single_path_returns_max(void)
{
    TEST(single path returns UINT64_MAX);

    flow_sched_t fs;
    flow_sched_init(&fs, MQVPN_SCHED_WLB);
    flow_sched_add_path(&fs, 0);

    uint8_t pkt[40];
    make_tcp_pkt(pkt, "10.0.0.1", 1234, "10.0.0.2", 80);
    ASSERT_EQ(flow_sched_get_path(&fs, pkt, 40), UINT64_MAX);

    PASS();
}

static void
test_two_paths_assigns_flow(void)
{
    TEST(two paths assigns flow);

    flow_sched_t fs;
    flow_sched_init(&fs, MQVPN_SCHED_WLB);
    flow_sched_add_path(&fs, 0);
    flow_sched_add_path(&fs, 1);

    uint8_t pkt[40];
    make_tcp_pkt(pkt, "10.0.0.1", 1234, "10.0.0.2", 80);

    uint64_t path = flow_sched_get_path(&fs, pkt, 40);
    ASSERT_NEQ(path, UINT64_MAX);

    /* Should be path 0 or 1 */
    assert(path == 0 || path == 1);

    PASS();
}

static void
test_flow_stickiness(void)
{
    TEST(same flow sticks to same path);

    flow_sched_t fs;
    flow_sched_init(&fs, MQVPN_SCHED_WLB);
    flow_sched_add_path(&fs, 0);
    flow_sched_add_path(&fs, 1);

    uint8_t pkt[40];
    make_tcp_pkt(pkt, "10.0.0.1", 1234, "10.0.0.2", 80);

    uint64_t path1 = flow_sched_get_path(&fs, pkt, 40);
    uint64_t path2 = flow_sched_get_path(&fs, pkt, 40);
    uint64_t path3 = flow_sched_get_path(&fs, pkt, 40);

    ASSERT_EQ(path1, path2);
    ASSERT_EQ(path2, path3);

    PASS();
}

static void
test_different_flows_distribute(void)
{
    TEST(different flows distributed across paths);

    flow_sched_t fs;
    flow_sched_init(&fs, MQVPN_SCHED_WLB);
    flow_sched_add_path(&fs, 10);
    flow_sched_add_path(&fs, 20);

    /* With equal weights (default), flows should alternate between paths */
    int count[2] = {0, 0};
    for (int i = 0; i < 20; i++) {
        uint8_t pkt[40];
        make_tcp_pkt(pkt, "10.0.0.1", 1000 + i, "10.0.0.2", 80);
        uint64_t path = flow_sched_get_path(&fs, pkt, 40);
        if (path == 10) count[0]++;
        else if (path == 20) count[1]++;
    }

    /* Both paths should get some flows */
    assert(count[0] > 0);
    assert(count[1] > 0);

    PASS();
}

static void
test_weight_update_affects_distribution(void)
{
    TEST(weight update affects distribution);

    flow_sched_t fs;
    flow_sched_init(&fs, MQVPN_SCHED_WLB);
    flow_sched_add_path(&fs, 0);
    flow_sched_add_path(&fs, 1);

    /* Give path 0 much higher weight via metrics update */
    xqc_path_metrics_t metrics[2];
    memset(metrics, 0, sizeof(metrics));

    metrics[0].path_id = 0;
    metrics[0].path_est_bw = 100000000;  /* 100 Mbps */
    metrics[0].path_srtt = 10000;        /* 10ms */
    metrics[0].path_min_rtt = 10000;
    metrics[0].path_cwnd = 125000;
    metrics[0].path_pkt_send_count = 100;
    metrics[0].path_lost_count = 0;

    metrics[1].path_id = 1;
    metrics[1].path_est_bw = 10000000;   /* 10 Mbps */
    metrics[1].path_srtt = 50000;        /* 50ms */
    metrics[1].path_min_rtt = 50000;
    metrics[1].path_cwnd = 62500;
    metrics[1].path_pkt_send_count = 100;
    metrics[1].path_lost_count = 0;

    flow_sched_update(&fs, metrics, 2);

    /* Path 0 should have much higher weight */
    assert(fs.paths[0].weight > fs.paths[1].weight);

    /* After update, new flows should favor path 0 */
    int count[2] = {0, 0};
    for (int i = 0; i < 20; i++) {
        uint8_t pkt[40];
        make_tcp_pkt(pkt, "192.168.1.1", 2000 + i, "8.8.8.8", 443);
        uint64_t path = flow_sched_get_path(&fs, pkt, 40);
        if (path == 0) count[0]++;
        else if (path == 1) count[1]++;
    }

    /* Path 0 should get significantly more flows */
    assert(count[0] > count[1]);

    PASS();
}

static void
test_loss_penalizes_weight(void)
{
    TEST(loss penalizes weight);

    flow_sched_t fs;
    flow_sched_init(&fs, MQVPN_SCHED_WLB);
    flow_sched_add_path(&fs, 0);
    flow_sched_add_path(&fs, 1);

    /* Same bandwidth, but path 1 has 50% loss */
    xqc_path_metrics_t metrics[2];
    memset(metrics, 0, sizeof(metrics));

    metrics[0].path_id = 0;
    metrics[0].path_est_bw = 50000000;
    metrics[0].path_srtt = 20000;
    metrics[0].path_min_rtt = 20000;
    metrics[0].path_pkt_send_count = 100;
    metrics[0].path_lost_count = 0;

    metrics[1].path_id = 1;
    metrics[1].path_est_bw = 50000000;
    metrics[1].path_srtt = 20000;
    metrics[1].path_min_rtt = 20000;
    metrics[1].path_pkt_send_count = 100;
    metrics[1].path_lost_count = 50;  /* 50% loss */

    flow_sched_update(&fs, metrics, 2);

    /* Path 0 weight should be ~2x path 1 weight */
    assert(fs.paths[0].weight > fs.paths[1].weight * 1.5);

    PASS();
}

static void
test_queue_delay_penalizes_weight(void)
{
    TEST(queue delay penalizes weight);

    flow_sched_t fs;
    flow_sched_init(&fs, MQVPN_SCHED_WLB);
    flow_sched_add_path(&fs, 0);
    flow_sched_add_path(&fs, 1);

    /* Same bandwidth, but path 1 has 5x queue delay (srtt >> min_rtt) */
    xqc_path_metrics_t metrics[2];
    memset(metrics, 0, sizeof(metrics));

    metrics[0].path_id = 0;
    metrics[0].path_est_bw = 50000000;
    metrics[0].path_srtt = 20000;     /* 20ms */
    metrics[0].path_min_rtt = 20000;  /* no queueing */
    metrics[0].path_pkt_send_count = 100;

    metrics[1].path_id = 1;
    metrics[1].path_est_bw = 50000000;
    metrics[1].path_srtt = 100000;    /* 100ms */
    metrics[1].path_min_rtt = 20000;  /* min was 20ms → 80ms queueing */
    metrics[1].path_pkt_send_count = 100;

    flow_sched_update(&fs, metrics, 2);

    /* Path 0 weight should be ~5x path 1 (rtt_q: 1.0 vs 0.2) */
    assert(fs.paths[0].weight > fs.paths[1].weight * 3);

    PASS();
}

static void
test_path_removal_migrates_flows(void)
{
    TEST(path removal causes flow re-assignment);

    flow_sched_t fs;
    flow_sched_init(&fs, MQVPN_SCHED_WLB);
    flow_sched_add_path(&fs, 0);
    flow_sched_add_path(&fs, 1);

    uint8_t pkt[40];
    make_tcp_pkt(pkt, "10.0.0.1", 5555, "10.0.0.2", 80);

    uint64_t original = flow_sched_get_path(&fs, pkt, 40);
    assert(original == 0 || original == 1);

    /* Remove the assigned path */
    flow_sched_remove_path(&fs, original);

    /* Same flow should now go to the other path */
    uint64_t migrated = flow_sched_get_path(&fs, pkt, 40);
    uint64_t other = (original == 0) ? 1 : 0;
    ASSERT_EQ(migrated, other);

    PASS();
}

static void
test_flow_expiry(void)
{
    TEST(flow expiry clears stale entries);

    flow_sched_t fs;
    flow_sched_init(&fs, MQVPN_SCHED_WLB);
    flow_sched_add_path(&fs, 0);
    flow_sched_add_path(&fs, 1);

    uint8_t pkt[40];
    make_tcp_pkt(pkt, "10.0.0.1", 7777, "10.0.0.2", 80);

    flow_sched_get_path(&fs, pkt, 40);

    /* Verify flow exists */
    uint32_t h = flow_hash_pkt(pkt, 40);
    int found = 0;
    for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
        if (fs.flows[i].hash == h) { found = 1; break; }
    }
    assert(found);

    /* Expire with a timestamp far in the future */
    uint64_t future = fs.flows[0].last_seen + FLOW_EXPIRE_US + 1;
    /* Find the actual entry */
    for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
        if (fs.flows[i].hash == h) {
            future = fs.flows[i].last_seen + FLOW_EXPIRE_US + 1;
            break;
        }
    }
    flow_sched_expire(&fs, future);

    /* Flow should be gone */
    found = 0;
    for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
        if (fs.flows[i].hash == h) { found = 1; break; }
    }
    ASSERT_EQ(found, 0);

    PASS();
}

static void
test_cold_start_uses_cwnd(void)
{
    TEST(cold start uses cwnd/srtt as bw estimate);

    flow_sched_t fs;
    flow_sched_init(&fs, MQVPN_SCHED_WLB);
    flow_sched_add_path(&fs, 0);
    flow_sched_add_path(&fs, 1);

    xqc_path_metrics_t metrics[2];
    memset(metrics, 0, sizeof(metrics));

    /* est_bw = 0 (cold start), but cwnd and srtt are available */
    metrics[0].path_id = 0;
    metrics[0].path_est_bw = 0;
    metrics[0].path_cwnd = 100000;    /* 100KB */
    metrics[0].path_srtt = 20000;     /* 20ms */
    metrics[0].path_min_rtt = 20000;
    metrics[0].path_pkt_send_count = 100;

    metrics[1].path_id = 1;
    metrics[1].path_est_bw = 0;
    metrics[1].path_cwnd = 50000;     /* 50KB */
    metrics[1].path_srtt = 20000;
    metrics[1].path_min_rtt = 20000;
    metrics[1].path_pkt_send_count = 100;

    flow_sched_update(&fs, metrics, 2);

    /* Path 0 should have ~2x weight (100K/20ms vs 50K/20ms) */
    assert(fs.paths[0].weight > fs.paths[1].weight * 1.5);

    PASS();
}

static void
test_path_can_send_with_headroom(void)
{
    TEST(cwnd gating allows send with headroom);

    flow_sched_t fs;
    flow_sched_init(&fs, MQVPN_SCHED_WLB);
    flow_sched_add_path(&fs, 0);
    flow_sched_add_path(&fs, 1);

    xqc_path_metrics_t metrics[2];
    memset(metrics, 0, sizeof(metrics));

    /* Path 0: plenty of cwnd headroom */
    metrics[0].path_id = 0;
    metrics[0].path_cwnd = 100000;
    metrics[0].path_bytes_in_flight = 10000;
    metrics[0].path_est_bw = 10000000;
    metrics[0].path_srtt = 10000;
    metrics[0].path_min_rtt = 10000;
    metrics[0].path_pkt_send_count = 100;

    /* Path 1: nearly full cwnd */
    metrics[1].path_id = 1;
    metrics[1].path_cwnd = 100000;
    metrics[1].path_bytes_in_flight = 95000;
    metrics[1].path_est_bw = 10000000;
    metrics[1].path_srtt = 10000;
    metrics[1].path_min_rtt = 10000;
    metrics[1].path_pkt_send_count = 100;

    flow_sched_update(&fs, metrics, 2);

    /* Path 0 has headroom → can send */
    ASSERT_EQ(flow_sched_path_can_send(&fs, 0, 1400), 1);

    /* Path 1 is nearly full → cannot send (inflight + pkt + 25% headroom > cwnd) */
    ASSERT_EQ(flow_sched_path_can_send(&fs, 1, 1400), 0);

    /* Unknown path → cannot send */
    ASSERT_EQ(flow_sched_path_can_send(&fs, 99, 1400), 0);

    PASS();
}

static void
test_path_can_send_zero_cwnd(void)
{
    TEST(cwnd gating rejects zero cwnd);

    flow_sched_t fs;
    flow_sched_init(&fs, MQVPN_SCHED_WLB);
    flow_sched_add_path(&fs, 0);

    /* No update called yet — cwnd=0 */
    ASSERT_EQ(flow_sched_path_can_send(&fs, 0, 1400), 0);

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
    test_init_disabled();
    test_init_enabled();
    test_disabled_returns_max();
    test_single_path_returns_max();
    test_two_paths_assigns_flow();
    test_flow_stickiness();
    test_different_flows_distribute();
    test_weight_update_affects_distribution();
    test_loss_penalizes_weight();
    test_queue_delay_penalizes_weight();
    test_path_removal_migrates_flows();
    test_flow_expiry();
    test_cold_start_uses_cwnd();
    test_path_can_send_with_headroom();
    test_path_can_send_zero_cwnd();

    printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
