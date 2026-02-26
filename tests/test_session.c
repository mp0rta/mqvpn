/*
 * test_session.c — unit tests for IP-offset based session table lookup
 *
 * Validates the offset calculation used in svr_tun_read_handler
 * for O(1) session routing.
 *
 * Build: cc -o tests/test_session tests/test_session.c src/addr_pool.c src/log.c -Isrc
 */
#include "addr_pool.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

static int g_pass = 0, g_fail = 0;

#define ASSERT_EQ_INT(a, b, msg) do { \
    if ((a) == (b)) { g_pass++; } \
    else { g_fail++; fprintf(stderr, "FAIL [%s]: %d != %d\n", msg, (int)(a), (int)(b)); } \
} while(0)

#define ASSERT_EQ_STR(a, b, msg) do { \
    if (strcmp((a), (b)) == 0) { g_pass++; } \
    else { g_fail++; fprintf(stderr, "FAIL [%s]: '%s' != '%s'\n", msg, (a), (b)); } \
} while(0)

#define ASSERT_TRUE(cond, msg) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; fprintf(stderr, "FAIL [%s]\n", msg); } \
} while(0)

static void test_offset_calculation(void)
{
    mqvpn_addr_pool_t pool;
    ASSERT_EQ_INT(mqvpn_addr_pool_init(&pool, "10.0.0.0/24"), 0,
                  "pool init");

    /* Base is 10.0.0.0 */
    char base_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &pool.base, base_str, sizeof(base_str));
    ASSERT_EQ_STR(base_str, "10.0.0.0", "base address");

    /* Alloc first IP — should be 10.0.0.2 (offset=2, .1 is server) */
    struct in_addr ip1;
    ASSERT_EQ_INT(mqvpn_addr_pool_alloc(&pool, &ip1), 0, "alloc ip1");
    char ip1_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip1, ip1_str, sizeof(ip1_str));
    ASSERT_EQ_STR(ip1_str, "10.0.0.2", "first alloc is .2");

    /* Offset calculation (same as svr_tun_read_handler) */
    uint32_t offset1 = ntohl(ip1.s_addr) - ntohl(pool.base.s_addr);
    ASSERT_EQ_INT(offset1, 2, "offset of .2 is 2");

    /* Alloc second IP — should be 10.0.0.3 (offset=3) */
    struct in_addr ip2;
    ASSERT_EQ_INT(mqvpn_addr_pool_alloc(&pool, &ip2), 0, "alloc ip2");
    char ip2_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip2, ip2_str, sizeof(ip2_str));
    ASSERT_EQ_STR(ip2_str, "10.0.0.3", "second alloc is .3");

    uint32_t offset2 = ntohl(ip2.s_addr) - ntohl(pool.base.s_addr);
    ASSERT_EQ_INT(offset2, 3, "offset of .3 is 3");

    /* Different offsets should be different */
    ASSERT_TRUE(offset1 != offset2, "offsets are different");
}

static void test_offset_boundary(void)
{
    mqvpn_addr_pool_t pool;
    ASSERT_EQ_INT(mqvpn_addr_pool_init(&pool, "10.0.0.0/24"), 0,
                  "pool init for boundary test");

    /* Server IP (.1) offset should be 1 */
    struct in_addr server_ip;
    mqvpn_addr_pool_server_addr(&pool, &server_ip);
    uint32_t server_offset = ntohl(server_ip.s_addr) - ntohl(pool.base.s_addr);
    ASSERT_EQ_INT(server_offset, 1, "server offset is 1");

    /* Offset 0 = network address (out of range for sessions) */
    /* Offset 255 = broadcast (out of range for sessions) */
    /* Valid session offsets: 2-254 */

    /* Allocate all IPs and verify offsets stay in range */
    struct in_addr ips[253]; /* .2 through .254 */
    int count = 0;
    for (int i = 0; i < 253; i++) {
        if (mqvpn_addr_pool_alloc(&pool, &ips[i]) < 0) break;
        uint32_t off = ntohl(ips[i].s_addr) - ntohl(pool.base.s_addr);
        if (off >= 2 && off <= 254) count++;
    }
    ASSERT_EQ_INT(count, 253, "all 253 IPs have valid offsets (2-254)");

    /* Pool should be exhausted now */
    struct in_addr extra;
    ASSERT_TRUE(mqvpn_addr_pool_alloc(&pool, &extra) < 0,
                "pool exhausted after 253 allocs");
}

static void test_release_and_realloc(void)
{
    mqvpn_addr_pool_t pool;
    ASSERT_EQ_INT(mqvpn_addr_pool_init(&pool, "192.168.1.0/24"), 0,
                  "pool init 192.168.1.0/24");

    struct in_addr ip1, ip2;
    ASSERT_EQ_INT(mqvpn_addr_pool_alloc(&pool, &ip1), 0, "alloc ip1");
    ASSERT_EQ_INT(mqvpn_addr_pool_alloc(&pool, &ip2), 0, "alloc ip2");

    /* Release ip1 */
    mqvpn_addr_pool_release(&pool, &ip1);

    /* Offset of released IP should still be calculable */
    uint32_t off1 = ntohl(ip1.s_addr) - ntohl(pool.base.s_addr);
    ASSERT_TRUE(off1 >= 2 && off1 <= 254, "released IP has valid offset");

    /* Re-alloc should eventually give back ip1's offset */
    struct in_addr ip3;
    ASSERT_EQ_INT(mqvpn_addr_pool_alloc(&pool, &ip3), 0, "realloc after release");
}

static void test_session_table_simulation(void)
{
    /* Simulate what the server does: sessions[offset] = conn */
    mqvpn_addr_pool_t pool;
    ASSERT_EQ_INT(mqvpn_addr_pool_init(&pool, "10.0.0.0/24"), 0,
                  "pool init for simulation");

    /* Simulate session table */
    int sessions[MQVPN_ADDR_POOL_MAX + 1]; /* 0=unused, nonzero=active */
    memset(sessions, 0, sizeof(sessions));
    int n_sessions = 0;

    /* Allocate 3 IPs and register */
    struct in_addr ips[3];
    for (int i = 0; i < 3; i++) {
        ASSERT_EQ_INT(mqvpn_addr_pool_alloc(&pool, &ips[i]), 0, "alloc for sim");
        uint32_t off = ntohl(ips[i].s_addr) - ntohl(pool.base.s_addr);
        sessions[off] = i + 1; /* nonzero = active */
        n_sessions++;
    }
    ASSERT_EQ_INT(n_sessions, 3, "3 sessions registered");

    /* Simulate packet routing: dst=10.0.0.3 → offset=3 → sessions[3] */
    struct in_addr dst;
    inet_pton(AF_INET, "10.0.0.3", &dst);
    uint32_t lookup_off = ntohl(dst.s_addr) - ntohl(pool.base.s_addr);
    ASSERT_EQ_INT(lookup_off, 3, "lookup offset for .3");
    ASSERT_TRUE(sessions[lookup_off] != 0, "session found for .3");

    /* Unknown IP → no session */
    inet_pton(AF_INET, "10.0.0.100", &dst);
    lookup_off = ntohl(dst.s_addr) - ntohl(pool.base.s_addr);
    ASSERT_EQ_INT(sessions[lookup_off], 0, "no session for .100");

    /* Remove session for .2 */
    uint32_t off_to_remove = ntohl(ips[0].s_addr) - ntohl(pool.base.s_addr);
    sessions[off_to_remove] = 0;
    n_sessions--;
    ASSERT_EQ_INT(n_sessions, 2, "2 sessions after removal");

    /* .2 no longer found, .3 and .4 still found */
    inet_pton(AF_INET, "10.0.0.2", &dst);
    lookup_off = ntohl(dst.s_addr) - ntohl(pool.base.s_addr);
    ASSERT_EQ_INT(sessions[lookup_off], 0, "session removed for .2");

    inet_pton(AF_INET, "10.0.0.4", &dst);
    lookup_off = ntohl(dst.s_addr) - ntohl(pool.base.s_addr);
    ASSERT_TRUE(sessions[lookup_off] != 0, "session still active for .4");
}

/* ---- CIDR parsing error tests ---- */

static void test_invalid_cidr_no_slash(void)
{
    mqvpn_addr_pool_t pool;
    ASSERT_TRUE(mqvpn_addr_pool_init(&pool, "10.0.0.0") < 0,
                "CIDR without slash rejected");
}

static void test_invalid_cidr_bad_prefix(void)
{
    mqvpn_addr_pool_t pool;

    /* Prefix > 30 → rejected */
    ASSERT_TRUE(mqvpn_addr_pool_init(&pool, "10.0.0.0/31") < 0,
                "prefix /31 rejected");
    ASSERT_TRUE(mqvpn_addr_pool_init(&pool, "10.0.0.0/32") < 0,
                "prefix /32 rejected");

    /* Prefix < 16 → rejected */
    ASSERT_TRUE(mqvpn_addr_pool_init(&pool, "10.0.0.0/15") < 0,
                "prefix /15 rejected");
    ASSERT_TRUE(mqvpn_addr_pool_init(&pool, "10.0.0.0/8") < 0,
                "prefix /8 rejected");

    /* Prefix > 32 → rejected */
    ASSERT_TRUE(mqvpn_addr_pool_init(&pool, "10.0.0.0/33") < 0,
                "prefix /33 rejected");
}

static void test_invalid_cidr_bad_ip(void)
{
    mqvpn_addr_pool_t pool;
    ASSERT_TRUE(mqvpn_addr_pool_init(&pool, "999.0.0.0/24") < 0,
                "invalid IP rejected");
    ASSERT_TRUE(mqvpn_addr_pool_init(&pool, "not.an.ip/24") < 0,
                "non-IP rejected");
}

static void test_invalid_cidr_empty_prefix(void)
{
    mqvpn_addr_pool_t pool;
    /* "10.0.0.0/" → strtol on empty string → endptr == slash+1 → rejected */
    ASSERT_TRUE(mqvpn_addr_pool_init(&pool, "10.0.0.0/") < 0,
                "empty prefix rejected");
    /* Non-numeric prefix */
    ASSERT_TRUE(mqvpn_addr_pool_init(&pool, "10.0.0.0/abc") < 0,
                "non-numeric prefix rejected");
}

static void test_subnet_size_28(void)
{
    /* /28 = 16 addresses, 14 usable (minus network + broadcast) */
    mqvpn_addr_pool_t pool;
    ASSERT_EQ_INT(mqvpn_addr_pool_init(&pool, "10.0.0.0/28"), 0,
                  "pool init /28");
    ASSERT_EQ_INT(pool.pool_size, 14, "/28 has 14 usable addresses");

    /* Allocate all client IPs (skip .1 server → 13 client IPs: .2 through .14) */
    struct in_addr ip;
    int count = 0;
    while (mqvpn_addr_pool_alloc(&pool, &ip) == 0) count++;
    ASSERT_EQ_INT(count, 13, "/28 yields 13 client IPs");

    /* Exhausted */
    ASSERT_TRUE(mqvpn_addr_pool_alloc(&pool, &ip) < 0,
                "/28 pool exhausted");
}

static void test_subnet_size_16(void)
{
    /* /16 = 65534 usable, but capped at MQVPN_ADDR_POOL_MAX (254) */
    mqvpn_addr_pool_t pool;
    ASSERT_EQ_INT(mqvpn_addr_pool_init(&pool, "172.16.0.0/16"), 0,
                  "pool init /16");
    ASSERT_EQ_INT(pool.pool_size, MQVPN_ADDR_POOL_MAX,
                  "/16 capped at MQVPN_ADDR_POOL_MAX");
}

static void test_release_outside_range(void)
{
    mqvpn_addr_pool_t pool;
    ASSERT_EQ_INT(mqvpn_addr_pool_init(&pool, "10.0.0.0/24"), 0,
                  "pool init for release test");

    /* Release an IP that's outside the pool range → should be a no-op */
    struct in_addr outside;
    inet_pton(AF_INET, "192.168.1.1", &outside);
    mqvpn_addr_pool_release(&pool, &outside); /* should not crash */

    /* Release an IP below the base → underflow check */
    struct in_addr below;
    inet_pton(AF_INET, "9.255.255.255", &below);
    mqvpn_addr_pool_release(&pool, &below); /* should not crash */

    /* Pool should still work normally after bad releases */
    struct in_addr ip;
    ASSERT_EQ_INT(mqvpn_addr_pool_alloc(&pool, &ip), 0,
                  "alloc works after bad releases");
}

static void test_release_double_free(void)
{
    mqvpn_addr_pool_t pool;
    ASSERT_EQ_INT(mqvpn_addr_pool_init(&pool, "10.0.0.0/24"), 0,
                  "pool init for double-free test");

    struct in_addr ip;
    ASSERT_EQ_INT(mqvpn_addr_pool_alloc(&pool, &ip), 0, "alloc for double-free");

    /* Release once */
    mqvpn_addr_pool_release(&pool, &ip);

    /* Release again → should not crash, just set used[off]=0 again */
    mqvpn_addr_pool_release(&pool, &ip);

    /* Verify pool still works: should be able to allocate the same IP */
    struct in_addr ip2;
    ASSERT_EQ_INT(mqvpn_addr_pool_alloc(&pool, &ip2), 0,
                  "alloc after double release");
}

static void test_fragmented_allocation(void)
{
    /* Exhaust the pool, release 2, then verify those 2 are reusable */
    mqvpn_addr_pool_t pool;
    ASSERT_EQ_INT(mqvpn_addr_pool_init(&pool, "10.0.0.0/28"), 0,
                  "pool init /28 for fragmented test");

    /* Allocate all 13 client IPs (.2-.14) */
    struct in_addr ips[13];
    for (int i = 0; i < 13; i++) {
        ASSERT_EQ_INT(mqvpn_addr_pool_alloc(&pool, &ips[i]), 0,
                      "alloc for frag test");
    }

    /* Pool is exhausted */
    struct in_addr extra;
    ASSERT_TRUE(mqvpn_addr_pool_alloc(&pool, &extra) < 0,
                "pool exhausted before release");

    /* Release 2 IPs in the middle (create holes) */
    uint32_t base_h = ntohl(pool.base.s_addr);
    uint32_t rel1_off = ntohl(ips[2].s_addr) - base_h; /* .4 */
    uint32_t rel2_off = ntohl(ips[6].s_addr) - base_h; /* .8 */
    mqvpn_addr_pool_release(&pool, &ips[2]);
    mqvpn_addr_pool_release(&pool, &ips[6]);

    /* Allocate 2 — must reuse the released offsets (no others available) */
    struct in_addr fill1, fill2;
    ASSERT_EQ_INT(mqvpn_addr_pool_alloc(&pool, &fill1), 0, "fill hole 1");
    ASSERT_EQ_INT(mqvpn_addr_pool_alloc(&pool, &fill2), 0, "fill hole 2");

    uint32_t fill1_off = ntohl(fill1.s_addr) - base_h;
    uint32_t fill2_off = ntohl(fill2.s_addr) - base_h;

    /* Both released offsets should be re-assigned */
    ASSERT_TRUE((fill1_off == rel1_off || fill1_off == rel2_off),
                "first fill reuses released offset");
    ASSERT_TRUE((fill2_off == rel1_off || fill2_off == rel2_off),
                "second fill reuses released offset");
    ASSERT_TRUE(fill1_off != fill2_off,
                "fills are different offsets");

    /* Pool is exhausted again */
    ASSERT_TRUE(mqvpn_addr_pool_alloc(&pool, &extra) < 0,
                "pool exhausted after re-fill");
}

static void test_server_addr(void)
{
    mqvpn_addr_pool_t pool;
    ASSERT_EQ_INT(mqvpn_addr_pool_init(&pool, "172.16.5.0/24"), 0,
                  "pool init for server_addr test");

    struct in_addr svr;
    mqvpn_addr_pool_server_addr(&pool, &svr);
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &svr, str, sizeof(str));
    ASSERT_EQ_STR(str, "172.16.5.1", "server addr is .1");
}

static void test_prefix_boundary_16(void)
{
    mqvpn_addr_pool_t pool;
    ASSERT_EQ_INT(mqvpn_addr_pool_init(&pool, "10.0.0.0/16"), 0,
                  "prefix /16 accepted");
    ASSERT_EQ_INT(pool.prefix_len, 16, "prefix_len is 16");
}

static void test_prefix_boundary_30(void)
{
    /* /30 = 4 addresses, 2 usable */
    mqvpn_addr_pool_t pool;
    ASSERT_EQ_INT(mqvpn_addr_pool_init(&pool, "10.0.0.0/30"), 0,
                  "prefix /30 accepted");
    ASSERT_EQ_INT(pool.pool_size, 2, "/30 has 2 usable addresses");

    /* .1 is server, .2 is the only client */
    struct in_addr ip;
    ASSERT_EQ_INT(mqvpn_addr_pool_alloc(&pool, &ip), 0, "/30 alloc .2");

    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, str, sizeof(str));
    ASSERT_EQ_STR(str, "10.0.0.2", "/30 first alloc is .2");

    /* Pool should be exhausted now (.1 is server) */
    ASSERT_TRUE(mqvpn_addr_pool_alloc(&pool, &ip) < 0,
                "/30 exhausted after 1 client");
}

/* ---- IPv6 pool tests ---- */

static void test_ipv6_pool_init(void)
{
    mqvpn_addr_pool_t pool;
    ASSERT_EQ_INT(mqvpn_addr_pool_init(&pool, "10.0.0.0/24"), 0,
                  "v4 pool init for v6 test");
    ASSERT_EQ_INT(mqvpn_addr_pool_init6(&pool, "fd00:abcd::/112"), 0,
                  "v6 pool init");
    ASSERT_EQ_INT(pool.has_v6, 1, "has_v6 set");
    ASSERT_EQ_INT(pool.prefix6, 112, "prefix6 is 112");
}

static void test_ipv6_pool_get6(void)
{
    mqvpn_addr_pool_t pool;
    mqvpn_addr_pool_init(&pool, "10.0.0.0/24");
    mqvpn_addr_pool_init6(&pool, "fd00:abcd::/112");

    /* Server addr (offset=1) */
    struct in6_addr srv6;
    mqvpn_addr_pool_server_addr6(&pool, &srv6);
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &srv6, str, sizeof(str));
    ASSERT_EQ_STR(str, "fd00:abcd::1", "server v6 addr is ::1");

    /* Client offset=2 → fd00:abcd::2 */
    struct in6_addr cli6;
    mqvpn_addr_pool_get6(&pool, 2, &cli6);
    inet_ntop(AF_INET6, &cli6, str, sizeof(str));
    ASSERT_EQ_STR(str, "fd00:abcd::2", "offset 2 → ::2");

    /* Client offset=100 → fd00:abcd::64 */
    mqvpn_addr_pool_get6(&pool, 100, &cli6);
    inet_ntop(AF_INET6, &cli6, str, sizeof(str));
    ASSERT_EQ_STR(str, "fd00:abcd::64", "offset 100 → ::64");
}

static void test_ipv6_pool_offset6(void)
{
    mqvpn_addr_pool_t pool;
    mqvpn_addr_pool_init(&pool, "10.0.0.0/24");
    mqvpn_addr_pool_init6(&pool, "fd00:abcd::/112");

    /* Round-trip: get6(offset) → offset6(addr) */
    struct in6_addr addr;
    mqvpn_addr_pool_get6(&pool, 42, &addr);
    uint32_t off = mqvpn_addr_pool_offset6(&pool, &addr);
    ASSERT_EQ_INT(off, 42, "offset6 round-trip for 42");

    mqvpn_addr_pool_get6(&pool, 1, &addr);
    off = mqvpn_addr_pool_offset6(&pool, &addr);
    ASSERT_EQ_INT(off, 1, "offset6 round-trip for 1 (server)");

    /* Out-of-range address → 0 */
    struct in6_addr bad;
    inet_pton(AF_INET6, "2001:db8::1", &bad);
    off = mqvpn_addr_pool_offset6(&pool, &bad);
    ASSERT_EQ_INT(off, 0, "out-of-range v6 addr → offset 0");
}

static void test_ipv6_pool_init_bad_prefix(void)
{
    mqvpn_addr_pool_t pool;
    mqvpn_addr_pool_init(&pool, "10.0.0.0/24");

    /* Too small prefix */
    ASSERT_TRUE(mqvpn_addr_pool_init6(&pool, "fd00::/64") < 0,
                "/64 prefix rejected");

    /* Too large prefix */
    ASSERT_TRUE(mqvpn_addr_pool_init6(&pool, "fd00::/127") < 0,
                "/127 prefix rejected");

    /* No slash */
    ASSERT_TRUE(mqvpn_addr_pool_init6(&pool, "fd00::1") < 0,
                "no slash rejected");
}

static void test_ipv6_shared_offset(void)
{
    /* Verify IPv4 and IPv6 share the same offset */
    mqvpn_addr_pool_t pool;
    mqvpn_addr_pool_init(&pool, "10.0.0.0/24");
    mqvpn_addr_pool_init6(&pool, "fd00:abcd::/112");

    struct in_addr ip4;
    mqvpn_addr_pool_alloc(&pool, &ip4); /* .2 → offset 2 */
    uint32_t off4 = ntohl(ip4.s_addr) - ntohl(pool.base.s_addr);

    struct in6_addr ip6;
    mqvpn_addr_pool_get6(&pool, off4, &ip6);
    uint32_t off6 = mqvpn_addr_pool_offset6(&pool, &ip6);
    ASSERT_EQ_INT(off4, off6, "IPv4 and IPv6 share same offset");
}

int main(void)
{
    test_offset_calculation();
    test_offset_boundary();
    test_release_and_realloc();
    test_session_table_simulation();
    test_invalid_cidr_no_slash();
    test_invalid_cidr_bad_prefix();
    test_invalid_cidr_bad_ip();
    test_invalid_cidr_empty_prefix();
    test_subnet_size_28();
    test_subnet_size_16();
    test_release_outside_range();
    test_release_double_free();
    test_fragmented_allocation();
    test_server_addr();
    test_prefix_boundary_16();
    test_prefix_boundary_30();

    /* IPv6 pool tests */
    test_ipv6_pool_init();
    test_ipv6_pool_get6();
    test_ipv6_pool_offset6();
    test_ipv6_pool_init_bad_prefix();
    test_ipv6_shared_offset();

    printf("\n=== test_session: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
