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

int main(void)
{
    test_offset_calculation();
    test_offset_boundary();
    test_release_and_realloc();
    test_session_table_simulation();

    printf("\n=== test_session: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
