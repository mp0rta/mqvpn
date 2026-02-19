#include "addr_pool.h"
#include "log.h"

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

int
mqvpn_addr_pool_init(mqvpn_addr_pool_t *pool, const char *cidr)
{
    memset(pool, 0, sizeof(*pool));

    /* Parse "10.0.0.0/24" */
    char buf[32];
    strncpy(buf, cidr, sizeof(buf) - 1);
    char *slash = strchr(buf, '/');
    if (!slash) {
        LOG_ERR("addr_pool: invalid CIDR: %s", cidr);
        return -1;
    }
    *slash = '\0';
    char *endptr;
    long plen = strtol(slash + 1, &endptr, 10);
    if (endptr == slash + 1 || *endptr != '\0' || plen < 0 || plen > 32) {
        LOG_ERR("addr_pool: invalid prefix length in CIDR: %s", cidr);
        return -1;
    }
    pool->prefix_len = (int)plen;

    if (inet_pton(AF_INET, buf, &pool->base) != 1) {
        LOG_ERR("addr_pool: invalid address: %s", buf);
        return -1;
    }

    if (pool->prefix_len < 16 || pool->prefix_len > 30) {
        LOG_ERR("addr_pool: prefix length %d out of range [16,30]", pool->prefix_len);
        return -1;
    }

    uint32_t host_bits = 32 - pool->prefix_len;
    uint32_t total_hosts = (1U << host_bits) - 2; /* exclude network and broadcast */
    pool->pool_size = total_hosts > MQVPN_ADDR_POOL_MAX
                    ? MQVPN_ADDR_POOL_MAX : total_hosts;
    pool->next = 2; /* .1 is reserved for server */

    LOG_INF("addr_pool: %s, %u addresses available", cidr, pool->pool_size - 1);
    return 0;
}

int
mqvpn_addr_pool_alloc(mqvpn_addr_pool_t *pool, struct in_addr *out)
{
    /* Linear scan starting from pool->next */
    for (uint32_t i = 0; i < pool->pool_size; i++) {
        uint32_t off = ((pool->next - 1 + i) % pool->pool_size) + 1;
        /* skip offset 1 (server) */
        if (off == 1) continue;

        if (!pool->used[off]) {
            pool->used[off] = 1;
            pool->next = off + 1;
            uint32_t base_h = ntohl(pool->base.s_addr);
            out->s_addr = htonl(base_h + off);
            char str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, out, str, sizeof(str));
            LOG_INF("addr_pool: allocated %s", str);
            return 0;
        }
    }

    LOG_ERR("addr_pool: exhausted");
    return -1;
}

void
mqvpn_addr_pool_release(mqvpn_addr_pool_t *pool, const struct in_addr *addr)
{
    uint32_t base_h = ntohl(pool->base.s_addr);
    uint32_t addr_h = ntohl(addr->s_addr);
    if (addr_h < base_h) {
        LOG_WRN("addr_pool: release underflow: addr outside pool range");
        return;
    }
    uint32_t off = addr_h - base_h;

    if (off >= 1 && off <= pool->pool_size) {
        pool->used[off] = 0;
        char str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, addr, str, sizeof(str));
        LOG_INF("addr_pool: released %s", str);
    }
}

void
mqvpn_addr_pool_server_addr(const mqvpn_addr_pool_t *pool, struct in_addr *out)
{
    uint32_t base_h = ntohl(pool->base.s_addr);
    out->s_addr = htonl(base_h + 1);
}
