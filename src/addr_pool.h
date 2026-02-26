#ifndef MQVPN_ADDR_POOL_H
#define MQVPN_ADDR_POOL_H

#include <stdint.h>
#include <netinet/in.h>

#define MQVPN_ADDR_POOL_MAX  254  /* /24 = 254 usable hosts */

typedef struct {
    struct in_addr  base;       /* network address (e.g. 10.0.0.0) */
    int             prefix_len; /* e.g. 24 */
    uint32_t        pool_size;  /* number of usable addresses */
    uint32_t        next;       /* next offset to try (starts at 2, .1=server) */
    uint8_t         used[MQVPN_ADDR_POOL_MAX + 1]; /* 1-indexed bitmap */

    /* IPv6 pool (optional, shares offsets with IPv4) */
    struct in6_addr base6;
    int             prefix6;
    int             has_v6;
} mqvpn_addr_pool_t;

/* Initialize pool from CIDR string (e.g. "10.0.0.0/24"). */
int  mqvpn_addr_pool_init(mqvpn_addr_pool_t *pool, const char *cidr);

/* Initialize IPv6 pool from CIDR string (e.g. "fd00:vpn::/112").
 * Call after mqvpn_addr_pool_init(). Shares offsets with IPv4 pool. */
int  mqvpn_addr_pool_init6(mqvpn_addr_pool_t *pool, const char *cidr6);

/* Allocate next available IP. Returns 0 on success, -1 if exhausted. */
int  mqvpn_addr_pool_alloc(mqvpn_addr_pool_t *pool, struct in_addr *out);

/* Release a previously allocated IP back to the pool. */
void mqvpn_addr_pool_release(mqvpn_addr_pool_t *pool, const struct in_addr *addr);

/* Get the server-side IP (.1) for this pool. */
void mqvpn_addr_pool_server_addr(const mqvpn_addr_pool_t *pool, struct in_addr *out);

/* Compute IPv6 address from a pool offset (same offset used for IPv4). */
void mqvpn_addr_pool_get6(const mqvpn_addr_pool_t *pool, uint32_t offset,
                           struct in6_addr *out);

/* Get the server-side IPv6 address (offset=1). */
void mqvpn_addr_pool_server_addr6(const mqvpn_addr_pool_t *pool,
                                   struct in6_addr *out);

/* Compute offset from an IPv6 address. Returns 0 if out of range. */
uint32_t mqvpn_addr_pool_offset6(const mqvpn_addr_pool_t *pool,
                                  const struct in6_addr *addr);

#endif /* MQVPN_ADDR_POOL_H */
