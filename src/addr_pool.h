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
} mqvpn_addr_pool_t;

/* Initialize pool from CIDR string (e.g. "10.0.0.0/24"). */
int  mqvpn_addr_pool_init(mqvpn_addr_pool_t *pool, const char *cidr);

/* Allocate next available IP. Returns 0 on success, -1 if exhausted. */
int  mqvpn_addr_pool_alloc(mqvpn_addr_pool_t *pool, struct in_addr *out);

/* Release a previously allocated IP back to the pool. */
void mqvpn_addr_pool_release(mqvpn_addr_pool_t *pool, const struct in_addr *addr);

/* Get the server-side IP (.1) for this pool. */
void mqvpn_addr_pool_server_addr(const mqvpn_addr_pool_t *pool, struct in_addr *out);

#endif /* MQVPN_ADDR_POOL_H */
