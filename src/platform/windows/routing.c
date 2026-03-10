/*
 * routing.c — Split-tunnel route management for Windows
 *
 * Uses IPHLPAPI (CreateIpForwardEntry2 / DeleteIpForwardEntry2) to
 * install VPN routes:
 *   - Pin server IP through original gateway
 *   - Route 0.0.0.0/1 + 128.0.0.0/1 through TUN (split default)
 *   - IPv6 ::/1 + 8000::/1 through TUN
 */

#ifdef _WIN32

#  include "platform_internal_win.h"
#  include "log.h"

#  include <stdio.h>
#  include <string.h>

/* Helper: store a route entry for later cleanup */
static int
store_route(platform_win_ctx_t *p, const MIB_IPFORWARD_ROW2 *row)
{
    if (p->n_installed_routes >= MAX_INSTALLED_ROUTES) {
        LOG_WRN("routing: too many routes to track");
        return -1;
    }
    p->installed_routes[p->n_installed_routes++] = *row;
    return 0;
}

/* Helper: add a single IPv4 route */
static int
add_route4(platform_win_ctx_t *p, const char *dst, int prefix, const NET_LUID *luid,
           const struct in_addr *nexthop, ULONG metric)
{
    MIB_IPFORWARD_ROW2 row;
    InitializeIpForwardEntry(&row);

    row.InterfaceLuid = *luid;
    row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
    inet_pton(AF_INET, dst, &row.DestinationPrefix.Prefix.Ipv4.sin_addr);
    row.DestinationPrefix.PrefixLength = (UINT8)prefix;

    if (nexthop) {
        row.NextHop.Ipv4.sin_family = AF_INET;
        row.NextHop.Ipv4.sin_addr = *nexthop;
    }

    row.Metric = metric;
    row.Protocol = MIB_IPPROTO_NETMGMT;

    DWORD err = CreateIpForwardEntry2(&row);
    if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS) {
        LOG_ERR("CreateIpForwardEntry2(%s/%d): error %lu", dst, prefix, err);
        return -1;
    }

    store_route(p, &row);
    return 0;
}

/* Helper: add a single IPv6 route (nexthop may be NULL for on-link) */
static int
add_route6(platform_win_ctx_t *p, const char *dst, int prefix, const NET_LUID *luid,
           const struct in6_addr *nexthop, ULONG metric)
{
    MIB_IPFORWARD_ROW2 row;
    InitializeIpForwardEntry(&row);

    row.InterfaceLuid = *luid;
    row.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, dst, &row.DestinationPrefix.Prefix.Ipv6.sin6_addr);
    row.DestinationPrefix.PrefixLength = (UINT8)prefix;

    if (nexthop) {
        row.NextHop.Ipv6.sin6_family = AF_INET6;
        row.NextHop.Ipv6.sin6_addr = *nexthop;
    }

    row.Metric = metric;
    row.Protocol = MIB_IPPROTO_NETMGMT;

    DWORD err = CreateIpForwardEntry2(&row);
    if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS) {
        LOG_ERR("CreateIpForwardEntry2(%s/%d v6): error %lu", dst, prefix, err);
        return -1;
    }

    store_route(p, &row);
    return 0;
}

int
win_setup_routes(platform_win_ctx_t *p)
{
    if (p->routing_configured) return 0;

    p->n_installed_routes = 0;

    /*
     * 1. Discover the original route to the VPN server.
     *    This lets us pin the server address through the physical gateway.
     */
    MIB_IPFORWARD_ROW2 best;
    SOCKADDR_INET dest_addr;
    SOCKADDR_INET best_src;
    memset(&dest_addr, 0, sizeof(dest_addr));
    memset(&best_src, 0, sizeof(best_src));

    if (p->server_addr.ss_family == AF_INET) {
        dest_addr.Ipv4.sin_family = AF_INET;
        dest_addr.Ipv4.sin_addr = ((struct sockaddr_in *)&p->server_addr)->sin_addr;
    } else {
        dest_addr.Ipv6.sin6_family = AF_INET6;
        dest_addr.Ipv6.sin6_addr = ((struct sockaddr_in6 *)&p->server_addr)->sin6_addr;
    }

    DWORD err = GetBestRoute2(NULL, 0, NULL, &dest_addr, 0, &best, &best_src);
    if (err != NO_ERROR) {
        LOG_ERR("GetBestRoute2 for server: error %lu", err);
        return -1;
    }

    /*
     * 2. Pin the VPN server IP through the original gateway.
     */
    if (p->server_addr.ss_family == AF_INET) {
        struct in_addr gw = best.NextHop.Ipv4.sin_addr;
        if (add_route4(p, p->server_ip_str, 32, &best.InterfaceLuid, &gw, 0) < 0)
            return -1;
    } else if (p->server_addr.ss_family == AF_INET6) {
        struct in6_addr gw6 = best.NextHop.Ipv6.sin6_addr;
        if (add_route6(p, p->server_ip_str, 128, &best.InterfaceLuid, &gw6, 0) < 0)
            return -1;
    }

    /*
     * 3. Route all traffic through TUN (split default).
     */
    if (add_route4(p, "0.0.0.0", 1, &p->tun.luid, NULL, 5) < 0) return -1;
    if (add_route4(p, "128.0.0.0", 1, &p->tun.luid, NULL, 5) < 0) return -1;

    p->routing_configured = 1;
    LOG_INF("routes configured (server pin + split default)");

    /*
     * 4. IPv6 routes if available.
     */
    if (p->has_v6) {
        if (add_route6(p, "::", 1, &p->tun.luid, NULL, 5) == 0 &&
            add_route6(p, "8000::", 1, &p->tun.luid, NULL, 5) == 0) {
            p->routing6_configured = 1;
            LOG_INF("IPv6 routes configured");
        }
    }

    return 0;
}

void
win_cleanup_routes(platform_win_ctx_t *p)
{
    for (int i = 0; i < p->n_installed_routes; i++) {
        DWORD err = DeleteIpForwardEntry2(&p->installed_routes[i]);
        if (err != NO_ERROR && err != ERROR_NOT_FOUND)
            LOG_WRN("DeleteIpForwardEntry2 [%d]: error %lu", i, err);
    }

    if (p->n_installed_routes > 0)
        LOG_INF("routes cleaned up (%d entries)", p->n_installed_routes);

    p->n_installed_routes = 0;
    p->routing_configured = 0;
    p->routing6_configured = 0;
}

#endif /* _WIN32 */
