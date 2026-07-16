// tests/test_route_check.c — iface_has_route_to_server() unit tests.
// Runs unprivileged: RTM_GETROUTE queries need no capabilities and the
// only interface assumed to exist is lo (local table provides
// 127.0.0.1 / ::1 entries).

/* Keep assert() live even in Release builds: CI runs ctest on Release too,
 * where NDEBUG would silently no-op every assertion in this file. */
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int iface_has_route_to_server(const char *ifname, const struct sockaddr_storage *server);

static struct sockaddr_storage
v4(const char *ip)
{
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    struct sockaddr_in *s = (struct sockaddr_in *)&ss;
    s->sin_family = AF_INET;
    assert(inet_pton(AF_INET, ip, &s->sin_addr) == 1);
    return ss;
}

static struct sockaddr_storage
v6(const char *ip)
{
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    struct sockaddr_in6 *s = (struct sockaddr_in6 *)&ss;
    s->sin6_family = AF_INET6;
    assert(inet_pton(AF_INET6, ip, &s->sin6_addr) == 1);
    return ss;
}

int
main(void)
{
    /* local-table entry for loopback → genuine FIB match */
    struct sockaddr_storage dst = v4("127.0.0.1");
    assert(iface_has_route_to_server("lo", &dst) == 1);

    /* TEST-NET-1 has no route via lo (only via a real NIC's default,
     * which RTA_OIF=lo excludes) → definite 0. This is exactly the
     * ANK on-link fallback case: a plain oif output lookup would
     * SUCCEED here; fibmatch must reject it. */
    dst = v4("192.0.2.123");
    assert(iface_has_route_to_server("lo", &dst) == 0);

    /* nonexistent interface → definite 0 */
    dst = v4("127.0.0.1");
    assert(iface_has_route_to_server("mqvpn-noif0", &dst) == 0);

    /* v6 loopback (skip silently if kernel has v6 disabled) */
    dst = v6("::1");
    int r = iface_has_route_to_server("lo", &dst);
    assert(r == 1 || r == -1);

    /* v6 loopback via a nonexistent interface → definite 0 (never a live
     * FIB match on an iface that has no index). */
    dst = v6("::1");
    assert(iface_has_route_to_server("mqvpn-noif0", &dst) == 0);

    /* v6 documentation prefix (2001:db8::/32) has no route via lo. Skip if
     * v6 is disabled (-1); otherwise it must be a definite 0, mirroring the
     * v4 TEST-NET-1 on-link fallback rejection above. */
    dst = v6("2001:db8::1");
    r = iface_has_route_to_server("lo", &dst);
    assert(r == 0 || r == -1);

    printf("test_route_check: all OK\n");
    return 0;
}
