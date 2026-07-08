// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * net_mon.c — Windows path recovery accelerator (sibling of Linux
 * netlink_mon.c)
 *
 * Linux drives drop/reactivate/re-add off async RTM_* netlink events plus
 * a periodic backstop timer (see netlink_mon.c's file comment). Windows has
 * no equivalent lightweight async link/address event source wired up yet,
 * so Phase 1 here is poll-only: the same drop/reactivate/re-add decisions,
 * driven entirely by the RECOVER_INTERVAL_SEC timer via GetIfEntry2 /
 * GetAdaptersAddresses / GetBestRoute2 probes. Phase 2 (later) adds an IP
 * Helper change-notification event source and demotes the timer back to a
 * backstop, matching the Linux split.
 *
 * This file (Task 3) contains only the skeleton and the three Layer C
 * probe primitives (iface_is_up_and_running / iface_has_usable_ip /
 * iface_has_route_to_server). They are static and currently unused —
 * the Layer B reconciler logic (drop/reactivate/re-add, sibling-cloned
 * from netlink_mon.c) lands in later tasks.
 */

#ifdef _WIN32

#  include "net_mon.h"
#  include "platform_internal_win.h"
#  include "compat/socket_compat.h"
#  include "log.h"

#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <iphlpapi.h>
#  include <netioapi.h>
#  include <string.h>
#  include <stdlib.h>

/* ================================================================
 *  Layer C — Windows iface/route probes
 * ================================================================ */

/* Resolve a FriendlyName to a NET_LUID via the same conversion approach as
 * win_pin_socket_to_iface() in platform_windows.c: convert the char*
 * FriendlyName to wide chars first, then ConvertInterfaceAliasToLuid().
 * Returns NO_ERROR / *luid filled, or the failing API's error code.
 * ConvertInterfaceAliasToLuid's alias-not-found code is undocumented on
 * MSDN, so callers defensively accept BOTH ERROR_FILE_NOT_FOUND and
 * ERROR_NOT_FOUND as "adapter gone" (empirical verification deferred to
 * the manual Windows test matrix); any other code is an ambiguous probe
 * failure. */
static DWORD
resolve_iface_luid(const char *ifname, NET_LUID *luid)
{
    wchar_t wname[IF_MAX_STRING_SIZE + 1];
    int wlen = MultiByteToWideChar(CP_ACP, 0, ifname, -1, wname,
                                   (int)(sizeof(wname) / sizeof(wname[0])));
    if (wlen <= 0) return ERROR_INVALID_PARAMETER;

    return ConvertInterfaceAliasToLuid(wname, luid);
}

/* Check interface operational state via GetIfEntry2.
 *
 * Windows-specific tri-state contract (deviates from the Linux sibling's
 * boolean return): the caller (Task 6's drop gate) must distinguish
 * "confirmed down/gone" from "probe failed" so a transient API hiccup can
 * never masquerade as a drop decision.
 *   1  — OperStatus == IfOperStatusUp (and MediaConnectState, when
 *        reported, is Connected).
 *   0  — confirmed not up, or the adapter is gone: LUID resolution or
 *        GetIfEntry2 reported not-found (ERROR_FILE_NOT_FOUND is
 *        GetIfEntry2's documented "LUID not on this machine" code;
 *        ERROR_NOT_FOUND kept defensively), or GetIfEntry2 returned
 *        NO_ERROR with a non-up OperStatus. This is the RTM_DELLINK
 *        analog — dropping on this result is correct.
 *  -1  — any other API error (ambiguous). Caller must NOT drop on -1
 *        (fail-safe, same fail-open discipline as the Linux probes). */
static int
iface_is_up_and_running(const char *ifname)
{
    NET_LUID luid;
    DWORD err = resolve_iface_luid(ifname, &luid);
    if (err == ERROR_FILE_NOT_FOUND || err == ERROR_NOT_FOUND) return 0;
    if (err != NO_ERROR) return -1;

    MIB_IF_ROW2 row;
    memset(&row, 0, sizeof(row));
    row.InterfaceLuid = luid;
    err = GetIfEntry2(&row);
    if (err == ERROR_FILE_NOT_FOUND || err == ERROR_NOT_FOUND) return 0;
    if (err != NO_ERROR) return -1;

    if (row.OperStatus != IfOperStatusUp) return 0;
    if (row.MediaConnectState != MediaConnectStateUnknown &&
        row.MediaConnectState != MediaConnectStateConnected)
        return 0;

    return 1;
}

/* Check whether `ifname` has a usable unicast source address for `af`.
 * Windows analog of the Linux getifaddrs() version (netlink_mon.c);
 * same exclusion semantics: skip IPv4 link-local (169.254/16) and IPv6
 * link-local (IN6_IS_ADDR_LINKLOCAL) addresses — neither can reach the
 * server, and their presence must not let a re-add pass.
 *
 * Returns 1 = usable address present, 0 = enumerated and found none,
 * -1 = probe failure (unknown). Callers must fail safe: a definite 0 is
 * required to drop, a definite 1 is required to re-add/reactivate, so a
 * transient enumeration failure never drops or re-adds a path. */
static int
iface_has_usable_ip(const char *ifname, ADDRESS_FAMILY af)
{
    NET_LUID luid;
    DWORD err = resolve_iface_luid(ifname, &luid);
    if (err == ERROR_FILE_NOT_FOUND || err == ERROR_NOT_FOUND) return 0;
    if (err != NO_ERROR) return -1;

    ULONG flags =
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG bufsize = 15000;
    IP_ADAPTER_ADDRESSES *addrs = (IP_ADAPTER_ADDRESSES *)malloc(bufsize);
    if (!addrs) return -1;

    err = GetAdaptersAddresses(af, flags, NULL, addrs, &bufsize);
    if (err == ERROR_BUFFER_OVERFLOW) {
        IP_ADAPTER_ADDRESSES *bigger = (IP_ADAPTER_ADDRESSES *)realloc(addrs, bufsize);
        if (!bigger) {
            free(addrs);
            return -1;
        }
        addrs = bigger;
        err = GetAdaptersAddresses(af, flags, NULL, addrs, &bufsize);
    }
    if (err != NO_ERROR) {
        free(addrs);
        return -1;
    }

    int found = 0;
    for (IP_ADAPTER_ADDRESSES *a = addrs; a; a = a->Next) {
        if (memcmp(&a->Luid, &luid, sizeof(NET_LUID)) != 0) continue;

        for (IP_ADAPTER_UNICAST_ADDRESS *ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
            const struct sockaddr *sa = ua->Address.lpSockaddr;
            if (!sa || sa->sa_family != af) continue;

            if (af == AF_INET) {
                const struct sockaddr_in *s4 =
                    (const struct sockaddr_in *)(const void *)sa;
                if ((ntohl(s4->sin_addr.s_addr) & 0xFFFF0000UL) == 0xA9FE0000UL)
                    continue; /* 169.254/16 */
            } else if (af == AF_INET6) {
                const struct sockaddr_in6 *s6 =
                    (const struct sockaddr_in6 *)(const void *)sa;
                if (IN6_IS_ADDR_LINKLOCAL(&s6->sin6_addr)) continue;
            }

            found = 1;
            break;
        }
        break;
    }

    free(addrs);
    return found;
}

/* Check whether `ifname` currently has a route to `server_addr`, using
 * GetBestRoute2 constrained to that interface's LUID (passed as
 * InterfaceLuid, the first argument) — NOT GetBestRoute2(NULL, ...)
 * followed by comparing the returned interface to ours. The unconstrained
 * form answers "which interface is BEST for this destination system-wide"
 * and would permanently block a deliberately-non-preferred NIC in a
 * multi-NIC bonding setup; the constrained form answers "does THIS
 * interface have a route at all", which is what the drop/re-add gate
 * needs (mirrors the Linux sibling's iface_has_route_to_server(ifname,
 * server_addr) contract in netlink_mon.c).
 *
 * Returns 1 = route exists, 0 = confirmed unreachable
 * (ERROR_NETWORK_UNREACHABLE / ERROR_HOST_UNREACHABLE) or interface gone
 * (ERROR_FILE_NOT_FOUND, GetBestRoute2's documented "interface could not
 * be found" code — parity with the Linux sibling's iface-gone → 0), -1 =
 * probe failure (fail-open; caller must not drop/withhold re-add on -1). */
static int
iface_has_route_to_server(const char *ifname, const struct sockaddr_storage *server_addr)
{
    NET_LUID luid;
    DWORD err = resolve_iface_luid(ifname, &luid);
    if (err == ERROR_FILE_NOT_FOUND || err == ERROR_NOT_FOUND) return 0;
    if (err != NO_ERROR) return -1;

    SOCKADDR_INET dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    if (server_addr->ss_family == AF_INET) {
        dest_addr.Ipv4 = *(const struct sockaddr_in *)(const void *)server_addr;
    } else if (server_addr->ss_family == AF_INET6) {
        dest_addr.Ipv6 = *(const struct sockaddr_in6 *)(const void *)server_addr;
    } else {
        return -1;
    }

    MIB_IPFORWARD_ROW2 best;
    SOCKADDR_INET best_src;
    memset(&best, 0, sizeof(best));
    memset(&best_src, 0, sizeof(best_src));

    err = GetBestRoute2(&luid, 0, NULL, &dest_addr, 0, &best, &best_src);
    if (err == NO_ERROR) return 1;
    if (err == ERROR_NETWORK_UNREACHABLE || err == ERROR_HOST_UNREACHABLE ||
        err == ERROR_FILE_NOT_FOUND)
        return 0;
    return -1;
}

#endif /* _WIN32 */
