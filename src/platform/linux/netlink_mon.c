// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * netlink_mon.c — Netlink link/address monitor (Linux Layer A)
 *
 * Everything Linux-netlink-specific lives here: RTM_* event parsing and
 * dispatch, plus the small platform adapters the shared decision layer
 * (src/platform/posix/netmon_common.c) calls back into. The drop /
 * reactivate / re-add decisions themselves — previously hand-synchronized
 * with Darwin's route_mon.c — live once in netmon_common.c.
 *
 * Split out of platform_linux.c so the reactor skeleton there stays free
 * of netlink types.
 */

#include "platform_internal.h"
#include "netlink_mon.h"
#include "netmon_common.h"
#include "log.h"
#include "udp_offload.h" /* mqvpn_udp_gro_enable */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/* ================================================================
 *  Platform adapters for the shared monitor core (netmon_common.h)
 * ================================================================ */

const char *const netmon_log_tag = "netlink";

int
netmon_platform_pin_socket(int fd, const char *ifname, sa_family_t af)
{
    (void)af; /* SO_BINDTODEVICE pins by name, family-agnostic */
    return linux_pin_socket_to_iface(fd, ifname);
}

/* Re-added paths get a brand-new fd: reproduce the startup sockopt or the
 * recovered path silently degrades to one datagram per recvmsg. The
 * "udp-gro: " prefix is asserted by scripts/ci_e2e/
 * run_udp_gso_config_test.sh; no script pins THIS line's wording (the
 * dellink wait regex /re.add/ matches it only incidentally, and matched
 * the failure-path lines above before it existed). The re-add path is
 * covered by reading the client log during the link-flap e2e run. */
void
netmon_platform_socket_created(platform_ctx_t *p, int fd, const char *ifname)
{
    if (!p->udp_gro) return;
    if (mqvpn_udp_gro_enable(fd) == 0) {
        LOG_INF("udp-gro: enabled on re-added path '%s'", ifname);
    } else {
        LOG_INF("udp-gro: unavailable on re-added path '%s' (%s)", ifname,
                strerror(errno));
    }
}

void
netmon_platform_pre_readd(platform_ctx_t *p, const char *ifname)
{
    (void)p;
    (void)ifname; /* no Linux equivalent of Darwin's scoped server pin */
}

int
netmon_platform_pre_reactivate(platform_ctx_t *p, int slot, const char *ifname)
{
    (void)p;
    (void)slot;
    (void)ifname;
    return 0; /* always proceed — the lib's own state gate rejects the rest */
}

int
netmon_platform_pre_scan(platform_ctx_t *p)
{
    (void)p;
    return 0; /* netlink signals overflow (ENOBUFS); no timer-driven resync */
}

/* ================================================================
 *  Netlink event parsing + dispatch (Layer A)
 * ================================================================ */

/* Extract interface name from IFLA_IFNAME attribute in netlink message.
 * Required for RTM_DELLINK where if_indextoname() fails (interface gone). */
static const char *
nlmsg_get_ifname(struct nlmsghdr *nh)
{
    struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nh);
    struct rtattr *rta = IFLA_RTA(ifi);
    int rtl = (int)IFLA_PAYLOAD(nh);
    for (; RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
        if (rta->rta_type == IFLA_IFNAME) return (const char *)RTA_DATA(rta);
    }
    return NULL;
}

/* Extract IFLA_OPERSTATE (RFC 2863 operational state) from a netlink message.
 * Returns the IF_OPER_* enum value (0..7), or -1 if the attribute is missing. */
static int
nlmsg_get_operstate(struct nlmsghdr *nh)
{
    struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nh);
    struct rtattr *rta = IFLA_RTA(ifi);
    int rtl = (int)IFLA_PAYLOAD(nh);
    for (; RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
        if (rta->rta_type == IFLA_OPERSTATE && RTA_PAYLOAD(rta) >= 1)
            return *(const uint8_t *)RTA_DATA(rta);
    }
    return -1;
}

/* RTM_NEWADDR: an interface gained an IP address.
 * Try re-add first because RTM_DELLINK invalidates the fd; only fall back
 * to reactivate if this slot wasn't fully dropped (fd still valid). */
static void
handle_rtm_newaddr(platform_ctx_t *p, struct nlmsghdr *nh)
{
    struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);
    char ifname[IFNAMSIZ];
    if (!if_indextoname(ifa->ifa_index, ifname)) return;
    if (!netmon_try_readd_removed_path(p, ifname))
        netmon_try_reactivate_by_ifname(p, ifname);
}

/* RTM_DELADDR: an address was removed while the link stayed up. NetworkManager
 * `nmcli dev disconnect`, a connection-profile switch, and DHCP lease expiry
 * all remove addresses WITHOUT toggling IFF_UP or carrier — so neither the
 * admin-down nor the carrier-loss branch of handle_rtm_newlink fires (no link
 * event at all), and the write-error path never triggers either: the device
 * is still up with a route, so sends keep succeeding into a black hole until
 * the address returns. If the removal leaves no usable source address of the
 * server's family, drop the path so the scheduler fails over immediately;
 * RTM_NEWADDR re-adds it when an address comes back.
 *
 * The tracked / still-up-and-running / definitely-address-less gates live in
 * netmon_on_addr_removed (shared with Darwin): admin down and link teardown
 * flush addresses too, and the kernel emits those RTM_DELADDRs BEFORE the
 * corresponding link event (`ip link del` -> v4 DELADDR before DELLINK; v6
 * admin down -> DELADDR before NEWLINK). Acting on them here would steal the
 * drop from the more specific handler and misreport the public reason as
 * ADDR_REMOVED. nmcli/DHCP address loss keeps IFF_UP and carrier set, so the
 * gate never blocks the case this handler exists for. */
static void
handle_rtm_deladdr(platform_ctx_t *p, struct nlmsghdr *nh)
{
    struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);
    if (ifa->ifa_family != p->server_addr.ss_family) return;
    char ifname[IFNAMSIZ];
    if (!if_indextoname(ifa->ifa_index, ifname)) return;
    netmon_on_addr_removed(p, ifname, ifa->ifa_family);
}

/* RTM_DELLINK: interface gone. The shared drop path uses drop_path
 * semantics (not orderly close) so surviving paths aren't blocked by
 * xquic shutdown handshakes. */
static void
handle_rtm_dellink(platform_ctx_t *p, struct nlmsghdr *nh)
{
    const char *ifname = nlmsg_get_ifname(nh);
    if (!ifname) return;
    netmon_drop_paths_by_ifname(p, ifname, MQVPN_PLATFORM_REASON_RTM_DELLINK);
}

/* Decide whether this RTM_NEWLINK is a carrier-loss event we should drop on.
 *
 * Gate on IFLA_OPERSTATE rather than !IFF_RUNNING. IFF_RUNNING also clears
 * during wifi association / dormant transitions, so an !IFF_RUNNING-based
 * gate would burn one path_id slot per wifi roam.
 *
 * Drop only on a definite operational-down report (RFC 2863): IF_OPER_DOWN
 * (link admin/peer down) or IF_OPER_LOWERLAYERDOWN (e.g. underlying ethernet
 * of a vlan/bridge went away). IF_OPER_DORMANT (wifi associating),
 * IF_OPER_UNKNOWN (driver doesn't report; common on virtual interfaces) and
 * IF_OPER_TESTING are tolerated — the carrier-up handler / recovery timer
 * will still re-add once IFF_RUNNING + has_ip become true.
 *
 * The IFF_UP term below is checked for defensiveness but is redundant in
 * practice: the caller (handle_rtm_newlink) already short-circuits on
 * admin_down before ever consulting this function, so IFF_UP is always 1
 * by the time we get here. It's kept only in case a future caller invokes
 * this helper without that same admin_down pre-check. The operstate
 * condition above is what actually protects the IFF_UP=1 flap cases (wifi
 * DORMANT/UNKNOWN etc.) from being misread as carrier loss.
 *
 * Note this function does not need to special-case admin-down to preserve
 * the fixed XQC_MAX_PATHS_COUNT (8) path_id budget — that budget is
 * obsolete since the draft-21 dynamic path cap work (paths now grow/shrink
 * via PATHS_BLOCKED / MAX_PATH_ID rather than a fixed array). Admin-down is
 * instead handled explicitly and immediately by the caller. */
static int
is_carrier_loss(struct ifinfomsg *ifi, int operstate)
{
    return (ifi->ifi_flags & IFF_UP) &&
           (operstate == IF_OPER_DOWN || operstate == IF_OPER_LOWERLAYERDOWN);
}

/* RTM_NEWLINK: link state changed. Either drop on admin-down/carrier loss,
 * or attempt recovery if the link is now usable. */
static void
handle_rtm_newlink(platform_ctx_t *p, struct nlmsghdr *nh)
{
    struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nh);
    const char *ifname = nlmsg_get_ifname(nh);
    if (!ifname) return;

    int admin_down = !(ifi->ifi_flags & IFF_UP);
    if (admin_down || is_carrier_loss(ifi, nlmsg_get_operstate(nh))) {
        netmon_drop_paths_by_ifname(p, ifname,
                                    admin_down ? MQVPN_PLATFORM_REASON_ADMIN_DOWN
                                               : MQVPN_PLATFORM_REASON_CARRIER_LOST);
        return;
    }

    if (!(ifi->ifi_flags & IFF_RUNNING)) return;
    if (netmon_iface_has_usable_ip(ifname, p->server_addr.ss_family) != 1) return;

    /* First: try to re-add paths removed by RTM_DELLINK (dead fd).
     * Otherwise: reactivate degraded/closed paths (fd still valid). */
    if (netmon_try_readd_removed_path(p, ifname)) return;
    netmon_try_reactivate_by_ifname(p, ifname);
}

static void
on_netlink_event(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    platform_ctx_t *p = (platform_ctx_t *)arg;
    char buf[NETLINK_BUF_SIZE];

    for (;;) {
        ssize_t len = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (len <= 0) break;

        int nlen = (int)len;
        for (struct nlmsghdr *nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, nlen);
             nh = NLMSG_NEXT(nh, nlen)) {
            switch (nh->nlmsg_type) {
            case RTM_NEWADDR: handle_rtm_newaddr(p, nh); break;
            case RTM_DELADDR: handle_rtm_deladdr(p, nh); break;
            case RTM_DELLINK: handle_rtm_dellink(p, nh); break;
            case RTM_NEWLINK: handle_rtm_newlink(p, nh); break;
            }
        }
    }

    /* Netlink handlers may have created/dropped paths (queuing frames such
     * as PATH_CHALLENGE inside xquic) — drive the engine and re-arm the
     * tick from the engine's new wakeup request, exactly as on_socket_read
     * does. Without this the queued frames wait for an unrelated timer. */
    mqvpn_client_tick(p->client);
    schedule_next_tick(p);
}

int
setup_netlink(platform_ctx_t *p)
{
    p->nl_fd =
        socket(AF_NETLINK, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (p->nl_fd < 0) {
        LOG_WRN("netlink socket failed: %s (path recovery via timer only)",
                strerror(errno));
        return -1;
    }

    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
        .nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR,
    };
    if (bind(p->nl_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        LOG_WRN("netlink bind failed: %s (path recovery via timer only)",
                strerror(errno));
        close(p->nl_fd);
        p->nl_fd = -1;
        return -1;
    }

    p->ev_netlink = event_new(p->eb, p->nl_fd, EV_READ | EV_PERSIST, on_netlink_event, p);
    if (!p->ev_netlink) {
        LOG_WRN("netlink event_new failed (OOM?)");
        close(p->nl_fd);
        p->nl_fd = -1;
        return -1;
    }
    event_add(p->ev_netlink, NULL);
    LOG_INF("netlink path recovery accelerator active");
    return 0;
}
