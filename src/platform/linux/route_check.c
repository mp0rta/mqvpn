// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * route_check.c — FIB-level "does this iface have a route to the
 * server" probe, used by the path re-add / reactivate gates.
 *
 * Why RTM_F_FIB_MATCH and not a plain output-route lookup: for
 * oif-bound lookups (our path sockets are SO_BINDTODEVICE) the kernel
 * falls back to "Apparently, routing tables are wrong. Assume, that
 * the destination is on link" (net/ipv4/route.c) when no FIB entry
 * matches — the lookup SUCCEEDS, sendto() succeeds, and the packet is
 * silently ARP-blackholed on the local LAN. RTM_F_FIB_MATCH asks for
 * the matching FIB entry itself; the fallback synthesizes a route
 * with res->fi == NULL, so the fibmatch query fails with
 * ENETUNREACH/EHOSTUNREACH exactly when no real route (gateway OR
 * genuine on-link) exists through this interface.
 *
 * Returns 1 = route exists, 0 = definitely no route via this iface,
 * -1 = query mechanism failed (socket error, pre-4.13 kernel without
 * RTM_F_FIB_MATCH, ...). Callers must treat -1 as PASS (fail open):
 * an environment where the probe cannot run must keep today's
 * behavior rather than permanently blocking path recovery.
 */

/* Deliberately does NOT include platform_internal.h: that header pulls
 * <event2/event.h>, and the standalone unit test target has no libevent
 * include path. This file needs only ifname + sockaddr_storage. */
#include "log.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

int iface_has_route_to_server(const char *ifname, const struct sockaddr_storage *server);

int
iface_has_route_to_server(const char *ifname, const struct sockaddr_storage *server)
{
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) return 0; /* iface gone: definitely unusable */

    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return -1;

    struct {
        struct nlmsghdr nh;
        struct rtmsg rt;
        char attrs[64];
    } req;
    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nh.nlmsg_type = RTM_GETROUTE;
    req.nh.nlmsg_flags = NLM_F_REQUEST;
    req.rt.rtm_family = server->ss_family;
    req.rt.rtm_flags = RTM_F_FIB_MATCH;

    struct rtattr *rta = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.nh.nlmsg_len));
    rta->rta_type = RTA_DST;
    if (server->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)server;
        rta->rta_len = RTA_LENGTH(sizeof(s6->sin6_addr));
        memcpy(RTA_DATA(rta), &s6->sin6_addr, sizeof(s6->sin6_addr));
        req.rt.rtm_dst_len = 128;
    } else {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)server;
        rta->rta_len = RTA_LENGTH(sizeof(s4->sin_addr));
        memcpy(RTA_DATA(rta), &s4->sin_addr, sizeof(s4->sin_addr));
        req.rt.rtm_dst_len = 32;
    }
    req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + RTA_ALIGN(rta->rta_len);

    rta = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.nh.nlmsg_len));
    rta->rta_type = RTA_OIF;
    rta->rta_len = RTA_LENGTH(sizeof(uint32_t));
    memcpy(RTA_DATA(rta), &ifindex, sizeof(uint32_t));
    req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + RTA_ALIGN(rta->rta_len);

    int ret = -1;
    if (send(fd, &req, req.nh.nlmsg_len, 0) == (ssize_t)req.nh.nlmsg_len) {
        char buf[4096];
        ssize_t len = recv(fd, buf, sizeof(buf), 0); /* kernel replies synchronously */
        if (len >= (ssize_t)sizeof(struct nlmsghdr)) {
            const struct nlmsghdr *nh = (const struct nlmsghdr *)buf;
            if (nh->nlmsg_type == RTM_NEWROUTE) {
                ret = 1;
            } else if (nh->nlmsg_type == NLMSG_ERROR) {
                int err = -((const struct nlmsgerr *)NLMSG_DATA(nh))->error;
                if (err == ENETUNREACH || err == EHOSTUNREACH || err == ESRCH)
                    ret = 0;
                else
                    LOG_DBG("route_check: RTM_GETROUTE(fibmatch) errno=%d "
                            "— treating as unknown (fail open)",
                            err);
            }
        }
    }
    close(fd);
    return ret;
}
