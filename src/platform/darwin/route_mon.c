// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * route_mon.c — PF_ROUTE link/address monitor + path recovery accelerator
 *
 * Everything Darwin-PF_ROUTE-specific lives here: RTM_* event parsing and
 * dispatch, the drop/reactivate/re-add decisions they drive, and the
 * periodic recovery timer that backstops missed one-shot events.
 *
 * Split out of platform_darwin.c so the reactor skeleton there stays free
 * of PF_ROUTE types — this module is the Darwin twin of the Linux
 * netlink_mon.c reactor, byte-diffed against it function by function so
 * the two accelerators drift apart only where the kernel ABI forces it.
 */

#ifdef __APPLE__

#  include "platform_internal.h"
#  include "route_mon.h"
#  include "log.h"
#  include "compat/socket_compat.h"

#  include <stdio.h>
#  include <stdlib.h>
#  include <string.h>
#  include <unistd.h>
#  include <errno.h>
#  include <fcntl.h>
#  include <sys/socket.h>
#  include <net/if.h>
#  include <net/if_dl.h>
#  include <net/route.h>
#  include <ifaddrs.h>
#  include <netinet/in.h>

/* ================================================================
 *  PF_ROUTE path recovery accelerator
 * ================================================================ */

/* Check whether `ifname` is admin-up AND has carrier (IFF_UP & IFF_RUNNING).
 * Used by the periodic recovery timer to skip retries on a still-down link.
 *
 * Darwin deviation from netlink_mon.c:141: no ioctl(SIOCGIFFLAGS) dgram
 * socket round trip — getifaddrs() already carries ifa_flags per
 * interface, so a single enumeration answers the question. */
static int
iface_is_up_and_running(const char *ifname)
{
    struct ifaddrs *ifa_list = NULL, *ifa;
    if (getifaddrs(&ifa_list) < 0) return 0;
    int ok = 0;
    for (ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, ifname) != 0) continue;
        ok = (ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_RUNNING);
        break;
    }
    freeifaddrs(ifa_list);
    return ok;
}

/* Check if the interface has a usable source address for the given
 * family. v4: any address except 169.254/16 link-local. v6: global scope
 * only — a link-local address cannot reach the server, and its presence
 * used to let the re-add gate pass during the v4-less window right after
 * link-up. Binding and challenging from an addressless iface triggers the
 * kernel's assume-on-link output fallback with a source address borrowed
 * from another interface, poisoning the server's view of the path 4-tuple.
 *
 * Returns 1 = usable address present, 0 = enumerated and found none,
 * -1 = getifaddrs() failed (unknown). Callers must fail safe: the
 * RTM_DELADDR drop requires a definite 0, the re-add gates a definite 1,
 * so a transient getifaddrs failure never drops or re-adds a path. */
static int
iface_has_usable_ip(const char *ifname, sa_family_t af)
{
    struct ifaddrs *ifa_list = NULL, *ifa;
    int found = 0;
    if (getifaddrs(&ifa_list) < 0) return -1;
    for (ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (strcmp(ifa->ifa_name, ifname) != 0) continue;
        if (ifa->ifa_addr->sa_family != af) continue;
        if (af == AF_INET6) {
            const struct sockaddr_in6 *s6 =
                (const struct sockaddr_in6 *)(const void *)ifa->ifa_addr;
            if (IN6_IS_ADDR_LINKLOCAL(&s6->sin6_addr)) continue;
        }
        if (af == AF_INET) {
            const struct sockaddr_in *s4 =
                (const struct sockaddr_in *)(const void *)ifa->ifa_addr;
            /* 169.254/16 (IPv4LL): same unusable-source class as v6
             * link-local — present exactly when DHCP has NOT restored a
             * real address yet. */
            if ((ntohl(s4->sin_addr.s_addr) & 0xFFFF0000UL) == 0xA9FE0000UL) continue;
        }
        found = 1;
        break;
    }
    freeifaddrs(ifa_list);
    return found;
}

/* ----------------------------------------------------------------
 * Layer B (route-event handlers: try_reactivate_by_ifname,
 * recovery_register_with_lib, recovery_rollback, try_readd_removed_path,
 * recover_dropped_paths_cb, handle_rtm_* equivalents, on_route_event,
 * setup_route_socket) lands here in a later change, mirroring
 * netlink_mon.c's canonical layout (netlink_mon.c:197-239, :288-554,
 * :556-744). iface_has_route_to_server below is already visible to that
 * future code via platform_internal.h's shared prototype, even though its
 * definition sits after recovery_socket_create() in this file.
 * ---------------------------------------------------------------- */

/* Create a UDP socket bound to the wildcard address and pinned to ifname.
 * Updates mp->local_addr / mp->local_addrlen on success.
 * Returns the new fd, or -1 (already logged).
 *
 * Darwin deviation from netlink_mon.c:245: SO_BINDTODEVICE has no Darwin
 * equivalent — darwin_pin_socket_to_iface() (IP_BOUND_IF / IPV6_BOUND_IF)
 * replaces it, applied after bind() exactly like the startup-loop order in
 * darwin_platform_run_client(). */
static int
recovery_socket_create(sa_family_t af, const char *ifname, mqvpn_path_t *mp)
{
    int fd = (int)socket(af, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOG_WRN("routemon: socket() for re-add %s: %s", ifname, strerror(errno));
        return -1;
    }
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        LOG_WRN("routemon: fcntl() for re-add %s: %s", ifname, strerror(errno));
        goto fail;
    }

    /* Socket buffers are set by mqvpn_client_add_path_fd() (7 MiB) */

    memset(&mp->local_addr, 0, sizeof(mp->local_addr));
    if (af == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&mp->local_addr;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = in6addr_any;
        mp->local_addrlen = sizeof(struct sockaddr_in6);
    } else {
        struct sockaddr_in *sin4 = (struct sockaddr_in *)&mp->local_addr;
        sin4->sin_family = AF_INET;
        sin4->sin_addr.s_addr = htonl(INADDR_ANY);
        mp->local_addrlen = sizeof(struct sockaddr_in);
    }
    if (bind(fd, (struct sockaddr *)&mp->local_addr, mp->local_addrlen) < 0) {
        LOG_WRN("routemon: bind() for re-add %s: %s", ifname, strerror(errno));
        goto fail;
    }

    /* Pin AFTER bind, matching startup-loop order. */
    if (darwin_pin_socket_to_iface(fd, ifname, af) < 0) {
        LOG_WRN("routemon: iface pin for re-add %s failed", ifname);
        goto fail;
    }

    return fd;
fail:
    close(fd);
    return -1;
}

/* Round a BSD routing-socket sockaddr length up to the next sizeof(long)
 * boundary. Routing-socket messages pack sockaddrs back to back with this
 * alignment (route(4)); a plain sizeof(sockaddr_in)/sizeof(sockaddr_in6)
 * stride would misparse a mixed v4/v6 message. Only one address is sent
 * here, but the same rule applies to sizing the message length. */
#  define ROUTE_SA_ROUNDUP(a) \
      ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

/* FIB-level "does this iface have a route to the server" probe, used by
 * the path re-add / reactivate gates. New code (no Linux clone source —
 * route_check.c's RTM_F_FIB_MATCH netlink query has no PF_ROUTE analog;
 * read route_check.c for the contract/style this mirrors).
 *
 * Uses a scoped RTM_GET (RTF_IFSCOPE + rtm_index) rather than a plain
 * destination lookup: an unscoped route-get answers with whatever
 * interface the kernel's default route table would pick, not whether
 * *this* interface can reach the server — the same "path socket bound to
 * an interface with no real route to the destination" blackhole that
 * route_check.c documents for Linux SO_BINDTODEVICE lookups.
 *
 * Returns 1 = route exists, 0 = definitely no route via this iface, -1 =
 * query mechanism failed (socket error, iface gone, ...). Callers must
 * treat -1 as PASS (fail open): an environment where the probe cannot run
 * must keep today's behavior rather than permanently blocking path
 * recovery. */
int
iface_has_route_to_server(const char *ifname, const struct sockaddr_storage *server)
{
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) return 0; /* iface gone: definitely unusable */

    /* Dedicated PF_ROUTE socket per probe — never the shared event socket
     * (p->rt_fd), which would interleave this synchronous reply with the
     * async RTM_* broadcasts on_route_event() consumes. */
    int fd = socket(PF_ROUTE, SOCK_RAW, 0);
    if (fd < 0) return -1;

    struct {
        struct rt_msghdr rtm;
        char space[512];
    } req;
    memset(&req, 0, sizeof(req));

    socklen_t salen = (server->ss_family == AF_INET6) ? sizeof(struct sockaddr_in6)
                                                      : sizeof(struct sockaddr_in);
    memcpy(req.space, server, salen);

    static int seq_counter = 0;
    int seq = ++seq_counter;
    pid_t pid = getpid();

    req.rtm.rtm_msglen =
        (u_short)(sizeof(struct rt_msghdr) + ROUTE_SA_ROUNDUP((int)salen));
    req.rtm.rtm_version = RTM_VERSION;
    req.rtm.rtm_type = RTM_GET;
    req.rtm.rtm_addrs = RTA_DST;
    req.rtm.rtm_flags = RTF_UP | RTF_IFSCOPE;
    req.rtm.rtm_index = (unsigned short)ifindex;
    req.rtm.rtm_pid = pid;
    req.rtm.rtm_seq = seq;

    ssize_t wn = write(fd, &req, req.rtm.rtm_msglen);
    if (wn != (ssize_t)req.rtm.rtm_msglen) {
        int err = errno;
        close(fd);
        /* BSD scoped route-get typically reports "no route" via write()
         * errno rather than a reply carrying rtm_errno. */
        if (err == ESRCH || err == ENETUNREACH || err == EHOSTUNREACH) return 0;
        LOG_DBG("routemon: RTM_GET write errno=%d — treating as unknown "
                "(fail open)",
                err);
        return -1;
    }

    int ret = -1;
    char buf[ROUTE_BUF_SIZE];
    /* Bounded read loop: the kernel answers this synchronous RTM_GET on
     * the same socket, but a route socket also observes other processes'
     * RTM_GET replies — loop a bounded number of times to find the reply
     * matching our pid+seq rather than trusting the first message read. */
    for (int i = 0; i < 8; i++) {
        ssize_t len = read(fd, buf, sizeof(buf));
        if (len < (ssize_t)sizeof(struct rt_msghdr)) break;
        const struct rt_msghdr *rtm = (const struct rt_msghdr *)buf;
        if (rtm->rtm_pid != pid || rtm->rtm_seq != seq) continue;
        if (rtm->rtm_errno == 0) {
            ret = 1;
        } else if (rtm->rtm_errno == ESRCH || rtm->rtm_errno == ENETUNREACH ||
                   rtm->rtm_errno == EHOSTUNREACH) {
            ret = 0;
        } else {
            LOG_DBG("routemon: RTM_GET rtm_errno=%d — treating as unknown "
                    "(fail open)",
                    rtm->rtm_errno);
        }
        break;
    }
    close(fd);
    return ret;
}

#endif /* __APPLE__ */
