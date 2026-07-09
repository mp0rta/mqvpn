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
#  include <sys/time.h> /* struct timeval for the probe's SO_RCVTIMEO */
#  include <sys/ioctl.h>
#  include <sys/sockio.h> /* SIOCGIFFLAGS lives here on Darwin */
#  include <net/if.h>
#  include <net/if_dl.h>
#  include <net/route.h>
#  include <ifaddrs.h>
#  include <netinet/in.h>

/* ================================================================
 *  PF_ROUTE path recovery accelerator
 * ================================================================ */

/* Layer B: drop_reason_str / remove_path_by_index / drop_paths_by_ifname */

/* Log wording per reason. Frozen: e2e scripts grep these exact strings
 * ("interface <if> <reason>, closing path"). */
static const char *
drop_reason_str(mqvpn_platform_reason_t reason)
{
    switch (reason) {
    case MQVPN_PLATFORM_REASON_RTM_DELLINK: return "removed";
    case MQVPN_PLATFORM_REASON_CARRIER_LOST: return "carrier lost";
    case MQVPN_PLATFORM_REASON_ADMIN_DOWN: return "admin down";
    case MQVPN_PLATFORM_REASON_ADDR_REMOVED: return "address removed";
    default: return "dropped";
    }
}

/* Remove a path because the kernel says it's no longer usable.
 * Four callers: RTM_DELLINK (interface gone); RTM_NEWLINK with
 * IFLA_OPERSTATE = IF_OPER_DOWN / IF_OPER_LOWERLAYERDOWN (carrier lost —
 * cable unplugged etc); RTM_NEWLINK with IFF_UP cleared (admin down,
 * e.g. `ip link set down`); and RTM_DELADDR (no usable source address
 * left). All share cleanup; the reason is logged and reported in the
 * public event.
 *
 * Cleans up: library path, libevent, fd. Preserves iface name for re-add. */
static void
remove_path_by_index(platform_ctx_t *p, int idx, mqvpn_platform_reason_t reason)
{
    if (p->path_mgr.paths[idx].fd < 0) return; /* already removed */

    LOG_WRN("routemon: interface %s %s, closing path %d", p->path_mgr.paths[idx].iface,
            drop_reason_str(reason), idx);

    /* PR5: emit PLATFORM_DROP via new public API with diagnostic info.
     * Library transitions slot to CLOSED_DROPPED; fd close is reported
     * via mqvpn_client_on_platform_fd_closed() below. */
    mqvpn_platform_path_event_info_t info = {0};
    snprintf(info.iface, sizeof(info.iface), "%s", p->path_mgr.paths[idx].iface);
    info.reason = reason;
    mqvpn_client_on_platform_path_dropped(p->client, p->lib_path_handles[idx], &info);

    /* Remove libevent watcher */
    if (p->ev_udp[idx]) {
        event_del(p->ev_udp[idx]);
        event_free(p->ev_udp[idx]);
        p->ev_udp[idx] = NULL;
    }

    /* Close dead socket + notify lib so CLOSED_DROPPED -> CLOSED_FREE
     * cleanup can complete (once xquic-side also clears). */
    close(p->path_mgr.paths[idx].fd);
    p->path_mgr.paths[idx].fd = -1;
    p->path_mgr.paths[idx].platform_attached = 0;
    mqvpn_client_on_platform_fd_closed(p->client, p->lib_path_handles[idx]);
}

/* Drop every tracked path on `ifname`. Shared by the RTM_DELADDR /
 * RTM_DELLINK / RTM_NEWLINK drop branches so slot matching stays in one
 * place. Returns the number of paths matched (dropped or already gone). */
static int
drop_paths_by_ifname(platform_ctx_t *p, const char *ifname,
                     mqvpn_platform_reason_t reason)
{
    int matched = 0;
    for (int i = 0; i < p->path_mgr.n_paths; i++) {
        if (strcmp(p->path_mgr.paths[i].iface, ifname) == 0) {
            remove_path_by_index(p, i, reason);
            matched++;
        }
    }
    return matched;
}

/* Check whether `ifname` is admin-up AND has carrier (IFF_UP & IFF_RUNNING).
 * Used by the periodic recovery timer to skip retries on a still-down link. */
static int
iface_is_up_and_running(const char *ifname)
{
    /* Darwin deviation: no SOCK_CLOEXEC socket() flag — set FD_CLOEXEC
     * post-hoc via fcntl instead. */
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return 0;
    fcntl(s, F_SETFD, FD_CLOEXEC);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    int ok = 0;
    if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0)
        ok = (ifr.ifr_flags & IFF_UP) && (ifr.ifr_flags & IFF_RUNNING);
    close(s);
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

/* Layer B: try_reactivate_by_ifname */

static void
try_reactivate_by_ifname(platform_ctx_t *p, const char *ifname)
{
    if (iface_has_route_to_server(ifname, &p->server_addr) == 0) return;

    /* PR5: query lib state instead of platform-tracked path_recoverable[].
     * Reactivate is valid for slots in DEGRADED / CREATE_WAIT /
     * CLOSED_RECOVERABLE (per lib's reactivate_slot_eligible gate added
     * in 433272f). Public projection collapses these to MQVPN_PATH_DEGRADED
     * (for DEGRADED+CREATE_WAIT) and MQVPN_PATH_CLOSED (for CLOSED_RECOVERABLE),
     * so both warrant attempting reactivate. The lib's gate rejects bad
     * states with MQVPN_ERR_INVALID_STATE which we silently swallow. */
    mqvpn_path_info_t pinfo[MQVPN_MAX_PATHS];
    int n = 0;
    if (mqvpn_client_get_paths(p->client, pinfo, MQVPN_MAX_PATHS, &n) != MQVPN_OK) return;

    for (int i = 0; i < p->path_mgr.n_paths; i++) {
        if (strcmp(p->path_mgr.paths[i].iface, ifname) != 0) continue;
        mqvpn_path_handle_t h = p->lib_path_handles[i];
        if (h < 0) continue;

        int found = 0;
        mqvpn_path_status_t st = MQVPN_PATH_PENDING;
        for (int j = 0; j < n; j++) {
            if (pinfo[j].handle == h) {
                found = 1;
                st = pinfo[j].status;
                break;
            }
        }
        if (!found) continue;
        if (st != MQVPN_PATH_DEGRADED && st != MQVPN_PATH_CLOSED) continue;

        /* WINDOWS-lesson ★1: interface re-enable can renumber the ifindex,
         * and IP_BOUND_IF/IPV6_BOUND_IF pin by index — a stale pin would
         * silently send traffic out the wrong interface on the very fd
         * we're about to hand back to xquic. Re-apply the pin now that the
         * route gate (top of this function) has already passed and this
         * slot is resolved as a genuine reactivate candidate — placing it
         * any earlier would waste a syscall + log on every poll for
         * routeless or ineligible ifaces. If the pin fails, skip reactivate
         * for this slot; the recovery timer / next event will retry. */
        sa_family_t af = (sa_family_t)p->server_addr.ss_family;
        if (darwin_pin_socket_to_iface(p->path_mgr.paths[i].fd, ifname, af) < 0) continue;

        int ret = mqvpn_client_reactivate_path(p->client, h);
        if (ret == MQVPN_OK) {
            LOG_INF("routemon: reactivated path %s", ifname);
        } else if (ret == MQVPN_ERR_INVALID_STATE) {
            /* slot not in 3-state acceptance window (e.g. already VALIDATING) */
        } else {
            LOG_WRN("routemon: reactivate %s failed: %s", ifname,
                    mqvpn_error_string(ret));
        }
    }
}

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

/* Layer B: recovery_register_with_lib / recovery_rollback /
 * try_readd_removed_path */

/* Register a freshly-created socket with the library and capture the
 * synchronous activation outcome via the with_outcome API. Returns the
 * new handle and writes *outcome (MQVPN_ADD_PATH_OK / TRANSIENT / PERMANENT);
 * returns -1 on handle-allocation failure (already logged). */
static mqvpn_path_handle_t
recovery_register_with_lib(platform_ctx_t *p, int slot, int fd, const char *ifname,
                           mqvpn_add_path_outcome_t *outcome)
{
    mqvpn_path_t *mp = &p->path_mgr.paths[slot];

    mqvpn_path_desc_t desc = {0};
    desc.struct_size = sizeof(desc);
    desc.fd = fd;
    snprintf(desc.iface, sizeof(desc.iface), "%s", mp->iface);
    if (mp->local_addrlen > 0 && mp->local_addrlen <= sizeof(desc.local_addr)) {
        memcpy(desc.local_addr, &mp->local_addr, mp->local_addrlen);
        desc.local_addr_len = mp->local_addrlen;
    }

    mqvpn_path_handle_t handle =
        mqvpn_client_add_path_fd_with_outcome(p->client, fd, &desc, outcome);
    if (handle < 0) {
        LOG_WRN("routemon: add_path_fd() for re-add %s failed", ifname);
        return -1;
    }
    p->lib_path_handles[slot] = handle;
    return handle;
}

/* Roll back a failed re-add so the next attempt starts from a clean slate.
 *
 * Safe ordering: remove_path() first, then close(fd). The xquic_path_live=0
 * invariant (enforced by apply_path_activation_failure /
 * apply_path_create_permanent_failure) makes remove_path() skip
 * xqc_conn_close_path(), so xquic never touches this fd during teardown.
 * Do NOT remove that defensive clear — it's what makes this rollback safe. */
static void
recovery_rollback(platform_ctx_t *p, int slot, mqvpn_add_path_outcome_t outcome)
{
    mqvpn_path_t *mp = &p->path_mgr.paths[slot];
    const char *ifname = mp->iface;

    mqvpn_client_remove_path(p->client, p->lib_path_handles[slot]);
    close(mp->fd);
    mp->fd = -1;
    mp->platform_attached = 0;

    if (outcome == MQVPN_ADD_PATH_PERMANENT_FAIL) {
        /* Saturate the per-slot counter — recover_dropped_paths_cb will
         * skip this slot until a fresh Level-2 reconnect resets the limit. */
        p->path_recover_failures[slot] = PATH_RECOVER_FAILURE_LIMIT;
        LOG_WRN("routemon: path %s recovery abandoned (xquic budget exhausted; "
                "reconnect required)",
                ifname);
        return;
    }

    /* Transient failure (most commonly -XQC_EMP_NO_AVAIL_PATH_ID during
     * WiFi reassoc CID-lag burst). Bump the consecutive-failure counter so
     * the 3s recovery timer eventually gives up and waits for reconnect. */
    p->path_recover_failures[slot]++;
    if (p->path_recover_failures[slot] >= PATH_RECOVER_FAILURE_LIMIT) {
        LOG_WRN("routemon: path %s recovery abandoned after %d consecutive "
                "failures (will resume on reconnect)",
                ifname, PATH_RECOVER_FAILURE_LIMIT);
    } else {
        LOG_WRN("routemon: re-add %s not activated, will retry (%d/%d)", ifname,
                p->path_recover_failures[slot], PATH_RECOVER_FAILURE_LIMIT);
    }
}

/* PR5: replace path_removed_by_platform[] polling with lib state query.
 * The slot is considered "ready for re-add" if its public status is
 * MQVPN_PATH_CLOSED — i.e., lib has fully cleaned up the previous incarnation
 * (CLOSED_FREE) OR is mid-cleanup (CLOSED_DROPPED with all xquic-side fields
 * drained). add_path_fd_with_outcome will refuse to reuse a non-CLOSED slot;
 * if cleanup hasn't completed we get TRANSIENT_FAIL and bail — next netlink
 * event will retry. */
static int
try_readd_removed_path(platform_ctx_t *p, const char *ifname)
{
    /* Never re-add on a down/no-carrier link, or while the interface lacks
     * a usable source address of the server's family (see
     * iface_has_usable_ip). RTM_NEWADDR for the right family, or the
     * recovery timer, will retry once both hold.
     *
     * Note: handle_rtm_newlink / recover_dropped_paths_cb already check
     * both conditions before calling in here — that's intentionally
     * redundant. This function is also reachable via handle_rtm_newaddr,
     * which must not be allowed to bypass the gate on an admin-down or
     * carrier-less iface. */
    if (!iface_is_up_and_running(ifname)) return 0;
    if (iface_has_usable_ip(ifname, p->server_addr.ss_family) != 1) return 0;

    mqvpn_path_info_t pinfo[MQVPN_MAX_PATHS];
    int n = 0;
    if (mqvpn_client_get_paths(p->client, pinfo, MQVPN_MAX_PATHS, &n) != MQVPN_OK)
        return 0;

    for (int i = 0; i < p->path_mgr.n_paths; i++) {
        if (strcmp(p->path_mgr.paths[i].iface, ifname) != 0) continue;
        if (p->path_recover_failures[i] >= PATH_RECOVER_FAILURE_LIMIT) continue;
        mqvpn_path_handle_t h = p->lib_path_handles[i];

        int found = 0;
        mqvpn_path_status_t st = MQVPN_PATH_PENDING;
        for (int j = 0; j < n; j++) {
            if (pinfo[j].handle == h) {
                found = 1;
                st = pinfo[j].status;
                break;
            }
        }
        /* Re-add candidate: slot exists in lib as CLOSED (DROPPED or FREE),
         * or slot was never tracked (handle invalid / removed before lib saw it). */
        if (found && st != MQVPN_PATH_CLOSED) continue;

        /* Definite "no FIB route to the server via this iface": re-adding
         * now would SO_BINDTODEVICE the challenge into the kernel's
         * assume-on-link ARP blackhole (sendto succeeds, nothing on the
         * wire). The 3s recovery timer retries once a route exists.
         * -1 (probe unavailable) intentionally passes — fail open. */
        if (iface_has_route_to_server(ifname, &p->server_addr) == 0) return 0;

        mqvpn_path_t *mp = &p->path_mgr.paths[i];
        int fd = recovery_socket_create(p->server_addr.ss_family, ifname, mp);
        if (fd < 0) return 0;

        mp->fd = fd;
        mp->platform_attached = 1;
        mp->xquic_path_live = 0;
        mp->path_id = 0;

        mqvpn_add_path_outcome_t outcome = MQVPN_ADD_PATH_OK;
        mqvpn_path_handle_t new_h =
            recovery_register_with_lib(p, i, fd, ifname, &outcome);
        if (new_h < 0) {
            close(fd);
            mp->fd = -1;
            mp->platform_attached = 0;
            return 0;
        }

        if (outcome != MQVPN_ADD_PATH_OK) {
            recovery_rollback(p, i, outcome);
            return 0;
        }

        /* Activation confirmed — register libevent so packets are read from
         * the new socket. */
        p->ev_udp[i] = event_new(p->eb, fd, EV_READ | EV_PERSIST, on_socket_read, p);
        event_add(p->ev_udp[i], NULL);

        p->path_recover_failures[i] = 0; /* success resets the budget */
        LOG_INF("routemon: path %s re-added (handle=%lld)", ifname, (long long)new_h);
        return 1;
    }
    return 0;
}

/* ----------------------------------------------------------------
 * Layer B insertion point: recover_dropped_paths_cb / handle_rtm_* /
 * on_route_event / setup_route_socket (canon netlink_mon.c:473+) land
 * here. iface_has_route_to_server stays last (new code, not in canon).
 * ---------------------------------------------------------------- */

/* Round the trailing sockaddr length up to the message stride. This is
 * conservative power-of-2 padding: xnu walks appended sockaddrs by sa_len
 * and tolerates trailing pad, so 8-byte rounding is safe even though the
 * kernel's own ROUNDUP32 uses 4. */
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
    fcntl(fd, F_SETFD, FD_CLOEXEC);

    /* xnu silently drops a routing-socket reply when appending it to the
     * receive buffer fails (unlike Linux netlink, which signals ENOBUFS),
     * so a blocking read could hang the event-loop thread forever —
     * precisely during the carrier-flap storms this probe runs in. Bound
     * the wait; a timeout maps to -1 (fail open) below. */
    struct timeval rcv_to = {0, 200000};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rcv_to, sizeof(rcv_to));

    struct {
        struct rt_msghdr rtm;
        char space[512];
    } req;
    memset(&req, 0, sizeof(req));

    socklen_t salen = (server->ss_family == AF_INET6) ? sizeof(struct sockaddr_in6)
                                                      : sizeof(struct sockaddr_in);
    memcpy(req.space, server, salen);
    /* The resolver's literal-IP fast paths may leave ss_len zero; the
     * routing socket walks appended sockaddrs by sa_len, so set it. */
    ((struct sockaddr *)(void *)req.space)->sa_len = (uint8_t)salen;

    /* Unsigned so wraparound is defined. Non-atomic: assumes the platform
     * run loop is single-threaded per process (multiple client instances
     * in one process would need atomics here). */
    static unsigned int seq_counter = 0;
    int seq = (int)++seq_counter;
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
    if (wn < 0) {
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
    if (wn != (ssize_t)req.rtm.rtm_msglen) {
        /* Short positive write: errno is stale here — never interpret it
         * as a definite "no route". Fail open. */
        close(fd);
        return -1;
    }

    int ret = -1;
    union {
        struct rt_msghdr rtm;
        char raw[ROUTE_BUF_SIZE];
    } rbuf;
    /* Bounded read loop: the kernel answers this synchronous RTM_GET on
     * the same socket, but a route socket also observes other processes'
     * RTM_GET replies — loop a bounded number of times to find the reply
     * matching our type+pid+seq rather than trusting the first message
     * read. A read timeout (SO_RCVTIMEO above) breaks out with ret == -1. */
    for (int i = 0; i < 8; i++) {
        ssize_t len = read(fd, rbuf.raw, sizeof(rbuf.raw));
        if (len < (ssize_t)sizeof(struct rt_msghdr)) break;
        const struct rt_msghdr *rtm = &rbuf.rtm;
        if (rtm->rtm_type != RTM_GET) continue;
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
