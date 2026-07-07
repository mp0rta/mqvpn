// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * netlink_mon.c — Netlink link/address monitor + path recovery accelerator
 *
 * Everything Linux-netlink-specific lives here: RTM_* event parsing and
 * dispatch, the drop/reactivate/re-add decisions they drive, and the
 * periodic recovery timer that backstops missed one-shot events.
 *
 * Split out of platform_linux.c so the reactor skeleton there stays free
 * of netlink types — a future Darwin platform layer reuses the reactor
 * and replaces only this module (PF_ROUTE / NWPathMonitor equivalent).
 */

#include "platform_internal.h"
#include "netlink_mon.h"
#include "log.h"

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
#include <ifaddrs.h>
#include <sys/ioctl.h>

/* ================================================================
 *  Netlink path recovery accelerator
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

    LOG_WRN("netlink: interface %s %s, closing path %d", p->path_mgr.paths[idx].iface,
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
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) return 0;
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

        int ret = mqvpn_client_reactivate_path(p->client, h);
        if (ret == MQVPN_OK) {
            LOG_INF("netlink: reactivated path %s", ifname);
        } else if (ret == MQVPN_ERR_INVALID_STATE) {
            /* slot not in 3-state acceptance window (e.g. already VALIDATING) */
        } else {
            LOG_WRN("netlink: reactivate %s failed: %s", ifname, mqvpn_error_string(ret));
        }
    }
}

/* Create a UDP socket bound to the wildcard address and pinned to ifname.
 * Updates mp->local_addr / mp->local_addrlen on success.
 * Returns the new fd, or -1 (already logged). */
static int
recovery_socket_create(sa_family_t af, const char *ifname, mqvpn_path_t *mp)
{
    int fd = (int)socket(af, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOG_WRN("netlink: socket() for re-add %s: %s", ifname, strerror(errno));
        return -1;
    }
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        LOG_WRN("netlink: fcntl() for re-add %s: %s", ifname, strerror(errno));
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
        LOG_WRN("netlink: bind() for re-add %s: %s", ifname, strerror(errno));
        goto fail;
    }

    /* Pin AFTER bind, matching startup-loop order. */
    if (linux_pin_socket_to_iface(fd, ifname) < 0) {
        LOG_WRN("netlink: iface pin for re-add %s failed", ifname);
        goto fail;
    }

    return fd;
fail:
    close(fd);
    return -1;
}

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
        LOG_WRN("netlink: add_path_fd() for re-add %s failed", ifname);
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
        LOG_WRN("netlink: path %s recovery abandoned (xquic budget exhausted; "
                "reconnect required)",
                ifname);
        return;
    }

    /* Transient failure (most commonly -XQC_EMP_NO_AVAIL_PATH_ID during
     * WiFi reassoc CID-lag burst). Bump the consecutive-failure counter so
     * the 3s recovery timer eventually gives up and waits for reconnect. */
    p->path_recover_failures[slot]++;
    if (p->path_recover_failures[slot] >= PATH_RECOVER_FAILURE_LIMIT) {
        LOG_WRN("netlink: path %s recovery abandoned after %d consecutive "
                "failures (will resume on reconnect)",
                ifname, PATH_RECOVER_FAILURE_LIMIT);
    } else {
        LOG_WRN("netlink: re-add %s not activated, will retry (%d/%d)", ifname,
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
        LOG_INF("netlink: path %s re-added (handle=%lld)", ifname, (long long)new_h);
        return 1;
    }
    return 0;
}

/* Periodically re-add platform slots whose library state is CLOSED but
 * whose interface is currently up. Fires every RECOVER_INTERVAL_SEC.
 *
 * Spec sec 3.4 "Stateless Platforms" compliance: this handler holds NO
 * lifecycle state — it queries the library via mqvpn_client_get_paths()
 * each tick (in try_readd_removed_path) and acts based on the public
 * MQVPN_PATH_CLOSED status. path_recover_failures[] is pure backpressure
 * to bound the busy-loop on transient xquic errors during a WiFi
 * reassoc CID-lag burst — not a state mirror.
 *
 * Why this timer is necessary: on carrier loss/restore the kernel emits
 * a single RTM_NEWLINK with IFF_RUNNING toggled — IP/admin state don't
 * change, so no RTM_NEWADDR follows. If the one-shot
 * try_readd_removed_path() driven by that single event fails
 * synchronously (e.g. xqc_conn_create_path returns
 * -XQC_EMP_NO_AVAIL_PATH_ID because the server hasn't replenished CIDs
 * yet, or the previous CLOSED_DROPPED slot hasn't drained xquic-side
 * fields), there is no further event to retry on. The library's
 * tick_drive_retry_timer only services CREATE_WAIT/DEGRADED, not
 * CLOSED_DROPPED — so a platform-side periodic poll is the only way
 * to recover.
 *
 * Pre-filters on link state + IP so we don't burn syscalls
 * (socket/bind/IP_BOUND_IF) when the interface is still down. */
void
recover_dropped_paths_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    platform_ctx_t *p = (platform_ctx_t *)arg;

    mqvpn_path_info_t pinfo[MQVPN_MAX_PATHS];
    int n = 0;
    if (mqvpn_client_get_paths(p->client, pinfo, MQVPN_MAX_PATHS, &n) != MQVPN_OK)
        goto rearm;

    for (int i = 0; i < p->path_mgr.n_paths; i++) {
        if (p->path_recover_failures[i] >= PATH_RECOVER_FAILURE_LIMIT) continue;
        if (p->path_mgr.paths[i].platform_attached) {
            /* CLOSED_RECOVERABLE slots (valid fd) are normally reactivated
             * by one-shot RTM_NEWADDR/NEWLINK events. A route appearing
             * emits neither, and the route gate may have swallowed the
             * original event — so the timer must also retry reactivate.
             * try_reactivate_by_ifname re-checks lib state and the lib
             * rejects wrong states with INVALID_STATE, so this is
             * idempotent. */
            mqvpn_path_handle_t ah = p->lib_path_handles[i];
            for (int j = 0; j < n; j++) {
                if (pinfo[j].handle == ah && pinfo[j].status == MQVPN_PATH_CLOSED) {
                    const char *rifname = p->path_mgr.paths[i].iface;
                    /* route gate runs inside try_reactivate_by_ifname */
                    if (iface_is_up_and_running(rifname) &&
                        iface_has_usable_ip(rifname, p->server_addr.ss_family) == 1)
                        try_reactivate_by_ifname(p, rifname);
                    break;
                }
            }
            continue;
        }

        mqvpn_path_handle_t h = p->lib_path_handles[i];
        int is_closed = 0;
        for (int j = 0; j < n; j++) {
            if (pinfo[j].handle == h) {
                is_closed = (pinfo[j].status == MQVPN_PATH_CLOSED);
                break;
            }
        }
        if (!is_closed) continue;

        const char *ifname = p->path_mgr.paths[i].iface;
        if (!iface_is_up_and_running(ifname)) continue;
        if (iface_has_usable_ip(ifname, p->server_addr.ss_family) != 1) continue;
        if (iface_has_route_to_server(ifname, &p->server_addr) == 0) {
            /* First block + every 10th (≈30s at the 3s poll). The message
             * wording is grepped by scripts/ci_e2e/run_route_gate_test.sh —
             * rewording it silently disables that e2e's gate check. */
            if (p->route_gate_blocked[i]++ % 10 == 0)
                LOG_WRN("netlink: %s has a usable address but no route to "
                        "the server — re-add deferred until a route appears",
                        ifname);
            continue;
        }
        p->route_gate_blocked[i] = 0;

        /* try_readd_removed_path scans by ifname, finds this slot via
         * lib state, and either succeeds (resets the counter via line
         * above) or fails through recovery_rollback (which bumps the
         * counter). Multiple slots sharing one ifname are handled by
         * try_readd's internal loop. */
        if (try_readd_removed_path(p, ifname))
            LOG_INF("netlink: timer re-added path %s after carrier-up failure", ifname);
    }

    /* The re-add above may have created a path (queuing a PATH_CHALLENGE
     * inside xquic) — drive the engine and re-arm the tick from the
     * engine's new wakeup request, exactly as on_socket_read does.
     * Without this the queued frames wait for an unrelated timer. */
    mqvpn_client_tick(p->client);
    schedule_next_tick(p);

rearm:
    if (p->ev_recover) {
        struct timeval tv = {.tv_sec = RECOVER_INTERVAL_SEC};
        event_add(p->ev_recover, &tv);
    }
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
    if (!try_readd_removed_path(p, ifname)) try_reactivate_by_ifname(p, ifname);
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
 * Only acts while the link is still up-and-running: admin down and link
 * teardown flush addresses too, and the kernel emits those RTM_DELADDRs
 * BEFORE the corresponding link event (`ip link del` -> v4 DELADDR before
 * DELLINK; v6 admin down -> DELADDR before NEWLINK). Acting on them here
 * would steal the drop from the more specific handler and misreport the
 * public reason as ADDR_REMOVED. nmcli/DHCP address loss keeps IFF_UP and
 * carrier set, so the gate never blocks the case this handler exists for. */
static void
handle_rtm_deladdr(platform_ctx_t *p, struct nlmsghdr *nh)
{
    struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);
    if (ifa->ifa_family != p->server_addr.ss_family) return;
    char ifname[IFNAMSIZ];
    if (!if_indextoname(ifa->ifa_index, ifname)) return;

    /* Cheap tracked-path match before the getifaddrs() enumeration: on
     * hosts with container/veth churn every unrelated DELADDR would
     * otherwise pay a full address-table walk inside the event loop. */
    int tracked = 0;
    for (int i = 0; i < p->path_mgr.n_paths; i++) {
        if (strcmp(p->path_mgr.paths[i].iface, ifname) == 0) {
            tracked = 1;
            break;
        }
    }
    if (!tracked) return;

    if (!iface_is_up_and_running(ifname)) return; /* link event owns the drop */
    if (iface_has_usable_ip(ifname, ifa->ifa_family) != 0) return;
    drop_paths_by_ifname(p, ifname, MQVPN_PLATFORM_REASON_ADDR_REMOVED);
}

/* RTM_DELLINK: interface gone. remove_path_by_index() uses drop_path
 * semantics (not orderly close) so surviving paths aren't blocked by
 * xquic shutdown handshakes. */
static void
handle_rtm_dellink(platform_ctx_t *p, struct nlmsghdr *nh)
{
    const char *ifname = nlmsg_get_ifname(nh);
    if (!ifname) return;
    drop_paths_by_ifname(p, ifname, MQVPN_PLATFORM_REASON_RTM_DELLINK);
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
        drop_paths_by_ifname(p, ifname,
                             admin_down ? MQVPN_PLATFORM_REASON_ADMIN_DOWN
                                        : MQVPN_PLATFORM_REASON_CARRIER_LOST);
        return;
    }

    if (!(ifi->ifi_flags & IFF_RUNNING)) return;
    if (iface_has_usable_ip(ifname, p->server_addr.ss_family) != 1) return;

    /* First: try to re-add paths removed by RTM_DELLINK (dead fd).
     * Otherwise: reactivate degraded/closed paths (fd still valid). */
    if (try_readd_removed_path(p, ifname)) return;
    try_reactivate_by_ifname(p, ifname);
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
