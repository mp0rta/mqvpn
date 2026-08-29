// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * netmon_common.c — shared core of the POSIX network-path monitors
 *
 * See netmon_common.h for the layer split and the adapter contract. Every
 * function here is a verbatim port of the previously hand-synchronized
 * twin bodies in netlink_mon.c / route_mon.c: the only changes are the
 * `netmon_` prefix, the log tag becoming a runtime argument (rendered
 * output is byte-identical — e2e scripts grep these lines), and the five
 * platform divergence points becoming adapter calls. Behavioral history
 * and rationale comments travel with the code they explain.
 */

#include "netmon_common.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#ifdef __APPLE__
#  include <sys/sockio.h> /* SIOCGIFFLAGS lives here on Darwin */
#endif
#include <net/if.h>
#include <ifaddrs.h>
#include <netinet/in.h>

/* Log wording per reason. Frozen: e2e scripts grep these exact strings
 * ("interface <if> <reason>, closing path"). */
const char *
netmon_drop_reason_str(mqvpn_platform_reason_t reason)
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
 * Four callers: interface-gone (RTM_DELLINK / detach fallback); carrier
 * lost; admin down; and address removed (no usable source address left).
 * All share cleanup; the reason is logged and reported in the public
 * event.
 *
 * Cleans up: library path, libevent, fd. Preserves iface name for re-add. */
static void
remove_path_by_index(platform_ctx_t *p, int idx, mqvpn_platform_reason_t reason)
{
    if (p->path_mgr.paths[idx].fd < 0) return; /* already removed */

    LOG_WRN("%s: interface %s %s, closing path %d", netmon_log_tag,
            p->path_mgr.paths[idx].iface, netmon_drop_reason_str(reason), idx);

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

/* Drop every tracked path on `ifname`. Shared by the address-removed /
 * link-gone / link-state drop branches so slot matching stays in one
 * place. Returns the number of paths matched (dropped or already gone). */
int
netmon_drop_paths_by_ifname(platform_ctx_t *p, const char *ifname,
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
int
netmon_iface_is_up_and_running(const char *ifname)
{
#ifdef SOCK_CLOEXEC
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) return 0;
#else
    /* Darwin deviation: no SOCK_CLOEXEC socket() flag — set FD_CLOEXEC
     * post-hoc via fcntl instead. */
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return 0;
    fcntl(s, F_SETFD, FD_CLOEXEC);
#endif
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
 * address-removed drop requires a definite 0, the re-add gates a definite
 * 1, so a transient getifaddrs failure never drops or re-adds a path. */
int
netmon_iface_has_usable_ip(const char *ifname, sa_family_t af)
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

void
netmon_try_reactivate_by_ifname(platform_ctx_t *p, const char *ifname)
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

        /* Platform hook: Darwin skips fd-less slots and re-applies the
         * iface pin + scoped server pin here; Linux always proceeds. */
        if (netmon_platform_pre_reactivate(p, i, ifname) < 0) continue;

        int ret = mqvpn_client_reactivate_path(p->client, h);
        if (ret == MQVPN_OK) {
            LOG_INF("%s: reactivated path %s", netmon_log_tag, ifname);
        } else if (ret == MQVPN_ERR_INVALID_STATE) {
            /* slot not in 3-state acceptance window (e.g. already VALIDATING) */
        } else {
            LOG_WRN("%s: reactivate %s failed: %s", netmon_log_tag, ifname,
                    mqvpn_error_string(ret));
        }
    }
}

/* Create a UDP socket bound to the wildcard address and pinned to ifname.
 * Updates mp->local_addr / mp->local_addrlen on success.
 * Returns the new fd, or -1 (already logged). Interface pinning and the
 * post-create sockopt reproduction (Linux UDP GRO) go through the platform
 * adapters. */
static int
recovery_socket_create(platform_ctx_t *p, sa_family_t af, const char *ifname,
                       mqvpn_path_t *mp)
{
    int fd = (int)socket(af, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOG_WRN("%s: socket() for re-add %s: %s", netmon_log_tag, ifname,
                strerror(errno));
        return -1;
    }
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        LOG_WRN("%s: fcntl() for re-add %s: %s", netmon_log_tag, ifname, strerror(errno));
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
        LOG_WRN("%s: bind() for re-add %s: %s", netmon_log_tag, ifname, strerror(errno));
        goto fail;
    }

    /* Pin AFTER bind, matching startup-loop order. */
    if (netmon_platform_pin_socket(fd, ifname, af) < 0) {
        LOG_WRN("%s: iface pin for re-add %s failed", netmon_log_tag, ifname);
        goto fail;
    }

    netmon_platform_socket_created(p, fd, ifname);

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
        LOG_WRN("%s: add_path_fd() for re-add %s failed", netmon_log_tag, ifname);
        return -1;
    }
    p->lib_path_handles[slot] = handle;
    return handle;
}

/* Roll back a failed re-add so the next attempt starts from a clean slate.
 *
 * Safe ordering: remove_path() first, then close(fd), then notify the lib the
 * fd is closed. remove_path() moves the slot to CLOSED_DROPPED; the
 * CLOSED_DROPPED -> CLOSED_FREE lazy gate only fires once the lib sees fd<0, so
 * the on_platform_fd_closed() call is required — without it the slot parks in
 * CLOSED_DROPPED and never becomes reusable via the FREE path. This mirrors the
 * close-then-notify handshake in remove_path_by_index(). The xquic_path_live=0
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
    mqvpn_client_on_platform_fd_closed(p->client, p->lib_path_handles[slot]);

    if (outcome == MQVPN_ADD_PATH_PERMANENT_FAIL) {
        /* Saturate the per-slot counter — recover_dropped_paths_cb will
         * skip this slot until a fresh Level-2 reconnect resets the limit. */
        p->path_recover_failures[slot] = PATH_RECOVER_FAILURE_LIMIT;
        LOG_WRN("%s: path %s recovery abandoned (xquic budget exhausted; "
                "reconnect required)",
                netmon_log_tag, ifname);
        return;
    }

    /* Transient failure (most commonly -XQC_EMP_NO_AVAIL_PATH_ID during
     * WiFi reassoc CID-lag burst). Bump the consecutive-failure counter so
     * the 3s recovery timer eventually gives up and waits for reconnect. */
    p->path_recover_failures[slot]++;
    if (p->path_recover_failures[slot] >= PATH_RECOVER_FAILURE_LIMIT) {
        LOG_WRN("%s: path %s recovery abandoned after %d consecutive "
                "failures (will resume on reconnect)",
                netmon_log_tag, ifname, PATH_RECOVER_FAILURE_LIMIT);
    } else {
        LOG_WRN("%s: re-add %s not activated, will retry (%d/%d)", netmon_log_tag, ifname,
                p->path_recover_failures[slot], PATH_RECOVER_FAILURE_LIMIT);
    }
}

/* PR5: replace path_removed_by_platform[] polling with lib state query.
 * The slot is considered "ready for re-add" if its public status is
 * MQVPN_PATH_CLOSED — i.e., lib has fully cleaned up the previous incarnation
 * (CLOSED_FREE) OR is mid-cleanup (CLOSED_DROPPED). Note the re-add does not
 * necessarily recycle the same slot: add_path_fd's reuse scan requires a
 * fully-drained slot (status CLOSED && !platform_attached && !xquic_path_live),
 * so a CLOSED_DROPPED slot still awaiting xquic-side drain is skipped and a
 * fresh slot is appended instead — the re-add succeeds on the new slot while
 * the old one drains and is reclaimed to CLOSED_FREE later. n_paths therefore
 * grows monotonically under rapid flapping and self-heals; it only fails
 * (returns -1) if MQVPN_MAX_PATHS is reached before the stale slots drain. */
int
netmon_try_readd_removed_path(platform_ctx_t *p, const char *ifname)
{
    /* Never re-add on a down/no-carrier link, or while the interface lacks
     * a usable source address of the server's family (see
     * netmon_iface_has_usable_ip). An address-gained event for the right
     * family, or the recovery timer, will retry once both hold.
     *
     * Note: the link-event handlers / recover_dropped_paths_cb already
     * check both conditions before calling in here — that's intentionally
     * redundant. This function is also reachable via the address-gained
     * handler, which must not be allowed to bypass the gate on an
     * admin-down or carrier-less iface. */
    if (!netmon_iface_is_up_and_running(ifname)) return 0;
    if (netmon_iface_has_usable_ip(ifname, p->server_addr.ss_family) != 1) return 0;

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
         * now would pin the challenge into the kernel's assume-on-link ARP
         * blackhole (sendto succeeds, nothing on the wire). The 3s
         * recovery timer retries once a route exists.
         * -1 (probe unavailable) intentionally passes — fail open. */
        if (iface_has_route_to_server(ifname, &p->server_addr) == 0) return 0;

        /* Platform hook: Darwin restores the scoped server pin (#F1)
         * before the add-path below fires the first PATH_CHALLENGE. */
        netmon_platform_pre_readd(p, ifname);

        mqvpn_path_t *mp = &p->path_mgr.paths[i];
        int fd = recovery_socket_create(p, p->server_addr.ss_family, ifname, mp);
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
        LOG_INF("%s: path %s re-added (handle=%lld)", netmon_log_tag, ifname,
                (long long)new_h);
        return 1;
    }
    return 0;
}

/* Shared decision tail of the DELADDR handlers (event parsing stays with
 * the platform): drop as ADDR_REMOVED only when tracked, still
 * up-and-running, and definitely address-less. */
void
netmon_on_addr_removed(platform_ctx_t *p, const char *ifname, sa_family_t af)
{
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

    if (!netmon_iface_is_up_and_running(ifname)) return; /* link event owns the drop */
    if (netmon_iface_has_usable_ip(ifname, af) != 0) return;
    netmon_drop_paths_by_ifname(p, ifname, MQVPN_PLATFORM_REASON_ADDR_REMOVED);
}

/* Periodically re-add platform slots whose library state is CLOSED but
 * whose interface is currently up. Fires every RECOVER_INTERVAL_SEC.
 *
 * Spec sec 3.4 "Stateless Platforms" compliance: this handler holds NO
 * lifecycle state — it queries the library via mqvpn_client_get_paths()
 * each tick (in netmon_try_readd_removed_path) and acts based on the
 * public MQVPN_PATH_CLOSED status. path_recover_failures[] is pure
 * backpressure to bound the busy-loop on transient xquic errors during a
 * WiFi reassoc CID-lag burst — not a state mirror.
 *
 * Why this timer is necessary: on carrier loss/restore the kernel emits
 * a single link event with the running flag toggled — IP/admin state
 * don't change, so no address event follows. If the one-shot
 * netmon_try_readd_removed_path() driven by that single event fails
 * synchronously (e.g. xqc_conn_create_path returns
 * -XQC_EMP_NO_AVAIL_PATH_ID because the server hasn't replenished CIDs
 * yet, or the previous CLOSED_DROPPED slot hasn't drained xquic-side
 * fields), there is no further event to retry on. The library's
 * tick_drive_retry_timer only services CREATE_WAIT/DEGRADED, not
 * CLOSED_DROPPED — so a platform-side periodic poll is the only way
 * to recover.
 *
 * Pre-filters on link state + IP so we don't burn syscalls
 * (socket/bind/pin) when the interface is still down. */
void
recover_dropped_paths_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    platform_ctx_t *p = (platform_ctx_t *)arg;

    /* Platform hook: Darwin runs its drop-capable route_resync here (xnu's
     * routing socket has no overflow signal, so the reconcile can only be
     * timer-driven, and drops must land before the scan below re-evaluates
     * library state). Returns nonzero when it may have queued work. */
    int pre_scan_dropped = netmon_platform_pre_scan(p);

    mqvpn_path_info_t pinfo[MQVPN_MAX_PATHS];
    int n = 0;
    if (mqvpn_client_get_paths(p->client, pinfo, MQVPN_MAX_PATHS, &n) != MQVPN_OK) {
        /* If the pre-scan may have dropped paths (queuing PATH_ABANDON
         * inside xquic), drive the engine before re-arming so those frames
         * don't wait for an unrelated timer. A bare re-arm is safe only
         * when no pre-scan work happened (the Linux case). */
        if (pre_scan_dropped) {
            mqvpn_client_tick(p->client);
            schedule_next_tick(p);
        }
        goto rearm;
    }

    for (int i = 0; i < p->path_mgr.n_paths; i++) {
        if (p->path_recover_failures[i] >= PATH_RECOVER_FAILURE_LIMIT) continue;
        if (p->path_mgr.paths[i].platform_attached) {
            /* CLOSED_RECOVERABLE slots (valid fd) are normally reactivated
             * by one-shot address/link events. A route appearing emits
             * neither, and the route gate may have swallowed the original
             * event — so the timer must also retry reactivate.
             * netmon_try_reactivate_by_ifname re-checks lib state and the
             * lib rejects wrong states with INVALID_STATE, so this is
             * idempotent. */
            mqvpn_path_handle_t ah = p->lib_path_handles[i];
            for (int j = 0; j < n; j++) {
                if (pinfo[j].handle == ah && pinfo[j].status == MQVPN_PATH_CLOSED) {
                    const char *rifname = p->path_mgr.paths[i].iface;
                    /* route gate runs inside netmon_try_reactivate_by_ifname */
                    if (netmon_iface_is_up_and_running(rifname) &&
                        netmon_iface_has_usable_ip(rifname, p->server_addr.ss_family) ==
                            1)
                        netmon_try_reactivate_by_ifname(p, rifname);
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
        if (!netmon_iface_is_up_and_running(ifname)) continue;
        if (netmon_iface_has_usable_ip(ifname, p->server_addr.ss_family) != 1) continue;
        if (iface_has_route_to_server(ifname, &p->server_addr) == 0) {
            /* First block + every 10th (≈30s at the 3s poll). The message
             * wording is grepped by scripts/ci_e2e/run_route_gate_test.sh —
             * rewording it silently disables that e2e's gate check (its
             * GATE_PATTERN hardcodes the "netlink:" prefix, so only the
             * Linux rendering is covered today). */
            if (p->route_gate_blocked[i]++ % 10 == 0)
                LOG_WRN("%s: %s has a usable address but no route to "
                        "the server — re-add deferred until a route appears",
                        netmon_log_tag, ifname);
            continue;
        }
        p->route_gate_blocked[i] = 0;

        /* netmon_try_readd_removed_path scans by ifname, finds this slot
         * via lib state, and either succeeds (resets the counter via line
         * above) or fails through recovery_rollback (which bumps the
         * counter). Multiple slots sharing one ifname are handled by
         * try_readd's internal loop. */
        if (netmon_try_readd_removed_path(p, ifname))
            LOG_INF("%s: timer re-added path %s after carrier-up failure", netmon_log_tag,
                    ifname);
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
