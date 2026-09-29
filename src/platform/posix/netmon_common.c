// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * netmon_common.c — shared core of the POSIX network-path monitors
 *
 * See netmon_common.h for the layer split and the adapter contract. The
 * monitor functions began as verbatim ports of the previously
 * hand-synchronized twin bodies in netlink_mon.c / route_mon.c: the only
 * changes were the `netmon_` prefix, the log tag becoming a runtime argument
 * (rendered output is byte-identical — e2e scripts grep these lines), and
 * the five platform divergence points becoming adapter calls. Behavioral
 * history and rationale comments travel with the code they explain. The
 * startup slots (platform_paths_open) and the release tail
 * (release_transport) serve both platforms from here too.
 */

#include "netmon_common.h"
#include "mqvpn_bind_posix.h"
#include "platform/path_readd.h"
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

/* Contract in platform_internal.h. Shared: the counters live in the POSIX
 * bind, which every POSIX platform uses. */
void
platform_read_rx_stats(const platform_path_t *s, uint64_t *receives, uint64_t *datagrams)
{
    *receives = 0;
    *datagrams = 0;
    if (!s->bind_ctx) return;
    mqvpn_bind_posix_stats_t st = {.struct_size = sizeof(st)};
    mqvpn_bind_posix_path_get_stats(s->bind_ctx, &st);
    *receives = st.rx_receives;
    *datagrams = st.rx_datagrams;
}

/* A release the library refuses right after this platform's own drop or
 * remove of that path cannot happen: drop and remove move every other
 * lifecycle state to CLOSED_DROPPED/FREE, and nothing runs in between. If it
 * ever does, the library still holds a transport whose socket is already
 * closed — a send would fail, or go out through whatever socket reused the
 * fd number — so the process stops instead of running on: the route the
 * tunnel-setup abort takes, exit 1 (the packaged service restarts on
 * failure). The ctx the library still owns is finalised by client_destroy
 * on the way out. */
static void
fatal_stop(platform_ctx_t *p)
{
    p->fatal_error = PLATFORM_FATAL_PATH_RELEASE;
    p->shutting_down = 1;
    mqvpn_client_disconnect(p->client);
    /* disconnect() fires no CLOSED transition from IDLE or CLOSED, and that
     * transition is what normally breaks the loop — break it here, as the
     * signal handler does. */
    event_base_loopbreak(p->eb);
}

/* Give a library-owned transport back: close the slot's socket, then report
 * the release so the library finalises the ctx (the CLOSED_DROPPED ->
 * CLOSED_FREE cleanup completes once the xquic side also clears). RX
 * telemetry is read BEFORE the release (the ctx dies inside it) and added
 * only once the release succeeded. The one place a drop or rollback hands a
 * transport back. */
static void
release_transport(platform_ctx_t *p, platform_path_t *s)
{
    uint64_t rx_r, rx_d;
    platform_read_rx_stats(s, &rx_r, &rx_d);

    platform_path_close_socket(s);
    int rc = mqvpn_client_on_platform_path_released(p->client, s->handle);
    if (rc == MQVPN_OK) {
        s->bind_ctx = NULL; /* finalised by the library */
        p->gro_receives += rx_r;
        p->gro_datagrams += rx_d;
        return;
    }
    LOG_ERR("%s: path_released for %s returned %s; transport stays library-owned",
            netmon_log_tag, s->iface, mqvpn_error_string(rc));
    fatal_stop(p);
}

/* Remove a path because the kernel says it's no longer usable.
 * Four callers: interface-gone (RTM_DELLINK / detach fallback); carrier
 * lost; admin down; and address removed (no usable source address left).
 * All share cleanup; the reason is logged and reported in the public
 * event.
 *
 * Cleans up: library path, libevent, fd. Preserves iface name for re-add. */
static void
remove_path_by_slot(platform_ctx_t *p, platform_path_t *s, mqvpn_platform_reason_t reason)
{
    if (s->fd < 0) return; /* already removed */

    LOG_WRN("%s: interface %s %s, closing path %d", netmon_log_tag, s->iface,
            netmon_drop_reason_str(reason), platform_path_index(s));

    /* PR5: emit PLATFORM_DROP via new public API with diagnostic info.
     * Library transitions slot to CLOSED_DROPPED; the transport release is
     * reported by release_transport() below. */
    mqvpn_platform_path_event_info_t info = {0};
    snprintf(info.iface, sizeof(info.iface), "%s", s->iface);
    info.reason = reason;
    mqvpn_client_on_platform_path_dropped(p->client, s->handle, &info);

    release_transport(p, s);
}

/* Drop every tracked path on `ifname`. Shared by the address-removed /
 * link-gone / link-state drop branches so slot matching stays in one
 * place. Returns the number of paths matched (dropped or already gone). */
int
netmon_drop_paths_by_ifname(platform_ctx_t *p, const char *ifname,
                            mqvpn_platform_reason_t reason)
{
    int matched = 0;
    for (int i = 0; i < p->n_paths; i++) {
        if (strcmp(p->paths[i].iface, ifname) == 0) {
            remove_path_by_slot(p, &p->paths[i], reason);
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
     * The lib accepts a reactivate for DEGRADED, CREATE_WAIT and
     * CLOSED_RECOVERABLE (reactivate_slot_eligible); publicly those read
     * DEGRADED, PENDING and CLOSED. Only DEGRADED and CLOSED are tried here:
     * a PENDING slot is validating or waits for the lib's own retry timer.
     * The lib's gate rejects bad states with MQVPN_ERR_INVALID_STATE, which
     * we silently swallow. */
    mqvpn_path_info_t pinfo[MQVPN_MAX_PATHS];
    int n = 0;
    if (mqvpn_client_get_paths(p->client, pinfo, MQVPN_MAX_PATHS, &n) != MQVPN_OK) return;

    for (int i = 0; i < p->n_paths; i++) {
        platform_path_t *s = &p->paths[i];
        if (strcmp(s->iface, ifname) != 0) continue;
        /* Reactivate reuses the slot's own socket; a slot without one is the
         * re-add path's (path_readd.h). */
        if (s->fd < 0) continue;
        mqvpn_path_handle_t h = s->handle;
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

        /* Platform hook: Darwin re-applies the iface pin + scoped server pin
         * here; Linux always proceeds. */
        if (netmon_platform_pre_reactivate(p, s, ifname) < 0) continue;

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

/* The startup slots: one per configured interface, or one "any" slot when
 * none is configured, each with its socket (readd_open_socket() below is the
 * re-add sibling). The "path_mgr:" lines keep the label of the module these
 * slots replaced: log wording is a compatibility surface. */
int
platform_paths_open(platform_ctx_t *p, int n_ifaces, const char *const *ifaces)
{
    int want = n_ifaces > 0 ? n_ifaces : 1;
    for (int i = 0; i < want; i++) {
        const char *iface = n_ifaces > 0 ? ifaces[i] : NULL;
        platform_path_t *s = platform_path_append(p, iface);
        if (!s) {
            LOG_ERR("path_mgr: max paths (%d) reached", MQVPN_MAX_PATHS);
        } else {
            int step = 0;
            s->fd = platform_path_socket_open(p->server_addr.ss_family, &step);
            if (s->fd < 0) {
                if (step == PLATFORM_PATH_STEP_SOCKET)
                    LOG_ERR("path_mgr: socket: %s", strerror(errno));
                else if (step == PLATFORM_PATH_STEP_NONBLOCK)
                    LOG_ERR("path_mgr: set_nonblock: %s", strerror(errno));
                else
                    LOG_ERR("path_mgr: bind(%s): %s", iface ? iface : "any",
                            strerror(errno));
            } else {
                LOG_INF("path_mgr: path[%d] created on %s (fd=%d)", i,
                        iface ? iface : "(any)", s->fd);
                continue;
            }
        }
        if (n_ifaces > 0)
            LOG_ERR("failed to create UDP socket for path[%d] '%s'", i, iface);
        else
            LOG_ERR("failed to create UDP socket");
        return -1;
    }
    return 0;
}

/* Open the slot's replacement socket, commit it to the slot, and pin it to
 * ifname (pin AFTER bind, matching startup order). Socket buffers are set by
 * the transport ctx (7 MiB). 0, or -1 (already logged; a committed socket is
 * closed again). The transport ctx (GRO/GSO policy) is built by the caller. */
static int
readd_open_socket(platform_ctx_t *p, platform_path_t *s, const char *ifname)
{
    sa_family_t af = p->server_addr.ss_family;
    int step = 0;
    int fd = platform_path_socket_open(af, &step);
    if (fd < 0) {
        if (step == PLATFORM_PATH_STEP_SOCKET)
            LOG_WRN("%s: socket() for re-add %s: %s", netmon_log_tag, ifname,
                    strerror(errno));
        else if (step == PLATFORM_PATH_STEP_NONBLOCK)
            LOG_WRN("%s: fcntl() for re-add %s: %s", netmon_log_tag, ifname,
                    strerror(errno));
        else
            LOG_WRN("%s: bind() for re-add %s: %s", netmon_log_tag, ifname,
                    strerror(errno));
        return -1;
    }
    s->fd = fd; /* committed: from here only platform_path_close_socket() closes it */

    if (netmon_platform_pin_socket(fd, ifname, af) < 0) {
        LOG_WRN("%s: iface pin for re-add %s failed", netmon_log_tag, ifname);
        platform_path_close_socket(s);
        return -1;
    }
    return 0;
}

/* Register a freshly-created transport ctx with the library and capture the
 * synchronous activation outcome. Returns the new handle and writes *outcome
 * (MQVPN_ADD_PATH_OK / TRANSIENT / PERMANENT); returns -1 on
 * handle-allocation failure (already logged), in which case the ctx stays
 * caller-owned and the slot keeps its previous handle. */
static mqvpn_path_handle_t
recovery_register_with_lib(platform_ctx_t *p, platform_path_t *s, void *tctx,
                           const char *ifname, mqvpn_add_path_outcome_t *outcome)
{
    mqvpn_path_desc_t desc;
    platform_path_fill_desc(p, s, &desc);

    mqvpn_path_handle_t handle = mqvpn_client_add_path(
        p->client, &desc, mqvpn_bind_posix_path_ops(), tctx, outcome);
    if (handle < 0) {
        LOG_WRN("%s: add_path() for re-add %s failed", netmon_log_tag, ifname);
        return -1;
    }
    s->handle = handle;
    s->bind_ctx = tctx; /* library-owned from here */
    return handle;
}

/* Roll back a failed re-add so the next attempt starts from a clean slate.
 *
 * Safe ordering: remove_path() first, then close the socket, then notify
 * the lib the transport is released (release_transport()). remove_path()
 * moves the slot to CLOSED_DROPPED; the CLOSED_DROPPED -> CLOSED_FREE lazy
 * gate only fires once the lib sees the transport released, so the release
 * report is required — without it the slot parks in CLOSED_DROPPED and never
 * becomes reusable via the FREE path. After an activation failure the core
 * slot's xquic_path_live is 0 (the lifecycle machine clears it), so
 * remove_path() emits no PATH_ABANDON (path_xquic_abandon_due() is false)
 * and xquic never touches this socket during the teardown. */
static void
recovery_rollback(platform_ctx_t *p, platform_path_t *s, mqvpn_add_path_outcome_t outcome)
{
    const char *ifname = s->iface;

    mqvpn_client_remove_path(p->client, s->handle);
    release_transport(p, s);

    if (outcome == MQVPN_ADD_PATH_PERMANENT_FAIL) {
        /* Saturate the per-slot counter — recover_dropped_paths_cb will
         * skip this slot until a fresh Level-2 reconnect resets the limit. */
        s->recover_failures = PATH_RECOVER_FAILURE_LIMIT;
        LOG_WRN("%s: path %s recovery abandoned (xquic budget exhausted; "
                "reconnect required)",
                netmon_log_tag, ifname);
        return;
    }

    /* Transient failure (most commonly -XQC_EMP_NO_AVAIL_PATH_ID during
     * WiFi reassoc CID-lag burst). Bump the consecutive-failure counter so
     * the 3s recovery timer eventually gives up and waits for reconnect. */
    s->recover_failures++;
    if (s->recover_failures >= PATH_RECOVER_FAILURE_LIMIT) {
        LOG_WRN("%s: path %s recovery abandoned after %d consecutive "
                "failures (will resume on reconnect)",
                netmon_log_tag, ifname, PATH_RECOVER_FAILURE_LIMIT);
    } else {
        LOG_WRN("%s: re-add %s not activated, will retry (%d/%d)", netmon_log_tag, ifname,
                s->recover_failures, PATH_RECOVER_FAILURE_LIMIT);
    }
}

/* Re-add slots on ifname that have no socket and whose previous library
 * incarnation is gone — CLOSED (DROPPED or FREE), or no longer listed
 * because another path's re-add recycled its library slot (the shared
 * decision in path_readd.h, which the recovery timer uses too). Slots that
 * still own a socket are reactivate's. The re-add does not necessarily reuse
 * this path's old library slot: add_path reuses the first fully released
 * (CLOSED_FREE) slot, or appends one while a CLOSED_DROPPED slot still waits
 * for its xquic side to drain — so the library's slot count grows under
 * rapid flapping and self-heals; the re-add fails (-1) only if
 * MQVPN_MAX_PATHS is reached before stale slots drain. */
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

    for (int i = 0; i < p->n_paths; i++) {
        platform_path_t *s = &p->paths[i];
        if (strcmp(s->iface, ifname) != 0) continue;
        if (!path_readd_candidate(s->fd >= 0, s->recover_failures,
                                  PATH_RECOVER_FAILURE_LIMIT, s->handle, pinfo, n))
            continue;

        /* Definite "no FIB route to the server via this iface": re-adding
         * now would pin the challenge into the kernel's assume-on-link ARP
         * blackhole (sendto succeeds, nothing on the wire). The 3s
         * recovery timer retries once a route exists.
         * -1 (probe unavailable) intentionally passes — fail open. */
        if (iface_has_route_to_server(ifname, &p->server_addr) == 0) return 0;

        /* Platform hook: Darwin restores the scoped server pin (#F1)
         * before the add-path below fires the first PATH_CHALLENGE. */
        netmon_platform_pre_readd(p, ifname);

        if (readd_open_socket(p, s, ifname) < 0) return 0;

        void *tctx = netmon_platform_transport_create(p, s->fd, ifname);
        if (!tctx) {
            platform_path_close_socket(s);
            return 0;
        }

        mqvpn_add_path_outcome_t outcome = MQVPN_ADD_PATH_OK;
        mqvpn_path_handle_t new_h =
            recovery_register_with_lib(p, s, tctx, ifname, &outcome);
        if (new_h < 0) {
            mqvpn_bind_posix_path_free(tctx); /* add failed: still ours */
            platform_path_close_socket(s);
            return 0;
        }

        if (outcome != MQVPN_ADD_PATH_OK) {
            recovery_rollback(p, s, outcome);
            return 0;
        }

        /* Activation confirmed — arm the read event so packets are read
         * from the new socket. If that fails, the path would live in the
         * library with no RX: give it back like a failed activation. */
        if (platform_path_arm(s) < 0) {
            LOG_WRN("%s: read event setup failed on %s; path rolled back", netmon_log_tag,
                    ifname);
            mqvpn_client_remove_path(p->client, s->handle);
            release_transport(p, s);
            s->recover_failures++;
            return 0;
        }

        s->recover_failures = 0; /* success resets the budget */
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
    for (int i = 0; i < p->n_paths; i++) {
        if (strcmp(p->paths[i].iface, ifname) == 0) {
            tracked = 1;
            break;
        }
    }
    if (!tracked) return;

    if (!netmon_iface_is_up_and_running(ifname)) return; /* link event owns the drop */
    if (netmon_iface_has_usable_ip(ifname, af) != 0) return;
    netmon_drop_paths_by_ifname(p, ifname, MQVPN_PLATFORM_REASON_ADDR_REMOVED);
}

/* Periodically re-add platform slots whose previous library incarnation is
 * CLOSED or no longer listed (path_readd.h) once their interface is up;
 * slots that still own a socket and read CLOSED are reactivated instead.
 * Fires every RECOVER_INTERVAL_SEC.
 *
 * Spec sec 3.4 "Stateless Platforms" compliance: this handler holds NO
 * lifecycle state — it queries the library via mqvpn_client_get_paths()
 * each tick and acts on the public path list. A slot's recover_failures is pure
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

    for (int i = 0; i < p->n_paths; i++) {
        platform_path_t *s = &p->paths[i];
        if (s->recover_failures >= PATH_RECOVER_FAILURE_LIMIT) continue;
        if (s->fd >= 0) {
            /* CLOSED_RECOVERABLE slots (with a socket) are normally
             * reactivated by one-shot address/link events. A route appearing
             * emits neither, and the route gate may have swallowed the
             * original event — so the timer must also retry reactivate.
             * netmon_try_reactivate_by_ifname re-checks lib state and the
             * lib rejects wrong states with INVALID_STATE, so this is
             * idempotent. */
            for (int j = 0; j < n; j++) {
                if (pinfo[j].handle == s->handle &&
                    pinfo[j].status == MQVPN_PATH_CLOSED) {
                    const char *rifname = s->iface;
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

        /* The event path's re-add decision (path_readd.h): a handle the
         * library no longer lists was recycled for another path and is a
         * candidate too. */
        if (!path_readd_candidate(0, s->recover_failures, PATH_RECOVER_FAILURE_LIMIT,
                                  s->handle, pinfo, n))
            continue;

        const char *ifname = s->iface;
        if (!netmon_iface_is_up_and_running(ifname)) continue;
        if (netmon_iface_has_usable_ip(ifname, p->server_addr.ss_family) != 1) continue;
        if (iface_has_route_to_server(ifname, &p->server_addr) == 0) {
            /* First block + every 10th (≈30s at the 3s poll). The message
             * wording is grepped by scripts/ci_e2e/run_route_gate_test.sh and
             * run_readd_recycled_slot_test.sh. Each needs the first block's
             * line within its 15s / 10s wait and fails without it, so
             * rewording the line, or not logging the first block, fails both
             * e2es. Their GATE_PATTERNs hardcode the "netlink:" prefix, so
             * only the Linux rendering is covered today. */
            if (s->route_gate_blocked++ % 10 == 0)
                LOG_WRN("%s: %s has a usable address but no route to "
                        "the server — re-add deferred until a route appears",
                        netmon_log_tag, ifname);
            continue;
        }
        s->route_gate_blocked = 0;

        /* netmon_try_readd_removed_path scans by ifname, finds this slot
         * through the same decision, and either succeeds (resets the
         * counter) or fails. Only failures after add_path() has returned a
         * handle count toward the limit: a failed activation goes through
         * recovery_rollback (transient bumps the counter, permanent
         * saturates it), and a failed read-event arm bumps it directly.
         * Every earlier exit (the gates, get_paths, socket open, iface pin,
         * transport ctx, add_path() < 0) leaves it untouched, so those never
         * exhaust the budget. Multiple slots sharing one ifname are handled
         * by try_readd's internal loop. */
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
