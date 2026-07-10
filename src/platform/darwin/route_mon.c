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
#  include <stdint.h> /* uint32_t for ROUTE_SA_ROUNDUP, uint8_t for sa_len */
#  include <stddef.h> /* offsetof for the sockaddr_dl name clamp */
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
#  include <net/if_media.h> /* IFM_AVALID / IFM_ACTIVE for the carrier probe */
#  include <net/route.h>
/* struct if_data (embedded by value in if_msghdr) is defined in
 * <net/if_var.h>; net/if.h pulls it in on default configs — kept
 * explicit. The msghdr structs themselves live in net/if.h. */
#  include <net/if_var.h>
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

/* Check whether `ifname`'s link-layer carrier is definitely down.
 *
 * Darwin's if_data has no ifi_link_state field (that is a FreeBSD-ism);
 * SIOCGIFMEDIA is the native carrier signal. IFM_AVALID gates whether
 * IFM_ACTIVE is meaningful — media-less virtual interfaces (utun, ...)
 * and drivers that don't implement media status leave it clear.
 *
 * Returns 1 = carrier definitely down (IFM_AVALID set, IFM_ACTIVE clear),
 * 0 = carrier present, -1 = unknown (ioctl failed or media status not
 * supported). Callers must fail safe: NEVER drop a path on -1 — the same
 * doctrine as iface_has_usable_ip's -1. Per-driver IFM_AVALID/IFM_ACTIVE
 * reporting is unverified on hardware. */
static int
iface_carrier_down(const char *ifname)
{
    /* Darwin deviation: no SOCK_CLOEXEC socket() flag — set FD_CLOEXEC
     * post-hoc via fcntl instead. */
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    fcntl(s, F_SETFD, FD_CLOEXEC);
    struct ifmediareq ifmr;
    memset(&ifmr, 0, sizeof(ifmr));
    snprintf(ifmr.ifm_name, sizeof(ifmr.ifm_name), "%s", ifname);
    int ret = -1;
    if (ioctl(s, SIOCGIFMEDIA, &ifmr) == 0 && (ifmr.ifm_status & IFM_AVALID))
        ret = (ifmr.ifm_status & IFM_ACTIVE) ? 0 : 1;
    close(s);
    return ret;
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
        if (p->path_mgr.paths[i].fd < 0)
            continue; /* CLOSED (dropped) slot: no socket to pin */

        /* Lesson from the Windows port: interface re-enable can renumber the ifindex,
         * and IP_BOUND_IF/IPV6_BOUND_IF pin by index — a stale pin would
         * silently send traffic out the wrong interface on the very fd
         * we're about to hand back to xquic. Re-apply the pin now that the
         * route gate (top of this function) has already passed and this
         * slot is resolved as a genuine reactivate candidate — placing it
         * any earlier would waste a syscall + log on every poll for
         * routeless or ineligible ifaces. If the pin fails, skip reactivate
         * for this slot; the recovery timer / next event will retry. */
        sa_family_t af = (sa_family_t)p->server_addr.ss_family;
        if (darwin_pin_socket_to_iface(p->path_mgr.paths[i].fd, ifname, af) < 0) {
            LOG_WRN("routemon: reactivate %s skipped: iface pin failed", ifname);
            continue;
        }

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
 * if cleanup hasn't completed we get TRANSIENT_FAIL and bail — next route
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

/* ================================================================
 *  Layer A: PF_ROUTE message parsing + reactor (canon netlink_mon.c:473+)
 * ================================================================ */

/* Round the trailing sockaddr length up to the message stride. xnu packs
 * and parses routing-socket sockaddrs with 4-byte ROUNDUP32 (see route(4)
 * consumers: network_cmds route.c, netstat); an 8-byte stride desyncs
 * parsing after any 4-aligned sockaddr length. A sa_len==0 entry advances
 * by the roundup minimum (4), preserving the infinite-loop guard. */
#  define ROUTE_SA_ROUNDUP(a) \
      ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))

/* Defined below with the Layer A parsers; the recovery timer calls it. */
static void route_resync(platform_ctx_t *p);

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

    /* Darwin addition (no Linux counterpart): xnu's routing socket has no overflow
     * notification (see route_resync), so the drop-capable reconcile can
     * only be timer-driven. It runs BEFORE the re-add/reactivate scan
     * below on purpose: drops must land first so the scan re-evaluates
     * the reconciled library state — in the reverse order the scan could
     * reactivate a slot from stale pre-drop state (IFF_RUNNING does not
     * reliably track carrier on Darwin, so the scan's own gates cannot be
     * trusted to catch a carrier loss the resync exists to detect), only
     * for the resync to tear it straight back down. The static counter is
     * throttle-class state (same class as the canon's log debounce), not
     * a lifecycle mirror. */
    static unsigned int resync_tick;
    if (resync_tick++ % RESYNC_EVERY_N_TICKS == 0) route_resync(p);

    mqvpn_path_info_t pinfo[MQVPN_MAX_PATHS];
    int n = 0;
    if (mqvpn_client_get_paths(p->client, pinfo, MQVPN_MAX_PATHS, &n) != MQVPN_OK) {
        /* Darwin addition (no Linux counterpart): the resync above may already have
         * dropped paths (queuing PATH_ABANDON inside xquic) before this
         * bail-out — drive the engine and re-arm the tick exactly as the
         * bottom of this function does, so those frames don't wait for an
         * unrelated timer. The canon's bare goto is safe there only
         * because it has no pre-scan work. */
        mqvpn_client_tick(p->client);
        schedule_next_tick(p);
        goto rearm;
    }

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
            /* First block + every 10th (≈30s at the 3s poll). Body wording
             * kept in sync with the Linux twin for a future Darwin e2e —
             * run_route_gate_test.sh's GATE_PATTERN hardcodes the
             * "netlink:" prefix, so this line is NOT covered by it today. */
            if (p->route_gate_blocked[i]++ % 10 == 0)
                LOG_WRN("routemon: %s has a usable address but no route to "
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
            LOG_INF("routemon: timer re-added path %s after carrier-up failure", ifname);
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

/* ----------------------------------------------------------------
 * BSD routing-socket message parsing. This is the only genuine rewrite
 * in Layer A — netlink's RTA_* attribute walk and PF_ROUTE's sockaddr
 * array are different wire formats, but both existing for the same
 * reason (extensible per-message metadata), so the walker below plays
 * the same role as nlmsg_get_ifname()/nlmsg_get_operstate() in
 * netlink_mon.c:38-67.
 * ---------------------------------------------------------------- */

/* Walk the sockaddr array appended after a routing-socket message header,
 * honoring the addrs bitmask (ifam_addrs / rtm_addrs / ifm_addrs) exactly
 * like route(4) describes: bit i present <=> a sockaddr for RTAX_i follows,
 * in ascending RTAX order. Returns the sockaddr for `want_idx` (e.g.
 * RTAX_IFP, RTAX_IFA) if the bit is set and it fits within [addrs, end),
 * else NULL.
 *
 * `addrs` points at the first byte after the fixed message header; `end`
 * bounds the scan to what actually arrived (rtm_msglen), guarding against
 * walking past a truncated read. A sa_len==0 entry (permitted by the ABI
 * for a masked-but-empty slot) still advances by the roundup minimum, or a
 * pathological/corrupt message could spin this loop forever. */
static const struct sockaddr *
route_msg_get_addr(const char *addrs, const char *end, int addrs_mask, int want_idx)
{
    const char *cp = addrs;
    for (int i = 0; i < RTAX_MAX && cp < end; i++) {
        if (!(addrs_mask & (1 << i))) continue;
        if ((size_t)(end - cp) < 2) break; /* not enough room for sa_len/sa_family */
        const struct sockaddr *sa = (const struct sockaddr *)(const void *)cp;
        size_t step = ROUTE_SA_ROUNDUP((int)sa->sa_len);
        /* A truncated read can leave a declared sa_len reaching past what
         * actually arrived; only hand back a sockaddr whose full declared
         * span is inside the message (fail safe — caller treats NULL like
         * "not present"). */
        if (i == want_idx) return ((size_t)(end - cp) >= (size_t)sa->sa_len) ? sa : NULL;
        cp += step;
    }
    return NULL;
}

/* RTA_IFP convenience wrapper: same walk, cast to sockaddr_dl and checked
 * for AF_LINK (the family carrying an interface name). */
static const struct sockaddr_dl *
route_msg_get_ifp(const char *addrs, const char *end, int addrs_mask)
{
    const struct sockaddr *sa = route_msg_get_addr(addrs, end, addrs_mask, RTAX_IFP);
    if (!sa || sa->sa_family != AF_LINK) return NULL;
    return (const struct sockaddr_dl *)(const void *)sa;
}

/* Resolve an interface name for a routing-socket message: prefer the
 * message's RTA_IFP sockaddr_dl name (works even after the interface has
 * been destroyed, when if_indextoname() would fail), else fall back to
 * if_indextoname() by index. Plays the same role nlmsg_get_ifname() plays
 * for RTM_DELLINK on Linux (netlink_mon.c:38-49) — except Darwin has no
 * RTM_IFANNOUNCE to announce full interface destruction, so there is no
 * single message type where this fallback is guaranteed to matter; every
 * caller below must run it.
 *
 * `ifname_size` is taken explicitly (rather than sizeof(ifname) computed
 * in here) because this is a function, not a macro: a `char *ifname`
 * parameter has decayed from its caller's array, so sizeof(ifname) inside
 * this function would silently measure a pointer, not IFNAMSIZ. Every
 * call site passes sizeof(ifname) from its own local `char ifname[IFNAMSIZ]`
 * array, so the effective bound is identical to inlining the check.
 *
 * Returns 1 on success (ifname filled). Returns 0 if both sources failed —
 * meaning the interface is already fully gone — after running the detach
 * fallback: scan tracked slots and drop any whose iface definitely no
 * longer exists (if_nametoindex fails with ENXIO). */
static int
route_resolve_ifname(platform_ctx_t *p, const struct sockaddr_dl *sdl, unsigned int index,
                     char *ifname, size_t ifname_size)
{
    if (sdl && sdl->sdl_nlen > 0 &&
        sdl->sdl_len >= offsetof(struct sockaddr_dl, sdl_data)) {
        /* Bounded copy only — sdl_data is NOT NUL-terminated, so
         * strcpy/strlen/%s directly on it would read past the interface
         * name into whatever link-layer address bytes follow it. Clamp by
         * BOTH the declared name length and how many bytes the sockaddr's
         * own sdl_len says physically exist after the header. */
        size_t avail = sdl->sdl_len - offsetof(struct sockaddr_dl, sdl_data);
        size_t n = sdl->sdl_nlen;
        if (n > avail) n = avail;
        if (n >= ifname_size) n = ifname_size - 1;
        if (n > 0) {
            memcpy(ifname, sdl->sdl_data, n);
            ifname[n] = '\0';
            return 1;
        }
    }
    if (index != 0 && if_indextoname(index, ifname)) return 1;

    for (int i = 0; i < p->path_mgr.n_paths; i++) {
        const char *tracked_ifname = p->path_mgr.paths[i].iface;
        if (tracked_ifname[0] == '\0') continue;
        /* Only a definite ENXIO ("no such interface") counts as gone:
         * if_nametoindex is getifaddrs-backed on Darwin and can fail for
         * resource reasons (ENOMEM) — such failures are correlated across
         * slots, so treating any 0-return as "gone" could mass-drop every
         * path at once. Unknown fails safe, the same doctrine as the -1
         * returns of iface_has_usable_ip / iface_carrier_down. The exact
         * errno xnu sets for a vanished interface is unverified on
         * hardware. */
        errno = 0;
        if (if_nametoindex(tracked_ifname) == 0 && errno == ENXIO)
            drop_paths_by_ifname(p, tracked_ifname, MQVPN_PLATFORM_REASON_RTM_DELLINK);
    }
    return 0;
}

/* RTM_NEWADDR: an interface gained an IP address.
 * Try re-add first because RTM_DELLINK invalidates the fd; only fall back
 * to reactivate if this slot wasn't fully dropped (fd still valid). */
static void
handle_rtm_newaddr(platform_ctx_t *p, const struct ifa_msghdr *ifam, const char *addrs,
                   const char *addrs_end)
{
    char ifname[IFNAMSIZ];
    const struct sockaddr_dl *sdl = route_msg_get_ifp(addrs, addrs_end, ifam->ifam_addrs);
    if (!route_resolve_ifname(p, sdl, ifam->ifam_index, ifname, sizeof(ifname))) return;

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
handle_rtm_deladdr(platform_ctx_t *p, const struct ifa_msghdr *ifam, const char *addrs,
                   const char *addrs_end)
{
    const struct sockaddr *ifa_sa =
        route_msg_get_addr(addrs, addrs_end, ifam->ifam_addrs, RTAX_IFA);
    if (!ifa_sa) return; /* family unknown, can't apply the filter below: skip */
    if (ifa_sa->sa_family != p->server_addr.ss_family) return;

    char ifname[IFNAMSIZ];
    const struct sockaddr_dl *sdl = route_msg_get_ifp(addrs, addrs_end, ifam->ifam_addrs);
    if (!route_resolve_ifname(p, sdl, ifam->ifam_index, ifname, sizeof(ifname))) return;

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
    if (iface_has_usable_ip(ifname, ifa_sa->sa_family) != 0) return;
    drop_paths_by_ifname(p, ifname, MQVPN_PLATFORM_REASON_ADDR_REMOVED);
}

/* RTM_IFINFO: link state changed (admin flags or carrier). Maps canon's
 * handle_rtm_newlink + handle_rtm_dellink + is_carrier_loss onto Darwin's
 * single link-info message type — PF_ROUTE has no RTM_DELLINK; a fully
 * removed interface is instead caught above in route_resolve_ifname's
 * detach fallback, which returns early before this function's body runs.
 *
 * Darwin has no RFC 2863 operational-state ladder (Linux's IFLA_OPERSTATE
 * with IF_OPER_DORMANT / TESTING / UNKNOWN tiers to tolerate during a wifi
 * association) and its if_data carries no link-state field at all —
 * SIOCGIFMEDIA (IFM_AVALID/IFM_ACTIVE) is the native carrier source, so
 * the carrier branch queries it on-event instead of parsing it from the
 * message. */
static void
handle_rtm_ifinfo(platform_ctx_t *p, const struct if_msghdr *ifm, const char *addrs,
                  const char *addrs_end)
{
    char ifname[IFNAMSIZ];
    const struct sockaddr_dl *sdl = route_msg_get_ifp(addrs, addrs_end, ifm->ifm_addrs);
    if (!route_resolve_ifname(p, sdl, ifm->ifm_index, ifname, sizeof(ifname))) return;

    int admin_down = !(ifm->ifm_flags & IFF_UP);
    if (admin_down) {
        drop_paths_by_ifname(p, ifname, MQVPN_PLATFORM_REASON_ADMIN_DOWN);
        return;
    }
    /* Query-on-event: whether xnu even delivers an RTM_IFINFO on a pure
     * carrier change is unverified on hardware — if it doesn't, the
     * periodic resync in recover_dropped_paths_cb catches the loss within
     * RESYNC_EVERY_N_TICKS ticks. -1 (unknown, e.g. utun) never drops. */
    if (iface_carrier_down(ifname) == 1) {
        drop_paths_by_ifname(p, ifname, MQVPN_PLATFORM_REASON_CARRIER_LOST);
        return;
    }

    if (!(ifm->ifm_flags & IFF_RUNNING)) return;
    if (iface_has_usable_ip(ifname, p->server_addr.ss_family) != 1) return;

    /* First: try to re-add paths removed by RTM_DELLINK (dead fd).
     * Otherwise: reactivate degraded/closed paths (fd still valid). */
    if (try_readd_removed_path(p, ifname)) return;
    try_reactivate_by_ifname(p, ifname);
}

/* Drop-capable periodic resync. xnu's routing socket gives no overflow
 * signal to react to: raw_input() silently discards a broadcast when
 * appending it to a full receive buffer fails (no recv-side ENOBUFS, no
 * SO_RERROR) — so unlike Linux netlink there is no event that tells us a
 * message was missed. This reconcile therefore runs periodically from
 * recover_dropped_paths_cb (every RESYNC_EVERY_N_TICKS ticks) rather than
 * on an overflow notification.
 *
 * For each tracked slot, evaluate iface-gone / admin-down / carrier-down /
 * usable-IP-lost and drop through the same drop_paths_by_ifname() path the
 * one-shot handlers above use. Re-add is intentionally NOT duplicated
 * here — the timer body's re-add/reactivate scan runs right after this in
 * the same callback, over the state this reconcile just settled.
 *
 * getifaddrs() returns one entry per interface×family (v4, v6, link) —
 * naive per-record judgment would evaluate admin state once per family
 * and could double-drop; this evaluates each tracked slot exactly once
 * with fixed per-predicate sources: presence = any entry with the slot's
 * name exists in this snapshot (definite — no separate resolver call, so
 * no correlated-failure mode); admin = the AF_LINK entry's ifa_flags;
 * carrier = SIOCGIFMEDIA via iface_carrier_down (its -1 never drops);
 * address = iface_has_usable_ip (its -1 never drops either). */
static void
route_resync(platform_ctx_t *p)
{
    struct ifaddrs *ifa_list = NULL;
    if (getifaddrs(&ifa_list) < 0) {
        /* Fail safe (skip entirely), but visibly: the drop backstop did
         * not run this round; the next resync tick covers it. */
        LOG_WRN("routemon: resync skipped: getifaddrs: %s", strerror(errno));
        return;
    }

    for (int i = 0; i < p->path_mgr.n_paths; i++) {
        const char *ifname = p->path_mgr.paths[i].iface;
        if (ifname[0] == '\0') continue;

        /* Presence + admin state from the one snapshot. */
        int present = 0;
        int admin_down = 0;
        for (struct ifaddrs *ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
            if (strcmp(ifa->ifa_name, ifname) != 0) continue;
            present = 1;
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_LINK) {
                admin_down = !(ifa->ifa_flags & IFF_UP);
                break; /* one AF_LINK entry per interface */
            }
        }
        if (!present) {
            drop_paths_by_ifname(p, ifname, MQVPN_PLATFORM_REASON_RTM_DELLINK);
            continue;
        }
        if (admin_down) {
            drop_paths_by_ifname(p, ifname, MQVPN_PLATFORM_REASON_ADMIN_DOWN);
            continue;
        }
        if (iface_carrier_down(ifname) == 1) {
            drop_paths_by_ifname(p, ifname, MQVPN_PLATFORM_REASON_CARRIER_LOST);
            continue;
        }
        if (iface_has_usable_ip(ifname, p->server_addr.ss_family) == 0)
            drop_paths_by_ifname(p, ifname, MQVPN_PLATFORM_REASON_ADDR_REMOVED);
    }

    freeifaddrs(ifa_list);
}

static void
on_route_event(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    platform_ctx_t *p = (platform_ctx_t *)arg;
    union {
        struct rt_msghdr rtm;
        char raw[ROUTE_BUF_SIZE];
    } rbuf;

    for (;;) {
        ssize_t len = recv(fd, rbuf.raw, sizeof(rbuf.raw), MSG_DONTWAIT);
        if (len < 0 && errno == EINTR) continue;
        if (len <= 0) {
            if (len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                break; /* drained — the normal exit */
            if (len < 0 && errno == ENOBUFS) {
                /* Belt-and-braces: xnu is not known to ever deliver
                 * recv-side ENOBUFS on a routing socket (raw_input drops
                 * silently on receive-buffer overflow — the reason the
                 * resync is timer-driven from recover_dropped_paths_cb,
                 * and the reason the RTM_GET probe below bounds its read
                 * with SO_RCVTIMEO instead of trusting an error). Kept in
                 * case that ever changes: it costs nothing and would
                 * tighten resync latency from ~15s to the event. */
                LOG_WRN("routemon: ENOBUFS on route socket, running full resync");
                route_resync(p);
                break;
            }
            /* EOF (len==0) or an unexpected errno: neither should happen
             * on a PF_ROUTE socket. Debounced so a persistently broken
             * socket doesn't flood the log from EV_PERSIST re-fires. */
            static unsigned int recv_err_throttle;
            if (recv_err_throttle++ % 10 == 0)
                LOG_WRN("routemon: route socket recv failed: %s (len=%zd)",
                        len < 0 ? strerror(errno) : "EOF", len);
            break;
        }

        const char *cp = rbuf.raw;
        const char *end = rbuf.raw + len;
        while (cp < end) {
            if ((size_t)(end - cp) < sizeof(struct rt_msghdr)) break; /* truncated tail */
            const struct rt_msghdr *rtm = (const struct rt_msghdr *)(const void *)cp;
            if (rtm->rtm_msglen == 0) break;       /* guard against an infinite loop */
            if (cp + rtm->rtm_msglen > end) break; /* truncated tail */
            if (rtm->rtm_version != RTM_VERSION) {
                cp += rtm->rtm_msglen;
                continue;
            }

            switch (rtm->rtm_type) {
            case RTM_NEWADDR:
            case RTM_DELADDR: {
                if (rtm->rtm_msglen < sizeof(struct ifa_msghdr)) break; /* short: skip */
                const struct ifa_msghdr *ifam =
                    (const struct ifa_msghdr *)(const void *)cp;
                LOG_DBG("routemon: RTM type=%d index=%u", rtm->rtm_type,
                        (unsigned)ifam->ifam_index);
                if (rtm->rtm_type == RTM_NEWADDR)
                    handle_rtm_newaddr(p, ifam, cp + sizeof(*ifam), cp + rtm->rtm_msglen);
                else
                    handle_rtm_deladdr(p, ifam, cp + sizeof(*ifam), cp + rtm->rtm_msglen);
                break;
            }
            case RTM_IFINFO: {
                if (rtm->rtm_msglen < sizeof(struct if_msghdr)) break; /* short: skip */
                const struct if_msghdr *ifm = (const struct if_msghdr *)(const void *)cp;
                LOG_DBG("routemon: RTM type=%d index=%u", rtm->rtm_type,
                        (unsigned)ifm->ifm_index);
                handle_rtm_ifinfo(p, ifm, cp + sizeof(*ifm), cp + rtm->rtm_msglen);
                break;
            }
            default: break;
            }
            cp += rtm->rtm_msglen;
        }
    }

    /* Route handlers may have created/dropped paths (queuing frames such
     * as PATH_CHALLENGE inside xquic) — drive the engine and re-arm the
     * tick from the engine's new wakeup request, exactly as on_socket_read
     * does. Without this the queued frames wait for an unrelated timer. */
    mqvpn_client_tick(p->client);
    schedule_next_tick(p);
}

int
setup_route_socket(platform_ctx_t *p)
{
    p->rt_fd = socket(PF_ROUTE, SOCK_RAW, 0);
    if (p->rt_fd < 0) {
        LOG_WRN("routemon: socket failed: %s (path recovery via timer only)",
                strerror(errno));
        return -1;
    }
    fcntl(p->rt_fd, F_SETFD, FD_CLOEXEC);

    /* Raise the receive buffer as the first line of overflow mitigation —
     * this reduces but does not eliminate message loss under a
     * carrier-flap storm (xnu drops silently on a full buffer, with no
     * signal to the reader); the periodic resync driven by
     * recover_dropped_paths_cb is the correctness backstop for whatever
     * this doesn't catch. */
    int bufsize = 256 * 1024;
    if (setsockopt(p->rt_fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize)) < 0)
        LOG_WRN("routemon: SO_RCVBUF failed: %s (overflow mitigation weakened)",
                strerror(errno));

    if (mqvpn_socket_set_nonblock(p->rt_fd) < 0) {
        LOG_WRN("routemon: fcntl failed: %s (path recovery via timer only)",
                strerror(errno));
        close(p->rt_fd);
        p->rt_fd = -1;
        return -1;
    }

    /* No group subscribe/bind: PF_ROUTE delivers every RTM_* to every
     * reader on the socket (unlike netlink's multicast groups), so there
     * is nothing to opt into here. */
    p->ev_route = event_new(p->eb, p->rt_fd, EV_READ | EV_PERSIST, on_route_event, p);
    if (!p->ev_route) {
        LOG_WRN("routemon: event_new failed (OOM?)");
        close(p->rt_fd);
        p->rt_fd = -1;
        return -1;
    }
    event_add(p->ev_route, NULL);
    LOG_INF("routemon: path recovery accelerator active");
    return 0;
}

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
/* One scoped RTM_GET probe: is there a route to `dst` scoped to `ifindex`?
 * Returns 1 = route exists, 0 = definitely no route via this iface, -1 =
 * query mechanism failed (fail open). Factored out of
 * iface_has_route_to_server() so that function can issue a second
 * (default-route) probe — see the fallback rationale there.
 *
 * want_default: when non-zero, append an all-zero RTA_NETMASK so the kernel
 * does a NETWORK-route lookup (matching a /0 default route) instead of a HOST
 * lookup for `dst`. A HOST lookup of 0.0.0.0 matches no route ("not in
 * table") even when a scoped default route exists; `route -nv get -ifscope
 * <if> default` emits exactly this DST+NETMASK pair (sockaddrs <DST,NETMASK,
 * IFP>), whereas a host get emits DST only (<DST,IFP>, RTF_HOST). */
static int
darwin_scoped_route_probe(unsigned int ifindex, const struct sockaddr_storage *dst,
                          int want_default)
{
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

    socklen_t salen = (dst->ss_family == AF_INET6) ? sizeof(struct sockaddr_in6)
                                                   : sizeof(struct sockaddr_in);
    memcpy(req.space, dst, salen);
    /* The resolver's literal-IP fast paths may leave ss_len zero; the
     * routing socket walks appended sockaddrs by sa_len, so set it. */
    ((struct sockaddr *)(void *)req.space)->sa_len = (uint8_t)salen;

    /* Unsigned so wraparound is defined. Non-atomic: assumes the platform
     * run loop is single-threaded per process (multiple client instances
     * in one process would need atomics here). */
    static unsigned int seq_counter = 0;
    int seq = (int)++seq_counter;
    pid_t pid = getpid();

    size_t msglen = sizeof(struct rt_msghdr) + ROUTE_SA_ROUNDUP((int)salen);
    int addrs = RTA_DST;
    if (want_default) {
        /* Append an all-zero netmask sockaddr (mask 0.0.0.0 == default) right
         * after the (rounded-up) DST, and set RTA_NETMASK so the kernel does a
         * network-route lookup that resolves through the scoped default route.
         * addr bytes are already zero from the memset above. */
        struct sockaddr *nm =
            (struct sockaddr *)(void *)(req.space + ROUTE_SA_ROUNDUP((int)salen));
        nm->sa_len = (uint8_t)salen;
        nm->sa_family = dst->ss_family;
        addrs |= RTA_NETMASK;
        msglen += ROUTE_SA_ROUNDUP((int)salen);
    }

    req.rtm.rtm_msglen = (u_short)msglen;
    req.rtm.rtm_version = RTM_VERSION;
    req.rtm.rtm_type = RTM_GET;
    req.rtm.rtm_addrs = addrs;
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

/* Public gate for the path re-add / reactivate paths (callers at the top of
 * try_reactivate_by_ifname / try_readd_removed_path). Returns 1 = this iface
 * can reach the server, 0 = definitely not, -1 = probe failed (callers treat
 * -1 as PASS / fail open). */
int
iface_has_route_to_server(const char *ifname, const struct sockaddr_storage *server)
{
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) return 0; /* iface gone: definitely unusable */

    int r = darwin_scoped_route_probe(ifindex, server, 0);
    if (r != 0) return r; /* 1 = route to server exists; -1 = probe failed (fail open) */

    /* No interface-scoped route to the SPECIFIC server. On real multi-
     * default-route macOS (e.g. Wi-Fi en0 + USB tether en5, each with its
     * own default gateway), mqvpn pins the server /32 to a SINGLE primary
     * gateway for split-tunnelling, so a scoped RTM_GET for the server via
     * any OTHER interface answers ESRCH ("not in table") even when that
     * interface has perfectly good upstream. But a multipath path socket is
     * IP_BOUND_IF-pinned to its interface: its egress follows THAT
     * interface's own default gateway, not the global server-route pin. So
     * fall back to asking whether this interface has its own upstream — a
     * scoped DEFAULT route. If it does, the bound socket can reach a public
     * server through it and the recovered path MUST be re-addable (the HARD
     * failover-reactivate requirement); if the interface has an address but
     * no default route of its own, both probes return 0 and the path stays
     * deferred exactly as before, preserving the "usable address but no
     * route to the server" behaviour. Hardware-verified on macOS 26 (Wi-Fi +
     * USB tether): scoped server probe via the tether → ESRCH, scoped
     * default via the tether → its own gateway, so the recovered path
     * re-adds instead of being trapped closed. */
    struct sockaddr_storage any;
    memset(&any, 0, sizeof(any));
    any.ss_family = server->ss_family;
    return (darwin_scoped_route_probe(ifindex, &any, 1) == 1) ? 1 : 0;
}

#endif /* __APPLE__ */
