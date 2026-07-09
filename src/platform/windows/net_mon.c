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
 * This file contains the Layer B teardown/rollback primitives (drop /
 * recovery-socket create / register / rollback, sibling-cloned from
 * netlink_mon.c), the three Layer C probe primitives
 * (iface_is_up_and_running / iface_has_usable_ip /
 * iface_has_route_to_server), and the poll reconciler (reconcile_all +
 * the recover_dropped_paths_cb timer wrapper net_mon.h declares) that
 * drives them. The function layout intentionally mirrors the Linux canon
 * netlink_mon.c order so the two files stay byte-diff auditable against
 * each other. Layer A — the event source (netlink on Linux; IP Helper
 * change notifications in a later phase here) — is absent in this phase,
 * which is why section labels start at B.
 *
 * One deliberate structural deviation from canon: reconcile_all()'s
 * per-slot loop runs a Windows-only poll-driven drop check BEFORE the
 * failure-limit gate. On Linux, drops arrive asynchronously via netlink,
 * so the gate (recovery backpressure only) never interacts with drop
 * decisions. On Windows the poll IS the drop source, so a
 * recovery-exhausted slot on a live-dead adapter must still be droppable
 * or it black-holes traffic — see the comment at that call site.
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
 *  Layer B — path drop/teardown (sibling of Linux netlink_mon.c)
 * ================================================================ */

/* Log wording per reason. Kept in sync with the Linux sibling's wording
 * ("interface <if> <reason>, closing path") for cross-platform log
 * consistency; not currently enforced by any Windows e2e grep. */
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

/* Remove a path because the platform says it's no longer usable.
 * Four callers: adapter gone (RTM_DELLINK analog); operational-state down
 * (carrier lost — cable unplugged etc); admin down (adapter disabled); and
 * no usable source address left (RTM_DELADDR analog). All share cleanup;
 * the reason is logged and reported in the public event.
 *
 * Cleans up: library path, libevent, fd. Preserves iface name for re-add. */
static void
remove_path_by_index(platform_win_ctx_t *p, int idx, mqvpn_platform_reason_t reason)
{
    if (p->path_mgr.paths[idx].fd < 0) return; /* already removed */

    LOG_WRN("netmon: interface %s %s, closing path %d", p->path_mgr.paths[idx].iface,
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
    mqvpn_socket_close(p->path_mgr.paths[idx].fd);
    p->path_mgr.paths[idx].fd = -1;
    p->path_mgr.paths[idx].platform_attached = 0;
    mqvpn_client_on_platform_fd_closed(p->client, p->lib_path_handles[idx]);
}

/* Drop every tracked path on `ifname`. Shared by the drop-decision branches
 * of the reconciler so slot matching stays in one place. Returns the number
 * of paths matched (dropped or already gone). */
static int
drop_paths_by_ifname(platform_win_ctx_t *p, const char *ifname,
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
 *        NO_ERROR with a non-up OperStatus other than Unknown. This is
 *        the RTM_DELLINK analog — dropping on this result is correct.
 *  -1  — any other API error, or OperStatus == IfOperStatusUnknown
 *        (ambiguous — Linux canon keeps IFF_RUNNING set for operstate
 *        UNKNOWN, so Unknown must not confirm a drop). Caller must NOT
 *        drop on -1 (fail-safe, same fail-open discipline as the Linux
 *        probes). */
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

    /* IfOperStatusUnknown is ambiguous, not a confirmed down: Linux canon
     * treats operstate UNKNOWN as running (IFF_RUNNING stays set), so
     * confirming a drop on Unknown would diverge in the dangerous direction. */
    if (row.OperStatus == IfOperStatusUnknown) return -1;
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
    if (err == ERROR_NO_DATA) {
        /* Confirmed: no addresses of this family anywhere on the system,
         * so the target adapter has none either — definite "no usable IP". */
        free(addrs);
        return 0;
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
    /* ERROR_NOT_FOUND is empirically GetBestRoute2's "no matching route"
     * result; mapping it to 0 is fail-safe — the gate just defers recovery
     * to a later poll once a route is confirmed. */
    if (err == ERROR_NETWORK_UNREACHABLE || err == ERROR_HOST_UNREACHABLE ||
        err == ERROR_FILE_NOT_FOUND || err == ERROR_NOT_FOUND)
        return 0;
    return -1;
}

static void
try_reactivate_by_ifname(platform_win_ctx_t *p, const char *ifname)
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

        /* WINDOWS-ONLY: IP_UNICAST_IF bakes the ifindex into the socket at
         * pin time, and that binding goes stale when the adapter is
         * disabled/re-enabled (or the index is otherwise reassigned) — the
         * old pin would silently send into a void. Re-apply the pin to the
         * existing fd now that the route gate above confirms the interface
         * is reachable again; must sit AFTER the route gate, or every 3s
         * poll would waste a syscall + log line while the route is still
         * absent. Skip reactivate for this slot if the re-pin fails: a
         * reactivate on a stale binding would defeat the fix. */
        if (win_pin_socket_to_iface(p->path_mgr.paths[i].fd, ifname,
                                    p->server_addr.ss_family) < 0) {
            LOG_WRN("netmon: re-pin %s before reactivate failed, skipping", ifname);
            continue;
        }

        int ret = mqvpn_client_reactivate_path(p->client, h);
        if (ret == MQVPN_OK) {
            LOG_INF("netmon: reactivated path %s", ifname);
        } else if (ret == MQVPN_ERR_INVALID_STATE) {
            /* slot not in 3-state acceptance window (e.g. already VALIDATING) */
        } else {
            LOG_WRN("netmon: reactivate %s failed: %s", ifname, mqvpn_error_string(ret));
        }
    }
}

/* ================================================================
 *  Layer B — recovery socket create / register / rollback
 *  (sibling of Linux netlink_mon.c)
 * ================================================================ */

/* Create a UDP socket bound to the wildcard address and pinned to ifname.
 * Updates mp->local_addr / mp->local_addrlen on success.
 * Returns the new fd, or -1 (already logged). */
static int
recovery_socket_create(ADDRESS_FAMILY af, const char *ifname, mqvpn_path_t *mp)
{
    int fd = (int)socket(af, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOG_WRN("netmon: socket() for re-add %s: %s", ifname, mqvpn_socket_strerror());
        return -1;
    }
    if (mqvpn_socket_set_nonblock(fd) < 0) {
        LOG_WRN("netmon: set_nonblock() for re-add %s: %s", ifname,
                mqvpn_socket_strerror());
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
        LOG_WRN("netmon: bind() for re-add %s: %s", ifname, mqvpn_socket_strerror());
        goto fail;
    }

    /* Pin AFTER bind, matching startup-loop order. */
    if (win_pin_socket_to_iface(fd, ifname, af) < 0) {
        LOG_WRN("netmon: iface pin for re-add %s failed", ifname);
        goto fail;
    }

    return fd;
fail:
    mqvpn_socket_close(fd);
    return -1;
}

/* Register a freshly-created socket with the library and capture the
 * synchronous activation outcome via the with_outcome API. Returns the
 * new handle and writes *outcome (MQVPN_ADD_PATH_OK / TRANSIENT / PERMANENT);
 * returns -1 on handle-allocation failure (already logged). */
static mqvpn_path_handle_t
recovery_register_with_lib(platform_win_ctx_t *p, int slot, int fd, const char *ifname,
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
        LOG_WRN("netmon: add_path_fd() for re-add %s failed", ifname);
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
recovery_rollback(platform_win_ctx_t *p, int slot, mqvpn_add_path_outcome_t outcome)
{
    mqvpn_path_t *mp = &p->path_mgr.paths[slot];
    const char *ifname = mp->iface;

    mqvpn_client_remove_path(p->client, p->lib_path_handles[slot]);
    mqvpn_socket_close(mp->fd);
    mp->fd = -1;
    mp->platform_attached = 0;

    if (outcome == MQVPN_ADD_PATH_PERMANENT_FAIL) {
        /* Saturate the per-slot counter — recover_dropped_paths_cb will
         * skip this slot until a fresh Level-2 reconnect resets the limit. */
        p->path_recover_failures[slot] = PATH_RECOVER_FAILURE_LIMIT;
        LOG_WRN("netmon: path %s recovery abandoned (xquic budget exhausted; "
                "reconnect required)",
                ifname);
        return;
    }

    /* Transient failure (most commonly -XQC_EMP_NO_AVAIL_PATH_ID during
     * WiFi reassoc CID-lag burst). Bump the consecutive-failure counter so
     * the 3s recovery timer eventually gives up and waits for reconnect. */
    p->path_recover_failures[slot]++;
    if (p->path_recover_failures[slot] >= PATH_RECOVER_FAILURE_LIMIT) {
        LOG_WRN("netmon: path %s recovery abandoned after %d consecutive "
                "failures (will resume on reconnect)",
                ifname, PATH_RECOVER_FAILURE_LIMIT);
    } else {
        LOG_WRN("netmon: re-add %s not activated, will retry (%d/%d)", ifname,
                p->path_recover_failures[slot], PATH_RECOVER_FAILURE_LIMIT);
    }
}

/* PR5: replace path_removed_by_platform[] polling with lib state query.
 * The slot is considered "ready for re-add" if its public status is
 * MQVPN_PATH_CLOSED — i.e., lib has fully cleaned up the previous incarnation
 * (CLOSED_FREE) OR is mid-cleanup (CLOSED_DROPPED with all xquic-side fields
 * drained). add_path_fd_with_outcome will refuse to reuse a non-CLOSED slot;
 * if cleanup hasn't completed we get TRANSIENT_FAIL and bail — next netlink
 * event will retry.
 *
 * try_reactivate_by_ifname / try_readd_removed_path are orchestration
 * (consumers of the Layer C probes above), not probes themselves — kept in
 * the Layer B section since they share Layer B's teardown/rollback
 * primitives, not because they belong to Layer C.
 *
 * Canon (Linux) call graph: this function is invoked from
 * handle_rtm_newlink / handle_rtm_newaddr / recover_dropped_paths_cb. None
 * of those event handlers exist on Windows in this phase — the only caller
 * here is reconcile_all()'s re-add branch below. */
static int
try_readd_removed_path(platform_win_ctx_t *p, const char *ifname)
{
    /* Never re-add on a down/no-carrier link, or while the interface lacks
     * a usable source address of the server's family (see
     * iface_has_usable_ip). RTM_NEWADDR for the right family, or the
     * recovery timer, will retry once both hold.
     *
     * Note: reconcile_all() already checks both conditions before calling
     * in here for the timer-driven path — that's intentionally redundant,
     * this function stays self-contained so a future Phase 2 event-driven
     * caller can invoke it directly without re-deriving the gate. */
    if (iface_is_up_and_running(ifname) != 1)
        return 0; /* tri-state: 0 and -1 both not-up-for-recovery */
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
            mqvpn_socket_close(fd);
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
        LOG_INF("netmon: path %s re-added (handle=%lld)", ifname, (long long)new_h);
        return 1;
    }
    return 0;
}

/* ================================================================
 *  Reconciler — poll body (sibling of Linux netlink_mon.c's
 *  recover_dropped_paths_cb steps 1-3)
 * ================================================================ */

/* Drop dead paths and re-add/reactivate recovered ones. Extracted from the
 * timer callback so a later Phase 2 IP Helper change-notification event
 * source can call this directly without touching the poll cadence — the
 * timer re-arm stays in recover_dropped_paths_cb(), NOT here.
 *
 * Spec sec 3.4 "Stateless Platforms" compliance: this holds NO lifecycle
 * state of its own — it queries the library via mqvpn_client_get_paths()
 * each call and acts on the public MQVPN_PATH_* status. path_recover_failures[]
 * is pure backpressure to bound the busy-loop on transient xquic errors
 * during a WiFi reassoc CID-lag burst — not a state mirror. */
static void
reconcile_all(platform_win_ctx_t *p)
{
    mqvpn_path_info_t pinfo[MQVPN_MAX_PATHS];
    int n = 0;
    if (mqvpn_client_get_paths(p->client, pinfo, MQVPN_MAX_PATHS, &n) != MQVPN_OK) return;

    for (int i = 0; i < p->path_mgr.n_paths; i++) {
        /* WINDOWS-ONLY: poll-driven drop (Linux does this via netlink), placed
         * BEFORE the failure-limit gate — a recovery-exhausted live-dead adapter
         * must still be droppable or it black-holes traffic. */
        if (p->path_mgr.paths[i].platform_attached) {
            mqvpn_path_handle_t ah = p->lib_path_handles[i];
            int lib_alive = 0;
            for (int j = 0; j < n; j++) {
                if (pinfo[j].handle == ah) {
                    lib_alive = (pinfo[j].status != MQVPN_PATH_CLOSED);
                    break;
                }
            }
            if (lib_alive) {
                const char *ifn = p->path_mgr.paths[i].iface;
                int up = iface_is_up_and_running(ifn); /* tri-state */
                int ip =
                    iface_has_usable_ip(ifn, p->server_addr.ss_family); /* tri-state */
                if (up == 0 || ip == 0) { /* -1 (probe failure) => do NOT drop */
                    /* reason is log-only, so the exact down-reason is cosmetic.
                     * up==0 conflates gone/operstate-down/admin-down; use
                     * CARRIER_LOST. ip==0 => ADDR_REMOVED. */
                    drop_paths_by_ifname(p, ifn,
                                         up == 0 ? MQVPN_PLATFORM_REASON_CARRIER_LOST
                                                 : MQVPN_PLATFORM_REASON_ADDR_REMOVED);
                    continue;
                }
            }
        }

        /* recovery backpressure gate — reactivate/re-add ONLY */
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
                    if (iface_is_up_and_running(rifname) ==
                            1 && /* tri-state: only ==1 counts as up */
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
        if (iface_is_up_and_running(ifname) != 1)
            continue; /* tri-state: 0 and -1 both not-up-for-recovery */
        if (iface_has_usable_ip(ifname, p->server_addr.ss_family) != 1) continue;
        if (iface_has_route_to_server(ifname, &p->server_addr) == 0) {
            /* First block + every 10th (≈30s at the 3s poll). Unlike the
             * canon "netlink:"-prefixed line, this "netmon:" line is not
             * currently grepped by scripts/ci_e2e/run_route_gate_test.sh
             * (that e2e is Linux-only) — no e2e marker constraint here yet. */
            if (p->route_gate_blocked[i]++ % 10 == 0)
                LOG_WRN("netmon: %s has a usable address but no route to "
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
            LOG_INF("netmon: timer re-added path %s after carrier-up failure", ifname);
    }

    /* The re-add above may have created a path (queuing a PATH_CHALLENGE
     * inside xquic) — drive the engine and re-arm the tick from the
     * engine's new wakeup request, exactly as on_socket_read does.
     * Without this the queued frames wait for an unrelated timer. */
    mqvpn_client_tick(p->client);
    schedule_next_tick(p);
}

/* 3s poll timer callback: reconcile, then re-arm. The re-arm stays here
 * (not in reconcile_all) so a future Phase 2 event-driven call to
 * reconcile_all doesn't perturb the poll cadence. */
void
recover_dropped_paths_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    platform_win_ctx_t *p = (platform_win_ctx_t *)arg;

    reconcile_all(p);

    if (p->ev_recover) {
        struct timeval tv = {.tv_sec = RECOVER_INTERVAL_SEC};
        event_add(p->ev_recover, &tv);
    }
}

#endif /* _WIN32 */
