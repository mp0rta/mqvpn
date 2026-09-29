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
 * re-add socket open / register / rollback, and the release tail
 * release_transport / fatal_stop, sibling-cloned from the
 * POSIX canon — formerly netlink_mon.c, now shared as
 * src/platform/posix/netmon_common.c), the three Layer C probe primitives
 * (iface_is_up_and_running / iface_has_usable_ip /
 * iface_has_route_to_server), and the poll reconciler (reconcile_all +
 * the recover_dropped_paths_cb timer wrapper net_mon.h declares) that
 * drives them. The function layout intentionally mirrors the POSIX canon
 * netmon_common.c order so the two stay byte-diff auditable against
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
#  include "platform/path_readd.h"
#  include "log.h"

#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <iphlpapi.h>
#  include <netioapi.h>
#  include <string.h>
#  include <stdlib.h>

/* ================================================================
 *  Layer B — path drop/teardown (sibling of the POSIX netmon_common.c)
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

/* A release the library refuses right after this platform's own drop or
 * remove of that path cannot happen: drop and remove move every other
 * lifecycle state to CLOSED_DROPPED/FREE, and nothing runs in between. If it
 * ever does, the library still holds a transport whose socket is already
 * closed — a send would fail, or go out through whatever socket reused the
 * handle value — so the process stops instead of running on (exit 1). The
 * ctx the library still owns is finalised by client_destroy on the way out.
 * Sibling of the POSIX netmon_common.c fatal_stop. */
static void
fatal_stop(platform_win_ctx_t *p)
{
    p->fatal_error = PLATFORM_FATAL_PATH_RELEASE;
    p->shutting_down = 1;
    mqvpn_client_disconnect(p->client);
    /* disconnect() fires no CLOSED transition from IDLE or CLOSED, and that
     * transition is what normally breaks the loop — break it here. */
    event_base_loopbreak(p->eb);
}

/* Give a library-owned transport back: close the slot's socket, then report
 * the release so the library finalises the ctx (the CLOSED_DROPPED ->
 * CLOSED_FREE cleanup completes once the xquic side also clears). Windows
 * keeps no receive telemetry, so there is nothing to harvest first (the
 * POSIX sibling reads the bind's RX counters here). The one place a drop or
 * rollback hands a transport back. */
static void
release_transport(platform_win_ctx_t *p, platform_path_t *s)
{
    platform_path_close_socket(s);
    int rc = mqvpn_client_on_platform_path_released(p->client, s->handle);
    if (rc == MQVPN_OK) {
        s->bind_ctx = NULL; /* finalised by the library */
        return;
    }
    LOG_ERR("netmon: path_released for %s returned %s; transport stays "
            "library-owned",
            s->iface, mqvpn_error_string(rc));
    fatal_stop(p);
}

/* Remove a path because the platform says it's no longer usable.
 * Four callers: adapter gone (RTM_DELLINK analog); operational-state down
 * (carrier lost — cable unplugged etc); admin down (adapter disabled); and
 * no usable source address left (RTM_DELADDR analog). All share cleanup;
 * the reason is logged and reported in the public event.
 *
 * Cleans up: library path, libevent, socket. Preserves iface name for re-add. */
static void
remove_path_by_slot(platform_win_ctx_t *p, platform_path_t *s,
                    mqvpn_platform_reason_t reason)
{
    if (s->sock == INVALID_SOCKET) return; /* already removed */

    LOG_WRN("netmon: interface %s %s, closing path %d", s->iface, drop_reason_str(reason),
            platform_path_index(s));

    /* PR5: emit PLATFORM_DROP via new public API with diagnostic info.
     * Library transitions slot to CLOSED_DROPPED; the transport release is
     * reported by release_transport() below. */
    mqvpn_platform_path_event_info_t info = {0};
    snprintf(info.iface, sizeof(info.iface), "%s", s->iface);
    info.reason = reason;
    mqvpn_client_on_platform_path_dropped(p->client, s->handle, &info);

    release_transport(p, s);
}

/* Drop every tracked path on `ifname`. Shared by the drop-decision branches
 * of the reconciler so slot matching stays in one place. Returns the number
 * of paths matched (dropped or already gone). */
static int
drop_paths_by_ifname(platform_win_ctx_t *p, const char *ifname,
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
 * Windows analog of the POSIX getifaddrs() version (netmon_common.c);
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
 * server_addr) contract in the POSIX monitors).
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
        if (s->sock == INVALID_SOCKET) continue;
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

        /* WINDOWS-ONLY: IP_UNICAST_IF bakes the ifindex into the socket at
         * pin time, and that binding goes stale when the adapter is
         * disabled/re-enabled (or the index is otherwise reassigned) — the
         * old pin would silently send into a void. Re-apply the pin to the
         * existing fd now that the route gate above confirms the interface
         * is reachable again; must sit AFTER the route gate, or every 3s
         * poll would waste a syscall + log line while the route is still
         * absent. Skip reactivate for this slot if the re-pin fails: a
         * reactivate on a stale binding would defeat the fix. */
        if (win_pin_socket_to_iface(s->sock, ifname, p->server_addr.ss_family) < 0) {
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
 *  (sibling of the POSIX netmon_common.c)
 * ================================================================ */

/* Open the slot's replacement socket, commit it to the slot, and pin it to
 * ifname (pin AFTER bind, matching startup order). Socket buffers are set by
 * the transport ctx (7 MiB). 0, or -1 (already logged; a committed socket is
 * closed again). */
static int
readd_open_socket(platform_win_ctx_t *p, platform_path_t *s, const char *ifname)
{
    ADDRESS_FAMILY af = p->server_addr.ss_family;
    int step = 0;
    SOCKET sock = platform_path_socket_open(af, &step);
    if (sock == INVALID_SOCKET) {
        if (step == PLATFORM_PATH_STEP_SOCKET)
            LOG_WRN("netmon: socket() for re-add %s: %s", ifname,
                    mqvpn_socket_strerror());
        else if (step == PLATFORM_PATH_STEP_NONBLOCK)
            LOG_WRN("netmon: set_nonblock() for re-add %s: %s", ifname,
                    mqvpn_socket_strerror());
        else
            LOG_WRN("netmon: bind() for re-add %s: %s", ifname, mqvpn_socket_strerror());
        return -1;
    }
    s->sock = sock; /* committed: from here only platform_path_close_socket() closes it */

    if (win_pin_socket_to_iface(sock, ifname, af) < 0) {
        LOG_WRN("netmon: iface pin for re-add %s failed", ifname);
        platform_path_close_socket(s);
        return -1;
    }
    return 0;
}

/* Build the transport ctx for a freshly created re-add socket — the same
 * Winsock bind the startup loop builds (platform_windows.c). Returns the
 * ctx, or NULL on failure (already logged). The ctx is caller-owned until
 * add_path succeeds. Sibling of the POSIX netmon_platform_transport_create. */
static void *
recovery_transport_create(SOCKET sock, const char *ifname)
{
    mqvpn_bind_winsock_opts_t bopts = {0};
    bopts.struct_size = sizeof(bopts);
    bopts.socket_buf_bytes = 0;
    snprintf(bopts.tag, sizeof(bopts.tag), "%s", ifname);
    void *ctx = NULL;
    if (mqvpn_bind_winsock_path_new(sock, &bopts, &ctx) != MQVPN_OK) {
        LOG_WRN("netmon: transport setup for re-add %s failed", ifname);
        return NULL;
    }
    return ctx;
}

/* Register a freshly-created transport ctx with the library and capture the
 * synchronous activation outcome. Returns the new handle and writes *outcome
 * (MQVPN_ADD_PATH_OK / TRANSIENT / PERMANENT); returns -1 on
 * handle-allocation failure (already logged), in which case the ctx stays
 * caller-owned and the slot keeps its previous handle. */
static mqvpn_path_handle_t
recovery_register_with_lib(platform_win_ctx_t *p, platform_path_t *s, void *tctx,
                           const char *ifname, mqvpn_add_path_outcome_t *outcome)
{
    mqvpn_path_desc_t desc;
    platform_path_fill_desc(p, s, &desc);

    mqvpn_path_handle_t handle = mqvpn_client_add_path(
        p->client, &desc, mqvpn_bind_winsock_path_ops(), tctx, outcome);
    if (handle < 0) {
        LOG_WRN("netmon: add_path() for re-add %s failed", ifname);
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
recovery_rollback(platform_win_ctx_t *p, platform_path_t *s,
                  mqvpn_add_path_outcome_t outcome)
{
    const char *ifname = s->iface;

    mqvpn_client_remove_path(p->client, s->handle);
    release_transport(p, s);

    if (outcome == MQVPN_ADD_PATH_PERMANENT_FAIL) {
        /* Saturate the per-slot counter — recover_dropped_paths_cb will
         * skip this slot until a fresh Level-2 reconnect resets the limit. */
        s->recover_failures = PATH_RECOVER_FAILURE_LIMIT;
        LOG_WRN("netmon: path %s recovery abandoned (xquic budget exhausted; "
                "reconnect required)",
                ifname);
        return;
    }

    /* Transient failure (most commonly -XQC_EMP_NO_AVAIL_PATH_ID during
     * WiFi reassoc CID-lag burst). Bump the consecutive-failure counter so
     * the 3s recovery timer eventually gives up and waits for reconnect. */
    s->recover_failures++;
    if (s->recover_failures >= PATH_RECOVER_FAILURE_LIMIT) {
        LOG_WRN("netmon: path %s recovery abandoned after %d consecutive "
                "failures (will resume on reconnect)",
                ifname, PATH_RECOVER_FAILURE_LIMIT);
    } else {
        LOG_WRN("netmon: re-add %s not activated, will retry (%d/%d)", ifname,
                s->recover_failures, PATH_RECOVER_FAILURE_LIMIT);
    }
}

/* Re-add slots on ifname that have no socket and whose previous library
 * incarnation is gone — CLOSED (DROPPED or FREE), or no longer listed
 * because another path's re-add recycled its library slot (the shared
 * decision in path_readd.h, which reconcile_all uses too). Slots that still
 * own a socket are reactivate's. add_path reuses only a fully released
 * (CLOSED_FREE) library slot and appends a fresh one otherwise, so the
 * re-add can succeed while the old incarnation drains (POSIX canon:
 * netmon_common.c); it fails only once MQVPN_MAX_PATHS is reached first.
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

    for (int i = 0; i < p->n_paths; i++) {
        platform_path_t *s = &p->paths[i];
        if (strcmp(s->iface, ifname) != 0) continue;
        if (!path_readd_candidate(s->sock != INVALID_SOCKET, s->recover_failures,
                                  PATH_RECOVER_FAILURE_LIMIT, s->handle, pinfo, n))
            continue;

        /* Definite "no FIB route to the server via this iface": re-adding
         * now would pin the challenge (IP_UNICAST_IF) into the kernel's
         * assume-on-link ARP blackhole (sendto succeeds, nothing on the
         * wire). The 3s recovery timer retries once a route exists.
         * -1 (probe unavailable) intentionally passes — fail open. */
        if (iface_has_route_to_server(ifname, &p->server_addr) == 0) return 0;

        if (readd_open_socket(p, s, ifname) < 0) return 0;

        void *tctx = recovery_transport_create(s->sock, ifname);
        if (!tctx) {
            platform_path_close_socket(s);
            return 0;
        }

        mqvpn_add_path_outcome_t outcome = MQVPN_ADD_PATH_OK;
        mqvpn_path_handle_t new_h =
            recovery_register_with_lib(p, s, tctx, ifname, &outcome);
        if (new_h < 0) {
            mqvpn_bind_winsock_path_free(tctx); /* add failed: still ours */
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
            LOG_WRN("netmon: read event setup failed on %s; path rolled back", ifname);
            mqvpn_client_remove_path(p->client, s->handle);
            release_transport(p, s);
            s->recover_failures++;
            return 0;
        }

        s->recover_failures = 0; /* success resets the budget */
        LOG_INF("netmon: path %s re-added (handle=%lld)", ifname, (long long)new_h);
        return 1;
    }
    return 0;
}

/* ================================================================
 *  Reconciler — poll body (sibling of the POSIX netmon_common.c's
 *  recover_dropped_paths_cb steps 1-3)
 * ================================================================ */

/* Drop dead paths and re-add/reactivate recovered ones. Extracted from the
 * timer callback so a later Phase 2 IP Helper change-notification event
 * source can call this directly without touching the poll cadence — the
 * timer re-arm stays in recover_dropped_paths_cb(), NOT here.
 *
 * Spec sec 3.4 "Stateless Platforms" compliance: this holds NO lifecycle
 * state of its own — it queries the library via mqvpn_client_get_paths()
 * each call and acts on the public MQVPN_PATH_* status. A slot's recover_failures
 * is pure backpressure to bound the busy-loop on transient xquic errors
 * during a WiFi reassoc CID-lag burst — not a state mirror. */
static void
reconcile_all(platform_win_ctx_t *p)
{
    mqvpn_path_info_t pinfo[MQVPN_MAX_PATHS];
    int n = 0;
    if (mqvpn_client_get_paths(p->client, pinfo, MQVPN_MAX_PATHS, &n) != MQVPN_OK) return;

    for (int i = 0; i < p->n_paths; i++) {
        platform_path_t *s = &p->paths[i];
        /* WINDOWS-ONLY: poll-driven drop (Linux does this via netlink), placed
         * BEFORE the failure-limit gate — a recovery-exhausted live-dead adapter
         * must still be droppable or it black-holes traffic. */
        if (s->sock != INVALID_SOCKET) {
            int lib_alive = 0;
            for (int j = 0; j < n; j++) {
                if (pinfo[j].handle == s->handle) {
                    lib_alive = (pinfo[j].status != MQVPN_PATH_CLOSED);
                    break;
                }
            }
            if (lib_alive) {
                const char *ifn = s->iface;
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
        if (s->recover_failures >= PATH_RECOVER_FAILURE_LIMIT) continue;
        if (s->sock != INVALID_SOCKET) {
            /* CLOSED_RECOVERABLE slots (with a socket) are reactivated by
             * this poll: Windows has no link/address event source in this
             * phase (see the file comment) that could trigger a reactivate.
             * try_reactivate_by_ifname re-checks lib state and the lib
             * rejects wrong states with INVALID_STATE, so this is
             * idempotent. */
            for (int j = 0; j < n; j++) {
                if (pinfo[j].handle == s->handle &&
                    pinfo[j].status == MQVPN_PATH_CLOSED) {
                    const char *rifname = s->iface;
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

        /* The shared re-add decision (path_readd.h): a handle the library no
         * longer lists was recycled for another path and is a candidate
         * too — Windows has no event path to catch it otherwise. */
        if (!path_readd_candidate(0, s->recover_failures, PATH_RECOVER_FAILURE_LIMIT,
                                  s->handle, pinfo, n))
            continue;

        const char *ifname = s->iface;
        if (iface_is_up_and_running(ifname) != 1)
            continue; /* tri-state: 0 and -1 both not-up-for-recovery */
        if (iface_has_usable_ip(ifname, p->server_addr.ss_family) != 1) continue;
        if (iface_has_route_to_server(ifname, &p->server_addr) == 0) {
            /* First block + every 10th (≈30s at the 3s poll). Unlike the
             * canon "netlink:"-prefixed line, this "netmon:" line is not
             * currently grepped by scripts/ci_e2e/run_route_gate_test.sh
             * (that e2e is Linux-only) — no e2e marker constraint here yet. */
            if (s->route_gate_blocked++ % 10 == 0)
                LOG_WRN("netmon: %s has a usable address but no route to "
                        "the server — re-add deferred until a route appears",
                        ifname);
            continue;
        }
        s->route_gate_blocked = 0;

        /* try_readd_removed_path scans by ifname, finds this slot through
         * the same decision, and either succeeds (resets the counter) or
         * fails. Only failures after add_path() has returned a handle count
         * toward the limit: a failed activation goes through
         * recovery_rollback (transient bumps the counter, permanent
         * saturates it), and a failed read-event arm bumps it directly.
         * Every earlier exit (the gates, get_paths, socket open, iface pin,
         * transport ctx, add_path() < 0) leaves it untouched, so those never
         * exhaust the budget. Multiple slots sharing one ifname are handled
         * by try_readd's internal loop. */
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
