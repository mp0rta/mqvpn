// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * netmon_common.h — shared core of the POSIX network-path monitors
 *
 * The drop / reactivate / re-add decision layer ("Layer B") that was
 * previously maintained as two hand-synchronized copies in Linux
 * netlink_mon.c and Darwin route_mon.c. The platform files keep only the
 * kernel-ABI layer ("Layer A": netlink vs PF_ROUTE event parsing, carrier
 * probes, socket setup) and provide the small adapter functions declared
 * below; everything else lives once in netmon_common.c.
 *
 * Windows net_mon.c is NOT a consumer: it keys paths by interface LUID on
 * a different ctx type (platform_win_ctx_t) — unifying it is a separate,
 * larger step.
 */

#ifndef MQVPN_PLATFORM_NETMON_COMMON_H
#define MQVPN_PLATFORM_NETMON_COMMON_H

#include "platform_internal.h"

/* Periodic dropped-path re-add timer period. Backstops carrier-up link
 * events that fire only once while netmon_try_readd_removed_path() fails
 * synchronously (see recover_dropped_paths_cb). Shared verbatim by both
 * monitors — previously duplicated in netlink_mon.h / route_mon.h. */
#define RECOVER_INTERVAL_SEC       3
#define PATH_RECOVER_FAILURE_LIMIT 5

/* ── Adapter contract ──────────────────────────────────────────────────
 * Each platform monitor TU defines these (link-time polymorphism — no
 * function-pointer table; there is exactly one platform per binary). */

/* Log tag prepended to every shared-layer message ("netlink" / "routemon").
 * The tag is a runtime argument but the rendered output is byte-identical
 * to the pre-split hardcoded strings — e2e scripts grep them (G13). */
extern const char *const netmon_log_tag;

/* Pin a freshly-created re-add socket to its interface. Returns 0/-1.
 * Linux: SO_BINDTODEVICE (af unused); Darwin: IP_BOUND_IF/IPV6_BOUND_IF. */
int netmon_platform_pin_socket(int fd, const char *ifname, sa_family_t af);

/* Called after a re-add socket is fully created and pinned, before it is
 * registered with the library. Linux: re-applies UDP GRO (a re-added path
 * gets a brand-new fd, so the startup sockopt must be reproduced or the
 * path silently degrades to one datagram per recvmsg). Darwin: no-op. */
void netmon_platform_socket_created(platform_ctx_t *p, int fd, const char *ifname);

/* Called inside netmon_try_readd_removed_path once a slot is resolved as a
 * genuine re-add candidate, before the socket is created. Darwin: restores
 * the interface's scoped server pin (#F1) so the first PATH_CHALLENGE
 * doesn't die with ENETUNREACH. Linux: no-op. */
void netmon_platform_pre_readd(platform_ctx_t *p, const char *ifname);

/* Called inside netmon_try_reactivate_by_ifname once a slot passes the
 * shared status gate, before mqvpn_client_reactivate_path(). Return 0 to
 * proceed, -1 to skip this slot (the shared layer moves on silently — the
 * adapter may log its own reason; Darwin's fd<0 guard rejects silently).
 * Darwin: skips fd<0 slots, re-applies the iface pin (ifindex may have
 * been renumbered) and the scoped server pin. Linux: always proceeds (the
 * library's own state gate rejects ineligible slots with INVALID_STATE,
 * which the shared layer swallows). */
int netmon_platform_pre_reactivate(platform_ctx_t *p, int slot, const char *ifname);

/* Called at the top of recover_dropped_paths_cb, before the lib-state
 * query. Returns nonzero if it may have dropped/changed paths — in that
 * case a failed lib-state query still drives the engine before re-arming
 * (queued PATH_ABANDONs must not wait for an unrelated timer). Darwin:
 * runs the drop-capable route_resync every Nth tick and returns 1 (xnu's
 * routing socket has no overflow signal, so the reconcile is timer-driven
 * and must land before the re-add/reactivate scan). Linux: no-op, 0. */
int netmon_platform_pre_scan(platform_ctx_t *p);

/* ── Shared Layer B API (implemented in netmon_common.c) ──────────────── */

/* Log wording per reason. Frozen: e2e scripts grep these exact strings
 * ("interface <if> <reason>, closing path"). */
const char *netmon_drop_reason_str(mqvpn_platform_reason_t reason);

/* Drop every tracked path on `ifname` (PLATFORM_DROP + fd close + lib
 * notify). Returns the number of paths matched. */
int netmon_drop_paths_by_ifname(platform_ctx_t *p, const char *ifname,
                                mqvpn_platform_reason_t reason);

/* IFF_UP && IFF_RUNNING probe. */
int netmon_iface_is_up_and_running(const char *ifname);

/* Usable-source-address probe. 1 = present, 0 = definitely none,
 * -1 = getifaddrs failed (callers fail safe — see netmon_common.c). */
int netmon_iface_has_usable_ip(const char *ifname, sa_family_t af);

/* Reactivate DEGRADED/CLOSED slots on `ifname` (fd still owned). */
void netmon_try_reactivate_by_ifname(platform_ctx_t *p, const char *ifname);

/* Re-add slots whose lib state is CLOSED (fd was closed on drop).
 * Returns 1 if a path was re-added. */
int netmon_try_readd_removed_path(platform_ctx_t *p, const char *ifname);

/* Shared decision tail of the DELADDR handlers: drop `ifname`'s paths as
 * ADDR_REMOVED iff it is tracked, still up-and-running (a link event owns
 * the drop otherwise) and definitely has no usable address left. */
void netmon_on_addr_removed(platform_ctx_t *p, const char *ifname, sa_family_t af);

/* Periodic re-add/reactivate timer callback (p->ev_recover) — shared by
 * both monitors; platform behavior is injected via the adapters above. */
void recover_dropped_paths_cb(evutil_socket_t fd, short what, void *arg);

#endif /* MQVPN_PLATFORM_NETMON_COMMON_H */
