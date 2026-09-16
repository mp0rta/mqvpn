// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * platform_internal.h — Shared types for the POSIX platform layers
 * (Linux, Darwin).
 *
 * Internal header used by platform_linux.c, routing.c, killswitch.c
 * (and their Darwin counterparts). NOT part of the public API.
 */

#ifndef MQVPN_PLATFORM_INTERNAL_H
#define MQVPN_PLATFORM_INTERNAL_H

#include "libmqvpn.h"
#include "tun.h"
#include "dns.h"
#include "path_mgr.h"

#include <arpa/inet.h>
#include <net/if.h>

#include <event2/event.h>

typedef struct {
    mqvpn_client_t *client;

    /* Event loop */
    struct event_base *eb;
    struct event *ev_tick;
    struct event *ev_tun;
    struct event *ev_sigint;
    struct event *ev_sigterm;
    struct event *ev_status;  /* periodic status log timer */
    struct event *ev_recover; /* periodic dropped-path re-add timer (3s) */

    /* Path manager (UDP sockets) */
    mqvpn_path_mgr_t path_mgr;
    mqvpn_path_handle_t lib_path_handles[MQVPN_MAX_PATHS];
    struct event *ev_udp[MQVPN_MAX_PATHS];

    /* Per-slot consecutive re-add failure counter. Pure backpressure,
     * NOT a state mirror — lifecycle state is queried via
     * mqvpn_client_get_paths(). Bounds the busy-loop on transient xquic
     * errors (e.g. -XQC_EMP_NO_AVAIL_PATH_ID during WiFi reassoc CID
     * lag). Reset on success or Level-2 reconnect. */
    int path_recover_failures[MQVPN_MAX_PATHS];
    int route_gate_blocked[MQVPN_MAX_PATHS]; /* consecutive poll blocks, warn debounce */

    /* TUN device */
    mqvpn_tun_t tun;
    char tun_name_cfg[IFNAMSIZ]; /* configured name, survives destroy */
    int tun_up;

    /* Server address */
    struct sockaddr_storage server_addr;
    socklen_t server_addrlen;

    /* Split tunneling state */
    int routing_configured;
    int routing6_configured;
    int manage_routes; /* 1=run setup_routes/cleanup_routes (default 1) */
#if defined(__linux__)
    /* [Advanced] UdpGro — effective RX GRO mode. Config-derived state kept
     * here (pattern: manage_routes above) so the netlink re-add path can
     * reproduce startup behavior on the fresh fd it creates. Linux-only:
     * GRO is a Linux sockopt and Darwin would carry a dead field. */
    int udp_gro;
    /* Receive-side offload telemetry, written by on_socket_read and read once
     * at teardown. The sockopt log proves GRO was requested; only
     * gro_datagrams > gro_receives proves the kernel actually coalesced. */
    uint64_t gro_receives;  /* recvmsg calls whose data was DELIVERED —
                             * truncated-dropped and drained-but-undelivered
                             * receives count toward neither counter, so the
                             * datagrams/receives factor cannot dip below
                             * 1.0 (see drain_udp_rx) */
    uint64_t gro_datagrams; /* datagrams delivered to the library */
#endif
    char orig_gateway[INET6_ADDRSTRLEN];
    char orig_iface[IFNAMSIZ];
    char server_ip_str[INET6_ADDRSTRLEN];
    int server_port;
    int has_v6;

    /* DNS */
    mqvpn_dns_t dns;

    /* Kill switch */
    int killswitch_active;
    int killswitch_enabled;
    char ks_comment[64];
    char ks_pf_token[24]; /* Darwin pf enable token (pfctl -E); unused on Linux.
                           * Length vs. real token format: verify on macOS. */

    /* Shutdown */
    int shutting_down;
    /* Tunnel setup aborted in cb_tunnel_config_ready()'s fail: path — the
     * platform could not build the tunnel the server just handed it (TUN,
     * addressing, MTU, routes, kill switch). Read once after the event loop
     * returns, to exit non-zero. Same name and meaning as platform_win_ctx_t's
     * fatal_error (platform_windows.c:236, read at :703). */
    int fatal_error;

    /* Path recovery event source (per-OS: netlink on Linux, PF_ROUTE on Darwin) */
#if defined(__linux__)
    int nl_fd; /* netlink socket, -1 if unavailable */
    struct event *ev_netlink;
#elif defined(__APPLE__)
    int rt_fd; /* PF_ROUTE socket, -1 if unavailable */
    struct event *ev_route;
#endif
} platform_ctx_t;

/* platform_{linux,darwin}.c — reactor entry points shared with
 * netlink_mon.c (Linux) / route_mon.c (Darwin) */
void on_socket_read(evutil_socket_t fd, short what, void *arg);
void schedule_next_tick(platform_ctx_t *p);

/* routing.c */
int setup_routes(platform_ctx_t *p);
void cleanup_routes(platform_ctx_t *p);

/* darwin/routing.c — `route -n get` output parser, non-static for unit tests.
 * Fills gateway (empty string if on-link, incl. "link#N" gateways) and iface.
 * Returns 0 if iface was found, -1 otherwise. Darwin-only (Linux never
 * compiles darwin/routing.c; declaration here is inert on Linux). */
int mqvpn_parse_route_get_output(const char *out, char *gateway, size_t gw_len,
                                 char *iface, size_t if_len);

/* route_check.c (linux) / route_mon.c (darwin) */
int iface_has_route_to_server(const char *ifname, const struct sockaddr_storage *server);

/* darwin/routing.c — (re)installs ifname's RTF_IFSCOPE host route to the
 * server via that interface's own default gateway (follow-up #F1: without
 * it, a recovered path whose interface flap flushed the unscoped server
 * pin gets ENETUNREACH on every scoped send and parks in VALIDATING —
 * rationale block at the definition). Called from setup_routes for every
 * configured path iface and from route_mon.c before a path re-add /
 * reactivate hands the socket back to xquic. Returns 0 on success, -1 if
 * routing is not configured, the interface has no default route, or
 * route(8) failed — callers treat failure as best-effort (log + continue).
 * Darwin-only (Linux never compiles darwin/routing.c; declaration here is
 * inert on Linux). */
int darwin_scoped_server_pin(platform_ctx_t *p, const char *ifname);

/* per-OS socket-to-interface pinning (platform_linux.c / platform_darwin.c) */
#if defined(__linux__)
int linux_pin_socket_to_iface(int fd, const char *ifname);
#elif defined(__APPLE__)
int darwin_pin_socket_to_iface(int fd, const char *ifname, sa_family_t af);
#endif

/* killswitch.c */
int setup_killswitch(platform_ctx_t *p);
void cleanup_killswitch(platform_ctx_t *p);

/* darwin/killswitch.c — flushes the pf anchor unconditionally, independent
 * of any platform_ctx_t / killswitch_active state. Darwin-only: called from
 * the startup stale-recovery block (darwin_platform_run_client) to self-heal
 * a pf anchor left live by a prior crash — for why this is a startup step
 * rather than part of setup_killswitch(), see this function's doc comment
 * in darwin/killswitch.c. Declaration is inert on Linux (never called
 * there; linux/killswitch.c does not define it). */
void kill_switch_flush_stale_anchor(void);

#endif /* MQVPN_PLATFORM_INTERNAL_H */
