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
#include "mqvpn_bind_posix.h"
#include "tun.h"
#include "dns.h"

#include <arpa/inet.h>
#include <net/if.h>

#include <event2/event.h>

typedef struct platform_ctx platform_ctx_t;

/* One platform path slot: the socket this platform owns for a configured
 * interface, the library incarnation registered on it, and the per-path
 * recovery state. The table lives in platform_ctx_t for the whole event
 * loop and never moves, so a slot pointer is a stable event arg.
 *
 * Ownership (see path_table.c for the mechanics):
 *   fd        — only platform_path_close_socket() closes a socket once it is
 *               committed here; -1 = no socket (never opened, or dropped).
 *   ev        — the read event; non-NULL implies fd >= 0.
 *   handle    — the last incarnation add_path registered; -1 before the
 *               first. Updated only when add_path returns a handle.
 *   bind_ctx  — the current transport ctx: platform-owned until add_path
 *               succeeds, library-owned after, NULL once the library has
 *               finalised it (path_released returned OK, or client_destroy).
 */
typedef struct platform_path {
    platform_ctx_t *p;          /* back pointer: the read event's arg is the slot */
    char iface[IFNAMSIZ];       /* configured name, "" = any; kept across drops */
    int fd;                     /* -1 = the platform holds no open socket */
    struct event *ev;           /* read event; non-NULL implies fd >= 0 */
    mqvpn_path_handle_t handle; /* last successfully registered incarnation */
    void *bind_ctx;             /* current transport ctx; NULL once finalised */
    /* Consecutive re-add failures. Pure backpressure, NOT a state mirror —
     * lifecycle state is queried via mqvpn_client_get_paths(). Bounds the
     * busy-loop on transient xquic errors (e.g. -XQC_EMP_NO_AVAIL_PATH_ID
     * during WiFi reassoc CID lag). Reset on success or Level-2 reconnect. */
    int recover_failures;
    int route_gate_blocked; /* consecutive route-gate blocks, warn debounce */
} platform_path_t;

struct platform_ctx {
    mqvpn_client_t *client;

    /* Event loop */
    struct event_base *eb;
    struct event *ev_tick;
    struct event *ev_tun;
    struct event *ev_sigint;
    struct event *ev_sigterm;
    struct event *ev_status;  /* periodic status log timer */
    struct event *ev_recover; /* periodic dropped-path re-add timer (3s) */

    /* Path slots (UDP sockets + their transports), append-only */
    platform_path_t paths[MQVPN_MAX_PATHS];
    int n_paths;

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
    int udp_gso; /* [Advanced] UdpGso policy, reproduced on re-add */
#endif
    /* Receive-side telemetry: cumulative PLATFORM totals. The bind counts per
     * transport ctx on every POSIX platform and those counters die with the
     * ctx, so the release sites (netmon_common.c) and, on Linux, the teardown harvest
     * fold each ctx's totals in here — while the bind keeps the per-ctx
     * originals. Only Linux prints them, in the udp-rx line: the sockopt log
     * proves GRO was requested, only gro_datagrams > gro_receives proves the
     * kernel actually coalesced. Darwin accumulates only what the release sites
     * add and reports nothing. */
    uint64_t gro_receives;  /* receives whose data was DELIVERED —
                             * truncated-dropped and drained-but-undelivered
                             * receives count toward neither counter, so the
                             * datagrams/receives factor cannot dip below 1.0 */
    uint64_t gro_datagrams; /* datagrams delivered to the library */
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
    /* Why the event loop was stopped on purpose, if it was (PLATFORM_FATAL_*
     * below; 0 = normal). Read once after the loop returns, to exit non-zero
     * and name the cause. Same name and meaning as platform_win_ctx_t's
     * fatal_error. */
    int fatal_error;

    /* Path recovery event source (per-OS: netlink on Linux, PF_ROUTE on Darwin) */
#if defined(__linux__)
    int nl_fd; /* netlink socket, -1 if unavailable */
    struct event *ev_netlink;
#elif defined(__APPLE__)
    int rt_fd; /* PF_ROUTE socket, -1 if unavailable */
    struct event *ev_route;
#endif
};

/* fatal_error causes. TUNNEL_SETUP: cb_tunnel_config_ready() could not build
 * the tunnel the server handed over (TUN, addressing, MTU, routes, kill
 * switch). PATH_RELEASE: the library refused a transport release the
 * platform reported right after its own drop/remove of that path — an
 * invariant violation (netmon_common.c). */
#define PLATFORM_FATAL_TUNNEL_SETUP 1
#define PLATFORM_FATAL_PATH_RELEASE 2

/* platform_{linux,darwin}.c (netmon_common.c, and netlink_mon.c on Linux or
 * route_mon.c on Darwin, call schedule_next_tick; on_socket_read is the read
 * callback platform_path_arm() installs) */
void on_socket_read(evutil_socket_t fd, short what, void *arg);
void schedule_next_tick(platform_ctx_t *p);

/* netmon_common.c — a slot's bind RX counters (cumulative since ctx
 * creation). Must run BEFORE the ctx is finalised (on_platform_path_released
 * / client_destroy); the accessor is invalid afterwards. Callers add the
 * values to the gro_* totals only once the ctx is definitely gone (released()
 * returned OK, or at teardown). */
void platform_read_rx_stats(const platform_path_t *s, uint64_t *receives,
                            uint64_t *datagrams);

/* netmon_common.c — the startup slots: one per configured interface
 * (n_ifaces 0 = one "any" slot), each with its socket, each logged. 0, or -1
 * (already logged; the caller exits through its cleanup). */
int platform_paths_open(platform_ctx_t *p, int n_ifaces, const char *const *ifaces);

/* path_table.c — slot mechanics (its header states what stays out) */

/* Append a slot for iface (NULL or "" = any): fd -1, handle -1. NULL when the
 * table is full — which the CLI cannot reach: MQVPN_MAX_PATH_IFACES and
 * MQVPN_CONFIG_MAX_PATHS are pinned to MQVPN_MAX_PATHS by _Static_assert. */
platform_path_t *platform_path_append(platform_ctx_t *p, const char *iface);

/* A slot's index in p->paths, for log lines that name path[N]. */
int platform_path_index(const platform_path_t *s);

/* Steps platform_path_socket_open() can fail at, so each caller keeps its own
 * log wording. */
enum {
    PLATFORM_PATH_STEP_SOCKET = 1,
    PLATFORM_PATH_STEP_NONBLOCK,
    PLATFORM_PATH_STEP_BIND,
};

/* A non-blocking UDP socket bound to the af wildcard (ephemeral port), or -1
 * with errno preserved and *failed_step set; the socket is closed on failure.
 * Logs nothing. The caller commits the fd to its slot at once. */
int platform_path_socket_open(sa_family_t af, int *failed_step);

/* desc for add_path: struct_size, the slot's iface, and the server-family
 * wildcard as local_addr (the address the socket is bound to). */
void platform_path_fill_desc(const platform_ctx_t *p, const platform_path_t *s,
                             mqvpn_path_desc_t *desc);

/* Create and add the slot's read event (on_socket_read, arg = the slot).
 * 0, or -1 with nothing armed (event_new or event_add failed). */
int platform_path_arm(platform_path_t *s);

/* event_del only — for use inside the slot's own read callback; the event is
 * freed by platform_path_close_socket() / platform_paths_close_all(). */
void platform_path_disarm(platform_path_t *s);

/* Free the slot's read event, close its socket, fd = -1. The only place a
 * socket committed to a slot is closed. */
void platform_path_close_socket(platform_path_t *s);

/* Teardown: platform_path_close_socket() for every slot. Runs after
 * mqvpn_client_destroy() (the destroy-time flush still sends on the fds). */
void platform_paths_close_all(platform_ctx_t *p);

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
