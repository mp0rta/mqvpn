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
 * the startup stale-recovery block (darwin_platform_run_client) before
 * routes/killswitch/DNS are (re)established, to self-heal a pf anchor left
 * live by a prior crash. Declaration is inert on Linux (never called
 * there; linux/killswitch.c does not define it). */
void kill_switch_flush_stale_anchor(void);

#endif /* MQVPN_PLATFORM_INTERNAL_H */
