// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * platform_internal.h — Shared types for Linux platform layer
 *
 * Internal header used by platform_linux.c, routing.c, killswitch.c.
 * NOT part of the public API.
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

    /* Shutdown */
    int shutting_down;

    /* Netlink path recovery */
    int nl_fd; /* netlink socket, -1 if unavailable */
    struct event *ev_netlink;
} platform_ctx_t;

/* routing.c */
int setup_routes(platform_ctx_t *p);
void cleanup_routes(platform_ctx_t *p);

/* killswitch.c */
int setup_killswitch(platform_ctx_t *p);
void cleanup_killswitch(platform_ctx_t *p);

#endif /* MQVPN_PLATFORM_INTERNAL_H */
