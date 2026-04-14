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
    struct event *ev_status; /* periodic status log timer */

    /* Path manager (UDP sockets) */
    mqvpn_path_mgr_t path_mgr;
    mqvpn_path_handle_t lib_path_handles[MQVPN_MAX_PATHS];
    struct event *ev_udp[MQVPN_MAX_PATHS];

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
    int path_recoverable[MQVPN_MAX_PATHS];         /* 1 = reactivate on netlink event */
    int path_removed_by_platform[MQVPN_MAX_PATHS]; /* 1 = platform called remove_path */
} platform_ctx_t;

/* routing.c */
int setup_routes(platform_ctx_t *p);
void cleanup_routes(platform_ctx_t *p);

/* killswitch.c */
int setup_killswitch(platform_ctx_t *p);
void cleanup_killswitch(platform_ctx_t *p);

#endif /* MQVPN_PLATFORM_INTERNAL_H */
