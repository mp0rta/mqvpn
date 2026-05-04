/*
 * platform_internal_win.h — Shared types for Windows platform layer
 *
 * Internal header used by platform_windows.c, routing.c, firewall.c, dns.c.
 * NOT part of the public API.
 */

#ifndef MQVPN_PLATFORM_INTERNAL_WIN_H
#define MQVPN_PLATFORM_INTERNAL_WIN_H

#ifdef _WIN32

#  include "libmqvpn.h"
#  include "tun_wintun.h"
#  include "path_mgr.h"

#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  include <iphlpapi.h>
#  include <netioapi.h>
#  include <fwpmu.h>

#  include <event2/event.h>

/* Maximum number of routes we install */
#  define MAX_INSTALLED_ROUTES 8

/* Maximum number of WFP filters (loopback*2 + TUN*2 + server + block*2 + spare) */
#  define MAX_WFP_FILTERS 10

typedef struct {
    mqvpn_client_t *client;

    /* Event loop */
    struct event_base *eb;
    struct event *ev_tick;
    struct event *ev_tun; /* monitors tun.pipe_rd */

    /* Path manager (UDP sockets) */
    mqvpn_path_mgr_t path_mgr;
    mqvpn_path_handle_t lib_path_handles[MQVPN_MAX_PATHS];
    struct event *ev_udp[MQVPN_MAX_PATHS];

    /* TUN device (Wintun) */
    mqvpn_tun_win_t tun;
    char tun_name_cfg[256];
    int tun_up;

    /* Server address */
    struct sockaddr_storage server_addr;
    socklen_t server_addrlen;

    /* Split tunneling state */
    int routing_configured;
    int routing6_configured;
    MIB_IPFORWARD_ROW2 installed_routes[MAX_INSTALLED_ROUTES];
    int n_installed_routes;
    char server_ip_str[INET6_ADDRSTRLEN];
    int server_port;
    int has_v6;

    /* DNS */
    int dns_configured;
    DWORD dns_if_index;
    int n_dns;
    char dns_servers[4][64];

    /* Kill switch (WFP) */
    HANDLE wfp_engine;
    GUID wfp_sublayer_key;
    UINT64 wfp_filter_ids[MAX_WFP_FILTERS];
    int n_wfp_filters;
    int killswitch_active;
    int killswitch_enabled;

    /* Shutdown */
    int shutting_down;
    int fatal_error; /* set by tunnel-setup failures to force exit code != 0 */
} platform_win_ctx_t;

/* routing.c */
int win_setup_routes(platform_win_ctx_t *p);
void win_cleanup_routes(platform_win_ctx_t *p);

/* firewall.c */
int win_setup_killswitch(platform_win_ctx_t *p);
void win_cleanup_killswitch(platform_win_ctx_t *p);

/* dns.c */
int win_setup_dns(platform_win_ctx_t *p);
void win_cleanup_dns(platform_win_ctx_t *p);

#endif /* _WIN32 */
#endif /* MQVPN_PLATFORM_INTERNAL_WIN_H */
