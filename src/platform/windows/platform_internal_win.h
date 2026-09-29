// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

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
#  include "mqvpn_bind_winsock.h"
#  include "tun_wintun.h"

#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  include <iphlpapi.h>
#  include <netioapi.h>
#  include <fwpmu.h>

#  include <event2/event.h>

/* Maximum number of routes we install */
#  define MAX_INSTALLED_ROUTES 8

/* Adapter FriendlyName buffer (Windows has no IFNAMSIZ; IF_MAX_STRING_SIZE
 * is 256). */
#  ifndef IFNAMSIZ
#    define IFNAMSIZ 256
#  endif

typedef struct platform_win_ctx platform_win_ctx_t;

/* One platform path slot — the Windows sibling of the POSIX platform_path_t
 * (src/platform/posix/platform_internal.h): the socket this platform owns
 * for a configured adapter, the library incarnation registered on it, and
 * the per-path recovery state. Kept in platform_win_ctx_t for the whole
 * event loop; never moves, so a slot pointer is a stable event arg.
 *
 * Ownership (mechanics in platform_windows.c):
 *   sock      — only platform_path_close_socket() closes a socket once it is
 *               committed here; INVALID_SOCKET = no socket. SOCKET is
 *               unsigned: test against INVALID_SOCKET, never `>= 0`.
 *   ev        — the read event; non-NULL implies sock != INVALID_SOCKET.
 *   handle    — the last incarnation add_path registered; -1 before the
 *               first. Updated only when add_path returns a handle.
 *   bind_ctx  — the current transport ctx: platform-owned until add_path
 *               succeeds, library-owned after, NULL once the library has
 *               finalised it (path_released returned OK, or client_destroy).
 */
typedef struct platform_path {
    platform_win_ctx_t *p;      /* back pointer: the read event's arg is the slot */
    char iface[IFNAMSIZ];       /* adapter FriendlyName, "" = any; kept across drops */
    SOCKET sock;                /* INVALID_SOCKET = the platform holds no open socket */
    struct event *ev;           /* read event; non-NULL implies a socket */
    mqvpn_path_handle_t handle; /* last successfully registered incarnation */
    void *bind_ctx;             /* current transport ctx; NULL once finalised */
    int recover_failures;       /* failed re-adds in a row; reset on success/reconnect */
    /* Route-gate log throttle. Intentionally NOT reset on reconnect — it
     * self-resets in the reconciler when a route reappears (POSIX canon:
     * netmon_common.c recover_dropped_paths_cb); a stale value only delays
     * one throttled log line and self-heals within a few polls. */
    int route_gate_blocked;
} platform_path_t;

struct platform_win_ctx {
    mqvpn_client_t *client;

    /* Event loop */
    struct event_base *eb;
    struct event *ev_tick;
    struct event *ev_tun; /* monitors tun.pipe_rd */

    /* Path slots (UDP sockets + their transports), append-only */
    platform_path_t paths[MQVPN_MAX_PATHS];
    int n_paths;

    /* Path recovery accelerator (net_mon.c) */
    struct event *ev_recover; /* 3s poll timer */

    /* TUN device (Wintun) */
    mqvpn_tun_win_t tun;
    char tun_name_cfg[256];
    int tun_up;

    /* Server address */
    struct sockaddr_storage server_addr;
    socklen_t server_addrlen;

    /* Split tunneling state */
    int manage_routes; /* 1=run win_setup_routes/win_cleanup_routes */
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
    int n_wfp_filters;
    int killswitch_active;
    int killswitch_enabled;
    /* FwpmEngineClose0 failed: the dynamic session may still hold its
     * block-all filters and nothing can address them any more. Only process
     * exit clears them — see win_cleanup_killswitch(). */
    int wfp_close_failed;

    /* Shutdown */
    int shutting_down;
    int fatal_error; /* PLATFORM_FATAL_* below; forces exit code != 0 */

    /* Ctrl+C bridge: the console-control handler runs on a Windows-spawned
     * thread, and every mqvpn_client_* call must stay on the loop thread
     * (libmqvpn.h single-thread contract). The handler only pokes
     * wake_pair[1]; ev_wake fires on_shutdown_wake on the loop thread,
     * which performs the actual disconnect — the Windows analogue of the
     * Linux in-loop evsignal pattern. */
    evutil_socket_t wake_pair[2]; /* [0]=loop-side read, [1]=handler-side write */
    struct event *ev_wake;
};

/* fatal_error causes (same names as the POSIX platform_internal.h).
 * TUNNEL_SETUP: the host side of the tunnel could not be set up, or its kill
 * switch torn down. PATH_RELEASE: the library refused a transport release
 * the platform reported right after its own drop/remove of that path — an
 * invariant violation (net_mon.c). */
#  define PLATFORM_FATAL_TUNNEL_SETUP 1
#  define PLATFORM_FATAL_PATH_RELEASE 2

/* routing.c */
int win_setup_routes(platform_win_ctx_t *p);
void win_cleanup_routes(platform_win_ctx_t *p);

/* firewall.c */
int win_setup_killswitch(platform_win_ctx_t *p);
void win_cleanup_killswitch(platform_win_ctx_t *p);

/* dns.c */
int win_setup_dns(platform_win_ctx_t *p);
void win_cleanup_dns(platform_win_ctx_t *p);

/* platform_windows.c (net_mon.c calls win_pin_socket_to_iface and
 * schedule_next_tick; on_socket_read is the read callback
 * platform_path_arm() installs) */
int win_pin_socket_to_iface(SOCKET sock, const char *friendly_name, ADDRESS_FAMILY af);
void schedule_next_tick(platform_win_ctx_t *p);
void on_socket_read(evutil_socket_t fd, short what, void *arg);

/* Path slot mechanics, defined in platform_windows.c (the Windows sibling of
 * the POSIX path_table.c): they make no library call, keep no failure counter
 * and check no library status; those stay with their callers. */

/* Append a slot for iface (NULL or "" = any): INVALID_SOCKET, handle -1.
 * NULL when the table is full — which the CLI cannot reach (the input caps
 * are pinned to MQVPN_MAX_PATHS by _Static_assert). */
platform_path_t *platform_path_append(platform_win_ctx_t *p, const char *iface);

/* A slot's index in p->paths, for log lines that name path[N]. */
int platform_path_index(const platform_path_t *s);

/* Steps platform_path_socket_open() can fail at, so each caller keeps its own
 * log wording. */
enum {
    PLATFORM_PATH_STEP_SOCKET = 1,
    PLATFORM_PATH_STEP_NONBLOCK,
    PLATFORM_PATH_STEP_BIND,
};

/* A non-blocking UDP socket bound to the af wildcard (ephemeral port), or
 * INVALID_SOCKET with *failed_step set and WSAGetLastError() preserved
 * across the socket's own closesocket (callers log mqvpn_socket_strerror()).
 * Logs nothing. The caller commits the socket to its slot at once. */
SOCKET platform_path_socket_open(ADDRESS_FAMILY af, int *failed_step);

/* desc for add_path: struct_size, the slot's iface, and the server-family
 * wildcard as local_addr (the address the socket is bound to). */
void platform_path_fill_desc(const platform_win_ctx_t *p, const platform_path_t *s,
                             mqvpn_path_desc_t *desc);

/* Create and add the slot's read event (on_socket_read, arg = the slot).
 * 0, or -1 with nothing armed. */
int platform_path_arm(platform_path_t *s);

/* event_del only — for use inside the slot's own read callback; the event is
 * freed by platform_path_close_socket() / platform_paths_close_all(). */
void platform_path_disarm(platform_path_t *s);

/* Free the slot's read event, closesocket, INVALID_SOCKET. The only place a
 * socket committed to a slot is closed. */
void platform_path_close_socket(platform_path_t *s);

/* Teardown: platform_path_close_socket() for every slot, after
 * mqvpn_client_destroy() (the destroy-time flush still sends on them). */
void platform_paths_close_all(platform_win_ctx_t *p);

#endif /* _WIN32 */
#endif /* MQVPN_PLATFORM_INTERNAL_WIN_H */
