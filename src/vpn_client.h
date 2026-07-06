// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef MQVPN_VPN_CLIENT_H
#define MQVPN_VPN_CLIENT_H

#include <stdint.h>

#include "libmqvpn.h"          /* for MQVPN_MAX_PATHS */
#include "reorder.h"           /* mqvpn_reorder_config_t (INI [Reorder] bridge) */
#include "hybrid/classifier.h" /* mqvpn_hybrid_config_t (INI [Hybrid] bridge) */

#define MQVPN_MAX_PATH_IFACES 8
_Static_assert(MQVPN_MAX_PATH_IFACES == MQVPN_MAX_PATHS,
               "CLI path cap must equal library cap (libmqvpn.h)");

typedef struct mqvpn_client_cfg_s {
    const char *server_addr;     /* server address (e.g. "1.2.3.4") */
    int server_port;             /* server port (e.g. 443) */
    const char *tls_server_name; /* SNI / cert verify name (NULL = use server_addr) */
    const char *tun_name;        /* TUN device name */
    int insecure;                /* skip TLS cert verification */
    int log_level;               /* mqvpn_log_level_t */
    const char *path_ifaces[MQVPN_MAX_PATH_IFACES]; /* network interfaces for multipath */
    int n_paths;          /* number of path interfaces (0 = single-path) */
    int scheduler;        /* 0=minrtt, 1=wlb (default), 2=backup_fec, 3=wlb_udp_pin */
    const char *auth_key; /* PSK for server authentication (NULL = no auth) */
    const char *dns_servers[4]; /* DNS servers to configure (NULL = no DNS override) */
    int n_dns;                  /* number of DNS servers */
    int reconnect;              /* 1=auto-reconnect on disconnect (default 1) */
    int reconnect_interval;     /* base reconnect interval in seconds (default 5) */
    int kill_switch;            /* 1=block traffic outside tunnel (default 0) */
    int manage_routes; /* 1=manage host routes (default 1), 0=skip routing setup */
    uint64_t init_max_path_id; /* draft-21 §4.6 TP cap, 0=use xquic default 8 */
    int tun_mtu;               /* 0=auto (MSS-derived), >0=cap (floor 1280) */
    int cc;                    /* mqvpn_cc_t: congestion control algorithm */
    mqvpn_reorder_config_t
        reorder;                  /* INI [Reorder]/[ReorderRule] (mode OFF by default) */
    mqvpn_hybrid_config_t hybrid; /* INI [Hybrid] (disabled by default) */
} mqvpn_client_cfg_t;

#endif /* MQVPN_VPN_CLIENT_H */
