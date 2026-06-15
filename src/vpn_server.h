// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef MQVPN_VPN_SERVER_H
#define MQVPN_VPN_SERVER_H

#include <stdint.h>
#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <netinet/in.h>
#endif

#include "reorder.h" /* mqvpn_reorder_config_t (INI [Reorder] bridge) */

typedef struct mqvpn_server_cfg_s {
    const char *listen_addr; /* bind address (e.g. "0.0.0.0") */
    int listen_port;         /* bind port (e.g. 443) */
    const char *subnet;      /* client IP pool CIDR (e.g. "10.0.0.0/24") */
    const char *subnet6;     /* IPv6 client pool CIDR (NULL = disabled) */
    const char *tun_name;    /* TUN device name */
    const char *cert_file;   /* TLS certificate path */
    const char *key_file;    /* TLS private key path */
    int log_level;           /* mqvpn_log_level_t */
    int scheduler;           /* 0=minrtt, 1=wlb (default), 2=backup_fec, 3=wlb_udp_pin */
    const char *auth_key;    /* PSK for client authentication (NULL = no auth) */
    const char *user_names[64];
    const char *user_keys[64];
    int n_users;
    int max_clients;           /* max concurrent clients (default 64) */
    const char *control_addr;  /* bind address for JSON control API (default 127.0.0.1) */
    int control_port;          /* TCP port for JSON control API (0 = disabled) */
    uint64_t init_max_path_id; /* draft-21 §4.6 TP cap, 0=use xquic default 8 */
    int tun_mtu;               /* 0=auto (1382 at startup), >0=override (floor 1280) */
    int cc;                    /* mqvpn_cc_t: congestion control algorithm */
    mqvpn_reorder_config_t
        reorder; /* INI [Reorder]/[ReorderRule] (mode OFF by default) */
} mqvpn_server_cfg_t;

#endif /* MQVPN_VPN_SERVER_H */
