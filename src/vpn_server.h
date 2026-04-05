#ifndef MQVPN_VPN_SERVER_H
#define MQVPN_VPN_SERVER_H

#include <stdint.h>
#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <netinet/in.h>
#endif

typedef struct mqvpn_server_cfg_s {
    const char  *listen_addr;   /* bind address (e.g. "0.0.0.0") */
    int          listen_port;   /* bind port (e.g. 443) */
    const char  *subnet;        /* client IP pool CIDR (e.g. "10.0.0.0/24") */
    const char  *subnet6;       /* IPv6 client pool CIDR (NULL = disabled) */
    const char  *tun_name;      /* TUN device name */
    const char  *cert_file;     /* TLS certificate path */
    const char  *key_file;      /* TLS private key path */
    int          log_level;     /* xquic log level */
    int          scheduler;     /* 0=minrtt, 1=wlb (default) */
    const char  *auth_key;     /* PSK for client authentication (NULL = no auth) */
    const char  *user_names[64];
    const char  *user_keys[64];
    int          n_users;
    int          max_clients;    /* max concurrent clients (default 64) */
    const char  *control_addr;  /* bind address for JSON control API (default 127.0.0.1) */
    int          control_port;  /* TCP port for JSON control API (0 = disabled) */
} mqvpn_server_cfg_t;

#endif /* MQVPN_VPN_SERVER_H */
