#ifndef MQVPN_VPN_SERVER_H
#define MQVPN_VPN_SERVER_H

#include <stdint.h>
#include <netinet/in.h>
#include <event2/event.h>

typedef struct mqvpn_server_cfg_s {
    const char  *listen_addr;   /* bind address (e.g. "0.0.0.0") */
    int          listen_port;   /* bind port (e.g. 443) */
    const char  *subnet;        /* client IP pool CIDR (e.g. "10.0.0.0/24") */
    const char  *tun_name;      /* TUN device name */
    const char  *cert_file;     /* TLS certificate path */
    const char  *key_file;      /* TLS private key path */
    int          log_level;     /* xquic log level */
    int          scheduler;     /* 0=minrtt, 1=wlb (default) */
} mqvpn_server_cfg_t;

/* Run the VPN server (blocks until shutdown). Returns 0 on clean exit. */
int mqvpn_server_run(const mqvpn_server_cfg_t *cfg);

#endif /* MQVPN_VPN_SERVER_H */
