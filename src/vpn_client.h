#ifndef MQVPN_VPN_CLIENT_H
#define MQVPN_VPN_CLIENT_H

#include <stdint.h>

#define MQVPN_MAX_PATH_IFACES  4

typedef struct mqvpn_client_cfg_s {
    const char  *server_addr;   /* server address (e.g. "1.2.3.4") */
    int          server_port;   /* server port (e.g. 443) */
    const char  *tun_name;      /* TUN device name */
    int          insecure;      /* skip TLS cert verification */
    int          log_level;     /* xquic log level */
    const char  *path_ifaces[MQVPN_MAX_PATH_IFACES]; /* network interfaces for multipath */
    int          n_paths;       /* number of path interfaces (0 = single-path) */
    int          scheduler;     /* 0=minrtt, 1=wlb (default) */
} mqvpn_client_cfg_t;

/* Run the VPN client (blocks until shutdown). Returns 0 on clean exit. */
int mqvpn_client_run(const mqvpn_client_cfg_t *cfg);

#endif /* MQVPN_VPN_CLIENT_H */
