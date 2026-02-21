/*
 * config.h — INI-style configuration file parser for mqvpn
 *
 * Sections: [Interface], [Server], [TLS], [Auth], [Multipath]
 * Mode is inferred from keys:
 *   [Interface] Listen → server mode
 *   [Server] Address   → client mode
 */
#ifndef MQVPN_CONFIG_H
#define MQVPN_CONFIG_H

#define MQVPN_CONFIG_MAX_PATHS   4
#define MQVPN_CONFIG_MAX_DNS     4

typedef struct mqvpn_config_s {
    /* [Interface] — common */
    char tun_name[32];
    char log_level[16];

    /* [Interface] — server */
    char listen[280];       /* "bind:port" */
    char subnet[32];

    /* [Interface] — client */
    char dns_servers[MQVPN_CONFIG_MAX_DNS][64];
    int  n_dns;

    /* [Server] — client */
    char server_addr[280];  /* "host:port" */
    int  insecure;

    /* [Auth] — client */
    char auth_key[256];

    /* [TLS] — server */
    char cert_file[256];
    char key_file[256];

    /* [Auth] — server */
    char server_auth_key[256];
    int  max_clients;

    /* [Multipath] */
    char paths[MQVPN_CONFIG_MAX_PATHS][32];
    int  n_paths;
    char scheduler[16];

    /* Inferred mode: 1=server, 0=client */
    int  is_server;
} mqvpn_config_t;

/* Fill cfg with default values */
void mqvpn_config_defaults(mqvpn_config_t *cfg);

/* Parse INI file at path into cfg. Returns 0 on success, -1 on error. */
int  mqvpn_config_load(mqvpn_config_t *cfg, const char *path);

#endif /* MQVPN_CONFIG_H */
