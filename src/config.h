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

#include <stddef.h> /* size_t */

#define MQVPN_CONFIG_MAX_PATHS 4
#define MQVPN_CONFIG_MAX_DNS   4
#define MQVPN_CONFIG_MAX_USERS 64

typedef struct mqvpn_file_config_s {
    /* [Interface] — common */
    char tun_name[32];
    char log_level[16];

    /* [Interface] — server */
    char listen[280]; /* "bind:port" */
    char subnet[32];
    char subnet6[64]; /* IPv6 tunnel subnet CIDR (e.g. "2001:db8:1::/112") */

    /* [Interface] — client */
    char dns_servers[MQVPN_CONFIG_MAX_DNS][64];
    int n_dns;

    /* [Server] — client */
    char server_addr[280]; /* "host:port" */
    int insecure;

    /* [Auth] — client */
    char auth_key[256];

    /* [TLS] — server */
    char cert_file[256];
    char key_file[256];

    /* [Auth] — server */
    char server_auth_key[256];
    char user_names[MQVPN_CONFIG_MAX_USERS][64];
    char user_keys[MQVPN_CONFIG_MAX_USERS][256];
    int n_users;
    int max_clients;

    /* [Control] — server */
    char control_listen[280]; /* "addr:port" — empty string when control API disabled */

    /* [Multipath] */
    char paths[MQVPN_CONFIG_MAX_PATHS][32];
    int n_paths;
    char scheduler[16];

    /* [Interface] — client reconnection */
    int reconnect;          /* 1=auto-reconnect (default), 0=exit on disconnect */
    int reconnect_interval; /* base interval in seconds (default 5) */
    int kill_switch;        /* 1=block traffic outside tunnel, 0=off (default) */

    /* Inferred mode: 1=server, 0=client */
    int is_server;
} mqvpn_file_config_t;

/* Fill cfg with default values */
void mqvpn_config_defaults(mqvpn_file_config_t *cfg);

/* Parse INI file at path into cfg. Returns 0 on success, -1 on error. */
int mqvpn_config_load(mqvpn_file_config_t *cfg, const char *path);

/* Parse JSON text into CLI cfg. Returns 0 on success, -1 on error. */
int mqvpn_config_load_json_filecfg(mqvpn_file_config_t *cfg, const char *json_text);

/*
 * Resolve the effective control-API endpoint by merging INI/JSON config
 * with CLI flags. Pure: no I/O, no globals.
 *
 *   file_listen   : file_cfg.control_listen — "" or NULL if absent
 *   cli_addr      : CLI --control-addr value — NULL if not passed
 *   cli_port      : CLI --control-port value (only meaningful when cli_port_set != 0)
 *   cli_port_set  : 1 iff --control-port was passed (so 0 means explicit disable)
 *   addr_buf      : caller-provided storage; *out_addr may point into it on return
 *   addr_buf_len  : capacity of addr_buf, must be >= 1
 *
 *   *out_addr     : NULL (control_socket defaults to 127.0.0.1) or a pointer
 *                   that lives at least as long as addr_buf and cli_addr
 *   *out_port     : 0 → control API disabled; >0 → bind on this port
 *
 * Returns 0 on success, -1 if file_listen is set but malformed.
 */
int mqvpn_resolve_control_endpoint(const char *file_listen, const char *cli_addr,
                                   int cli_port, int cli_port_set, char *addr_buf,
                                   size_t addr_buf_len, const char **out_addr,
                                   int *out_port);

#endif /* MQVPN_CONFIG_H */
