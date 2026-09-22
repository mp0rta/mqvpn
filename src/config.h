// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

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

#include "libmqvpn.h"          /* for MQVPN_MAX_PATHS, MQVPN_MAX_USERS */
#include "reorder.h"           /* for embedded mqvpn_reorder_config_t (§16.1 INI) */
#include "hybrid/classifier.h" /* for embedded mqvpn_hybrid_config_t ([Hybrid]) */

#define MQVPN_CONFIG_MAX_PATHS 8
#define MQVPN_CONFIG_MAX_DNS   4
#define MQVPN_CONFIG_MAX_USERS 64
/* Largest value accepted for the four [Advanced] receive-buffer limits. */
#define MQVPN_CONFIG_MAX_BUF_LIMIT 0xffffffffULL
_Static_assert(MQVPN_CONFIG_MAX_PATHS == MQVPN_MAX_PATHS,
               "Config path cap must equal library cap (libmqvpn.h)");
_Static_assert(MQVPN_CONFIG_MAX_USERS == MQVPN_MAX_USERS,
               "Config user cap must equal library cap (libmqvpn.h)");

typedef struct mqvpn_file_config_s {
    /* [Interface] — common */
    char tun_name[32];
    char log_level[16];

    /* [Interface] — server */
    char listen[280]; /* "bind:port" */
    char subnet[32];
    char subnet6[64]; /* IPv6 tunnel subnet CIDR (e.g. "fd00:abcd::/112") */

    /* [Interface] — client */
    char dns_servers[MQVPN_CONFIG_MAX_DNS][64];
    int n_dns;

    /* [Server] — client */
    char server_addr[280]; /* "host:port" */
    char tls_server_name[256];
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
    char cc[16]; /* congestion control: bbr2 (default), bbr, cubic, none */

    char reinjection[16];                    /* "off" | "deadline" | "idle" | "dgram" */
    int reinjection_srtt_factor_pct;         /* deadline mode only; [100,1000] */
    int reinjection_hard_deadline_ms;        /* deadline mode only; [1,60000] */
    int reinjection_deadline_lower_bound_ms; /* deadline mode only; [1,60000] */

    /* draft-21 §4.6 initial Maximum Path Identifier TP, 0 = use xquic default 8 */
    unsigned long long init_max_path_id;

    /* [Interface] — client reconnection */
    int reconnect;          /* 1=auto-reconnect (default), 0=exit on disconnect */
    int reconnect_interval; /* base interval in seconds (default 5) */
    int kill_switch;        /* 1=block traffic outside tunnel, 0=off (default) */
    int manage_routes; /* 1=manage host routes (default), 0=skip routing table setup */

    int tun_mtu; /* [Interface] MTU — 0=auto, >0=cap (floor 1280) */

    /* [Reorder] / repeated [ReorderRule] — flow-aware reorder shim (§16.1).
     * Seeded with mqvpn_reorder_config_default() in mqvpn_config_defaults(). */
    mqvpn_reorder_config_t reorder;

    /* [Hybrid] — hybrid-mode ingress classifier policy (H1).
     * Seeded with mqvpn_hybrid_config_default() in mqvpn_config_defaults(). */
    mqvpn_hybrid_config_t hybrid;

    /* [Advanced] — cross-cutting QUIC transport knobs. recv_rate_limit:
     * conn-level receive-rate cap in bytes/sec, 0 = library default (off).
     * CLIENT-ONLY by policy — see mqvpn_conn_settings.c. */
    uint64_t recv_rate_limit;

    /* [Advanced] UdpGso — Linux TX UDP GSO/batched send; 1 (default) =
     * engage when the kernel supports it, 0 = per-packet send path. Applies
     * to both client and server (unlike recv_rate_limit). */
    int udp_gso;

    /* [Advanced] UdpGro — Linux RX UDP GRO (kernel-coalesced receive);
     * 1 (default) = set SOL_UDP/UDP_GRO on every path/listen socket when the
     * kernel supports it, 0 = one datagram per recvmsg. Applies to both
     * client and server. Platform-side only: unlike udp_gso it never crosses
     * the library ABI. */
    int udp_gro;

    /* [Advanced] H3BodyBufPerStream — buffered HTTP/3 DATA payload one
     * request may hold. Bytes; 0 = leave xquic's own default alone. Client
     * and server, unlike recv_rate_limit above. Sets
     * xqc_conn_settings_t.max_body_buf_per_stream; a build whose xquic has no
     * such field refuses to start when this is non-zero — see
     * mqvpn_config_unsupported_buf_limit() below. */
    uint64_t h3_body_buf_per_stream;

    /* [Advanced] BlockedBufPerStream / BlockedBufPerConn — set
     * xqc_conn_settings_t.max_blocked_buf_per_stream / _per_conn, the QPACK
     * decode-blocked buffer per stream and per connection. Exceeding either
     * closes the HTTP/3 connection with H3_EXCESSIVE_LOAD
     * (third_party/xquic/src/http3/xqc_h3_stream.c). 0 leaves xquic's own
     * defaults; website/guide/configuration.md has the rest. */
    uint64_t blocked_buf_per_stream;
    uint64_t blocked_buf_per_conn;

    /* [Advanced] MaxRecvWindow — ceiling on the per-stream receive window,
     * bytes; 0 = xquic's own default. Sets
     * xqc_conn_settings_t.max_recv_window, with the same refusal as above
     * where the field is absent. */
    uint64_t max_recv_window;

    /* Inferred mode: 1=server, 0=client */
    int is_server;
} mqvpn_file_config_t;

/* Fill cfg with default values */
void mqvpn_config_defaults(mqvpn_file_config_t *cfg);

/* Parse INI file at path into cfg. Returns 0 on success, -1 on error. */
int mqvpn_config_load(mqvpn_file_config_t *cfg, const char *path);

/* Parse JSON text into CLI cfg. Returns 0 on success, -1 on error. */
int mqvpn_config_load_json_filecfg(mqvpn_file_config_t *cfg, const char *json_text);

/* Returns the [Advanced] key name of the first receive-buffer limit that is
 * set to a non-zero value but whose xqc_conn_settings_t field is missing from
 * the xquic this build links against, or NULL when every limit that is set
 * can be applied. All-zero always returns NULL: 0 means "leave xquic's own
 * default alone" and needs no field.
 *
 * CMake probes for the two fields that may be absent and defines
 * MQVPN_HAVE_XQC_* for the ones it finds. src/main.c calls this once after
 * the config is loaded, below the --status early exit, and refuses to
 * start. */
const char *mqvpn_config_unsupported_buf_limit(const mqvpn_file_config_t *cfg);

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
