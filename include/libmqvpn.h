// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * libmqvpn — Multipath QUIC VPN library
 *
 * Public API header (single file).
 * Version: 0.8.0 (callback ABI version 2)
 *
 * Thread safety: All functions must be called from a single thread
 * (the "tick thread"). Debug builds assert this via MQVPN_ASSERT_TICK_THREAD.
 */

#ifndef LIBMQVPN_H
#define LIBMQVPN_H

#include <stddef.h>
#include <stdint.h>
#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <sys/socket.h> /* socklen_t, struct sockaddr */
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ─── Visibility ─── */

#ifdef _WIN32
#  define MQVPN_API __declspec(dllexport)
#else
#  define MQVPN_API __attribute__((visibility("default")))
#endif

/* ─── Version ─── */

#define MQVPN_VERSION_MAJOR 0
#define MQVPN_VERSION_MINOR 8
#define MQVPN_VERSION_PATCH 0

/* ─── ABI ─── */

#define MQVPN_CALLBACKS_ABI_VERSION 2

/* ─── Capacity constants ─── */

#define MQVPN_MAX_USERS            64
#define MQVPN_MAX_PATHS            8
#define MQVPN_INIT_MAX_PATH_ID_MAX UINT64_C(0xffffffff)

/* ─── Opaque handles ─── */

typedef struct mqvpn_client_s mqvpn_client_t;
typedef struct mqvpn_server_s mqvpn_server_t;
typedef struct mqvpn_config_s mqvpn_config_t;

typedef int64_t mqvpn_path_handle_t;

/* ─── Error codes ─── */

typedef enum {
    MQVPN_OK = 0,
    MQVPN_ERR_INVALID_ARG = -1,
    MQVPN_ERR_NO_MEMORY = -2,
    MQVPN_ERR_ENGINE = -3,         /* xquic engine error */
    MQVPN_ERR_TLS = -4,            /* TLS handshake failure */
    MQVPN_ERR_AUTH = -5,           /* PSK auth failure (403) */
    MQVPN_ERR_PROTOCOL = -6,       /* MASQUE not supported */
    MQVPN_ERR_POOL_FULL = -7,      /* server: IP pool exhausted */
    MQVPN_ERR_MAX_CLIENTS = -8,    /* server: max clients reached */
    MQVPN_ERR_AGAIN = -9,          /* back-pressure */
    MQVPN_ERR_CLOSED = -10,        /* connection closed */
    MQVPN_ERR_ABI_MISMATCH = -11,  /* callback ABI version mismatch */
    MQVPN_ERR_TIMEOUT = -12,       /* connection timeout */
    MQVPN_ERR_INVALID_STATE = -13, /* operation not valid in current state */
} mqvpn_error_t;

/* ─── Enumerations ─── */

#ifndef MQVPN_LOG_LEVEL_DEFINED
#  define MQVPN_LOG_LEVEL_DEFINED
typedef enum {
    MQVPN_LOG_DEBUG = 0,
    MQVPN_LOG_INFO = 1,
    MQVPN_LOG_WARN = 2,
    MQVPN_LOG_ERROR = 3,
} mqvpn_log_level_t;
#endif

typedef enum {
    MQVPN_MODE_CLIENT = 0,
    MQVPN_MODE_SERVER = 1,
} mqvpn_mode_t;

typedef enum {
    MQVPN_SCHED_MINRTT = 0,
    MQVPN_SCHED_WLB = 1,
    MQVPN_SCHED_BACKUP_FEC =
        2, /* FEC repair on standby path. Requires XQC_ENABLE_FEC build. */
    MQVPN_SCHED_WLB_UDP_PIN = 3, /* WLB + 5-tuple pin for UDP flows. */
} mqvpn_scheduler_t;

/* Flow-aware reorder-only datagram delivery (see reorder design spec).
 * AUTO is deferred to a later phase and will be appended as = 2. */
typedef enum {
    MQVPN_REORDER_OFF = 0,
    MQVPN_REORDER_ON = 1,
} mqvpn_reorder_mode_t;

/* Per-rule reorder profile (§16.1). Values 0/1/2 are ABI-fixed; presets are
 * appended (cellular_bond/fiber_lte) so the enum is no longer 3-valued. */
typedef enum {
    MQVPN_RPROF_QUIC_BULK = 0,     /* back-compat alias of CELLULAR_BOND preset */
    MQVPN_RPROF_LOW_LATENCY = 1,   /* reserved; no preset in v1 (inert) */
    MQVPN_RPROF_DEFAULT_UDP = 2,   /* matched but no reorder (OFF class) */
    MQVPN_RPROF_CELLULAR_BOND = 3, /* preset: wait=50ms cap=1024 */
    MQVPN_RPROF_FIBER_LTE = 4,     /* preset: wait=50ms cap=2048 */
} mqvpn_reorder_profile_t;

typedef enum {
    MQVPN_CC_BBR2 = 0, /* default */
    MQVPN_CC_BBR = 1,
    MQVPN_CC_CUBIC = 2,
    MQVPN_CC_NONE = 3, /* unlimited / no congestion control */
} mqvpn_cc_t;

typedef enum {
    MQVPN_STATE_IDLE = 0,
    MQVPN_STATE_CONNECTING = 1,
    MQVPN_STATE_AUTHENTICATING = 2,
    MQVPN_STATE_TUNNEL_READY = 3,
    MQVPN_STATE_ESTABLISHED = 4,
    MQVPN_STATE_RECONNECTING = 5,
    MQVPN_STATE_CLOSED = 6,
    MQVPN_STATE__COUNT = 7,
} mqvpn_client_state_t;

/*
 * Path lifecycle:
 *   platform_attached = platform owns this path slot, fd is valid
 *   xquic_path_live   = xquic has a live QUIC path on this slot
 *
 *   PENDING   → add_path_fd() called, awaiting activation
 *   ACTIVE    → xquic path created (validation async)
 *   DEGRADED  → transport failed, library timer retries with backoff (5s→60s, max 6)
 *   CLOSED    → retries exhausted (platform can still call reactivate_path if
 * platform_attached==1) OR explicitly removed via remove_path() (platform_attached==0, no
 * recovery)
 */
typedef enum {
    MQVPN_PATH_PENDING = 0,
    MQVPN_PATH_ACTIVE = 1,
    MQVPN_PATH_DEGRADED = 2,
    MQVPN_PATH_STANDBY = 3,
    MQVPN_PATH_CLOSED = 4,
} mqvpn_path_status_t;

MQVPN_API const char *mqvpn_path_status_string(mqvpn_path_status_t status);

/*
 * Outcome of the synchronous half of mqvpn_client_add_path_fd_with_outcome().
 *
 * After add_path_fd, the slot has been registered and (if multipath is
 * already negotiated) activation has been attempted in the same call. The
 * outcome reports what that synchronous attempt produced:
 *
 *   OK              — handle stored. Either activation succeeded (xqc path
 *                     created; PATH_CHALLENGE validation will complete async
 *                     and the slot will land in ACTIVE/STANDBY when xquic
 *                     reports XQC_PATH_STATE_ACTIVE), OR multipath wasn't
 *                     ready yet and activation will fire from
 *                     cb_ready_to_create_path when handshake completes.
 *                     In both cases the caller should keep the fd.
 *
 *   TRANSIENT_FAIL  — xqc_conn_create_path returned a recoverable error
 *                     (e.g. -XQC_EMP_NO_AVAIL_PATH_ID — server hasn't
 *                     distributed CIDs yet). The library's tick recovery
 *                     loop will retry with exponential backoff. The
 *                     platform layer typically rolls back the fd here
 *                     so a fresh re-add starts from a clean state.
 *
 *   PERMANENT_FAIL  — xqc_conn_create_path returned -XQC_EMP_CREATE_PATH
 *                     (XQC_MAX_PATHS_COUNT cap hit or OOM). The slot is
 *                     marked CLOSED; recovery requires a Level-2 reconnect
 *                     that resets the path_id namespace.
 *
 * The legacy add_path_fd() always succeeds at the handle layer (returning
 * the handle) and silently swallows TRANSIENT_FAIL / PERMANENT_FAIL; the
 * caller has to poll status via mqvpn_client_get_paths to discover them.
 * The with_outcome variant exists because that poll loses information:
 * PR3's PATH_LC_VALIDATING and PATH_LC_CREATE_WAIT both project to
 * MQVPN_PATH_PENDING, so status alone cannot tell sync success from
 * sync transient failure. Platform recovery (RTM_NEWLINK after a
 * carrier-loss drop_path) needs this distinction to avoid rolling back
 * a successful activation and burning xqc path_id budget — see
 * platform_linux::try_readd_removed_path().
 */
typedef enum {
    MQVPN_ADD_PATH_OK = 0,
    MQVPN_ADD_PATH_TRANSIENT_FAIL = 1,
    MQVPN_ADD_PATH_PERMANENT_FAIL = 2,
} mqvpn_add_path_outcome_t;

/*
 * Optional info accompanying a platform path event notification.
 *
 * Fields:
 *   iface  - interface name (NUL-terminated, may be empty if N/A).
 *            Diagnostic only - library does not parse this.
 *   reason - platform-specific reason code. Currently only
 *            MQVPN_PLATFORM_REASON_RTM_DELLINK is emitted (Linux PR5).
 *            Library does not branch on this - log only.
 *            More values added when concrete emitter ships (CARRIER_LOST,
 *            NM_IFDOWN, iOS variants etc) - ABI-additive.
 *
 * Future: `platform_net_id` (Android Network handle) is intentionally NOT
 * included now. Android path management uses existing
 * `mqvpn_client_add_path_fd` / `mqvpn_client_remove_path` per spec sec 3.4 /
 * sec 10.2, so this struct's caller is currently Linux-only.
 *
 * Caller may pass NULL info to mqvpn_client_on_platform_path_dropped() for
 * "drop with no diagnostic context" (legacy mqvpn_client_drop_path()
 * semantic). */
typedef enum {
    MQVPN_PLATFORM_REASON_UNKNOWN = 0,
    MQVPN_PLATFORM_REASON_RTM_DELLINK = 1,
    /* extend ABI-additively when concrete emitter ships:
     * MQVPN_PLATFORM_REASON_CARRIER_LOST = 2,
     * MQVPN_PLATFORM_REASON_NM_IFDOWN    = 3, ... */
} mqvpn_platform_reason_t;

typedef struct {
    char iface[16]; /* iface name, "" if N/A */
    mqvpn_platform_reason_t reason;
} mqvpn_platform_path_event_info_t;

/* ─── Data structures ─── */

typedef struct {
    uint32_t struct_size;
    uint8_t assigned_ip[4]; /* IPv4 tunnel IP (network order) */
    uint8_t assigned_prefix;
    uint8_t server_ip[4]; /* server tunnel IP */
    uint8_t server_prefix;
    int mtu;
    uint8_t assigned_ip6[16]; /* IPv6 tunnel IP (all-zero = none) */
    uint8_t assigned_prefix6;
    int has_v6; /* 1 = IPv6 assigned */
} mqvpn_tunnel_info_t;

typedef struct {
    uint32_t struct_size;
    uint64_t bytes_tx;
    uint64_t bytes_rx;
    uint64_t dgram_sent;
    uint64_t dgram_recv;
    uint64_t dgram_lost;
    uint64_t dgram_acked;
    int srtt_ms;
    /* Hybrid-mode per-lane counters (0 unless hybrid classifier active). */
    uint64_t pkts_lane_tcp;
    uint64_t pkts_lane_dgram;
    uint64_t pkts_lane_raw;
    uint64_t tcp_flows_active;   /* future tcp_lane; 0 for now */
    uint64_t tcp_flows_total;    /* future tcp_lane; 0 for now */
    uint64_t tcp_flows_rejected; /* future tcp_lane; 0 for now */
} mqvpn_stats_t;

typedef struct {
    uint32_t struct_size;
    mqvpn_path_handle_t handle;
    mqvpn_path_status_t status;
    char name[16]; /* interface name */
    int srtt_ms;
    uint64_t bytes_tx;
    uint64_t bytes_rx;
} mqvpn_path_info_t;

typedef struct {
    uint32_t struct_size;
    uint64_t path_id;
    uint64_t srtt_us;
    uint64_t min_rtt_us;
    uint64_t cwnd;
    uint64_t bytes_in_flight;
    uint64_t bytes_tx;
    uint64_t bytes_rx;
    uint64_t pkt_sent;
    uint64_t pkt_recv;
    uint64_t pkt_lost;
    uint8_t state;
} mqvpn_path_stats_t;

typedef struct {
    uint32_t struct_size;
    char username[64];
    char endpoint[64];
    uint64_t connected_at_us;
    uint64_t bytes_tx;
    uint64_t bytes_rx;
    mqvpn_path_stats_t paths[MQVPN_MAX_PATHS];
    int n_paths;
} mqvpn_client_info_t;

typedef struct {
    uint32_t struct_size;
    int next_timer_ms; /* ms until next tick() needed */
    int tun_readable;  /* 1 = accept on_tun_packet */
    int is_idle;       /* 1 = no active streams */
} mqvpn_interest_t;

typedef struct {
    uint32_t struct_size;
    int fd;                  /* UDP socket fd (-1 = ops path) */
    char iface[16];          /* interface name (optional) */
    uint8_t local_addr[128]; /* sockaddr storage */
    uint32_t local_addr_len;
    int64_t platform_net_id; /* Android: Network handle */
    uint32_t flags;
} mqvpn_path_desc_t;

/* ─── Callback function types ─── */

typedef void (*mqvpn_tun_output_fn)(const uint8_t *pkt, size_t len, void *user_ctx);

typedef void (*mqvpn_tunnel_config_ready_fn)(const mqvpn_tunnel_info_t *info,
                                             void *user_ctx);

typedef void (*mqvpn_send_packet_fn)(mqvpn_path_handle_t path, const uint8_t *pkt,
                                     size_t len, const struct sockaddr *peer,
                                     socklen_t peer_len, void *user_ctx);

typedef void (*mqvpn_tunnel_closed_fn)(mqvpn_error_t reason, void *user_ctx);

typedef void (*mqvpn_ready_for_tun_fn)(void *user_ctx);

typedef void (*mqvpn_state_changed_fn)(mqvpn_client_state_t old_state,
                                       mqvpn_client_state_t new_state, void *user_ctx);

/* Path lifecycle observer.
 *
 * Fires on every state transition: PENDING → ACTIVE, ACTIVE → DEGRADED,
 * DEGRADED → CLOSED, etc. Observers should treat this as the authoritative
 * source of truth for a handle's lifecycle.
 *
 * RE-ENTRANCY CONTRACT: this callback MAY be invoked synchronously from
 * inside `mqvpn_client_add_path_fd()`, `mqvpn_client_remove_path()`,
 * `mqvpn_client_drop_path()` and `mqvpn_client_reactivate_path()` —
 * i.e. the event can fire BEFORE the call returns, and for `add_path_fd`
 * even before the caller receives the handle. Callers that store
 * handle → observer mappings must therefore either (a) ignore events
 * for handles they have not yet recorded (works for `add_path_fd`),
 * or (b) snapshot status via `mqvpn_client_get_paths()` after the call
 * returns (works for all four entry points). */
typedef void (*mqvpn_path_event_fn)(mqvpn_path_handle_t path, mqvpn_path_status_t status,
                                    void *user_ctx);

typedef void (*mqvpn_mtu_updated_fn)(int mtu, void *user_ctx);

typedef void (*mqvpn_log_fn)(mqvpn_log_level_t level, const char *msg, void *user_ctx);

/* ─── Client callback table ─── */

typedef struct {
    uint32_t abi_version; /* MQVPN_CALLBACKS_ABI_VERSION */
    uint32_t struct_size;

    /* REQUIRED */
    mqvpn_tun_output_fn tun_output;
    mqvpn_tunnel_config_ready_fn tunnel_config_ready;
    mqvpn_send_packet_fn send_packet; /* NULL = fd-only mode */

    /* RECOMMENDED */
    mqvpn_tunnel_closed_fn tunnel_closed;
    mqvpn_ready_for_tun_fn ready_for_tun;

    /* OPTIONAL */
    mqvpn_state_changed_fn state_changed;
    mqvpn_path_event_fn path_event;
    mqvpn_mtu_updated_fn mtu_updated;
    mqvpn_log_fn log;

    /* v5: reconnect control */
    void (*reconnect_scheduled)(int delay_sec, void *user_ctx);
} mqvpn_client_callbacks_t;

#define MQVPN_CLIENT_CALLBACKS_INIT                      \
    {                                                    \
        .abi_version = MQVPN_CALLBACKS_ABI_VERSION,      \
        .struct_size = sizeof(mqvpn_client_callbacks_t), \
    }

_Static_assert(offsetof(mqvpn_client_callbacks_t, abi_version) == 0,
               "abi_version must be at offset 0");

/* ─── Server callback table ─── */

typedef struct {
    uint32_t abi_version;
    uint32_t struct_size;

    mqvpn_tun_output_fn tun_output;                   /* REQUIRED */
    mqvpn_tunnel_config_ready_fn tunnel_config_ready; /* REQUIRED */
    mqvpn_send_packet_fn send_packet;                 /* NULL = fd-only mode */

    mqvpn_log_fn log;
    void (*on_client_connected)(const mqvpn_tunnel_info_t *info, uint32_t session_id,
                                void *user_ctx);
    void (*on_client_disconnected)(uint32_t session_id, mqvpn_error_t reason,
                                   void *user_ctx);

    /* v6: hybrid TCP lane egress fd interest (OPTIONAL — NULL disables
     * tcp_egress; connect-tcp-style requests get 503 if unset). The core
     * (src/hybrid/tcp_egress.c) owns every egress fd's socket()/connect()/
     * send()/recv()/close() syscalls directly — same "fd-path mode"
     * convention the client's UDP path fds already use. These two
     * callbacks only ask the platform to (un)register interest in an
     * ALREADY-OPEN fd with its reactor. want_read/want_write may be
     * updated on an already-registered fd (egress_fd_register is called
     * again with new flags, not just once at creation) — on Linux this
     * means replacing the libevent event, not mutating one in place. */
    void (*egress_fd_register)(int fd, int want_read, int want_write, void *fd_ctx,
                               void *user_ctx);
    void (*egress_fd_unregister)(int fd, void *user_ctx);
} mqvpn_server_callbacks_t;

#define MQVPN_SERVER_CALLBACKS_INIT                      \
    {                                                    \
        .abi_version = MQVPN_CALLBACKS_ABI_VERSION,      \
        .struct_size = sizeof(mqvpn_server_callbacks_t), \
    }

_Static_assert(offsetof(mqvpn_server_callbacks_t, abi_version) == 0,
               "abi_version must be at offset 0");

/* ─── Configuration API ─── */

MQVPN_API mqvpn_config_t *mqvpn_config_new(void);
MQVPN_API void mqvpn_config_free(mqvpn_config_t *cfg);

MQVPN_API int mqvpn_config_set_server(mqvpn_config_t *cfg, const char *host, int port);
MQVPN_API int mqvpn_config_set_tls_server_name(mqvpn_config_t *cfg, const char *name);
MQVPN_API int mqvpn_config_set_auth_key(mqvpn_config_t *cfg, const char *key);
MQVPN_API int mqvpn_config_add_user(mqvpn_config_t *cfg, const char *username,
                                    const char *key);
MQVPN_API int mqvpn_config_remove_user(mqvpn_config_t *cfg, const char *username);
MQVPN_API int mqvpn_config_load_json(mqvpn_config_t *cfg, const char *json_text);
MQVPN_API int mqvpn_config_set_insecure(mqvpn_config_t *cfg, int insecure);
MQVPN_API int mqvpn_config_set_scheduler(mqvpn_config_t *cfg, mqvpn_scheduler_t sched);
MQVPN_API int mqvpn_config_set_cc(mqvpn_config_t *cfg, mqvpn_cc_t cc);
MQVPN_API int mqvpn_config_set_log_level(mqvpn_config_t *cfg, mqvpn_log_level_t level);
MQVPN_API int mqvpn_config_set_multipath(mqvpn_config_t *cfg, int enable);
MQVPN_API int mqvpn_config_set_reconnect(mqvpn_config_t *cfg, int enable,
                                         int interval_sec);
MQVPN_API int mqvpn_config_set_killswitch_hint(mqvpn_config_t *cfg, int enable);

/* draft-21 §4.6: set the initial Maximum Path Identifier advertised in TP.
 * 0 = use xquic default (XQC_DEFAULT_INIT_MAX_PATH_ID = 8). Valid explicit
 * values are 1..MQVPN_INIT_MAX_PATH_ID_MAX. Set lower (e.g. 2) to
 * deterministically trigger G-P16 PATHS_BLOCKED. */
MQVPN_API int mqvpn_config_set_init_max_path_id(mqvpn_config_t *cfg, uint64_t v);
/* TUN MTU cap: 0 = auto (MSS-derived), 1280..9000 = upper bound. */
MQVPN_API int mqvpn_config_set_tun_mtu(mqvpn_config_t *cfg, int mtu);

/* ─── Flow-aware reorder shim config (§16.1) ───
 *
 * These mirror the reorder design spec's builder surface. Values are validated
 * (cross-side invariants like cap-power-of-two and ingress < egress) when the
 * config is applied by the library, not by the setters. Calling none of these
 * leaves the shim disabled (mode OFF, the default). */
MQVPN_API int mqvpn_config_set_reorder_enabled(mqvpn_config_t *cfg,
                                               mqvpn_reorder_mode_t mode);
MQVPN_API int mqvpn_config_set_reorder_wait(mqvpn_config_t *cfg, uint32_t max_wait_ms);
MQVPN_API int mqvpn_config_set_reorder_cap(mqvpn_config_t *cfg, uint32_t cap_packets,
                                           uint64_t max_bytes_per_flow);
MQVPN_API int mqvpn_config_set_reorder_classify(mqvpn_config_t *cfg, uint16_t window,
                                                uint16_t max_large,
                                                uint32_t small_threshold);
MQVPN_API int mqvpn_config_set_reorder_reset(mqvpn_config_t *cfg, uint32_t mark_packets,
                                             uint32_t idle_grace_ms);
MQVPN_API int mqvpn_config_set_reorder_limits(mqvpn_config_t *cfg, uint32_t max_flows,
                                              uint64_t global_max_bytes,
                                              uint32_t ingress_idle_sec,
                                              uint32_t egress_idle_sec);
/* Append one port/protocol → profile rule. Rules are matched in insertion
 * order. Returns MQVPN_ERR_INVALID_ARG if more than the fixed rule cap are
 * added or the profile enum is out of range. */
MQVPN_API int mqvpn_config_add_reorder_rule(mqvpn_config_t *cfg, uint8_t proto,
                                            uint16_t port,
                                            mqvpn_reorder_profile_t profile);

/* ─── Hybrid-mode config (H1) ───
 *
 * Hybrid mode classifies inner TUN packets into per-lane transports (TCP
 * stream lane / datagram lane / raw CONNECT-IP lane). Disabled by default.
 * The TCP mode enum stays internal; the setter takes a plain int:
 * 0 = stream (always use the TCP stream lane), 1 = raw (never), 2 = auto
 * (per-flow decision at SYN time, the default). */
MQVPN_API int mqvpn_config_set_hybrid_enabled(mqvpn_config_t *cfg, int enabled);
/* mode: 0=stream 1=raw 2=auto. Other values → MQVPN_ERR_INVALID_ARG. */
MQVPN_API int mqvpn_config_set_hybrid_tcp_mode(mqvpn_config_t *cfg, int mode);
/* Limits for the future tcp_lane. tcp_max_flows must be > 0 (defaults:
 * 256 flows, 300 s idle timeout). */
MQVPN_API int mqvpn_config_set_hybrid_limits(mqvpn_config_t *cfg, uint32_t tcp_max_flows,
                                             uint32_t tcp_idle_timeout_sec);
/* Server-side egress connect() timeout for the connect-tcp lane, in
 * seconds (default 10). sec must be > 0. */
MQVPN_API int mqvpn_config_set_hybrid_connect_timeout(mqvpn_config_t *cfg, uint32_t sec);
/* Server-wide cap on concurrent egress TCP fds the connect-tcp lane will
 * ever open (default MQVPN_TCP_MAX_GLOBAL_FLOWS_DEFAULT = 4096), narrowed
 * further at startup by available rlimit headroom — see
 * mqvpn_server_egress_fd_budget(). Distinct from
 * mqvpn_config_set_hybrid_limits()'s tcp_max_flows, which caps concurrent
 * flows per H3 connection, not server-wide. max_flows must be > 0. */
MQVPN_API int mqvpn_config_set_hybrid_max_global_flows(mqvpn_config_t *cfg,
                                                       uint32_t max_flows);
/* Egress ACL for the connect-tcp lane's destination check (server-side
 * only; harmless but unused on clients). `allow` punches holes through the
 * mandatory default-deny (loopback/RFC1918/link-local/CGNAT/multicast/
 * broadcast/the server's own tunnel subnet); `deny` adds extra blocks
 * evaluated after the default-deny set. Each entry is a strict "a.b.c.d/n"
 * IPv4 CIDR string (n = 0..32, no bare-address form). Unlike the INI/JSON
 * file-config loaders (which skip malformed entries with a warning), this
 * setter validates the WHOLE call atomically: any malformed entry rejects
 * the entire call with MQVPN_ERR_INVALID_ARG and leaves cfg unmodified.
 * n_allow/n_deny may be 0 with allow/deny NULL; either list capped at
 * MQVPN_EGRESS_ACL_MAX entries (src/hybrid/classifier.h). Caution:
 * "0.0.0.0/0" in the allow list disables the built-in protections
 * (loopback/RFC1918/...); enumerate specific ranges instead. */
MQVPN_API int mqvpn_config_set_hybrid_egress_acl(mqvpn_config_t *cfg, const char **allow,
                                                 int n_allow, const char **deny,
                                                 int n_deny);

/* Clock injection (Android: CLOCK_BOOTTIME, testing: mock clock) */
typedef uint64_t (*mqvpn_clock_fn)(void *ctx);
MQVPN_API int mqvpn_config_set_clock(mqvpn_config_t *cfg, mqvpn_clock_fn clock_fn,
                                     void *clock_ctx);

/* Server-only config */
MQVPN_API int mqvpn_config_set_listen(mqvpn_config_t *cfg, const char *addr, int port);
MQVPN_API int mqvpn_config_set_subnet(mqvpn_config_t *cfg, const char *cidr);
MQVPN_API int mqvpn_config_set_subnet6(mqvpn_config_t *cfg, const char *cidr6);
MQVPN_API int mqvpn_config_set_tls_cert(mqvpn_config_t *cfg, const char *cert,
                                        const char *key);
MQVPN_API int mqvpn_config_set_max_clients(mqvpn_config_t *cfg, int max);

/* ─── Client API ─── */

MQVPN_API mqvpn_client_t *mqvpn_client_new(const mqvpn_config_t *cfg,
                                           const mqvpn_client_callbacks_t *cbs,
                                           void *user_ctx);

MQVPN_API void mqvpn_client_destroy(mqvpn_client_t *client);

MQVPN_API int mqvpn_client_connect(mqvpn_client_t *client);
MQVPN_API int mqvpn_client_disconnect(mqvpn_client_t *client);

MQVPN_API mqvpn_path_handle_t mqvpn_client_add_path_fd(mqvpn_client_t *client, int fd,
                                                       const mqvpn_path_desc_t *desc);

/*
 * Same as mqvpn_client_add_path_fd() but reports the outcome of the
 * synchronous activation attempt via *outcome. See mqvpn_add_path_outcome_t
 * for the three outcomes. If `outcome` is NULL, behaves identically to
 * mqvpn_client_add_path_fd().
 *
 * Returns the path handle (>= 0) on success, or -1 if the slot table is
 * full / args are invalid (in which case *outcome is not written).
 *
 * Use this in platform recovery paths (RTM_NEWLINK / NotifyUnicastIpAddress
 * Change / NWPathMonitor) where the caller needs to distinguish:
 *   - sync activation succeeded → keep the fd
 *   - sync transient failure → close fd, let the recovery timer retry
 *   - permanent failure (xqc path budget exhausted) → give up on this conn
 *
 * Because PATH_LC_VALIDATING (xqc path created, async validation pending)
 * and PATH_LC_CREATE_WAIT (sync activate failed transiently) both project
 * to MQVPN_PATH_PENDING in the public 5-state status, querying status
 * via mqvpn_client_get_paths after add_path_fd cannot make this
 * distinction — this API does.
 */
MQVPN_API mqvpn_path_handle_t mqvpn_client_add_path_fd_with_outcome(
    mqvpn_client_t *client, int fd, const mqvpn_path_desc_t *desc,
    mqvpn_add_path_outcome_t *outcome);

MQVPN_API int mqvpn_client_remove_path(mqvpn_client_t *client, mqvpn_path_handle_t path);

/*
 * Drop a path slot without notifying xquic (no PATH_ABANDON, no draining).
 * Used when the platform detects interface removal (RTM_DELLINK) — the fd is
 * already dead, so xquic will detect the failure naturally via sendto() errors
 * (same as link-down). This frees the slot for re-use by add_path_fd().
 */
MQVPN_API int mqvpn_client_drop_path(mqvpn_client_t *client, mqvpn_path_handle_t path);

/*
 * Platform reports that a path is no longer reachable via its current fd
 * (carrier loss, RTM_DELLINK, NotifyIpInterfaceChange ifDown, etc).
 *
 * Library transitions the slot to PATH_CLOSED_DROPPED (via EVENT_PLATFORM_DROP).
 * The fd is left for the platform to close; call
 * mqvpn_client_on_platform_fd_closed() after close() to drive the lazy
 * CLOSED_DROPPED -> CLOSED_FREE cleanup.
 *
 * info may be NULL - in that case behaves identically to
 * mqvpn_client_drop_path() with no diagnostic context.
 *
 * Returns MQVPN_OK on success, MQVPN_ERR_INVALID_ARG on bad client/handle. */
MQVPN_API int
mqvpn_client_on_platform_path_dropped(mqvpn_client_t *client, mqvpn_path_handle_t handle,
                                      const mqvpn_platform_path_event_info_t *info);

/*
 * Platform reports that the fd for the given path has been closed.
 *
 * Library sets p->fd = -1 and re-evaluates the CLOSED_DROPPED ->
 * CLOSED_FREE cleanup completion.
 *
 * Returns:
 *   MQVPN_OK              - handle found; FSM dispatched. Late-arrival on
 *                           a slot already past CLOSED_DROPPED is treated
 *                           as a benign race (LOG_D + no state change).
 *   MQVPN_ERR_INVALID_ARG - client is NULL, or handle is unknown to the
 *                           library (caller bug: handle freed and reused,
 *                           or never registered).
 *
 * Call this AFTER mqvpn_client_on_platform_path_dropped() (or the legacy
 * mqvpn_client_drop_path()), AFTER your close(fd). */
MQVPN_API int mqvpn_client_on_platform_fd_closed(mqvpn_client_t *client,
                                                 mqvpn_path_handle_t handle);

/*
 * Re-activate a DEGRADED or CLOSED path using the existing fd.
 * Called by the platform layer when it detects the path is viable again
 * (e.g., netlink RTM_NEWADDR on Linux, NotifyUnicastIpAddressChange on
 * Windows keyed by NET_LUID, NWPathMonitor on macOS for Wi-Fi/Ethernet flap).
 *
 * NOT applicable to platforms whose APIs invalidate path identity on loss
 * and deliver a fresh handle on recovery (Android ConnectivityManager Network,
 * iOS NEPacketTunnelProvider where socket-to-interface bindings are invalidated
 * when the underlying interface re-attaches, e.g. cellular handoff). Those
 * platforms should call remove_path() + a new add_path_fd() with a fresh fd
 * instead.
 *
 * Preconditions: !xquic_path_live && platform_attached && (DEGRADED || CLOSED).
 * On success: xquic creates a new path (validation is async). The library
 * recovery timer is cancelled. Retry counter resets after 30s stability.
 *
 * Returns MQVPN_OK, MQVPN_ERR_INVALID_ARG, MQVPN_ERR_INVALID_STATE, or
 * MQVPN_ERR_ENGINE.
 * Thread safety: must be called from the tick thread (same as all other APIs).
 */
MQVPN_API int mqvpn_client_reactivate_path(mqvpn_client_t *client,
                                           mqvpn_path_handle_t path);

MQVPN_API int mqvpn_client_set_tun_active(mqvpn_client_t *client, int active, int tun_fd);

/* Feed data from platform into the engine */
MQVPN_API int mqvpn_client_on_tun_packet(mqvpn_client_t *client, const uint8_t *pkt,
                                         size_t len);

MQVPN_API int mqvpn_client_on_socket_recv(mqvpn_client_t *client,
                                          mqvpn_path_handle_t path, const uint8_t *pkt,
                                          size_t len, const struct sockaddr *peer,
                                          socklen_t peer_len);

/* Drive the engine — must be called periodically */
MQVPN_API int mqvpn_client_tick(mqvpn_client_t *client);

/* Query state */
MQVPN_API mqvpn_client_state_t mqvpn_client_get_state(const mqvpn_client_t *client);

MQVPN_API int mqvpn_client_get_stats(const mqvpn_client_t *client, mqvpn_stats_t *out);

MQVPN_API int mqvpn_client_get_paths(const mqvpn_client_t *client, mqvpn_path_info_t *out,
                                     int max_paths, int *n_paths);

MQVPN_API int mqvpn_client_get_interest(const mqvpn_client_t *client,
                                        mqvpn_interest_t *out);

/* Set resolved server address (must be called before connect) */
MQVPN_API int mqvpn_client_set_server_addr(mqvpn_client_t *client,
                                           const struct sockaddr *addr,
                                           socklen_t addrlen);

/* ─── Server API ─── */

MQVPN_API mqvpn_server_t *mqvpn_server_new(const mqvpn_config_t *cfg,
                                           const mqvpn_server_callbacks_t *cbs,
                                           void *user_ctx);

MQVPN_API void mqvpn_server_destroy(mqvpn_server_t *server);

MQVPN_API int mqvpn_server_set_socket_fd(mqvpn_server_t *server, int fd,
                                         const struct sockaddr *local_addr,
                                         socklen_t local_addrlen);
MQVPN_API int mqvpn_server_start(mqvpn_server_t *server);
MQVPN_API int mqvpn_server_stop(mqvpn_server_t *server);

MQVPN_API int mqvpn_server_on_socket_recv(mqvpn_server_t *server, const uint8_t *pkt,
                                          size_t len, const struct sockaddr *peer,
                                          socklen_t peer_len);

/* Platform calls this when a previously-registered egress fd (via
 * egress_fd_register) becomes readable and/or writable. fd_ctx is the
 * opaque pointer the core passed to egress_fd_register for that fd. */
MQVPN_API void mqvpn_server_on_egress_fd_ready(mqvpn_server_t *server, int fd,
                                               void *fd_ctx, int readable, int writable);

/* Upper bound on concurrent egress TCP fds the server will ever open
 * (min(rlimit_nofile - reserve, configured cap)). Computed once at
 * mqvpn_server_new and frozen for the server's lifetime: platforms size
 * their fd->event registries from this, and the server's own admission cap
 * uses the same snapshot, so the two bounds cannot drift (a runtime
 * setrlimit changes neither). Returns 0 on NULL server; a value <= 0 means
 * "treat tcp_egress as disabled — do not allocate a registry". */
MQVPN_API int mqvpn_server_egress_fd_budget(mqvpn_server_t *server);

MQVPN_API int mqvpn_server_on_tun_packet(mqvpn_server_t *server, const uint8_t *pkt,
                                         size_t len);

MQVPN_API int mqvpn_server_tick(mqvpn_server_t *server);

MQVPN_API int mqvpn_server_get_stats(const mqvpn_server_t *server, mqvpn_stats_t *out);

MQVPN_API int mqvpn_server_get_interest(const mqvpn_server_t *server,
                                        mqvpn_interest_t *out);

MQVPN_API int mqvpn_server_get_n_clients(const mqvpn_server_t *server);

MQVPN_API int mqvpn_server_add_user(mqvpn_server_t *server, const char *username,
                                    const char *key);

MQVPN_API int mqvpn_server_remove_user(mqvpn_server_t *server, const char *username);

/* Fill names[0..max-1] with current user names. Returns the count. */
MQVPN_API int mqvpn_server_list_users(const mqvpn_server_t *server, char names[][64],
                                      int max);

/* Fill out[0..max-1] with per-client info including per-path stats. */
MQVPN_API int mqvpn_server_get_client_info(const mqvpn_server_t *server,
                                           mqvpn_client_info_t *out, int max_clients,
                                           int *n_clients);

/* ─── Utility API ─── */

MQVPN_API int mqvpn_generate_key(char *out, size_t out_len);
MQVPN_API const char *mqvpn_error_string(mqvpn_error_t err);
MQVPN_API const char *mqvpn_version_string(void);

#ifdef __cplusplus
}
#endif

#endif /* LIBMQVPN_H */
