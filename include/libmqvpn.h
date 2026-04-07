/*
 * libmqvpn — Multipath QUIC VPN library
 *
 * Public API header (single file).
 * Version: 0.5.0 (ABI version 2)
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
#define MQVPN_VERSION_MINOR 5
#define MQVPN_VERSION_PATCH 0

/* ─── ABI ─── */

#define MQVPN_CALLBACKS_ABI_VERSION  2

/* ─── Capacity constants ─── */

#define MQVPN_MAX_USERS   64
#define MQVPN_MAX_PATHS    4

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
    MQVPN_ERR_ENGINE = -3,        /* xquic engine error */
    MQVPN_ERR_TLS = -4,           /* TLS handshake failure */
    MQVPN_ERR_AUTH = -5,          /* PSK auth failure (403) */
    MQVPN_ERR_PROTOCOL = -6,      /* MASQUE not supported */
    MQVPN_ERR_POOL_FULL = -7,     /* server: IP pool exhausted */
    MQVPN_ERR_MAX_CLIENTS = -8,   /* server: max clients reached */
    MQVPN_ERR_AGAIN = -9,         /* back-pressure */
    MQVPN_ERR_CLOSED = -10,       /* connection closed */
    MQVPN_ERR_ABI_MISMATCH = -11, /* callback ABI version mismatch */
    MQVPN_ERR_TIMEOUT = -12,      /* connection timeout */
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
} mqvpn_scheduler_t;

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

typedef enum {
    MQVPN_PATH_PENDING = 0,
    MQVPN_PATH_ACTIVE = 1,
    MQVPN_PATH_DEGRADED = 2,
    MQVPN_PATH_STANDBY = 3,
    MQVPN_PATH_CLOSED = 4,
} mqvpn_path_status_t;

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
    uint8_t  state;
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

MQVPN_API int mqvpn_config_set_server(mqvpn_config_t *cfg,
                                       const char *host, int port);
MQVPN_API int mqvpn_config_set_auth_key(mqvpn_config_t *cfg,
                                         const char *key);
MQVPN_API int mqvpn_config_add_user(mqvpn_config_t *cfg,
                                     const char *username,
                                     const char *key);
MQVPN_API int mqvpn_config_remove_user(mqvpn_config_t *cfg,
                                        const char *username);
MQVPN_API int mqvpn_config_load_json(mqvpn_config_t *cfg,
                                      const char *json_text);
MQVPN_API int mqvpn_config_set_insecure(mqvpn_config_t *cfg, int insecure);
MQVPN_API int mqvpn_config_set_scheduler(mqvpn_config_t *cfg, mqvpn_scheduler_t sched);
MQVPN_API int mqvpn_config_set_log_level(mqvpn_config_t *cfg, mqvpn_log_level_t level);
MQVPN_API int mqvpn_config_set_multipath(mqvpn_config_t *cfg, int enable);
MQVPN_API int mqvpn_config_set_reconnect(mqvpn_config_t *cfg, int enable,
                                         int interval_sec);
MQVPN_API int mqvpn_config_set_killswitch_hint(mqvpn_config_t *cfg, int enable);

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

MQVPN_API int mqvpn_client_remove_path(mqvpn_client_t *client, mqvpn_path_handle_t path);

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

MQVPN_API int mqvpn_server_on_tun_packet(mqvpn_server_t *server, const uint8_t *pkt,
                                         size_t len);

MQVPN_API int mqvpn_server_tick(mqvpn_server_t *server);

MQVPN_API int mqvpn_server_get_stats(const mqvpn_server_t *server, mqvpn_stats_t *out);

MQVPN_API int mqvpn_server_get_interest(const mqvpn_server_t *server,
                                        mqvpn_interest_t *out);

MQVPN_API int mqvpn_server_get_n_clients(const mqvpn_server_t *server);

MQVPN_API int mqvpn_server_add_user(mqvpn_server_t *server,
                                     const char *username, const char *key);

MQVPN_API int mqvpn_server_remove_user(mqvpn_server_t *server,
                                        const char *username);

/* Fill names[0..max-1] with current user names. Returns the count. */
MQVPN_API int mqvpn_server_list_users(const mqvpn_server_t *server,
                                       char names[][64], int max);

/* Fill out[0..max-1] with per-client info including per-path stats. */
MQVPN_API int mqvpn_server_get_client_info(const mqvpn_server_t *server,
                                            mqvpn_client_info_t *out,
                                            int max_clients, int *n_clients);

/* ─── Utility API ─── */

MQVPN_API int mqvpn_generate_key(char *out, size_t out_len);
MQVPN_API const char *mqvpn_error_string(mqvpn_error_t err);
MQVPN_API const char *mqvpn_version_string(void);

#ifdef __cplusplus
}
#endif

#endif /* LIBMQVPN_H */
