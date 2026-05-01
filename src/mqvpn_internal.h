/*
 * mqvpn_internal.h — Internal type definitions for libmqvpn
 *
 * NOT part of the public API. Do not install this header.
 */

#ifndef MQVPN_INTERNAL_H
#define MQVPN_INTERNAL_H

#include "libmqvpn.h"
#include <stdbool.h>

/* ─── Constants ─── */
/* MQVPN_MAX_PATHS and MQVPN_MAX_USERS are defined in libmqvpn.h */

/* ─── Config (opaque to callers) ─── */

struct mqvpn_config_s {
    char server_host[256];
    int server_port;
    char auth_key[256];
    char user_names[MQVPN_MAX_USERS][64];
    char user_keys[MQVPN_MAX_USERS][256];
    int n_users;
    int insecure;

    mqvpn_scheduler_t scheduler;
    mqvpn_log_level_t log_level;
    int multipath;
    int reconnect_enable;
    int reconnect_interval_sec;
    int killswitch_hint;

    /* Clock injection (Android: CLOCK_BOOTTIME) */
    mqvpn_clock_fn clock_fn;
    void *clock_ctx;

    /* Server-only fields */
    char listen_addr[256];
    int listen_port;
    char subnet[64];
    char subnet6[64];
    char tls_cert[256];
    char tls_key[256];
    int max_clients;
};

/* ─── State transition validation (M0-5) ─── */

int mqvpn_state_transition_valid(mqvpn_client_state_t from, mqvpn_client_state_t to);

/* ─── Scheduler precondition predicate ─── */

/* Returns true if the scheduler+path combination warrants a warning.
 * Pure predicate — caller emits the actual log via LOG_W() to keep
 * level filtering and connection-id prefixing consistent. */
bool mqvpn_check_scheduler_preconditions(mqvpn_scheduler_t scheduler, int n_paths);

/* ── Internal accessors (NOT in public libmqvpn.h) ────────────────── */

/* Returns "minrtt" / "wlb" / "backup_fec" / "unknown" — caller-owned static
 * string, do not free. Used by control_socket.c for get_build_info JSON. */
const char *mqvpn_server_scheduler_label(const mqvpn_server_t *s);

/* Snapshot of FEC / multipath counters for one client.
 * INTERNAL — not in public libmqvpn.h. Field widths chosen to safely accept
 * either uint32_t or uint64_t xquic counters now or in the future. */
typedef struct {
    uint8_t enable_fec;
    uint8_t mp_state;
    uint64_t fec_send_cnt;    /* widened from xquic uint32_t */
    uint64_t fec_recover_cnt; /* widened from xquic uint32_t */
    uint64_t lost_dgram_cnt;  /* widened from xquic uint32_t */
    uint64_t total_app_bytes;
    uint64_t standby_app_bytes;
} mqvpn_internal_fec_stats_t;

/* Returns:
 *   1  -> out filled with the user's FEC stats
 *   0  -> user has no active session
 *  -1  -> mqvpn was built without XQC_ENABLE_FEC (out is zeroed) */
int mqvpn_server_get_client_fec_stats(const mqvpn_server_t *s, const char *user,
                                      mqvpn_internal_fec_stats_t *out);

#endif /* MQVPN_INTERNAL_H */
