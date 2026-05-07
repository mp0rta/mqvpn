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

/* MQVPN_INTERNAL marks symbols that are shared across translation units in
 * libmqvpn but MUST NOT be exported in libmqvpn.so's dynamic symbol table.
 * Compilers that support visibility attributes (gcc/clang on ELF) hide them;
 * other toolchains fall back to default linkage (acceptable: such builds
 * would not have a symbols-file ABI contract anyway). Keeping these out of
 * the export table prevents Debian dpkg-gensymbols (and similar) from
 * picking them up as part of libmqvpn0's stable ABI. */
#if defined(__GNUC__) || defined(__clang__)
#  define MQVPN_INTERNAL __attribute__((visibility("hidden")))
#else
#  define MQVPN_INTERNAL
#endif

/* Returns "minrtt" / "wlb" / "backup_fec" / "unknown" — caller-owned static
 * string, do not free. Used by control_socket.c for get_build_info JSON. */
MQVPN_INTERNAL const char *mqvpn_server_scheduler_label(const mqvpn_server_t *s);

/* Map xquic xqc_path_state_t (uint8) to a stable, operator-readable string.
 * Strings are URL-safe and lowercase to be usable as Prometheus label values.
 * Unknown values map to "unknown". Static storage — do not free.
 *
 * Pinned values (xqc_multipath.h xqc_path_state_t enum):
 *   0 init, 1 validating, 2 active, 3 closing, 4 closed.
 * If xquic re-orders this enum the labels become wrong; the corresponding
 * _Static_assert lives in mqvpn_server.c next to the implementation. */
MQVPN_INTERNAL const char *mqvpn_path_state_label(int state);

/* Snapshot of FEC / multipath counters for one client.
 * INTERNAL — not in public libmqvpn.h. Field widths chosen to safely accept
 * either uint32_t or uint64_t xquic counters now or in the future.
 *
 * mp_state is the raw xquic xqc_conn_stats_t.mp_state — populated by
 * xqc_conn_path_metrics_print() in xqc_multipath.c and documented in
 * xquic.h:1617-1623 as taking values:
 *   0  no multipath attempted (create_path_count <= 1)
 *   1  multipath established and validated (>1 paths, >1 validated)
 *   2  multipath attempted but not validated (>1 paths, <=1 validated)
 *
 * mp_state_label is the operator-readable derivation mqvpn computes by
 * walking xqc_conn_stats_t.paths_info[]: pointer to a static string (do
 * not free). One of "single_path", "active_with_standby", "standby_only",
 * "active_only", or "unknown". Empty/null means the helper failed before
 * it could classify (e.g. NULL stats); callers should treat as "unknown". */
typedef struct {
    uint8_t enable_fec;
    uint8_t mp_state;
    const char *mp_state_label;
    uint64_t fec_send_cnt;    /* widened from xquic uint32_t */
    uint64_t fec_recover_cnt; /* widened from xquic uint32_t */
    uint64_t lost_dgram_cnt;  /* widened from xquic uint32_t */
    uint64_t total_app_bytes;
    uint64_t standby_app_bytes;
} mqvpn_internal_fec_stats_t;

/* Seconds since the server was booted (mqvpn_server_create). */
MQVPN_INTERNAL uint64_t mqvpn_server_uptime_seconds(const mqvpn_server_t *s);

/* Returns:
 *   1  -> out filled with the user's FEC stats
 *   0  -> user has no active (tunnel-established) session
 *  -1  -> mqvpn was built without XQC_ENABLE_FEC, OR a NULL arg was passed
 *        (caller-bug case is folded into "unavailable" so 0 always means
 *         "user not found", never "internal error") */
MQVPN_INTERNAL int mqvpn_server_get_client_fec_stats(const mqvpn_server_t *s,
                                                     const char *user,
                                                     mqvpn_internal_fec_stats_t *out);

/* Bulk variant: write FEC stats for every active (tunnel-established) session
 * into out[]. Used by control_socket.c::get_all_fec_stats to collapse the
 * per-user N+1 RPC pattern into a single call.
 *
 * Returns:
 *    >= 0 -> count of entries written (clamped to max)
 *      -1 -> mqvpn was built without XQC_ENABLE_FEC, OR a NULL arg was passed
 *
 * The username is copied into out[i].user (NUL-terminated, max 63 chars). */
typedef struct {
    char user[64];
    mqvpn_internal_fec_stats_t stats;
} mqvpn_internal_fec_entry_t;

MQVPN_INTERNAL int mqvpn_server_get_all_fec_stats(const mqvpn_server_t *s,
                                                  mqvpn_internal_fec_entry_t *out,
                                                  int max);

#endif /* MQVPN_INTERNAL_H */
