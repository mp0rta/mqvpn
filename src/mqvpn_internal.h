// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * mqvpn_internal.h — Internal type definitions for libmqvpn
 *
 * NOT part of the public API. Do not install this header.
 */

#ifndef MQVPN_INTERNAL_H
#define MQVPN_INTERNAL_H

#include "libmqvpn.h"
#include "reorder.h"           /* mqvpn_reorder_config_t embedded in the builder config */
#include "hybrid/classifier.h" /* mqvpn_hybrid_config_t embedded in the builder config */
#include <stdbool.h>

/* ─── Constants ─── */
/* MQVPN_MAX_PATHS and MQVPN_MAX_USERS are defined in libmqvpn.h */

/* Mirror of xquic's private XQC_PATH_STATE_ACTIVE (third_party/xquic/
 * src/transport/xqc_multipath.h). The library links shared xquic and sees
 * only its public header, which exposes xqc_path_metrics_t.path_state as a
 * bare uint8_t, so the enum symbol is not visible here. Use this named
 * constant instead of a bare literal; its value is pinned to the real enum
 * at compile time by tests/test_xquic_abi_pin.c. */
#define MQVPN_XQC_PATH_STATE_ACTIVE 2

/* Server "auto" TUN MTU.  The true MASQUE datagram MSS is per-connection
 * (peer TPs, CID length, FEC headroom, PMTUD) and unknowable at server
 * startup, so "auto" uses the typical negotiated value on a 1500-MTU path
 * with default engine settings (max_pkt_out_size 1400 − QUIC short header
 * − DATAGRAM/MASQUE headers = 1382).  Clients that negotiated less are
 * handled per-client via ICMP PTB in mqvpn_server_on_tun_packet(), so a
 * high default is safe. */
#define MQVPN_TUN_MTU_AUTO 1382

/* ─── Config (opaque to callers) ─── */

struct mqvpn_config_s {
    char server_host[256];
    char tls_server_name[256];
    int server_port;
    char auth_key[256];
    char user_names[MQVPN_MAX_USERS][64];
    char user_keys[MQVPN_MAX_USERS][256];
    int n_users;
    int insecure;

    mqvpn_scheduler_t scheduler;
    mqvpn_cc_t cc;
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

    /* draft-21 §4.6: initial Maximum Path Identifier we advertise in TP.
     * 0 = use xquic default (XQC_DEFAULT_INIT_MAX_PATH_ID = 8). */
    uint64_t init_max_path_id;

    int tun_mtu; /* 0 = auto (client: negotiated; server: 1382), >0 = client cap / server
                    TUN MTU */

    /* Flow-aware reorder shim config (§16). Seeded with
     * mqvpn_reorder_config_default() in mqvpn_config_new(); the library
     * consumer reads cfg->reorder. */
    mqvpn_reorder_config_t reorder;

    /* Hybrid-mode classifier policy (H1). Seeded with
     * mqvpn_hybrid_config_default() in mqvpn_config_new(); the library
     * consumer reads cfg->hybrid. */
    mqvpn_hybrid_config_t hybrid;
};

/* ─── State transition validation (M0-5) ─── */

int mqvpn_state_transition_valid(mqvpn_client_state_t from, mqvpn_client_state_t to);

/* ─── Reorder config bridge (§16) ─── */

/* Translate a parsed/built reorder config (e.g. from INI [Reorder]/[ReorderRule]
 * via mqvpn_file_config_t) into `cfg` using the public builder setters. Shared by
 * the platform layers so every surface honors reorder config identically. The
 * internal-only eval_force_no_demotion knob is intentionally NOT bridged. */
void mqvpn_config_apply_reorder(mqvpn_config_t *cfg, const mqvpn_reorder_config_t *src);

/* ─── Hybrid config bridge (H1) ─── */

/* Translate a parsed/built hybrid config (e.g. from INI [Hybrid] via
 * mqvpn_file_config_t) into `cfg`. Shared by the platform layers so every
 * surface honors hybrid config identically. */
void mqvpn_config_apply_hybrid(mqvpn_config_t *cfg, const mqvpn_hybrid_config_t *src);

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
 * picking them up as part of libmqvpn's stable ABI. */
#if defined(__GNUC__) || defined(__clang__)
#  define MQVPN_INTERNAL __attribute__((visibility("hidden")))
#else
#  define MQVPN_INTERNAL
#endif

/* Returns "minrtt" / "wlb" / "wlb_udp_pin" / "backup_fec" / "unknown" —
 * caller-owned static string, do not free.
 * Used by control_socket.c for get_build_info JSON. */
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

/* Aggregate reorder-shim RX statistics across every live connection that has a
 * reorder engine (cfg.reorder.mode != OFF). Zero-inits *out, then SUMs each
 * mqvpn_reorder_stats_t counter (mqvpn_reorder_rx_get_stats) over all such
 * conns. A server with no reorder-enabled conn leaves *out all-zero — that is a
 * valid result, not an error. mqvpn_reorder_stats_t is defined in reorder.h
 * (already included above).
 *
 * Returns:
 *    0  -> *out filled (possibly all-zero)
 *   -1  -> a NULL arg was passed
 *
 * Used by control_socket.c::get_reorder_stats. Aggregate-only (no per-conn
 * breakdown): the e2e/exporter only needs the engine-fired evidence
 * (gap_count > 0), and per-conn detail is not required at this layer. */
MQVPN_INTERNAL int mqvpn_server_get_reorder_stats(const mqvpn_server_t *s,
                                                  mqvpn_reorder_stats_t *out);
MQVPN_INTERNAL int mqvpn_client_get_reorder_stats(const mqvpn_client_t *c,
                                                  mqvpn_reorder_stats_t *out);

#endif /* MQVPN_INTERNAL_H */
