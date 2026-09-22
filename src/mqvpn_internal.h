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

/* Mirror of xquic's private xqc_path_state_t (third_party/xquic/
 * src/transport/xqc_multipath.h). The library links shared xquic and sees
 * only its public header, which types xqc_path_metrics_t.path_state as a
 * bare uint8_t, so the enum symbols are not visible here. mqvpn depends on
 * these values by number: the validation poll / mp-state label test ACTIVE,
 * mqvpn_path_state_label() maps all five, and the raw value is surfaced
 * through the public control API (mqvpn_path_stat_t.state). Use these named
 * constants instead of bare literals; every value is pinned to the real
 * enum at compile time by tests/test_xquic_abi_pin.c, so an upstream
 * renumber fails the build instead of silently mislabeling paths. */
#define MQVPN_XQC_PATH_STATE_INIT       0
#define MQVPN_XQC_PATH_STATE_VALIDATING 1
#define MQVPN_XQC_PATH_STATE_ACTIVE     2
#define MQVPN_XQC_PATH_STATE_CLOSING    3
#define MQVPN_XQC_PATH_STATE_CLOSED     4

/* Outer QUIC/UDP payload bound handed to xquic (single source of truth —
 * also the TX-batch registration guard; the fork's batch enc buffer is
 * 1500B, xqc_defs.h XQC_CONN_MAX_UDP_PAYLOAD_SIZE). */
#define MQVPN_MAX_PKT_OUT_SIZE 1400

/* Is the Linux batched-send path engaged for this config?
 *
 * ONE definition, used by both the client and the server for two decisions
 * that must never disagree: registering the write_mmsg_ex callback (with
 * xconfig.sendmmsg_on), and setting conn_settings.defer_send_flush. With no
 * batch callback registered xquic sends one packet per syscall regardless, so
 * deferring the flush there would move it for no benefit at all. Spelling the
 * condition out per call site is what would let the two drift — notably if
 * MQVPN_MAX_PKT_OUT_SIZE is ever raised past the single-run/no-splitting
 * bound that mqvpn_udp_send_batch() documents in udp_offload.h.
 *
 * Callers still record the result on the client/server struct (tx_batch) and
 * read THAT when building conn settings: the stored flag also carries the
 * platform guard, since the registration block is Linux-only. */
static inline int
mqvpn_tx_batch_enabled(int udp_gso)
{
    return udp_gso && MQVPN_MAX_PKT_OUT_SIZE <= 1500;
}

/* Teardown TX-offload telemetry line, emitted by mqvpn_client_destroy and
 * mqvpn_server_destroy. ONE format definition so the two endpoints'
 * script-parsed wording (benchmarks/bench_stream_gso.sh,
 * scripts/ci_e2e/run_udp_gso_bench.sh, run_udp_gso_config_test.sh's
 * check_teardown_line) cannot drift — same hazard class the
 * MQVPN_UDP_GSO_MARKER_* strings solve for the enablement marker.
 * Callers pass (sends, datagrams, gso_config) as PRIu64/PRIu64/int and
 * must include <inttypes.h>. */
#define MQVPN_UDP_TX_LINE_FMT \
    "udp-tx: sends=%" PRIu64 " datagrams=%" PRIu64 " gso_config=%d"

/* Server "auto" TUN MTU.  The true MASQUE datagram MSS is per-connection
 * (peer TPs, CID length, FEC headroom, PMTUD) and unknowable at server
 * startup, so "auto" uses the typical negotiated value on a 1500-MTU path
 * with default engine settings (MQVPN_MAX_PKT_OUT_SIZE − QUIC short header
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

    /* Reinjection (speculative multipath duplication). 0 = OFF (default,
     * matches calloc). The three numeric fields are only consulted in
     * DEADLINE mode; 0 there means "engine default" (110/500/20) — see
     * mqvpn_conn_settings.c. */
    mqvpn_reinjection_t reinjection;
    int reinj_srtt_factor_pct;
    int reinj_hard_deadline_ms;
    int reinj_deadline_lower_bound_ms;

    mqvpn_log_level_t log_level;
    int multipath;
    int reconnect_enable;
    int reconnect_interval_sec;
    int killswitch_hint;

    /* Clock injection (Android: CLOCK_BOOTTIME) */
    mqvpn_clock_fn clock_fn;
    void *clock_ctx;

    /* Platform certificate verifier (NULL = library root store) */
    mqvpn_cert_verify_fn cert_verify_fn;
    void *cert_verify_ctx;

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

    uint64_t recv_rate_limit; /* 0 = off; client-only, see libmqvpn.h */

    int udp_gso; /* TX GSO/batch enable; default 1 */

    /* [Advanced] receive-buffering limits; 0 = xquic's own default
     * untouched. Both sides, unlike recv_rate_limit above. Consumed by
     * mqvpn_build_conn_settings(); documented in src/config.h. */
    uint64_t h3_body_buf_per_stream;
    uint64_t blocked_buf_per_stream;
    uint64_t blocked_buf_per_conn;
    uint64_t max_recv_window;
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

/* ─── Receive-buffering limits bridge ([Advanced]) ─── */

/* Set the four [Advanced] receive-buffer limits on `cfg`. Both bridges carry
 * all of them: the client bridge (src/platform/client_config_bridge.c) and
 * the server run loop (linux_platform_run_server). Values are passed through
 * as given — the config surface range-checks them against
 * MQVPN_CONFIG_MAX_BUF_LIMIT at parse time, and 0 is always legal (it means
 * "leave xquic's own default alone"). */
void mqvpn_config_set_buf_limits(mqvpn_config_t *cfg, uint64_t h3_body_buf_per_stream,
                                 uint64_t blocked_buf_per_stream,
                                 uint64_t blocked_buf_per_conn, uint64_t max_recv_window);

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
 * Values mirror xqc_multipath.h xqc_path_state_t (MQVPN_XQC_PATH_STATE_*
 * above): 0 init, 1 validating, 2 active, 3 closing, 4 closed.
 * If xquic re-orders this enum the labels become wrong; every value is
 * pinned to the real enum by tests/test_xquic_abi_pin.c. */
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

/* Per-client snapshot of per-path reinjection TX byte counters
 * (xqc_path_metrics_t.path_send_reinject_bytes). INTERNAL — not in public
 * libmqvpn.h. mqvpn_path_stats_t (the public per-path struct embedded in
 * mqvpn_client_info_t) cannot grow a field without breaking ABI (fixed
 * array stride), so this snapshot is control_socket.c's own side channel.
 * Index-alignment contract: see mqvpn_server_get_client_reinject() below. */
typedef struct {
    int n_paths;
    struct {
        uint64_t path_id;
        uint64_t reinject_tx_bytes;
    } paths[MQVPN_MAX_PATHS];
} mqvpn_internal_client_reinject_t;

/* Fills out[0..max) with each active (tunnel-established) session's
 * per-path reinject_tx_bytes, in the SAME session-iteration order and with
 * the SAME tunnel_established guard as mqvpn_server_get_client_info(), so
 * the two result arrays are index-aligned within one control-command
 * handler (the session set cannot change between the two calls — both run
 * inside a single-threaded control-command handler). out[i] corresponds to
 * the i-th entry of that call's client array.
 *
 * Returns the number of entries filled (clamped to max). Callers should
 * still match by path_id when emitting, not rely on array-order alone. */
MQVPN_INTERNAL int mqvpn_server_get_client_reinject(const mqvpn_server_t *s,
                                                    mqvpn_internal_client_reinject_t *out,
                                                    int max);

#endif /* MQVPN_INTERNAL_H */
