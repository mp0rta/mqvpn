// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * control_socket.c — TCP control API for mqvpn server
 *
 * Supported JSON commands:
 *
 *   {"cmd":"add_user",    "name":"alice","key":"alice-secret"}
 *   {"cmd":"remove_user", "name":"alice"}
 *   {"cmd":"list_users"}
 *   {"cmd":"get_stats"}
 *   {"cmd":"get_status"}
 *   {"cmd":"get_build_info"}
 *   {"cmd":"get_fec_stats","user":"alice"}
 *   {"cmd":"get_all_fec_stats"}
 *   {"cmd":"get_reorder_stats"}
 *
 * Responses:
 *   {"ok":true}
 *   {"ok":false,"error":"<reason>"}
 *   {"ok":true,"users":["alice","bob"]}
 *   {"ok":true,"n_clients":N,"bytes_tx":X,"bytes_rx":Y,
 *    "dgram_sent":S,"dgram_recv":R,"dgram_lost":L,"dgram_acked":A,
 *    "uptime_sec":U}
 *   {"ok":true,"version":"0.7.0","scheduler":"backup_fec","fec_enabled":1}
 *   {"ok":true,"user":"alice","enable_fec":1,"mp_state":1,
 *    "mp_state_label":"active_with_standby",
 *    "fec_send_cnt":142,"fec_recover_cnt":17,"lost_dgram_cnt":23,
 *    "total_app_bytes":9123456,"standby_app_bytes":421337}
 *   {"ok":true,"n_clients":N,"clients":[{"user":"alice","enable_fec":1,
 *    "mp_state":1,"mp_state_label":"active_with_standby", ...}, ...]}
 *   {"ok":true,"reorder":{"gap_count":N,"gap_filled_count":N,
 *    "gap_timeout_count":N,"gap_overflow_count":N,"gap_demote_count":N,
 *    "gap_reset_count":N,"ack_demote_count":N,"too_late_drop_count":N,
 *    "too_far_ahead_drop_count":N,"duplicate_drop_count":N,"pool_drop_count":N,
 *    "per_flow_limit_drop_count":N,"reset_discard_count":N,"delivered_count":N,
 *    "added_latency_p99_ms":F,"added_latency_max_ms":F,
 *    "added_latency_buffered_p99_ms":F}}
 */

#include "control_socket.h"
#include "json_util.h"
#include "log.h"

#include <event2/event.h>
#include "mqvpn_internal.h" /* mqvpn_server_scheduler_label,
                               mqvpn_path_state_label,
                               mqvpn_internal_fec_stats_t (carries mp_state_label),
                               mqvpn_server_get_client_fec_stats,
                               mqvpn_server_get_all_fec_stats,
                               mqvpn_server_get_reorder_stats,
                               mqvpn_reorder_stats_t (via reorder.h),
                               mqvpn_internal_client_reinject_t,
                               mqvpn_server_get_client_reinject,
                               mqvpn_internal_client_sched_t,
                               mqvpn_server_get_client_sched */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define CTRL_MAX_REQ          4096 /* per-connection request buffer */
#define CTRL_MAX_CONNS        8    /* max concurrent control connections */
#define CTRL_READ_TIMEOUT_SEC 5    /* close idle connections after 5s */
/* CTRL_MAX_RESP_BYTES is in control_socket.h; test_control_socket checks that
 * the worst-case get_status fits. */

/* ── Per-connection state ────────────────────────────────────────────────── */

typedef struct {
    int fd;
    struct event *ev;
    char req[CTRL_MAX_REQ + 1];
    size_t req_len;
    ctrl_socket_t *cs;
} ctrl_conn_t;

/* ── Server handle ───────────────────────────────────────────────────────── */

struct ctrl_socket_s {
    int listen_fd;
    struct event *ev_accept;
    struct event_base *eb;
    mqvpn_server_t *server;
    /* Getter into the platform's transport ctx for the RX offload counters;
     * see ctrl_socket_create's doc for why these do not travel through
     * mqvpn_stats_t. NULL fn = report 0. */
    ctrl_rx_stats_fn rx_stats;
    void *rx_ctx;
    int n_conns; /* active control connections */
};

/* ── Response building ───────────────────────────────────────────────────── */

/* Writes doc into resp as compact JSON and frees it. A NULL doc (a handler's
 * malloc failure) or a response that does not fit resp_len gives the fixed
 * envelope, never a cut-off prefix. Invalid UTF-8 passes through byte for
 * byte: intake does not validate it, and name[64] can cut a character. */
static int
ctrl_reply(yyjson_mut_doc *doc, char *resp, size_t resp_len)
{
    size_t n = yyjson_mut_write_buf(resp, resp_len, doc,
                                    YYJSON_WRITE_ALLOW_INVALID_UNICODE, NULL);
    yyjson_mut_doc_free(doc);
    if (n == 0)
        return snprintf(resp, resp_len,
                        "{\"ok\":false,\"error\":\"response too large\"}");
    return (int)n;
}

/* {"ok":false,"error":msg} */
static int
ctrl_error(char *resp, size_t resp_len, const char *msg)
{
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    bool ok = yyjson_mut_obj_add_bool(doc, root, "ok", false);
    ok &= yyjson_mut_obj_add_strcpy(doc, root, "error", msg);
    if (!ok) {
        yyjson_mut_doc_free(doc);
        return ctrl_reply(NULL, resp, resp_len);
    }
    return ctrl_reply(doc, resp, resp_len);
}

/* {"ok":true} */
static int
ctrl_ok(char *resp, size_t resp_len)
{
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    if (!yyjson_mut_obj_add_bool(doc, root, "ok", true)) {
        yyjson_mut_doc_free(doc);
        return ctrl_reply(NULL, resp, resp_len);
    }
    return ctrl_reply(doc, resp, resp_len);
}

/* A latency in ms as a number with at most 3 decimals (the old "%.3f"). */
static bool
ctrl_add_ms(yyjson_mut_doc *doc, yyjson_mut_val *obj, const char *key, double ms)
{
    yyjson_mut_val *v = yyjson_mut_real(doc, ms);
    return yyjson_mut_set_fp_to_fixed(v, 3) && yyjson_mut_obj_add_val(doc, obj, key, v);
}

/* ── Command dispatch ────────────────────────────────────────────────────── */

/* Each handler creates a doc for its reply, adds the keys in wire order (keys,
 * order and JSON types are a compatibility surface), and hands the doc to
 * ctrl_reply, which frees it. Every add result is folded into `ok`; a failed
 * add (malloc) turns the reply into the envelope. */

static int
ctrl_cmd_add_user(yyjson_val *req, char *resp, size_t resp_len, ctrl_socket_t *cs)
{
    mqvpn_server_t *server = cs->server;
    char name[64] = {0}, key[256] = {0};
    yyjson_val *name_val = yyjson_obj_get(req, "name");
    if (json_copy_str(name_val, name, sizeof(name)) < 0 ||
        json_copy_str(yyjson_obj_get(req, "key"), key, sizeof(key)) < 0)
        return ctrl_error(resp, resp_len, "name and key required");
    if (yyjson_get_len(name_val) >= sizeof(name))
        return ctrl_error(resp, resp_len, "name exceeds 63 bytes");

    int rc = mqvpn_server_add_user(server, name, key);
    if (rc != MQVPN_OK) {
        char m[48];
        snprintf(m, sizeof(m), "add_user failed (%d)", rc);
        return ctrl_error(resp, resp_len, m);
    }
    return ctrl_ok(resp, resp_len);
}

static int
ctrl_cmd_remove_user(yyjson_val *req, char *resp, size_t resp_len, ctrl_socket_t *cs)
{
    mqvpn_server_t *server = cs->server;
    char name[64] = {0};
    yyjson_val *name_val = yyjson_obj_get(req, "name");
    if (json_copy_str(name_val, name, sizeof(name)) < 0)
        return ctrl_error(resp, resp_len, "name required");
    if (yyjson_get_len(name_val) >= sizeof(name))
        return ctrl_error(resp, resp_len, "name exceeds 63 bytes");

    int rc = mqvpn_server_remove_user(server, name);
    if (rc != MQVPN_OK) return ctrl_error(resp, resp_len, "user not found");
    return ctrl_ok(resp, resp_len);
}

static int
ctrl_cmd_list_users(yyjson_val *req, char *resp, size_t resp_len, ctrl_socket_t *cs)
{
    mqvpn_server_t *server = cs->server;
    (void)req;
    char unames[MQVPN_MAX_USERS][64];
    int n_users = mqvpn_server_list_users(server, unames, MQVPN_MAX_USERS);

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    bool ok = yyjson_mut_obj_add_bool(doc, root, "ok", true);
    yyjson_mut_val *users = yyjson_mut_obj_add_arr(doc, root, "users");
    ok &= users != NULL;
    for (int i = 0; i < n_users; i++)
        ok &= yyjson_mut_arr_add_strcpy(doc, users, unames[i]);
    if (!ok) {
        yyjson_mut_doc_free(doc);
        return ctrl_reply(NULL, resp, resp_len);
    }
    return ctrl_reply(doc, resp, resp_len);
}

static int
ctrl_cmd_get_stats(yyjson_val *req, char *resp, size_t resp_len, ctrl_socket_t *cs)
{
    mqvpn_server_t *server = cs->server;
    (void)req;
    mqvpn_stats_t st = {0};
    st.struct_size = sizeof(st);
    mqvpn_server_get_stats(server, &st);
    int nc = mqvpn_server_get_n_clients(server);
    uint64_t uptime = mqvpn_server_uptime_seconds(server);
    uint64_t rx_receives = 0, rx_datagrams = 0, rx_drops = 0;
    if (cs->rx_stats) cs->rx_stats(cs->rx_ctx, &rx_receives, &rx_datagrams, &rx_drops);

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    bool ok = yyjson_mut_obj_add_bool(doc, root, "ok", true);
    ok &= yyjson_mut_obj_add_int(doc, root, "n_clients", nc);
    ok &= yyjson_mut_obj_add_uint(doc, root, "bytes_tx", st.bytes_tx);
    ok &= yyjson_mut_obj_add_uint(doc, root, "bytes_rx", st.bytes_rx);
    ok &= yyjson_mut_obj_add_uint(doc, root, "dgram_sent", st.dgram_sent);
    ok &= yyjson_mut_obj_add_uint(doc, root, "dgram_recv", st.dgram_recv);
    ok &= yyjson_mut_obj_add_uint(doc, root, "dgram_lost", st.dgram_lost);
    ok &= yyjson_mut_obj_add_uint(doc, root, "dgram_acked", st.dgram_acked);
    ok &= yyjson_mut_obj_add_uint(doc, root, "pkts_lane_tcp", st.pkts_lane_tcp);
    ok &= yyjson_mut_obj_add_uint(doc, root, "pkts_lane_dgram", st.pkts_lane_dgram);
    ok &= yyjson_mut_obj_add_uint(doc, root, "pkts_lane_raw", st.pkts_lane_raw);
    ok &= yyjson_mut_obj_add_uint(doc, root, "pkts_lane_tcp_dropped",
                                  st.pkts_lane_tcp_dropped);
    ok &= yyjson_mut_obj_add_uint(doc, root, "tcp_flows_active", st.tcp_flows_active);
    ok &= yyjson_mut_obj_add_uint(doc, root, "tcp_flows_total", st.tcp_flows_total);
    ok &= yyjson_mut_obj_add_uint(doc, root, "tcp_flows_rejected", st.tcp_flows_rejected);
    ok &= yyjson_mut_obj_add_uint(doc, root, "raw_markers_active", st.raw_markers_active);
    /* udp_tx_* from the library (it issues those sends); udp_rx_* from the
     * platform's transport getter (RX offload never crosses the library
     * ABI). datagrams/sends and datagrams/receives are the achieved
     * batching and coalescing factors — 1.0 means every datagram cost
     * its own syscall, which the one-shot "udp-gso:"/"udp-gro:" startup
     * markers cannot distinguish because they only report the kernel
     * capability probe. */
    ok &= yyjson_mut_obj_add_uint(doc, root, "udp_tx_sends", st.udp_tx_sends);
    ok &= yyjson_mut_obj_add_uint(doc, root, "udp_tx_datagrams", st.udp_tx_datagrams);
    ok &= yyjson_mut_obj_add_uint(doc, root, "udp_rx_receives", rx_receives);
    ok &= yyjson_mut_obj_add_uint(doc, root, "udp_rx_datagrams", rx_datagrams);
    /* Receive-queue drops on the listen socket (datagrams, or whole GRO
     * batches): they never reach QUIC, so no other counter here sees them. */
    ok &= yyjson_mut_obj_add_uint(doc, root, "udp_rx_drops", rx_drops);
    ok &= yyjson_mut_obj_add_uint(doc, root, "uptime_sec", uptime);
    if (!ok) {
        yyjson_mut_doc_free(doc);
        return ctrl_reply(NULL, resp, resp_len);
    }
    return ctrl_reply(doc, resp, resp_len);
}

static int
ctrl_cmd_get_status(yyjson_val *req, char *resp, size_t resp_len, ctrl_socket_t *cs)
{
    mqvpn_server_t *server = cs->server;
    (void)req;
    mqvpn_client_info_t clients[MQVPN_MAX_USERS];
    int n_clients = 0;
    mqvpn_server_get_client_info(server, clients, MQVPN_MAX_USERS, &n_clients);

    /* Index-aligned with clients[] above — contract is on
     * mqvpn_server_get_client_reinject() in mqvpn_internal.h. Matched by
     * path_id below anyway, not by array position alone. */
    mqvpn_internal_client_reinject_t reinj[MQVPN_MAX_USERS];
    int n_reinj = mqvpn_server_get_client_reinject(server, reinj, MQVPN_MAX_USERS);
    if (n_reinj < 0) n_reinj = 0;

    /* Same index alignment, see mqvpn_server_get_client_sched(). */
    mqvpn_internal_client_sched_t sched[MQVPN_MAX_USERS];
    int n_sched = mqvpn_server_get_client_sched(server, sched, MQVPN_MAX_USERS);
    if (n_sched < 0) n_sched = 0;

    uint64_t now = 0;
    struct timeval tv;
    if (gettimeofday(&tv, NULL) == 0)
        now = (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    bool ok = yyjson_mut_obj_add_bool(doc, root, "ok", true);
    ok &= yyjson_mut_obj_add_int(doc, root, "n_clients", n_clients);
    yyjson_mut_val *jclients = yyjson_mut_obj_add_arr(doc, root, "clients");
    ok &= jclients != NULL;

    for (int i = 0; i < n_clients; i++) {
        mqvpn_client_info_t *ci = &clients[i];
        uint64_t conn_sec = (ci->connected_at_us > 0 && now > ci->connected_at_us)
                                ? (now - ci->connected_at_us) / 1000000
                                : 0;

        yyjson_mut_val *jc = yyjson_mut_arr_add_obj(doc, jclients);
        ok &= yyjson_mut_obj_add_strcpy(doc, jc, "user", ci->username);
        ok &= yyjson_mut_obj_add_strcpy(doc, jc, "endpoint", ci->endpoint);
        ok &= yyjson_mut_obj_add_strcpy(doc, jc, "scheduler",
                                        i < n_sched ? sched[i].scheduler : "unknown");
        ok &= yyjson_mut_obj_add_uint(doc, jc, "connected_sec", conn_sec);
        ok &= yyjson_mut_obj_add_uint(doc, jc, "bytes_tx", ci->bytes_tx);
        ok &= yyjson_mut_obj_add_uint(doc, jc, "bytes_rx", ci->bytes_rx);
        ok &= yyjson_mut_obj_add_int(doc, jc, "n_paths", ci->n_paths);
        yyjson_mut_val *jpaths = yyjson_mut_obj_add_arr(doc, jc, "paths");
        ok &= jpaths != NULL;

        for (int p = 0; p < ci->n_paths; p++) {
            mqvpn_path_stats_t *ps = &ci->paths[p];

            /* Emit 0 on mismatch/absence (index out of range, or no path_id
             * match within reinj[i]) rather than skipping the field — every
             * path object keeps the same shape. */
            uint64_t reinject_tx_bytes = 0;
            if (i < n_reinj) {
                mqvpn_internal_client_reinject_t *re = &reinj[i];
                for (int rp = 0; rp < re->n_paths; rp++) {
                    if (re->paths[rp].path_id == ps->path_id) {
                        reinject_tx_bytes = re->paths[rp].reinject_tx_bytes;
                        break;
                    }
                }
            }

            yyjson_mut_val *jp = yyjson_mut_arr_add_obj(doc, jpaths);
            ok &= yyjson_mut_obj_add_uint(doc, jp, "path_id", ps->path_id);
            ok &= yyjson_mut_obj_add_uint(doc, jp, "srtt_ms", ps->srtt_us / 1000);
            ok &= yyjson_mut_obj_add_uint(doc, jp, "min_rtt_ms", ps->min_rtt_us / 1000);
            ok &= yyjson_mut_obj_add_uint(doc, jp, "cwnd", ps->cwnd);
            ok &= yyjson_mut_obj_add_uint(doc, jp, "in_flight", ps->bytes_in_flight);
            ok &= yyjson_mut_obj_add_uint(doc, jp, "bytes_tx", ps->bytes_tx);
            ok &= yyjson_mut_obj_add_uint(doc, jp, "bytes_rx", ps->bytes_rx);
            ok &= yyjson_mut_obj_add_uint(doc, jp, "pkt_sent", ps->pkt_sent);
            ok &= yyjson_mut_obj_add_uint(doc, jp, "pkt_recv", ps->pkt_recv);
            ok &= yyjson_mut_obj_add_uint(doc, jp, "pkt_lost", ps->pkt_lost);
            ok &= yyjson_mut_obj_add_uint(doc, jp, "state", ps->state);
            ok &= yyjson_mut_obj_add_strcpy(doc, jp, "state_label",
                                            mqvpn_path_state_label(ps->state));
            ok &=
                yyjson_mut_obj_add_uint(doc, jp, "reinject_tx_bytes", reinject_tx_bytes);
        }
    }
    if (!ok) {
        yyjson_mut_doc_free(doc);
        return ctrl_reply(NULL, resp, resp_len);
    }
    return ctrl_reply(doc, resp, resp_len);
}

static int
ctrl_cmd_get_build_info(yyjson_val *req, char *resp, size_t resp_len, ctrl_socket_t *cs)
{
    mqvpn_server_t *server = cs->server;
    (void)req;
    const char *ver = mqvpn_version_string();
    const char *sched = mqvpn_server_scheduler_label(server);
#ifdef XQC_ENABLE_FEC
    int fec_enabled = 1;
#else
    int fec_enabled = 0;
#endif
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    bool ok = yyjson_mut_obj_add_bool(doc, root, "ok", true);
    ok &= yyjson_mut_obj_add_strcpy(doc, root, "version", ver ? ver : "unknown");
    ok &= yyjson_mut_obj_add_strcpy(doc, root, "scheduler", sched);
    ok &= yyjson_mut_obj_add_int(doc, root, "fec_enabled", fec_enabled);
    if (!ok) {
        yyjson_mut_doc_free(doc);
        return ctrl_reply(NULL, resp, resp_len);
    }
    return ctrl_reply(doc, resp, resp_len);
}

static int
ctrl_cmd_get_fec_stats(yyjson_val *req, char *resp, size_t resp_len, ctrl_socket_t *cs)
{
    mqvpn_server_t *server = cs->server;
    char user[64] = {0};
    yyjson_val *user_val = yyjson_obj_get(req, "user");
    if (json_copy_str(user_val, user, sizeof(user)) < 0)
        return ctrl_error(resp, resp_len, "user required");
    if (yyjson_get_len(user_val) >= sizeof(user))
        return ctrl_error(resp, resp_len, "name exceeds 63 bytes");

    mqvpn_internal_fec_stats_t fs;
    int rc = mqvpn_server_get_client_fec_stats(server, user, &fs);
    if (rc < 0) return ctrl_error(resp, resp_len, "fec not built");
    if (rc == 0) return ctrl_error(resp, resp_len, "user not found");

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    bool ok = yyjson_mut_obj_add_bool(doc, root, "ok", true);
    ok &= yyjson_mut_obj_add_strcpy(doc, root, "user", user);
    ok &= yyjson_mut_obj_add_uint(doc, root, "enable_fec", fs.enable_fec);
    ok &= yyjson_mut_obj_add_uint(doc, root, "mp_state", fs.mp_state);
    ok &= yyjson_mut_obj_add_strcpy(doc, root, "mp_state_label",
                                    fs.mp_state_label ? fs.mp_state_label : "unknown");
    ok &= yyjson_mut_obj_add_uint(doc, root, "fec_send_cnt", fs.fec_send_cnt);
    ok &= yyjson_mut_obj_add_uint(doc, root, "fec_recover_cnt", fs.fec_recover_cnt);
    ok &= yyjson_mut_obj_add_uint(doc, root, "lost_dgram_cnt", fs.lost_dgram_cnt);
    ok &= yyjson_mut_obj_add_uint(doc, root, "total_app_bytes", fs.total_app_bytes);
    ok &= yyjson_mut_obj_add_uint(doc, root, "standby_app_bytes", fs.standby_app_bytes);
    if (!ok) {
        yyjson_mut_doc_free(doc);
        return ctrl_reply(NULL, resp, resp_len);
    }
    return ctrl_reply(doc, resp, resp_len);
}

static int
ctrl_cmd_get_all_fec_stats(yyjson_val *req, char *resp, size_t resp_len,
                           ctrl_socket_t *cs)
{
    mqvpn_server_t *server = cs->server;
    (void)req;
    /* Bulk variant collapsing the per-user N+1 RPC pattern in scrapers
     * (Prometheus exporter) to a single call. Same XQC_ENABLE_FEC guard
     * as get_fec_stats — we surface "fec not built" so the consumer can
     * stop probing for the rest of the scrape. */
    mqvpn_internal_fec_entry_t entries[MQVPN_MAX_USERS];
    int n = mqvpn_server_get_all_fec_stats(server, entries, MQVPN_MAX_USERS);
    if (n < 0) return ctrl_error(resp, resp_len, "fec not built");

    /* Field name parity with get_status: "n_clients" + "clients[]". A
     * connected user IS a client in mqvpn nomenclature; "users" is used
     * by list_users for the registered auth-table users (a superset). */
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    bool ok = yyjson_mut_obj_add_bool(doc, root, "ok", true);
    ok &= yyjson_mut_obj_add_int(doc, root, "n_clients", n);
    yyjson_mut_val *jclients = yyjson_mut_obj_add_arr(doc, root, "clients");
    ok &= jclients != NULL;
    for (int i = 0; i < n; i++) {
        const mqvpn_internal_fec_stats_t *fs = &entries[i].stats;
        yyjson_mut_val *jc = yyjson_mut_arr_add_obj(doc, jclients);
        ok &= yyjson_mut_obj_add_strcpy(doc, jc, "user", entries[i].user);
        ok &= yyjson_mut_obj_add_uint(doc, jc, "enable_fec", fs->enable_fec);
        ok &= yyjson_mut_obj_add_uint(doc, jc, "mp_state", fs->mp_state);
        ok &= yyjson_mut_obj_add_strcpy(doc, jc, "mp_state_label",
                                        fs->mp_state_label ? fs->mp_state_label
                                                           : "unknown");
        ok &= yyjson_mut_obj_add_uint(doc, jc, "fec_send_cnt", fs->fec_send_cnt);
        ok &= yyjson_mut_obj_add_uint(doc, jc, "fec_recover_cnt", fs->fec_recover_cnt);
        ok &= yyjson_mut_obj_add_uint(doc, jc, "lost_dgram_cnt", fs->lost_dgram_cnt);
        ok &= yyjson_mut_obj_add_uint(doc, jc, "total_app_bytes", fs->total_app_bytes);
        ok &=
            yyjson_mut_obj_add_uint(doc, jc, "standby_app_bytes", fs->standby_app_bytes);
    }
    if (!ok) {
        yyjson_mut_doc_free(doc);
        return ctrl_reply(NULL, resp, resp_len);
    }
    return ctrl_reply(doc, resp, resp_len);
}

static int
ctrl_cmd_get_reorder_stats(yyjson_val *req, char *resp, size_t resp_len,
                           ctrl_socket_t *cs)
{
    mqvpn_server_t *server = cs->server;
    (void)req;
    /* Aggregate reorder-shim RX counters across all live conns (§17). One
     * fixed-shape object, no per-conn array. The getter zero-fills when no
     * conn has reorder enabled, so the JSON is always well-formed (all-zero
     * counters). */
    mqvpn_reorder_stats_t rs;
    if (mqvpn_server_get_reorder_stats(server, &rs) < 0)
        return ctrl_error(resp, resp_len, "internal error");

    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(doc);
    yyjson_mut_doc_set_root(doc, root);
    bool ok = yyjson_mut_obj_add_bool(doc, root, "ok", true);
    yyjson_mut_val *r = yyjson_mut_obj_add_obj(doc, root, "reorder");
    ok &= r != NULL;
    ok &= yyjson_mut_obj_add_uint(doc, r, "gap_count", rs.gap_count);
    ok &= yyjson_mut_obj_add_uint(doc, r, "gap_filled_count", rs.gap_filled_count);
    ok &= yyjson_mut_obj_add_uint(doc, r, "gap_timeout_count", rs.gap_timeout_count);
    ok &= yyjson_mut_obj_add_uint(doc, r, "gap_overflow_count", rs.gap_overflow_count);
    ok &= yyjson_mut_obj_add_uint(doc, r, "gap_demote_count", rs.gap_demote_count);
    ok &= yyjson_mut_obj_add_uint(doc, r, "gap_reset_count", rs.gap_reset_count);
    ok &= yyjson_mut_obj_add_uint(doc, r, "ack_demote_count", rs.ack_demote_count);
    ok &= yyjson_mut_obj_add_uint(doc, r, "too_late_drop_count", rs.too_late_drop_count);
    ok &= yyjson_mut_obj_add_uint(doc, r, "too_far_ahead_drop_count",
                                  rs.too_far_ahead_drop_count);
    ok &=
        yyjson_mut_obj_add_uint(doc, r, "duplicate_drop_count", rs.duplicate_drop_count);
    ok &= yyjson_mut_obj_add_uint(doc, r, "pool_drop_count", rs.pool_drop_count);
    ok &= yyjson_mut_obj_add_uint(doc, r, "per_flow_limit_drop_count",
                                  rs.per_flow_limit_drop_count);
    ok &= yyjson_mut_obj_add_uint(doc, r, "reset_discard_count", rs.reset_discard_count);
    ok &= yyjson_mut_obj_add_uint(doc, r, "delivered_count", rs.delivered_count);
    ok &= ctrl_add_ms(doc, r, "added_latency_p99_ms",
                      mqvpn_reorder_latency_percentile(&rs, 0.99));
    ok &=
        ctrl_add_ms(doc, r, "added_latency_max_ms", (double)rs.residence_max_us / 1000.0);
    ok &= ctrl_add_ms(doc, r, "added_latency_buffered_p99_ms",
                      mqvpn_reorder_latency_buffered_percentile(&rs, 0.99));
    if (!ok) {
        yyjson_mut_doc_free(doc);
        return ctrl_reply(NULL, resp, resp_len);
    }
    return ctrl_reply(doc, resp, resp_len);
}

/* Commands take the whole socket context, not just the server handle: some
 * answers (get_stats' udp_rx_* pair) come from platform-owned state that
 * never crosses the library ABI. Handlers that only need the server open
 * with `mqvpn_server_t *server = cs->server;` and are otherwise unchanged. */
typedef int (*ctrl_cmd_fn)(yyjson_val *req, char *resp, size_t resp_len,
                           ctrl_socket_t *cs);

/* Keep in sync (and in order) with the file-header command list. */
static const struct {
    const char *name;
    ctrl_cmd_fn fn;
} ctrl_cmds[] = {
    {"add_user", ctrl_cmd_add_user},
    {"remove_user", ctrl_cmd_remove_user},
    {"list_users", ctrl_cmd_list_users},
    {"get_stats", ctrl_cmd_get_stats},
    {"get_status", ctrl_cmd_get_status},
    {"get_build_info", ctrl_cmd_get_build_info},
    {"get_fec_stats", ctrl_cmd_get_fec_stats},
    {"get_all_fec_stats", ctrl_cmd_get_all_fec_stats},
    {"get_reorder_stats", ctrl_cmd_get_reorder_stats},
};

static int
dispatch(const char *req, char *resp, size_t resp_len, ctrl_socket_t *cs)
{
    /* STOP_WHEN_DONE: bytes after the first complete value (read together
     * with the request) are ignored, like the brace framing in ctrl_on_read.
     * Without INSITU yyjson only reads the buffer, hence the cast. */
    yyjson_doc *doc = yyjson_read_opts((char *)req, strlen(req),
                                       YYJSON_READ_STOP_WHEN_DONE, NULL, NULL);
    yyjson_val *root = yyjson_doc_get_root(doc);
    char cmd[32] = {0};
    int rc;

    /* NULL doc or non-object root: yyjson_obj_get returns NULL -> -1. */
    if (json_copy_str(yyjson_obj_get(root, "cmd"), cmd, sizeof(cmd)) < 0) {
        rc = ctrl_error(resp, resp_len, "missing cmd");
    } else {
        ctrl_cmd_fn fn = NULL;
        for (size_t i = 0; i < sizeof(ctrl_cmds) / sizeof(ctrl_cmds[0]); i++)
            if (strcmp(cmd, ctrl_cmds[i].name) == 0) {
                fn = ctrl_cmds[i].fn;
                break;
            }
        rc =
            fn ? fn(root, resp, resp_len, cs) : ctrl_error(resp, resp_len, "unknown cmd");
    }
    yyjson_doc_free(doc); /* handlers neither free nor keep the request doc */
    return rc;
}

/* ── Connection read handler ─────────────────────────────────────────────── */

/* Common per-connection teardown: unhook the libevent event, close the fd,
 * release the connection's slot in the ctrl-socket's active-connection
 * count, and free the connection struct. conn->fd is set once in
 * ctrl_on_accept() and never changes, so it always matches the fd the
 * caller's event fired on. */
static void
ctrl_conn_close(ctrl_conn_t *conn)
{
    event_del(conn->ev);
    event_free(conn->ev);
    close(conn->fd);
    conn->cs->n_conns--;
    free(conn);
}

static void
ctrl_on_read(evutil_socket_t fd, short what, void *arg)
{
    ctrl_conn_t *conn = (ctrl_conn_t *)arg;

    /* Idle timeout — close without processing */
    if (what & EV_TIMEOUT) {
        ctrl_conn_close(conn);
        return;
    }

    /* Accumulate data until we have a complete request */
    while (conn->req_len < CTRL_MAX_REQ) {
        ssize_t n = read(fd, conn->req + conn->req_len, CTRL_MAX_REQ - conn->req_len);
        if (n > 0) {
            conn->req_len += (size_t)n;

            /* Detect a complete JSON object by brace counting */
            const char *p = conn->req;
            while (*p && isspace((unsigned char)*p))
                p++;
            if (*p == '{') {
                int depth = 0, in_str = 0;
                int complete = 0;
                for (size_t i = (size_t)(p - conn->req); i < conn->req_len; i++) {
                    char c = conn->req[i];
                    if (in_str) {
                        if (c == '\\') {
                            i++;
                            continue;
                        }
                        if (c == '"') in_str = 0;
                    } else {
                        if (c == '"')
                            in_str = 1;
                        else if (c == '{')
                            depth++;
                        else if (c == '}' && --depth == 0) {
                            complete = 1;
                            break;
                        }
                    }
                }
                if (!complete) continue;
            } else if (!memchr(conn->req, '\n', conn->req_len)) {
                continue; /* newline-terminated form: wait for more */
            }
        } else if (n == 0) {
            break; /* EOF — process whatever we have */
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return; /* wait for more data */
        } else {
            /* read error — close connection */
            ctrl_conn_close(conn);
            return;
        }
        break;
    }

    conn->req[conn->req_len] = '\0';

    char resp[CTRL_MAX_RESP_BYTES];
    int rlen = dispatch(conn->req, resp, sizeof(resp) - 2, conn->cs);
    if (rlen <= 0) {
        /* dispatch failed to format anything — close silently. */
    } else if ((size_t)rlen >= sizeof(resp) - 2) {
        /* The reply did not fit in resp. Send a small error JSON instead so the
         * client doesn't see a malformed body, and emit a warning. */
        static const char too_large[] =
            "{\"ok\":false,\"error\":\"response too large\"}\n";
        (void)write(fd, too_large, sizeof(too_large) - 1);
        LOG_WRN(
            "control: dispatch response truncated (would have been %d bytes, max %zu)",
            rlen, sizeof(resp) - 2);
    } else {
        resp[rlen] = '\n';
        resp[rlen + 1] = '\0';
        (void)write(fd, resp, (size_t)rlen + 1);
    }

    ctrl_conn_close(conn);
}

/* ── Accept handler ──────────────────────────────────────────────────────── */

static void
ctrl_on_accept(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    ctrl_socket_t *cs = (ctrl_socket_t *)arg;

    if (cs->n_conns >= CTRL_MAX_CONNS) {
        int cfd = accept(fd, NULL, NULL);
        if (cfd >= 0) {
            const char *msg = "{\"ok\":false,\"error\":\"too many connections\"}\n";
            (void)write(cfd, msg, strlen(msg));
            close(cfd);
        }
        return;
    }

    int cfd = accept(fd, NULL, NULL);
    if (cfd < 0) return;

    int flags = fcntl(cfd, F_GETFL, 0);
    if (flags < 0 || fcntl(cfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(cfd);
        return;
    }

    ctrl_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) {
        close(cfd);
        return;
    }

    conn->fd = cfd;
    conn->cs = cs;
    conn->ev =
        event_new(cs->eb, cfd, EV_READ | EV_PERSIST | EV_TIMEOUT, ctrl_on_read, conn);
    if (!conn->ev) {
        free(conn);
        close(cfd);
        return;
    }
    struct timeval tv = {.tv_sec = CTRL_READ_TIMEOUT_SEC};
    event_add(conn->ev, &tv);
    cs->n_conns++;
}

/* ── Public API ──────────────────────────────────────────────────────────── */

ctrl_socket_t *
ctrl_socket_create(struct event_base *eb, const char *addr, int port,
                   mqvpn_server_t *server, ctrl_rx_stats_fn rx_stats, void *rx_ctx)
{
    if (!eb || port <= 0 || port > 65535 || !server) return NULL;

    if (!addr || addr[0] == '\0') addr = "127.0.0.1";

    /* Warn if exposed beyond loopback — the control API has no auth */
    if (strcmp(addr, "127.0.0.1") != 0 && strcmp(addr, "::1") != 0)
        LOG_WRN("control API: binding to non-loopback address %s — "
                "the control API has no authentication",
                addr);

    ctrl_socket_t *cs = calloc(1, sizeof(*cs));
    if (!cs) return NULL;
    cs->eb = eb;
    cs->server = server;
    /* Borrowed getter — the platform ctx outlives this socket. */
    cs->rx_stats = rx_stats;
    cs->rx_ctx = rx_ctx;

    /* Determine address family */
    struct sockaddr_in sin4;
    struct sockaddr_in6 sin6;
    struct sockaddr *sa;
    socklen_t sa_len;

    memset(&sin4, 0, sizeof(sin4));
    memset(&sin6, 0, sizeof(sin6));

    if (inet_pton(AF_INET6, addr, &sin6.sin6_addr) == 1) {
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port = htons((uint16_t)port);
        sa = (struct sockaddr *)&sin6;
        sa_len = sizeof(sin6);
        cs->listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
    } else {
        if (inet_pton(AF_INET, addr, &sin4.sin_addr) != 1) {
            LOG_ERR("control API: invalid address '%s'", addr);
            free(cs);
            return NULL;
        }
        sin4.sin_family = AF_INET;
        sin4.sin_port = htons((uint16_t)port);
        sa = (struct sockaddr *)&sin4;
        sa_len = sizeof(sin4);
        cs->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    }

    if (cs->listen_fd < 0) {
        LOG_ERR("control API: socket(): %s", strerror(errno));
        free(cs);
        return NULL;
    }

    int opt = 1;
    setsockopt(cs->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(cs->listen_fd, sa, sa_len) < 0) {
        LOG_ERR("control API: bind(%s:%d): %s", addr, port, strerror(errno));
        close(cs->listen_fd);
        free(cs);
        return NULL;
    }

    if (listen(cs->listen_fd, 8) < 0) {
        LOG_ERR("control API: listen(): %s", strerror(errno));
        close(cs->listen_fd);
        free(cs);
        return NULL;
    }

    int flags = fcntl(cs->listen_fd, F_GETFL, 0);
    fcntl(cs->listen_fd, F_SETFL, flags | O_NONBLOCK);

    cs->ev_accept =
        event_new(eb, cs->listen_fd, EV_READ | EV_PERSIST, ctrl_on_accept, cs);
    if (!cs->ev_accept) {
        close(cs->listen_fd);
        free(cs);
        return NULL;
    }
    event_add(cs->ev_accept, NULL);

    LOG_INF("control API listening on %s:%d", addr, port);
    return cs;
}

void
ctrl_socket_destroy(ctrl_socket_t *cs)
{
    if (!cs) return;
    if (cs->ev_accept) {
        event_del(cs->ev_accept);
        event_free(cs->ev_accept);
    }
    if (cs->listen_fd >= 0) close(cs->listen_fd);
    free(cs);
}
