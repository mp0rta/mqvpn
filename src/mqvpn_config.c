// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * mqvpn_config.c — Configuration builder (opaque handle + setter pattern)
 *
 * Part of libmqvpn public API. No platform dependencies.
 */

#include "libmqvpn.h"
#include "mqvpn_internal.h"
#include "mqvpn_sched_names.h"
#include "json_mini.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int mqvpn_config_add_user(mqvpn_config_t *cfg, const char *username, const char *key);

/* json_skip_ws, mqvpn_copy_str, json_find_key, json_read_string, json_read_bool,
 * json_read_int are provided by json_mini.h */

static int
json_read_string_array(const char *p, char out[][32], int max_items, int *n_items)
{
    if (!p || !out || !n_items || *p != '[') return MQVPN_ERR_INVALID_ARG;
    p = json_skip_ws(p + 1);

    int n = 0;
    while (*p && *p != ']') {
        if (*p != '"') return MQVPN_ERR_INVALID_ARG;
        if (n >= max_items) return MQVPN_ERR_INVALID_ARG;
        if (json_read_string(p, out[n], sizeof(out[n])) != 0) {
            return MQVPN_ERR_INVALID_ARG;
        }

        const char *e = p + 1;
        while (*e && *e != '"') {
            if (*e == '\\' && e[1]) e++;
            e++;
        }
        if (*e != '"') return MQVPN_ERR_INVALID_ARG;
        p = json_skip_ws(e + 1);
        n++;

        if (*p == ',') {
            p = json_skip_ws(p + 1);
        } else if (*p != ']') {
            return MQVPN_ERR_INVALID_ARG;
        }
    }

    if (*p != ']') return MQVPN_ERR_INVALID_ARG;
    *n_items = n;
    return MQVPN_OK;
}

static int
json_add_user_cb(void *ctx, const char *name, const char *key)
{
    return (mqvpn_config_add_user((mqvpn_config_t *)ctx, name, key) == MQVPN_OK) ? 0 : -1;
}

static int
json_read_users(mqvpn_config_t *cfg, const char *p)
{
    if (!cfg || !p || *p != '[') return MQVPN_ERR_INVALID_ARG;
    cfg->n_users = 0;
    return (mqvpn_json_parse_users(p, cfg, json_add_user_cb) == 0)
               ? MQVPN_OK
               : MQVPN_ERR_INVALID_ARG;
}

/* JSON path deliberately does NOT gate "backup_fec" on XQC_ENABLE_FEC (that
 * gate lives only at the main.c CLI call site) — known, intentional drift
 * per mqvpn_sched_names.h's header comment; config format is a compat
 * surface, do not unify. */
static int
parse_scheduler_name(const char *s, mqvpn_scheduler_t *out)
{
    if (!s || !out) return MQVPN_ERR_INVALID_ARG;
    int v = mqvpn_sched_from_name(s);
    if (v < 0) return MQVPN_ERR_INVALID_ARG;
    *out = (mqvpn_scheduler_t)v;
    return MQVPN_OK;
}

static int
parse_cc_name(const char *s, mqvpn_cc_t *out)
{
    if (!s || !out) return MQVPN_ERR_INVALID_ARG;
    int v = mqvpn_cc_from_name(s);
    if (v < 0) return MQVPN_ERR_INVALID_ARG;
    *out = (mqvpn_cc_t)v;
    return MQVPN_OK;
}

static int
is_valid_scheduler(mqvpn_scheduler_t sched)
{
    return mqvpn_sched_is_valid(sched);
}

static int
is_valid_cc(mqvpn_cc_t cc)
{
    return mqvpn_cc_is_valid(cc);
}

/* ─── Config new/free ─── */

mqvpn_config_t *
mqvpn_config_new(void)
{
    mqvpn_config_t *cfg = calloc(1, sizeof(*cfg));
    if (!cfg) return NULL;

    /* Defaults */
    cfg->server_port = 443;
    cfg->scheduler = MQVPN_SCHED_WLB;
    cfg->log_level = MQVPN_LOG_INFO;
    cfg->multipath = 1;
    cfg->reconnect_enable = 1;
    cfg->reconnect_interval_sec = 5;
    cfg->max_clients = 64;
    cfg->listen_port = 443;
    cfg->init_max_path_id = 0; /* 0 = use xquic default (8) */

    /* §16: reorder shim defaults (mode OFF until explicitly enabled). */
    mqvpn_reorder_config_default(&cfg->reorder);

    /* H1: hybrid classifier defaults (disabled until explicitly enabled). */
    mqvpn_hybrid_config_default(&cfg->hybrid);

    return cfg;
}

void
mqvpn_config_free(mqvpn_config_t *cfg)
{
    if (!cfg) return;
    free(cfg);
}

/* ─── Setters ─── */

int
mqvpn_config_set_server(mqvpn_config_t *cfg, const char *host, int port)
{
    if (!cfg || !host) return MQVPN_ERR_INVALID_ARG;

    snprintf(cfg->server_host, sizeof(cfg->server_host), "%s", host);
    cfg->server_port = port;
    return MQVPN_OK;
}

int
mqvpn_config_set_tls_server_name(mqvpn_config_t *cfg, const char *name)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    if (name)
        snprintf(cfg->tls_server_name, sizeof(cfg->tls_server_name), "%s", name);
    else
        cfg->tls_server_name[0] = '\0';
    return MQVPN_OK;
}

int
mqvpn_config_set_auth_key(mqvpn_config_t *cfg, const char *key)
{
    if (!cfg || !key) return MQVPN_ERR_INVALID_ARG;

    snprintf(cfg->auth_key, sizeof(cfg->auth_key), "%s", key);
    return MQVPN_OK;
}

int
mqvpn_config_add_user(mqvpn_config_t *cfg, const char *username, const char *key)
{
    if (!cfg || !username || !key || username[0] == '\0' || key[0] == '\0') {
        return MQVPN_ERR_INVALID_ARG;
    }

    /* Reject characters that would break JSON serialization in control API */
    for (const char *p = username; *p; p++) {
        if (*p == '"' || *p == '\\' || (unsigned char)*p < 0x20)
            return MQVPN_ERR_INVALID_ARG;
    }

    for (int i = 0; i < cfg->n_users; i++) {
        if (strcmp(cfg->user_names[i], username) == 0) {
            snprintf(cfg->user_keys[i], sizeof(cfg->user_keys[i]), "%s", key);
            return MQVPN_OK;
        }
    }

    if (cfg->n_users >= MQVPN_MAX_USERS) {
        return MQVPN_ERR_MAX_CLIENTS;
    }

    snprintf(cfg->user_names[cfg->n_users], sizeof(cfg->user_names[cfg->n_users]), "%s",
             username);
    snprintf(cfg->user_keys[cfg->n_users], sizeof(cfg->user_keys[cfg->n_users]), "%s",
             key);
    cfg->n_users++;
    return MQVPN_OK;
}

int
mqvpn_config_remove_user(mqvpn_config_t *cfg, const char *username)
{
    if (!cfg || !username || username[0] == '\0') {
        return MQVPN_ERR_INVALID_ARG;
    }

    for (int i = 0; i < cfg->n_users; i++) {
        if (strcmp(cfg->user_names[i], username) == 0) {
            for (int j = i + 1; j < cfg->n_users; j++) {
                memcpy(cfg->user_names[j - 1], cfg->user_names[j],
                       sizeof(cfg->user_names[j - 1]));
                memcpy(cfg->user_keys[j - 1], cfg->user_keys[j],
                       sizeof(cfg->user_keys[j - 1]));
            }
            cfg->n_users--;
            return MQVPN_OK;
        }
    }

    return MQVPN_ERR_INVALID_ARG;
}

int
mqvpn_config_load_json(mqvpn_config_t *cfg, const char *json_text)
{
    if (!cfg || !json_text) return MQVPN_ERR_INVALID_ARG;

    const char *v = NULL;
    char tmp[256];
    int iv = 0;

    v = json_find_key(json_text, "server_host");
    if (v && json_read_string(v, tmp, sizeof(tmp)) == MQVPN_OK) {
        mqvpn_copy_str(cfg->server_host, sizeof(cfg->server_host), tmp);
    }

    v = json_find_key(json_text, "server_port");
    if (v && json_read_int(v, &iv) == MQVPN_OK) {
        cfg->server_port = iv;
    }

    v = json_find_key(json_text, "tls_server_name");
    if (v && json_read_string(v, tmp, sizeof(tmp)) == MQVPN_OK) {
        mqvpn_copy_str(cfg->tls_server_name, sizeof(cfg->tls_server_name), tmp);
    }

    v = json_find_key(json_text, "auth_key");
    if (v && json_read_string(v, tmp, sizeof(tmp)) == MQVPN_OK) {
        mqvpn_copy_str(cfg->auth_key, sizeof(cfg->auth_key), tmp);
    }

    v = json_find_key(json_text, "listen_addr");
    if (v && json_read_string(v, tmp, sizeof(tmp)) == MQVPN_OK) {
        mqvpn_copy_str(cfg->listen_addr, sizeof(cfg->listen_addr), tmp);
    }

    v = json_find_key(json_text, "listen_port");
    if (v && json_read_int(v, &iv) == MQVPN_OK) {
        cfg->listen_port = iv;
    }

    v = json_find_key(json_text, "subnet");
    if (v && json_read_string(v, tmp, sizeof(tmp)) == MQVPN_OK) {
        mqvpn_copy_str(cfg->subnet, sizeof(cfg->subnet), tmp);
    }

    v = json_find_key(json_text, "subnet6");
    if (v && json_read_string(v, tmp, sizeof(tmp)) == MQVPN_OK) {
        mqvpn_copy_str(cfg->subnet6, sizeof(cfg->subnet6), tmp);
    }

    v = json_find_key(json_text, "tls_cert");
    if (v && json_read_string(v, tmp, sizeof(tmp)) == MQVPN_OK) {
        mqvpn_copy_str(cfg->tls_cert, sizeof(cfg->tls_cert), tmp);
    }

    v = json_find_key(json_text, "tls_key");
    if (v && json_read_string(v, tmp, sizeof(tmp)) == MQVPN_OK) {
        mqvpn_copy_str(cfg->tls_key, sizeof(cfg->tls_key), tmp);
    }

    v = json_find_key(json_text, "max_clients");
    if (v && json_read_int(v, &iv) == MQVPN_OK) {
        cfg->max_clients = iv;
    }

    v = json_find_key(json_text, "insecure");
    if (v && json_read_bool(v, &iv) == MQVPN_OK) {
        cfg->insecure = iv;
    }

    v = json_find_key(json_text, "multipath");
    if (v && json_read_bool(v, &iv) == MQVPN_OK) {
        cfg->multipath = iv;
    }

    v = json_find_key(json_text, "scheduler");
    if (v && json_read_string(v, tmp, sizeof(tmp)) == MQVPN_OK) {
        mqvpn_scheduler_t sched = MQVPN_SCHED_WLB;
        if (parse_scheduler_name(tmp, &sched) != MQVPN_OK) {
            return MQVPN_ERR_INVALID_ARG;
        }
        cfg->scheduler = sched;
    }

    v = json_find_key(json_text, "cc");
    if (v && json_read_string(v, tmp, sizeof(tmp)) == MQVPN_OK) {
        mqvpn_cc_t cc = MQVPN_CC_BBR2;
        if (parse_cc_name(tmp, &cc) != MQVPN_OK) {
            return MQVPN_ERR_INVALID_ARG;
        }
        cfg->cc = cc;
    }

    v = json_find_key(json_text, "reconnect_enable");
    if (v && json_read_bool(v, &iv) == MQVPN_OK) {
        cfg->reconnect_enable = iv;
    }

    v = json_find_key(json_text, "reconnect_interval_sec");
    if (v && json_read_int(v, &iv) == MQVPN_OK) {
        cfg->reconnect_interval_sec = iv;
    }

    v = json_find_key(json_text, "killswitch_hint");
    if (v && json_read_bool(v, &iv) == MQVPN_OK) {
        cfg->killswitch_hint = iv;
    }

    v = json_find_key(json_text, "init_max_path_id");
    if (v) {
        uint64_t uv = 0;
        if (json_read_u64_strict(v, &uv) != 0 || uv > MQVPN_INIT_MAX_PATH_ID_MAX) {
            return MQVPN_ERR_INVALID_ARG;
        }
        cfg->init_max_path_id = uv;
    }

    v = json_find_key(json_text, "mtu");
    if (v) {
        if (json_read_int_strict(v, &iv) != 0 || (iv != 0 && (iv < 1280 || iv > 9000))) {
            return MQVPN_ERR_INVALID_ARG;
        }
        cfg->tun_mtu = iv;
    }

    v = json_find_key(json_text, "tun_mtu");
    if (v) {
        if (json_read_int_strict(v, &iv) != 0 || (iv != 0 && (iv < 1280 || iv > 9000))) {
            return MQVPN_ERR_INVALID_ARG;
        }
        cfg->tun_mtu = iv;
    }

    /* "paths" sets the multipath flag; individual interface names are not stored
     * in the opaque config — callers must configure interface binding separately
     * via the platform layer. */
    char arr_paths[MQVPN_MAX_PATHS][32];
    int n_paths = 0;
    v = json_find_key(json_text, "paths");
    (void)json_read_string_array(v, arr_paths, MQVPN_MAX_PATHS, &n_paths);

    v = json_find_key(json_text, "users");
    if (v && json_read_users(cfg, v) != MQVPN_OK) {
        return MQVPN_ERR_INVALID_ARG;
    }

    return MQVPN_OK;
}

int
mqvpn_config_set_insecure(mqvpn_config_t *cfg, int insecure)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    cfg->insecure = insecure;
    return MQVPN_OK;
}

int
mqvpn_config_set_scheduler(mqvpn_config_t *cfg, mqvpn_scheduler_t sched)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    if (!is_valid_scheduler(sched)) return MQVPN_ERR_INVALID_ARG;
    cfg->scheduler = sched;
    return MQVPN_OK;
}

int
mqvpn_config_set_cc(mqvpn_config_t *cfg, mqvpn_cc_t cc)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    if (!is_valid_cc(cc)) return MQVPN_ERR_INVALID_ARG;
    cfg->cc = cc;
    return MQVPN_OK;
}

int
mqvpn_config_set_init_max_path_id(mqvpn_config_t *cfg, uint64_t v)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    if (v > MQVPN_INIT_MAX_PATH_ID_MAX) return MQVPN_ERR_INVALID_ARG;
    cfg->init_max_path_id = v;
    return MQVPN_OK;
}

int
mqvpn_config_set_log_level(mqvpn_config_t *cfg, mqvpn_log_level_t level)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    cfg->log_level = level;
    return MQVPN_OK;
}

int
mqvpn_config_set_multipath(mqvpn_config_t *cfg, int enable)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    cfg->multipath = enable;
    return MQVPN_OK;
}

int
mqvpn_config_set_reconnect(mqvpn_config_t *cfg, int enable, int interval_sec)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    cfg->reconnect_enable = enable;
    cfg->reconnect_interval_sec = interval_sec > 0 ? interval_sec : 5;
    return MQVPN_OK;
}

int
mqvpn_config_set_killswitch_hint(mqvpn_config_t *cfg, int enable)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    cfg->killswitch_hint = enable;
    return MQVPN_OK;
}

int
mqvpn_config_set_clock(mqvpn_config_t *cfg, mqvpn_clock_fn clock_fn, void *clock_ctx)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    cfg->clock_fn = clock_fn;
    cfg->clock_ctx = clock_ctx;
    return MQVPN_OK;
}

int
mqvpn_config_set_listen(mqvpn_config_t *cfg, const char *addr, int port)
{
    if (!cfg || !addr) return MQVPN_ERR_INVALID_ARG;
    snprintf(cfg->listen_addr, sizeof(cfg->listen_addr), "%s", addr);
    cfg->listen_port = port;
    return MQVPN_OK;
}

int
mqvpn_config_set_subnet(mqvpn_config_t *cfg, const char *cidr)
{
    if (!cfg || !cidr) return MQVPN_ERR_INVALID_ARG;
    snprintf(cfg->subnet, sizeof(cfg->subnet), "%s", cidr);
    return MQVPN_OK;
}

int
mqvpn_config_set_subnet6(mqvpn_config_t *cfg, const char *cidr6)
{
    if (!cfg || !cidr6) return MQVPN_ERR_INVALID_ARG;
    snprintf(cfg->subnet6, sizeof(cfg->subnet6), "%s", cidr6);
    return MQVPN_OK;
}

int
mqvpn_config_set_tls_cert(mqvpn_config_t *cfg, const char *cert, const char *key)
{
    if (!cfg || !cert || !key) return MQVPN_ERR_INVALID_ARG;
    snprintf(cfg->tls_cert, sizeof(cfg->tls_cert), "%s", cert);
    snprintf(cfg->tls_key, sizeof(cfg->tls_key), "%s", key);
    return MQVPN_OK;
}

int
mqvpn_config_set_max_clients(mqvpn_config_t *cfg, int max)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    cfg->max_clients = max;
    return MQVPN_OK;
}

int
mqvpn_config_set_tun_mtu(mqvpn_config_t *cfg, int mtu)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    if (mtu != 0 && (mtu < 1280 || mtu > 9000)) return MQVPN_ERR_INVALID_ARG;
    cfg->tun_mtu = mtu;
    return MQVPN_OK;
}

/* ─── Reorder setters (§16.1) ───
 *
 * These write the corresponding field(s) of the embedded reorder config. They
 * do NOT enforce cross-side invariants (ingress < egress, cap power-of-two);
 * that is mqvpn_reorder_config_validate()'s job, run by the consumer when the
 * config is applied. AUTO and eval_force_no_demotion are intentionally not
 * exposed (AUTO is a later phase; eval_force_no_demotion is an internal test
 * knob). */

int
mqvpn_config_set_reorder_enabled(mqvpn_config_t *cfg, mqvpn_reorder_mode_t mode)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    if (mode != MQVPN_REORDER_OFF && mode != MQVPN_REORDER_ON) {
        return MQVPN_ERR_INVALID_ARG;
    }
    cfg->reorder.mode = mode;
    return MQVPN_OK;
}

int
mqvpn_config_set_reorder_wait(mqvpn_config_t *cfg, uint32_t max_wait_ms)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    cfg->reorder.max_wait_ms = max_wait_ms;
    cfg->reorder.has_explicit_wait = 1;
    return MQVPN_OK;
}

int
mqvpn_config_set_reorder_cap(mqvpn_config_t *cfg, uint32_t cap_packets,
                             uint64_t max_bytes_per_flow)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    cfg->reorder.cap_packets_per_flow = cap_packets;
    cfg->reorder.max_buffer_bytes_per_flow = max_bytes_per_flow;
    cfg->reorder.has_explicit_cap = 1;
    return MQVPN_OK;
}

int
mqvpn_config_set_reorder_classify(mqvpn_config_t *cfg, uint16_t window,
                                  uint16_t max_large, uint32_t small_threshold)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    cfg->reorder.classify_window = window;
    cfg->reorder.ack_demote_max_large_packets = max_large;
    cfg->reorder.small_packet_threshold_bytes = small_threshold;
    return MQVPN_OK;
}

int
mqvpn_config_set_reorder_reset(mqvpn_config_t *cfg, uint32_t mark_packets,
                               uint32_t idle_grace_ms)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    cfg->reorder.reset_mark_packets = mark_packets;
    cfg->reorder.reset_idle_grace_ms = idle_grace_ms;
    return MQVPN_OK;
}

int
mqvpn_config_set_reorder_limits(mqvpn_config_t *cfg, uint32_t max_flows,
                                uint64_t global_max_bytes, uint32_t ingress_idle_sec,
                                uint32_t egress_idle_sec)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    cfg->reorder.max_flows = max_flows;
    cfg->reorder.global_max_buffer_bytes = global_max_bytes;
    cfg->reorder.ingress_idle_timeout_sec = ingress_idle_sec;
    cfg->reorder.egress_idle_timeout_sec = egress_idle_sec;
    return MQVPN_OK;
}

int
mqvpn_config_add_reorder_rule(mqvpn_config_t *cfg, uint8_t proto, uint16_t port,
                              mqvpn_reorder_profile_t profile)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    /* Bound BOTH ends: the lower bound rejects a negative enum-cast, the upper
     * bound the last valid profile. A single (<= FIBER_LTE) test would admit
     * negatives. */
    if (profile < MQVPN_RPROF_QUIC_BULK || profile > MQVPN_RPROF_FIBER_LTE) {
        return MQVPN_ERR_INVALID_ARG;
    }
    if (cfg->reorder.n_rules >= MQVPN_REORDER_MAX_RULES) {
        return MQVPN_ERR_INVALID_ARG;
    }
    mqvpn_reorder_rule_t *r = &cfg->reorder.rules[cfg->reorder.n_rules];
    /* Zero every field first (per-rule params = unset; finalize's precedence
     * depends on explicit_*==0), then set the caller's intent fields. */
    memset(r, 0, sizeof(*r));
    r->proto = proto;
    r->port = port;
    r->profile = profile;
    cfg->reorder.n_rules++;
    return MQVPN_OK;
}

void
mqvpn_config_apply_reorder(mqvpn_config_t *cfg, const mqvpn_reorder_config_t *src)
{
    if (!cfg || !src) return;
    int eval = cfg->reorder.eval_force_no_demotion; /* internal-only, not bridged */
    cfg->reorder = *src; /* scalars, has_explicit_*, rules incl. explicit_*, n_rules */
    cfg->reorder.eval_force_no_demotion = eval;
}

/* ─── Hybrid setters (H1) ───
 *
 * The public setters take plain int/uint32_t so libmqvpn.h stays free of the
 * internal hybrid/classifier.h enum. The 0/1/2 ↔ enum mapping is pinned below. */

_Static_assert(MQVPN_HYBRID_TCP_STREAM == 0 && MQVPN_HYBRID_TCP_RAW == 1 &&
                   MQVPN_HYBRID_TCP_AUTO == 2,
               "public setter doc pins tcp mode values 0=stream 1=raw 2=auto");

int
mqvpn_config_set_hybrid_enabled(mqvpn_config_t *cfg, int enabled)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    cfg->hybrid.enabled = enabled ? 1 : 0;
    return MQVPN_OK;
}

int
mqvpn_config_set_hybrid_tcp_mode(mqvpn_config_t *cfg, int mode)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    /* Range-check the raw int BEFORE casting to the internal enum. */
    if (mode < 0 || mode > (int)MQVPN_HYBRID_TCP_AUTO) return MQVPN_ERR_INVALID_ARG;
    cfg->hybrid.tcp_mode = (mqvpn_hybrid_tcp_mode_t)mode;
    return MQVPN_OK;
}

int
mqvpn_config_set_hybrid_limits(mqvpn_config_t *cfg, uint32_t tcp_max_flows,
                               uint32_t tcp_idle_timeout_sec)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    /* mqvpn_hybrid_config_validate semantics: max_flows == 0 is invalid. */
    if (tcp_max_flows == 0) return MQVPN_ERR_INVALID_ARG;
    cfg->hybrid.tcp_max_flows = tcp_max_flows;
    cfg->hybrid.tcp_idle_timeout_sec = tcp_idle_timeout_sec;
    return MQVPN_OK;
}

void
mqvpn_config_apply_hybrid(mqvpn_config_t *cfg, const mqvpn_hybrid_config_t *src)
{
    if (!cfg || !src) return;
    cfg->hybrid = *src;
}

int
mqvpn_config_set_hybrid_connect_timeout(mqvpn_config_t *cfg, uint32_t sec)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    if (sec == 0) return MQVPN_ERR_INVALID_ARG;
    cfg->hybrid.tcp_connect_timeout_sec = sec;
    return MQVPN_OK;
}

int
mqvpn_config_set_hybrid_max_global_flows(mqvpn_config_t *cfg, uint32_t max_flows)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    /* Same not-zero rule as tcp_max_flows/tcp_connect_timeout above: this is
     * an admission cap, not an idle-style opt-out field, so 0 (admit
     * nothing, server-wide) is rejected as a misconfiguration rather than
     * accepted as "disabled". */
    if (max_flows == 0) return MQVPN_ERR_INVALID_ARG;
    cfg->hybrid.tcp_max_global_flows = max_flows;
    return MQVPN_OK;
}

int
mqvpn_config_set_hybrid_egress_acl(mqvpn_config_t *cfg, const char **allow, int n_allow,
                                   const char **deny, int n_deny)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    if (n_allow < 0 || n_allow > MQVPN_EGRESS_ACL_MAX || n_deny < 0 ||
        n_deny > MQVPN_EGRESS_ACL_MAX)
        return MQVPN_ERR_INVALID_ARG;
    if ((n_allow > 0 && !allow) || (n_deny > 0 && !deny)) return MQVPN_ERR_INVALID_ARG;

    /* Validate into scratch buffers first: the whole call is atomic, so a
     * malformed entry anywhere must leave cfg untouched. */
    mqvpn_cidr_entry_t parsed_allow[MQVPN_EGRESS_ACL_MAX];
    mqvpn_cidr_entry_t parsed_deny[MQVPN_EGRESS_ACL_MAX];
    for (int i = 0; i < n_allow; i++) {
        if (mqvpn_parse_cidr(allow[i], &parsed_allow[i]) < 0)
            return MQVPN_ERR_INVALID_ARG;
    }
    for (int i = 0; i < n_deny; i++) {
        if (mqvpn_parse_cidr(deny[i], &parsed_deny[i]) < 0) return MQVPN_ERR_INVALID_ARG;
    }

    if (n_allow > 0)
        memcpy(cfg->hybrid.egress_allow, parsed_allow,
               sizeof(parsed_allow[0]) * (size_t)n_allow);
    cfg->hybrid.n_egress_allow = n_allow;
    if (n_deny > 0)
        memcpy(cfg->hybrid.egress_deny, parsed_deny,
               sizeof(parsed_deny[0]) * (size_t)n_deny);
    cfg->hybrid.n_egress_deny = n_deny;
    return MQVPN_OK;
}
