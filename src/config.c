// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * config.c — INI/JSON configuration file parser for mqvpn
 *
 * Scalar keys are described ONCE in cfg_keys[]; both the INI and JSON
 * parsers walk that table. To add a scalar key: add one table row (and a
 * test in tests/test_config.c). Complex keys (DNS/User/Path/ReorderRule)
 * are hand-written in both parsers.
 */
#include "config.h"
#include "json_mini.h"
#include "libmqvpn.h"
#include "log.h"

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _MSC_VER
#  define strcasecmp _stricmp
#endif

/* ---- helpers ---- */

/* Trim leading and trailing whitespace in-place, return pointer to start */
static char *
trim(char *s)
{
    while (isspace((unsigned char)*s))
        s++;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end))
        *end-- = '\0';
    return s;
}

/* mqvpn_copy_str is provided by json_mini.h as mqvpn_copy_str */

/* Parse boolean: "true"/"yes"/"1" → 1, else 0 */
static int
parse_bool(const char *val)
{
    return (strcmp(val, "true") == 0 || strcmp(val, "yes") == 0 || strcmp(val, "1") == 0);
}

static int
parse_int_strict(const char *val, int *out)
{
    if (!val || !out || *val == '\0') return -1;

    errno = 0;
    char *end = NULL;
    long v = strtol(val, &end, 10);
    if (end == val || *end != '\0' || errno == ERANGE || v < INT_MIN || v > INT_MAX) {
        return -1;
    }

    *out = (int)v;
    return 0;
}

static int
parse_u64_strict(const char *val, unsigned long long *out)
{
    if (!val || !out || *val < '0' || *val > '9') return -1;

    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(val, &end, 10);
    if (end == val || *end != '\0' || errno == ERANGE) {
        return -1;
    }

    *out = v;
    return 0;
}

/* Section IDs */
enum {
    SEC_NONE = 0,
    SEC_INTERFACE,
    SEC_SERVER,
    SEC_TLS,
    SEC_AUTH,
    SEC_MULTIPATH,
    SEC_CONTROL,
    SEC_REORDER,
    SEC_REORDER_RULE,
};

static int
parse_section(const char *name)
{
    if (strcasecmp(name, "Interface") == 0) return SEC_INTERFACE;
    if (strcasecmp(name, "Server") == 0) return SEC_SERVER;
    if (strcasecmp(name, "TLS") == 0) return SEC_TLS;
    if (strcasecmp(name, "Auth") == 0) return SEC_AUTH;
    if (strcasecmp(name, "Multipath") == 0) return SEC_MULTIPATH;
    if (strcasecmp(name, "Control") == 0) return SEC_CONTROL;
    if (strcasecmp(name, "Reorder") == 0) return SEC_REORDER;
    if (strcasecmp(name, "ReorderRule") == 0) return SEC_REORDER_RULE;
    return -1;
}

static const char *
section_name(int section)
{
    switch (section) {
    case SEC_INTERFACE: return "Interface";
    case SEC_SERVER: return "Server";
    case SEC_TLS: return "TLS";
    case SEC_AUTH: return "Auth";
    case SEC_MULTIPATH: return "Multipath";
    case SEC_CONTROL: return "Control";
    case SEC_REORDER: return "Reorder";
    case SEC_REORDER_RULE: return "ReorderRule";
    default: return "?";
    }
}

/* Split comma-separated DNS list into cfg->dns_servers[] */
static void
parse_dns_list(mqvpn_file_config_t *cfg, const char *val)
{
    cfg->n_dns = 0;
    const char *p = val;
    while (*p && cfg->n_dns < MQVPN_CONFIG_MAX_DNS) {
        /* skip leading whitespace and commas */
        while (*p == ',' || isspace((unsigned char)*p))
            p++;
        if (*p == '\0') break;

        const char *start = p;
        while (*p && *p != ',')
            p++;

        /* copy and trim trailing whitespace */
        size_t len = (size_t)(p - start);
        if (len >= sizeof(cfg->dns_servers[0])) len = sizeof(cfg->dns_servers[0]) - 1;
        memcpy(cfg->dns_servers[cfg->n_dns], start, len);
        cfg->dns_servers[cfg->n_dns][len] = '\0';

        /* trim trailing whitespace from the copied entry */
        char *end = cfg->dns_servers[cfg->n_dns] + len - 1;
        while (end >= cfg->dns_servers[cfg->n_dns] && isspace((unsigned char)*end))
            *end-- = '\0';

        if (cfg->dns_servers[cfg->n_dns][0] != '\0') cfg->n_dns++;
    }
}

static void
add_user_entry(mqvpn_file_config_t *cfg, const char *name, const char *key, int lineno,
               const char *path)
{
    if (!name || !key || name[0] == '\0' || key[0] == '\0') {
        LOG_WRN("%s:%d: invalid user entry", path, lineno);
        return;
    }

    /* Reject characters that would break JSON serialization in control API */
    for (const char *p = name; *p; p++) {
        if (*p == '"' || *p == '\\' || (unsigned char)*p < 0x20) {
            LOG_WRN("%s:%d: username contains invalid character", path, lineno);
            return;
        }
    }

    for (int i = 0; i < cfg->n_users; i++) {
        if (strcmp(cfg->user_names[i], name) == 0) {
            snprintf(cfg->user_keys[i], sizeof(cfg->user_keys[i]), "%s", key);
            return;
        }
    }

    if (cfg->n_users >= MQVPN_CONFIG_MAX_USERS) {
        LOG_WRN("%s:%d: max %d users supported, ignoring '%s'", path, lineno,
                MQVPN_CONFIG_MAX_USERS, name);
        return;
    }

    snprintf(cfg->user_names[cfg->n_users], sizeof(cfg->user_names[cfg->n_users]), "%s",
             name);
    snprintf(cfg->user_keys[cfg->n_users], sizeof(cfg->user_keys[cfg->n_users]), "%s",
             key);
    cfg->n_users++;
}

static void
parse_user_pair(mqvpn_file_config_t *cfg, const char *val, int lineno, const char *path)
{
    char pair[360];
    snprintf(pair, sizeof(pair), "%s", val);
    char *sep = strchr(pair, ':');
    if (!sep) {
        LOG_WRN("%s:%d: [Auth] User must be NAME:KEY", path, lineno);
        return;
    }

    *sep = '\0';
    char *name = trim(pair);
    char *key = trim(sep + 1);
    add_user_entry(cfg, name, key, lineno, path);
}

/* json_skip_ws, json_find_key, json_read_string, json_read_bool,
 * json_read_int are provided by json_mini.h */

/* Parse JSON string array, silently capping at max_items (parity with INI
 * Path=/DNS= lists). Extra entries are parsed syntactically but not copied. */
static int
json_read_string_array(const char *p, char out[][64], int max_items, int *n_items)
{
    if (!p || !out || !n_items || *p != '[') return -1;

    p = json_skip_ws(p + 1);
    int n = 0;
    int dropped = 0;
    while (*p && *p != ']') {
        if (*p != '"') return -1;

        if (n < max_items) {
            if (json_read_string(p, out[n], sizeof(out[n])) < 0) return -1;
            n++;
        } else {
            dropped++;
        }

        const char *e = p + 1;
        while (*e && *e != '"') {
            if (*e == '\\' && e[1]) e++;
            e++;
        }
        if (*e != '"') return -1;
        p = json_skip_ws(e + 1);

        if (*p == ',')
            p = json_skip_ws(p + 1);
        else if (*p != ']')
            return -1;
    }

    if (*p != ']') return -1;
    if (dropped)
        LOG_WRN("JSON: array capped at %d items, dropped %d", max_items, dropped);
    *n_items = n;
    return 0;
}

static int
json_read_users(mqvpn_file_config_t *cfg, const char *p)
{
    if (!cfg || !p || *p != '[') return -1;
    cfg->n_users = 0;
    p = json_skip_ws(p + 1);

    while (*p && *p != ']') {
        char name[64] = {0};
        char key[256] = {0};

        if (*p == '"') {
            char pair[360] = {0};
            if (json_read_string(p, pair, sizeof(pair)) < 0) return -1;
            char *sep = strchr(pair, ':');
            if (!sep) return -1;
            *sep = '\0';
            mqvpn_copy_str(name, sizeof(name), pair);
            mqvpn_copy_str(key, sizeof(key), sep + 1);

            const char *e = p + 1;
            while (*e && *e != '"') {
                if (*e == '\\' && e[1]) e++;
                e++;
            }
            if (*e != '"') return -1;
            p = json_skip_ws(e + 1);
        } else if (*p == '{') {
            const char *end = strchr(p, '}');
            if (!end) return -1;

            char obj[512];
            size_t len = (size_t)(end - p + 1);
            if (len >= sizeof(obj)) return -1;
            memcpy(obj, p, len);
            obj[len] = '\0';

            const char *name_v = json_find_key(obj, "name");
            const char *key_v = json_find_key(obj, "key");
            if (!name_v || !key_v) return -1;
            if (json_read_string(name_v, name, sizeof(name)) < 0) return -1;
            if (json_read_string(key_v, key, sizeof(key)) < 0) return -1;

            p = json_skip_ws(end + 1);
        } else {
            return -1;
        }

        add_user_entry(cfg, name, key, 0, "json");

        if (*p == ',')
            p = json_skip_ws(p + 1);
        else if (*p != ']')
            return -1;
    }

    return (*p == ']') ? 0 : -1;
}

/* Parse the "reorder_rules" JSON array of {proto, port, profile} objects into
 * cfg->reorder.rules[], mirroring json_read_users(). Reuses the same value
 * mappers (parse_reorder_proto/parse_reorder_profile) and the same per-rule
 * begin/cap/no-clobber discipline as the INI [ReorderRule] path: each accepted
 * object is seeded with begin-time defaults (proto UDP, profile QUIC_BULK) and
 * over-cap objects are dropped without touching the last accepted rule. An
 * invalid proto/profile/port warns but keeps the begin-time default (the rule
 * is still added), exactly as the INI parser does. Returns 0 on success, -1 on
 * malformed JSON. Declared here; defined after the reorder mappers below. */
static int json_read_reorder_rules(mqvpn_file_config_t *cfg, const char *p);

/* §16.1 [Reorder] Enabled mapping: off/false→OFF, on/true→ON, auto→ON+warn
 * (adaptive is a later phase; v1 treats auto as ON). Returns 0 on a recognized
 * value (and writes *out), -1 otherwise. */
static int
parse_reorder_enabled(const char *val, mqvpn_reorder_mode_t *out)
{
    if (strcasecmp(val, "off") == 0 || strcasecmp(val, "false") == 0) {
        *out = MQVPN_REORDER_OFF;
        return 0;
    }
    if (strcasecmp(val, "on") == 0 || strcasecmp(val, "true") == 0) {
        *out = MQVPN_REORDER_ON;
        return 0;
    }
    if (strcasecmp(val, "auto") == 0) {
        LOG_WRN("[Reorder] Enabled=auto: adaptive is Phase 3; treating as ON");
        *out = MQVPN_REORDER_ON;
        return 0;
    }
    return -1;
}

/* Parse an L4 protocol token for [ReorderRule] Proto. v1 only handles UDP
 * (the only eligible protocol, §4); a bare numeric value is also accepted. */
static int
parse_reorder_proto(const char *val, uint8_t *out)
{
    if (strcasecmp(val, "udp") == 0) {
        *out = MQVPN_IPPROTO_UDP;
        return 0;
    }
    int v = 0;
    if (parse_int_strict(val, &v) == 0 && v >= 0 && v <= 255) {
        *out = (uint8_t)v;
        return 0;
    }
    return -1;
}

static int
parse_reorder_profile(const char *val, mqvpn_reorder_profile_t *out)
{
    if (strcasecmp(val, "quic_bulk") == 0) {
        *out = MQVPN_RPROF_QUIC_BULK;
        return 0;
    }
    if (strcasecmp(val, "low_latency") == 0) {
        *out = MQVPN_RPROF_LOW_LATENCY;
        return 0;
    }
    if (strcasecmp(val, "default_udp") == 0) {
        *out = MQVPN_RPROF_DEFAULT_UDP;
        return 0;
    }
    if (strcasecmp(val, "cellular_bond") == 0) {
        *out = MQVPN_RPROF_CELLULAR_BOND;
        return 0;
    }
    if (strcasecmp(val, "fiber_lte") == 0) {
        *out = MQVPN_RPROF_FIBER_LTE;
        return 0;
    }
    return -1;
}

/* u32 helper sharing parse_u64_strict's strictness, with a range clamp. */
static int
parse_u32_strict(const char *val, uint32_t *out)
{
    unsigned long long v = 0;
    if (parse_u64_strict(val, &v) < 0 || v > 0xffffffffULL) return -1;
    *out = (uint32_t)v;
    return 0;
}

/* Begin a new [ReorderRule] instance: push a default-initialized rule slot that
 * subsequent Proto/Port/Profile keys fill in (mirrors [Multipath] Path= cap
 * handling). Returns 0 on success, -1 if the rule cap is hit (already warned). */
static int
reorder_rule_begin(mqvpn_file_config_t *cfg, int lineno, const char *path)
{
    if (cfg->reorder.n_rules >= MQVPN_REORDER_MAX_RULES) {
        LOG_WRN("%s:%d: max %d reorder rules supported, ignoring [ReorderRule]", path,
                lineno, MQVPN_REORDER_MAX_RULES);
        return -1;
    }
    mqvpn_reorder_rule_t *r = &cfg->reorder.rules[cfg->reorder.n_rules];
    /* Zero every field first (per-rule params = unset; finalize's precedence
     * depends on explicit_*==0). One memset covers all fields and doesn't rely
     * on a prior whole-struct memset surviving into a reused config. */
    memset(r, 0, sizeof(*r));
    r->proto = MQVPN_IPPROTO_UDP;       /* v1 default: UDP */
    r->profile = MQVPN_RPROF_QUIC_BULK; /* port stays 0 = match-any until Port= */
    cfg->reorder.n_rules++;
    return 0;
}

/* ── Scalar config key descriptor table ──────────────────────────────────
 * ONE row per scalar key, walked by BOTH the INI parser (cfg_key_apply_ini,
 * called from handle_kv) and the JSON parser (cfg_key_apply_json, called
 * from mqvpn_config_load_json_filecfg). Complex keys (DNS, User, Path,
 * ReorderRule, JSON "mode") stay hand-written in their parsers.
 * Adding a scalar key = adding one row here.
 */

typedef enum {
    CFGK_STR,          /* char[]: snprintf copy, silent truncation          */
    CFGK_BOOL,         /* int: parse_bool / json_read_bool                  */
    CFGK_INT,          /* int: int_ok() gate; optional fallback on invalid  */
    CFGK_U32,          /* uint32_t: inclusive max bound                     */
    CFGK_U16,          /* uint16_t: max 0xffff                              */
    CFGK_U64,          /* 64-bit unsigned: inclusive max bound              */
    CFGK_REORDER_MODE, /* mqvpn_reorder_mode_t via parse_reorder_enabled    */
} cfg_key_type_t;

typedef struct {
    uint8_t section;      /* SEC_*: INI section; SEC_REORDER doubles as
                             "inside the JSON reorder object" scope         */
    const char *ini_key;  /* NULL = JSON-only key                           */
    const char *json_key; /* NULL = INI-only key                           */
    cfg_key_type_t type;
    size_t offset;            /* offsetof(mqvpn_file_config_t, field)    */
    size_t size;              /* CFGK_STR only: sizeof(field)            */
    unsigned long long max;   /* CFGK_U32/U16/U64: inclusive upper bound */
    int (*int_ok)(int v);     /* CFGK_INT: NULL = accept any parsed      */
    int has_invalid_fallback; /* CFGK_INT: write fallback when invalid   */
    int invalid_fallback;
    void (*post_set)(mqvpn_file_config_t *cfg); /* side effect, NULL = none */
} cfg_key_desc_t;

_Static_assert(sizeof(unsigned long long) == sizeof(uint64_t),
               "CFGK_U64 stores through a single 8-byte write");
_Static_assert(sizeof(((mqvpn_file_config_t *)0)->listen) <= 280,
               "cfg_key_apply_json sbuf must cover the largest CFGK_STR field");

/* int_ok gates */
static int
cfgk_int_positive(int v)
{
    return v > 0;
}

static int
cfgk_int_mtu(int v)
{
    return v == 0 || (v >= 1280 && v <= 9000);
}

/* post_set hooks */
static void
cfgk_post_mark_server(mqvpn_file_config_t *cfg)
{
    cfg->is_server = 1;
}

static void
cfgk_post_mirror_auth_key(mqvpn_file_config_t *cfg)
{
    /* INI [Auth] Key is mode-agnostic: mirror into server_auth_key. */
    snprintf(cfg->server_auth_key, sizeof(cfg->server_auth_key), "%s", cfg->auth_key);
}

static void
cfgk_post_explicit_wait(mqvpn_file_config_t *cfg)
{
    cfg->reorder.has_explicit_wait = 1;
}

static void
cfgk_post_explicit_cap(mqvpn_file_config_t *cfg)
{
    cfg->reorder.has_explicit_cap = 1;
}

#define CFGK_OFF(field) offsetof(mqvpn_file_config_t, field)

/* Row helpers keep the table readable; positional init otherwise. */
#define CFG_STR(sec, ik, jk, field)                                        \
    {                                                                      \
        (sec), (ik), (jk), CFGK_STR, CFGK_OFF(field),                      \
            sizeof(((mqvpn_file_config_t *)0)->field), 0, NULL, 0, 0, NULL \
    }
#define CFG_STR_POST(sec, ik, jk, field, post)                               \
    {                                                                        \
        (sec), (ik), (jk), CFGK_STR, CFGK_OFF(field),                        \
            sizeof(((mqvpn_file_config_t *)0)->field), 0, NULL, 0, 0, (post) \
    }
#define CFG_BOOL(sec, ik, jk, field)                                          \
    {                                                                         \
        (sec), (ik), (jk), CFGK_BOOL, CFGK_OFF(field), 0, 0, NULL, 0, 0, NULL \
    }
#define CFG_INT(sec, ik, jk, field, okfn)                                      \
    {                                                                          \
        (sec), (ik), (jk), CFGK_INT, CFGK_OFF(field), 0, 0, (okfn), 0, 0, NULL \
    }
#define CFG_INT_FB(sec, ik, jk, field, okfn, fb)                                  \
    {                                                                             \
        (sec), (ik), (jk), CFGK_INT, CFGK_OFF(field), 0, 0, (okfn), 1, (fb), NULL \
    }
#define CFG_U32(sec, ik, jk, field)                                                      \
    {                                                                                    \
        (sec), (ik), (jk), CFGK_U32, CFGK_OFF(field), 0, 0xffffffffULL, NULL, 0, 0, NULL \
    }
#define CFG_U32_POST(sec, ik, jk, field, post)                                      \
    {                                                                               \
        (sec), (ik), (jk), CFGK_U32, CFGK_OFF(field), 0, 0xffffffffULL, NULL, 0, 0, \
            (post)                                                                  \
    }
#define CFG_U16(sec, ik, jk, field)                                                  \
    {                                                                                \
        (sec), (ik), (jk), CFGK_U16, CFGK_OFF(field), 0, 0xffffULL, NULL, 0, 0, NULL \
    }
#define CFG_U64(sec, ik, jk, field, maxv)                                         \
    {                                                                             \
        (sec), (ik), (jk), CFGK_U64, CFGK_OFF(field), 0, (maxv), NULL, 0, 0, NULL \
    }

static const cfg_key_desc_t cfg_keys[] = {
    /* [Interface] */
    CFG_STR(SEC_INTERFACE, "TunName", "tun_name", tun_name),
    CFG_STR_POST(SEC_INTERFACE, "Listen", "listen", listen, cfgk_post_mark_server),
    CFG_STR(SEC_INTERFACE, "Subnet", "subnet", subnet),
    CFG_STR(SEC_INTERFACE, "Subnet6", "subnet6", subnet6),
    CFG_STR(SEC_INTERFACE, "LogLevel", "log_level", log_level),
    CFG_BOOL(SEC_INTERFACE, "KillSwitch", "kill_switch", kill_switch),
    CFG_BOOL(SEC_INTERFACE, "ManageRoutes", "manage_routes", manage_routes),
    CFG_BOOL(SEC_INTERFACE, "Reconnect", "reconnect", reconnect),
    CFG_INT(SEC_INTERFACE, "ReconnectInterval", "reconnect_interval", reconnect_interval,
            cfgk_int_positive),
    CFG_INT(SEC_INTERFACE, "MTU", "mtu", tun_mtu, cfgk_int_mtu),
    /* [Server] */
    CFG_STR(SEC_SERVER, "Address", "server_addr", server_addr),
    CFG_STR(SEC_SERVER, "ServerName", "tls_server_name", tls_server_name),
    CFG_BOOL(SEC_SERVER, "Insecure", "insecure", insecure),
    /* [TLS] */
    CFG_STR(SEC_TLS, "Cert", "cert_file", cert_file),
    CFG_STR(SEC_TLS, "Key", "key_file", key_file),
    /* [Auth] — INI Key is mode-agnostic dual-write; JSON has two keys */
    CFG_STR_POST(SEC_AUTH, "Key", NULL, auth_key, cfgk_post_mirror_auth_key),
    CFG_STR(SEC_AUTH, NULL, "auth_key", auth_key),
    CFG_STR(SEC_AUTH, NULL, "server_auth_key", server_auth_key),
    CFG_INT_FB(SEC_AUTH, "MaxClients", "max_clients", max_clients, cfgk_int_positive, 64),
    /* [Control] */
    CFG_STR(SEC_CONTROL, "Listen", "control_listen", control_listen),
    /* [Multipath] */
    CFG_STR(SEC_MULTIPATH, "Scheduler", "scheduler", scheduler),
    CFG_STR(SEC_MULTIPATH, "CC", "cc", cc),
    CFG_U64(SEC_MULTIPATH, "InitMaxPathId", "init_max_path_id", init_max_path_id,
            MQVPN_INIT_MAX_PATH_ID_MAX),
    /* [Reorder] — JSON side lives inside the bounded "reorder" object */
    {SEC_REORDER, "Enabled", "enabled", CFGK_REORDER_MODE, CFGK_OFF(reorder.mode), 0, 0,
     NULL, 0, 0, NULL},
    CFG_U32_POST(SEC_REORDER, "MaxWaitMs", "max_wait_ms", reorder.max_wait_ms,
                 cfgk_post_explicit_wait),
    CFG_U32_POST(SEC_REORDER, "CapPackets", "cap_packets", reorder.cap_packets_per_flow,
                 cfgk_post_explicit_cap),
    CFG_U64(SEC_REORDER, "MaxBytesPerFlow", "max_bytes_per_flow",
            reorder.max_buffer_bytes_per_flow, 0xffffffffffffffffULL),
    CFG_U16(SEC_REORDER, "ClassifyWindow", "classify_window", reorder.classify_window),
    CFG_U16(SEC_REORDER, "AckDemoteMaxLarge", "ack_demote_max_large",
            reorder.ack_demote_max_large_packets),
    CFG_U32(SEC_REORDER, "SmallPacketThreshold", "small_packet_threshold",
            reorder.small_packet_threshold_bytes),
    CFG_U32(SEC_REORDER, "ResetMarkPackets", "reset_mark_packets",
            reorder.reset_mark_packets),
    CFG_U32(SEC_REORDER, "ResetIdleGraceMs", "reset_idle_grace_ms",
            reorder.reset_idle_grace_ms),
    CFG_U32(SEC_REORDER, "MaxFlows", "max_flows", reorder.max_flows),
    CFG_U64(SEC_REORDER, "GlobalMaxBytes", "global_max_bytes",
            reorder.global_max_buffer_bytes, 0xffffffffffffffffULL),
    CFG_U32(SEC_REORDER, "IngressIdleSec", "ingress_idle_sec",
            reorder.ingress_idle_timeout_sec),
    CFG_U32(SEC_REORDER, "EgressIdleSec", "egress_idle_sec",
            reorder.egress_idle_timeout_sec),
};

/* Shared typed store. Returns 0 on success, -1 on invalid value (caller
 * warns per-surface). `v_ull` carries U32/U16/U64 payloads, `v_int` carries
 * BOOL/INT, `v_str` carries STR/REORDER_MODE. */
static int
cfg_key_store(mqvpn_file_config_t *cfg, const cfg_key_desc_t *d, const char *v_str,
              int v_int, unsigned long long v_ull)
{
    char *base = (char *)cfg + d->offset;
    /* memcpy for sub-int/64-bit/enum fields avoids alignment+aliasing questions;
     * int fields store via *(int *) since the offset names a real int member. */
    switch (d->type) {
    case CFGK_STR: snprintf(base, d->size, "%s", v_str); break;
    case CFGK_BOOL: *(int *)base = v_int; break;
    case CFGK_INT:
        /* forced-invalid sentinel from the walkers. Note: a genuine input of
         * -2147483648 collides with this sentinel and is rejected too;
         * acceptable since no legal config int is INT_MIN, but a future
         * gate-less signed row author must know. */
        if (v_int == INT_MIN) {
            if (d->has_invalid_fallback) *(int *)base = d->invalid_fallback;
            return -1;
        }
        if (d->int_ok && !d->int_ok(v_int)) {
            if (d->has_invalid_fallback) *(int *)base = d->invalid_fallback;
            return -1;
        }
        *(int *)base = v_int;
        break;
    case CFGK_U32: {
        if (v_ull > d->max) return -1;
        uint32_t u = (uint32_t)v_ull;
        memcpy(base, &u, sizeof(u));
        break;
    }
    case CFGK_U16: {
        if (v_ull > d->max) return -1;
        uint16_t u = (uint16_t)v_ull;
        memcpy(base, &u, sizeof(u));
        break;
    }
    case CFGK_U64: {
        if (v_ull > d->max) return -1;
        memcpy(base, &v_ull, sizeof(v_ull));
        break;
    }
    case CFGK_REORDER_MODE: {
        mqvpn_reorder_mode_t m = MQVPN_REORDER_OFF;
        if (parse_reorder_enabled(v_str, &m) < 0) return -1;
        memcpy(base, &m, sizeof(m));
        break;
    }
    }
    if (d->post_set) d->post_set(cfg);
    return 0;
}

/* INI-side walker: returns 1 if (section,key) matched a table row (value
 * applied or warned), 0 if the key is unknown to the table. */
static int
cfg_key_apply_ini(mqvpn_file_config_t *cfg, int section, const char *key, const char *val,
                  int lineno, const char *path)
{
    for (size_t i = 0; i < sizeof(cfg_keys) / sizeof(cfg_keys[0]); i++) {
        const cfg_key_desc_t *d = &cfg_keys[i];
        if (d->section != section || !d->ini_key || strcasecmp(d->ini_key, key) != 0)
            continue;

        int rc = 0;
        switch (d->type) {
        case CFGK_STR:
        case CFGK_REORDER_MODE: rc = cfg_key_store(cfg, d, val, 0, 0); break;
        case CFGK_BOOL: rc = cfg_key_store(cfg, d, NULL, parse_bool(val), 0); break;
        case CFGK_INT: {
            /* INT_MIN sentinel: forced-invalid marker so an unparseable value
             * takes the same fallback path as a parsed-but-rejected one
             * (cfg_key_store recognizes the sentinel explicitly). */
            int v = 0;
            if (parse_int_strict(val, &v) < 0)
                rc = d->has_invalid_fallback ? cfg_key_store(cfg, d, NULL, INT_MIN, 0)
                                             : -1;
            else
                rc = cfg_key_store(cfg, d, NULL, v, 0);
            break;
        }
        case CFGK_U32:
        case CFGK_U16: {
            uint32_t v = 0;
            rc = (parse_u32_strict(val, &v) < 0) ? -1 : cfg_key_store(cfg, d, NULL, 0, v);
            break;
        }
        case CFGK_U64: {
            unsigned long long v = 0;
            rc = (parse_u64_strict(val, &v) < 0) ? -1 : cfg_key_store(cfg, d, NULL, 0, v);
            break;
        }
        }
        if (rc < 0)
            LOG_WRN("%s:%d: invalid %s '%s'; %s", path, lineno, d->ini_key, val,
                    d->has_invalid_fallback ? "using default" : "ignoring");
        return 1;
    }
    return 0;
}

/* JSON-side walker: applies every table row that has a json_key. SEC_REORDER
 * rows are searched inside [ro_raw, ro_end) (the bounded "reorder" object);
 * everything else at top level. Absent keys are silent (forward-compat);
 * present-but-invalid keys warn. */
static void
cfg_key_apply_json(mqvpn_file_config_t *cfg, const char *json_text, const char *ro_raw,
                   const char *ro_end)
{
    /* Must cover the largest CFGK_STR destination (listen/server_addr/
     * control_listen, all char[280]) or JSON strings would truncate
     * shorter than INI ones. */
    char sbuf[280];
    for (size_t i = 0; i < sizeof(cfg_keys) / sizeof(cfg_keys[0]); i++) {
        const cfg_key_desc_t *d = &cfg_keys[i];
        if (!d->json_key) continue;

        const char *v;
        if (d->section == SEC_REORDER) {
            if (!ro_raw || !ro_end) continue;
            v = json_find_key_bounded(ro_raw, ro_end, d->json_key);
        } else {
            v = json_find_key(json_text, d->json_key);
        }
        if (!v) continue;

        int rc = 0;
        switch (d->type) {
        case CFGK_STR:
        case CFGK_REORDER_MODE:
            if (json_read_string(v, sbuf, sizeof(sbuf)) < 0)
                rc = -1;
            else
                rc = cfg_key_store(cfg, d, sbuf, 0, 0);
            break;
        case CFGK_BOOL: {
            int iv = 0;
            rc = (json_read_bool(v, &iv) < 0) ? -1 : cfg_key_store(cfg, d, NULL, iv, 0);
            break;
        }
        case CFGK_INT: {
            int iv = 0;
            if (json_read_int(v, &iv) < 0)
                rc = d->has_invalid_fallback ? cfg_key_store(cfg, d, NULL, INT_MIN, 0)
                                             : -1;
            else
                rc = cfg_key_store(cfg, d, NULL, iv, 0);
            break;
        }
        case CFGK_U32:
        case CFGK_U16:
        case CFGK_U64: {
            /* u64 lexing + table bound == INI parse_u32_strict semantics for
             * u32 fields (accepts (2^31, 2^32); regression pin deb2115). */
            uint64_t uv = 0;
            rc = (json_read_u64_strict(v, &uv) < 0) ? -1
                                                    : cfg_key_store(cfg, d, NULL, 0, uv);
            break;
        }
        }
        if (rc < 0)
            LOG_WRN("JSON: invalid %s%s; %s", d->section == SEC_REORDER ? "reorder " : "",
                    d->json_key, d->has_invalid_fallback ? "using default" : "ignoring");
    }
}

static int
json_read_reorder_rules(mqvpn_file_config_t *cfg, const char *p)
{
    if (!cfg || !p || *p != '[') return -1;
    p = json_skip_ws(p + 1);

    while (*p && *p != ']') {
        if (*p != '{') return -1;
        /* Bound sub-key searches to this rule's object span (no fixed-size copy):
         * json_find_key() would otherwise leak into the next rule. An
         * unterminated object aborts the whole array. */
        const char *obj_end = json_object_end(p);
        if (!obj_end) return -1;

        /* Push a default-initialized slot (proto UDP, profile QUIC_BULK, port 0);
         * over-cap rules are dropped without clobbering the last accepted one.
         * lineno 0 / path "json" mirror the synthetic context used by the
         * users array (LOG_WRN only). */
        if (reorder_rule_begin(cfg, 0, "json") == 0) {
            mqvpn_reorder_rule_t *rule = &cfg->reorder.rules[cfg->reorder.n_rules - 1];

            const char *proto_v = json_find_key_bounded(p, obj_end, "proto");
            if (proto_v) {
                char s[32];
                if (json_read_string(proto_v, s, sizeof(s)) == 0) {
                    uint8_t pr = 0;
                    if (parse_reorder_proto(s, &pr) == 0)
                        rule->proto = pr;
                    else
                        LOG_WRN("JSON: invalid reorder rule proto '%s'; keeping default",
                                s);
                }
            }

            const char *port_v = json_find_key_bounded(p, obj_end, "port");
            if (port_v) {
                int pv = 0;
                if (json_read_int_strict(port_v, &pv) == 0 && pv >= 0 && pv <= 0xffff)
                    rule->port = (uint16_t)pv;
                else
                    LOG_WRN("JSON: invalid reorder rule port; keeping default");
            }

            const char *prof_v = json_find_key_bounded(p, obj_end, "profile");
            if (prof_v) {
                char s[32];
                if (json_read_string(prof_v, s, sizeof(s)) == 0) {
                    mqvpn_reorder_profile_t prof = MQVPN_RPROF_QUIC_BULK;
                    if (parse_reorder_profile(s, &prof) == 0)
                        rule->profile = prof;
                    else
                        LOG_WRN(
                            "JSON: invalid reorder rule profile '%s'; keeping default",
                            s);
                }
            }

            /* per-rule param overrides, validated exactly like the INI path:
             * max_wait_ms==0 is rejected (use profile default_udp), cap must be
             * a non-zero power of two; rejected values stay unset (explicit_*==0). */
            const char *wait_v = json_find_key_bounded(p, obj_end, "max_wait_ms");
            if (wait_v) {
                uint64_t wv = 0;
                if (json_read_u64_strict(wait_v, &wv) != 0 || wv > 0xffffffffULL)
                    LOG_WRN("JSON: invalid reorder rule max_wait_ms; ignoring");
                else if (wv == 0)
                    LOG_WRN("JSON: reorder rule max_wait_ms=0 unsupported; use "
                            "profile=default_udp for pass-through; ignoring");
                else
                    rule->explicit_wait_ms = (uint32_t)wv;
            }

            const char *cap_v = json_find_key_bounded(p, obj_end, "cap_packets");
            if (cap_v) {
                uint64_t cv = 0;
                if (json_read_u64_strict(cap_v, &cv) != 0 || cv > 0xffffffffULL)
                    LOG_WRN("JSON: invalid reorder rule cap_packets; ignoring");
                else if (!mqvpn_reorder_cap_is_valid((uint32_t)cv))
                    LOG_WRN("JSON: reorder rule cap_packets must be a non-zero power "
                            "of two; ignoring");
                else
                    rule->explicit_cap = (uint32_t)cv;
            }
        }

        p = json_skip_ws(obj_end + 1);
        if (*p == ',')
            p = json_skip_ws(p + 1);
        else if (*p != ']')
            return -1;
    }

    return (*p == ']') ? 0 : -1;
}

/* Handle a key=value pair in the given section */
static void
handle_kv(mqvpn_file_config_t *cfg, int section, const char *key, const char *val,
          int lineno, const char *path)
{
    /* Complex keys first (lists / repeated keys / rule slots). */
    switch (section) {
    case SEC_INTERFACE:
        if (strcasecmp(key, "DNS") == 0) {
            parse_dns_list(cfg, val);
            return;
        }
        break;
    case SEC_AUTH:
        if (strcasecmp(key, "User") == 0) {
            parse_user_pair(cfg, val, lineno, path);
            return;
        }
        break;
    case SEC_MULTIPATH:
        if (strcasecmp(key, "Path") == 0) {
            if (cfg->n_paths < MQVPN_CONFIG_MAX_PATHS) {
                snprintf(cfg->paths[cfg->n_paths], sizeof(cfg->paths[0]), "%s", val);
                cfg->n_paths++;
            } else {
                LOG_WRN("%s:%d: max %d paths supported, ignoring '%s'", path, lineno,
                        MQVPN_CONFIG_MAX_PATHS, val);
            }
            return;
        }
        break;
    case SEC_REORDER_RULE: {
        /* Keys fill the rule slot pushed by reorder_rule_begin() on section
         * entry. An over-cap [ReorderRule] is demoted to SEC_NONE at section
         * entry, so its keys never reach this case. This n_rules==0 guard only
         * defends against a [ReorderRule] key arriving with no slot ever pushed
         * (e.g. a key before the first section header). */
        if (cfg->reorder.n_rules == 0) return;
        mqvpn_reorder_rule_t *rule = &cfg->reorder.rules[cfg->reorder.n_rules - 1];
        if (strcasecmp(key, "Proto") == 0) {
            uint8_t p = 0;
            if (parse_reorder_proto(val, &p) < 0)
                LOG_WRN("%s:%d: invalid [ReorderRule] Proto '%s'", path, lineno, val);
            else
                rule->proto = p;
        } else if (strcasecmp(key, "Port") == 0) {
            uint32_t v = 0;
            if (parse_u32_strict(val, &v) < 0 || v > 0xffff)
                LOG_WRN("%s:%d: invalid [ReorderRule] Port '%s'", path, lineno, val);
            else
                rule->port = (uint16_t)v;
        } else if (strcasecmp(key, "Profile") == 0) {
            mqvpn_reorder_profile_t prof = MQVPN_RPROF_QUIC_BULK;
            if (parse_reorder_profile(val, &prof) < 0)
                LOG_WRN("%s:%d: invalid [ReorderRule] Profile '%s'", path, lineno, val);
            else
                rule->profile = prof;
        } else if (strcasecmp(key, "MaxWaitMs") == 0) {
            uint32_t v = 0;
            if (parse_u32_strict(val, &v) < 0)
                LOG_WRN("%s:%d: invalid [ReorderRule] MaxWaitMs '%s'", path, lineno, val);
            else if (v == 0)
                /* per-rule wait=0 is unsupported; pass-through is expressed via
                 * Profile=default_udp. Leave explicit_wait_ms unset. */
                LOG_WRN("%s:%d: [ReorderRule] MaxWaitMs=0 unsupported; use "
                        "Profile=default_udp for pass-through; ignoring",
                        path, lineno);
            else
                rule->explicit_wait_ms = v;
        } else if (strcasecmp(key, "CapPackets") == 0) {
            uint32_t v = 0;
            if (parse_u32_strict(val, &v) < 0)
                LOG_WRN("%s:%d: invalid [ReorderRule] CapPackets '%s'", path, lineno,
                        val);
            else if (!mqvpn_reorder_cap_is_valid(v))
                LOG_WRN("%s:%d: [ReorderRule] CapPackets '%s' must be a non-zero power "
                        "of two; ignoring",
                        path, lineno, val);
            else
                rule->explicit_cap = v;
        } else {
            LOG_WRN("%s:%d: unknown key '%s' in [ReorderRule]", path, lineno, key);
        }
        return;
    }
    case SEC_NONE:
        LOG_WRN("%s:%d: key '%s' outside any section", path, lineno, key);
        return;
    default: break;
    }

    /* Scalar keys via the descriptor table. */
    if (cfg_key_apply_ini(cfg, section, key, val, lineno, path)) return;

    LOG_WRN("%s:%d: unknown key '%s' in [%s]", path, lineno, key, section_name(section));
}

int
mqvpn_config_load_json_filecfg(mqvpn_file_config_t *cfg, const char *json_text)
{
    if (!cfg || !json_text) return -1;

    const char *v = NULL;
    char s32[32];

    /* Mode has no INI counterpart (INI infers from Listen/Address). */
    v = json_find_key(json_text, "mode");
    if (v && json_read_string(v, s32, sizeof(s32)) == 0) {
        if (strcasecmp(s32, "server") == 0)
            cfg->is_server = 1;
        else if (strcasecmp(s32, "client") == 0)
            cfg->is_server = 0;
    }

    /* [Reorder] equivalent: a "reorder" object holding the same flat scalar
     * knobs as the INI section (snake_case), plus a "reorder_rules" array of
     * {proto, port, profile} objects. The Enabled string and rule proto/profile
     * go through the SAME mappers (parse_reorder_enabled/proto/profile) as the
     * INI path so the two surfaces produce identical mqvpn_reorder_config_t.
     * Numeric ranges mirror the INI parser; the cross-side invariants
     * (cap power-of-two, ingress < egress) are enforced by
     * mqvpn_reorder_config_validate() at apply time, not here. Unknown sub-keys
     * are simply not found (forward-compat). eval_force_no_demotion is
     * deliberately NOT parseable (internal/test knob, same as INI). */
    const char *ro_raw = json_find_key(json_text, "reorder");
    /* Bound every sub-key search to the reorder object's span. json_find_key()
     * does not stop at the object's closing brace, so an unbounded search would
     * leak into sibling keys (e.g. reorder_rules' max_wait_ms) and falsely set
     * has_explicit_*. json_object_end() returns the matching '}' (no fixed-size
     * copy, so arbitrarily large objects are handled); a malformed/unterminated
     * object yields ro_end == NULL and the block is skipped (same as absent). */
    const char *ro_end = (ro_raw && *ro_raw == '{') ? json_object_end(ro_raw) : NULL;

    /* All scalar keys — one walk of the shared descriptor table. */
    cfg_key_apply_json(cfg, json_text, ro_raw, ro_end);

    char dns_buf[MQVPN_CONFIG_MAX_DNS][64];
    int n_dns = 0;
    v = json_find_key(json_text, "dns");
    if (v && json_read_string_array(v, dns_buf, MQVPN_CONFIG_MAX_DNS, &n_dns) == 0) {
        cfg->n_dns = 0;
        for (int i = 0; i < n_dns; i++) {
            mqvpn_copy_str(cfg->dns_servers[cfg->n_dns],
                           sizeof(cfg->dns_servers[cfg->n_dns]), dns_buf[i]);
            cfg->n_dns++;
        }
    }

    char path_buf[MQVPN_CONFIG_MAX_PATHS][64];
    int n_paths = 0;
    v = json_find_key(json_text, "paths");
    if (v && json_read_string_array(v, path_buf, MQVPN_CONFIG_MAX_PATHS, &n_paths) == 0) {
        cfg->n_paths = 0;
        for (int i = 0; i < n_paths; i++) {
            mqvpn_copy_str(cfg->paths[cfg->n_paths], sizeof(cfg->paths[cfg->n_paths]),
                           path_buf[i]);
            cfg->n_paths++;
        }
    }

    v = json_find_key(json_text, "users");
    if (v && json_read_users(cfg, v) < 0) return -1;

    v = json_find_key(json_text, "reorder_rules");
    if (v && json_read_reorder_rules(cfg, v) < 0) return -1;

    return 0;
}

/* Split "host:port" or "[host]:port" (IPv6 bracket form). Pure — no I/O.
 * Returns 0 on success, -1 on malformed input.
 */
static int
split_addr_port(const char *str, char *host, size_t host_len, int *port)
{
    if (!str || !host || !port || host_len == 0) return -1;
    const char *port_start;
    if (str[0] == '[') {
        const char *close = strchr(str, ']');
        if (!close || close[1] != ':') return -1;
        size_t hlen = (size_t)(close - str - 1);
        if (hlen == 0 || hlen >= host_len) return -1;
        memcpy(host, str + 1, hlen);
        host[hlen] = '\0';
        port_start = close + 2;
    } else {
        const char *colon = strrchr(str, ':');
        if (!colon || colon == str) return -1;
        size_t hlen = (size_t)(colon - str);
        if (hlen >= host_len) return -1;
        memcpy(host, str, hlen);
        host[hlen] = '\0';
        port_start = colon + 1;
    }
    /* Reject leading whitespace and sign prefix that strtol would otherwise
     * silently accept. Port must be a bare unsigned decimal. */
    if (!isdigit((unsigned char)*port_start)) return -1;
    char *end;
    long p = strtol(port_start, &end, 10);
    if (*end != '\0' || p <= 0 || p > 65535) return -1;
    *port = (int)p;
    return 0;
}

int
mqvpn_resolve_control_endpoint(const char *file_listen, const char *cli_addr,
                               int cli_port, int cli_port_set, char *addr_buf,
                               size_t addr_buf_len, const char **out_addr, int *out_port)
{
    if (!addr_buf || addr_buf_len == 0 || !out_addr || !out_port) return -1;
    *out_addr = NULL;
    *out_port = 0;
    addr_buf[0] = '\0';

    /* Step 1: INI base. */
    if (file_listen && file_listen[0] != '\0') {
        int port_buf = 0;
        if (split_addr_port(file_listen, addr_buf, addr_buf_len, &port_buf) < 0) {
            return -1;
        }
        *out_addr = addr_buf;
        *out_port = port_buf;
    }

    /* Step 2: per-field CLI overrides. */
    if (cli_addr != NULL) *out_addr = cli_addr;
    if (cli_port_set) *out_port = cli_port; /* 0 means explicit disable */

    return 0;
}

/* ---- public API ---- */

void
mqvpn_config_defaults(mqvpn_file_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->tun_name, sizeof(cfg->tun_name), "mqvpn0");
    snprintf(cfg->log_level, sizeof(cfg->log_level), "info");
    snprintf(cfg->listen, sizeof(cfg->listen), "0.0.0.0:443");
    snprintf(cfg->subnet, sizeof(cfg->subnet), "10.0.0.0/24");
    snprintf(cfg->cert_file, sizeof(cfg->cert_file), "server.crt");
    snprintf(cfg->key_file, sizeof(cfg->key_file), "server.key");
    snprintf(cfg->scheduler, sizeof(cfg->scheduler), "wlb");
    snprintf(cfg->cc, sizeof(cfg->cc), "bbr2");
    cfg->max_clients = 64;
    cfg->reconnect = 1;
    cfg->reconnect_interval = 5;
    cfg->manage_routes = 1;
    mqvpn_reorder_config_default(&cfg->reorder); /* §16: reorder defaults (mode OFF) */
}

int
mqvpn_config_load(mqvpn_file_config_t *cfg, const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        LOG_ERR("config: cannot open '%s': %m", path);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    if (sz < 0) {
        fclose(fp);
        return -1;
    }
    rewind(fp);

    char *buf = malloc((size_t)sz + 1);
    if (!buf) {
        fclose(fp);
        return -1;
    }

    size_t got = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    buf[got] = '\0';

    const char *s = buf;
    while (*s && isspace((unsigned char)*s))
        s++;

    if (*s == '{') {
        int rc = mqvpn_config_load_json_filecfg(cfg, s);
        free(buf);
        return rc;
    }

    int lineno = 0;
    int section = SEC_NONE;
    char *line = strtok(buf, "\n");
    while (line) {
        lineno++;
        char *t = trim(line);

        if (*t == '\0' || *t == '#' || *t == ';') {
            line = strtok(NULL, "\n");
            continue;
        }

        if (*t == '[') {
            char *end = strchr(t, ']');
            if (!end) {
                LOG_WRN("%s:%d: malformed section header", path, lineno);
                line = strtok(NULL, "\n");
                continue;
            }
            *end = '\0';
            int sec = parse_section(t + 1);
            if (sec < 0) {
                LOG_WRN("%s:%d: unknown section '%s'", path, lineno, t + 1);
                section = SEC_NONE;
            } else {
                section = sec;
                /* Each [ReorderRule] occurrence pushes a fresh rule slot that
                 * its keys then fill (mirrors WireGuard repeated [Peer]). */
                if (section == SEC_REORDER_RULE) {
                    /* On over-cap the slot push fails; drop the section so its
                     * keys fall through to SEC_NONE handling instead of writing
                     * to the last accepted rule slot. */
                    if (reorder_rule_begin(cfg, lineno, path) < 0) {
                        section = SEC_NONE;
                    }
                }
            }
            line = strtok(NULL, "\n");
            continue;
        }

        char *eq = strchr(t, '=');
        if (!eq) {
            LOG_WRN("%s:%d: malformed line (no '=')", path, lineno);
            line = strtok(NULL, "\n");
            continue;
        }
        *eq = '\0';
        handle_kv(cfg, section, trim(t), trim(eq + 1), lineno, path);

        line = strtok(NULL, "\n");
    }

    free(buf);
    return 0;
}
