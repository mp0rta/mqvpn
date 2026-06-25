// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * config.c — INI/JSON configuration file parser for mqvpn
 */
#include "config.h"
#include "json_mini.h"
#include "libmqvpn.h"
#include "log.h"

#include <errno.h>
#include <limits.h>
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
    switch (section) {
    case SEC_INTERFACE:
        if (strcasecmp(key, "TunName") == 0) {
            snprintf(cfg->tun_name, sizeof(cfg->tun_name), "%s", val);
        } else if (strcasecmp(key, "Listen") == 0) {
            snprintf(cfg->listen, sizeof(cfg->listen), "%s", val);
            cfg->is_server = 1;
        } else if (strcasecmp(key, "Subnet") == 0) {
            snprintf(cfg->subnet, sizeof(cfg->subnet), "%s", val);
        } else if (strcasecmp(key, "Subnet6") == 0) {
            snprintf(cfg->subnet6, sizeof(cfg->subnet6), "%s", val);
        } else if (strcasecmp(key, "LogLevel") == 0) {
            snprintf(cfg->log_level, sizeof(cfg->log_level), "%s", val);
        } else if (strcasecmp(key, "DNS") == 0) {
            parse_dns_list(cfg, val);
        } else if (strcasecmp(key, "KillSwitch") == 0) {
            cfg->kill_switch = parse_bool(val);
        } else if (strcasecmp(key, "ManageRoutes") == 0) {
            cfg->manage_routes = parse_bool(val);
        } else if (strcasecmp(key, "Reconnect") == 0) {
            cfg->reconnect = parse_bool(val);
        } else if (strcasecmp(key, "ReconnectInterval") == 0) {
            int v = 0;
            if (parse_int_strict(val, &v) < 0 || v <= 0) {
                LOG_WRN("%s:%d: invalid ReconnectInterval '%s'; ignoring", path, lineno,
                        val);
            } else {
                cfg->reconnect_interval = v;
            }
        } else if (strcasecmp(key, "MTU") == 0) {
            int v = 0;
            if (parse_int_strict(val, &v) < 0) {
                LOG_WRN("%s:%d: invalid MTU '%s'; ignoring", path, lineno, val);
                break;
            }
            if (v != 0 && (v < 1280 || v > 9000)) {
                LOG_WRN("%s:%d: MTU must be 1280..9000, got %d; ignoring", path, lineno,
                        v);
            } else {
                cfg->tun_mtu = v;
            }
        } else {
            LOG_WRN("%s:%d: unknown key '%s' in [Interface]", path, lineno, key);
        }
        break;

    case SEC_SERVER:
        if (strcasecmp(key, "Address") == 0) {
            snprintf(cfg->server_addr, sizeof(cfg->server_addr), "%s", val);
        } else if (strcasecmp(key, "ServerName") == 0) {
            snprintf(cfg->tls_server_name, sizeof(cfg->tls_server_name), "%s", val);
        } else if (strcasecmp(key, "Insecure") == 0) {
            cfg->insecure = parse_bool(val);
        } else {
            LOG_WRN("%s:%d: unknown key '%s' in [Server]", path, lineno, key);
        }
        break;

    case SEC_TLS:
        if (strcasecmp(key, "Cert") == 0) {
            snprintf(cfg->cert_file, sizeof(cfg->cert_file), "%s", val);
        } else if (strcasecmp(key, "Key") == 0) {
            snprintf(cfg->key_file, sizeof(cfg->key_file), "%s", val);
        } else {
            LOG_WRN("%s:%d: unknown key '%s' in [TLS]", path, lineno, key);
        }
        break;

    case SEC_AUTH:
        if (strcasecmp(key, "Key") == 0) {
            /* Context: [Auth] Key is server_auth_key if is_server,
             * else auth_key (client). We store in both and let the
             * caller use the right one based on is_server. */
            snprintf(cfg->server_auth_key, sizeof(cfg->server_auth_key), "%s", val);
            snprintf(cfg->auth_key, sizeof(cfg->auth_key), "%s", val);
        } else if (strcasecmp(key, "User") == 0) {
            parse_user_pair(cfg, val, lineno, path);
        } else if (strcasecmp(key, "MaxClients") == 0) {
            int v = 0;
            if (parse_int_strict(val, &v) < 0 || v <= 0) {
                LOG_WRN("%s:%d: invalid MaxClients '%s'; using default 64", path, lineno,
                        val);
                cfg->max_clients = 64;
            } else {
                cfg->max_clients = v;
            }
        } else {
            LOG_WRN("%s:%d: unknown key '%s' in [Auth]", path, lineno, key);
        }
        break;

    case SEC_MULTIPATH:
        if (strcasecmp(key, "Scheduler") == 0) {
            snprintf(cfg->scheduler, sizeof(cfg->scheduler), "%s", val);
        } else if (strcasecmp(key, "CC") == 0) {
            snprintf(cfg->cc, sizeof(cfg->cc), "%s", val);
        } else if (strcasecmp(key, "InitMaxPathId") == 0) {
            unsigned long long v = 0;
            if (parse_u64_strict(val, &v) < 0 || v > MQVPN_INIT_MAX_PATH_ID_MAX) {
                LOG_WRN("%s:%d: invalid InitMaxPathId '%s'", path, lineno, val);
            } else {
                cfg->init_max_path_id = v;
            }
        } else if (strcasecmp(key, "Path") == 0) {
            if (cfg->n_paths < MQVPN_CONFIG_MAX_PATHS) {
                snprintf(cfg->paths[cfg->n_paths], sizeof(cfg->paths[0]), "%s", val);
                cfg->n_paths++;
            } else {
                LOG_WRN("%s:%d: max %d paths supported, ignoring '%s'", path, lineno,
                        MQVPN_CONFIG_MAX_PATHS, val);
            }
        } else {
            LOG_WRN("%s:%d: unknown key '%s' in [Multipath]", path, lineno, key);
        }
        break;

    case SEC_CONTROL:
        if (strcasecmp(key, "Listen") == 0) {
            snprintf(cfg->control_listen, sizeof(cfg->control_listen), "%s", val);
        } else {
            LOG_WRN("%s:%d: unknown key '%s' in [Control]", path, lineno, key);
        }
        break;

    case SEC_REORDER: {
        /* All numeric keys store the raw value; cross-side invariants (cap
         * power-of-two, ingress < egress) are enforced by
         * mqvpn_reorder_config_validate() when the config is applied. */
        mqvpn_reorder_config_t *r = &cfg->reorder;
        if (strcasecmp(key, "Enabled") == 0) {
            mqvpn_reorder_mode_t m = MQVPN_REORDER_OFF;
            if (parse_reorder_enabled(val, &m) < 0) {
                LOG_WRN("%s:%d: invalid [Reorder] Enabled '%s'; ignoring", path, lineno,
                        val);
            } else {
                r->mode = m;
            }
        } else if (strcasecmp(key, "MaxWaitMs") == 0) {
            uint32_t v = 0;
            if (parse_u32_strict(val, &v) < 0)
                LOG_WRN("%s:%d: invalid MaxWaitMs '%s'", path, lineno, val);
            else {
                r->max_wait_ms = v;
                r->has_explicit_wait = 1;
            }
        } else if (strcasecmp(key, "CapPackets") == 0) {
            uint32_t v = 0;
            if (parse_u32_strict(val, &v) < 0)
                LOG_WRN("%s:%d: invalid CapPackets '%s'", path, lineno, val);
            else {
                r->cap_packets_per_flow = v;
                r->has_explicit_cap = 1;
            }
        } else if (strcasecmp(key, "MaxBytesPerFlow") == 0) {
            unsigned long long v = 0;
            if (parse_u64_strict(val, &v) < 0)
                LOG_WRN("%s:%d: invalid MaxBytesPerFlow '%s'", path, lineno, val);
            else
                r->max_buffer_bytes_per_flow = v;
        } else if (strcasecmp(key, "ClassifyWindow") == 0) {
            uint32_t v = 0;
            if (parse_u32_strict(val, &v) < 0 || v > 0xffff)
                LOG_WRN("%s:%d: invalid ClassifyWindow '%s'", path, lineno, val);
            else
                r->classify_window = (uint16_t)v;
        } else if (strcasecmp(key, "AckDemoteMaxLarge") == 0) {
            uint32_t v = 0;
            if (parse_u32_strict(val, &v) < 0 || v > 0xffff)
                LOG_WRN("%s:%d: invalid AckDemoteMaxLarge '%s'", path, lineno, val);
            else
                r->ack_demote_max_large_packets = (uint16_t)v;
        } else if (strcasecmp(key, "SmallPacketThreshold") == 0) {
            uint32_t v = 0;
            if (parse_u32_strict(val, &v) < 0)
                LOG_WRN("%s:%d: invalid SmallPacketThreshold '%s'", path, lineno, val);
            else
                r->small_packet_threshold_bytes = v;
        } else if (strcasecmp(key, "ResetMarkPackets") == 0) {
            uint32_t v = 0;
            if (parse_u32_strict(val, &v) < 0)
                LOG_WRN("%s:%d: invalid ResetMarkPackets '%s'", path, lineno, val);
            else
                r->reset_mark_packets = v;
        } else if (strcasecmp(key, "ResetIdleGraceMs") == 0) {
            uint32_t v = 0;
            if (parse_u32_strict(val, &v) < 0)
                LOG_WRN("%s:%d: invalid ResetIdleGraceMs '%s'", path, lineno, val);
            else
                r->reset_idle_grace_ms = v;
        } else if (strcasecmp(key, "MaxFlows") == 0) {
            uint32_t v = 0;
            if (parse_u32_strict(val, &v) < 0)
                LOG_WRN("%s:%d: invalid MaxFlows '%s'", path, lineno, val);
            else
                r->max_flows = v;
        } else if (strcasecmp(key, "GlobalMaxBytes") == 0) {
            unsigned long long v = 0;
            if (parse_u64_strict(val, &v) < 0)
                LOG_WRN("%s:%d: invalid GlobalMaxBytes '%s'", path, lineno, val);
            else
                r->global_max_buffer_bytes = v;
        } else if (strcasecmp(key, "IngressIdleSec") == 0) {
            uint32_t v = 0;
            if (parse_u32_strict(val, &v) < 0)
                LOG_WRN("%s:%d: invalid IngressIdleSec '%s'", path, lineno, val);
            else
                r->ingress_idle_timeout_sec = v;
        } else if (strcasecmp(key, "EgressIdleSec") == 0) {
            uint32_t v = 0;
            if (parse_u32_strict(val, &v) < 0)
                LOG_WRN("%s:%d: invalid EgressIdleSec '%s'", path, lineno, val);
            else
                r->egress_idle_timeout_sec = v;
        } else {
            LOG_WRN("%s:%d: unknown key '%s' in [Reorder]", path, lineno, key);
        }
        break;
    }

    case SEC_REORDER_RULE: {
        /* Keys fill the rule slot pushed by reorder_rule_begin() on section
         * entry. An over-cap [ReorderRule] is demoted to SEC_NONE at section
         * entry, so its keys never reach this case. This n_rules==0 guard only
         * defends against a [ReorderRule] key arriving with no slot ever pushed
         * (e.g. a key before the first section header). */
        if (cfg->reorder.n_rules == 0) break;
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
        break;
    }

    default: LOG_WRN("%s:%d: key '%s' outside any section", path, lineno, key); break;
    }
}

int
mqvpn_config_load_json_filecfg(mqvpn_file_config_t *cfg, const char *json_text)
{
    if (!cfg || !json_text) return -1;

    const char *v = NULL;
    int iv;
    char s32[32], s64[64], s256[256], s280[280];

    v = json_find_key(json_text, "mode");
    if (v && json_read_string(v, s32, sizeof(s32)) == 0) {
        if (strcasecmp(s32, "server") == 0)
            cfg->is_server = 1;
        else if (strcasecmp(s32, "client") == 0)
            cfg->is_server = 0;
    }

    v = json_find_key(json_text, "tun_name");
    if (v && json_read_string(v, s32, sizeof(s32)) == 0)
        mqvpn_copy_str(cfg->tun_name, sizeof(cfg->tun_name), s32);

    v = json_find_key(json_text, "log_level");
    if (v && json_read_string(v, s32, sizeof(s32)) == 0)
        mqvpn_copy_str(cfg->log_level, sizeof(cfg->log_level), s32);

    v = json_find_key(json_text, "listen");
    if (v && json_read_string(v, s280, sizeof(s280)) == 0) {
        mqvpn_copy_str(cfg->listen, sizeof(cfg->listen), s280);
        cfg->is_server = 1;
    }

    v = json_find_key(json_text, "subnet");
    if (v && json_read_string(v, s64, sizeof(s64)) == 0)
        mqvpn_copy_str(cfg->subnet, sizeof(cfg->subnet), s64);

    v = json_find_key(json_text, "subnet6");
    if (v && json_read_string(v, s64, sizeof(s64)) == 0)
        mqvpn_copy_str(cfg->subnet6, sizeof(cfg->subnet6), s64);

    v = json_find_key(json_text, "server_addr");
    if (v && json_read_string(v, s280, sizeof(s280)) == 0)
        mqvpn_copy_str(cfg->server_addr, sizeof(cfg->server_addr), s280);

    v = json_find_key(json_text, "tls_server_name");
    if (v && json_read_string(v, s256, sizeof(s256)) == 0)
        mqvpn_copy_str(cfg->tls_server_name, sizeof(cfg->tls_server_name), s256);

    v = json_find_key(json_text, "insecure");
    if (v && json_read_bool(v, &iv) == 0) cfg->insecure = iv;

    v = json_find_key(json_text, "auth_key");
    if (v && json_read_string(v, s256, sizeof(s256)) == 0)
        mqvpn_copy_str(cfg->auth_key, sizeof(cfg->auth_key), s256);

    v = json_find_key(json_text, "server_auth_key");
    if (v && json_read_string(v, s256, sizeof(s256)) == 0)
        mqvpn_copy_str(cfg->server_auth_key, sizeof(cfg->server_auth_key), s256);

    v = json_find_key(json_text, "cert_file");
    if (v && json_read_string(v, s256, sizeof(s256)) == 0)
        mqvpn_copy_str(cfg->cert_file, sizeof(cfg->cert_file), s256);

    v = json_find_key(json_text, "key_file");
    if (v && json_read_string(v, s256, sizeof(s256)) == 0)
        mqvpn_copy_str(cfg->key_file, sizeof(cfg->key_file), s256);

    v = json_find_key(json_text, "max_clients");
    if (v && json_read_int(v, &iv) == 0) cfg->max_clients = iv > 0 ? iv : 64;

    v = json_find_key(json_text, "scheduler");
    if (v && json_read_string(v, s32, sizeof(s32)) == 0)
        mqvpn_copy_str(cfg->scheduler, sizeof(cfg->scheduler), s32);

    v = json_find_key(json_text, "cc");
    if (v && json_read_string(v, s32, sizeof(s32)) == 0)
        mqvpn_copy_str(cfg->cc, sizeof(cfg->cc), s32);

    v = json_find_key(json_text, "init_max_path_id");
    if (v) {
        uint64_t uv = 0;
        if (json_read_u64_strict(v, &uv) == 0 && uv <= MQVPN_INIT_MAX_PATH_ID_MAX) {
            cfg->init_max_path_id = uv;
        } else {
            LOG_WRN("JSON: invalid init_max_path_id; ignoring");
        }
    }

    v = json_find_key(json_text, "reconnect");
    if (v && json_read_bool(v, &iv) == 0) cfg->reconnect = iv;

    v = json_find_key(json_text, "reconnect_interval");
    if (v && json_read_int(v, &iv) == 0 && iv > 0) cfg->reconnect_interval = iv;

    v = json_find_key(json_text, "kill_switch");
    if (v && json_read_bool(v, &iv) == 0) cfg->kill_switch = iv;

    v = json_find_key(json_text, "manage_routes");
    if (v && json_read_bool(v, &iv) == 0) cfg->manage_routes = iv;

    v = json_find_key(json_text, "mtu");
    if (v && json_read_int(v, &iv) == 0) {
        if (iv != 0 && (iv < 1280 || iv > 9000)) {
            LOG_WRN("JSON: MTU must be 1280..9000, got %d; ignoring", iv);
        } else {
            cfg->tun_mtu = iv;
        }
    }

    v = json_find_key(json_text, "control_listen");
    if (v && json_read_string(v, s280, sizeof(s280)) == 0)
        mqvpn_copy_str(cfg->control_listen, sizeof(cfg->control_listen), s280);

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
    if (ro_raw && ro_end) {
        mqvpn_reorder_config_t *r = &cfg->reorder;
        const char *kv;
        uint64_t uv;

        /* u32 scalars use json_read_u64_strict + a <= 0xffffffff clamp to match
         * the INI path's parse_u32_strict exactly (which accepts up to 2^32-1,
         * not just INT_MAX) — otherwise values in (2^31, 2^32) would parse on INI
         * but be silently rejected on JSON. u16 fields keep the <= 0xffff clamp
         * (same as INI). Each numeric scalar warns when the key is PRESENT but
         * fails to parse/range-check, mirroring the INI per-key LOG_WRN and the
         * JSON enabled warning; absent keys are silent (forward-compat). */
        kv = json_find_key_bounded(ro_raw, ro_end, "enabled");
        if (kv && json_read_string(kv, s32, sizeof(s32)) == 0) {
            mqvpn_reorder_mode_t m = MQVPN_REORDER_OFF;
            if (parse_reorder_enabled(s32, &m) == 0)
                r->mode = m;
            else
                LOG_WRN("JSON: invalid reorder enabled '%s'; ignoring", s32);
        }

        kv = json_find_key_bounded(ro_raw, ro_end, "max_wait_ms");
        if (kv) {
            if (json_read_u64_strict(kv, &uv) == 0 && uv <= 0xffffffffULL) {
                r->max_wait_ms = (uint32_t)uv;
                r->has_explicit_wait = 1;
            } else
                LOG_WRN("JSON: invalid reorder max_wait_ms; keeping default");
        }

        kv = json_find_key_bounded(ro_raw, ro_end, "cap_packets");
        if (kv) {
            if (json_read_u64_strict(kv, &uv) == 0 && uv <= 0xffffffffULL) {
                r->cap_packets_per_flow = (uint32_t)uv;
                r->has_explicit_cap = 1;
            } else
                LOG_WRN("JSON: invalid reorder cap_packets; keeping default");
        }

        kv = json_find_key_bounded(ro_raw, ro_end, "max_bytes_per_flow");
        if (kv) {
            if (json_read_u64_strict(kv, &uv) == 0)
                r->max_buffer_bytes_per_flow = uv;
            else
                LOG_WRN("JSON: invalid reorder max_bytes_per_flow; keeping default");
        }

        kv = json_find_key_bounded(ro_raw, ro_end, "classify_window");
        if (kv) {
            if (json_read_u64_strict(kv, &uv) == 0 && uv <= 0xffff)
                r->classify_window = (uint16_t)uv;
            else
                LOG_WRN("JSON: invalid reorder classify_window; keeping default");
        }

        kv = json_find_key_bounded(ro_raw, ro_end, "ack_demote_max_large");
        if (kv) {
            if (json_read_u64_strict(kv, &uv) == 0 && uv <= 0xffff)
                r->ack_demote_max_large_packets = (uint16_t)uv;
            else
                LOG_WRN("JSON: invalid reorder ack_demote_max_large; keeping default");
        }

        kv = json_find_key_bounded(ro_raw, ro_end, "small_packet_threshold");
        if (kv) {
            if (json_read_u64_strict(kv, &uv) == 0 && uv <= 0xffffffffULL)
                r->small_packet_threshold_bytes = (uint32_t)uv;
            else
                LOG_WRN("JSON: invalid reorder small_packet_threshold; keeping default");
        }

        kv = json_find_key_bounded(ro_raw, ro_end, "reset_mark_packets");
        if (kv) {
            if (json_read_u64_strict(kv, &uv) == 0 && uv <= 0xffffffffULL)
                r->reset_mark_packets = (uint32_t)uv;
            else
                LOG_WRN("JSON: invalid reorder reset_mark_packets; keeping default");
        }

        kv = json_find_key_bounded(ro_raw, ro_end, "reset_idle_grace_ms");
        if (kv) {
            if (json_read_u64_strict(kv, &uv) == 0 && uv <= 0xffffffffULL)
                r->reset_idle_grace_ms = (uint32_t)uv;
            else
                LOG_WRN("JSON: invalid reorder reset_idle_grace_ms; keeping default");
        }

        kv = json_find_key_bounded(ro_raw, ro_end, "max_flows");
        if (kv) {
            if (json_read_u64_strict(kv, &uv) == 0 && uv <= 0xffffffffULL)
                r->max_flows = (uint32_t)uv;
            else
                LOG_WRN("JSON: invalid reorder max_flows; keeping default");
        }

        kv = json_find_key_bounded(ro_raw, ro_end, "global_max_bytes");
        if (kv) {
            if (json_read_u64_strict(kv, &uv) == 0)
                r->global_max_buffer_bytes = uv;
            else
                LOG_WRN("JSON: invalid reorder global_max_bytes; keeping default");
        }

        kv = json_find_key_bounded(ro_raw, ro_end, "ingress_idle_sec");
        if (kv) {
            if (json_read_u64_strict(kv, &uv) == 0 && uv <= 0xffffffffULL)
                r->ingress_idle_timeout_sec = (uint32_t)uv;
            else
                LOG_WRN("JSON: invalid reorder ingress_idle_sec; keeping default");
        }

        kv = json_find_key_bounded(ro_raw, ro_end, "egress_idle_sec");
        if (kv) {
            if (json_read_u64_strict(kv, &uv) == 0 && uv <= 0xffffffffULL)
                r->egress_idle_timeout_sec = (uint32_t)uv;
            else
                LOG_WRN("JSON: invalid reorder egress_idle_sec; keeping default");
        }
    }

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
