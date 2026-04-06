/*
 * config.c — INI/JSON configuration file parser for mqvpn
 */
#include "config.h"
#include "log.h"

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

static void
copy_str(char *dst, size_t dst_len, const char *src)
{
    if (!dst || dst_len == 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    strncpy(dst, src, dst_len - 1);
    dst[dst_len - 1] = '\0';
}

/* Parse boolean: "true"/"yes"/"1" → 1, else 0 */
static int
parse_bool(const char *val)
{
    return (strcmp(val, "true") == 0 || strcmp(val, "yes") == 0 || strcmp(val, "1") == 0);
}

/* Section IDs */
enum {
    SEC_NONE = 0,
    SEC_INTERFACE,
    SEC_SERVER,
    SEC_TLS,
    SEC_AUTH,
    SEC_MULTIPATH,
};

static int
parse_section(const char *name)
{
    if (strcasecmp(name, "Interface") == 0) return SEC_INTERFACE;
    if (strcasecmp(name, "Server") == 0) return SEC_SERVER;
    if (strcasecmp(name, "TLS") == 0) return SEC_TLS;
    if (strcasecmp(name, "Auth") == 0) return SEC_AUTH;
    if (strcasecmp(name, "Multipath") == 0) return SEC_MULTIPATH;
    return -1;
}

/* Split comma-separated DNS list into cfg->dns_servers[] */
static void
parse_dns_list(mqvpn_config_t *cfg, const char *val)
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

        if (cfg->dns_servers[cfg->n_dns][0] != '\0')
            cfg->n_dns++;
    }
}

static void
add_user_entry(mqvpn_config_t *cfg, const char *name, const char *key,
               int lineno, const char *path)
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
        LOG_WRN("%s:%d: max %d users supported, ignoring '%s'",
                path, lineno, MQVPN_CONFIG_MAX_USERS, name);
        return;
    }

    snprintf(cfg->user_names[cfg->n_users], sizeof(cfg->user_names[cfg->n_users]),
             "%s", name);
    snprintf(cfg->user_keys[cfg->n_users], sizeof(cfg->user_keys[cfg->n_users]),
             "%s", key);
    cfg->n_users++;
}

static void
parse_user_pair(mqvpn_config_t *cfg, const char *val, int lineno, const char *path)
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

static const char *json_skip_ws(const char *p)
{
    while (*p && isspace((unsigned char)*p)) p++;
    return p;
}

static const char *json_find_key(const char *json, const char *key)
{
    size_t key_len = strlen(key);
    const char *p = json;

    while ((p = strchr(p, '"')) != NULL) {
        const char *k = p + 1;
        const char *e = k;
        while (*e && *e != '"') {
            if (*e == '\\' && e[1]) e++;
            e++;
        }
        if (*e != '"') return NULL;

        if ((size_t)(e - k) == key_len && strncmp(k, key, key_len) == 0) {
            const char *c = json_skip_ws(e + 1);
            if (*c == ':') {
                return json_skip_ws(c + 1);
            }
        }
        p = e + 1;
    }
    return NULL;
}

static int json_read_string(const char *p, char *out, size_t out_len)
{
    if (!p || !out || out_len == 0 || *p != '"') return -1;
    p++;

    size_t j = 0;
    while (*p && *p != '"') {
        if (*p == '\\' && p[1]) p++;
        if (j + 1 < out_len) out[j++] = *p;
        p++;
    }
    if (*p != '"') return -1;
    out[j] = '\0';
    return 0;
}

static int json_read_bool(const char *p, int *out)
{
    if (!p || !out) return -1;
    if (strncmp(p, "true", 4) == 0) {
        *out = 1;
        return 0;
    }
    if (strncmp(p, "false", 5) == 0) {
        *out = 0;
        return 0;
    }
    return -1;
}

static int json_read_int(const char *p, int *out)
{
    if (!p || !out) return -1;
    char *end = NULL;
    long v = strtol(p, &end, 10);
    if (end == p) return -1;
    *out = (int)v;
    return 0;
}

static int json_read_string_array(const char *p,
                                  char out[][64],
                                  int max_items,
                                  int *n_items)
{
    if (!p || !out || !n_items || *p != '[') return -1;

    p = json_skip_ws(p + 1);
    int n = 0;
    while (*p && *p != ']') {
        if (*p != '"' || n >= max_items) return -1;
        if (json_read_string(p, out[n], sizeof(out[n])) < 0) return -1;

        const char *e = p + 1;
        while (*e && *e != '"') {
            if (*e == '\\' && e[1]) e++;
            e++;
        }
        if (*e != '"') return -1;
        p = json_skip_ws(e + 1);
        n++;

        if (*p == ',') p = json_skip_ws(p + 1);
        else if (*p != ']') return -1;
    }

    if (*p != ']') return -1;
    *n_items = n;
    return 0;
}

static int json_read_users(mqvpn_config_t *cfg, const char *p)
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
            copy_str(name, sizeof(name), pair);
            copy_str(key, sizeof(key), sep + 1);

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

        if (*p == ',') p = json_skip_ws(p + 1);
        else if (*p != ']') return -1;
    }

    return (*p == ']') ? 0 : -1;
}

/* Handle a key=value pair in the given section */
static void
handle_kv(mqvpn_config_t *cfg, int section, const char *key, const char *val, int lineno,
          const char *path)
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
        } else if (strcasecmp(key, "Reconnect") == 0) {
            cfg->reconnect = parse_bool(val);
        } else if (strcasecmp(key, "ReconnectInterval") == 0) {
            int v = atoi(val);
            if (v > 0) cfg->reconnect_interval = v;
        } else {
            LOG_WRN("%s:%d: unknown key '%s' in [Interface]", path, lineno, key);
        }
        break;

    case SEC_SERVER:
        if (strcasecmp(key, "Address") == 0) {
            snprintf(cfg->server_addr, sizeof(cfg->server_addr), "%s", val);
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
            cfg->max_clients = atoi(val);
            if (cfg->max_clients <= 0) cfg->max_clients = 64;
        } else {
            LOG_WRN("%s:%d: unknown key '%s' in [Auth]", path, lineno, key);
        }
        break;

    case SEC_MULTIPATH:
        if (strcasecmp(key, "Scheduler") == 0) {
            snprintf(cfg->scheduler, sizeof(cfg->scheduler), "%s", val);
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

    default:
        LOG_WRN("%s:%d: key '%s' outside any section", path, lineno, key);
        break;
    }
}

int
mqvpn_config_load_json_filecfg(mqvpn_config_t *cfg, const char *json_text)
{
    if (!cfg || !json_text) return -1;

    const char *v = NULL;
    int iv;
    char s32[32], s64[64], s256[256], s280[280];

    v = json_find_key(json_text, "mode");
    if (v && json_read_string(v, s32, sizeof(s32)) == 0) {
        if (strcasecmp(s32, "server") == 0) cfg->is_server = 1;
        else if (strcasecmp(s32, "client") == 0) cfg->is_server = 0;
    }

    v = json_find_key(json_text, "tun_name");
    if (v && json_read_string(v, s32, sizeof(s32)) == 0)
        copy_str(cfg->tun_name, sizeof(cfg->tun_name), s32);

    v = json_find_key(json_text, "log_level");
    if (v && json_read_string(v, s32, sizeof(s32)) == 0)
        copy_str(cfg->log_level, sizeof(cfg->log_level), s32);

    v = json_find_key(json_text, "listen");
    if (v && json_read_string(v, s280, sizeof(s280)) == 0) {
        copy_str(cfg->listen, sizeof(cfg->listen), s280);
        cfg->is_server = 1;
    }

    v = json_find_key(json_text, "subnet");
    if (v && json_read_string(v, s64, sizeof(s64)) == 0)
        copy_str(cfg->subnet, sizeof(cfg->subnet), s64);

    v = json_find_key(json_text, "subnet6");
    if (v && json_read_string(v, s64, sizeof(s64)) == 0)
        copy_str(cfg->subnet6, sizeof(cfg->subnet6), s64);

    v = json_find_key(json_text, "server_addr");
    if (v && json_read_string(v, s280, sizeof(s280)) == 0)
        copy_str(cfg->server_addr, sizeof(cfg->server_addr), s280);

    v = json_find_key(json_text, "insecure");
    if (v && json_read_bool(v, &iv) == 0) cfg->insecure = iv;

    v = json_find_key(json_text, "auth_key");
    if (v && json_read_string(v, s256, sizeof(s256)) == 0)
        copy_str(cfg->auth_key, sizeof(cfg->auth_key), s256);

    v = json_find_key(json_text, "server_auth_key");
    if (v && json_read_string(v, s256, sizeof(s256)) == 0)
        copy_str(cfg->server_auth_key, sizeof(cfg->server_auth_key), s256);

    v = json_find_key(json_text, "cert_file");
    if (v && json_read_string(v, s256, sizeof(s256)) == 0)
        copy_str(cfg->cert_file, sizeof(cfg->cert_file), s256);

    v = json_find_key(json_text, "key_file");
    if (v && json_read_string(v, s256, sizeof(s256)) == 0)
        copy_str(cfg->key_file, sizeof(cfg->key_file), s256);

    v = json_find_key(json_text, "max_clients");
    if (v && json_read_int(v, &iv) == 0) cfg->max_clients = iv > 0 ? iv : 64;

    v = json_find_key(json_text, "scheduler");
    if (v && json_read_string(v, s32, sizeof(s32)) == 0)
        copy_str(cfg->scheduler, sizeof(cfg->scheduler), s32);

    v = json_find_key(json_text, "reconnect");
    if (v && json_read_bool(v, &iv) == 0) cfg->reconnect = iv;

    v = json_find_key(json_text, "reconnect_interval");
    if (v && json_read_int(v, &iv) == 0 && iv > 0) cfg->reconnect_interval = iv;

    v = json_find_key(json_text, "kill_switch");
    if (v && json_read_bool(v, &iv) == 0) cfg->kill_switch = iv;

    char dns_buf[MQVPN_CONFIG_MAX_DNS][64];
    int n_dns = 0;
    v = json_find_key(json_text, "dns");
    if (v && json_read_string_array(v, dns_buf, MQVPN_CONFIG_MAX_DNS, &n_dns) == 0) {
        cfg->n_dns = 0;
        for (int i = 0; i < n_dns; i++) {
            copy_str(cfg->dns_servers[cfg->n_dns], sizeof(cfg->dns_servers[cfg->n_dns]),
                     dns_buf[i]);
            cfg->n_dns++;
        }
    }

    char path_buf[MQVPN_CONFIG_MAX_PATHS][64];
    int n_paths = 0;
    v = json_find_key(json_text, "paths");
    if (v && json_read_string_array(v, path_buf, MQVPN_CONFIG_MAX_PATHS, &n_paths) == 0) {
        cfg->n_paths = 0;
        for (int i = 0; i < n_paths; i++) {
            copy_str(cfg->paths[cfg->n_paths], sizeof(cfg->paths[cfg->n_paths]),
                     path_buf[i]);
            cfg->n_paths++;
        }
    }

    v = json_find_key(json_text, "users");
    if (v && json_read_users(cfg, v) < 0) return -1;

    return 0;
}

/* ---- public API ---- */

void
mqvpn_config_defaults(mqvpn_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->tun_name, sizeof(cfg->tun_name), "mqvpn0");
    snprintf(cfg->log_level, sizeof(cfg->log_level), "info");
    snprintf(cfg->listen, sizeof(cfg->listen), "0.0.0.0:443");
    snprintf(cfg->subnet, sizeof(cfg->subnet), "10.0.0.0/24");
    snprintf(cfg->cert_file, sizeof(cfg->cert_file), "server.crt");
    snprintf(cfg->key_file, sizeof(cfg->key_file), "server.key");
    snprintf(cfg->scheduler, sizeof(cfg->scheduler), "wlb");
    cfg->max_clients = 64;
    cfg->reconnect = 1;
    cfg->reconnect_interval = 5;
}

int
mqvpn_config_load(mqvpn_config_t *cfg, const char *path)
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
    while (*s && isspace((unsigned char)*s)) s++;

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
