/*
 * config.c — INI-style configuration file parser for mqvpn
 */
#include "config.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ---- helpers ---- */

/* Trim leading and trailing whitespace in-place, return pointer to start */
static char *
trim(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

/* Parse boolean: "true"/"yes"/"1" → 1, else 0 */
static int
parse_bool(const char *val)
{
    return (strcmp(val, "true") == 0 ||
            strcmp(val, "yes") == 0 ||
            strcmp(val, "1") == 0);
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
    if (strcasecmp(name, "Server") == 0)    return SEC_SERVER;
    if (strcasecmp(name, "TLS") == 0)       return SEC_TLS;
    if (strcasecmp(name, "Auth") == 0)      return SEC_AUTH;
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
        while (*p == ',' || isspace((unsigned char)*p)) p++;
        if (*p == '\0') break;

        const char *start = p;
        while (*p && *p != ',') p++;

        /* copy and trim trailing whitespace */
        size_t len = (size_t)(p - start);
        if (len >= sizeof(cfg->dns_servers[0]))
            len = sizeof(cfg->dns_servers[0]) - 1;
        memcpy(cfg->dns_servers[cfg->n_dns], start, len);
        cfg->dns_servers[cfg->n_dns][len] = '\0';

        /* trim trailing whitespace from the copied entry */
        char *end = cfg->dns_servers[cfg->n_dns] + len - 1;
        while (end >= cfg->dns_servers[cfg->n_dns] &&
               isspace((unsigned char)*end))
            *end-- = '\0';

        if (cfg->dns_servers[cfg->n_dns][0] != '\0')
            cfg->n_dns++;
    }
}

/* Handle a key=value pair in the given section */
static void
handle_kv(mqvpn_config_t *cfg, int section, const char *key, const char *val,
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
            snprintf(cfg->server_auth_key, sizeof(cfg->server_auth_key),
                     "%s", val);
            snprintf(cfg->auth_key, sizeof(cfg->auth_key), "%s", val);
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
                snprintf(cfg->paths[cfg->n_paths], sizeof(cfg->paths[0]),
                         "%s", val);
                cfg->n_paths++;
            } else {
                LOG_WRN("%s:%d: max %d paths supported, ignoring '%s'",
                        path, lineno, MQVPN_CONFIG_MAX_PATHS, val);
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

    char line[1024];
    int lineno = 0;
    int section = SEC_NONE;

    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        char *s = trim(line);

        /* Skip empty lines and comments */
        if (*s == '\0' || *s == '#' || *s == ';')
            continue;

        /* Section header */
        if (*s == '[') {
            char *end = strchr(s, ']');
            if (!end) {
                LOG_WRN("%s:%d: malformed section header", path, lineno);
                continue;
            }
            *end = '\0';
            int sec = parse_section(s + 1);
            if (sec < 0) {
                LOG_WRN("%s:%d: unknown section '%s'", path, lineno, s + 1);
                section = SEC_NONE;
            } else {
                section = sec;
            }
            continue;
        }

        /* Key = Value */
        char *eq = strchr(s, '=');
        if (!eq) {
            LOG_WRN("%s:%d: malformed line (no '=')", path, lineno);
            continue;
        }
        *eq = '\0';
        char *key = trim(s);
        char *val = trim(eq + 1);

        handle_kv(cfg, section, key, val, lineno, path);
    }

    fclose(fp);
    return 0;
}
