/*
 * mqvpn_config.c — Configuration builder (opaque handle + setter pattern)
 *
 * Part of libmqvpn public API. No platform dependencies.
 */

#include "libmqvpn.h"
#include "mqvpn_internal.h"
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
json_read_users(mqvpn_config_t *cfg, const char *p)
{
    if (!cfg || !p || *p != '[') return MQVPN_ERR_INVALID_ARG;
    p = json_skip_ws(p + 1);
    cfg->n_users = 0;

    while (*p && *p != ']') {
        char uname[64] = {0};
        char key[256] = {0};

        if (*p == '"') {
            char pair[320] = {0};
            if (json_read_string(p, pair, sizeof(pair)) != MQVPN_OK) {
                return MQVPN_ERR_INVALID_ARG;
            }
            char *sep = strchr(pair, ':');
            if (!sep) return MQVPN_ERR_INVALID_ARG;
            *sep = '\0';
            mqvpn_copy_str(uname, sizeof(uname), pair);
            mqvpn_copy_str(key, sizeof(key), sep + 1);

            const char *e = p + 1;
            while (*e && *e != '"') {
                if (*e == '\\' && e[1]) e++;
                e++;
            }
            if (*e != '"') return MQVPN_ERR_INVALID_ARG;
            p = json_skip_ws(e + 1);
        } else if (*p == '{') {
            const char *obj_end = strchr(p, '}');
            if (!obj_end) return MQVPN_ERR_INVALID_ARG;

            char obj[512];
            size_t obj_len = (size_t)(obj_end - p + 1);
            if (obj_len >= sizeof(obj)) return MQVPN_ERR_INVALID_ARG;
            memcpy(obj, p, obj_len);
            obj[obj_len] = '\0';

            const char *name_val = json_find_key(obj, "name");
            const char *key_val = json_find_key(obj, "key");
            if (!name_val || !key_val) return MQVPN_ERR_INVALID_ARG;
            if (json_read_string(name_val, uname, sizeof(uname)) != MQVPN_OK) {
                return MQVPN_ERR_INVALID_ARG;
            }
            if (json_read_string(key_val, key, sizeof(key)) != MQVPN_OK) {
                return MQVPN_ERR_INVALID_ARG;
            }

            p = json_skip_ws(obj_end + 1);
        } else {
            return MQVPN_ERR_INVALID_ARG;
        }

        if (mqvpn_config_add_user(cfg, uname, key) != MQVPN_OK) {
            return MQVPN_ERR_INVALID_ARG;
        }

        if (*p == ',') {
            p = json_skip_ws(p + 1);
        } else if (*p != ']') {
            return MQVPN_ERR_INVALID_ARG;
        }
    }

    return (*p == ']') ? MQVPN_OK : MQVPN_ERR_INVALID_ARG;
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
    cfg->scheduler = sched;
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
