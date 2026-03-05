/*
 * mqvpn_config.c — Configuration builder (opaque handle + setter pattern)
 *
 * Part of libmqvpn public API. No platform dependencies.
 */

#include "libmqvpn.h"
#include "mqvpn_internal.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ─── Config new/free ─── */

mqvpn_config_t *mqvpn_config_new(void)
{
    mqvpn_config_t *cfg = calloc(1, sizeof(*cfg));
    if (!cfg)
        return NULL;

    /* Defaults */
    cfg->server_port        = 443;
    cfg->scheduler          = MQVPN_SCHED_WLB;
    cfg->log_level          = MQVPN_LOG_INFO;
    cfg->multipath          = 1;
    cfg->reconnect_enable   = 1;
    cfg->reconnect_interval_sec = 5;
    cfg->max_clients        = 64;
    cfg->listen_port        = 443;

    return cfg;
}

void mqvpn_config_free(mqvpn_config_t *cfg)
{
    if (!cfg)
        return;
    free(cfg);
}

/* ─── Setters ─── */

int mqvpn_config_set_server(mqvpn_config_t *cfg, const char *host, int port)
{
    if (!cfg || !host)
        return MQVPN_ERR_INVALID_ARG;

    snprintf(cfg->server_host, sizeof(cfg->server_host), "%s", host);
    cfg->server_port = port;
    return MQVPN_OK;
}

int mqvpn_config_set_auth_key(mqvpn_config_t *cfg, const char *key)
{
    if (!cfg || !key)
        return MQVPN_ERR_INVALID_ARG;

    snprintf(cfg->auth_key, sizeof(cfg->auth_key), "%s", key);
    return MQVPN_OK;
}

int mqvpn_config_set_insecure(mqvpn_config_t *cfg, int insecure)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    cfg->insecure = insecure;
    return MQVPN_OK;
}

int mqvpn_config_set_scheduler(mqvpn_config_t *cfg, mqvpn_scheduler_t sched)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    cfg->scheduler = sched;
    return MQVPN_OK;
}

int mqvpn_config_set_log_level(mqvpn_config_t *cfg, mqvpn_log_level_t level)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    cfg->log_level = level;
    return MQVPN_OK;
}

int mqvpn_config_set_multipath(mqvpn_config_t *cfg, int enable)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    cfg->multipath = enable;
    return MQVPN_OK;
}

int mqvpn_config_set_reconnect(mqvpn_config_t *cfg, int enable, int interval_sec)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    cfg->reconnect_enable = enable;
    cfg->reconnect_interval_sec = interval_sec > 0 ? interval_sec : 5;
    return MQVPN_OK;
}

int mqvpn_config_set_killswitch_hint(mqvpn_config_t *cfg, int enable)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    cfg->killswitch_hint = enable;
    return MQVPN_OK;
}

int mqvpn_config_set_listen(mqvpn_config_t *cfg, const char *addr, int port)
{
    if (!cfg || !addr) return MQVPN_ERR_INVALID_ARG;
    snprintf(cfg->listen_addr, sizeof(cfg->listen_addr), "%s", addr);
    cfg->listen_port = port;
    return MQVPN_OK;
}

int mqvpn_config_set_subnet(mqvpn_config_t *cfg, const char *cidr)
{
    if (!cfg || !cidr) return MQVPN_ERR_INVALID_ARG;
    snprintf(cfg->subnet, sizeof(cfg->subnet), "%s", cidr);
    return MQVPN_OK;
}

int mqvpn_config_set_subnet6(mqvpn_config_t *cfg, const char *cidr6)
{
    if (!cfg || !cidr6) return MQVPN_ERR_INVALID_ARG;
    snprintf(cfg->subnet6, sizeof(cfg->subnet6), "%s", cidr6);
    return MQVPN_OK;
}

int mqvpn_config_set_tls_cert(mqvpn_config_t *cfg,
                               const char *cert, const char *key)
{
    if (!cfg || !cert || !key) return MQVPN_ERR_INVALID_ARG;
    snprintf(cfg->tls_cert, sizeof(cfg->tls_cert), "%s", cert);
    snprintf(cfg->tls_key, sizeof(cfg->tls_key), "%s", key);
    return MQVPN_OK;
}

int mqvpn_config_set_max_clients(mqvpn_config_t *cfg, int max)
{
    if (!cfg) return MQVPN_ERR_INVALID_ARG;
    cfg->max_clients = max;
    return MQVPN_OK;
}
