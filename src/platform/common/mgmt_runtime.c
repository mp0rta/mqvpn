// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#include "mgmt_runtime.h"
#include "log.h"

#include <stdio.h>
#include <string.h>

int
mgmt_runtime_start(mgmt_runtime_t *rt, struct event_base *eb,
                   const char *endpoint_version, int enabled, const char *endpoint,
                   const char *socket_mode, const char *socket_group)
{
    char err[256] = {0};
    mgmt_conn_limits_t limits;
    mgmt_listen_opts_t lo;

    if (!enabled) return 1;

    if (cmp_endpoint_resolve(endpoint, rt->path, sizeof(rt->path)) != 0) {
        LOG_ERR("mgmt ipc disabled: endpoint path is invalid or too long");
        return -1;
    }

    lo.path = rt->path;
    lo.mode = mgmt_listen_parse_mode(socket_mode);
    lo.group = socket_group;
    rt->listener = mgmt_listen_open(&lo, err, sizeof(err));
    if (!rt->listener) {
        LOG_ERR("mgmt ipc disabled: %s", err);
        return -1;
    }

    rt->ctx.endpoint_version = endpoint_version;
    rt->ctx.capabilities = NULL;
    rt->ctx.n_capabilities = 0;
    mgmt_conn_limits_default(&limits);
    rt->endpoint = mgmt_endpoint_new(eb, &rt->ctx, &limits);
    if (!rt->endpoint ||
        !mgmt_endpoint_add_listener(rt->endpoint, mgmt_listen_fd(rt->listener),
                                    MGMT_ROLE_ADMIN, rt->path)) {
        LOG_ERR("mgmt ipc disabled: out of memory");
        mgmt_endpoint_free(rt->endpoint);
        rt->endpoint = NULL;
        mgmt_listen_close(rt->listener);
        rt->listener = NULL;
        return -1;
    }

    LOG_INF("mgmt ipc listening on %s (role %s)", rt->path,
            mgmt_role_name(MGMT_ROLE_ADMIN));
    return 0;
}

void
mgmt_runtime_stop(mgmt_runtime_t *rt)
{
    if (!rt->listener) return;
    mgmt_endpoint_free(rt->endpoint);
    rt->endpoint = NULL;
    mgmt_listen_close(rt->listener);
    rt->listener = NULL;
    LOG_INF("mgmt ipc stopped");
}
