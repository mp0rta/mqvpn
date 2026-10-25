// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * mgmt_runtime.h — start/stop glue for the client management endpoint,
 * shared by the desktop platforms.
 */
#ifndef MQVPN_MGMT_RUNTIME_H
#define MQVPN_MGMT_RUNTIME_H

#include "cmp_endpoint.h"
#include "mgmt_conn.h"
#include "mgmt_dispatch.h"
#include "mgmt_listen.h"

struct event_base;

typedef struct {
    mgmt_listen_t *listener;
    mgmt_endpoint_t *endpoint;
    mgmt_endpoint_ctx_t ctx; /* the endpoint refers to endpoint_version */
    char path[CMP_ENDPOINT_MAX];
} mgmt_runtime_t;

/*
 * enabled == 0: does nothing and returns 1. Otherwise resolves the path,
 * parses the mode, opens the listener and the endpoint. A failure logs
 * "mgmt ipc disabled: <reason>" once, undoes what was created and returns -1;
 * the caller carries on without the endpoint. 0 = listening.
 * endpoint_version must outlive the runtime. Zero-initialise rt first.
 */
int mgmt_runtime_start(mgmt_runtime_t *rt, struct event_base *eb,
                       const char *endpoint_version, int enabled, const char *endpoint,
                       const char *socket_mode, const char *socket_group);

/* Endpoint first (connections), then the listener (fd, unlink, lock). No-op
 * when not started. */
void mgmt_runtime_stop(mgmt_runtime_t *rt);

#endif /* MQVPN_MGMT_RUNTIME_H */
