// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef MGMT_CONN_H
#define MGMT_CONN_H

#include "mgmt_dispatch.h"

#include <event2/event.h>
#include <event2/util.h>
#include <stdint.h>

/* libevent connection layer of the management IPC. OS-neutral: it never creates,
 * chmods or unlinks a listener (the caller owns that) and shares the VPN's event
 * base. */

typedef struct mgmt_endpoint mgmt_endpoint_t; /* one per process: budgets, timers */
typedef struct mgmt_listener mgmt_listener_t;

typedef struct {
    uint32_t max_connections;         /* CMP_MAX_CONNECTIONS_PER_LISTENER */
    uint32_t max_request_line;        /* CMP_MAX_REQUEST_LINE (bytes before the LF) */
    uint32_t max_response_line;       /* CMP_MAX_RESPONSE_LINE (sanity check) */
    uint32_t handshake_deadline_ms;   /* CMP_HANDSHAKE_DEADLINE_MS */
    uint32_t drain_deadline_ms;       /* CMP_DRAIN_DEADLINE_MS */
    uint32_t request_budget_per_loop; /* CMP_REQUEST_BUDGET_PER_LOOP, endpoint-wide */
    uint32_t accept_budget_per_loop;  /* CMP_ACCEPT_BUDGET_PER_LOOP, endpoint-wide */
    uint32_t log_interval_ms;         /* CMP_LOG_INTERVAL_MS */
} mgmt_conn_limits_t;
void mgmt_conn_limits_default(mgmt_conn_limits_t *l);

/* NULL = allocation failure. ctx is copied (its arrays must outlive the endpoint). */
mgmt_endpoint_t *mgmt_endpoint_new(struct event_base *eb, const mgmt_endpoint_ctx_t *ctx,
                                   const mgmt_conn_limits_t *limits);
/* Takes a bound+listening fd (made nonblocking here). Closing it is the caller's job,
 * after mgmt_endpoint_free(). name is for logs. NULL = failure; fd untouched. */
mgmt_listener_t *mgmt_endpoint_add_listener(mgmt_endpoint_t *ep,
                                            evutil_socket_t listen_fd, mgmt_role_t role,
                                            const char *name);
/* Closes every connection, frees listeners and timers; the listen fds stay open. */
void mgmt_endpoint_free(mgmt_endpoint_t *ep);

typedef struct {
    uint64_t accepted, open, rejected_limit, invalid_requests, oversized,
        handshake_timeouts, budget_deferrals, accept_deferrals, dispatched, log_lines;
} mgmt_listener_counters_t; /* dispatched = mgmt_dispatch_line() calls (notifications too)
                             */
void mgmt_listener_counters(const mgmt_listener_t *l, mgmt_listener_counters_t *out);

#endif /* MGMT_CONN_H */
