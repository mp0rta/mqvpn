// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * route_mon.h — PF_ROUTE link/address monitor + path recovery accelerator
 *
 * Internal to the Darwin platform layer. platform_darwin.c calls
 * setup_route_socket() once from the client run loop and arms the periodic
 * recovery timer with recover_dropped_paths_cb. The PF_ROUTE event layer
 * lives in route_mon.c; the shared drop/reactivate/re-add decisions it
 * dispatches into live in src/platform/posix/netmon_common.c.
 */

#ifndef MQVPN_PLATFORM_ROUTE_MON_H
#define MQVPN_PLATFORM_ROUTE_MON_H

#include "platform_internal.h"
#include "netmon_common.h" /* shared decision layer + RECOVER_INTERVAL_SEC /
                            * PATH_RECOVER_FAILURE_LIMIT / recover_dropped_paths_cb */

/* Analog of NETLINK_BUF_SIZE — on_route_event / route probe read buffer. */
#define ROUTE_BUF_SIZE 8192
/* Run the drop-capable resync every Nth recovery tick (~15s at
 * RECOVER_INTERVAL_SEC=3). xnu's routing socket delivers no overflow
 * notification (no recv-side ENOBUFS, no SO_RERROR), so a periodic
 * reconcile is the only sound trigger for catching missed drop events. */
#define RESYNC_EVERY_N_TICKS 5

/* Open the PF_ROUTE socket, subscribe to link/addr events and register
 * the read event on p->eb. Returns 0 on success, -1 if PF_ROUTE is
 * unavailable (p->rt_fd stays -1; the client still runs, only the
 * recovery accelerator is lost). */
int setup_route_socket(platform_ctx_t *p);

#endif /* MQVPN_PLATFORM_ROUTE_MON_H */
