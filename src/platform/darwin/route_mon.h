// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * route_mon.h — PF_ROUTE link/address monitor + path recovery accelerator
 *
 * Internal to the Darwin platform layer. platform_darwin.c calls
 * setup_route_socket() once from the client run loop and arms the periodic
 * recovery timer with recover_dropped_paths_cb; everything else in
 * route_mon.c is self-contained.
 */

#ifndef MQVPN_PLATFORM_ROUTE_MON_H
#define MQVPN_PLATFORM_ROUTE_MON_H

#include "platform_internal.h"

/* Periodic dropped-path re-add timer period. Backstops carrier-up route
 * events that fire only once while try_readd_removed_path() fails
 * synchronously (see recover_dropped_paths_cb). */
#define RECOVER_INTERVAL_SEC       3 /* byte-identical to netlink_mon.h */
#define PATH_RECOVER_FAILURE_LIMIT 5
/* Analog of NETLINK_BUF_SIZE — on_route_event / route probe read buffer. */
#define ROUTE_BUF_SIZE 8192

/* Open the PF_ROUTE socket, subscribe to link/addr events and register
 * the read event on p->eb. Returns 0 on success, -1 if PF_ROUTE is
 * unavailable (p->rt_fd stays -1; the client still runs, only the
 * recovery accelerator is lost). */
int setup_route_socket(platform_ctx_t *p);

/* Periodic re-add timer callback (p->ev_recover). */
void recover_dropped_paths_cb(evutil_socket_t fd, short what, void *arg);

#endif /* MQVPN_PLATFORM_ROUTE_MON_H */
