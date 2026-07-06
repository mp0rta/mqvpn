// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * netlink_mon.h — Netlink link/address monitor + path recovery accelerator
 *
 * Internal to the Linux platform layer. platform_linux.c calls
 * setup_netlink() once from the client run loop and arms the periodic
 * recovery timer with recover_dropped_paths_cb; everything else in
 * netlink_mon.c is self-contained.
 */

#ifndef MQVPN_PLATFORM_NETLINK_MON_H
#define MQVPN_PLATFORM_NETLINK_MON_H

#include "platform_internal.h"

/* Periodic dropped-path re-add timer period. Backstops carrier-up netlink
 * events that fire only once while try_readd_removed_path() fails
 * synchronously (see recover_dropped_paths_cb). */
#define RECOVER_INTERVAL_SEC       3
#define PATH_RECOVER_FAILURE_LIMIT 5
#define NETLINK_BUF_SIZE           8192

/* Open the rtnetlink socket, subscribe to link/addr groups and register
 * the read event on p->eb. Returns 0 on success, -1 if netlink is
 * unavailable (p->nl_fd stays -1; the client still runs, only the
 * recovery accelerator is lost). */
int setup_netlink(platform_ctx_t *p);

/* Periodic re-add timer callback (p->ev_recover). */
void recover_dropped_paths_cb(evutil_socket_t fd, short what, void *arg);

#endif /* MQVPN_PLATFORM_NETLINK_MON_H */
