// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * netlink_mon.h — Netlink link/address monitor + path recovery accelerator
 *
 * Internal to the Linux platform layer. platform_linux.c calls
 * setup_netlink() once from the client run loop and arms the periodic
 * recovery timer with recover_dropped_paths_cb. The RTM_* event layer
 * lives in netlink_mon.c; the shared drop/reactivate/re-add decisions it
 * dispatches into live in src/platform/posix/netmon_common.c.
 */

#ifndef MQVPN_PLATFORM_NETLINK_MON_H
#define MQVPN_PLATFORM_NETLINK_MON_H

#include "platform_internal.h"
#include "netmon_common.h" /* shared decision layer + RECOVER_INTERVAL_SEC /
                            * PATH_RECOVER_FAILURE_LIMIT / recover_dropped_paths_cb */

#define NETLINK_BUF_SIZE 8192

/* Open the rtnetlink socket, subscribe to link/addr groups and register
 * the read event on p->eb. Returns 0 on success, -1 if netlink is
 * unavailable (p->nl_fd stays -1; the client still runs, only the
 * recovery accelerator is lost). */
int setup_netlink(platform_ctx_t *p);

#endif /* MQVPN_PLATFORM_NETLINK_MON_H */
