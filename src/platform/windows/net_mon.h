// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * net_mon.h — Windows path recovery accelerator (sibling of Linux
 * netlink_mon.h). Phase 1: 3s poll reconciler that drops dead paths and
 * re-adds/reactivates recovered ones. Phase 2 (later): IP Helper event source.
 */

#ifndef MQVPN_NET_MON_WIN_H
#define MQVPN_NET_MON_WIN_H

#ifdef _WIN32

#  include "platform_internal_win.h"

#  include <event2/event.h>

#  define RECOVER_INTERVAL_SEC       3
#  define PATH_RECOVER_FAILURE_LIMIT 5

/* 3s poll timer callback: drop dead paths, re-add/reactivate recovered ones. */
void recover_dropped_paths_cb(evutil_socket_t fd, short what, void *arg);

#endif /* _WIN32 */
#endif /* MQVPN_NET_MON_WIN_H */
