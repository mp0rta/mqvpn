// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * path_readd.h — the re-add decision shared by every desktop path monitor:
 * the POSIX event path and recovery timer (src/platform/posix/netmon_common.c)
 * and the Windows poll reconciler (src/platform/windows/net_mon.c).
 *
 * A platform slot is re-added (fresh socket, fresh transport, add_path) only
 * when it holds no socket of its own and the library no longer holds a live
 * incarnation of it. A slot that still owns a socket belongs to reactivate,
 * never to a re-add: re-adding it would overwrite the socket and orphan its
 * read event. The callers used to carry their own copies of this test, and
 * the copies disagreed — keep it here, once.
 *
 * Plain C, no OS types: the caller says whether the slot has a socket.
 */
#ifndef MQVPN_PLATFORM_PATH_READD_H
#define MQVPN_PLATFORM_PATH_READD_H

#include "libmqvpn.h"

/* May the previous library incarnation of a platform slot be replaced?
 * Yes when the library lists that handle as CLOSED, and yes when it does not
 * list the handle at all: add_path recycles a fully released library slot
 * for any new path under a new handle, so a path's old handle disappears
 * from mqvpn_client_get_paths() once another path's re-add has taken its
 * slot. That is a normal outcome, not an unregistered slot — every platform
 * slot is registered once before the event loop starts. */
static inline int
path_lib_allows_readd(mqvpn_path_handle_t handle, const mqvpn_path_info_t *paths,
                      int n_paths)
{
    for (int i = 0; i < n_paths; i++) {
        if (paths[i].handle == handle) return paths[i].status == MQVPN_PATH_CLOSED;
    }
    /* The previous library slot may already have been reused by another
     * platform path, replacing its old handle. */
    return 1;
}

/* The whole re-add candidate test. has_socket: the slot still owns an open
 * socket. recover_failures / failure_limit: the platform's re-add
 * backpressure (consecutive failed re-adds). */
static inline int
path_readd_candidate(int has_socket, int recover_failures, int failure_limit,
                     mqvpn_path_handle_t handle, const mqvpn_path_info_t *paths,
                     int n_paths)
{
    return !has_socket && recover_failures < failure_limit &&
           path_lib_allows_readd(handle, paths, n_paths);
}

#endif /* MQVPN_PLATFORM_PATH_READD_H */
