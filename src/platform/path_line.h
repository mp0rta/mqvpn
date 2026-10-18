// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * path_line.h — the "path <handle> (<iface>) -> <status>" INFO line every
 * desktop platform logs from its path_event callback. The mqvpn-desktop GUI
 * parses it; <iface> is "?" when the handle is not in the platform slot
 * table (or the slot is configured "any"). Plain C, no OS types.
 */
#ifndef MQVPN_PLATFORM_PATH_LINE_H
#define MQVPN_PLATFORM_PATH_LINE_H

#include "libmqvpn.h"

#include <stddef.h>
#include <stdio.h>

/* The interface for `handle`: the slot holding it, else `adding` (the iface of
 * the add_path in flight: it fires path_event before the platform has stored
 * the new handle), else NULL. Slots are walked by stride so the POSIX and
 * Windows slot types share this; use the PLATFORM_PATH_IFACE wrapper. Reads
 * platform state only: callbacks must not re-enter libmqvpn. */
static inline const char *
platform_path_iface(const char *ifaces, const mqvpn_path_handle_t *handles, size_t stride,
                    int n, mqvpn_path_handle_t handle, const char *adding)
{
    for (int i = 0; i < n; i++)
        if (*(const mqvpn_path_handle_t *)((const char *)handles + i * stride) == handle)
            return ifaces + i * stride;
    return adding;
}

#define PLATFORM_PATH_IFACE(p, h)                                   \
    platform_path_iface((p)->paths[0].iface, &(p)->paths[0].handle, \
                        sizeof((p)->paths[0]), (p)->n_paths, (h), (p)->adding_iface)

/* iface: the slot's configured name, or NULL when the handle has no slot. */
static inline void
platform_fmt_path_line(char *buf, size_t n, mqvpn_path_handle_t handle, const char *iface,
                       mqvpn_path_status_t status)
{
    snprintf(buf, n, "path %lld (%s) -> %s", (long long)handle,
             (iface && *iface) ? iface : "?", mqvpn_path_status_string(status));
}

#endif /* MQVPN_PLATFORM_PATH_LINE_H */
