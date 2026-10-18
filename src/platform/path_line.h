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

#include <stdio.h>

/* iface: the slot's configured name, or NULL when the handle has no slot. */
static inline void
platform_fmt_path_line(char *buf, size_t n, mqvpn_path_handle_t handle, const char *iface,
                       mqvpn_path_status_t status)
{
    snprintf(buf, n, "path %lld (%s) -> %s", (long long)handle,
             (iface && *iface) ? iface : "?", mqvpn_path_status_string(status));
}

#endif /* MQVPN_PLATFORM_PATH_LINE_H */
