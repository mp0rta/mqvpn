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

/* Longest line: "path " + 20-digit handle + " (" + iface (Windows slots hold
 * up to 255 bytes) + ") -> " + status + NUL, with slack. Size every line
 * buffer with this so a long name cannot truncate the ") -> status" suffix. */
#define PLATFORM_PATH_LINE_MAX 320

/* out = the interface for handle h: the slot of ctx p holding it, else the
 * iface of the add_path in flight (it fires path_event before the platform
 * has stored the new handle), else NULL. A statement macro, typed indexing:
 * the POSIX and Windows slot types both have .iface/.handle. Reads platform
 * state only: callbacks must not re-enter libmqvpn. */
#define PLATFORM_PATH_IFACE(out, p, h)              \
    do {                                            \
        (out) = (p)->adding_iface;                  \
        for (int i_ = 0; i_ < (p)->n_paths; i_++) { \
            if ((p)->paths[i_].handle == (h)) {     \
                (out) = (p)->paths[i_].iface;       \
                break;                              \
            }                                       \
        }                                           \
    } while (0)

/* iface: the slot's configured name, or NULL when the handle has no slot. */
static inline void
platform_fmt_path_line(char *buf, size_t n, mqvpn_path_handle_t handle, const char *iface,
                       mqvpn_path_status_t status)
{
    snprintf(buf, n, "path %lld (%s) -> %s", (long long)handle,
             (iface && *iface) ? iface : "?", mqvpn_path_status_string(status));
}

#endif /* MQVPN_PLATFORM_PATH_LINE_H */
