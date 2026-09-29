// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * path_table.c — path slot mechanics shared by the POSIX platforms (Linux,
 * Darwin): append a slot, open and bind its UDP socket, describe it to
 * add_path, arm and free its read event, close its socket.
 *
 * Mechanics only: whether a slot is dropped, re-added or reactivated, what
 * the library is told and what is logged all stay with the callers, so each
 * keeps its own log wording (log lines are a compatibility surface).
 */

#include "platform_internal.h"
#include "compat/socket_compat.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* The address a path socket binds to: the wildcard of the server's family,
 * ephemeral port. Also what add_path is told as the path's local address. */
static socklen_t
wildcard_addr(sa_family_t af, struct sockaddr_storage *ss)
{
    memset(ss, 0, sizeof(*ss));
    if (af == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = in6addr_any;
        return sizeof(struct sockaddr_in6);
    }
    struct sockaddr_in *sin = (struct sockaddr_in *)ss;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(INADDR_ANY);
    return sizeof(struct sockaddr_in);
}

platform_path_t *
platform_path_append(platform_ctx_t *p, const char *iface)
{
    if (p->n_paths >= MQVPN_MAX_PATHS) return NULL;
    platform_path_t *s = &p->paths[p->n_paths++];
    memset(s, 0, sizeof(*s));
    s->p = p;
    s->fd = -1;
    s->handle = -1;
    if (iface && iface[0]) snprintf(s->iface, sizeof(s->iface), "%s", iface);
    return s;
}

int
platform_path_index(const platform_path_t *s)
{
    return (int)(s - s->p->paths);
}

int
platform_path_socket_open(sa_family_t af, int *failed_step)
{
    int fd = (int)socket(af, SOCK_DGRAM, 0);
    if (fd < 0) {
        *failed_step = PLATFORM_PATH_STEP_SOCKET;
        return -1;
    }
    int step = 0;
    if (mqvpn_socket_set_nonblock(fd) < 0) {
        step = PLATFORM_PATH_STEP_NONBLOCK;
    } else {
        struct sockaddr_storage ss;
        socklen_t len = wildcard_addr(af, &ss);
        if (bind(fd, (struct sockaddr *)&ss, len) < 0) step = PLATFORM_PATH_STEP_BIND;
    }
    if (step) {
        int saved = errno; /* the caller logs the failing call's errno */
        close(fd);
        errno = saved;
        *failed_step = step;
        return -1;
    }
    return fd;
}

void
platform_path_fill_desc(const platform_ctx_t *p, const platform_path_t *s,
                        mqvpn_path_desc_t *desc)
{
    memset(desc, 0, sizeof(*desc));
    desc->struct_size = sizeof(*desc);
    snprintf(desc->iface, sizeof(desc->iface), "%s", s->iface);
    struct sockaddr_storage ss;
    socklen_t len = wildcard_addr(p->server_addr.ss_family, &ss);
    memcpy(desc->local_addr, &ss, len);
    desc->local_addr_len = len;
}

int
platform_path_arm(platform_path_t *s)
{
    struct event *ev =
        event_new(s->p->eb, s->fd, EV_READ | EV_PERSIST, on_socket_read, s);
    if (!ev) return -1;
    if (event_add(ev, NULL) < 0) {
        event_free(ev);
        return -1;
    }
    s->ev = ev;
    return 0;
}

void
platform_path_disarm(platform_path_t *s)
{
    if (s->ev) event_del(s->ev);
}

void
platform_path_close_socket(platform_path_t *s)
{
    if (s->ev) {
        event_del(s->ev);
        event_free(s->ev);
        s->ev = NULL;
    }
    if (s->fd >= 0) {
        close(s->fd);
        s->fd = -1;
    }
}

void
platform_paths_close_all(platform_ctx_t *p)
{
    for (int i = 0; i < p->n_paths; i++)
        platform_path_close_socket(&p->paths[i]);
}
