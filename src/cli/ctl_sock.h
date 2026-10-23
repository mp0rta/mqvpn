// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef CTL_SOCK_H
#define CTL_SOCK_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    CTL_SOCK_OK = 0,
    CTL_SOCK_E_NOENT,
    CTL_SOCK_E_ACCESS,
    CTL_SOCK_E_REFUSED,
    CTL_SOCK_E_TIMEOUT,
    CTL_SOCK_E_EOF,
    CTL_SOCK_E_TOO_LONG,
    CTL_SOCK_E_IO
} ctl_sock_err_t;

typedef struct {
    intptr_t fd;
    char *rbuf; /* heap; starts at 4 KiB and doubles */
    size_t rcap;
    size_t rlen;
    size_t rpos; /* bytes of rbuf already handed out as lines */
} ctl_sock_t;

/* Longest endpoint path the OS socket address can hold. */
size_t ctl_sock_max_path(void);

/* All four return 0 (CTL_SOCK_OK) or a ctl_sock_err_t. */
int ctl_sock_connect(ctl_sock_t *s, const char *path, int timeout_ms);
int ctl_sock_send_all(ctl_sock_t *s, const void *buf, size_t len, int timeout_ms);
/* Next LF-terminated line (LF and a preceding CR removed, NUL-terminated).
 * A line longer than max_line gives CTL_SOCK_E_TOO_LONG. Bytes after the
 * line stay buffered for the next call. *line is valid until the next call. */
int ctl_sock_recv_line(ctl_sock_t *s, size_t max_line, int timeout_ms, const char **line,
                       size_t *line_len);
void ctl_sock_close(ctl_sock_t *s);

#endif /* CTL_SOCK_H */
