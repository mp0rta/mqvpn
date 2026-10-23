// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#include "ctl_sock.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#  define MSG_NOSIGNAL 0 /* macOS: SO_NOSIGPIPE is set on the socket instead */
#endif

static long long
now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int
remaining_ms(long long deadline)
{
    long long r = deadline - now_ms();
    return r < 0 ? 0 : (int)r;
}

/* 0 = ready, CTL_SOCK_E_TIMEOUT, or CTL_SOCK_E_IO. */
static int
wait_fd(int fd, short ev, long long deadline)
{
    for (;;) {
        struct pollfd p = {.fd = fd, .events = ev};
        int n = poll(&p, 1, remaining_ms(deadline));
        if (n > 0) return 0;
        if (n == 0) return CTL_SOCK_E_TIMEOUT;
        if (errno != EINTR) return CTL_SOCK_E_IO;
    }
}

static int
map_errno(int e)
{
    switch (e) {
    case ENOENT: return CTL_SOCK_E_NOENT;
    case EACCES:
    case EPERM: return CTL_SOCK_E_ACCESS;
    case ECONNREFUSED: return CTL_SOCK_E_REFUSED;
    case ETIMEDOUT: return CTL_SOCK_E_TIMEOUT;
    default: return CTL_SOCK_E_IO;
    }
}

int
ctl_sock_connect(ctl_sock_t *s, const char *path, int timeout_ms)
{
    memset(s, 0, sizeof(*s));
    s->fd = -1;

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(sa.sun_path)) return CTL_SOCK_E_IO;
    strcpy(sa.sun_path, path);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return CTL_SOCK_E_IO;
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0 ||
        fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
        close(fd);
        return CTL_SOCK_E_IO;
    }
#ifdef SO_NOSIGPIPE
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif

    int err = 0;
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        if (errno == EINPROGRESS || errno == EAGAIN) {
            err = wait_fd(fd, POLLOUT, now_ms() + timeout_ms);
            if (err == 0) {
                int soerr = 0;
                socklen_t sl = sizeof(soerr);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) < 0)
                    err = CTL_SOCK_E_IO;
                else if (soerr != 0)
                    err = map_errno(soerr);
            }
        } else {
            err = map_errno(errno);
        }
    }
    if (err) {
        close(fd);
        return err;
    }
    s->fd = fd;
    return CTL_SOCK_OK;
}

int
ctl_sock_send_all(ctl_sock_t *s, const void *buf, size_t len, int timeout_ms)
{
    const char *p = buf;
    long long deadline = now_ms() + timeout_ms;
    while (len > 0) {
        ssize_t n = send((int)s->fd, p, len, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n > 0) {
            p += n;
            len -= (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            int w = wait_fd((int)s->fd, POLLOUT, deadline);
            if (w) return w;
            continue;
        }
        return CTL_SOCK_E_IO;
    }
    return CTL_SOCK_OK;
}

int
ctl_sock_recv_line(ctl_sock_t *s, size_t max_line, int timeout_ms, const char **line,
                   size_t *line_len)
{
    long long deadline = now_ms() + timeout_ms;

    /* drop the line handed out last time, keep what follows it */
    if (s->rpos > 0) {
        memmove(s->rbuf, s->rbuf + s->rpos, s->rlen - s->rpos);
        s->rlen -= s->rpos;
        s->rpos = 0;
    }

    size_t scanned = 0;
    for (;;) {
        char *lf =
            s->rlen > scanned ? memchr(s->rbuf + scanned, '\n', s->rlen - scanned) : NULL;
        if (lf) {
            size_t n = (size_t)(lf - s->rbuf);
            s->rpos = n + 1;
            if (n > max_line) return CTL_SOCK_E_TOO_LONG;
            if (n > 0 && s->rbuf[n - 1] == '\r') n--;
            s->rbuf[n] = '\0'; /* overwrites the CR or LF */
            *line = s->rbuf;
            *line_len = n;
            return CTL_SOCK_OK;
        }
        scanned = s->rlen;
        if (s->rlen > max_line) return CTL_SOCK_E_TOO_LONG;

        if (s->rlen == s->rcap) {
            size_t ncap = s->rcap ? s->rcap * 2 : 4096;
            char *nb = realloc(s->rbuf, ncap);
            if (!nb) return CTL_SOCK_E_IO;
            s->rbuf = nb;
            s->rcap = ncap;
        }
        int w = wait_fd((int)s->fd, POLLIN, deadline);
        if (w) return w;
        ssize_t n = recv((int)s->fd, s->rbuf + s->rlen, s->rcap - s->rlen, MSG_DONTWAIT);
        if (n > 0)
            s->rlen += (size_t)n;
        else if (n == 0)
            return CTL_SOCK_E_EOF;
        else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
            return CTL_SOCK_E_IO;
    }
}

void
ctl_sock_close(ctl_sock_t *s)
{
    if (s->fd >= 0) close((int)s->fd);
    s->fd = -1;
    free(s->rbuf);
    s->rbuf = NULL;
    s->rcap = s->rlen = s->rpos = 0;
}
