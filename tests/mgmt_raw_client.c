// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * mgmt_raw_client — raw line client and "somebody else's socket" for
 * scripts/ci_e2e/run_client_mgmt_ipc_test.sh.
 *
 *   mgmt_raw_client <path> [--timeout-ms N] [--lines N]
 *                   [--payload STR | --payload-file F | --fill N]
 *   mgmt_raw_client --bind-only <path> [--hold-lock] [--stop-file PATH]
 *
 * Client mode sends the payload while reading reply lines (one nonblocking
 * poll loop), so a reply the endpoint wants to drain never waits on a send
 * the endpoint has stopped reading. Exit: 0 = N lines received (or EOF with
 * --lines 0), 3 = EOF first, 5 = connect failed, 8 = no progress for
 * --timeout-ms, 1 = anything else.
 */
#include "ctl_sock.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#  include <winsock2.h>
#  define POLL_FN(p, n, t) WSAPoll((p), (n), (t))
#  define CLOSE_FD(fd)     closesocket((SOCKET)(fd))
#  define IO_AGAIN()       (WSAGetLastError() == WSAEWOULDBLOCK)
#  define SLEEP_MS(ms)     Sleep(ms)
typedef int io_len_t;
#else
#  include <fcntl.h>
#  include <poll.h>
#  include <sys/file.h>
#  include <sys/socket.h>
#  include <sys/stat.h>
#  include <sys/un.h>
#  include <unistd.h>
#  define POLL_FN(p, n, t) poll((p), (n), (t))
#  define CLOSE_FD(fd)     close((int)(fd))
#  define IO_AGAIN()       (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
#  define SLEEP_MS(ms)     usleep((ms) * 1000)
typedef ssize_t io_len_t;
#  ifndef MSG_NOSIGNAL
#    define MSG_NOSIGNAL 0
#  endif
#endif

static long long
now_ms(void)
{
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int
file_exists(const char *p)
{
    FILE *f = fopen(p, "rb");
    if (!f) return 0;
    fclose(f);
    return 1;
}

#ifndef _WIN32
/* The listener side of somebody else's program: bind (and listen(1) unless
 * --hold-lock), never accept. --hold-lock reproduces mqvpn's lock protocol
 * by hand and stops between bind and listen. */
static int
bind_only(const char *path, int hold_lock, const char *stop_file)
{
    int lock_fd = -1;
    if (hold_lock) {
        char lp[512];
        snprintf(lp, sizeof(lp), "%s.lock", path);
        lock_fd = open(lp, O_CREAT | O_RDWR | O_CLOEXEC, 0644);
        if (lock_fd < 0 || flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
            fprintf(stderr, "mgmt_raw_client: cannot lock %s: %s\n", lp, strerror(errno));
            return 1;
        }
    }
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(sa.sun_path)) {
        fprintf(stderr, "mgmt_raw_client: path too long\n");
        return 1;
    }
    strcpy(sa.sun_path, path);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0 || bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        fprintf(stderr, "mgmt_raw_client: bind %s: %s\n", path, strerror(errno));
        return 1;
    }
    if (hold_lock) {
        struct stat st;
        char rec[64];
        if (stat(path, &st) != 0) return 1;
        int n = snprintf(rec, sizeof(rec), "%llu %llu\n", (unsigned long long)st.st_dev,
                         (unsigned long long)st.st_ino);
        if (ftruncate(lock_fd, 0) != 0 || pwrite(lock_fd, rec, (size_t)n, 0) != n)
            return 1;
    } else if (listen(fd, 1) != 0) {
        fprintf(stderr, "mgmt_raw_client: listen: %s\n", strerror(errno));
        return 1;
    }
    printf("bound %s\n", path);
    fflush(stdout);
    while (!stop_file || !file_exists(stop_file))
        SLEEP_MS(100);
    return 0;
}
#endif

static char *payload, *rbuf;
static ctl_sock_t s;

/* Leak-clean exit: the helper runs under ASan/LSan in CI. */
static int
finish(int rc)
{
    free(payload);
    free(rbuf);
    ctl_sock_close(&s);
    return rc;
}

static int
usage(void)
{
    fprintf(stderr,
            "usage: mgmt_raw_client <path> [--timeout-ms N] [--lines N]\n"
            "         [--payload STR | --payload-file F | --fill N]\n"
            "       mgmt_raw_client --bind-only <path> [--hold-lock] [--stop-file P]\n");
    return 1;
}

int
main(int argc, char **argv)
{
    const char *path = NULL, *payload_s = NULL, *payload_f = NULL, *stop_file = NULL;
    long timeout_ms = 5000, want = 1, fill = -1;
    int bind_mode = 0, hold = 0;
    s.fd = -1;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        int has_val = i + 1 < argc;
        if (!strcmp(a, "--bind-only"))
            bind_mode = 1;
        else if (!strcmp(a, "--hold-lock"))
            hold = 1;
        else if (!strcmp(a, "--timeout-ms") && has_val)
            timeout_ms = atol(argv[++i]);
        else if (!strcmp(a, "--lines") && has_val)
            want = atol(argv[++i]);
        else if (!strcmp(a, "--payload") && has_val)
            payload_s = argv[++i];
        else if (!strcmp(a, "--payload-file") && has_val)
            payload_f = argv[++i];
        else if (!strcmp(a, "--fill") && has_val)
            fill = atol(argv[++i]);
        else if (!strcmp(a, "--stop-file") && has_val)
            stop_file = argv[++i];
        else if (a[0] != '-' && !path)
            path = a;
        else
            return usage();
    }
    if (!path) return usage();

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
#endif
    if (bind_mode) {
#ifdef _WIN32
        fprintf(stderr,
                "mgmt_raw_client: --bind-only is not implemented on this OS yet\n");
        return 1;
#else
        return bind_only(path, hold, stop_file);
#endif
    }

    size_t plen = 0;
    if (payload_f) {
        FILE *f = fopen(payload_f, "rb");
        if (!f) {
            fprintf(stderr, "mgmt_raw_client: cannot open %s\n", payload_f);
            return finish(1);
        }
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        payload = malloc((size_t)sz + 1);
        if (!payload || (plen = fread(payload, 1, (size_t)sz, f)) != (size_t)sz) {
            fclose(f);
            return finish(1);
        }
        fclose(f);
    } else if (fill >= 0) {
        payload = malloc((size_t)fill + 1);
        if (!payload) return finish(1);
        memset(payload, 'a', (size_t)fill);
        plen = (size_t)fill;
    } else if (payload_s) {
        payload = strdup(payload_s);
        if (!payload) return finish(1);
        plen = strlen(payload);
    }

    if (ctl_sock_connect(&s, path, (int)timeout_ms) != CTL_SOCK_OK) return finish(5);

    size_t sent = 0;
    size_t cap = 4096, rlen = 0;
    rbuf = malloc(cap);
    long got = 0;
    long long last = now_ms();
    if (!rbuf) return finish(1);

    for (;;) {
        if (want > 0 && got >= want) return finish(0);
        struct pollfd p = {.fd = (int)s.fd, .events = POLLIN};
        if (sent < plen) p.events |= POLLOUT;
        long long left = last + timeout_ms - now_ms();
        if (left <= 0) return finish(8);
        int n = POLL_FN(&p, 1, (int)left);
        if (n < 0) {
            if (IO_AGAIN()) continue;
            return finish(1);
        }
        if (n == 0) return finish(8);

        if ((p.revents & POLLOUT) && sent < plen) {
            io_len_t w =
                send((int)s.fd, payload + sent, (size_t)(plen - sent), MSG_NOSIGNAL);
            if (w > 0) {
                sent += (size_t)w;
                last = now_ms();
            } else if (w < 0 && !IO_AGAIN()) {
                plen = sent; /* peer closed: stop sending, drain what it wrote */
            }
        }
        if (p.revents & (POLLIN | POLLHUP | POLLERR)) {
            if (rlen == cap) {
                cap *= 2;
                char *nb = realloc(rbuf, cap);
                if (!nb) return finish(1);
                rbuf = nb;
            }
            io_len_t r = recv((int)s.fd, rbuf + rlen, cap - rlen, 0);
            if (r == 0 || (r < 0 && !IO_AGAIN())) return finish(want == 0 ? 0 : 3);
            if (r > 0) {
                last = now_ms();
                size_t start = 0;
                for (size_t i = rlen; i < rlen + (size_t)r; i++) {
                    if (rbuf[i] != '\n') continue;
                    fwrite(rbuf + start, 1, i - start + 1, stdout);
                    fflush(stdout);
                    start = i + 1;
                    got++;
                }
                rlen += (size_t)r;
                memmove(rbuf, rbuf + start, rlen - start);
                rlen -= start;
            }
        }
    }
}
