// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * mgmt_listen.c — POSIX AF_UNIX management listener (see mgmt_listen.h).
 */
#include "mgmt_listen.h"
#include "cmp_proto.h"
#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

struct mgmt_listen {
    int fd;
    int lock_fd;
    char *path;
    unsigned long long dev, ino; /* our socket's identity */
};

#define SET_ERR(...)                                                 \
    do {                                                             \
        if (errbuf && errlen) snprintf(errbuf, errlen, __VA_ARGS__); \
    } while (0)

int
mgmt_listen_parse_mode(const char *s)
{
    if (!s || !*s) return 0660;
    char *end;
    unsigned long v = strtoul(s, &end, 8);
    if (end == s || *end != '\0' || v > 07777) {
        LOG_WRN("invalid ClientManagement SocketMode '%s'; using 0660", s);
        return 0660;
    }
    return (int)v;
}

static int
mkdir_parents(const char *path)
{
    char *d = strdup(path);
    if (!d) return -1;
    for (char *p = d; *p; p++) {
        if (p == d || *p != '/') continue;
        *p = '\0';
        if (mkdir(d, 0755) != 0 && errno != EEXIST) {
            int e = errno;
            free(d);
            errno = e;
            return -1;
        }
        *p = '/';
    }
    free(d);
    return 0;
}

static int
read_record(int lock_fd, unsigned long long *dev, unsigned long long *ino)
{
    char buf[64];
    ssize_t n = pread(lock_fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return -1;
    buf[n] = '\0';
    return sscanf(buf, "%llu %llu", dev, ino) == 2 ? 0 : -1;
}

static int
write_record(int lock_fd, unsigned long long dev, unsigned long long ino)
{
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "%llu %llu\n", dev, ino);
    if (ftruncate(lock_fd, 0) != 0) return -1;
    return pwrite(lock_fd, buf, (size_t)n, 0) == n ? 0 : -1;
}

/* Is path a socket whose identity equals (dev, ino)? */
static int
path_is_ours(const char *path, unsigned long long dev, unsigned long long ino)
{
    struct stat st;
    return lstat(path, &st) == 0 && S_ISSOCK(st.st_mode) &&
           (unsigned long long)st.st_dev == dev && (unsigned long long)st.st_ino == ino;
}

static void
release_lock(int lock_fd)
{
    if (ftruncate(lock_fd, 0) != 0) { /* best effort */
    }
    flock(lock_fd, LOCK_UN);
    close(lock_fd);
}

mgmt_listen_t *
mgmt_listen_open(const mgmt_listen_opts_t *opts, char *errbuf, size_t errlen)
{
    const char *path = opts->path;
    struct sockaddr_un sa;
    struct stat st;
    char *lock_path = NULL;
    int lock_fd = -1, fd = -1, bound = 0, have_id = 0;
    unsigned long long dev = 0, ino = 0;
    mgmt_listen_t *l = NULL;

    if (strlen(path) > sizeof(sa.sun_path) - 1) {
        SET_ERR("endpoint path too long for AF_UNIX");
        return NULL;
    }
    if (mkdir_parents(path) != 0) {
        SET_ERR("cannot create parent directory of %s: %s", path, strerror(errno));
        return NULL;
    }

    size_t lplen = strlen(path) + sizeof(".lock");
    lock_path = malloc(lplen);
    if (!lock_path) {
        SET_ERR("out of memory");
        return NULL;
    }
    snprintf(lock_path, lplen, "%s.lock", path);

    lock_fd = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (lock_fd < 0) {
        SET_ERR("cannot open lock file %s: %s", lock_path, strerror(errno));
        goto fail;
    }
    if (flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        if (errno == EWOULDBLOCK)
            SET_ERR("another endpoint owns %s", path);
        else
            SET_ERR("cannot lock %s: %s", lock_path, strerror(errno));
        close(lock_fd);
        lock_fd = -1;
        goto fail;
    }

    if (lstat(path, &st) == 0) {
        unsigned long long rdev, rino;
        if (S_ISSOCK(st.st_mode) && read_record(lock_fd, &rdev, &rino) == 0 &&
            path_is_ours(path, rdev, rino)) {
            if (unlink(path) != 0) {
                SET_ERR("cannot remove stale socket %s: %s", path, strerror(errno));
                goto fail_keep;
            }
        } else {
            SET_ERR("%s exists and is not a socket owned by mqvpn", path);
            goto fail_keep;
        }
    } else if (errno != ENOENT) {
        SET_ERR("cannot stat %s: %s", path, strerror(errno));
        goto fail_keep;
    }

#ifdef SOCK_CLOEXEC
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    /* Darwin: no SOCK_CLOEXEC; set FD_CLOEXEC after socket(). */
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd >= 0) fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
    if (fd < 0) {
        SET_ERR("socket(AF_UNIX) failed for %s: %s", path, strerror(errno));
        goto fail_unlock;
    }
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    memcpy(sa.sun_path, path, strlen(path));
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        SET_ERR("bind %s failed: %s", path, strerror(errno));
        goto fail_unlock;
    }
    bound = 1;

    /* Record ownership before anything else can fail or crash. */
    if (lstat(path, &st) == 0 && S_ISSOCK(st.st_mode)) {
        have_id = 1;
        dev = (unsigned long long)st.st_dev;
        ino = (unsigned long long)st.st_ino;
    }
    if (!have_id) {
        SET_ERR("endpoint path replaced after bind: %s", path);
        goto fail_unlock;
    }
    if (write_record(lock_fd, dev, ino) != 0) {
        SET_ERR("cannot record socket ownership for %s: %s", path, strerror(errno));
        goto fail_unlock;
    }

    if (chmod(path, (mode_t)opts->mode) != 0) {
        SET_ERR("chmod %s failed: %s", path, strerror(errno));
        goto fail_unlock;
    }
    /* BSD gives a new socket the parent directory's group; pin ours instead. */
    gid_t gid = getegid();
    if (opts->group && opts->group[0]) {
        struct group *gr = getgrnam(opts->group);
        if (!gr)
            LOG_WRN("mgmt ipc: group %s not found, leaving socket group unchanged",
                    opts->group);
        else
            gid = gr->gr_gid;
    }
    if (chown(path, (uid_t)-1, gid) != 0) {
        SET_ERR("chown %s failed: %s", path, strerror(errno));
        goto fail_unlock;
    }

    if (listen(fd, CMP_LISTEN_BACKLOG) != 0) {
        SET_ERR("listen %s failed: %s", path, strerror(errno));
        goto fail_unlock;
    }

    l = calloc(1, sizeof(*l));
    char *pcopy = strdup(path);
    if (!l || !pcopy) {
        free(l);
        free(pcopy);
        l = NULL;
        SET_ERR("out of memory");
        goto fail_unlock;
    }
    l->fd = fd;
    l->lock_fd = lock_fd;
    l->path = pcopy;
    l->dev = (unsigned long long)st.st_dev;
    l->ino = (unsigned long long)st.st_ino;
    free(lock_path);
    return l;

fail_unlock:
    /* Unlink only a socket verified as ours; if the post-bind stat failed the
     * identity is unknown, so leave the path alone rather than risk a foreign file. */
    if (bound && have_id && path_is_ours(path, dev, ino)) unlink(path);
    if (fd >= 0) close(fd);
    release_lock(lock_fd);
    goto fail;
fail_keep: /* nothing of ours on disk: keep the record, just drop the lock */
    close(lock_fd);
fail:
    free(lock_path);
    return NULL;
}

evutil_socket_t
mgmt_listen_fd(const mgmt_listen_t *l)
{
    return l->fd;
}

void
mgmt_listen_close(mgmt_listen_t *l)
{
    if (!l) return;
    close(l->fd);
    int unlinked = 1;
    if (path_is_ours(l->path, l->dev, l->ino)) unlinked = unlink(l->path) == 0;
    /* If unlink failed the socket is still ours: keep the record for the next start. */
    if (unlinked)
        release_lock(l->lock_fd);
    else {
        flock(l->lock_fd, LOCK_UN);
        close(l->lock_fd);
    }
    free(l->path);
    free(l);
}
