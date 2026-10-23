// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * mgmt_listen.h — OS-neutral management endpoint listener.
 *
 * The implementation lives in platform/posix (AF_UNIX socket file) and
 * platform/windows. The listener owns the endpoint's name on disk: it never
 * removes anything it did not create.
 */
#ifndef MQVPN_MGMT_LISTEN_H
#define MQVPN_MGMT_LISTEN_H

#include <stddef.h>
#include <event2/util.h> /* evutil_socket_t (header only) */

typedef struct {
    const char *path;  /* resolved endpoint path */
    int mode;          /* POSIX: socket file mode, e.g. 0660. Windows: ignored */
    const char *group; /* POSIX: NULL/"" = no chown. Windows: ignored */
} mgmt_listen_opts_t;

typedef struct mgmt_listen mgmt_listen_t;

/*
 * Order (each step only after the previous one succeeded):
 *   1. create the parent directory (0755)
 *   2. open <path>.lock and take flock(LOCK_EX|LOCK_NB); a held lock means
 *      another endpoint owns the path
 *   3. stale check with lstat(path): absent is fine; a socket whose
 *      (st_dev, st_ino) equals the record in the lock file is ours from a
 *      previous run and is unlinked; anything else is a failure and is left
 *      untouched
 *   4. socket + bind
 *   5. immediately record the socket's "%llu %llu\n" (st_dev st_ino) in the
 *      lock file, so a crash before listen is still recognised next time
 *   6. chmod(mode), chown(-1, gid) when a group is given (an unknown group is
 *      a warning, not a failure)
 *   7. listen
 * On failure returns NULL with a reason in errbuf, releases the lock and
 * unlinks the socket only if step 4 created it.
 */
mgmt_listen_t *mgmt_listen_open(const mgmt_listen_opts_t *opts, char *errbuf,
                                size_t errlen);
evutil_socket_t mgmt_listen_fd(const mgmt_listen_t *l);

/*
 * Close the fd, unlink the path only when it is still the recorded socket,
 * truncate and release the lock, free. The lock file itself stays.
 */
void mgmt_listen_close(mgmt_listen_t *l);

/*
 * "0660"-style octal string -> mode. NULL / "" give 0660 without a log. A
 * non-empty value that is not octal, has trailing characters or exceeds 07777
 * logs a warning and gives 0660. The Windows implementation always returns
 * 0660 (the value is unused there).
 */
int mgmt_listen_parse_mode(const char *s);

#endif /* MQVPN_MGMT_LISTEN_H */
