// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* src/platform/linux/mgmt_socket.c — Client Management IPC socket layer.
 *
 * Owns the AF_UNIX listener fd/libevent plumbing: accept, per-connection
 * bufferevents, request framing (NDJSON, one request per LF-terminated
 * line), and handing complete lines to the OS-neutral
 * mgmt_dispatch_request() (src/mgmt/mgmt_dispatch.c). This file has no
 * opinion on CMP semantics — it only frames bytes and calls the dispatcher.
 *
 * Logging: reuses the project-wide src/log.h / mqvpn_log() (LOG_INF/WRN/ERR)
 * rather than inventing a parallel callback mechanism — log.h is a
 * dependency-free logging shim (no libmqvpn engine/platform state), already
 * linked standalone into several unit-test binaries (see CMakeLists.txt),
 * so it compiles cleanly in both the mqvpn binary and the mgmt_endpoint_host
 * test harness with zero extra plumbing.
 */
#define _GNU_SOURCE /* accept4 */

#include "mgmt_socket.h"

#include "cmp_error.h"
#include "cmp_types.h"
#include "log.h"
#include "mgmt_dispatch.h"

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/util.h>

#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define MGMT_LISTEN_BACKLOG  8
#define MGMT_CONN_DEADLINE_S 5
/* Output backpressure threshold: while a connection's output evbuffer holds
 * more than this, stop reading further pipelined requests from it. */
#define MGMT_OUTPUT_HIGH_BYTES CMP_MAX_RESPONSE_BYTES

/* ── Per-connection state ────────────────────────────────────────────────── */

typedef struct mgmt_conn_impl {
    struct bufferevent *bev;
    mgmt_socket_t *ms;
    mgmt_conn_t mconn; /* handshake_done — owned by mgmt_dispatch.c contract */
    /* Absolute wall-clock deadline (evtimer, NOT a bufferevent read timeout
     * — those re-arm on every received byte, so a 1-byte-per-second
     * trickler would evade them forever and could wedge all connection
     * slots). Armed at accept, deleted when the handshake completes,
     * re-armed once (fresh 5s) when reject-teardown starts. Allocated for
     * the connection's whole lifetime; freed in mgmt_conn_free. */
    struct event *deadline;
    struct mgmt_conn_impl *prev, *next;
} mgmt_conn_impl_t;

/* ── Server handle ───────────────────────────────────────────────────────── */

struct mgmt_socket {
    struct event_base *eb;
    int listen_fd;
    struct event *ev_accept;
    const mgmt_ctx_t *ctx;
    char sock_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    int n_conns;
    mgmt_conn_impl_t *conns; /* intrusive doubly-linked list, no fixed cap */

    /* Single scratch response buffer, sized CMP_MAX_RESPONSE_BYTES (1 MiB),
     * shared by every connection. Safe because libevent runs one callback
     * at a time on a single thread/event_base — mgmt_on_read for connection
     * A always fully completes (including the bufferevent_write of
     * `scratch`, which copies the bytes into that bev's own output
     * evbuffer) before connection B's callback can run. There is never a
     * second writer live concurrently, so one buffer suffices instead of
     * one per connection (which would cost up to CMP_MAX_CONNECTIONS MiB). */
    char *scratch;
};

/* ── connection list helpers ─────────────────────────────────────────────── */

static void
mgmt_conn_link(mgmt_socket_t *ms, mgmt_conn_impl_t *c)
{
    c->prev = NULL;
    c->next = ms->conns;
    if (ms->conns) ms->conns->prev = c;
    ms->conns = c;
    ms->n_conns++;
}

static void
mgmt_conn_unlink(mgmt_socket_t *ms, mgmt_conn_impl_t *c)
{
    if (c->prev)
        c->prev->next = c->next;
    else
        ms->conns = c->next;
    if (c->next) c->next->prev = c->prev;
    ms->n_conns--;
}

/* bufferevent_free() (BEV_OPT_CLOSE_ON_FREE) closes the underlying fd and
 * cancels all pending/queued callbacks for `bev`, so this is always the
 * single, final teardown point for a connection — no other code path frees
 * `c` or its bev. */
static void
mgmt_conn_free(mgmt_conn_impl_t *c)
{
    mgmt_socket_t *ms = c->ms;
    mgmt_conn_unlink(ms, c);
    if (c->deadline) event_free(c->deadline); /* event_free deletes if pending */
    bufferevent_free(c->bev);
    free(c);
}

/* ── absolute per-connection deadline ────────────────────────────────────── */

static void
mgmt_on_deadline(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    mgmt_conn_impl_t *c = (mgmt_conn_impl_t *)arg;
    LOG_WRN("mgmt ipc: connection deadline expired, closing connection");
    mgmt_conn_free(c);
}

/* (Re-)arm the deadline with a fresh window. event_add on an already-pending
 * timer re-schedules it, so this is safe for both the accept-time arm and
 * the reject-teardown re-arm. */
static void
mgmt_deadline_arm(mgmt_conn_impl_t *c)
{
    struct timeval tv = {.tv_sec = MGMT_CONN_DEADLINE_S};
    evtimer_add(c->deadline, &tv);
}

/* ── oversized-request rejection ─────────────────────────────────────────── */

static void mgmt_on_event(struct bufferevent *bev, short events, void *arg);

/* While a rejected connection is being torn down, keep reading and
 * discarding whatever the peer sends. Unread bytes (userspace or kernel
 * receive queue) at close() time would make the kernel emit RST, and the
 * peer would see ECONNRESET instead of error-line-then-EOF. */
static void
mgmt_on_read_discard(struct bufferevent *bev, void *arg)
{
    (void)arg;
    evbuffer_drain(bufferevent_get_input(bev), (size_t)-1);
}

/* Error line fully flushed: send a clean FIN via shutdown(SHUT_WR) and wait
 * for the peer's EOF (or the connection deadline) before freeing — an
 * immediate close() could still race bytes in flight into an RST. */
static void
mgmt_on_write_drained_shutdown(struct bufferevent *bev, void *arg)
{
    mgmt_conn_impl_t *c = (mgmt_conn_impl_t *)arg;
    if (evbuffer_get_length(bufferevent_get_output(bev)) == 0) {
        shutdown(bufferevent_getfd(bev), SHUT_WR);
        bufferevent_setcb(bev, mgmt_on_read_discard, NULL, mgmt_on_event, c);
    }
}

/* Reject a request that is (or would become, once fully buffered) larger
 * than CMP_MAX_REQUEST_BYTES: write a fixed error line (no id — we may not
 * have parsed one), then FIN-then-EOF teardown (see the callbacks above).
 * The re-armed deadline bounds a peer that never reads/closes (the
 * accept-time one may already have been deleted at handshake). The caller
 * must return immediately after this: the connection may already be freed
 * (write failure). */
static void
mgmt_reject_oversized(mgmt_conn_impl_t *c)
{
    char buf[192];
    snprintf(buf, sizeof(buf),
             "{\"protocol\":\"%s\",\"ok\":false,\"error\":{\"code\":\"%s\","
             "\"message\":\"request too large\",\"retryable\":false}}\n",
             CMP_PROTOCOL_VERSION, cmp_error_code_str(CMP_E_INVALID_ARGUMENT));

    LOG_WRN("mgmt ipc: rejecting oversized request (> %d bytes), closing connection",
            CMP_MAX_REQUEST_BYTES);

    evbuffer_drain(bufferevent_get_input(c->bev), (size_t)-1);
    bufferevent_setcb(c->bev, mgmt_on_read_discard, mgmt_on_write_drained_shutdown,
                      mgmt_on_event, c);
    mgmt_deadline_arm(c);
    if (bufferevent_write(c->bev, buf, strlen(buf)) != 0) {
        LOG_WRN("mgmt ipc: response write failed, closing connection");
        mgmt_conn_free(c);
        return;
    }
    bufferevent_enable(c->bev, EV_READ | EV_WRITE);
}

/* ── read / event callbacks ──────────────────────────────────────────────── */

static void
mgmt_on_read(struct bufferevent *bev, void *arg)
{
    mgmt_conn_impl_t *c = (mgmt_conn_impl_t *)arg;
    mgmt_socket_t *ms = c->ms;
    struct evbuffer *input = bufferevent_get_input(bev);

    for (;;) {
        size_t eol_len = 0;
        struct evbuffer_ptr eol =
            evbuffer_search_eol(input, NULL, &eol_len, EVBUFFER_EOL_LF);

        if (eol.pos < 0) {
            /* No LF yet: reject only once unbounded buffering would exceed
             * the cap; otherwise wait for more data. */
            if (evbuffer_get_length(input) > CMP_MAX_REQUEST_BYTES) {
                mgmt_reject_oversized(c);
            }
            return;
        }
        if ((size_t)eol.pos > CMP_MAX_REQUEST_BYTES) {
            /* A line exists but it is already oversized — reject without
             * ever extracting it into a heap buffer. */
            mgmt_reject_oversized(c);
            return;
        }

        size_t n = 0;
        char *line = evbuffer_readln(input, &n, EVBUFFER_EOL_LF);
        if (!line) return; /* defensive: eol was found above, should not happen */

        if (n > 0 && line[n - 1] == '\r') {
            line[n - 1] = '\0';
            n--;
        }

        int rc = mgmt_dispatch_request(ms->ctx, &c->mconn, line, n, ms->scratch,
                                       CMP_MAX_RESPONSE_BYTES);
        free(line);
        /* Warn only for malformed/invalid requests (spec: "invalid request"
         * is logged). Other error codes (HANDSHAKE_REQUIRED,
         * METHOD_NOT_FOUND, ...) are normal protocol-level replies. */
        if (rc == (int)CMP_E_INVALID_ARGUMENT) {
            LOG_WRN("mgmt ipc: invalid request from client");
        }
        if (bufferevent_write(bev, ms->scratch, strlen(ms->scratch)) != 0) {
            LOG_WRN("mgmt ipc: response write failed, closing connection");
            mgmt_conn_free(c);
            return;
        }

        /* The 5s deadline only covers the handshake; once it completes,
         * persistent connections have no idle limit. Deleting is
         * idempotent, so no extra "already deleted" bookkeeping. */
        if (c->mconn.handshake_done) {
            evtimer_del(c->deadline);
        }

        /* Backpressure: a client that pipelines requests without reading
         * responses would otherwise grow the output evbuffer without
         * bound. Stop reading until mgmt_on_write drains it. */
        if (evbuffer_get_length(bufferevent_get_output(bev)) > MGMT_OUTPUT_HIGH_BYTES) {
            bufferevent_disable(bev, EV_READ);
            return;
        }
    }
}

/* Normal-connection write callback (fires when the output evbuffer fully
 * drains): lift read backpressure and resume any pipelined requests that
 * are already sitting in the input evbuffer — re-enabling EV_READ alone
 * would not reprocess them until the peer sends more bytes. */
static void
mgmt_on_write(struct bufferevent *bev, void *arg)
{
    mgmt_conn_impl_t *c = (mgmt_conn_impl_t *)arg;
    if (evbuffer_get_length(bufferevent_get_output(bev)) <= MGMT_OUTPUT_HIGH_BYTES &&
        !(bufferevent_get_enabled(bev) & EV_READ)) {
        bufferevent_enable(bev, EV_READ);
        mgmt_on_read(bev, c);
    }
}

static void
mgmt_on_event(struct bufferevent *bev, short events, void *arg)
{
    (void)bev;
    mgmt_conn_impl_t *c = (mgmt_conn_impl_t *)arg;

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        mgmt_conn_free(c);
    }
}

/* ── accept handler ──────────────────────────────────────────────────────── */

static void
mgmt_on_accept(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    mgmt_socket_t *ms = (mgmt_socket_t *)arg;

    int cfd = accept4(fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (cfd < 0) return;

    if (ms->n_conns >= CMP_MAX_CONNECTIONS) {
        LOG_WRN("mgmt ipc: connection limit reached (%d), rejecting new connection",
                CMP_MAX_CONNECTIONS);
        close(cfd);
        return;
    }

    mgmt_conn_impl_t *c = calloc(1, sizeof(*c));
    if (!c) {
        close(cfd);
        return;
    }
    c->ms = ms;

    c->bev = bufferevent_socket_new(ms->eb, cfd, BEV_OPT_CLOSE_ON_FREE);
    if (!c->bev) {
        free(c);
        close(cfd);
        return;
    }

    c->deadline = evtimer_new(ms->eb, mgmt_on_deadline, c);
    if (!c->deadline) {
        bufferevent_free(c->bev); /* closes cfd (BEV_OPT_CLOSE_ON_FREE) */
        free(c);
        return;
    }

    bufferevent_setcb(c->bev, mgmt_on_read, mgmt_on_write, mgmt_on_event, c);
    mgmt_deadline_arm(c);
    bufferevent_enable(c->bev, EV_READ | EV_WRITE);

    mgmt_conn_link(ms, c);
}

/* ── lifecycle / permissions setup ───────────────────────────────────────── */

/* mkdir the parent directory of `path` (mode 0755). No-op if it already
 * exists. Only the immediate parent is created (not a full mkdir -p chain)
 * — §9.2 lifecycle expects the parent (e.g. /run/mqvpn) to already exist or
 * be a single level below an existing ancestor (e.g. /run). */
static int
mgmt_mkdir_parent(const char *path, char *errbuf, size_t errlen)
{
    const char *slash = strrchr(path, '/');
    if (!slash || slash == path) return 0; /* no parent component to create */

    size_t dirlen = (size_t)(slash - path);
    char dir[sizeof(((struct mgmt_socket *)0)->sock_path)];
    if (dirlen >= sizeof(dir)) {
        snprintf(errbuf, errlen, "mgmt socket parent directory path too long");
        return -1;
    }
    memcpy(dir, path, dirlen);
    dir[dirlen] = '\0';

    if (mkdir(dir, 0755) == 0 || errno == EEXIST) return 0;

    snprintf(errbuf, errlen, "mkdir(%s): %s", dir, strerror(errno));
    return -1;
}

static void
mgmt_apply_group(const char *path, const char *group)
{
    if (!group || group[0] == '\0') return;

    struct group *gr = getgrnam(group);
    if (!gr) {
        LOG_WRN("mgmt ipc: group '%s' not found, socket stays root-only group", group);
        return;
    }
    if (chown(path, (uid_t)-1, gr->gr_gid) != 0) {
        LOG_WRN("mgmt ipc: chown(%s, group=%s) failed: %s", path, group, strerror(errno));
    }
}

mgmt_socket_t *
mgmt_socket_create(struct event_base *eb, const char *path, mode_t mode,
                   const char *group, const mgmt_ctx_t *ctx, char *errbuf, size_t errlen)
{
    if (!eb || !path || !ctx || !errbuf || errlen == 0) return NULL;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    if (strlen(path) >= sizeof(addr.sun_path)) {
        snprintf(errbuf, errlen, "mgmt socket path too long (max %zu bytes): %s",
                 sizeof(addr.sun_path) - 1, path);
        return NULL;
    }

    if (mgmt_mkdir_parent(path, errbuf, errlen) != 0) {
        LOG_ERR("mgmt ipc: %s", errbuf);
        return NULL;
    }

    /* Stale socket file from a previous run: remove before bind(). A
     * missing file (ENOENT) is the expected common case, not an error. */
    if (unlink(path) != 0 && errno != ENOENT) {
        snprintf(errbuf, errlen, "unlink(%s): %s", path, strerror(errno));
        LOG_ERR("mgmt ipc: %s", errbuf);
        return NULL;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        snprintf(errbuf, errlen, "socket(): %s", strerror(errno));
        LOG_ERR("mgmt ipc: %s", errbuf);
        return NULL;
    }

    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, path, strlen(path) + 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        snprintf(errbuf, errlen, "bind(%s): %s", path, strerror(errno));
        LOG_ERR("mgmt ipc: %s", errbuf);
        close(fd);
        return NULL;
    }

    /* Permissions are applied between bind() and listen(): no peer can ever
     * connect() to a socket with the wrong mode/group. */
    if (chmod(path, mode) != 0) {
        snprintf(errbuf, errlen, "chmod(%s, %o): %s", path, (unsigned)mode,
                 strerror(errno));
        LOG_ERR("mgmt ipc: %s", errbuf);
        close(fd);
        unlink(path);
        return NULL;
    }
    mgmt_apply_group(path, group);

    if (listen(fd, MGMT_LISTEN_BACKLOG) != 0) {
        snprintf(errbuf, errlen, "listen(%s): %s", path, strerror(errno));
        LOG_ERR("mgmt ipc: %s", errbuf);
        close(fd);
        unlink(path);
        return NULL;
    }

    if (evutil_make_socket_nonblocking(fd) < 0) {
        snprintf(errbuf, errlen, "evutil_make_socket_nonblocking(%s): %s", path,
                 strerror(errno));
        LOG_ERR("mgmt ipc: %s", errbuf);
        close(fd);
        unlink(path);
        return NULL;
    }

    mgmt_socket_t *ms = calloc(1, sizeof(*ms));
    if (!ms) {
        snprintf(errbuf, errlen, "out of memory");
        close(fd);
        unlink(path);
        return NULL;
    }
    ms->scratch = malloc(CMP_MAX_RESPONSE_BYTES);
    if (!ms->scratch) {
        snprintf(errbuf, errlen, "out of memory");
        free(ms);
        close(fd);
        unlink(path);
        return NULL;
    }

    ms->eb = eb;
    ms->listen_fd = fd;
    ms->ctx = ctx;
    memcpy(ms->sock_path, path, strlen(path) + 1);

    ms->ev_accept = event_new(eb, fd, EV_READ | EV_PERSIST, mgmt_on_accept, ms);
    if (!ms->ev_accept) {
        snprintf(errbuf, errlen, "event_new() failed");
        free(ms->scratch);
        free(ms);
        close(fd);
        unlink(path);
        return NULL;
    }
    event_add(ms->ev_accept, NULL);

    LOG_INF("mgmt ipc listening on %s", path);
    return ms;
}

void
mgmt_socket_destroy(mgmt_socket_t *ms)
{
    if (!ms) return;

    while (ms->conns) {
        mgmt_conn_free(ms->conns);
    }

    if (ms->ev_accept) {
        event_del(ms->ev_accept);
        event_free(ms->ev_accept);
    }
    if (ms->listen_fd >= 0) close(ms->listen_fd);
    unlink(ms->sock_path);
    free(ms->scratch);
    free(ms);
}
