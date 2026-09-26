// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* reactor.c — see reactor.h. Linux-only (eventfd); Android is Linux. */

#include "reactor.h"

#include "log.h"
#include "mqvpn_bind_posix.h"

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#define REACTOR_DRAIN_BUDGET 64 /* the BULK_READ_COUNT every platform uses */
#define RX_LINE_FMT          "android-reactor: udp-rx: receives=%" PRIu64 " datagrams=%" PRIu64

typedef struct {
    mqvpn_android_reactor_entry_state_t state;
    int fd;
    mqvpn_path_handle_t handle;
    void *ctx; /* posix bind ctx; library-owned while the entry is not FREE */
    char tag[16];
} entry_t;

struct mqvpn_android_reactor {
    int wake_fd;
    entry_t e[MQVPN_MAX_PATHS];
    int wake_err_logged;
    int poll_err_logged;
    uint64_t rx_receives; /* totals of released paths (added on MQVPN_OK) */
    uint64_t rx_datagrams;
};

static entry_t *
find_entry(mqvpn_android_reactor_t *r, mqvpn_path_handle_t handle)
{
    for (int i = 0; i < MQVPN_MAX_PATHS; i++) {
        if (r->e[i].state != MQVPN_REACTOR_ENTRY_FREE && r->e[i].handle == handle)
            return &r->e[i];
    }
    return NULL;
}

static void
read_rx(const entry_t *e, uint64_t *receives, uint64_t *datagrams)
{
    mqvpn_bind_posix_stats_t st;
    memset(&st, 0, sizeof(st));
    st.struct_size = sizeof(st);
    mqvpn_bind_posix_path_get_stats(e->ctx, &st);
    *receives = st.rx_receives;
    *datagrams = st.rx_datagrams;
}

mqvpn_android_reactor_t *
mqvpn_android_reactor_new(void)
{
    mqvpn_android_reactor_t *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (r->wake_fd < 0) {
        LOG_ERR("android-reactor: eventfd: %s", strerror(errno));
        free(r);
        return NULL;
    }
    return r;
}

void
mqvpn_android_reactor_free(mqvpn_android_reactor_t *r)
{
    if (!r) return;
    int live = 0;
    for (int i = 0; i < MQVPN_MAX_PATHS; i++)
        if (r->e[i].state != MQVPN_REACTOR_ENTRY_FREE) live++;
    assert(live == 0 &&
           "android-reactor: freed with live entries; destroy the client first");
    if (live)
        LOG_WRN("android-reactor: freed with %d live entries (leaked, never freed here)",
                live);
    close(r->wake_fd);
    free(r);
}

int
mqvpn_android_reactor_wake(mqvpn_android_reactor_t *r)
{
    const uint64_t one = 1;
    for (;;) {
        ssize_t n = write(r->wake_fd, &one, sizeof(one));
        if (n == (ssize_t)sizeof(one)) return 0;
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return 0; /* already pending */
        /* Any thread: the once-only latch is an atomic exchange. */
        if (!__atomic_exchange_n(&r->wake_err_logged, 1, __ATOMIC_RELAXED))
            LOG_ERR("android-reactor: wake: %s", n < 0 ? strerror(errno) : "short write");
        return -1;
    }
}

static void
consume_wake(mqvpn_android_reactor_t *r)
{
    /* A non-EFD_SEMAPHORE eventfd read returns the whole counter and resets
     * it atomically: one read consumes every pending wake; a second one
     * would only report EAGAIN. POLLIN was reported, so the result needs no
     * handling: on EAGAIN there is nothing to consume, and an EINTR leaves
     * the counter set, so the next poll() returns at once. Assigned, not
     * cast to void: gcc's -Wunused-result (read() under _FORTIFY_SOURCE)
     * ignores a (void) cast. */
    uint64_t v;
    ssize_t n = read(r->wake_fd, &v, sizeof(v));
    (void)n;
}

int
mqvpn_android_reactor_wait(mqvpn_android_reactor_t *r, mqvpn_client_t *client,
                           int timeout_ms)
{
    struct pollfd pfd[MQVPN_MAX_PATHS + 1];
    int slot[MQVPN_MAX_PATHS];
    int n = 0;
    for (int i = 0; i < MQVPN_MAX_PATHS; i++) {
        if (r->e[i].state != MQVPN_REACTOR_ENTRY_ATTACHED) continue;
        pfd[n].fd = r->e[i].fd;
        pfd[n].events = POLLIN;
        pfd[n].revents = 0;
        slot[n] = i;
        n++;
    }
    if (!client && n > 0)
        return -1; /* contract: NULL client only with nothing attached */
    pfd[n].fd = r->wake_fd;
    pfd[n].events = POLLIN;
    pfd[n].revents = 0;

    int rc = poll(pfd, (nfds_t)(n + 1), timeout_ms);
    if (rc < 0) {
        if (errno == EINTR) return 0;
        if (!r->poll_err_logged) {
            r->poll_err_logged = 1;
            LOG_ERR("android-reactor: poll: %s", strerror(errno));
        }
        return -1;
    }

    int drains = 0;
    for (int k = 0; k < n; k++) {
        entry_t *e = &r->e[slot[k]];
        if (pfd[k].revents == 0) continue;
        if (pfd[k].revents & POLLNVAL) {
            /* The number is no longer open: someone closed it behind the
             * platform. Stop polling it; the platform learns the handle from
             * take_bad_fd() and finishes the removal without closing. */
            e->state = MQVPN_REACTOR_ENTRY_INVALID;
            LOG_WRN("android-reactor: path[%" PRId64
                    "] (%s): fd %d is not open (POLLNVAL); "
                    "removed from the poll set",
                    e->handle, e->tag, e->fd);
            continue;
        }
        if (pfd[k].revents & (POLLIN | POLLERR | POLLHUP)) {
            /* A pending socket error is consumed only by a receive; draining
             * on POLLIN alone would spin. Hard errors are ignored, as on
             * Linux: the network monitor owns drop detection. */
            (void)mqvpn_bind_posix_path_drain(e->ctx, client, e->handle,
                                              REACTOR_DRAIN_BUDGET);
            drains++;
        }
    }
    if (pfd[n].revents & POLLIN) consume_wake(r);
    return drains;
}

mqvpn_path_handle_t
mqvpn_android_reactor_take_bad_fd(mqvpn_android_reactor_t *r)
{
    for (int i = 0; i < MQVPN_MAX_PATHS; i++) {
        if (r->e[i].state == MQVPN_REACTOR_ENTRY_INVALID) {
            r->e[i].state = MQVPN_REACTOR_ENTRY_DETACHED;
            return r->e[i].handle;
        }
    }
    return -1;
}

mqvpn_path_handle_t
mqvpn_android_reactor_add_path(mqvpn_android_reactor_t *r, mqvpn_client_t *client, int fd,
                               const char *iface, int gso_policy, int gro_policy)
{
    entry_t *e = NULL;
    for (int i = 0; i < MQVPN_MAX_PATHS; i++) {
        if (r->e[i].state == MQVPN_REACTOR_ENTRY_FREE) {
            e = &r->e[i];
            break;
        }
    }
    if (!e) {
        LOG_ERR("android-reactor: add_path(%s): table full", iface ? iface : "");
        return -1;
    }
    memset(e, 0, sizeof(*e));
    snprintf(e->tag, sizeof(e->tag), "%s", (iface && iface[0]) ? iface : "path");

    mqvpn_path_desc_t desc;
    memset(&desc, 0, sizeof(desc));
    desc.struct_size = sizeof(desc);
    snprintf(desc.iface, sizeof(desc.iface), "%s", iface ? iface : "");
    struct sockaddr_storage ss;
    socklen_t ss_len = sizeof(ss);
    if (getsockname(fd, (struct sockaddr *)&ss, &ss_len) == 0 &&
        ss_len <= sizeof(desc.local_addr)) {
        memcpy(desc.local_addr, &ss, ss_len);
        desc.local_addr_len = ss_len;
    } else {
        /* xquic learns the local address from the first packet instead. */
        LOG_WRN("android-reactor: add_path(%s): getsockname: %s", e->tag,
                strerror(errno));
    }

    mqvpn_bind_posix_opts_t bopts;
    memset(&bopts, 0, sizeof(bopts));
    bopts.struct_size = sizeof(bopts);
    bopts.udp_gso = gso_policy;
    bopts.udp_gro = gro_policy;
    bopts.socket_buf_bytes = 0; /* 7 MiB request, what add_path_fd applied */
    snprintf(bopts.tag, sizeof(bopts.tag), "%s", e->tag);

    void *ctx = NULL;
    int brc = mqvpn_bind_posix_path_new(fd, &bopts, &ctx);
    if (brc != MQVPN_OK) {
        LOG_ERR("android-reactor: add_path(%s): transport setup failed: %s", e->tag,
                mqvpn_error_string(brc));
        memset(e, 0, sizeof(*e));
        return -1;
    }

    mqvpn_add_path_outcome_t outcome = MQVPN_ADD_PATH_OK;
    mqvpn_path_handle_t h =
        mqvpn_client_add_path(client, &desc, mqvpn_bind_posix_path_ops(), ctx, &outcome);
    if (h < 0) {
        LOG_ERR("android-reactor: add_path(%s): library refused the path", e->tag);
        mqvpn_bind_posix_path_free(ctx); /* add failed: still ours */
        memset(e, 0, sizeof(*e));
        return -1;
    }
    e->state = MQVPN_REACTOR_ENTRY_ATTACHED;
    e->fd = fd;
    e->handle = h;
    e->ctx = ctx;
    if (outcome != MQVPN_ADD_PATH_OK) {
        /* The ctx is library-owned now and the path is kept: the library's
         * retry timer or the platform's next Lost resolves it (same as the
         * old add_path_fd and iOS). */
        LOG_WRN("android-reactor: path[%" PRId64 "] (%s) activation outcome=%d, kept", h,
                e->tag, (int)outcome);
    }
    if (gro_policy) {
        if (mqvpn_bind_posix_path_gro_enabled(ctx)) {
            LOG_INF("udp-gro: enabled on path[%" PRId64 "]", h);
        } else {
            LOG_INF("udp-gro: unavailable on path[%" PRId64
                    "] (%s); receiving one datagram per syscall",
                    h, strerror(mqvpn_bind_posix_path_gro_errno(ctx)));
        }
    }
    return h;
}

int
mqvpn_android_reactor_remove_path(mqvpn_android_reactor_t *r, mqvpn_client_t *client,
                                  mqvpn_path_handle_t handle)
{
    entry_t *e = find_entry(r, handle);
    if (!e || e->state == MQVPN_REACTOR_ENTRY_POISONED) return MQVPN_ERR_INVALID_ARG;
    /* Every non-FREE state reaches the library: on the bad-fd chain this is
     * the call that moves the slot to CLOSED_DROPPED so the core stops
     * sending; the library ignores a repeat. */
    int rc = mqvpn_client_remove_path(client, handle);
    e->state = MQVPN_REACTOR_ENTRY_DETACHED;
    return rc;
}

int
mqvpn_android_reactor_path_released(mqvpn_android_reactor_t *r, mqvpn_client_t *client,
                                    mqvpn_path_handle_t handle)
{
    entry_t *e = find_entry(r, handle);
    if (!e || e->state != MQVPN_REACTOR_ENTRY_DETACHED) return MQVPN_ERR_INVALID_ARG;

    /* Read BEFORE the notification (the library finalises the ctx inside it)
     * and add only on MQVPN_OK, so a refused release cannot count twice at
     * the destroy-time harvest. */
    uint64_t rx_r, rx_d;
    read_rx(e, &rx_r, &rx_d);

    int rc = mqvpn_client_on_platform_path_released(client, handle);
    if (rc == MQVPN_OK) {
        r->rx_receives += rx_r;
        r->rx_datagrams += rx_d;
        LOG_INF("android-reactor: path[%" PRId64 "] (%s) released: receives=%" PRIu64
                " datagrams=%" PRIu64,
                handle, e->tag, rx_r, rx_d);
        memset(e, 0, sizeof(*e)); /* FREE; the library finalised the ctx */
        return MQVPN_OK;
    }
    if (rc == MQVPN_ERR_INVALID_ARG) {
        /* The library does not know a handle this table holds: ledger
         * corruption. Whether it still holds the ctx cannot be known here,
         * so the entry is never polled, dereferenced or reused again; the
         * caller ends the session (destroy clears the entry). */
        LOG_ERR("android-reactor: path[%" PRId64 "] (%s): unknown to the library; entry "
                "poisoned, session must end",
                handle, e->tag);
        e->state = MQVPN_REACTOR_ENTRY_POISONED;
        return MQVPN_REACTOR_POISONED;
    }
    LOG_WRN("android-reactor: path[%" PRId64
            "] (%s): path_released returned %s; transport "
            "stays library-owned",
            handle, e->tag, mqvpn_error_string(rc));
    return rc;
}

void
mqvpn_android_reactor_client_destroy(mqvpn_android_reactor_t *r, mqvpn_client_t *client)
{
    if (!client) {
        /* No client: nothing to harvest or destroy, the table is just cleared. */
        memset(r->e, 0, sizeof(r->e));
        r->rx_receives = 0;
        r->rx_datagrams = 0;
        return;
    }
    uint64_t receives = r->rx_receives, datagrams = r->rx_datagrams;
    for (int i = 0; i < MQVPN_MAX_PATHS; i++) {
        entry_t *e = &r->e[i];
        if (e->state == MQVPN_REACTOR_ENTRY_ATTACHED)
            e->state = MQVPN_REACTOR_ENTRY_DETACHED;
        if (e->state == MQVPN_REACTOR_ENTRY_DETACHED ||
            e->state == MQVPN_REACTOR_ENTRY_INVALID) {
            /* Still library-owned: readable now, dangling after destroy. */
            uint64_t rx_r, rx_d;
            read_rx(e, &rx_r, &rx_d);
            receives += rx_r;
            datagrams += rx_d;
        }
        /* POISONED: never dereferenced. */
    }
    LOG_INF(RX_LINE_FMT, receives, datagrams);
    mqvpn_client_destroy(client);  /* finalises every still-attached ctx */
    memset(r->e, 0, sizeof(r->e)); /* forget_all: no pointer is followed */
    r->rx_receives = 0;
    r->rx_datagrams = 0;
}

int
mqvpn_android_reactor_entry_state(const mqvpn_android_reactor_t *r,
                                  mqvpn_path_handle_t handle)
{
    const entry_t *e = find_entry((mqvpn_android_reactor_t *)r, handle);
    return e ? (int)e->state : -1;
}
