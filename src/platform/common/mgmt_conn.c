// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#include "mgmt_conn.h"
#include "cmp_error.h"
#include "cmp_proto.h"
#include "log.h"

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <winsock2.h>
#  define MGMT_SHUT_WR SD_SEND
#else
#  include <sys/socket.h>
#  define MGMT_SHUT_WR SHUT_WR
#endif
#ifndef MSG_NOSIGNAL
#  define MSG_NOSIGNAL 0
#endif

/* Circular doubly-linked list node; a head is a node that points at itself. */
typedef struct lnode {
    struct lnode *prev, *next;
} lnode_t;

static void
ln_init(lnode_t *n)
{
    n->prev = n->next = n;
}
static int
ln_linked(const lnode_t *n)
{
    return n->next != n;
}
static void
ln_unlink(lnode_t *n)
{
    n->prev->next = n->next;
    n->next->prev = n->prev;
    ln_init(n);
}
static void
ln_push_tail(lnode_t *head, lnode_t *n)
{
    n->prev = head->prev;
    n->next = head;
    head->prev->next = n;
    head->prev = n;
}

#define CONTAINER_OF(p, type, member) ((type *)((char *)(p) - offsetof(type, member)))

/* Pause between an accept() failure (fd exhaustion) and the next attempt; without it
 * libevent retries on every loop pass and spins the shared VPN loop. */
#define MGMT_ACCEPT_BACKOFF_MS 200

typedef struct mgmt_conn {
    mgmt_listener_t *l;
    struct bufferevent *bev;
    struct event *deadline; /* handshake deadline, then drain deadline */
    mgmt_conn_state_t st;
    int draining; /* DRAINING_CLOSE: error line written, waiting for peer EOF */
    lnode_t all;  /* listener's connection list */
    lnode_t wq;   /* endpoint's FIFO of connections with a complete line */
} mgmt_conn_t;

struct mgmt_listener {
    mgmt_endpoint_t *ep;
    struct evconnlistener *lev;
    mgmt_role_t role;
    char *name;
    lnode_t conns;
    struct event *log_timer;
    uint32_t delta_invalid, delta_oversized, delta_limit, delta_hs_timeout;
    mgmt_listener_counters_t cnt;
    struct mgmt_listener *next;
};

struct mgmt_endpoint {
    struct event_base *eb;
    mgmt_endpoint_ctx_t ctx;
    mgmt_conn_limits_t lim;
    struct event *resume;
    struct event *backoff; /* one-shot: listeners stay disabled after an accept error */
    uint32_t requests_used, accepts_used;
    lnode_t wq;
    size_t wq_len;
    mgmt_listener_t *listeners;
};

void
mgmt_conn_limits_default(mgmt_conn_limits_t *l)
{
    l->max_connections = CMP_MAX_CONNECTIONS_PER_LISTENER;
    l->max_request_line = CMP_MAX_REQUEST_LINE;
    l->max_response_line = CMP_MAX_RESPONSE_LINE;
    l->handshake_deadline_ms = CMP_HANDSHAKE_DEADLINE_MS;
    l->drain_deadline_ms = CMP_DRAIN_DEADLINE_MS;
    l->request_budget_per_loop = CMP_REQUEST_BUDGET_PER_LOOP;
    l->accept_budget_per_loop = CMP_ACCEPT_BUDGET_PER_LOOP;
    l->log_interval_ms = CMP_LOG_INTERVAL_MS;
}

static void
tv_from_ms(struct timeval *tv, uint32_t ms)
{
    tv->tv_sec = ms / 1000;
    tv->tv_usec = (ms % 1000) * 1000;
}

static void
arm_resume(mgmt_endpoint_t *ep)
{
    static const struct timeval zero = {0, 0};
    if (!evtimer_pending(ep->resume, NULL)) evtimer_add(ep->resume, &zero);
}

static void wq_remove(mgmt_conn_t *c);

/* The only teardown path for a connection. */
static void
conn_destroy(mgmt_conn_t *c)
{
    if (c->deadline) event_free(c->deadline);
    wq_remove(c);
    ln_unlink(&c->all);
    bufferevent_free(c->bev); /* BEV_OPT_CLOSE_ON_FREE closes the fd */
    c->l->cnt.open--;
    free(c);
}

/* Log budget: count now, log from a one-shot timer, never on the input path. */
static void
log_note(mgmt_listener_t *l, uint32_t *delta)
{
    (*delta)++;
    if (!evtimer_pending(l->log_timer, NULL)) {
        struct timeval tv;
        tv_from_ms(&tv, l->ep->lim.log_interval_ms);
        evtimer_add(l->log_timer, &tv);
    }
}

static void
log_timer_cb(evutil_socket_t fd, short what, void *arg)
{
    mgmt_listener_t *l = arg;
    (void)fd;
    (void)what;
    LOG_WRN("mgmt ipc [%s] dropped input: invalid=%u oversized=%u limit=%u "
            "handshake_timeout=%u",
            l->name, l->delta_invalid, l->delta_oversized, l->delta_limit,
            l->delta_hs_timeout);
    l->delta_invalid = l->delta_oversized = l->delta_limit = l->delta_hs_timeout = 0;
    l->cnt.log_lines++;
}

static void
wq_remove(mgmt_conn_t *c)
{
    mgmt_endpoint_t *ep = c->l->ep;
    if (ln_linked(&c->wq)) {
        ln_unlink(&c->wq);
        ep->wq_len--;
    }
}

static void
wq_push(mgmt_conn_t *c)
{
    mgmt_endpoint_t *ep = c->l->ep;
    if (ln_linked(&c->wq)) return;
    ln_push_tail(&ep->wq, &c->wq);
    ep->wq_len++;
}

/* Queue the error line, then wait for the peer to close (oversized line). */
static void
conn_oversized(mgmt_conn_t *c)
{
    mgmt_endpoint_t *ep = c->l->ep;
    struct evbuffer *in = bufferevent_get_input(c->bev);
    char msg[64];
    mgmt_line_t line = {NULL, 0};
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    struct timeval tv;

    c->l->cnt.oversized++;
    log_note(c->l, &c->l->delta_oversized);
    wq_remove(c);
    evbuffer_drain(in, evbuffer_get_length(in));
    c->draining = 1;
    snprintf(msg, sizeof(msg), "request line exceeds %u bytes", ep->lim.max_request_line);
    if (doc &&
        mgmt_rpc_error_line(doc, NULL, CMP_E_INVALID_REQUEST, msg, NULL, &line) == 0)
        bufferevent_write(c->bev, line.buf, line.len);
    free(line.buf);
    yyjson_mut_doc_free(doc);
    /* Bound the drain even if the peer never reads the error line. */
    tv_from_ms(&tv, ep->lim.drain_deadline_ms);
    evtimer_add(c->deadline, &tv);
}

/* Look for a complete line; never dispatches. */
static void
conn_check_input(mgmt_conn_t *c)
{
    struct evbuffer *in = bufferevent_get_input(c->bev);
    struct evbuffer_ptr p;
    size_t line_len;

    if (c->draining) {
        evbuffer_drain(in, evbuffer_get_length(in));
        return;
    }
    if (ln_linked(&c->wq)) return;
    p = evbuffer_search_eol(in, NULL, NULL, EVBUFFER_EOL_LF);
    line_len = p.pos >= 0 ? (size_t)p.pos : evbuffer_get_length(in);
    if (line_len > c->l->ep->lim.max_request_line) {
        conn_oversized(c);
        return;
    }
    if (p.pos < 0) return;
    bufferevent_disable(c->bev, EV_READ);
    wq_push(c);
    arm_resume(c->l->ep);
}

static void
conn_read_cb(struct bufferevent *bev, void *arg)
{
    (void)bev;
    conn_check_input(arg);
}

static void
conn_write_cb(struct bufferevent *bev, void *arg)
{
    mgmt_conn_t *c = arg;
    if (c->draining) {
        struct timeval tv;
        shutdown(bufferevent_getfd(bev), MGMT_SHUT_WR);
        if (!evtimer_pending(c->deadline, NULL)) {
            tv_from_ms(&tv, c->l->ep->lim.drain_deadline_ms);
            evtimer_add(c->deadline, &tv);
        }
        return;
    }
    if (ln_linked(&c->wq)) return; /* a request is queued: reads stay off */
    bufferevent_enable(bev, EV_READ);
    conn_check_input(c);
}

static void
conn_event_cb(struct bufferevent *bev, short what, void *arg)
{
    (void)bev;
    if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) conn_destroy(arg);
}

static void
conn_deadline_cb(evutil_socket_t fd, short what, void *arg)
{
    mgmt_conn_t *c = arg;
    (void)fd;
    (void)what;
    if (!c->draining) {
        c->l->cnt.handshake_timeouts++;
        log_note(c->l, &c->l->delta_hs_timeout);
    }
    conn_destroy(c);
}

/* Over the connection limit: one best-effort BUSY line, then close. */
static void
reject_busy(mgmt_listener_t *l, evutil_socket_t fd)
{
    mgmt_line_t line = {NULL, 0};
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);

    l->cnt.rejected_limit++;
    log_note(l, &l->delta_limit);
    if (doc && mgmt_rpc_error_line(doc, NULL, CMP_E_BUSY, NULL, NULL, &line) == 0)
        (void)send(fd, line.buf, (int)line.len, MSG_NOSIGNAL);
    free(line.buf);
    yyjson_mut_doc_free(doc);
    evutil_closesocket(fd);
}

static void
accept_cb(struct evconnlistener *lev, evutil_socket_t fd, struct sockaddr *sa, int salen,
          void *arg)
{
    mgmt_listener_t *l = arg;
    mgmt_endpoint_t *ep = l->ep;
    mgmt_conn_t *c;
    struct timeval tv;
    (void)lev;
    (void)sa;
    (void)salen;

    arm_resume(ep); /* resets the per-loop budgets next iteration */
    if (++ep->accepts_used >= ep->lim.accept_budget_per_loop) {
        mgmt_listener_t *x;
        l->cnt.accept_deferrals++;
        for (x = ep->listeners; x; x = x->next)
            evconnlistener_disable(x->lev);
    }
    if (l->cnt.open >= ep->lim.max_connections) {
        reject_busy(l, fd);
        return;
    }
    c = calloc(1, sizeof(*c));
    if (!c) {
        evutil_closesocket(fd);
        return;
    }
    c->l = l;
    c->st.role = l->role;
    ln_init(&c->all);
    ln_init(&c->wq);
    c->bev = bufferevent_socket_new(ep->eb, fd, BEV_OPT_CLOSE_ON_FREE);
    c->deadline = evtimer_new(ep->eb, conn_deadline_cb, c);
    if (!c->bev || !c->deadline) {
        if (c->deadline) event_free(c->deadline);
        if (c->bev)
            bufferevent_free(c->bev); /* closes fd */
        else
            evutil_closesocket(fd);
        free(c);
        return;
    }
    ln_push_tail(&l->conns, &c->all);
    l->cnt.open++;
    l->cnt.accepted++;
    bufferevent_setcb(c->bev, conn_read_cb, conn_write_cb, conn_event_cb, c);
    tv_from_ms(&tv, ep->lim.handshake_deadline_ms);
    evtimer_add(c->deadline, &tv);
    bufferevent_enable(c->bev, EV_READ | EV_WRITE);
}

/* Does the input hold another complete line? (Oversize is re-checked by check_input.) */
static void
conn_next(mgmt_conn_t *c)
{
    bufferevent_enable(c->bev, EV_READ);
    conn_check_input(c);
}

static void
dispatch_one(mgmt_conn_t *c)
{
    mgmt_endpoint_t *ep = c->l->ep;
    struct evbuffer *in = bufferevent_get_input(c->bev);
    struct evbuffer_ptr p = evbuffer_search_eol(in, NULL, NULL, EVBUFFER_EOL_LF);
    size_t n = p.pos < 0 ? 0 : (size_t)p.pos;
    char *buf = p.pos < 0 ? NULL : malloc(n + 1);
    mgmt_line_t out = {NULL, 0};
    int err = 0, rc, was_done;

    if (!buf || (n && evbuffer_remove(in, buf, n) != (int)n)) {
        free(buf);
        conn_destroy(c);
        return;
    }
    evbuffer_drain(in, 1); /* the LF */
    if (n && buf[n - 1] == '\r') n--;
    was_done = c->st.handshake_done;
    c->l->cnt.dispatched++;
    rc = mgmt_dispatch_line(&ep->ctx, &c->st, buf, n, &out, &err);
    free(buf);
    if (err == CMP_E_INVALID_REQUEST || err == CMP_E_PARSE_ERROR ||
        err == CMP_E_INVALID_PARAMS) {
        c->l->cnt.invalid_requests++;
        log_note(c->l, &c->l->delta_invalid);
    }
    /* Before the reply is written: a hello that completed must not be timed out. */
    if (!was_done && c->st.handshake_done) event_del(c->deadline);
    if (rc == 0 && out.buf && out.len <= ep->lim.max_response_line) {
        bufferevent_write(c->bev, out.buf, out.len); /* reads stay off: 1 in flight */
        free(out.buf);
    } else if (rc == 1) {
        conn_next(c);
    } else {
        free(out.buf); /* dispatcher failure or oversize reply: drop the connection */
        conn_destroy(c);
    }
}

static void
accept_error_cb(struct evconnlistener *lev, void *arg)
{
    mgmt_listener_t *l = arg;
    mgmt_endpoint_t *ep = l->ep;
    mgmt_listener_t *x;
    struct timeval tv;
    (void)lev;

    l->cnt.accept_errors++;
    for (x = ep->listeners; x; x = x->next)
        evconnlistener_disable(x->lev);
    tv_from_ms(&tv, MGMT_ACCEPT_BACKOFF_MS);
    if (!evtimer_pending(ep->backoff, NULL)) evtimer_add(ep->backoff, &tv);
}

static void
backoff_cb(evutil_socket_t fd, short what, void *arg)
{
    mgmt_endpoint_t *ep = arg;
    mgmt_listener_t *l;
    (void)fd;
    (void)what;
    for (l = ep->listeners; l; l = l->next)
        evconnlistener_enable(l->lev);
}

static void
resume_cb(evutil_socket_t fd, short what, void *arg)
{
    mgmt_endpoint_t *ep = arg;
    mgmt_listener_t *l;
    (void)fd;
    (void)what;

    ep->requests_used = 0;
    ep->accepts_used = 0;
    if (!evtimer_pending(ep->backoff, NULL))
        for (l = ep->listeners; l; l = l->next)
            evconnlistener_enable(l->lev);
    while (ep->wq_len && ep->requests_used < ep->lim.request_budget_per_loop) {
        mgmt_conn_t *c = CONTAINER_OF(ep->wq.next, mgmt_conn_t, wq);
        wq_remove(c);
        ep->requests_used++;
        dispatch_one(c);
    }
    if (ep->wq_len) {
        lnode_t *n;
        for (n = ep->wq.next; n != &ep->wq; n = n->next)
            CONTAINER_OF(n, mgmt_conn_t, wq)->l->cnt.budget_deferrals++;
        arm_resume(ep);
    }
}

mgmt_endpoint_t *
mgmt_endpoint_new(struct event_base *eb, const mgmt_endpoint_ctx_t *ctx,
                  const mgmt_conn_limits_t *limits)
{
    mgmt_endpoint_t *ep = calloc(1, sizeof(*ep));
    if (!ep) return NULL;
    ep->eb = eb;
    ep->ctx = *ctx;
    ep->lim = *limits;
    /* a 0 budget would re-arm the 0 ms resume timer forever */
    if (ep->lim.request_budget_per_loop < 1) ep->lim.request_budget_per_loop = 1;
    if (ep->lim.accept_budget_per_loop < 1) ep->lim.accept_budget_per_loop = 1;
    ln_init(&ep->wq);
    ep->resume = evtimer_new(eb, resume_cb, ep);
    ep->backoff = evtimer_new(eb, backoff_cb, ep);
    if (!ep->resume || !ep->backoff) {
        if (ep->resume) event_free(ep->resume);
        if (ep->backoff) event_free(ep->backoff);
        free(ep);
        return NULL;
    }
    return ep;
}

mgmt_listener_t *
mgmt_endpoint_add_listener(mgmt_endpoint_t *ep, evutil_socket_t listen_fd,
                           mgmt_role_t role, const char *name)
{
    mgmt_listener_t *l = calloc(1, sizeof(*l));
    if (!l) return NULL;
    l->ep = ep;
    l->role = role;
    {
        const char *nm = name ? name : "";
        l->name = malloc(strlen(nm) + 1);
        if (l->name) memcpy(l->name, nm, strlen(nm) + 1);
    }
    ln_init(&l->conns);
    l->log_timer = evtimer_new(ep->eb, log_timer_cb, l);
    if (!l->name || !l->log_timer || evutil_make_socket_nonblocking(listen_fd) != 0)
        goto fail;
    /* No CLOSE_ON_FREE (the fd stays caller-owned); backlog 0: already listening.
     * CLOSE_ON_EXEC keeps helper processes the client execs from inheriting
     * admin connections. */
    l->lev =
        evconnlistener_new(ep->eb, accept_cb, l, LEV_OPT_CLOSE_ON_EXEC, 0, listen_fd);
    if (!l->lev) goto fail;
    evconnlistener_set_error_cb(l->lev, accept_error_cb);
    l->next = ep->listeners;
    ep->listeners = l;
    return l;
fail:
    if (l->log_timer) event_free(l->log_timer);
    free(l->name);
    free(l);
    return NULL;
}

void
mgmt_endpoint_free(mgmt_endpoint_t *ep)
{
    mgmt_listener_t *l, *next;
    if (!ep) return;
    for (l = ep->listeners; l; l = next) {
        next = l->next;
        while (ln_linked(&l->conns))
            conn_destroy(CONTAINER_OF(l->conns.next, mgmt_conn_t, all));
        evconnlistener_free(l->lev);
        event_free(l->log_timer);
        free(l->name);
        free(l);
    }
    event_free(ep->resume);
    event_free(ep->backoff);
    free(ep);
}

void
mgmt_listener_counters(const mgmt_listener_t *l, mgmt_listener_counters_t *out)
{
    *out = l->cnt;
}
