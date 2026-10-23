// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * mgmt_endpoint_host — test host for the management IPC endpoint.
 *
 * Opens the listener and the connection layer directly (not through
 * mgmt_runtime_start) so the limits can be shrunk from the command line.
 * Used by scripts/ci_e2e/run_client_mgmt_ipc_test.sh.
 *
 *   mgmt_endpoint_host <path> [--mode 0660] [--group NAME] [--version STR]
 *       [--budget N] [--handshake-ms N] [--max-conn N] [--silent] [--no-accept]
 *       [--stop-file PATH]
 */
#include "mgmt_conn.h"
#include "mgmt_listen.h"

#include <event2/event.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <winsock2.h>
#else
#  include <sys/socket.h>
#endif
#include <sys/stat.h>

#define SILENT_MAX 64

static struct event_base *g_eb;
static const char *g_stop_file;
static evutil_socket_t g_silent_fds[SILENT_MAX];
static int g_silent_n;

static void
stop_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    (void)arg;
    event_base_loopbreak(g_eb);
}

static void
poll_stop_file_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    (void)arg;
    struct stat st;
    if (g_stop_file && stat(g_stop_file, &st) == 0) event_base_loopbreak(g_eb);
}

/* --silent: accept and keep the connection open, never read it. */
static void
silent_accept_cb(evutil_socket_t lfd, short what, void *arg)
{
    (void)what;
    (void)arg;
    evutil_socket_t c = accept(lfd, NULL, NULL);
    if (c == (evutil_socket_t)-1) return;
    if (g_silent_n < SILENT_MAX)
        g_silent_fds[g_silent_n++] = c;
    else
        evutil_closesocket(c);
}

static int
usage(void)
{
    fprintf(stderr,
            "usage: mgmt_endpoint_host <path> [--mode M] [--group G] [--version V]\n"
            "       [--budget N] [--handshake-ms N] [--max-conn N] [--silent]\n"
            "       [--no-accept] [--stop-file PATH]\n");
    return 1;
}

int
main(int argc, char **argv)
{
    const char *path = NULL, *mode_s = NULL, *group = NULL, *version = "test";
    long budget = -1, hs_ms = -1, max_conn = -1;
    int silent = 0, no_accept = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        int has_val = i + 1 < argc;
        if (!strcmp(a, "--silent")) {
            silent = 1;
        } else if (!strcmp(a, "--no-accept")) {
            no_accept = 1;
        } else if (!strcmp(a, "--mode") && has_val) {
            mode_s = argv[++i];
        } else if (!strcmp(a, "--group") && has_val) {
            group = argv[++i];
        } else if (!strcmp(a, "--version") && has_val) {
            version = argv[++i];
        } else if (!strcmp(a, "--budget") && has_val) {
            budget = atol(argv[++i]);
        } else if (!strcmp(a, "--handshake-ms") && has_val) {
            hs_ms = atol(argv[++i]);
        } else if (!strcmp(a, "--max-conn") && has_val) {
            max_conn = atol(argv[++i]);
        } else if (!strcmp(a, "--stop-file") && has_val) {
            g_stop_file = argv[++i];
        } else if (a[0] != '-' && !path) {
            path = a;
        } else {
            return usage();
        }
    }
    if (!path) return usage();

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif

    char err[256] = "";
    mgmt_listen_opts_t lo = {
        .path = path, .mode = mgmt_listen_parse_mode(mode_s), .group = group};
    mgmt_listen_t *l = mgmt_listen_open(&lo, err, sizeof(err));
    if (!l) {
        fprintf(stderr, "mgmt_endpoint_host: %s\n", err);
        return 1;
    }

    g_eb = event_base_new();
    if (!g_eb) {
        fprintf(stderr, "mgmt_endpoint_host: event_base_new failed\n");
        mgmt_listen_close(l);
        return 1;
    }

    mgmt_endpoint_t *ep = NULL;
    struct event *lev = NULL;
    if (!no_accept) {
        mgmt_endpoint_ctx_t ctx = {.endpoint_version = version};
        mgmt_conn_limits_t lim;
        mgmt_conn_limits_default(&lim);
        if (budget >= 0) lim.request_budget_per_loop = (uint32_t)budget;
        if (hs_ms >= 0) lim.handshake_deadline_ms = (uint32_t)hs_ms;
        if (max_conn >= 0) lim.max_connections = (uint32_t)max_conn;
        if (silent) {
            evutil_socket_t fd = mgmt_listen_fd(l);
            evutil_make_socket_nonblocking(fd);
            lev = event_new(g_eb, fd, EV_READ | EV_PERSIST, silent_accept_cb, NULL);
            if (!lev || event_add(lev, NULL) != 0) {
                fprintf(stderr, "mgmt_endpoint_host: cannot watch the listener\n");
                mgmt_listen_close(l);
                return 1;
            }
        } else {
            ep = mgmt_endpoint_new(g_eb, &ctx, &lim);
            if (!ep || !mgmt_endpoint_add_listener(ep, mgmt_listen_fd(l), MGMT_ROLE_ADMIN,
                                                   path)) {
                fprintf(stderr, "mgmt_endpoint_host: cannot start the endpoint\n");
                if (ep) mgmt_endpoint_free(ep);
                mgmt_listen_close(l);
                return 1;
            }
        }
    }

    struct event *tmr = event_new(g_eb, -1, EV_PERSIST, poll_stop_file_cb, NULL);
    struct timeval tv = {0, 100 * 1000};
    if (tmr) event_add(tmr, &tv);
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
    struct event *sigt = evsignal_new(g_eb, SIGTERM, stop_cb, NULL);
    struct event *sigi = evsignal_new(g_eb, SIGINT, stop_cb, NULL);
    if (sigt) event_add(sigt, NULL);
    if (sigi) event_add(sigi, NULL);
#endif

    printf("listening on %s\n", path);
    fflush(stdout);

    event_base_dispatch(g_eb);

    /* Runtime order: endpoint free -> one loop pass so the connection fds
     * really close -> listener close (unlinks the path). */
    if (ep) mgmt_endpoint_free(ep);
    if (lev) event_free(lev);
    for (int i = 0; i < g_silent_n; i++)
        evutil_closesocket(g_silent_fds[i]);
    event_base_loop(g_eb, EVLOOP_NONBLOCK);
    mgmt_listen_close(l);
    if (tmr) event_free(tmr);
#ifndef _WIN32
    if (sigt) event_free(sigt);
    if (sigi) event_free(sigi);
#endif
    event_base_free(g_eb);
    return 0;
}
