// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * mgmt_endpoint_host.c — standalone Client Management IPC socket-layer test
 * harness. Not a unit test binary (not registered with add_test): it is a
 * long-running process a human or shell script drives over the Unix domain
 * socket to smoke-test mgmt_socket.c end to end.
 *
 * Usage: mgmt_endpoint_host <socket-path> [--mode 0660] [--group NAME]
 */
#include "log.h"
#include "mgmt_dispatch.h"
#include "mgmt_socket.h"

#include <event2/event.h>

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static struct event_base *g_eb;

static void
on_signal(evutil_socket_t sig, short what, void *arg)
{
    (void)sig;
    (void)what;
    (void)arg;
    event_base_loopbreak(g_eb);
}

static void
usage(const char *argv0)
{
    fprintf(stderr, "usage: %s <socket-path> [--mode 0660] [--group NAME]\n", argv0);
}

int
main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *sock_path = argv[1];
    mode_t mode = 0660;
    const char *group = NULL;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            const char *arg = argv[++i];
            char *end = NULL;
            errno = 0;
            unsigned long v = strtoul(arg, &end, 8);
            if (errno != 0 || end == arg || *end != '\0' || v > 07777) {
                fprintf(stderr, "invalid --mode (octal, max 7777): %s\n", arg);
                return 1;
            }
            mode = (mode_t)v;
        } else if (strcmp(argv[i], "--group") == 0 && i + 1 < argc) {
            group = argv[++i];
        } else {
            fprintf(stderr, "unrecognized argument: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    /* Embedding contract (mgmt_socket.h): the host process must ignore
     * SIGPIPE, or a peer closing/RSTing before a response write flushes
     * would kill the whole process. */
    signal(SIGPIPE, SIG_IGN);

    g_eb = event_base_new();
    if (!g_eb) {
        fprintf(stderr, "event_base_new() failed\n");
        return 1;
    }

    /* capabilities is only ever indexed for i < n_capabilities (see
     * mgmt_dispatch.c's write_capabilities_array), so NULL is safe here. */
    mgmt_ctx_t ctx = {
        .endpoint_version = "host-test-1.0",
        .capabilities = NULL,
        .n_capabilities = 0,
    };

    char errbuf[256];
    mgmt_socket_t *ms =
        mgmt_socket_create(g_eb, sock_path, mode, group, &ctx, errbuf, sizeof(errbuf));
    if (!ms) {
        fprintf(stderr, "mgmt_socket_create: %s\n", errbuf);
        event_base_free(g_eb);
        return 1;
    }

    struct event *ev_term = evsignal_new(g_eb, SIGTERM, on_signal, NULL);
    struct event *ev_int = evsignal_new(g_eb, SIGINT, on_signal, NULL);
    if (!ev_term || !ev_int) {
        fprintf(stderr, "evsignal_new() failed\n");
        if (ev_term) event_free(ev_term);
        if (ev_int) event_free(ev_int);
        mgmt_socket_destroy(ms);
        event_base_free(g_eb);
        return 1;
    }
    event_add(ev_term, NULL);
    event_add(ev_int, NULL);

    event_base_dispatch(g_eb);

    event_free(ev_term);
    event_free(ev_int);
    mgmt_socket_destroy(ms);
    event_base_free(g_eb);
    return 0;
}
