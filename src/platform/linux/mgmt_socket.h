// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* src/platform/linux/mgmt_socket.h — Client Management IPC socket layer.
 * Linux/libevent only (included only in the Linux CMake build).
 *
 * Embedding contract: the process embedding this layer MUST ignore SIGPIPE
 * (signal(SIGPIPE, SIG_IGN)). A peer that closes (or RSTs) its end while a
 * response write is in flight would otherwise kill the whole process.
 * Handled by the embedder, not here, because signal handling lives in the
 * CLI/platform process, never in library-ish code (see AGENTS.md). */
#ifndef MQVPN_MGMT_SOCKET_H
#define MQVPN_MGMT_SOCKET_H
#include <stddef.h>
#include <sys/types.h>
struct event_base;
struct mgmt_ctx; /* mgmt_dispatch.h */

typedef struct mgmt_socket mgmt_socket_t;

/* mkdir the parent dir of path with mode 0755 (no-op if it exists) →
 * unlink a stale socket file → bind → chmod(mode) / chown to group (only if
 * group is non-NULL and non-empty; unknown group = warn + skip, socket stays
 * root-only) → listen(backlog 8). Permissions are applied BEFORE listen()
 * so no connection is ever accepted with wrong perms.
 * ctx must outlive the returned object. On fatal failure returns NULL and
 * writes the reason to errbuf. */
mgmt_socket_t *mgmt_socket_create(struct event_base *eb, const char *path, mode_t mode,
                                  const char *group, const struct mgmt_ctx *ctx,
                                  char *errbuf, size_t errlen);

/* Close all connections, free the listener, unlink the socket file. */
void mgmt_socket_destroy(mgmt_socket_t *ms);

#endif
