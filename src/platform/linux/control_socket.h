// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * control_socket.h — TCP control API for mqvpn server
 *
 * Listens on a TCP port (default: 127.0.0.1 only) and accepts JSON commands.
 * All I/O is driven by the same libevent loop as the VPN — no locking needed.
 *
 * Protocol: one JSON object per connection (newline-terminated or EOF).
 * Response: one JSON object followed by a newline, then connection closes.
 *
 * Example:
 *   echo '{"cmd":"add_user","name":"carol","key":"carol-secret"}' \
 *       | nc 127.0.0.1 9090
 */

#ifndef MQVPN_CONTROL_SOCKET_H
#define MQVPN_CONTROL_SOCKET_H

#include "libmqvpn.h"

/* Forward-decl so consumers that only want CTRL_MAX_RESP_BYTES (e.g.
 * tests/test_control_response_bound.c) don't transitively pull libevent
 * headers. The control_socket.c implementation itself includes
 * <event2/event.h> directly. */
struct event_base;

/* Maximum response size. Worst-case get_status with MQVPN_MAX_USERS=64 and
 * MQVPN_MAX_PATHS=8 produces ~210 KB; round up to 256 KB. The exact bound is
 * verified by tests/test_control_response_bound.c — bump it if either limit
 * grows. */
#define CTRL_MAX_RESP_BYTES (256 * 1024)

typedef struct ctrl_socket_s ctrl_socket_t;

/* addr defaults to "127.0.0.1" when NULL. */
ctrl_socket_t *ctrl_socket_create(struct event_base *eb, const char *addr, int port,
                                  mqvpn_server_t *server);

void ctrl_socket_destroy(ctrl_socket_t *cs);

#endif /* MQVPN_CONTROL_SOCKET_H */
