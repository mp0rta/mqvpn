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
#include <event2/event.h>

typedef struct ctrl_socket_s ctrl_socket_t;

/* addr defaults to "127.0.0.1" when NULL. */
ctrl_socket_t *ctrl_socket_create(struct event_base *eb,
                                   const char *addr, int port,
                                   mqvpn_server_t *server);

void ctrl_socket_destroy(ctrl_socket_t *cs);

#endif /* MQVPN_CONTROL_SOCKET_H */
