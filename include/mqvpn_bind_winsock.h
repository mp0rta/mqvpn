// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* mqvpn_bind_winsock.h — bundled Winsock transport for libmqvpn (ABI 3).
 *
 * Implements mqvpn_path_ops_t (client paths) on top of a BORROWED native
 * SOCKET: the platform creates, binds, pins and CLOSES the socket; a ctx
 * here only uses it. One sendto() per datagram (the core never batches on
 * Windows) and a recvfrom() drain helper for the platform's reactor.
 * Client paths only — the Windows platform has no server mode. POSIX
 * systems use mqvpn_bind_posix.h instead.
 *
 * Thread safety: same rule as every libmqvpn API — the tick thread only.
 * drain() ends in mqvpn_client_on_socket_recv() and adds no locking. */
#ifndef MQVPN_BIND_WINSOCK_H
#define MQVPN_BIND_WINSOCK_H

#ifndef _WIN32
#  error "mqvpn_bind_winsock.h is Windows-only; POSIX systems use mqvpn_bind_posix.h"
#endif

#include "libmqvpn.h" /* winsock2.h / ws2tcpip.h: SOCKET, struct sockaddr */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t struct_size;
    /* SO_SNDBUF/SO_RCVBUF: > 0 explicit bytes, 0 = library default (7 MiB),
     * -1 = leave the socket's current buffers untouched. Best effort: a
     * setsockopt failure is logged at WARN and construction continues. */
    int socket_buf_bytes;
    /* Optional label used in the bind's own log lines (adapter
     * FriendlyName). Empty = the socket value is used. */
    char tag[64];
} mqvpn_bind_winsock_opts_t;

/* Copies the recognised prefix of *opts (min(struct_size, sizeof)) and never
 * retains the pointer. Returns MQVPN_OK and writes *out_ctx;
 * MQVPN_ERR_INVALID_ARG (sock == INVALID_SOCKET, opts/out_ctx NULL,
 * struct_size not covering socket_buf_bytes); MQVPN_ERR_NO_MEMORY. On failure
 * *out_ctx is untouched and the socket is left exactly as it was — this
 * module never closes it. */
MQVPN_API int mqvpn_bind_winsock_path_new(SOCKET sock,
                                          const mqvpn_bind_winsock_opts_t *opts,
                                          void **out_ctx);
MQVPN_API const mqvpn_path_ops_t *mqvpn_bind_winsock_path_ops(void);
/* Destructor for a ctx the library never took ownership of (add_path
 * failed). Identical to ops.release; never closes the socket. */
MQVPN_API void mqvpn_bind_winsock_path_free(void *ctx);

/* RX helper — the platform calls it when its reactor says the socket is
 * readable. Receives until the socket would block or `budget` receives were
 * made (one unit each), pushing every datagram to
 * mqvpn_client_on_socket_recv (handle < 0: drains without delivering).
 * Returns the number of receives (>= 0), or -1 when a receive failed with
 * anything but WSAEWOULDBLOCK — WSAECONNRESET included, which is how Winsock
 * reports an ICMP port-unreachable for an earlier send. A zero-length
 * datagram also ends the drain. client must be non-NULL (-1 otherwise). */
MQVPN_API int mqvpn_bind_winsock_path_drain(void *ctx, mqvpn_client_t *client,
                                            mqvpn_path_handle_t handle, int budget);

#ifdef __cplusplus
}
#endif
#endif /* MQVPN_BIND_WINSOCK_H */
