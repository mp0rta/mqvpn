// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* mqvpn_bind_posix.h — bundled POSIX socket transport for libmqvpn (ABI 3).
 *
 * Implements mqvpn_path_ops_t (client paths) and
 * mqvpn_server_transport_ops_t (server) on top of a BORROWED file
 * descriptor: the platform creates, binds, pins, protects and CLOSES the
 * socket; a ctx here only uses it. On Linux the TX side batches with
 * UDP_SEGMENT / sendmmsg and the RX side splits UDP_GRO aggregates; on other
 * POSIX systems it is one syscall per datagram. Windows uses
 * mqvpn_bind_winsock.h instead.
 *
 * Thread safety: same rule as every libmqvpn API — the tick thread only.
 * recv_one()/drain() end in mqvpn_*_on_socket_recv() and add no locking. */
#ifndef MQVPN_BIND_POSIX_H
#define MQVPN_BIND_POSIX_H

#include "libmqvpn.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t struct_size;
    /* Compatibility policy value (config UdpGso). The bind derives its own
     * "GSO allowed" from it with the same rule the core uses for batching, so
     * the two cannot drift. Linux only; ignored elsewhere. */
    int udp_gso;
    /* Enable UDP_GRO on the fd (config UdpGro). Linux only; ignored elsewhere. */
    int udp_gro;
    /* SO_SNDBUF/SO_RCVBUF: > 0 explicit bytes, 0 = library default (7 MiB),
     * -1 = leave the socket's current buffers untouched. Best effort: a
     * setsockopt failure is logged at WARN and construction continues. */
    int socket_buf_bytes;
    /* Optional label used in the bind's own log lines (ifname, "server").
     * Empty = the fd number is used. */
    char tag[16];
} mqvpn_bind_posix_opts_t;

/* Additive growth under struct_size, like every public struct. The embedded
 * mqvpn_transport_stats_t is frozen (see libmqvpn.h). */
typedef struct {
    uint32_t struct_size;       /* caller sets; the bind fills min(struct_size, sizeof) */
    mqvpn_transport_stats_t tx; /* same numbers ops.get_stats reports */
    uint64_t rx_receives;       /* receive calls that delivered data */
    uint64_t rx_datagrams;      /* datagrams pushed to on_socket_recv */
} mqvpn_bind_posix_stats_t;

/* ── Client path transport ──
 *
 * Constructors copy the recognised prefix of *opts (min(struct_size,
 * sizeof)) and never retain the pointer. Returns MQVPN_OK and writes
 * *out_ctx; MQVPN_ERR_INVALID_ARG (fd < 0, opts/out_ctx NULL, struct_size not
 * covering udp_gso); MQVPN_ERR_NO_MEMORY. On failure *out_ctx is untouched
 * and the fd is left exactly as it was — it is never closed by this module.
 * A NULL ctx can therefore never mean "failed" (NULL is a legal ctx for
 * generic transports). GRO unsupported is NOT a failure: construction
 * succeeds with gro_enabled == 0 and the errno readable below. */
MQVPN_API int mqvpn_bind_posix_path_new(int fd, const mqvpn_bind_posix_opts_t *opts,
                                        void **out_ctx);
MQVPN_API const mqvpn_path_ops_t *mqvpn_bind_posix_path_ops(void);
/* Destructor for a ctx the library never took ownership of (add_path failed).
 * Identical to ops.release; never closes the fd. */
MQVPN_API void mqvpn_bind_posix_path_free(void *ctx);

MQVPN_API int mqvpn_bind_posix_path_gro_enabled(const void *ctx); /* 0/1 */
/* errno of a failed enable, else 0 */
MQVPN_API int mqvpn_bind_posix_path_gro_errno(const void *ctx);
/* out->struct_size must be set by the caller and must be at least
 * sizeof(uint32_t) — the size field itself, since a smaller buffer cannot
 * even carry the size written back. A smaller value writes nothing, in every
 * build (it is ABI input, so it is validated rather than asserted); a NULL
 * ctx or out is a programming error and asserts in Debug builds.
 * Valid only while the ctx is alive: until on_platform_path_released() is
 * CALLED (the ctx is finalised inside it — harvest before, never after), or
 * until client_destroy() returns. */
MQVPN_API void mqvpn_bind_posix_path_get_stats(const void *ctx,
                                               mqvpn_bind_posix_stats_t *out);

/* RX helpers — the platform calls one of these when its reactor (or reader
 * thread) says the fd is readable. recv_one() performs ONE receive (possibly
 * a GRO aggregate) and pushes every segment to mqvpn_client_on_socket_recv
 * (handle < 0: drains without delivering). drain() repeats recv_one() until
 * EAGAIN or `budget` units of work (one unit per delivered datagram, or per
 * dropped/undelivered receive — same soft threshold the Linux platform
 * always used, so a single callback cannot starve the tick path).
 * Returns: recv_one: 1 = a receive was performed, 0 = nothing available
 * (EAGAIN / zero-length), -1 = hard socket error (errno preserved).
 * drain: number of receives performed (>= 0), or -1 on a hard error. The
 * platform decides what a hard error means (the Linux platform ignores it
 * and relies on netlink for drop detection, as before). client must be
 * non-NULL even when handle < 0 (-1 otherwise). */
MQVPN_API int mqvpn_bind_posix_path_recv_one(void *ctx, mqvpn_client_t *client,
                                             mqvpn_path_handle_t handle);
MQVPN_API int mqvpn_bind_posix_path_drain(void *ctx, mqvpn_client_t *client,
                                          mqvpn_path_handle_t handle, int budget);

/* ── Server shared transport (single fd) ── */
MQVPN_API int mqvpn_bind_posix_server_new(int fd, const mqvpn_bind_posix_opts_t *opts,
                                          void **out_ctx);
MQVPN_API const mqvpn_server_transport_ops_t *mqvpn_bind_posix_server_ops(void);
MQVPN_API void mqvpn_bind_posix_server_free(void *ctx);
MQVPN_API int mqvpn_bind_posix_server_gro_enabled(const void *ctx);
MQVPN_API int mqvpn_bind_posix_server_gro_errno(const void *ctx);
/* Valid until mqvpn_server_destroy() returns. */
MQVPN_API void mqvpn_bind_posix_server_get_stats(const void *ctx,
                                                 mqvpn_bind_posix_stats_t *out);
MQVPN_API int mqvpn_bind_posix_server_recv_one(void *ctx, mqvpn_server_t *server);
MQVPN_API int mqvpn_bind_posix_server_drain(void *ctx, mqvpn_server_t *server,
                                            int budget);

#ifdef __cplusplus
}
#endif
#endif /* MQVPN_BIND_POSIX_H */
