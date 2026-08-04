// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* UDP offload (Linux): GSO-batched send used by the write_mmsg_ex callbacks
 * (TX) and GRO-coalesced receive used by the platform read loops (RX). Pure
 * syscall/mechanics layer — no xquic types, no client or server state.
 * (issue #167) */
#ifndef MQVPN_UDP_OFFLOAD_H
#define MQVPN_UDP_OFFLOAD_H

#if defined(__linux__)

#  include <stddef.h>
#  include <stdint.h>
#  include <sys/socket.h>
#  include <sys/uio.h>

#  ifdef MQVPN_OFFLOAD_TEST_SEAM
/* Fault-injection seam for unit tests: tests/test_udp_offload.c DEFINES these
 * symbols; declaring them here (rather than as .c-local prototypes) makes
 * those definitions compiler-checked against the exact signatures
 * src/udp_offload.c maps OFFLOAD_SENDMSG/OFFLOAD_SENDMMSG to. Never defined
 * outside the test_udp_offload target. struct mmsghdr requires _GNU_SOURCE,
 * which every TU that reaches this header (src/udp_offload.c,
 * tests/test_udp_offload.c) already #defines before its first #include. */
ssize_t mqvpn_seam_sendmsg(int fd, const struct msghdr *msg, int flags);
int mqvpn_seam_sendmmsg(int fd, struct mmsghdr *msgvec, unsigned int vlen, int flags);
ssize_t mqvpn_seam_recvmsg(int fd, struct msghdr *msg, int flags);
#  endif

/* Result classes for mqvpn_udp_send_batch() when 0 datagrams were sent.
 * (>= 0 return = contiguous-prefix count of datagrams handed to the kernel.)
 * Deliberately disjoint from XQC_SOCKET_ERROR(-1)/XQC_SOCKET_EAGAIN(-2),
 * whose meanings are SWAPPED relative to these — returning r raw to xquic
 * would invert EAGAIN/ERROR; the callbacks map explicitly. */
#  define MQVPN_SEND_EAGAIN (-3) /* would block; caller maps to XQC_SOCKET_EAGAIN */
#  define MQVPN_SEND_ERR    (-4) /* hard socket error; caller decides fate */

/* Fallback (non-GSO) sendmmsg batch cap. Matches xquic's
 * XQC_MAX_SEND_MSG_ONCE; compile-pinned by the _Static_assert next to each
 * write_mmsg_ex registration in mqvpn_client.c / mqvpn_server.c. */
#  define MQVPN_OFFLOAD_MAX_BATCH 32

/* Stateless capability probe: does the kernel accept UDP_SEGMENT?
 * (Kernel property; callers store the result per client/server instance —
 * no global cache: probing is idempotent and engine creation is rare.) */
int mqvpn_udp_gso_probe(void);

/* TX counters accumulated by mqvpn_udp_send_batch() over one socket's
 * lifetime. `datagrams / sends` is the achieved batching factor: 1.0 means
 * every datagram cost its own syscall — no GSO run and no sendmmsg batch ever
 * formed — which the "udp-gso: GSO enabled" marker cannot distinguish from a
 * fully batched run, because that marker only reports the kernel capability
 * probe. Failed syscalls contribute to nothing. Owned by the caller (one
 * instance per client/server), read at teardown for the "udp-tx: " line. */
typedef struct {
    uint64_t bytes;     /* bytes the kernel accepted */
    uint64_t sends;     /* send syscalls that accepted >= 1 datagram */
    uint64_t datagrams; /* datagrams the kernel accepted */
} mqvpn_tx_counters_t;

/* Length of the maximal GSO run starting at iov[0]: the longest prefix of
 * equal-size datagrams, optionally closed by ONE shorter datagram (kernel
 * rule: all segments equal, only the last may be short). A larger datagram
 * always ends the run before itself. cnt >= 1; every iov_len >= 1 (QUIC
 * packets are never empty). Pure function. */
size_t mqvpn_gso_run_len(const struct iovec *iov, size_t cnt);

/* Send cnt datagrams to peer on fd, honoring the contiguous-prefix
 * contract:
 *   - use_gso != 0 and *gso_disabled == 0: one sendmsg + UDP_SEGMENT cmsg
 *     per run (single-datagram runs skip the cmsg); GSO-class errors
 *     (EIO/EINVAL/ENOTSUP) set *gso_disabled = 1 and, iff nothing was sent
 *     yet, the whole batch is retried via sendmmsg within this call.
 *     Sticky-disable fires ONLY when the failed send carried the
 *     UDP_SEGMENT cmsg (run > 1) — a cmsg-less single-datagram (run == 1)
 *     error is a plain hard error and never sticky-disables GSO.
 *   - otherwise: one sendmmsg for the whole batch.
 *   - Any failure after >= 1 datagram sent: return the cumulative count
 *     (never send later runs after a failed one).
 *   - 0 sent: MQVPN_SEND_EAGAIN on EAGAIN/EWOULDBLOCK, MQVPN_SEND_ERR else.
 *   - EINTR: retry the current syscall.  All syscalls use MSG_DONTWAIT.
 *   - *tx accumulates bytes, send syscalls and datagrams from syscall
 *     results; a syscall that failed outright contributes nothing, so the
 *     sticky-disable retry counts only the sendmmsg that succeeded.
 * Precondition: cnt >= 1 (the engine's burst path never sends empty); every
 * iov_len >= 1 (QUIC packets are never empty).
 *
 * Forward-compat invariant: today's safety envelope is
 * MQVPN_OFFLOAD_MAX_BATCH (32) packets x 1400B = 44,800B, comfortably under
 * both the ~64KB kernel GSO/UDP ceiling and UDP_MAX_SEGMENTS (64) — cnt is
 * capped at MQVPN_OFFLOAD_MAX_BATCH (== XQC_MAX_SEND_MSG_ONCE). This module
 * never itself checks MQVPN_MAX_PKT_OUT_SIZE: the write_mmsg_ex registration
 * in mqvpn_client.c / mqvpn_server.c's init_xquic_engine() already guards
 * entry to this whole batching path on MQVPN_MAX_PKT_OUT_SIZE <= 1500, so a
 * full run cannot approach the 64KB ceiling today. Run splitting inside this
 * module would only become necessary if that registration guard were lifted
 * (MQVPN_MAX_PKT_OUT_SIZE raised above ~2KB without adding splitting here
 * first) — otherwise a full run could exceed 64KB and fail EMSGSIZE (not a
 * GSO-class errno here). */
ssize_t mqvpn_udp_send_batch(int fd, const struct iovec *iov, unsigned int cnt,
                             const struct sockaddr *peer, socklen_t peerlen, int use_gso,
                             int *gso_disabled, mqvpn_tx_counters_t *tx);

/* ── RX ─────────────────────────────────────────────────────────────── */

/* mqvpn_udp_recv_segmented(): the datagram was truncated and discarded — the
 * caller keeps draining the socket. Disjoint from -1 (syscall error), 0
 * (zero-length datagram) and from the MQVPN_SEND_* codes above, so a return
 * value routed to the wrong consumer can never look plausible. */
#  define MQVPN_RECV_DROP (-5)

/* Enable kernel UDP GRO on fd (SOL_UDP/UDP_GRO): the kernel coalesces a
 * burst of same-flow datagrams into one buffer and reports the segment size
 * as a cmsg. Returns 0 on success, -1 with errno preserved for the caller's
 * log (kernels < 5.0 fail with ENOPROTOOPT). */
int mqvpn_udp_gro_enable(int fd);

/* Length of the GRO segment starting at byte offset `off` inside a `len`-byte
 * receive buffer whose segments are `seg` bytes each (only the last may be
 * shorter). `seg == 0` means no UDP_GRO cmsg was present, i.e. the buffer
 * holds exactly one datagram. Returns 0 once `off` reaches the end — the read
 * loop's terminator. Pure function. */
size_t mqvpn_gro_seg_len(size_t len, size_t seg, size_t off);

/* Receive one datagram — or one GRO-coalesced burst — from fd into buf.
 *   - Returns the byte count (> 0), 0 for a zero-length datagram, -1 on a
 *     syscall error (errno preserved; EAGAIN means the socket is drained),
 *     or MQVPN_RECV_DROP when the kernel reported truncation.
 *   - *seg_size is the UDP_GRO segment size, or 0 when the kernel sent no
 *     cmsg (an un-coalesced datagram). Feed it to mqvpn_gro_seg_len().
 *   - *peerlen is value-result: set it to the size of the peer buffer before
 *     the call; it is reset on every internal retry and written back with the
 *     kernel's value.
 *   - EINTR is retried internally. The syscall uses MSG_DONTWAIT.
 * A cmsg with an unexpected level, type, length or a non-positive segment
 * size is ignored, not fatal: *seg_size stays 0 and the buffer is delivered
 * as a single datagram — the pre-GRO behavior. */
ssize_t mqvpn_udp_recv_segmented(int fd, void *buf, size_t buflen, struct sockaddr *peer,
                                 socklen_t *peerlen, size_t *seg_size);

#endif /* __linux__ */
#endif /* MQVPN_UDP_OFFLOAD_H */
