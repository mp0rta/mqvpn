// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#define _GNU_SOURCE    /* glibc gates sendmmsg/struct mmsghdr behind    \
                          _GNU_SOURCE, and no build target here defines \
                          it. Must precede every #include. */
#include "udp_offload.h"
#if defined(__linux__)
/* All implementation, includes included, stays inside this __linux__
 * block: netinet/udp.h etc. do not exist on Windows/macOS, and the
 * Windows compile is this file's only CI gate there. */

#  include <errno.h>
#  include <netinet/in.h>
#  include <netinet/udp.h>
#  include <string.h>
#  include <unistd.h>

#  ifndef UDP_SEGMENT
#    define UDP_SEGMENT 103 /* old glibc headers; value from linux/udp.h UAPI */
#  endif

#  ifndef UDP_GRO
#    define UDP_GRO 104 /* old glibc headers; value from linux/udp.h UAPI */
#  endif

#  ifdef MQVPN_OFFLOAD_TEST_SEAM
/* Fault-injection seam for unit tests: prototypes live in udp_offload.h
 * (tests/test_udp_offload.c defines these symbols; the header declaration
 * makes those definitions compiler-checked against this mapping). */
#    define OFFLOAD_SENDMSG  mqvpn_seam_sendmsg
#    define OFFLOAD_SENDMMSG mqvpn_seam_sendmmsg
#    define OFFLOAD_RECVMSG  mqvpn_seam_recvmsg
#  else
#    define OFFLOAD_SENDMSG  sendmsg
#    define OFFLOAD_SENDMMSG sendmmsg
#    define OFFLOAD_RECVMSG  recvmsg
#  endif

size_t
mqvpn_gso_run_len(const struct iovec *iov, size_t cnt)
{
    size_t seg = iov[0].iov_len;
    for (size_t i = 1; i < cnt; i++) {
        if (iov[i].iov_len == seg) continue;
        if (iov[i].iov_len < seg) return i + 1; /* short tail closes the run */
        return i;                               /* larger starts a new run */
    }
    return cnt;
}

/* Stateless capability probe: does the kernel accept UDP_SEGMENT? Uses a
 * real socket — not seam-interceptable — since it tests an actual kernel
 * property, not a fault-injection scenario. */
int
mqvpn_udp_gso_probe(void)
{
    int fd = (int)socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) fd = (int)socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 0;
    int zero = 0;
    int ok = setsockopt(fd, SOL_UDP, UDP_SEGMENT, &zero, sizeof(zero)) == 0;
    close(fd);
    return ok;
}

int
mqvpn_udp_gro_enable(int fd)
{
    int one = 1;
    /* errno is left as setsockopt set it: the caller logs strerror(errno). */
    return setsockopt(fd, SOL_UDP, UDP_GRO, &one, sizeof(one)) == 0 ? 0 : -1;
}

size_t
mqvpn_gro_seg_len(size_t len, size_t seg, size_t off)
{
    if (off >= len) return 0;
    size_t rest = len - off;
    /* seg == 0: no cmsg, one datagram. seg >= rest: the short final segment.
     * A segment size larger than the whole buffer cannot occur in a valid
     * untruncated kernel result; this shape still delivers it as a single
     * datagram rather than discarding a packet the kernel considers fine. */
    if (seg == 0 || seg >= rest) return rest;
    return seg;
}

/* Sends one GSO run (run == 1 or run > 1 equal-size datagrams, optionally
 * with a final short one) as a single sendmsg(). */
static ssize_t
send_one_run(int fd, const struct iovec *iov, size_t run, uint16_t seg,
             const struct sockaddr *peer, socklen_t peerlen)
{
    struct msghdr msg;
    /* union: a bare char[] has alignment 1 and CMSG_FIRSTHDR's cast to
     * struct cmsghdr* is UB on it (the exact class G11's UBSan catches) */
    union {
        char buf[CMSG_SPACE(sizeof(uint16_t))];
        struct cmsghdr align;
    } ctrl;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)peer;
    msg.msg_namelen = peerlen;
    msg.msg_iov = (struct iovec *)iov;
    msg.msg_iovlen = run;
    if (run > 1) { /* single-datagram runs need no cmsg */
        memset(ctrl.buf, 0, sizeof(ctrl.buf));
        msg.msg_control = ctrl.buf;
        msg.msg_controllen = sizeof(ctrl.buf);
        struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
        cm->cmsg_level = SOL_UDP;
        cm->cmsg_type = UDP_SEGMENT;
        cm->cmsg_len = CMSG_LEN(sizeof(uint16_t)); /* kernel validates exactly */
        memcpy(CMSG_DATA(cm), &seg, sizeof(seg));
        msg.msg_controllen = CMSG_SPACE(sizeof(uint16_t));
    }
    ssize_t r;
    do {
        r = OFFLOAD_SENDMSG(fd, &msg, MSG_DONTWAIT);
    } while (r < 0 && errno == EINTR);
    return r;
}

/* Sends the whole batch via one sendmmsg() call (non-GSO fallback / GSO
 * disabled path). cnt is capped at MQVPN_OFFLOAD_MAX_BATCH (== 32 ==
 * XQC_MAX_SEND_MSG_ONCE) — see the forward-compat invariant on
 * mqvpn_udp_send_batch() in udp_offload.h. */
static ssize_t
send_batch_mmsg(int fd, const struct iovec *iov, unsigned int cnt,
                const struct sockaddr *peer, socklen_t peerlen, mqvpn_tx_counters_t *tx)
{
    struct mmsghdr mv[MQVPN_OFFLOAD_MAX_BATCH];
    if (cnt > MQVPN_OFFLOAD_MAX_BATCH) cnt = MQVPN_OFFLOAD_MAX_BATCH;
    memset(mv, 0, sizeof(mv[0]) * cnt);
    for (unsigned int i = 0; i < cnt; i++) {
        mv[i].msg_hdr.msg_name = (void *)peer;
        mv[i].msg_hdr.msg_namelen = peerlen;
        mv[i].msg_hdr.msg_iov = (struct iovec *)&iov[i];
        mv[i].msg_hdr.msg_iovlen = 1;
    }
    int r;
    do {
        r = OFFLOAD_SENDMMSG(fd, mv, cnt, MSG_DONTWAIT);
    } while (r < 0 && errno == EINTR);
    if (r > 0) {
        /* One syscall carried r datagrams — the whole point of the fallback
         * path, and indistinguishable from r separate sendto()s in every
         * other counter we keep. */
        tx->sends++;
        tx->datagrams += (uint64_t)r;
        for (int i = 0; i < r; i++)
            tx->bytes += mv[i].msg_len;
    }
    return r;
}

/* Errnos that indicate the *kernel/NIC* rejected UDP_SEGMENT itself (as
 * opposed to an ordinary transient send failure) — evidence to sticky-
 * disable GSO for the rest of this socket's lifetime. */
static int
gso_class_error(int e)
{
    return e == EIO || e == EINVAL || e == ENOTSUP;
}

ssize_t
mqvpn_udp_send_batch(int fd, const struct iovec *iov, unsigned int cnt,
                     const struct sockaddr *peer, socklen_t peerlen, int use_gso,
                     int *gso_disabled, mqvpn_tx_counters_t *tx)
{
    if (cnt == 0) return 0; /* nothing to do; avoids classifying stale errno */

    if (!use_gso || *gso_disabled) {
        ssize_t r = send_batch_mmsg(fd, iov, cnt, peer, peerlen, tx);
        if (r > 0) return r;
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? MQVPN_SEND_EAGAIN
                                                         : MQVPN_SEND_ERR;
    }

    unsigned int sent = 0;
    while (sent < cnt) {
        size_t run = mqvpn_gso_run_len(&iov[sent], cnt - sent);
        ssize_t r =
            send_one_run(fd, &iov[sent], run, (uint16_t)iov[sent].iov_len, peer, peerlen);
        if (r < 0) {
            /* A GSO-class errno is only evidence of a GSO failure when this
             * send actually carried the UDP_SEGMENT cmsg (run > 1); a plain
             * single-datagram sendmsg EINVAL/EIO must not sticky-disable. */
            if (run > 1 && gso_class_error(errno)) {
                *gso_disabled = 1; /* sticky, any burst position */
                if (sent == 0)     /* in-call retry only at 0 sent */
                    return mqvpn_udp_send_batch(fd, iov, cnt, peer, peerlen, 0,
                                                gso_disabled, tx);
            }
            if (sent > 0) return sent; /* contiguous prefix */
            return (errno == EAGAIN || errno == EWOULDBLOCK) ? MQVPN_SEND_EAGAIN
                                                             : MQVPN_SEND_ERR;
        }
        tx->bytes += (uint64_t)r;
        /* One sendmsg carried `run` datagrams: run > 1 means the UDP_SEGMENT
         * cmsg was attached and the kernel fanned the buffer out. */
        tx->sends++;
        tx->datagrams += run;
        sent += (unsigned int)run;
    }
    return sent;
}

ssize_t
mqvpn_udp_recv_segmented(int fd, void *buf, size_t buflen, struct sockaddr *peer,
                         socklen_t *peerlen, size_t *seg_size)
{
    struct msghdr msg;
    struct iovec iov;
    /* union, not a bare char[]: CMSG_FIRSTHDR casts this to struct cmsghdr*,
     * which is UB on an alignment-1 array (same fix as the TX path). */
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } ctrl;
    const socklen_t peerlen_in = *peerlen;

    *seg_size = 0;

    ssize_t n;
    do {
        /* msg_namelen / msg_controllen / msg_flags are value-result: the
         * kernel overwrites them, so every call — retries included — starts
         * from full capacity. */
        memset(&msg, 0, sizeof(msg));
        iov.iov_base = buf;
        iov.iov_len = buflen;
        msg.msg_name = peer;
        msg.msg_namelen = peerlen_in;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrl.buf;
        msg.msg_controllen = sizeof(ctrl.buf);
        n = OFFLOAD_RECVMSG(fd, &msg, MSG_DONTWAIT);
    } while (n < 0 && errno == EINTR);
    if (n < 0) return -1; /* errno preserved for the caller (EAGAIN = drained) */

    *peerlen = msg.msg_namelen;

    /* Never hand a truncated buffer to the library as a whole datagram: the
     * QUIC packet at the tail would be silently cut. The 64 KB caller buffer
     * makes this unreachable in practice — but that is an assumption about
     * the current kernel's coalescing bound, not a documented ABI ceiling
     * (udp(7) promises only "multiple datagrams worth of data"), so the check
     * stays and an oversize aggregate is discarded rather than mangled. */
    if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) return MQVPN_RECV_DROP;

    for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msg); cm != NULL;
         cm = CMSG_NXTHDR(&msg, cm)) {
        if (cm->cmsg_level != SOL_UDP || cm->cmsg_type != UDP_GRO) continue;
        if (cm->cmsg_len != CMSG_LEN(sizeof(int))) continue; /* kernel ABI */
        int gso = 0;
        memcpy(&gso, CMSG_DATA(cm), sizeof(gso)); /* alignment-safe copy-out */
        if (gso > 0) *seg_size = (size_t)gso;
        break;
    }
    return n;
}

#endif
