// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#define _GNU_SOURCE    /* sendmmsg / struct mmsghdr — see src/udp_offload.c header \
                          comment; must precede every #include, same as there. */
/* Keep assert() live even in Release builds: CI runs ctest on Release too,
 * where NDEBUG would silently no-op every assertion in this file. */
#undef NDEBUG
#include <arpa/inet.h> /* htons() for the peer round-trip check below */
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "udp_offload.h"

#ifndef UDP_SEGMENT
#  define UDP_SEGMENT 103
#endif

#ifndef UDP_GRO
#  define UDP_GRO 104
#endif

static struct iovec
iv(size_t len)
{
    struct iovec v = {(void *)"", len};
    return v;
}

/* --- seam control -------------------------------------------------- */
static int seam_fail_call; /* 1-based syscall index to fail; 0 = never */
static int seam_fail_errno;
static int seam_mmsg_partial; /* if >0, sendmmsg reports only this many */
static int seam_calls;
static char seam_ops[64];     /* op trace: 'm' = sendmsg, 'M' = sendmmsg
                                 (64 > worst case: 32 single-datagram runs) */
static int seam_last_was_gso; /* last sendmsg carried a VALID UDP_SEGMENT cmsg */
static uint16_t seam_last_seg;
static size_t seam_bytes;

ssize_t
mqvpn_seam_sendmsg(int fd, const struct msghdr *msg, int flags)
{
    /* Every case in this suite drives mqvpn_udp_send_batch() with the same
     * fake fd (3) and an AF_INET peer (port 4433) — pin all of fd, address
     * family, namelen, and port, since a mismatch on any of them would mean
     * the peer/fd arguments were not propagated from the batch call through
     * to the underlying syscall unchanged (a truncated msg_namelen or a
     * mangled port would not be caught by the family check alone). */
    assert(fd == 3);
    assert(flags & MSG_DONTWAIT);
    assert(msg->msg_name != NULL);
    assert(msg->msg_namelen == sizeof(struct sockaddr_in));
    assert(((const struct sockaddr_in *)msg->msg_name)->sin_family == AF_INET);
    assert(((const struct sockaddr_in *)msg->msg_name)->sin_port == htons(4433));
    seam_ops[seam_calls++] = 'm';
    seam_last_was_gso = 0;
    if (msg->msg_controllen != 0) {
        /* full TX cmsg ABI check: level/type/exact len/payload value */
        struct cmsghdr *cm = CMSG_FIRSTHDR((struct msghdr *)msg);
        assert(cm != NULL);
        assert(cm->cmsg_level == SOL_UDP);
        assert(cm->cmsg_type == UDP_SEGMENT);
        assert(cm->cmsg_len == CMSG_LEN(sizeof(uint16_t)));
        memcpy(&seam_last_seg, CMSG_DATA(cm), sizeof(seam_last_seg));
        assert(seam_last_seg == msg->msg_iov[0].iov_len);
        seam_last_was_gso = 1;
    }
    if (seam_fail_call == seam_calls) {
        errno = seam_fail_errno;
        return -1;
    }
    size_t n = 0;
    for (size_t i = 0; i < msg->msg_iovlen; i++)
        n += msg->msg_iov[i].iov_len;
    seam_bytes += n;
    return (ssize_t)n;
}
int
mqvpn_seam_sendmmsg(int fd, struct mmsghdr *mv, unsigned int vlen, int flags)
{
    assert(fd == 3);
    assert(flags & MSG_DONTWAIT);
    seam_ops[seam_calls++] = 'M';
    if (seam_fail_call == seam_calls) {
        errno = seam_fail_errno;
        return -1;
    }
    /* Peer propagation check (mmsg equivalent of mqvpn_seam_sendmsg's): the
     * fallback path fans one peer out to every mmsghdr entry — check all of
     * them, not just the first, for family, namelen, AND port (see the
     * comment in mqvpn_seam_sendmsg for why all four fields matter). */
    for (unsigned int i = 0; i < vlen; i++) {
        assert(mv[i].msg_hdr.msg_name != NULL);
        assert(mv[i].msg_hdr.msg_namelen == sizeof(struct sockaddr_in));
        assert(((const struct sockaddr_in *)mv[i].msg_hdr.msg_name)->sin_family ==
               AF_INET);
        assert(((const struct sockaddr_in *)mv[i].msg_hdr.msg_name)->sin_port ==
               htons(4433));
    }
    unsigned int n = seam_mmsg_partial ? (unsigned)seam_mmsg_partial : vlen;
    for (unsigned int i = 0; i < n; i++) {
        mv[i].msg_len = (unsigned)mv[i].msg_hdr.msg_iov[0].iov_len;
        seam_bytes += mv[i].msg_len;
    }
    return (int)n;
}
static void
seam_reset(void)
{
    memset(seam_ops, 0, sizeof(seam_ops));
    seam_fail_call = seam_fail_errno = seam_mmsg_partial = 0;
    seam_calls = seam_last_was_gso = 0;
    seam_last_seg = 0;
    seam_bytes = 0;
}

static void
test_run_len(void)
{
    struct iovec a[5];
    /* uniform: all one run */
    for (int i = 0; i < 5; i++)
        a[i] = iv(1400);
    assert(mqvpn_gso_run_len(a, 5) == 5);
    /* trailing short joins the run */
    a[4] = iv(200);
    assert(mqvpn_gso_run_len(a, 5) == 5);
    /* short then more: short closes the run */
    a[2] = iv(200);
    assert(mqvpn_gso_run_len(a, 5) == 3); /* 1400,1400,200 */
    /* larger datagram never joins */
    a[0] = iv(1400);
    a[1] = iv(1500);
    assert(mqvpn_gso_run_len(a, 2) == 1);
    /* single */
    assert(mqvpn_gso_run_len(a, 1) == 1);
    /* 32-cap (XQC_MAX_SEND_MSG_ONCE): a full uniform burst is one run */
    {
        struct iovec b[32];
        for (int i = 0; i < 32; i++)
            b[i] = iv(1400);
        assert(mqvpn_gso_run_len(b, 32) == 32);
    }
    /* two consecutive shorts: second short starts the next run */
    {
        struct iovec c[3];
        c[0] = iv(1400);
        c[1] = iv(200);
        c[2] = iv(200);
        assert(mqvpn_gso_run_len(c, 3) == 2);
    }
    /* short at position 1, cnt=2: one run (short tail) */
    {
        struct iovec d[2];
        d[0] = iv(1400);
        d[1] = iv(200);
        assert(mqvpn_gso_run_len(d, 2) == 2);
    }
    printf("test_run_len OK\n");
}

static void
test_probe(void)
{
    /* The probe uses a real socket — not seam-interceptable — so this
     * asserts only the result SHAPE, never a kernel capability: a valid
     * old-kernel/seccomp environment must not fail the suite. */
    int r = mqvpn_udp_gso_probe();
    assert(r == 0 || r == 1);
    if (!r) printf("note: kernel lacks UDP_SEGMENT; GSO paths covered via seam\n");
    printf("test_probe OK\n");
}

/* --- mqvpn_udp_send_batch cases ------------------------------------- */

static void
test_gso_full_burst(void)
{
    seam_reset();
    struct iovec iov[9] = {iv(1400), iv(1400), iv(1400), iv(1400), iv(1400),
                           iv(1400), iv(1400), iv(1400), iv(300)};
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof peer);
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    int sticky = 0;
    mqvpn_tx_counters_t tx = {0};
    ssize_t r = mqvpn_udp_send_batch(3, iov, 9, (struct sockaddr *)&peer, sizeof peer, 1,
                                     &sticky, &tx);
    assert(r == 9);
    assert(seam_calls == 1);
    assert(seam_ops[0] == 'm');
    assert(seam_last_was_gso == 1);
    assert(seam_last_seg == 1400);
    assert(tx.bytes == 8 * 1400u + 300u);
    /* The batching factor the udp-tx teardown line reports: one syscall
     * carried all 9 datagrams. */
    assert(tx.sends == 1);
    assert(tx.datagrams == 9);
    printf("test_gso_full_burst OK\n");
}

static void
test_gso_single_skips_cmsg(void)
{
    seam_reset();
    struct iovec iov[1] = {iv(1400)};
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof peer);
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    int sticky = 0;
    mqvpn_tx_counters_t tx = {0};
    ssize_t r = mqvpn_udp_send_batch(3, iov, 1, (struct sockaddr *)&peer, sizeof peer, 1,
                                     &sticky, &tx);
    assert(r == 1);
    assert(seam_calls == 1);
    assert(seam_ops[0] == 'm');
    assert(seam_last_was_gso == 0);
    assert(tx.sends == 1);
    assert(tx.datagrams == 1);
    printf("test_gso_single_skips_cmsg OK\n");
}

static void
test_mixed_runs(void)
{
    seam_reset();
    struct iovec iov[4] = {iv(1400), iv(1400), iv(200), iv(1400)};
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof peer);
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    int sticky = 0;
    mqvpn_tx_counters_t tx = {0};
    ssize_t r = mqvpn_udp_send_batch(3, iov, 4, (struct sockaddr *)&peer, sizeof peer, 1,
                                     &sticky, &tx);
    assert(r == 4);
    assert(seam_calls == 2);
    assert(seam_ops[0] == 'm' && seam_ops[1] == 'm');
    assert(tx.sends == 2); /* two runs = two sendmsg calls */
    assert(tx.datagrams == 4);
    printf("test_mixed_runs OK\n");
}

static void
test_fallback_sendmmsg(void)
{
    seam_reset();
    struct iovec iov[3] = {iv(1400), iv(1400), iv(1400)};
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof peer);
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    int sticky = 0;
    mqvpn_tx_counters_t tx = {0};
    ssize_t r = mqvpn_udp_send_batch(3, iov, 3, (struct sockaddr *)&peer, sizeof peer, 0,
                                     &sticky, &tx);
    assert(r == 3);
    assert(seam_calls == 1);
    assert(seam_ops[0] == 'M');
    /* sendmmsg batches too: the ratio is not GSO-exclusive. */
    assert(tx.sends == 1);
    assert(tx.datagrams == 3);
    printf("test_fallback_sendmmsg OK\n");
}

static void
test_gso_error_zero_sent_resends(void)
{
    seam_reset();
    struct iovec iov[4] = {iv(1400), iv(1400), iv(1400), iv(1400)};
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof peer);
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    int sticky = 0;
    mqvpn_tx_counters_t tx = {0};
    seam_fail_call = 1;
    seam_fail_errno = EIO;
    ssize_t r = mqvpn_udp_send_batch(3, iov, 4, (struct sockaddr *)&peer, sizeof peer, 1,
                                     &sticky, &tx);
    assert(r == 4);
    assert(sticky == 1);
    assert(seam_ops[0] == 'm' && seam_ops[1] == 'M');
    assert(seam_calls == 2);
    assert(tx.bytes == 4 * 1400u);
    /* The failed GSO sendmsg delivered nothing, so only the retry counts. */
    assert(tx.sends == 1);
    assert(tx.datagrams == 4);
    printf("test_gso_error_zero_sent_resends OK\n");
}

static void
test_gso_error_einval_resends(void)
{
    /* Mirror of test_gso_error_zero_sent_resends with EINVAL instead of EIO:
     * pins gso_class_error()'s set membership beyond just EIO. */
    seam_reset();
    struct iovec iov[4] = {iv(1400), iv(1400), iv(1400), iv(1400)};
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof peer);
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    int sticky = 0;
    mqvpn_tx_counters_t tx = {0};
    seam_fail_call = 1;
    seam_fail_errno = EINVAL;
    ssize_t r = mqvpn_udp_send_batch(3, iov, 4, (struct sockaddr *)&peer, sizeof peer, 1,
                                     &sticky, &tx);
    assert(r == 4);
    assert(sticky == 1);
    assert(seam_ops[0] == 'm' && seam_ops[1] == 'M');
    assert(tx.sends == 1);
    assert(tx.datagrams == 4);
    printf("test_gso_error_einval_resends OK\n");
}

static void
test_gso_error_enotsup_resends(void)
{
    /* Mirror of test_gso_error_einval_resends with ENOTSUP instead of
     * EINVAL: pins gso_class_error()'s set membership for all three
     * documented GSO-class errnos (EIO/EINVAL/ENOTSUP). */
    seam_reset();
    struct iovec iov[4] = {iv(1400), iv(1400), iv(1400), iv(1400)};
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof peer);
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    int sticky = 0;
    mqvpn_tx_counters_t tx = {0};
    seam_fail_call = 1;
    seam_fail_errno = ENOTSUP;
    ssize_t r = mqvpn_udp_send_batch(3, iov, 4, (struct sockaddr *)&peer, sizeof peer, 1,
                                     &sticky, &tx);
    assert(r == 4);
    assert(sticky == 1);
    assert(seam_ops[0] == 'm' && seam_ops[1] == 'M');
    assert(tx.bytes == 4 * 1400u);
    assert(tx.sends == 1);
    assert(tx.datagrams == 4);
    printf("test_gso_error_enotsup_resends OK\n");
}

static void
test_gso_error_after_progress_stops(void)
{
    seam_reset();
    struct iovec iov[4] = {iv(1400), iv(1400), iv(1500), iv(1500)};
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof peer);
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    int sticky = 0;
    mqvpn_tx_counters_t tx = {0};
    seam_fail_call = 2;
    seam_fail_errno = EIO;
    ssize_t r = mqvpn_udp_send_batch(3, iov, 4, (struct sockaddr *)&peer, sizeof peer, 1,
                                     &sticky, &tx);
    assert(r == 2);
    assert(sticky == 1);
    assert(seam_calls == 2);
    assert(tx.bytes == 2 * 1400u);
    assert(tx.sends == 1); /* only the first run's sendmsg landed */
    assert(tx.datagrams == 2);
    printf("test_gso_error_after_progress_stops OK\n");
}

static void
test_eintr_retries(void)
{
    /* The generic seam_fail_call/seam_fail_errno mechanism already models
     * EINTR correctly with no extra seam state: seam_calls increments on
     * every physical invocation (success or failure), so failing exactly
     * call 1 with EINTR is inherently one-shot — the retried call (call 2,
     * driven by src/udp_offload.c's own `while (r < 0 && errno == EINTR)`
     * loop) does not match seam_fail_call again and proceeds normally. */
    seam_reset();
    struct iovec iov[4] = {iv(1400), iv(1400), iv(1400), iv(1400)};
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof peer);
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    int sticky = 0;
    mqvpn_tx_counters_t tx = {0};
    seam_fail_call = 1;
    seam_fail_errno = EINTR;
    ssize_t r = mqvpn_udp_send_batch(3, iov, 4, (struct sockaddr *)&peer, sizeof peer, 1,
                                     &sticky, &tx);
    assert(r == 4);
    assert(seam_calls == 2); /* retry happened */
    assert(sticky == 0);
    assert(tx.bytes == 4 * 1400u);
    assert(tx.sends == 1); /* the EINTR attempt delivered nothing */
    assert(tx.datagrams == 4);
    printf("test_eintr_retries OK\n");
}

static void
test_fallback_eintr_retries(void)
{
    /* Fallback (use_gso=0) counterpart of test_eintr_retries: pins the
     * OTHER EINTR retry loop — send_batch_mmsg's own
     * `do { r = OFFLOAD_SENDMMSG(...); } while (r < 0 && errno == EINTR);`
     * (src/udp_offload.c, inside send_batch_mmsg) — which was previously
     * untested; only the GSO sendmsg loop's EINTR retry was pinned before
     * this. Same one-shot-via-seam_calls reasoning as test_eintr_retries
     * applies here, just against mqvpn_seam_sendmmsg instead of
     * mqvpn_seam_sendmsg. */
    seam_reset();
    struct iovec iov[4] = {iv(1400), iv(1400), iv(1400), iv(1400)};
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof peer);
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    int sticky = 0;
    mqvpn_tx_counters_t tx = {0};
    seam_fail_call = 1;
    seam_fail_errno = EINTR;
    ssize_t r = mqvpn_udp_send_batch(3, iov, 4, (struct sockaddr *)&peer, sizeof peer, 0,
                                     &sticky, &tx);
    assert(r == 4);
    assert(seam_calls == 2); /* retry happened */
    assert(seam_ops[0] == 'M' && seam_ops[1] == 'M');
    assert(sticky == 0);
    assert(tx.bytes == 4 * 1400u);
    assert(tx.sends == 1); /* the EINTR attempt delivered nothing */
    assert(tx.datagrams == 4);
    printf("test_fallback_eintr_retries OK\n");
}

static void
test_eagain_first(void)
{
    seam_reset();
    struct iovec iov[2] = {iv(1400), iv(1400)};
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof peer);
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    int sticky = 0;
    mqvpn_tx_counters_t tx = {0};
    seam_fail_call = 1;
    seam_fail_errno = EAGAIN;
    ssize_t r = mqvpn_udp_send_batch(3, iov, 2, (struct sockaddr *)&peer, sizeof peer, 1,
                                     &sticky, &tx);
    assert(r == MQVPN_SEND_EAGAIN);
    assert(sticky == 0);
    assert(tx.sends == 0);
    assert(tx.datagrams == 0);
    printf("test_eagain_first OK\n");
}

static void
test_eagain_mid(void)
{
    seam_reset();
    struct iovec iov[4] = {iv(1400), iv(1400), iv(1500), iv(1500)};
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof peer);
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    int sticky = 0;
    mqvpn_tx_counters_t tx = {0};
    seam_fail_call = 2;
    seam_fail_errno = EAGAIN;
    ssize_t r = mqvpn_udp_send_batch(3, iov, 4, (struct sockaddr *)&peer, sizeof peer, 1,
                                     &sticky, &tx);
    assert(r == 2);
    assert(sticky == 0);
    assert(seam_calls == 2);
    assert(tx.sends == 1);
    assert(tx.datagrams == 2);
    printf("test_eagain_mid OK\n");
}

static void
test_mmsg_partial_stops(void)
{
    seam_reset();
    struct iovec iov[5] = {iv(100), iv(200), iv(300), iv(400), iv(500)};
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof peer);
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    int sticky = 0;
    mqvpn_tx_counters_t tx = {0};
    seam_mmsg_partial = 3;
    ssize_t r = mqvpn_udp_send_batch(3, iov, 5, (struct sockaddr *)&peer, sizeof peer, 0,
                                     &sticky, &tx);
    assert(r == 3);
    assert(seam_calls == 1);
    assert(seam_ops[0] == 'M');
    assert(tx.bytes == 100u + 200u + 300u);
    /* datagrams counts what the kernel accepted (3), not what was offered (5). */
    assert(tx.sends == 1);
    assert(tx.datagrams == 3);
    printf("test_mmsg_partial_stops OK\n");
}

static void
test_hard_error_zero(void)
{
    seam_reset();
    struct iovec iov[2] = {iv(1400), iv(1400)};
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof peer);
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    int sticky = 0;
    mqvpn_tx_counters_t tx = {0};
    seam_fail_call = 1;
    seam_fail_errno = EPERM;
    ssize_t r = mqvpn_udp_send_batch(3, iov, 2, (struct sockaddr *)&peer, sizeof peer, 0,
                                     &sticky, &tx);
    assert(r == MQVPN_SEND_ERR);
    assert(tx.sends == 0);
    assert(tx.datagrams == 0);
    printf("test_hard_error_zero OK\n");
}

static void
test_run1_gso_errno_no_sticky(void)
{
    seam_reset();
    struct iovec iov[1] = {iv(1400)};
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof peer);
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    int sticky = 0;
    mqvpn_tx_counters_t tx = {0};
    seam_fail_call = 1;
    seam_fail_errno = EINVAL;
    ssize_t r = mqvpn_udp_send_batch(3, iov, 1, (struct sockaddr *)&peer, sizeof peer, 1,
                                     &sticky, &tx);
    assert(r == MQVPN_SEND_ERR);
    assert(sticky == 0);
    assert(seam_calls == 1);
    assert(tx.sends == 0);
    assert(tx.datagrams == 0);
    printf("test_run1_gso_errno_no_sticky OK\n");
}

static void
test_sticky_short_circuit(void)
{
    /* *gso_disabled already set from a prior call: the `|| *gso_disabled`
     * term in mqvpn_udp_send_batch must take the sendmmsg fallback even
     * though use_gso == 1 and this run would otherwise qualify for GSO
     * (deleting that term passes every other case in this suite). */
    seam_reset();
    struct iovec iov[4] = {iv(1400), iv(1400), iv(1400), iv(1400)};
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof peer);
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    int sticky = 1;
    mqvpn_tx_counters_t tx = {0};
    ssize_t r = mqvpn_udp_send_batch(3, iov, 4, (struct sockaddr *)&peer, sizeof peer, 1,
                                     &sticky, &tx);
    assert(r == 4);
    assert(seam_calls == 1);
    assert(seam_ops[0] == 'M');
    assert(sticky == 1);
    assert(tx.sends == 1);
    assert(tx.datagrams == 4);
    printf("test_sticky_short_circuit OK\n");
}

static void
test_full_32_burst(void)
{
    seam_reset();
    struct iovec iov[32];
    for (int i = 0; i < 32; i++)
        iov[i] = iv(1400);
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof peer);
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    int sticky = 0;
    mqvpn_tx_counters_t tx = {0};
    ssize_t r = mqvpn_udp_send_batch(3, iov, 32, (struct sockaddr *)&peer, sizeof peer, 1,
                                     &sticky, &tx);
    assert(r == 32);
    assert(seam_calls == 1);
    assert(seam_ops[0] == 'm');
    assert(seam_last_seg == 1400);
    assert(tx.bytes == 32 * 1400u);
    assert(tx.sends == 1);
    assert(tx.datagrams == 32);
    printf("test_full_32_burst OK\n");
}

static void
test_fallback_32_burst(void)
{
    /* Fallback (use_gso=0) counterpart of test_full_32_burst: pins the
     * sendmmsg path's cap headroom now that MQVPN_OFFLOAD_MAX_BATCH (32)
     * replaced the old mv[64] margin — a full 32-datagram burst must still
     * fit in one sendmmsg() call with no truncation. */
    seam_reset();
    struct iovec iov[32];
    for (int i = 0; i < 32; i++)
        iov[i] = iv(1400);
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof peer);
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    int sticky = 0;
    mqvpn_tx_counters_t tx = {0};
    ssize_t r = mqvpn_udp_send_batch(3, iov, 32, (struct sockaddr *)&peer, sizeof peer, 0,
                                     &sticky, &tx);
    assert(r == 32);
    assert(seam_calls == 1);
    assert(seam_ops[0] == 'M');
    assert(tx.bytes == 32 * 1400u);
    assert(tx.sends == 1);
    assert(tx.datagrams == 32);
    printf("test_fallback_32_burst OK\n");
}

static void
test_counters_flat_when_no_run_forms(void)
{
    /* Strictly increasing sizes: every datagram starts a new run, so GSO is
     * enabled and yet each packet costs its own sendmsg. The counters must
     * report a batching factor of exactly 1.0 — the state the startup
     * "udp-gso: GSO enabled" marker cannot distinguish from a fully batched
     * run, and the reason the udp-tx teardown line exists. */
    seam_reset();
    struct iovec iov[4] = {iv(100), iv(200), iv(300), iv(400)};
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof peer);
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    int sticky = 0;
    mqvpn_tx_counters_t tx = {0};
    ssize_t r = mqvpn_udp_send_batch(3, iov, 4, (struct sockaddr *)&peer, sizeof peer, 1,
                                     &sticky, &tx);
    assert(r == 4);
    assert(seam_calls == 4);
    assert(seam_last_was_gso == 0); /* no run > 1 ⇒ no UDP_SEGMENT cmsg */
    assert(tx.sends == 4);
    assert(tx.datagrams == 4);
    printf("test_counters_flat_when_no_run_forms OK\n");
}

static void
test_counters_accumulate_across_calls(void)
{
    /* The counters accumulate (+=), never assign: one struct spans a
     * socket's lifetime across every callback invocation, which is what
     * makes the teardown ratio a whole-run figure rather than a last-burst
     * one. Deleting the += in either the GSO or the sendmmsg branch shows up
     * here and nowhere else in this suite. */
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof peer);
    peer.sin_family = AF_INET;
    peer.sin_port = htons(4433);
    int sticky = 0;
    mqvpn_tx_counters_t tx = {0};

    seam_reset();
    struct iovec burst[4] = {iv(1400), iv(1400), iv(1400), iv(1400)};
    assert(mqvpn_udp_send_batch(3, burst, 4, (struct sockaddr *)&peer, sizeof peer, 1,
                                &sticky, &tx) == 4);
    assert(tx.sends == 1);
    assert(tx.datagrams == 4);

    /* Second call on the same struct, this time down the sendmmsg branch. */
    seam_reset();
    struct iovec single[1] = {iv(300)};
    assert(mqvpn_udp_send_batch(3, single, 1, (struct sockaddr *)&peer, sizeof peer, 0,
                                &sticky, &tx) == 1);
    assert(tx.sends == 2);
    assert(tx.datagrams == 5);
    assert(tx.bytes == 4 * 1400u + 300u);
    printf("test_counters_accumulate_across_calls OK\n");
}

/* ── RX: pure segment split ─────────────────────────────────────────── */

static void
test_gro_seg_len(void)
{
    /* full segments, then the terminator */
    assert(mqvpn_gro_seg_len(4200, 1400, 0) == 1400);
    assert(mqvpn_gro_seg_len(4200, 1400, 2800) == 1400);
    assert(mqvpn_gro_seg_len(4200, 1400, 4200) == 0);
    assert(mqvpn_gro_seg_len(100, 40, 101) == 0);

    /* short tail */
    assert(mqvpn_gro_seg_len(3000, 1400, 2800) == 200);
    assert(mqvpn_gro_seg_len(3000, 1400, 3000) == 0);

    /* seg == 0 means "no cmsg": the whole buffer is one datagram */
    assert(mqvpn_gro_seg_len(1400, 0, 0) == 1400);
    assert(mqvpn_gro_seg_len(1400, 0, 1400) == 0);

    /* seg >= len: one (short) segment, never a zero-length second one. The
     * seg > len row pins the fail-open policy for a segment size the kernel
     * cannot legitimately report: it is delivered, not dropped. */
    assert(mqvpn_gro_seg_len(500, 1400, 0) == 500);
    assert(mqvpn_gro_seg_len(500, 1400, 500) == 0);
    assert(mqvpn_gro_seg_len(1400, 1400, 0) == 1400);
    assert(mqvpn_gro_seg_len(0, 1400, 0) == 0);

    /* the split covers the buffer exactly — walk it as the read loop does */
    size_t off = 0, total = 0, count = 0, sl;
    while ((sl = mqvpn_gro_seg_len(65535, 1400, off)) > 0) {
        total += sl;
        count++;
        off += sl;
    }
    assert(total == 65535);
    assert(count == 47); /* 46 x 1400 + 1 x 1135 */
    printf("test_gro_seg_len OK\n");
}

/* ── RX: sockopt enabler ────────────────────────────────────────────── */

static void
test_gro_enable(void)
{
    /* Like test_gso_probe: pin the contract (0 or -1, errno set on -1), NOT
     * the kernel's capability — runners differ and a capability assert here
     * would be a flake. */
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    int r = mqvpn_udp_gro_enable(fd);
    assert(r == 0 || r == -1);
    if (r == 0) {
        /* Read-back is best-effort: UDP_GRO shipped in Linux 5.0 but its
         * getsockopt handler was added later (kernel commit 98184612aca0)
         * and backported unevenly, so ENOPROTOOPT here is a kernel-version
         * artifact, not a failure of the setsockopt above. */
        int val = 0;
        socklen_t vlen = sizeof(val);
        if (getsockopt(fd, SOL_UDP, UDP_GRO, &val, &vlen) == 0) {
            assert(val != 0);
        } else {
            assert(errno == ENOPROTOOPT);
        }
    }
    close(fd);

    /* Closed fd: pins the -1 return mapping — a wrapper that always returned
     * 0 would pass everything above and fail here — and the errno-preservation
     * contract the caller's log depends on. */
    errno = 0;
    assert(mqvpn_udp_gro_enable(fd) == -1);
    assert(errno == EBADF);
    printf("test_gro_enable OK (r=%d)\n", r);
}

/* ── RX seam ────────────────────────────────────────────────────────── */

static int rx_calls;
static int rx_fail_call; /* 1-based call index to fail; 0 = never */
static int rx_fail_errno;
static size_t rx_payload_len; /* bytes the fake kernel delivers */
static int rx_emit_cmsg;      /* 1 = emit a UDP_GRO cmsg */
static int rx_cmsg_level;
static int rx_cmsg_type;
static socklen_t rx_cmsg_len; /* 0 = the correct CMSG_LEN(sizeof(int)) */
static int rx_cmsg_val;
static int rx_msg_flags; /* flags the fake kernel reports back */

static void
rx_reset(void)
{
    rx_calls = 0;
    rx_fail_call = 0;
    rx_fail_errno = 0;
    rx_payload_len = 4200;
    rx_emit_cmsg = 0;
    rx_cmsg_level = SOL_UDP;
    rx_cmsg_type = UDP_GRO;
    rx_cmsg_len = 0;
    rx_cmsg_val = 1400;
    rx_msg_flags = 0;
}

ssize_t
mqvpn_seam_recvmsg(int fd, struct msghdr *msg, int flags)
{
    assert(fd == 3);
    assert(flags & MSG_DONTWAIT);
    /* Value-result contract: both lengths, and msg_flags, must be at full
     * capacity / zero on EVERY call, retries included. The failure branch
     * below poisons them precisely so a caller that resets only once outside
     * the retry loop trips these asserts on the retry. */
    assert(msg->msg_namelen == sizeof(struct sockaddr_storage));
    assert(msg->msg_controllen == CMSG_SPACE(sizeof(int)));
    assert(msg->msg_flags == 0);
    assert(msg->msg_iovlen == 1);
    assert(msg->msg_iov[0].iov_base != NULL);
    assert(msg->msg_iov[0].iov_len == 65536);
    assert(msg->msg_name != NULL);
    rx_calls++;

    if (rx_fail_call == rx_calls) {
        msg->msg_namelen = 0; /* simulate the kernel shrinking these */
        msg->msg_controllen = 0;
        msg->msg_flags = MSG_TRUNC; /* and leaving stale flags behind */
        errno = rx_fail_errno;
        return -1;
    }

    memset(msg->msg_iov[0].iov_base, 0xAB, rx_payload_len);
    struct sockaddr_in *sin = (struct sockaddr_in *)msg->msg_name;
    memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;
    sin->sin_port = htons(4433);
    msg->msg_namelen = sizeof(*sin);
    msg->msg_flags = rx_msg_flags;

    if (rx_emit_cmsg) {
        struct cmsghdr *cm = CMSG_FIRSTHDR(msg);
        assert(cm != NULL);
        cm->cmsg_level = rx_cmsg_level;
        cm->cmsg_type = rx_cmsg_type;
        cm->cmsg_len = rx_cmsg_len ? rx_cmsg_len : CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cm), &rx_cmsg_val, sizeof(rx_cmsg_val));
        msg->msg_controllen = CMSG_SPACE(sizeof(int));
    } else {
        msg->msg_controllen = 0;
    }
    return (ssize_t)rx_payload_len;
}

/* ── RX: recvmsg wrapper ────────────────────────────────────────────── */

static ssize_t
rx_call(size_t *seg, socklen_t *plen)
{
    static uint8_t buf[65536];
    static struct sockaddr_storage peer;
    *plen = sizeof(peer);
    *seg = 12345; /* poison: the wrapper must always write this */
    return mqvpn_udp_recv_segmented(3, buf, sizeof(buf), (struct sockaddr *)&peer, plen,
                                    seg);
}

static void
test_recv_no_cmsg(void)
{
    size_t seg;
    socklen_t plen;
    rx_reset();
    assert(rx_call(&seg, &plen) == 4200);
    assert(seg == 0); /* no cmsg → one datagram */
    assert(plen == sizeof(struct sockaddr_in));
    assert(rx_calls == 1);
    printf("test_recv_no_cmsg OK\n");
}

static void
test_recv_gro_cmsg(void)
{
    size_t seg;
    socklen_t plen;
    rx_reset();
    rx_emit_cmsg = 1;
    assert(rx_call(&seg, &plen) == 4200);
    assert(seg == 1400);
    printf("test_recv_gro_cmsg OK\n");
}

static void
test_recv_bad_cmsg_ignored(void)
{
    size_t seg;
    socklen_t plen;
    struct {
        const char *what;
        int level, type, val;
        socklen_t len;
        size_t expect_seg; /* what *seg_size must be after the call */
    } cases[] = {
        {"undersized len", SOL_UDP, UDP_GRO, 1400, CMSG_LEN(sizeof(uint16_t)), 0},
        /* oversized too: the length test is an exact compare, not a lower
         * bound — a >= would accept a payload shape the kernel never emits */
        {"oversized len", SOL_UDP, UDP_GRO, 1400, CMSG_LEN(sizeof(int) + 4), 0},
        {"wrong type", SOL_UDP, UDP_SEGMENT, 1400, 0, 0},
        {"wrong level", SOL_SOCKET, UDP_GRO, 1400, 0, 0},
        {"zero seg", SOL_UDP, UDP_GRO, 0, 0, 0},      /* pins the gso > 0 filter */
        {"negative seg", SOL_UDP, UDP_GRO, -1, 0, 0}, /* pins gso > 0, not gso != 0 */
        {"seg > n", SOL_UDP, UDP_GRO, 4201, 0, 4201}, /* stored, then fails open below */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        rx_reset();
        rx_emit_cmsg = 1;
        rx_cmsg_level = cases[i].level;
        rx_cmsg_type = cases[i].type;
        rx_cmsg_val = cases[i].val;
        rx_cmsg_len = cases[i].len;
        assert(rx_call(&seg, &plen) == 4200);
        /* The wrapper's own output: a malformed cmsg must leave seg at 0 —
         * checking only the split below cannot tell "never stored" from
         * "stored as a huge value", since both fail open to one datagram. */
        assert(seg == cases[i].expect_seg);
        /* And every row still delivers exactly one datagram: the malformed
         * rows because seg is 0, the oversize row through the seg >= rest arm. */
        assert(mqvpn_gro_seg_len(4200, seg, 0) == 4200);
        assert(mqvpn_gro_seg_len(4200, seg, 4200) == 0);
    }
    printf("test_recv_bad_cmsg_ignored OK\n");
}

static void
test_recv_truncated_dropped(void)
{
    size_t seg;
    socklen_t plen;

    rx_reset();
    rx_msg_flags = MSG_TRUNC;
    assert(rx_call(&seg, &plen) == MQVPN_RECV_DROP);

    rx_reset();
    rx_emit_cmsg = 1;
    rx_msg_flags = MSG_CTRUNC;
    assert(rx_call(&seg, &plen) == MQVPN_RECV_DROP);

    printf("test_recv_truncated_dropped OK\n");
}

static void
test_recv_eintr_retried(void)
{
    size_t seg;
    socklen_t plen;
    rx_reset();
    rx_fail_call = 1;
    rx_fail_errno = EINTR;
    assert(rx_call(&seg, &plen) == 4200); /* retried, not surfaced */
    assert(rx_calls == 2);
    printf("test_recv_eintr_retried OK\n");
}

static void
test_recv_eagain(void)
{
    size_t seg;
    socklen_t plen;
    rx_reset();
    rx_fail_call = 1;
    rx_fail_errno = EAGAIN;
    assert(rx_call(&seg, &plen) == -1);
    assert(errno == EAGAIN); /* the read loop breaks on this */
    assert(rx_calls == 1);

    /* A hard error must surface with ITS OWN errno. EAGAIN alone cannot tell
     * "errno preserved" from "every failure reported as EAGAIN", and the read
     * loop's break is only correct because the caller can distinguish a
     * drained socket from a dead one. */
    rx_reset();
    rx_fail_call = 1;
    rx_fail_errno = EBADF;
    assert(rx_call(&seg, &plen) == -1);
    assert(errno == EBADF);
    assert(rx_calls == 1);
    printf("test_recv_eagain OK\n");
}

int
main(void)
{
    test_run_len();
    test_probe();
    test_gso_full_burst();
    test_gso_single_skips_cmsg();
    test_mixed_runs();
    test_fallback_sendmmsg();
    test_gso_error_zero_sent_resends();
    test_gso_error_einval_resends();
    test_gso_error_enotsup_resends();
    test_gso_error_after_progress_stops();
    test_eintr_retries();
    test_fallback_eintr_retries();
    test_eagain_first();
    test_eagain_mid();
    test_mmsg_partial_stops();
    test_hard_error_zero();
    test_run1_gso_errno_no_sticky();
    test_sticky_short_circuit();
    test_full_32_burst();
    test_fallback_32_burst();
    test_counters_flat_when_no_run_forms();
    test_counters_accumulate_across_calls();
    test_gro_seg_len();
    test_gro_enable();
    test_recv_no_cmsg();
    test_recv_gro_cmsg();
    test_recv_bad_cmsg_ignored();
    test_recv_truncated_dropped();
    test_recv_eintr_retried();
    test_recv_eagain();
    return 0;
}
