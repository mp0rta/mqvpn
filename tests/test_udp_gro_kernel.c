// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* Kernel-backed UDP GSO/GRO round trip. Built WITHOUT MQVPN_OFFLOAD_TEST_SEAM,
 * so every syscall here is the real one. Coalescing is opportunistic and not
 * every host or path aggregates, so a run without coalescing is reported as an
 * environmental outcome — but any UNEXPECTED error fails the test rather than
 * skipping, otherwise a broken wrapper would keep ctest green. */
#define _GNU_SOURCE
#undef NDEBUG
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "udp_offload.h"

#ifndef UDP_GRO
#  define UDP_GRO 104
#endif

#define SEG   1200
#define NSEGS 4
#define TOTAL (SEG * NSEGS)

/* The only errnos that mean "this kernel/host cannot do it", as opposed to
 * "our code is wrong". */
static int
capability_errno(int e)
{
    return e == ENOPROTOOPT || e == EOPNOTSUPP;
}

int
main(void)
{
    int rx = socket(AF_INET, SOCK_DGRAM, 0);
    int tx = socket(AF_INET, SOCK_DGRAM, 0);
    assert(rx >= 0 && tx >= 0);

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(rx, (struct sockaddr *)&a, sizeof(a)) == 0);
    socklen_t alen = sizeof(a);
    assert(getsockname(rx, (struct sockaddr *)&a, &alen) == 0);

    if (mqvpn_udp_gro_enable(rx) < 0) {
        assert(capability_errno(errno)); /* anything else is our bug */
        printf("SKIP: UDP_GRO unavailable (%s)\n", strerror(errno));
        return 0;
    }

    /* Distinct per-segment content: an implementation that delivers only the
     * first segment, or splits at the wrong offset, cannot pass below. */
    uint8_t payload[TOTAL];
    for (int s = 0; s < NSEGS; s++)
        memset(payload + s * SEG, 'A' + s, SEG);

    if (mqvpn_udp_gso_probe()) {
        struct iovec segs[NSEGS];
        for (int s = 0; s < NSEGS; s++) {
            segs[s].iov_base = payload + s * SEG;
            segs[s].iov_len = SEG;
        }
        /* `tx` is the socket fd here, hence the tx_cnt name. */
        mqvpn_tx_counters_t tx_cnt = {0};
        int gso_disabled = 0;
        ssize_t r = mqvpn_udp_send_batch(tx, segs, NSEGS, (struct sockaddr *)&a,
                                         sizeof(a), 1, &gso_disabled, &tx_cnt);
        assert(r == NSEGS); /* a short/failed batch send is a real defect */
        assert(tx_cnt.bytes == TOTAL);
        /* Uniform segments form one run, so the real kernel took all NSEGS
         * datagrams in a single sendmsg — the TX-side counterpart of the
         * receives/datagrams coalescing check below. */
        assert(tx_cnt.sends == 1);
        assert(tx_cnt.datagrams == NSEGS);
    } else {
        for (int s = 0; s < NSEGS; s++)
            assert(sendto(tx, payload + s * SEG, SEG, 0, (struct sockaddr *)&a,
                          sizeof(a)) == SEG);
    }

    /* The receiver should see the sender's address; capture it so the drain
     * loop can verify the wrapper propagates *peer / *peerlen from the real
     * kernel, not just the payload. tx is unbound until its first send, so
     * this must come after the send block, not before it. */
    struct sockaddr_in txaddr;
    socklen_t txlen = sizeof(txaddr);
    assert(getsockname(tx, (struct sockaddr *)&txaddr, &txlen) == 0);

    /* Drain: with coalescing this is one recvmsg, without it NSEGS. Either
     * way the concatenation of everything delivered must equal `payload`
     * exactly, in order. mqvpn_udp_recv_segmented passes MSG_DONTWAIT, so
     * EAGAIN surfaces here regardless of the socket's O_NONBLOCK state. */
    uint8_t got[TOTAL];
    size_t got_len = 0;
    int datagrams = 0, receives = 0, coalesced = 0;
    for (int i = 0; i < NSEGS * 4 && datagrams < NSEGS; i++) {
        uint8_t buf[65536];
        struct sockaddr_storage peer;
        socklen_t plen = sizeof(peer);
        size_t seg = 0;
        ssize_t n = mqvpn_udp_recv_segmented(rx, buf, sizeof(buf),
                                             (struct sockaddr *)&peer, &plen, &seg);
        /* MQVPN_RECV_DROP is negative, so it must be tested BEFORE the error
         * branch or it is swallowed there as a stale-errno retry. A 64 KB
         * buffer cannot truncate a single UDP aggregate — seeing this means
         * the wrapper is wrong. */
        assert(n != MQVPN_RECV_DROP);
        if (n < 0) {
            assert(errno == EAGAIN || errno == EWOULDBLOCK); /* nothing else */
            usleep(20000);
            continue;
        }
        assert(n > 0);
        /* Value-result: the kernel writes the real length back, and the
         * wrapper must hand it through unchanged. */
        assert(plen == sizeof(struct sockaddr_in));
        const struct sockaddr_in *from = (const struct sockaddr_in *)&peer;
        assert(from->sin_family == AF_INET);
        /* Port only, deliberately: tx is never bind()'d, and Linux's UDP
         * autobind fixes the port but leaves the socket's own address at
         * INADDR_ANY, so getsockname(tx) has no address to compare against
         * even though the kernel does pick a real source address per
         * packet. */
        assert(from->sin_port == txaddr.sin_port);
        receives++;
        if (seg > 0 && (size_t)n > seg) coalesced++;
        size_t sl;
        for (size_t off = 0; (sl = mqvpn_gro_seg_len((size_t)n, seg, off)) > 0;
             off += sl) {
            assert(got_len + sl <= sizeof(got));
            memcpy(got + got_len, buf + off, sl);
            got_len += sl;
            datagrams++;
        }
    }

    assert(datagrams == NSEGS);
    assert(got_len == TOTAL);
    assert(memcmp(got, payload, TOTAL) == 0);
    if (coalesced > 0) {
        printf("  ok: GRO verified (%d datagrams in %d receives, %d coalesced)\n",
               datagrams, receives, coalesced);
    } else {
        printf("  ok (no coalescing on this path): %d datagrams in %d receives — "
               "content/order verified, GRO split NOT exercised\n",
               datagrams, receives);
    }
    close(rx);
    close(tx);
    return 0;
}
