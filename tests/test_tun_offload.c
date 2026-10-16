// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * TUN offload helpers (src/platform/linux/tun_offload.c): GSO segmentation and
 * checksum completion, checked against an independent byte-wise RFC 1071
 * verifier, over IPv4/IPv6, TCP/UDP, odd sizes and malformed input.
 * No TUN device or root needed.
 */

#undef NDEBUG
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "platform/linux/tun_offload.h"

#define SEG_CAP 65536

/* ---- reference checksum: big-endian words, written the textbook way ---- */

static uint32_t
ref_sum(const uint8_t *p, size_t n, uint32_t acc)
{
    for (size_t i = 0; i + 1 < n; i += 2)
        acc += (uint32_t)(p[i] << 8 | p[i + 1]);
    if (n & 1) acc += (uint32_t)(p[n - 1] << 8);
    return acc;
}

static uint16_t
ref_fold(uint32_t acc)
{
    while (acc >> 16)
        acc = (acc & 0xffff) + (acc >> 16);
    return (uint16_t)acc;
}

/* Sum over pseudo header + transport segment; 0xffff means "valid". */
static uint16_t
ref_l4_sum(const uint8_t *ip, int v6, uint8_t proto, const uint8_t *l4, size_t l4len)
{
    uint8_t tail[4] = {0, proto, (uint8_t)(l4len >> 8), (uint8_t)l4len};
    uint32_t acc = v6 ? ref_sum(ip + 8, 32, 0) : ref_sum(ip + 12, 8, 0);
    acc = ref_sum(tail, 4, acc);
    acc = ref_sum(l4, l4len, acc);
    return ref_fold(acc);
}

/* ---- packet builder ---- */

typedef struct {
    int v6;
    int proto;   /* IPPROTO_TCP / IPPROTO_UDP */
    int ext;     /* IPv6 extension header bytes (multiple of 8), 0 or 8 */
    int ip_opts; /* IPv4 option bytes (multiple of 4) */
    size_t payload;
    uint8_t tcp_flags;
    uint32_t seq;
    uint16_t id;
} spec_t;

static size_t
build(uint8_t *p, const spec_t *s, size_t *ip_hlen_out)
{
    size_t ip_hlen = s->v6 ? 40 + (size_t)s->ext : 20 + (size_t)s->ip_opts;
    size_t l4hlen = s->proto == IPPROTO_TCP ? 20 : 8;
    size_t total = ip_hlen + l4hlen + s->payload;
    memset(p, 0, total);

    if (s->v6) {
        p[0] = 0x60;
        p[4] = (uint8_t)((total - 40) >> 8);
        p[5] = (uint8_t)(total - 40);
        p[6] = s->ext ? 0 : (uint8_t)s->proto; /* hop-by-hop, then the protocol */
        p[7] = 64;
        for (int i = 0; i < 32; i++)
            p[8 + i] = (uint8_t)(0x20 + i * 7);
        if (s->ext) {
            p[40] = (uint8_t)s->proto; /* next header */
            p[41] = (uint8_t)(s->ext / 8 - 1);
            p[42] = 1; /* PadN */
            p[43] = (uint8_t)(s->ext - 4);
        }
    } else {
        p[0] = (uint8_t)(0x40 | (ip_hlen / 4));
        p[2] = (uint8_t)(total >> 8);
        p[3] = (uint8_t)total;
        p[4] = (uint8_t)(s->id >> 8);
        p[5] = (uint8_t)s->id;
        p[6] = 0x40; /* DF */
        p[8] = 64;
        p[9] = (uint8_t)s->proto;
        for (int i = 0; i < 8; i++)
            p[12 + i] = (uint8_t)(10 + i * 11);
    }

    uint8_t *l4 = p + ip_hlen;
    if (s->proto == IPPROTO_TCP) {
        l4[0] = 0x12;
        l4[1] = 0x34;
        l4[2] = 0x56;
        l4[3] = 0x78;
        uint32_t seq = htonl(s->seq);
        memcpy(l4 + 4, &seq, 4);
        l4[12] = 5 << 4;
        l4[13] = s->tcp_flags;
        l4[14] = 0xff;
        l4[15] = 0xff;
    } else {
        l4[0] = 0x12;
        l4[1] = 0x34;
        l4[2] = 0x56;
        l4[3] = 0x78;
        l4[4] = (uint8_t)((8 + s->payload) >> 8);
        l4[5] = (uint8_t)(8 + s->payload);
    }
    for (size_t i = 0; i < s->payload; i++)
        l4[l4hlen + i] = (uint8_t)(i * 31 + 7);

    *ip_hlen_out = ip_hlen;
    return total;
}

static struct virtio_net_hdr
vnet(const spec_t *s, size_t ip_hlen, uint16_t gso_size)
{
    struct virtio_net_hdr h;
    memset(&h, 0, sizeof(h));
    h.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    h.csum_start = (uint16_t)ip_hlen;
    h.csum_offset = s->proto == IPPROTO_TCP ? 16 : 6;
    if (gso_size) {
        h.gso_size = gso_size;
        h.gso_type = s->proto == IPPROTO_UDP ? VIRTIO_NET_HDR_GSO_UDP_L4
                     : s->v6                 ? VIRTIO_NET_HDR_GSO_TCPV6
                                             : VIRTIO_NET_HDR_GSO_TCPV4;
    }
    return h;
}

/* ---- checks ---- */

/* Split pkt and verify every segment against the super-packet. */
static void
check_split(const spec_t *s, uint16_t gso_size)
{
    uint8_t pkt[SEG_CAP];
    size_t ip_hlen;
    size_t total = build(pkt, s, &ip_hlen);
    size_t l4hlen = s->proto == IPPROTO_TCP ? 20 : 8;
    size_t hdr_len = ip_hlen + l4hlen;
    struct virtio_net_hdr vh = vnet(s, ip_hlen, gso_size);

    uint8_t orig[SEG_CAP];
    memcpy(orig, pkt, total);

    mqvpn_gso_iter_t it;
    assert(mqvpn_gso_begin(&it, pkt, total, &vh) == 0);

    uint8_t seg[SEG_CAP];
    size_t got = 0;
    unsigned nseg = 0;
    int n;
    while ((n = mqvpn_gso_next(&it, seg, sizeof(seg))) > 0) {
        size_t len = (size_t)n;
        size_t pay = len - hdr_len;
        int last = got + pay == s->payload;
        assert(len > hdr_len || s->payload == 0);
        assert(pay <= gso_size);
        if (!last) assert(pay == gso_size);

        /* IP header */
        if (s->v6) {
            assert(seg[0] >> 4 == 6);
            assert(((seg[4] << 8) | seg[5]) == (int)(len - 40));
        } else {
            assert(seg[0] == pkt[0]);
            assert(((seg[2] << 8) | seg[3]) == (int)len);
            assert(((seg[4] << 8) | seg[5]) == (uint16_t)(s->id + nseg));
            assert(ref_fold(ref_sum(seg, ip_hlen, 0)) == 0xffff); /* IP checksum */
        }
        /* Rest of the headers unchanged except the fields the splitter owns */
        assert(memcmp(seg + 6, pkt + 6, s->v6 ? 2 : 0) == 0);

        const uint8_t *l4 = seg + ip_hlen;
        assert(ref_l4_sum(seg, s->v6, (uint8_t)s->proto, l4, len - ip_hlen) == 0xffff);
        if (s->proto == IPPROTO_TCP) {
            uint32_t seq;
            memcpy(&seq, l4 + 4, 4);
            assert(ntohl(seq) == s->seq + (uint32_t)got);
            uint8_t want = s->tcp_flags;
            if (!last) want &= (uint8_t) ~(0x01 | 0x08);
            if (nseg) want &= (uint8_t)~0x80;
            assert(l4[13] == want);
            assert(memcmp(l4 + 8, orig + ip_hlen + 8, 5) == 0);   /* ack, offset */
            assert(memcmp(l4 + 14, orig + ip_hlen + 14, 2) == 0); /* window */
        } else {
            assert(((l4[4] << 8) | l4[5]) == (int)(len - ip_hlen));
        }
        /* Payload */
        assert(memcmp(seg + hdr_len, orig + hdr_len + got, pay) == 0);
        got += pay;
        nseg++;
    }
    assert(n == 0);
    assert(got == s->payload);
    size_t want_segs = s->payload ? (s->payload + gso_size - 1) / gso_size : 1;
    assert(nseg == want_segs);
    /* The super-packet itself is untouched */
    assert(memcmp(pkt, orig, total) == 0);
    /* An exhausted iterator stays exhausted */
    assert(mqvpn_gso_next(&it, seg, sizeof(seg)) == 0);
}

static void
test_split_matrix(void)
{
    static const size_t payloads[] = {1,    2,    99,   100,   101,   999,   1000,
                                      1001, 2000, 2001, 14600, 14601, 30001, 60000};
    static const uint16_t sizes[] = {1, 7, 100, 536, 1000, 1360, 1460, 8960};
    unsigned cases = 0;

    for (int v6 = 0; v6 < 2; v6++)
        for (int proto = 0; proto < 2; proto++)
            for (int ext = 0; ext < (v6 ? 2 : 1); ext++)
                for (int opts = 0; opts < (v6 ? 1 : 2); opts++)
                    for (size_t pi = 0; pi < sizeof(payloads) / sizeof(*payloads); pi++)
                        for (size_t gi = 0; gi < sizeof(sizes) / sizeof(*sizes); gi++) {
                            spec_t s = {.v6 = v6,
                                        .proto = proto ? IPPROTO_TCP : IPPROTO_UDP,
                                        .ext = ext * 8,
                                        .ip_opts = opts * 8,
                                        .payload = payloads[pi],
                                        .tcp_flags = 0x80 | 0x10 | 0x08 | 0x01,
                                        .seq = 0xfffff000u, /* wraps within the packet */
                                        .id = 0xfff0};      /* ID wraps too */
                            /* skip silly counts that would only slow the run */
                            if (s.payload / sizes[gi] > 4000) continue;
                            check_split(&s, sizes[gi]);
                            cases++;
                        }
    printf("  split matrix: %u cases\n", cases);
}

static void
test_split_random(void)
{
    srand(12345);
    for (int i = 0; i < 3000; i++) {
        spec_t s = {.v6 = rand() & 1,
                    .proto = (rand() & 1) ? IPPROTO_TCP : IPPROTO_UDP,
                    .payload = (size_t)(rand() % 60000) + 1,
                    .tcp_flags = (uint8_t)rand(),
                    .seq = (uint32_t)rand() * 2654435761u,
                    .id = (uint16_t)rand()};
        s.tcp_flags &= (uint8_t) ~(0x02 | 0x04); /* no SYN/RST in a TSO packet */
        uint16_t gso = (uint16_t)(rand() % 3000 + 1);
        if (s.payload / gso > 4000) continue;
        check_split(&s, gso);
    }
}

/* Leave the checksum field the way the kernel does for a partial checksum:
 * the pseudo-header sum, not complemented. */
static void
set_partial(uint8_t *pkt, const spec_t *s, size_t ip_hlen, size_t total,
            const struct virtio_net_hdr *vh)
{
    uint8_t tail[4] = {0, (uint8_t)s->proto, (uint8_t)((total - ip_hlen) >> 8),
                       (uint8_t)(total - ip_hlen)};
    uint32_t ph = s->v6 ? ref_sum(pkt + 8, 32, 0) : ref_sum(pkt + 12, 8, 0);
    ph = ref_fold(ref_sum(tail, 4, ph));
    size_t at = ip_hlen + vh->csum_offset;
    pkt[at] = (uint8_t)(ph >> 8);
    pkt[at + 1] = (uint8_t)ph;
}

/* Non-GSO packet with a partial checksum: the finished packet verifies. */
static void
check_finish(const spec_t *s)
{
    uint8_t pkt[SEG_CAP];
    size_t ip_hlen;
    size_t total = build(pkt, s, &ip_hlen);
    struct virtio_net_hdr vh = vnet(s, ip_hlen, 0);

    set_partial(pkt, s, ip_hlen, total, &vh);
    assert(mqvpn_vnet_finish_csum(pkt, total, &vh) == 0);
    assert(ref_l4_sum(pkt, s->v6, (uint8_t)s->proto, pkt + ip_hlen, total - ip_hlen) ==
           0xffff);
}

/* Every NEEDS_CSUM packet that is not GSO (any CHECKSUM_PARTIAL skb gets the
 * flag from the kernel, whatever offloads were requested, e.g. forwarded
 * fraglist GRO chains) must come out with a complete checksum: IPv4 and IPv6,
 * TCP and UDP, even and odd lengths, empty payload included. */
static void
test_finish_csum(void)
{
    static const size_t payloads[] = {0, 1, 2, 3, 17, 512, 1399, 1400, 9000};
    for (int v6 = 0; v6 < 2; v6++)
        for (int proto = 0; proto < 2; proto++)
            for (size_t pi = 0; pi < sizeof(payloads) / sizeof(*payloads); pi++) {
                spec_t s = {.v6 = v6,
                            .proto = proto ? IPPROTO_TCP : IPPROTO_UDP,
                            .payload = payloads[pi],
                            .tcp_flags = 0x10};
                check_finish(&s);
            }
}

/* A UDP checksum that computes to zero must go out as 0xffff. */
static void
test_udp_zero_checksum(void)
{
    for (int v6 = 0; v6 < 2; v6++) {
        spec_t s = {.v6 = v6, .proto = IPPROTO_UDP, .payload = 20};
        uint8_t pkt[256];
        size_t ip_hlen;
        size_t total = build(pkt, &s, &ip_hlen);
        struct virtio_net_hdr vh = vnet(&s, ip_hlen, 0);
        size_t at = ip_hlen + 6;
        size_t w = total - 2; /* last payload word: the knob */
        int found = 0;
        for (uint32_t v = 0; v < 0x10000; v++) {
            pkt[w] = (uint8_t)(v >> 8);
            pkt[w + 1] = (uint8_t)v;
            set_partial(pkt, &s, ip_hlen, total, &vh);
            /* the sum over the packet with the partial value in place is the
             * complement of the checksum we are about to store */
            uint16_t sum = ref_fold(ref_sum(pkt + ip_hlen, total - ip_hlen, 0));
            if (sum == 0xffff) {
                found = 1;
                break;
            }
        }
        assert(found);
        assert(mqvpn_vnet_finish_csum(pkt, total, &vh) == 0);
        assert(pkt[at] == 0xff && pkt[at + 1] == 0xff);
    }
}

static void
test_malformed(void)
{
    spec_t s = {.v6 = 0, .proto = IPPROTO_TCP, .payload = 3000, .tcp_flags = 0x10};
    uint8_t pkt[SEG_CAP];
    size_t ip_hlen;
    size_t total = build(pkt, &s, &ip_hlen);
    mqvpn_gso_iter_t it;

    struct virtio_net_hdr ok = vnet(&s, ip_hlen, 1000);
    assert(mqvpn_gso_begin(&it, pkt, total, &ok) == 0);

    struct virtio_net_hdr h = ok;
    h.gso_size = 0;
    assert(mqvpn_gso_begin(&it, pkt, total, &h) == -1);
    h = ok;
    h.gso_type = VIRTIO_NET_HDR_GSO_TCPV6; /* family disagrees with the packet */
    assert(mqvpn_gso_begin(&it, pkt, total, &h) == -1);
    h = ok;
    h.gso_type = 7;
    assert(mqvpn_gso_begin(&it, pkt, total, &h) == -1);
    h = ok;
    h.csum_start = 24; /* not the IP header length */
    assert(mqvpn_gso_begin(&it, pkt, total, &h) == -1);
    h = ok;
    h.csum_offset = 6; /* a UDP offset on a TCP packet */
    assert(mqvpn_gso_begin(&it, pkt, total, &h) == -1);
    assert(mqvpn_gso_begin(&it, pkt, 30, &ok) == -1); /* cut inside the TCP header */
    assert(mqvpn_gso_begin(&it, pkt, 10, &ok) == -1);
    pkt[ip_hlen + 12] = 4 << 4; /* TCP header shorter than 20 */
    assert(mqvpn_gso_begin(&it, pkt, total, &ok) == -1);
    pkt[ip_hlen + 12] = 15 << 4; /* TCP header longer than the packet allows? 60 */
    assert(mqvpn_gso_begin(&it, pkt, ip_hlen + 40, &ok) == -1);
    pkt[ip_hlen + 12] = 5 << 4;

    /* output buffer too small */
    uint8_t seg[1030];
    assert(mqvpn_gso_begin(&it, pkt, total, &ok) == 0);
    assert(mqvpn_gso_next(&it, seg, sizeof(seg)) == -1);

    /* checksum field out of range */
    struct virtio_net_hdr c = vnet(&s, ip_hlen, 0);
    c.csum_start = (uint16_t)total;
    assert(mqvpn_vnet_finish_csum(pkt, total, &c) == -1);
    c = vnet(&s, ip_hlen, 0);
    c.csum_offset = (uint16_t)(total - ip_hlen - 1);
    assert(mqvpn_vnet_finish_csum(pkt, total, &c) == -1);

    /* USO: IPv4 and IPv6 share one gso_type, the packet decides */
    spec_t u = {.v6 = 1, .proto = IPPROTO_UDP, .payload = 3000};
    total = build(pkt, &u, &ip_hlen);
    struct virtio_net_hdr uh = vnet(&u, ip_hlen, 1000);
    assert(mqvpn_gso_begin(&it, pkt, total, &uh) == 0);
    assert(it.v6 == 1);
    /* ECN bit on the type is tolerated */
    struct virtio_net_hdr e = vnet(&s, 20, 1000);
    e.gso_type |= VIRTIO_NET_HDR_GSO_ECN;
    total = build(pkt, &s, &ip_hlen);
    assert(mqvpn_gso_begin(&it, pkt, total, &e) == 0);
}


int
main(void)
{
    test_split_matrix();
    test_split_random();
    test_finish_csum();
    test_udp_zero_checksum();
    test_malformed();
    printf("test_tun_offload: OK\n");
    return 0;
}
