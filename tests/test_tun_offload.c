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


/* ---- GRO ---- */

typedef struct {
    struct virtio_net_hdr vh;
    size_t len;
    uint8_t pkt[SEG_CAP];
} emitted_t;

static emitted_t out_q[512];
static unsigned out_n;

static int
capture(void *ctx, const struct virtio_net_hdr *vh, const uint8_t *pkt, size_t len)
{
    (void)ctx;
    assert(out_n < 512);
    out_q[out_n].vh = *vh;
    out_q[out_n].len = len;
    memcpy(out_q[out_n].pkt, pkt, len);
    out_n++;
    return 0;
}

/* A fully valid TCP data packet: checksums, sequential IP ID. */
static size_t
mk_tcp(uint8_t *p, int v6, uint32_t seq, size_t payload, uint8_t flags, uint16_t id,
       uint16_t sport, uint16_t ack_lo)
{
    spec_t s = {.v6 = v6,
                .proto = IPPROTO_TCP,
                .payload = payload,
                .tcp_flags = flags,
                .seq = seq,
                .id = id};
    size_t ip_hlen;
    size_t total = build(p, &s, &ip_hlen);
    uint8_t *l4 = p + ip_hlen;
    l4[0] = (uint8_t)(sport >> 8);
    l4[1] = (uint8_t)sport;
    l4[10] = 0;
    l4[11] = 0;
    l4[8] = 0;
    l4[9] = 0;
    l4[10] = (uint8_t)(ack_lo >> 8);
    l4[11] = (uint8_t)ack_lo;
    if (!v6) {
        p[10] = p[11] = 0;
        uint16_t c = (uint16_t)~ref_fold(ref_sum(p, ip_hlen, 0));
        p[10] = (uint8_t)(c >> 8);
        p[11] = (uint8_t)c;
    }
    l4[16] = l4[17] = 0;
    uint16_t c = (uint16_t)~ref_l4_sum(p, v6, IPPROTO_TCP, l4, total - ip_hlen);
    l4[16] = (uint8_t)(c >> 8);
    l4[17] = (uint8_t)c;
    return total;
}

/* Expand everything captured into plain packets (re-segmenting supers) and
 * verify each is a valid packet; returns them in order. */
static unsigned
expand(uint8_t (*pk)[2048], size_t *lens, unsigned max)
{
    unsigned n = 0;
    for (unsigned i = 0; i < out_n; i++) {
        emitted_t *e = &out_q[i];
        if ((e->vh.gso_type & ~VIRTIO_NET_HDR_GSO_ECN) == VIRTIO_NET_HDR_GSO_NONE) {
            assert(e->vh.flags == 0 && n < max && e->len <= 2048);
            memcpy(pk[n], e->pkt, e->len);
            lens[n++] = e->len;
            continue;
        }
        assert(e->vh.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM);
        assert(e->vh.csum_offset == 16 && e->len <= 65535);
        int v6 = e->vh.gso_type == VIRTIO_NET_HDR_GSO_TCPV6;
        assert(e->vh.csum_start == (v6 ? 40 : 20));
        assert(e->vh.hdr_len == e->vh.csum_start + 20);
        /* The kernel finishes the checksum from the pseudo-header sum left in
         * the field: do that, then split with our own splitter. */
        uint8_t tmp[SEG_CAP];
        memcpy(tmp, e->pkt, e->len);
        assert(mqvpn_vnet_finish_csum(tmp, e->len, &e->vh) == 0);
        assert(ref_l4_sum(tmp, v6, IPPROTO_TCP, tmp + e->vh.csum_start,
                          e->len - e->vh.csum_start) == 0xffff);
        mqvpn_gso_iter_t it;
        assert(mqvpn_gso_begin(&it, e->pkt, e->len, &e->vh) == 0);
        int r;
        while ((r = mqvpn_gso_next(&it, pk[n], 2048)) > 0) {
            assert(n < max);
            lens[n++] = (size_t)r;
        }
        assert(r == 0);
    }
    return n;
}

static void
gro_run(int v6, unsigned npk, size_t mss, size_t last_len, int psh_last,
        unsigned *supers_out)
{
    static uint8_t in[200][2048];
    static size_t in_len[200];
    static uint8_t ex[600][2048];
    static size_t ex_len[600];
    mqvpn_gro_t *g = mqvpn_gro_new(capture, NULL);
    assert(g);
    out_n = 0;
    uint32_t seq = 0xffffff00u;
    for (unsigned i = 0; i < npk; i++) {
        size_t pay = (i == npk - 1) ? last_len : mss;
        uint8_t fl = 0x10 | ((i == npk - 1 && psh_last) ? 0x08 : 0);
        in_len[i] = mk_tcp(in[i], v6, seq, pay, fl, (uint16_t)(1000 + i), 5000, 0x1234);
        seq += (uint32_t)pay;
        mqvpn_gro_push(g, in[i], in_len[i]);
    }
    mqvpn_gro_flush(g);
    assert(!mqvpn_gro_pending(g));
    unsigned n = expand(ex, ex_len, 600);
    assert(n == npk);
    for (unsigned i = 0; i < n; i++) {
        assert(ex_len[i] == in_len[i]);
        assert(memcmp(ex[i], in[i], in_len[i]) == 0); /* byte-exact, IDs included */
    }
    if (supers_out) *supers_out = out_n;
    mqvpn_gro_free(g);
}

static void
test_gro_roundtrip(void)
{
    unsigned supers;
    for (int v6 = 0; v6 < 2; v6++) {
        gro_run(v6, 1, 1000, 1000, 0, &supers);
        assert(supers == 1 && out_q[0].vh.gso_type == 0);
        gro_run(v6, 2, 1000, 1000, 0, &supers);
        assert(supers == 1 && out_q[0].vh.gso_type != 0);
        gro_run(v6, 5, 1448, 300, 1, &supers);
        assert(supers == 1);
        gro_run(v6, 40, 1448, 1448, 1, &supers);
        assert(supers == 1);
        gro_run(v6, 100, 1448, 1, 0, &supers); /* > 64 KiB: several supers */
        assert(supers >= 2);
        for (unsigned i = 0; i < out_n; i++)
            assert(out_q[i].len <= 65535);
        gro_run(v6, 3, 7, 7, 0, &supers);
    }
}

/* Packets that must not merge keep their order and content. */
static void
test_gro_order(void)
{
    static uint8_t in[16][2048];
    static size_t in_len[16];
    static uint8_t ex[64][2048];
    static size_t ex_len[64];
    mqvpn_gro_t *g = mqvpn_gro_new(capture, NULL);

    for (int v6 = 0; v6 < 2; v6++) {
        out_n = 0;
        unsigned k = 0;
        uint32_t seq = 100;
        /* data, data, gap (lost segment), data, pure ACK, data, bigger than
         * the first, other ACK number, other flow, FIN */
        in_len[k] = mk_tcp(in[k], v6, seq, 1000, 0x10, 1, 5000, 1);
        seq += 1000;
        k++;
        in_len[k] = mk_tcp(in[k], v6, seq, 1000, 0x10, 2, 5000, 1);
        seq += 1000;
        k++;
        seq += 1000; /* gap */
        in_len[k] = mk_tcp(in[k], v6, seq, 1000, 0x10, 4, 5000, 1);
        seq += 1000;
        k++;
        in_len[k] = mk_tcp(in[k], v6, seq, 0, 0x10, 5, 5000, 1);
        k++; /* pure ACK */
        in_len[k] = mk_tcp(in[k], v6, seq, 1000, 0x10, 6, 5000, 1);
        seq += 1000;
        k++;
        in_len[k] = mk_tcp(in[k], v6, seq, 1200, 0x10, 7, 5000, 1);
        seq += 1200;
        k++;
        in_len[k] = mk_tcp(in[k], v6, seq, 500, 0x10, 8, 5000, 2);
        seq += 500;
        k++; /* ack differs */
        in_len[k] = mk_tcp(in[k], v6, 9000, 600, 0x10, 9, 6000, 1);
        k++; /* other flow */
        in_len[k] = mk_tcp(in[k], v6, 9600, 600, 0x10, 10, 6000, 1);
        k++;
        in_len[k] = mk_tcp(in[k], v6, seq, 10, 0x11, 11, 5000, 2);
        k++; /* FIN */
        for (unsigned i = 0; i < k; i++)
            mqvpn_gro_push(g, in[i], in_len[i]);
        mqvpn_gro_flush(g);
        unsigned n = expand(ex, ex_len, 64);
        /* Every input comes out exactly once, per flow in input order. */
        for (int flow = 0; flow < 2; flow++) {
            unsigned j = 0;
            for (unsigned i = 0; i < k; i++) {
                uint16_t sport =
                    (uint16_t)((in[i][(v6 ? 40 : 20)] << 8) | in[i][(v6 ? 41 : 21)]);
                if ((sport == 6000) != flow) continue;
                while (j < n) {
                    uint16_t sp2 =
                        (uint16_t)((ex[j][(v6 ? 40 : 20)] << 8) | ex[j][(v6 ? 41 : 21)]);
                    if ((sp2 == 6000) == flow) break;
                    j++;
                }
                assert(j < n && ex_len[j] == in_len[i] &&
                       memcmp(ex[j], in[i], in_len[i]) == 0);
                j++;
            }
        }
        assert(n == k);
    }
    mqvpn_gro_free(g);
}

/* A short segment ends its super-packet: what follows it never joins. */
static void
test_gro_short_closes(void)
{
    static uint8_t in[3][2048];
    size_t ln[3];
    mqvpn_gro_t *g = mqvpn_gro_new(capture, NULL);
    out_n = 0;
    ln[0] = mk_tcp(in[0], 0, 0, 1000, 0x10, 1, 5000, 0);
    ln[1] = mk_tcp(in[1], 0, 1000, 500, 0x10, 2, 5000, 0);
    ln[2] = mk_tcp(in[2], 0, 1500, 500, 0x10, 3, 5000, 0);
    for (int i = 0; i < 3; i++)
        mqvpn_gro_push(g, in[i], ln[i]);
    mqvpn_gro_flush(g);
    assert(out_n == 2);
    assert(out_q[0].vh.gso_type != 0 && out_q[0].vh.gso_size == 1000);
    assert(out_q[0].len == ln[0] + 500);
    assert(out_q[1].vh.gso_type == 0 && out_q[1].len == ln[2]);
    mqvpn_gro_free(g);
}

/* Non-TCP, options, fragments, SYN: passed through untouched. */
static void
test_gro_passthrough(void)
{
    mqvpn_gro_t *g = mqvpn_gro_new(capture, NULL);
    static uint8_t pk[8][2048];
    size_t ln[8], ip_hlen;
    unsigned k = 0;
    out_n = 0;

    spec_t u = {.v6 = 0, .proto = IPPROTO_UDP, .payload = 100};
    ln[k] = build(pk[k], &u, &ip_hlen);
    k++;
    spec_t u6 = {.v6 = 1, .proto = IPPROTO_UDP, .payload = 100};
    ln[k] = build(pk[k], &u6, &ip_hlen);
    k++;
    ln[k] = mk_tcp(pk[k], 0, 1, 100, 0x02, 1, 5000, 0);
    k++; /* SYN */
    spec_t o = {
        .v6 = 0, .proto = IPPROTO_TCP, .ip_opts = 8, .payload = 100, .tcp_flags = 0x10};
    ln[k] = build(pk[k], &o, &ip_hlen);
    k++; /* IP options */
    ln[k] = mk_tcp(pk[k], 0, 1, 100, 0x10, 1, 5000, 0);
    pk[k][6] = 0x20; /* more fragments */
    k++;
    ln[k] = 10;
    memset(pk[k], 0x45, 10);
    k++; /* runt */
    for (unsigned i = 0; i < k; i++)
        mqvpn_gro_push(g, pk[i], ln[i]);
    assert(!mqvpn_gro_pending(g));
    assert(out_n == k);
    for (unsigned i = 0; i < k; i++) {
        assert(out_q[i].vh.gso_type == 0 && out_q[i].vh.flags == 0);
        assert(out_q[i].len == ln[i] && memcmp(out_q[i].pkt, pk[i], ln[i]) == 0);
    }
    mqvpn_gro_free(g);
}

/* More flows than slots: nothing is lost or reordered within a flow. */
static void
test_gro_many_flows(void)
{
    static uint8_t in[40][2048];
    static size_t in_len[40];
    static uint8_t ex[100][2048];
    static size_t ex_len[100];
    mqvpn_gro_t *g = mqvpn_gro_new(capture, NULL);
    out_n = 0;
    unsigned k = 0;
    for (int round = 0; round < 4; round++)
        for (int f = 0; f < 10; f++) {
            in_len[k] = mk_tcp(in[k], 0, 1000 + round * 500, 500, 0x10, (uint16_t)k,
                               (uint16_t)(7000 + f), 0);
            mqvpn_gro_push(g, in[k], in_len[k]);
            k++;
        }
    mqvpn_gro_flush(g);
    unsigned n = expand(ex, ex_len, 100);
    assert(n == k);
    for (int f = 0; f < 10; f++) {
        unsigned j = 0, want = 0;
        for (unsigned i = 0; i < k; i++) {
            if ((i % 10) != (unsigned)f) continue;
            for (; j < n; j++) {
                uint16_t sp = (uint16_t)((ex[j][20] << 8) | ex[j][21]);
                if (sp == 7000 + f) break;
            }
            assert(j < n);
            uint32_t seq;
            memcpy(&seq, ex[j] + 24, 4);
            assert(ntohl(seq) == 1000 + want * 500);
            want++;
            j++;
        }
    }
    mqvpn_gro_free(g);
}

/* A segment with a reserved bit or AccECN's AE flag set (TCP byte 12) is
 * never merged: GRO would carry only the first segment's bits. */
static void
test_gro_reserved_bits(void)
{
    static uint8_t in[3][2048];
    size_t ln[3];
    mqvpn_gro_t *g = mqvpn_gro_new(capture, NULL);
    for (int v6 = 0; v6 < 2; v6++) {
        size_t th = v6 ? 40 : 20;
        out_n = 0;
        ln[0] = mk_tcp(in[0], v6, 0, 1000, 0x10, 1, 5000, 0);
        ln[1] = mk_tcp(in[1], v6, 1000, 1000, 0x10, 2, 5000, 0);
        in[1][th + 12] |= 0x01; /* AE; the checksum is not checked here */
        ln[2] = mk_tcp(in[2], v6, 2000, 1000, 0x10, 3, 5000, 0);
        for (int i = 0; i < 3; i++)
            mqvpn_gro_push(g, in[i], ln[i]);
        mqvpn_gro_flush(g);
        assert(out_n == 3);
        for (int i = 0; i < 3; i++)
            assert(out_q[i].vh.gso_type == 0 && out_q[i].len == ln[i] &&
                   memcmp(out_q[i].pkt, in[i], ln[i]) == 0);
    }
    mqvpn_gro_free(g);
}

int
main(void)
{
    test_split_matrix();
    test_split_random();
    test_finish_csum();
    test_udp_zero_checksum();
    test_malformed();
    test_gro_roundtrip();
    test_gro_order();
    test_gro_short_closes();
    test_gro_passthrough();
    test_gro_many_flows();
    test_gro_reserved_bits();
    printf("test_tun_offload: OK\n");
    return 0;
}
