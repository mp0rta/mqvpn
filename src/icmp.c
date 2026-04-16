#include "icmp.h"

#include <stdint.h>
#include <string.h>

/* ─── Checksum helpers ─── */

static uint16_t
ipv4_checksum(const uint8_t *hdr, size_t len)
{
    uint32_t cksum = 0;
    for (size_t i = 0; i < len; i += 2)
        cksum += ((uint32_t)hdr[i] << 8) | hdr[i + 1];
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    return ~(uint16_t)cksum;
}

static uint16_t
icmpv6_checksum(const uint8_t *src6, const uint8_t *dst6, const uint8_t *icmp,
                size_t icmpv6_len)
{
    uint32_t cksum = 0;

    /* Pseudo-header: src (16), dst (16), length (4), next-hdr=58 (4) */
    for (int i = 0; i < 16; i += 2)
        cksum += ((uint32_t)src6[i] << 8) | src6[i + 1];
    for (int i = 0; i < 16; i += 2)
        cksum += ((uint32_t)dst6[i] << 8) | dst6[i + 1];
    cksum += (uint32_t)(icmpv6_len >> 16);
    cksum += (uint32_t)(icmpv6_len & 0xFFFF);
    cksum += 58; /* next header = ICMPv6 */

    /* ICMPv6 payload */
    for (size_t i = 0; i < icmpv6_len; i += 2) {
        cksum += ((uint32_t)icmp[i] << 8);
        if (i + 1 < icmpv6_len) cksum += icmp[i + 1];
    }

    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    return ~(uint16_t)cksum;
}

/* ─── Public API ─── */

void
mqvpn_icmp_send_v4(mqvpn_tun_output_fn cb, void *ctx, const uint8_t *src_ip, uint8_t type,
                   uint8_t code, uint16_t mtu, const uint8_t *orig, size_t orig_len)
{
    if (!cb || !src_ip || !orig) return;
    if (orig_len < IPV4_MIN_HDR) return;

    size_t ihl = (size_t)(orig[0] & 0x0F) * 4;
    if (ihl < IPV4_MIN_HDR || ihl > orig_len) return;

    size_t icmp_data_len = ihl + 8;
    if (icmp_data_len > orig_len) icmp_data_len = orig_len;

    size_t total = IPV4_MIN_HDR + 8 + icmp_data_len;
    uint8_t pkt[128];
    if (total > sizeof(pkt)) return;

    memset(pkt, 0, total);

    /* IPv4 header */
    pkt[0] = 0x45;
    pkt[1] = 0xC0;
    pkt[2] = (total >> 8) & 0xFF;
    pkt[3] = total & 0xFF;
    pkt[8] = MQVPN_ICMP_TTL;
    pkt[9] = 1; /* protocol = ICMP */
    memcpy(pkt + 12, src_ip, 4);
    memcpy(pkt + 16, orig + 12, 4);

    uint16_t ip_ck = ipv4_checksum(pkt, IPV4_MIN_HDR);
    pkt[10] = ip_ck >> 8;
    pkt[11] = ip_ck & 0xFF;

    /* ICMP header + data */
    uint8_t *icmp = pkt + IPV4_MIN_HDR;
    icmp[0] = type;
    icmp[1] = code;
    /* bytes 4-5 unused (zero); bytes 6-7 = MTU for PTB, zero otherwise */
    icmp[6] = mtu >> 8;
    icmp[7] = mtu & 0xFF;
    memcpy(icmp + 8, orig, icmp_data_len);

    size_t icmp_total = 8 + icmp_data_len;
    uint32_t cksum = 0;
    for (size_t i = 0; i < icmp_total; i += 2) {
        cksum += ((uint32_t)icmp[i] << 8);
        if (i + 1 < icmp_total) cksum += icmp[i + 1];
    }
    while (cksum >> 16)
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    uint16_t ic = ~(uint16_t)cksum;
    icmp[2] = ic >> 8;
    icmp[3] = ic & 0xFF;

    cb(pkt, total, ctx);
}

void
mqvpn_icmp_send_v6(mqvpn_tun_output_fn cb, void *ctx, const uint8_t *src_ip6,
                   uint8_t type, uint8_t code, uint32_t mtu, const uint8_t *orig,
                   size_t orig_len)
{
    if (!cb || !src_ip6 || !orig) return;
    if (orig_len < IPV6_MIN_HDR) return;

    size_t icmpv6_data_len = orig_len;
    if (IPV6_MIN_HDR + 8 + icmpv6_data_len > IPV6_MIN_MTU)
        icmpv6_data_len = IPV6_MIN_MTU - IPV6_MIN_HDR - 8;

    size_t icmpv6_len = 8 + icmpv6_data_len;
    size_t total = IPV6_MIN_HDR + icmpv6_len;

    uint8_t pkt[IPV6_MIN_MTU];
    memset(pkt, 0, total);

    /* IPv6 header */
    pkt[0] = 0x60;
    pkt[4] = (icmpv6_len >> 8) & 0xFF;
    pkt[5] = icmpv6_len & 0xFF;
    pkt[6] = 58; /* next header = ICMPv6 */
    pkt[7] = MQVPN_ICMP_TTL;
    memcpy(pkt + 8, src_ip6, 16);
    memcpy(pkt + 24, orig + 8, 16);

    /* ICMPv6 header + data */
    uint8_t *icmp = pkt + IPV6_MIN_HDR;
    icmp[0] = type;
    icmp[1] = code;
    /* bytes 4-7 = MTU for PTB (type=2), zero for others */
    icmp[4] = (mtu >> 24) & 0xFF;
    icmp[5] = (mtu >> 16) & 0xFF;
    icmp[6] = (mtu >> 8) & 0xFF;
    icmp[7] = mtu & 0xFF;
    memcpy(icmp + 8, orig, icmpv6_data_len);

    uint16_t ic = icmpv6_checksum(pkt + 8, pkt + 24, icmp, icmpv6_len);
    icmp[2] = ic >> 8;
    icmp[3] = ic & 0xFF;

    cb(pkt, total, ctx);
}
