// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * flow_sched.c
 *
 * IPv4/IPv6 5-tuple flow hash for xquic flow-affinity hint
 * (xqc_conn_set_dgram_flow_hash).
 */
#include "flow_sched.h"

#define FNV1A_OFFSET 2166136261u
#define FNV1A_PRIME  16777619u

static uint32_t
flow_hash_update_byte(uint32_t h, uint8_t b)
{
    return (h ^ b) * FNV1A_PRIME;
}

static uint32_t
flow_hash_finish(uint32_t h)
{
    /* 0 means "no hash" in xquic's WLB flow table (empty-slot sentinel). */
    if (h == 0) {
        h = 1;
    }
    /* Avoid collision with the unpinned sentinel. */
    if (h == MQVPN_FLOW_HASH_UNPINNED) {
        h = MQVPN_FLOW_HASH_UNPINNED - 1;
    }
    return h;
}

uint32_t
flow_hash_pkt(const uint8_t *pkt, int len, bool udp_pin)
{
    if (!pkt || len < 1) {
        return 0;
    }

    uint8_t version = pkt[0] >> 4;

    if (version == 4) {
        /* === IPv4 === */
        if (len < 20) return 0;

        uint8_t proto = pkt[9];
        int ihl = (pkt[0] & 0x0f) * 4;

        if (ihl < 20 || ihl > len) {
            return 0;
        }

        uint16_t frag = ((uint16_t)pkt[6] << 8) | pkt[7];
        bool is_fragmented = (frag & 0x3fff) != 0;

        /* TCP always pinned (reordering breaks inner TCP).
         * UDP pinned only when udp_pin=true (wlb_udp_pin scheduler).
         * Other (ICMP, etc.) → unpinned WRR. */
        bool should_pin = (proto == 6) || (proto == 17 && udp_pin);
        if (!should_pin) {
            return MQVPN_FLOW_HASH_UNPINNED;
        }

        uint32_t h = FNV1A_OFFSET;

        for (int i = 12; i < 20; i++) {
            h = flow_hash_update_byte(h, pkt[i]);
        }
        h = flow_hash_update_byte(h, proto);

        if (is_fragmented) {
            /* Non-first IPv4 fragments do not carry TCP/UDP ports. Pin all
             * fragments from the same original datagram by the fields IPv4
             * reassembly also keys on: src/dst IP, protocol, Identification. */
            h = flow_hash_update_byte(h, pkt[4]);
            h = flow_hash_update_byte(h, pkt[5]);
            return flow_hash_finish(h);
        }

        if (len < ihl + 4) {
            return MQVPN_FLOW_HASH_UNPINNED;
        }

        /* TCP/UDP source and destination ports. */
        for (int i = ihl; i < ihl + 4; i++) {
            h = flow_hash_update_byte(h, pkt[i]);
        }

        return flow_hash_finish(h);

    } else if (version == 6) {
        /* === IPv6 === */
        if (len < 40) return 0;

        /* Extension-header walking is intentionally out of scope for now.
         * Only packets whose IPv6 base header points directly at TCP or UDP
         * are eligible for flow pinning. */
        uint8_t next_hdr = pkt[6];

        /* TCP always pinned; UDP pinned only when udp_pin=true. */
        bool should_pin = (next_hdr == 6) || (next_hdr == 17 && udp_pin);
        if (!should_pin) {
            return MQVPN_FLOW_HASH_UNPINNED;
        }
        if (len < 44) {
            return MQVPN_FLOW_HASH_UNPINNED;
        }

        /* src IP (8..23) + dst IP (24..39) + next_hdr + TCP ports (40..43) */
        uint32_t h = FNV1A_OFFSET;

        for (int i = 8; i < 40; i++) {
            h = flow_hash_update_byte(h, pkt[i]);
        }

        h = flow_hash_update_byte(h, next_hdr);

        for (int i = 40; i < 44; i++) {
            h = flow_hash_update_byte(h, pkt[i]);
        }

        return flow_hash_finish(h);
    }

    return 0; /* Unknown IP version */
}
