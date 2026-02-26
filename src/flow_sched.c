/*
 * flow_sched.c
 *
 * IPv4/IPv6 5-tuple flow hash for xquic flow-affinity hint
 * (xqc_conn_set_dgram_flow_hash).
 */
#include "flow_sched.h"

uint32_t
flow_hash_pkt(const uint8_t *pkt, int len)
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

        /* Only TCP needs flow pinning (reordering breaks inner TCP).
         * UDP/QUIC handle reordering themselves → unpinned WRR. */
        if (proto != 6) {
            return MQVPN_FLOW_HASH_UNPINNED;
        }
        if (len < ihl + 4) {
            return MQVPN_FLOW_HASH_UNPINNED;
        }

        /* src_ip (12..19), protocol, and TCP ports */
        uint32_t h = 2166136261u;

        for (int i = 12; i < 20; i++) {
            h = (h ^ pkt[i]) * 16777619u;
        }

        h = (h ^ proto) * 16777619u;

        for (int i = ihl; i < ihl + 4; i++) {
            h = (h ^ pkt[i]) * 16777619u;
        }

        /* 0 means "no hash" in xquic's WLB flow table (empty-slot sentinel). */
        if (h == 0) {
            h = 1;
        }
        /* Avoid collision with the unpinned sentinel. */
        if (h == MQVPN_FLOW_HASH_UNPINNED) {
            h = MQVPN_FLOW_HASH_UNPINNED - 1;
        }
        return h;

    } else if (version == 6) {
        /* === IPv6 === */
        if (len < 40) return 0;

        uint8_t next_hdr = pkt[6];

        /* Only TCP needs flow pinning */
        if (next_hdr != 6) {
            return MQVPN_FLOW_HASH_UNPINNED;
        }
        if (len < 44) {
            return MQVPN_FLOW_HASH_UNPINNED;
        }

        /* src IP (8..23) + dst IP (24..39) + next_hdr + TCP ports (40..43) */
        uint32_t h = 2166136261u;

        for (int i = 8; i < 40; i++) {
            h = (h ^ pkt[i]) * 16777619u;
        }

        h = (h ^ next_hdr) * 16777619u;

        for (int i = 40; i < 44; i++) {
            h = (h ^ pkt[i]) * 16777619u;
        }

        if (h == 0) {
            h = 1;
        }
        if (h == MQVPN_FLOW_HASH_UNPINNED) {
            h = MQVPN_FLOW_HASH_UNPINNED - 1;
        }
        return h;
    }

    return 0;  /* Unknown IP version */
}
