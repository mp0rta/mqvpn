/*
 * flow_sched.c
 *
 * IPv4 5-tuple flow hash for xquic flow-affinity hint
 * (xqc_conn_set_dgram_flow_hash).
 */
#include "flow_sched.h"

uint32_t
flow_hash_pkt(const uint8_t *pkt, int len)
{
    if (len < 20 || (pkt[0] >> 4) != 4) {
        return 0;
    }

    uint8_t proto = pkt[9];

    /* Only TCP needs flow pinning (reordering breaks inner TCP).
     * UDP/QUIC handle reordering themselves → unpinned WRR. */
    if (proto != 6) {
        return MQVPN_FLOW_HASH_UNPINNED;
    }

    int ihl = (pkt[0] & 0x0f) * 4;

    /* src_ip (12..15), dst_ip (16..19), protocol, and TCP ports */
    uint32_t h = 2166136261u;

    for (int i = 12; i < 20; i++) {
        h = (h ^ pkt[i]) * 16777619u;
    }

    h = (h ^ proto) * 16777619u;

    if (len >= ihl + 4) {
        for (int i = ihl; i < ihl + 4; i++) {
            h = (h ^ pkt[i]) * 16777619u;
        }
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
}
