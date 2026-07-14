// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#include "classifier.h"

/* addr[0..9] all zero and addr[10..11] == 0xff,0xff: the ::ffff:0:0/96
 * v4-mapped range (RFC 4291 §2.5.5.2). */
static int
is_v4mapped(const uint8_t addr[16])
{
    for (int i = 0; i < 10; i++) {
        if (addr[i] != 0) return 0;
    }
    return addr[10] == 0xff && addr[11] == 0xff;
}

static int
is_all_zero(const uint8_t addr[16])
{
    for (int i = 0; i < 16; i++) {
        if (addr[i] != 0) return 0;
    }
    return 1;
}

/* v6 TCP address classes lwIP pre-accept-drops before a PENDING_ACCEPT slot
 * is ever created (spec §3.C rev7/rev8): v4-mapped src/dst (::ffff:0:0/96,
 * not a real dual-stack address on the wire here), a multicast src or dst
 * (first octet 0xff — TCP has no valid multicast use), and an unspecified
 * (::) source. Laning any of these would only ever fail inside lwIP, so
 * they're routed RAW instead — each maps to a concrete lwIP drop site cited
 * in the design spec. */
static int
v6_lane_ineligible(const mqvpn_flow_key_t *key)
{
    return is_v4mapped(key->dst_ip) || is_v4mapped(key->src_ip) ||
           key->src_ip[0] == 0xff || key->dst_ip[0] == 0xff || is_all_zero(key->src_ip);
}

mqvpn_hybrid_lane_t
mqvpn_hybrid_classify(const uint8_t *pkt, size_t len, const mqvpn_hybrid_config_t *pol,
                      mqvpn_flow_key_t *out_key)
{
    mqvpn_flow_key_t local;
    mqvpn_flow_key_t *key = out_key ? out_key : &local;

    switch (mqvpn_parse_l3l4(pkt, len, key)) {
    case MQVPN_L4_UDP: return MQVPN_LANE_DGRAM;
    case MQVPN_L4_TCP:
        if (!pol || !pol->enabled || pol->tcp_mode == MQVPN_HYBRID_TCP_RAW)
            return MQVPN_LANE_RAW;
        /* mqvpn_parse_l3l4 walks the v6 extension-header chain to reach
         * TCP, so an MQVPN_L4_TCP verdict does not imply the packet's BASE
         * Next Header (pkt offset 6) is TCP — an ext-header-then-TCP packet
         * still verdicts TCP. lwIP's netif input only special-cases a
         * handful of base-NH values, so anything else is pre-accept-
         * dropped rather than delivered to the stream lane; route it RAW
         * instead. Reading pkt[6] needs no separate length guard here:
         * reaching this branch already required mqvpn_parse_l3l4's v6
         * fixed-header check (len >= 40). */
        if (key->ip_version == 6 && pkt[6] != MQVPN_IPPROTO_TCP) return MQVPN_LANE_RAW;
        /* Address classes lwIP would pre-accept-drop before the stream lane
         * ever sees a PENDING_ACCEPT slot — see v6_lane_ineligible above. */
        if (key->ip_version == 6 && v6_lane_ineligible(key)) return MQVPN_LANE_RAW;
        /* Tunnel-subnet destinations stay RAW: the server-side connect-tcp
         * egress ACL rejects the tunnel subnet unconditionally (its check
         * precedes EgressAllow — svr_tcp_egress_acl_decide), so laning
         * such a flow guarantees a RESET where RAW keeps intra-VPN TCP
         * working exactly as with hybrid off. dst_ip is already network-
         * order bytes (same layout mqvpn_cidr_match expects), and an unset
         * subnet (family == 0 — not learned, or not a client) always
         * misses, so no separate gate is needed here. Matched against
         * whichever family this flow is: index 0 is the v4 entry, index 1
         * the v6 entry (mqvpn_hybrid_config_t.client_tunnel_subnet's
         * docstring). */
        if (mqvpn_cidr_match(&pol->client_tunnel_subnet[key->ip_version == 6 ? 1 : 0],
                             key->ip_version, key->dst_ip))
            return MQVPN_LANE_RAW;
        return MQVPN_LANE_TCP;
    case MQVPN_L4_FRAGMENT:
    case MQVPN_L4_OTHER:
    case MQVPN_L4_MALFORMED:
    default: return MQVPN_LANE_RAW;
    }
}
