// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#include "classifier.h"

mqvpn_hybrid_lane_t
mqvpn_hybrid_classify(const uint8_t *pkt, size_t len, const mqvpn_hybrid_config_t *pol,
                      mqvpn_flow_key_t *out_key)
{
    mqvpn_flow_key_t local;
    mqvpn_flow_key_t *key = out_key ? out_key : &local;

    switch (mqvpn_parse_l3l4(pkt, len, key)) {
    case MQVPN_L4_UDP: return MQVPN_LANE_DGRAM;
    case MQVPN_L4_TCP:
        if (key->ip_version != 4) return MQVPN_LANE_RAW; /* v1: IPv6 TCP → RAW */
        if (!pol || !pol->enabled || pol->tcp_mode == MQVPN_HYBRID_TCP_RAW)
            return MQVPN_LANE_RAW;
        /* Tunnel-subnet destinations stay RAW: the server-side connect-tcp
         * egress ACL rejects the tunnel subnet unconditionally (its check
         * precedes EgressAllow — svr_tcp_egress_acl_decide), so laning
         * such a flow guarantees a RESET where RAW keeps intra-VPN TCP
         * working exactly as with hybrid off. mask == 0 = subnet not
         * learned (or not a client) — gate off. */
        if (pol->client_tunnel_subnet.mask != 0) {
            uint32_t dst = ((uint32_t)key->dst_ip[0] << 24) |
                           ((uint32_t)key->dst_ip[1] << 16) |
                           ((uint32_t)key->dst_ip[2] << 8) | (uint32_t)key->dst_ip[3];
            if ((dst & pol->client_tunnel_subnet.mask) == pol->client_tunnel_subnet.net)
                return MQVPN_LANE_RAW;
        }
        return MQVPN_LANE_TCP;
    case MQVPN_L4_FRAGMENT:
    case MQVPN_L4_OTHER:
    case MQVPN_L4_MALFORMED:
    default: return MQVPN_LANE_RAW;
    }
}
