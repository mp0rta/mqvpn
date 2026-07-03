// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* Hybrid-mode ingress classifier (H1). Pure functions only — no
 * allocation, no state, no lwIP types may leak out of src/hybrid/. */
#ifndef MQVPN_HYBRID_CLASSIFIER_H
#define MQVPN_HYBRID_CLASSIFIER_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "reorder.h" /* mqvpn_flow_key_t, mqvpn_parse_l3l4 */

typedef enum {
    MQVPN_LANE_TCP,   /* IPv4 TCP, hybrid enabled, tcp mode != raw */
    MQVPN_LANE_DGRAM, /* parseable UDP — reorder engine decides profile */
    MQVPN_LANE_RAW,   /* everything else — existing CONNECT-IP RAW */
} mqvpn_hybrid_lane_t;

typedef enum {
    MQVPN_HYBRID_TCP_STREAM = 0,
    MQVPN_HYBRID_TCP_RAW,
    MQVPN_HYBRID_TCP_AUTO,
} mqvpn_hybrid_tcp_mode_t;

/* Static per-session policy. The per-flow SYN-time verdict for tcp=auto
 * (active_paths >= 2) belongs to tcp_lane.c at flow creation — NOT
 * evaluated here; classify() applies only the static gates so it stays
 * pure and per-packet. */
typedef struct {
    int enabled;
    mqvpn_hybrid_tcp_mode_t tcp_mode;
    uint32_t tcp_max_flows;        /* consumed by tcp_lane.c */
    uint32_t tcp_idle_timeout_sec; /* consumed by tcp_lane.c */
} mqvpn_hybrid_config_t;

/* Server-wide cap on concurrent egress TCP fds tcp_egress will ever open,
 * before mqvpn_server_egress_fd_budget()'s rlimit-derived headroom check
 * narrows it further. This is a whole-server bound, distinct from the
 * per-flow-table tcp_max_flows above. config key lands with the
 * server-side cap enforcement. */
#define MQVPN_TCP_MAX_GLOBAL_FLOWS_DEFAULT 4096

/* static inline ON PURPOSE (not in classifier.c): src/config.c and
 * src/mqvpn_config.c will call these, and three test targets link those
 * sources WITHOUT mqvpn_lib — out-of-line definitions would break links. */
static inline void
mqvpn_hybrid_config_default(mqvpn_hybrid_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->enabled = 0;
    cfg->tcp_mode = MQVPN_HYBRID_TCP_AUTO;
    cfg->tcp_max_flows = 256;
    cfg->tcp_idle_timeout_sec = 300;
}

static inline int
mqvpn_hybrid_config_validate(const mqvpn_hybrid_config_t *cfg)
{
    if (!cfg) return -1;
    if (cfg->tcp_mode > MQVPN_HYBRID_TCP_AUTO) return -1;
    if (cfg->tcp_max_flows == 0) return -1;
    return 0;
}

/* Classify one inner IP packet from TUN. Fills *out_key (nullable) for
 * TCP/UDP verdicts. Rules: IPv4 fragment → RAW; IPv4 TCP → TCP lane iff
 * enabled && tcp_mode != RAW; UDP → DGRAM; IPv6 TCP → RAW (v1);
 * ICMP/other/parse-fail → RAW. */
mqvpn_hybrid_lane_t mqvpn_hybrid_classify(const uint8_t *pkt, size_t len,
                                          const mqvpn_hybrid_config_t *pol,
                                          mqvpn_flow_key_t *out_key);

#endif
