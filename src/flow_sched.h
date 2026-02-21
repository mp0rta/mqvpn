/*
 * flow_sched.h
 *
 * Scheduler mode constants and IPv4 5-tuple flow hash utility.
 * Path selection is handled inside xquic scheduler callbacks
 * (minrtt/wlb).
 */
#ifndef MQVPN_FLOW_SCHED_H
#define MQVPN_FLOW_SCHED_H

#include <stdint.h>

/* Scheduler mode */
#define MQVPN_SCHED_MINRTT      0
#define MQVPN_SCHED_WLB         1   /* WLB with flow-affinity WRR (default) */

/* Sentinel: WRR without flow pinning (for UDP/QUIC — no reordering concern) */
#define MQVPN_FLOW_HASH_UNPINNED  0xFFFFFFFFU

/*
 * Compute flow hash for WLB scheduler hint.
 *   TCP (proto 6)  → FNV-1a 5-tuple hash (non-zero, flow-pinned)
 *   UDP/other      → MQVPN_FLOW_HASH_UNPINNED (WRR without pinning)
 *   non-IPv4/short → 0 (MinRTT fallback)
 */
uint32_t flow_hash_pkt(const uint8_t *pkt, int len);

#endif /* MQVPN_FLOW_SCHED_H */
