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

/* Compute FNV-1a hash of IPv4 5-tuple.  Returns 0 for non-IPv4/too-short. */
uint32_t flow_hash_pkt(const uint8_t *pkt, int len);

#endif /* MQVPN_FLOW_SCHED_H */
