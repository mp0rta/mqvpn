/*
 * flow_sched.h
 *
 * Scheduler mode constants and IPv4/IPv6 5-tuple flow hash utility.
 * Path selection is handled inside xquic scheduler callbacks
 * (minrtt/wlb).
 */
#ifndef MQVPN_FLOW_SCHED_H
#define MQVPN_FLOW_SCHED_H

#include <stdint.h>
#include <stdbool.h>

/* Scheduler mode (mirrors mqvpn_scheduler_t in include/libmqvpn.h).
 * Keep in sync — referenced by tests that include only flow_sched.h. */
#define MQVPN_SCHED_MINRTT      0
#define MQVPN_SCHED_WLB         1
#define MQVPN_SCHED_BACKUP_FEC  2
#define MQVPN_SCHED_WLB_UDP_PIN 3

#define MQVPN_FLOW_HASH_UNPINNED 0xFFFFFFFFU

/* Returns flow hash for xquic WLB scheduler hint.
 *   TCP                        → FNV-1a 5-tuple hash
 *   UDP, udp_pin=true          → FNV-1a 5-tuple hash (used by wlb_udp_pin)
 *   UDP, udp_pin=false / ICMP  → MQVPN_FLOW_HASH_UNPINNED (per-packet WRR)
 *   malformed / unknown        → 0 (xquic falls back to MinRTT) */
uint32_t flow_hash_pkt(const uint8_t *pkt, int len, bool udp_pin);

#endif /* MQVPN_FLOW_SCHED_H */
