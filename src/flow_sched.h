/*
 * flow_sched.h — Flow-affinity Weighted Load Balancing (WLB) scheduler
 *
 * Distributes VPN flows across multipath QUIC paths proportionally to
 * each path's effective bandwidth.  Based on:
 *   - OLB (Optimal Load Balancing, Comp. Comm. 2017): WRR mechanism
 *   - LATE (Loss-Aware Throughput Estimation, IEEE TWC 2021): weight formula
 *
 * Extended to flow-level affinity (5-tuple sticky) to avoid inner TCP
 * reordering that packet-level schedulers cause in VPN tunnels.
 */
#ifndef MQVPN_FLOW_SCHED_H
#define MQVPN_FLOW_SCHED_H

#include <stdint.h>
#include <stddef.h>

/* Forward declaration — avoids pulling in all of xquic.h */
struct xqc_path_metrics_s;
typedef struct xqc_path_metrics_s xqc_path_metrics_t;

#define FLOW_TABLE_SIZE    4096  /* must be power of 2 */
#define FLOW_TABLE_MASK    (FLOW_TABLE_SIZE - 1)
#define FLOW_MAX_PROBE     16   /* linear probing limit */
#define FLOW_EXPIRE_US     (60ULL * 1000000)  /* 60 s */
#define WLB_MAX_PATHS      4

/* Scheduler mode */
#define MQVPN_SCHED_MINRTT  0
#define MQVPN_SCHED_WLB     1

typedef struct {
    uint32_t  hash;        /* FNV-1a of 5-tuple (0 = empty slot) */
    uint64_t  path_id;     /* assigned xquic path */
    uint64_t  last_seen;   /* timestamp in usec */
} flow_entry_t;

typedef struct {
    uint64_t  path_id;
    uint64_t  weight;      /* effective bandwidth (bytes/sec) */
    int64_t   deficit;     /* WRR deficit counter */
    int       active;
    /* Previous counters for delta-based loss rate */
    uint32_t  prev_lost;
    uint64_t  prev_sent;
    /* Cwnd gating: only use send_on_path() when headroom exists */
    uint64_t  cwnd;
    uint64_t  bytes_in_flight;
} wlb_path_t;

typedef struct flow_sched_s {
    int           enabled;     /* 0 = disabled (minrtt), 1 = wlb */
    flow_entry_t  flows[FLOW_TABLE_SIZE];
    wlb_path_t    paths[WLB_MAX_PATHS];
    int           n_paths;     /* total registered (including inactive) */
    int           n_active;    /* currently active paths */
} flow_sched_t;

/* Initialize scheduler.  mode: MQVPN_SCHED_MINRTT or MQVPN_SCHED_WLB */
void flow_sched_init(flow_sched_t *fs, int mode);

/* Register a new path (called when xquic path becomes active). */
void flow_sched_add_path(flow_sched_t *fs, uint64_t path_id);

/* Remove a path (path went down).  Invalidates flows on that path. */
void flow_sched_remove_path(flow_sched_t *fs, uint64_t path_id);

/* Update path weights from xquic stats.  Called every ~1 second. */
void flow_sched_update(flow_sched_t *fs,
                       const xqc_path_metrics_t *metrics, int n_paths);

/* Get path for an IPv4 packet.  Extracts 5-tuple, does flow lookup/assign.
 * Returns path_id, or UINT64_MAX if scheduler disabled / single path. */
uint64_t flow_sched_get_path(flow_sched_t *fs,
                             const uint8_t *ip_pkt, int pkt_len);

/* Check if a path has cwnd headroom to accept a packet of pkt_size bytes.
 * Returns 1 if send_on_path() is safe, 0 if caller should fall back to send(). */
int flow_sched_path_can_send(flow_sched_t *fs, uint64_t path_id, size_t pkt_size);

/* Expire stale flows older than FLOW_EXPIRE_US. */
void flow_sched_expire(flow_sched_t *fs, uint64_t now_us);

/* ── Internals exposed for unit testing ── */

/* Compute FNV-1a hash of IPv4 5-tuple.  Returns 0 for non-IPv4/too-short. */
uint32_t flow_hash_pkt(const uint8_t *pkt, int len);

#endif /* MQVPN_FLOW_SCHED_H */
