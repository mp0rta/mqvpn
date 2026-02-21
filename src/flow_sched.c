/*
 * flow_sched.c — Flow-affinity Weighted Load Balancing (WLB) scheduler
 *
 * See flow_sched.h for design overview and academic references.
 */
#include "flow_sched.h"
#include "log.h"

#include <inttypes.h>
#include <string.h>
#include <limits.h>
#include <xquic/xquic.h>

/* ── Time helper ── */

#include <time.h>

static uint64_t
now_usec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000;
}

/* ── FNV-1a hash of IPv4 5-tuple ── */

uint32_t
flow_hash_pkt(const uint8_t *pkt, int len)
{
    if (len < 20 || (pkt[0] >> 4) != 4)
        return 0;

    uint8_t proto = pkt[9];
    int ihl = (pkt[0] & 0x0f) * 4;

    /* src_ip (12..15), dst_ip (16..19) */
    uint32_t h = 2166136261u;

    for (int i = 12; i < 20; i++)
        h = (h ^ pkt[i]) * 16777619u;

    h = (h ^ proto) * 16777619u;

    /* TCP(6) or UDP(17) ports at ihl..ihl+3 */
    if ((proto == 6 || proto == 17) && len >= ihl + 4) {
        for (int i = ihl; i < ihl + 4; i++)
            h = (h ^ pkt[i]) * 16777619u;
    }

    /* Ensure non-zero (0 = empty slot sentinel) */
    if (h == 0) h = 1;
    return h;
}

/* ── Flow table operations ── */

static flow_entry_t *
flow_lookup(flow_sched_t *fs, uint32_t hash)
{
    int idx = hash & FLOW_TABLE_MASK;
    for (int p = 0; p < FLOW_MAX_PROBE; p++) {
        int i = (idx + p) & FLOW_TABLE_MASK;
        if (fs->flows[i].hash == hash)
            return &fs->flows[i];
        if (fs->flows[i].hash == 0)
            return NULL;
    }
    return NULL;
}

static void
flow_insert(flow_sched_t *fs, uint32_t hash, uint64_t path_id, uint64_t ts)
{
    int idx = hash & FLOW_TABLE_MASK;
    for (int p = 0; p < FLOW_MAX_PROBE; p++) {
        int i = (idx + p) & FLOW_TABLE_MASK;
        if (fs->flows[i].hash == 0 || fs->flows[i].hash == hash) {
            fs->flows[i].hash = hash;
            fs->flows[i].path_id = path_id;
            fs->flows[i].last_seen = ts;
            return;
        }
    }
    /* Table full — overwrite first slot (rare) */
    int i = idx & FLOW_TABLE_MASK;
    fs->flows[i].hash = hash;
    fs->flows[i].path_id = path_id;
    fs->flows[i].last_seen = ts;
}

/* ── Path helpers ── */

static wlb_path_t *
find_wlb_path(flow_sched_t *fs, uint64_t path_id)
{
    for (int i = 0; i < fs->n_paths; i++) {
        if (fs->paths[i].path_id == path_id)
            return &fs->paths[i];
    }
    return NULL;
}

static int
path_is_active(flow_sched_t *fs, uint64_t path_id)
{
    wlb_path_t *wp = find_wlb_path(fs, path_id);
    return wp && wp->active;
}

/* ── Public API ── */

void
flow_sched_init(flow_sched_t *fs, int mode)
{
    memset(fs, 0, sizeof(*fs));
    fs->enabled = (mode == MQVPN_SCHED_WLB);
}

void
flow_sched_add_path(flow_sched_t *fs, uint64_t path_id)
{
    /* Check if already registered */
    wlb_path_t *existing = find_wlb_path(fs, path_id);
    if (existing) {
        existing->active = 1;
        goto recount;
    }

    if (fs->n_paths >= WLB_MAX_PATHS) {
        LOG_WRN("WLB: max paths reached, ignoring path %" PRIu64, path_id);
        return;
    }

    wlb_path_t *wp = &fs->paths[fs->n_paths++];
    wp->path_id = path_id;
    wp->weight = 1;
    wp->deficit = 0;
    wp->active = 1;
    wp->prev_lost = 0;
    wp->prev_sent = 0;

recount:;
    int active = 0;
    for (int i = 0; i < fs->n_paths; i++)
        if (fs->paths[i].active) active++;
    fs->n_active = active;

    LOG_INF("WLB: path %" PRIu64 " added (%d active)", path_id, fs->n_active);
}

void
flow_sched_remove_path(flow_sched_t *fs, uint64_t path_id)
{
    wlb_path_t *wp = find_wlb_path(fs, path_id);
    if (!wp) return;

    wp->active = 0;

    int active = 0;
    for (int i = 0; i < fs->n_paths; i++)
        if (fs->paths[i].active) active++;
    fs->n_active = active;

    LOG_INF("WLB: path %" PRIu64 " removed (%d active)", path_id, fs->n_active);
}

void
flow_sched_update(flow_sched_t *fs,
                  const xqc_path_metrics_t *metrics, int n_paths)
{
    if (!fs->enabled) return;

    for (int i = 0; i < n_paths; i++) {
        wlb_path_t *wp = find_wlb_path(fs, metrics[i].path_id);
        if (!wp || !wp->active) continue;

        uint64_t est_bw = metrics[i].path_est_bw;
        uint64_t srtt   = metrics[i].path_srtt;
        uint64_t minrtt = metrics[i].path_min_rtt;

        /* Cold start fallback: cwnd / srtt  (bytes/sec) */
        if (est_bw == 0 && srtt > 0)
            est_bw = metrics[i].path_cwnd * 1000000ULL / srtt;

        /* Delta-based loss rate */
        uint32_t lost_delta = metrics[i].path_lost_count - wp->prev_lost;
        uint64_t sent_delta = metrics[i].path_pkt_send_count - wp->prev_sent;
        double loss = (sent_delta > 10)
                    ? (double)lost_delta / (double)sent_delta : 0.0;
        if (loss > 1.0) loss = 1.0;

        /* Queue delay factor: min_rtt / srtt  →  1.0 = no queueing */
        double rtt_q = (srtt > 0 && minrtt > 0 && minrtt <= srtt)
                     ? (double)minrtt / (double)srtt : 1.0;

        /* LATE-inspired weight:
         *   effective_bw = est_bw × (1 - loss) × (min_rtt / srtt)   */
        uint64_t w = (uint64_t)(est_bw * (1.0 - loss) * rtt_q);
        if (w < 1) w = 1;
        wp->weight = w;

        /* WRR deficit replenishment — scale down to prevent overflow.
         * deficit unit ≈ Mbps, so divide by 1M. */
        wp->deficit += (int64_t)(w / 1000000ULL) + 1;

        wp->prev_lost = metrics[i].path_lost_count;
        wp->prev_sent = metrics[i].path_pkt_send_count;

        /* Store cwnd / inflight for cwnd-aware gating */
        wp->cwnd = metrics[i].path_cwnd;
        wp->bytes_in_flight = metrics[i].path_bytes_in_flight;

        LOG_DBG("WLB path %" PRIu64 ": est_bw=%" PRIu64
                " loss=%.3f rtt_q=%.3f weight=%" PRIu64
                " deficit=%" PRId64 " cwnd=%" PRIu64 " inflight=%" PRIu64,
                wp->path_id, est_bw, loss, rtt_q, wp->weight, wp->deficit,
                wp->cwnd, wp->bytes_in_flight);
    }
}

uint64_t
flow_sched_get_path(flow_sched_t *fs, const uint8_t *ip_pkt, int pkt_len)
{
    if (!fs->enabled || fs->n_paths <= 1 || fs->n_active < 1)
        return UINT64_MAX;

    uint32_t h = flow_hash_pkt(ip_pkt, pkt_len);
    if (h == 0)
        return UINT64_MAX;

    uint64_t ts = now_usec();

    /* Lookup existing flow → sticky path */
    flow_entry_t *entry = flow_lookup(fs, h);
    if (entry && path_is_active(fs, entry->path_id)) {
        entry->last_seen = ts;
        return entry->path_id;
    }

    /* New flow (or dead path) → WRR: pick path with max deficit */
    int best = -1;
    int64_t max_deficit = INT64_MIN;
    for (int i = 0; i < fs->n_paths; i++) {
        if (!fs->paths[i].active) continue;
        if (fs->paths[i].deficit > max_deficit) {
            max_deficit = fs->paths[i].deficit;
            best = i;
        }
    }
    if (best < 0)
        return UINT64_MAX;

    fs->paths[best].deficit -= 1;
    flow_insert(fs, h, fs->paths[best].path_id, ts);

    LOG_DBG("WLB: new flow 0x%08x → path %" PRIu64, h, fs->paths[best].path_id);
    return fs->paths[best].path_id;
}

int
flow_sched_path_can_send(flow_sched_t *fs, uint64_t path_id, size_t pkt_size)
{
    wlb_path_t *wp = find_wlb_path(fs, path_id);
    if (!wp || !wp->active || wp->cwnd == 0)
        return 0;

    /* Require at least 25% cwnd headroom beyond the packet itself.
     * This is conservative: stale (1s-old) metrics mean the real
     * inflight may be higher, so we leave a safety margin. */
    uint64_t headroom = wp->cwnd / 4;
    if (headroom < pkt_size)
        headroom = pkt_size;

    return (wp->bytes_in_flight + pkt_size + headroom) <= wp->cwnd;
}

void
flow_sched_expire(flow_sched_t *fs, uint64_t now_us)
{
    for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
        if (fs->flows[i].hash != 0
            && (now_us - fs->flows[i].last_seen) > FLOW_EXPIRE_US)
        {
            fs->flows[i].hash = 0;
        }
    }
}
