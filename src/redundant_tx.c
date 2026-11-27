// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#include "redundant_tx.h"

#include "libmqvpn.h" /* MQVPN_MAX_PATHS */

#include <stdlib.h>
#include <string.h>

#define RTX_CAP 16384 /* power of two; both tables */
/* Physical slots: load <= 0.5, so a probe always meets an empty slot. */
#define RTX_SLOTS       (2 * RTX_CAP)
#define RTX_LAG         250000u   /* us a path may queue beyond the least-queued one */
#define RTX_RTT_UNKNOWN 10000000u /* us: at or above, no min RTT sample (UINT32_MAX) */
/* us per rate bucket; the last complete bucket estimates the current rate */
#define RTX_RATE_BUCKET 100000u
/* shortcut: the fit check assumes full-size datagrams (SRT), so a small-packet stream
 * needs a faster path to count as fitting; count the stream's bytes if that matters */
#define RTX_PKT_BYTES   1400u
#define RTX_MODE_WIN    200000u   /* us: window of one judgement */
#define RTX_IDLE        1000000u  /* us: no packet counted, or no judgement, this long */
#define RTX_START_GRACE 2000000u  /* us: from the start, no judgement counts as short */
#define RTX_ENTER_N     5         /* all-short judgements in a row to enter */
#define RTX_REENTER_N   2         /* the same during a probe */
#define RTX_HOLD_FIRST  10000000u /* us: first overload hold; a probe also needs a fit */
#define RTX_HOLD_MAX    32000000u /* us: the hold doubles per failed probe, up to this */
#define RTX_PROBE_OK    10000000u /* us: a probe this long resets the hold */
#define RTX_HIST        10        /* whole seconds of rate history */
/* fewest copies per window to judge: below it, ACKs every 2nd packet swing past 5% */
#define RTX_MIN_JUDGED 40u
enum { RTX_NORMAL, RTX_PROBE, RTX_OVERLOAD };

/* ---- port list / packet matching ---- */

int
mqvpn_redundant_parse_ports(const char *s, uint16_t *out, int max)
{
    if (!s) return 0;
    const char *p = s;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;
    if (!*p) return 0;

    int n_tok = 0, n = 0;
    for (p = s;; p++) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
            p++;
        unsigned v = 0;
        int digits = 0;
        while (*p >= '0' && *p <= '9') {
            if (v <= 65535) v = v * 10 + (unsigned)(*p - '0');
            digits++;
            p++;
        }
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
            p++;
        if (digits == 0 || v < 1 || v > 65535) return -1;
        if (++n_tok > max) return -1;
        int dup = 0;
        for (int i = 0; i < n; i++)
            if (out[i] == v) dup = 1;
        if (!dup) out[n++] = (uint16_t)v;
        if (*p == '\0') return n;
        if (*p != ',') return -1;
    }
}

int
mqvpn_redundant_match(const uint16_t *ports, int n_ports, const uint8_t *pkt, size_t len)
{
    if (!pkt || len < 1) return 0;
    size_t off;
    if ((pkt[0] >> 4) == 4) {
        if (len < 20 || pkt[9] != 17) return 0;
        if (n_ports <= 0) return 1;
        if ((((unsigned)pkt[6] << 8 | pkt[7]) & 0x1fff) != 0) return 0; /* non-first */
        off = (size_t)(pkt[0] & 0x0f) * 4;
        if (off < 20) return 0;
    } else if ((pkt[0] >> 4) == 6) {
        /* No extension-header walk, same as flow_hash_pkt. */
        if (len < 40 || pkt[6] != 17) return 0;
        if (n_ports <= 0) return 1;
        off = 40;
    } else {
        return 0;
    }
    if (off + 4 > len) return 0;
    uint16_t dport = (uint16_t)((pkt[off + 2] << 8) | pkt[off + 3]);
    for (int i = 0; i < n_ports; i++)
        if (ports[i] == dport) return 1;
    return 0;
}

/* ---- copy tracking and queue gate ---- */

/* Open-addressing table (linear probe, backward-shift delete, no eviction).
 * Copies: key = dgram_id, a = original key, b = path (-1 detached), len = bytes.
 * Originals: key = internal counter, a = unresolved copies, b = acked flag. */
typedef struct {
    uint64_t key;
    uint64_t a;
    int32_t b;
    uint8_t used;
    uint16_t len;
} rtx_ent_t;

typedef struct {
    rtx_ent_t *e;
    int n;
} rtx_tab_t;

typedef struct {
    int bound;
    uint64_t xqc_id;
    int outstanding;
    uint64_t out_bytes; /* bytes of the unresolved copies */
    uint64_t min_rtt_us;
    uint32_t first;            /* sent[] index of the oldest unresolved copy */
    uint64_t acked;            /* copies acked since the judgement window start */
    uint64_t est_bw, inflight; /* bytes/s (congestion estimate), bytes in flight */
    int hit;                   /* select left it out in the window */
} rtx_path_t;

struct mqvpn_redundant_tx_s {
    rtx_tab_t copies, origs;
    uint64_t next_orig;
    rtx_path_t path[MQVPN_MAX_PATHS];
    int have_win;
    uint64_t win_sec;
    uint32_t win_count, prev_count;     /* originals in win_sec / the second before */
    uint64_t last_us;                   /* latest counted packet time */
    uint64_t bkt_id;                    /* now_us / RTX_RATE_BUCKET of the open bucket */
    uint32_t bkt_count, prev_bkt_count; /* originals in bkt_id / bkt_id - 1 */
    /* overload mode */
    int mode, short_n;                    /* RTX_*; all-short judgements in a row */
    uint64_t win_start_us, flow_since_us; /* window, stream start (0 = unset) */
    uint64_t since_us, hold_us;           /* OVERLOAD / PROBE start; overload hold */
    uint32_t sec_hist[RTX_HIST];          /* originals per whole second, a ring */
    /* hand-over times of each path's unresolved copies: outstanding entries from first */
    uint64_t sent[MQVPN_MAX_PATHS][RTX_CAP];
};

static uint32_t
rtx_slot(uint64_t k)
{
    k *= 0x9E3779B97F4A7C15ull;
    return (uint32_t)(k >> 40) & (RTX_SLOTS - 1);
}

static rtx_ent_t *
tab_find(rtx_tab_t *t, uint64_t key)
{
    for (uint32_t i = rtx_slot(key);; i = (i + 1) & (RTX_SLOTS - 1)) {
        if (!t->e[i].used) return NULL;
        if (t->e[i].key == key) return &t->e[i];
    }
}

static rtx_ent_t *
tab_insert(rtx_tab_t *t, uint64_t key)
{
    if (t->n >= RTX_CAP) return NULL;
    uint32_t i = rtx_slot(key);
    while (t->e[i].used)
        i = (i + 1) & (RTX_SLOTS - 1);
    memset(&t->e[i], 0, sizeof(t->e[i]));
    t->e[i].used = 1;
    t->e[i].key = key;
    t->n++;
    return &t->e[i];
}

static void
tab_remove(rtx_tab_t *t, rtx_ent_t *ent)
{
    uint32_t i = (uint32_t)(ent - t->e), j = i;
    for (;;) {
        j = (j + 1) & (RTX_SLOTS - 1);
        if (!t->e[j].used) break;
        uint32_t h = rtx_slot(t->e[j].key);
        /* entry j may move to hole i unless its home lies cyclically in (i, j] */
        if (i <= j ? (h > i && h <= j) : (h > i || h <= j)) continue;
        t->e[i] = t->e[j];
        i = j;
    }
    t->e[i].used = 0;
    t->n--;
}

static void
rtx_mode_reset(mqvpn_redundant_tx_t *t)
{
    t->mode = RTX_NORMAL;
    t->short_n = 0;
    t->win_start_us = 0;
    t->flow_since_us = 0;
    t->hold_us = RTX_HOLD_FIRST;
    memset(t->sec_hist, 0, sizeof(t->sec_hist));
}

mqvpn_redundant_tx_t *
mqvpn_redundant_tx_new(void)
{
    mqvpn_redundant_tx_t *t = calloc(1, sizeof(*t));
    if (!t) return NULL;
    rtx_mode_reset(t);
    t->copies.e = calloc(RTX_SLOTS, sizeof(rtx_ent_t));
    t->origs.e = calloc(RTX_SLOTS, sizeof(rtx_ent_t));
    if (!t->copies.e || !t->origs.e) {
        mqvpn_redundant_tx_free(t);
        return NULL;
    }
    return t;
}

void
mqvpn_redundant_tx_free(mqvpn_redundant_tx_t *t)
{
    if (!t) return;
    free(t->copies.e);
    free(t->origs.e);
    free(t);
}

static int
path_ok(int path)
{
    return path >= 0 && path < MQVPN_MAX_PATHS;
}

void
mqvpn_redundant_tx_detach_path(mqvpn_redundant_tx_t *t, int path)
{
    if (!t || !path_ok(path)) return;
    /* outstanding counts exactly the copies with b == path, so an idle slot
     * (the common call) needs no scan. shortcut: a real detach scans the whole
     * table; index copies per path if detaches become frequent. */
    if (t->path[path].outstanding == 0) return;
    for (int i = 0; i < RTX_SLOTS; i++)
        if (t->copies.e[i].used && t->copies.e[i].b == path) t->copies.e[i].b = -1;
    t->path[path].outstanding = 0;
    t->path[path].out_bytes = 0;
}

void
mqvpn_redundant_tx_bind_path(mqvpn_redundant_tx_t *t, int path, uint64_t xqc_path_id)
{
    if (!t || !path_ok(path)) return;
    rtx_path_t *p = &t->path[path];
    if (p->bound && p->xqc_id != xqc_path_id) mqvpn_redundant_tx_detach_path(t, path);
    p->bound = 1;
    p->xqc_id = xqc_path_id;
}

void
mqvpn_redundant_tx_set_path_metrics(mqvpn_redundant_tx_t *t, int path,
                                    uint64_t min_rtt_us, uint64_t est_bw,
                                    uint64_t inflight)
{
    if (!t || !path_ok(path)) return;
    t->path[path].min_rtt_us = min_rtt_us < RTX_RTT_UNKNOWN ? min_rtt_us : 0;
    t->path[path].est_bw = est_bw;
    t->path[path].inflight = inflight;
}

int
mqvpn_redundant_tx_outstanding(const mqvpn_redundant_tx_t *t, int path)
{
    return (t && path_ok(path)) ? t->path[path].outstanding : 0;
}

/* shortcut: pps is the larger of the previous second and the last complete
 * 100 ms bucket x10; an idle gap keeps the last value until the next counted packet. */
static uint64_t
rtx_stream_pps(const mqvpn_redundant_tx_t *t)
{
    uint64_t pps = t->prev_count;
    uint64_t bkt = (uint64_t)t->prev_bkt_count * (1000000u / RTX_RATE_BUCKET);
    return bkt > pps ? bkt : pps;
}

uint64_t
mqvpn_redundant_tx_stream_pps(const mqvpn_redundant_tx_t *t)
{
    return t ? rtx_stream_pps(t) : 0;
}

/* 0 with no unresolved copy, or until the oldest one has waited its min RTT; the clock
 * can step back. */
static uint64_t
rtx_queued_us(const mqvpn_redundant_tx_t *t, int path, uint64_t now_us)
{
    const rtx_path_t *p = &t->path[path];
    if (p->outstanding == 0) return 0;
    uint64_t due = t->sent[path][p->first] + p->min_rtt_us;
    return now_us > due ? now_us - due : 0;
}

int
mqvpn_redundant_tx_select(mqvpn_redundant_tx_t *t, const int *usable, int n_usable,
                          int *out, uint64_t now_us)
{
    if (!t || !usable || !out || n_usable <= 0) return 0;
    if (t->origs.n >= RTX_CAP) return 0;
    uint64_t q[MQVPN_MAX_PATHS];
    int best = -1;
    for (int i = 0; i < n_usable; i++) {
        int p = usable[i];
        if (!path_ok(p)) continue;
        q[p] = rtx_queued_us(t, p, now_us);
        int o = t->path[p].outstanding;
        if (best < 0 || q[p] < q[best] ||
            (q[p] == q[best] && (o < t->path[best].outstanding ||
                                 (o == t->path[best].outstanding && p < best))))
            best = p;
    }
    if (best < 0) return 0;
    /* copies more than RTX_LAG behind another path's rarely arrive in time to fill a
     * loss, and if that path drops, every fresh packet waits behind them */
    int n = 0;
    for (int i = 0; i < n_usable; i++) {
        int p = usable[i];
        if (!path_ok(p)) continue;
        if (q[best] > RTX_LAG ? p == best : q[p] <= q[best] + RTX_LAG)
            out[n++] = p;
        else
            t->path[p].hit = 1;
    }
    int room = RTX_CAP - t->copies.n;
    return n < room ? n : room;
}

/* Count one original toward the stream rate: the whole second and the 100 ms bucket. */
static void
rtx_count_rate(mqvpn_redundant_tx_t *t, uint64_t now_us)
{
    uint64_t sec = now_us / 1000000u;
    /* the clock stepped back, so restart the window */
    if (t->have_win && now_us < t->last_us) t->have_win = 0;
    int fresh = !t->have_win;
    if (!t->have_win || sec != t->win_sec) {
        int contiguous = t->have_win && sec == t->win_sec + 1;
        if (contiguous) t->sec_hist[t->win_sec % RTX_HIST] = t->win_count;
        t->prev_count = contiguous ? t->win_count : 0;
        t->have_win = 1;
        t->win_sec = sec;
        t->win_count = 0;
    }
    t->win_count++;
    uint64_t b = now_us / RTX_RATE_BUCKET;
    if (fresh || b != t->bkt_id) {
        t->prev_bkt_count = (!fresh && b == t->bkt_id + 1) ? t->bkt_count : 0;
        t->bkt_id = b;
        t->bkt_count = 0;
    }
    t->bkt_count++;
    t->last_us = now_us;
}

void
mqvpn_redundant_tx_commit(mqvpn_redundant_tx_t *t, const uint64_t *dgram_ids,
                          const int *paths, int k, uint64_t now_us, size_t len)
{
    if (!t || k <= 0 || t->origs.n >= RTX_CAP || t->copies.n + k > RTX_CAP) return;
    rtx_count_rate(t, now_us);
    uint16_t bytes = len > UINT16_MAX ? UINT16_MAX : (uint16_t)len;

    rtx_ent_t *o = tab_insert(&t->origs, ++t->next_orig);
    o->a = (uint64_t)k;
    for (int i = 0; i < k; i++) {
        rtx_ent_t *c = tab_insert(&t->copies, dgram_ids[i]);
        c->a = o->key;
        c->b = path_ok(paths[i]) ? paths[i] : -1;
        c->len = bytes;
        if (c->b >= 0) {
            rtx_path_t *p = &t->path[c->b];
            t->sent[c->b][(p->first + (uint32_t)p->outstanding) & (RTX_CAP - 1)] = now_us;
            p->outstanding++;
            p->out_bytes += bytes;
        }
    }
}

/* Drop one resolved copy; returns its original (NULL if untracked). */
static rtx_ent_t *
resolve(mqvpn_redundant_tx_t *t, uint64_t dgram_id, int *last, int acked)
{
    rtx_ent_t *c = tab_find(&t->copies, dgram_id);
    if (!c) return NULL;
    rtx_ent_t *o = tab_find(&t->origs, c->a);
    if (c->b >= 0) {
        rtx_path_t *p = &t->path[c->b];
        p->outstanding--;
        p->out_bytes -= c->len;
        if (acked) p->acked++;
        /* shortcut: drops the oldest time whichever copy resolved, so an out-of-order
         * resolution under-estimates the queue (never over); keep per-copy times if that
         * matters. A copy xquic never reports (none known) pins the time once the path
         * gets no copy for RTX_LAG past its min RTT, leaving it out until a detach. */
        p->first = (p->first + 1) & (RTX_CAP - 1);
    }
    tab_remove(&t->copies, c);
    *last = (--o->a == 0);
    return o;
}

int
mqvpn_redundant_tx_on_acked(mqvpn_redundant_tx_t *t, uint64_t dgram_id)
{
    int last;
    rtx_ent_t *o = t ? resolve(t, dgram_id, &last, 1) : NULL;
    if (!o) return -1;
    int first = !o->b;
    o->b = 1;
    if (last) tab_remove(&t->origs, o);
    return first;
}

int
mqvpn_redundant_tx_on_lost(mqvpn_redundant_tx_t *t, uint64_t dgram_id)
{
    int last;
    rtx_ent_t *o = t ? resolve(t, dgram_id, &last, 0) : NULL;
    if (!o) return -1;
    int r = last && !o->b;
    if (last) tab_remove(&t->origs, o);
    return r;
}

/* ---- overload mode ---- */

static void
rtx_window_start(mqvpn_redundant_tx_t *t, uint64_t now_us)
{
    t->win_start_us = now_us ? now_us : 1;
    for (int i = 0; i < MQVPN_MAX_PATHS; i++) {
        t->path[i].acked = 0;
        t->path[i].hit = 0;
    }
}

int
mqvpn_redundant_tx_update_mode(mqvpn_redundant_tx_t *t, const int *usable, int n_usable,
                               uint64_t now_us)
{
    if (!t || !usable || n_usable <= 0) return 0;
    /* start afresh when this update finds no packet counted, or no judgement (a total
     * outage skips the update), for RTX_IDLE, or the clock stepped back */
    if (!t->have_win || now_us < t->last_us || now_us - t->last_us >= RTX_IDLE ||
        now_us < t->win_start_us ||
        (t->win_start_us && now_us - t->win_start_us >= RTX_IDLE)) {
        int was_overload = t->mode == RTX_OVERLOAD;
        rtx_mode_reset(t);
        return was_overload ? -1 : 0;
    }
    if (t->win_start_us == 0) {
        rtx_window_start(t, now_us);
        t->flow_since_us = t->win_start_us;
        return 0;
    }
    uint64_t el = now_us - t->win_start_us;
    if (el < RTX_MODE_WIN) return 0;

    uint64_t pps = rtx_stream_pps(t), base = 0;
    /* the lowest second: overload loss inflates the others with retransmissions */
    for (int i = 0; i < RTX_HIST; i++)
        if (t->sec_hist[i] && (base == 0 || t->sec_hist[i] < base)) base = t->sec_hist[i];
    if (base == 0) base = pps;

    int all_short = 1, fit = 0;
    for (int i = 0; i < n_usable; i++) {
        if (!path_ok(usable[i])) continue;
        const rtx_path_t *p = &t->path[usable[i]];
        /* short: backed up (left out by select, or copies queued in xquic) yet
         * delivering under 95% of the stream */
        uint64_t acked_pps = p->acked * 1000000u / el;
        int fed = p->hit || p->out_bytes > p->inflight + p->inflight / 10;
        if (!fed || acked_pps * 100 >= pps * 95) all_short = 0;
        if (p->est_bw / RTX_PKT_BYTES * 100 >= base * 105) fit = 1;
    }
    if (pps * el < (uint64_t)RTX_MIN_JUDGED * 1000000u) all_short = 0;
    rtx_window_start(t, now_us);
    if (pps == 0) return 0;

    if (t->mode == RTX_OVERLOAD) {
        /* copying while no path can carry the stream only costs, so probe on a fit */
        if (now_us - t->since_us < t->hold_us || !fit) return 0;
        t->mode = RTX_PROBE;
        t->since_us = now_us;
        t->short_n = 0;
        return -1;
    }
    if (all_short && now_us - t->flow_since_us >= RTX_START_GRACE)
        t->short_n++;
    else
        t->short_n = 0;
    if (t->short_n >= (t->mode == RTX_PROBE ? RTX_REENTER_N : RTX_ENTER_N)) {
        if (t->mode == RTX_PROBE) {
            t->hold_us *= 2;
            if (t->hold_us > RTX_HOLD_MAX) t->hold_us = RTX_HOLD_MAX;
        }
        t->mode = RTX_OVERLOAD;
        t->since_us = now_us;
        return 1;
    }
    if (t->mode == RTX_PROBE && now_us - t->since_us >= RTX_PROBE_OK) {
        t->mode = RTX_NORMAL;
        t->hold_us = RTX_HOLD_FIRST;
    }
    return 0;
}

int
mqvpn_redundant_tx_overload_bypass(mqvpn_redundant_tx_t *t, uint64_t now_us)
{
    if (!t || t->mode != RTX_OVERLOAD) return 0;
    rtx_count_rate(t, now_us);
    return 1;
}
