// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * tcp_lane.c — client-side TCP-lane flow table (H2b): sticky-lane lookup,
 * SYN-time commit + cap enforcement, the lwIP accept callback, the downlink
 * relay (H3 recv_body -> lwIP tcp_write), and the close/error
 * mapping + flow removal that makes flow teardown real.
 *
 * The uplink relay (lwIP recv -> H3 send_body: the QUEUE + SEND +
 * FLUSH + FIN machinery) lives in tcp_lane_uplink.c — split out
 * once this file crossed the ~800-line extraction trigger. The two files
 * are one logical module; see tcp_lane_internal.h for the shared struct
 * layouts, the compile-time test-double hooks, and the small cross-TU
 * function seam between them.
 */

#include "hybrid/tcp_lane_internal.h"

#include <assert.h> /* pins the h3_recv "0 bytes implies fin" contract */
#include <stdlib.h>
#include <string.h>

#include "lwip/priv/tcp_priv.h" /* TCP_MSL — C1's CLOSING grace-sweep window */

/* Dual-stack (LWIP_IPV6=1): ip_addr_t is now a tagged union
 * (lwip/ip_addr.h) — sizeof(ip_addr_t) != 4, so the old compile-time pin on
 * the bare-ip4_addr_t assumption no longer applies. The accept callback
 * (mqvpn_tcp_lane_lwip_accept below) instead switches on IP_IS_V6() and
 * memcpy's from ip_2_ip4()/ip_2_ip6()'s ->addr fields explicitly for each
 * family — see its docstring for the byte-order contract, now covering
 * both v4 and v6. */

/* Sticky-RAW markers are capped separately from tcp_max_flows: they are
 * never idle-evicted (the idle sweep covers TCP-lane flows only — a marker's
 * eviction bound is purely this cap, NOT time-based; I2 gives markers a
 * DIFFERENT, tuple-reuse-triggered replacement path — a new pure SYN with
 * a different ISN — see mqvpn_tcp_lane_on_syn — but a marker for a tuple
 * that simply never sees another SYN lives until this cap forces an
 * eviction), so counting them against tcp_max_flows would let a tcp=auto
 * client on a single path permanently exhaust the TCP lane with markers —
 * exactly the scenario tcp=auto exists for. This cap only bounds memory: a
 * marker entry is one mqvpn_tcp_flow_t (200 B, key 38 B) so 4096 markers
 * ≈ 0.82 MB worst case; the keys alone are 38 B × 4096 ≈ 156 KB. On cap hit
 * the flow just stays unsticky and re-evaluates per SYN (harmless).
 * #ifndef so tests can override it small to exercise the cap
 * branch. */
#ifndef TCP_LANE_RAW_MARKER_CAP
#  define TCP_LANE_RAW_MARKER_CAP 4096u
#endif

/* CLOSING routing-marker residency bound (C1) — same "memory bound only"
 * rationale as TCP_LANE_RAW_MARKER_CAP above: a CLOSING entry is one
 * mqvpn_tcp_flow_t with a NULL pcb/h3_request AND a freed downlink_stash
 * (tcp_lane_mark_closing releases it at the transition — see that
 * function's comment), so 4096 of them cost roughly the same ~0.82 MB
 * worst case. Overflow evicts the OLDEST CLOSING
 * entry immediately (mqvpn_tcp_lane_tick's cap check) rather than refusing
 * the transition — the cost of evicting early is only that one flow's
 * stray post-close packets (a FIN-storm flow, worst case) fall back to
 * RAW a little sooner than the full grace window; never counted against
 * flows_rejected_* (this is churn bookkeeping, not a rejected new flow).
 * #ifndef so tests can override it small to exercise the cap branch. */
#ifndef TCP_LANE_CLOSING_CAP
#  define TCP_LANE_CLOSING_CAP 4096u
#endif

/* Grace residency for a CLOSING routing marker (C1): must outlive the
 * inner OS's worst-case post-close retransmit horizon so the marker is
 * still there to catch it. TCP_MSL (vendored lwip/priv/tcp_priv.h) is
 * 60000 ms; a TIME_WAIT pcb is held for 2*TCP_MSL by lwIP itself, and a
 * LAST_ACK pcb's FIN-retransmit backoff (TCP_MAXRTX, bounded by the same
 * tcp_tmr-driven RTO doubling) is the same order of magnitude. 2*TCP_MSL
 * (120 s) covers both shapes without requiring per-connection RTT/RTO
 * tracking here — a coarse, cite-able constant beats a timing heuristic. */
#define TCP_LANE_CLOSING_GRACE_US ((uint64_t)(2 * TCP_MSL) * 1000ULL)

struct mqvpn_tcp_lane {
    mqvpn_hybrid_config_t cfg;
    uint64_t hash_seed;
    void *client_ctx;
    mqvpn_lwip_clock_fn clock_fn; /* nullable; last_activity_us stays 0 then */
    void *clock_ctx;
    mqvpn_tcp_flow_t **buckets;
    uint32_t n_buckets;
    uint32_t n_tcp_flows;   /* to_tcp=1 entries; capped by cfg.tcp_max_flows */
    uint32_t n_raw_markers; /* sticky-RAW entries; capped by
                             * TCP_LANE_RAW_MARKER_CAP */
    uint32_t n_closing;     /* TCP_FLOW_CLOSING routing markers (C1); capped
                             * by TCP_LANE_CLOSING_CAP, swept after
                             * TCP_LANE_CLOSING_GRACE_US. Does NOT count
                             * toward n_tcp_flows — see that state's
                             * comment (tcp_lane_internal.h). */
    uint64_t last_sweep_us; /* idle-sweep cadence gate — see
                             * mqvpn_tcp_lane_tick */
    mqvpn_tcp_lane_stats_t stats;
};

/* Defined with the downlink-relay machinery below; needed by
 * mqvpn_tcp_lane_free's teardown loop above it. */
static void tcp_lane_downlink_stash_free(mqvpn_tcp_flow_t *f);
/* Defined further below; mqvpn_tcp_lane_downlink_pump
 * needs it before that point in the file, same forward-reference reason as
 * the other declaration here. */
static mqvpn_tcp_flow_t *find_flow_by_stream(mqvpn_tcp_lane_t *lane, void *stream);
/* Defined with the downlink-relay machinery below; needed by
 * mqvpn_tcp_lane_tick's I3 stash-retry-and-resume branch, which runs earlier
 * in the file than either definition. */
static tcp_lane_flow_status_t tcp_lane_downlink_stash_retry(mqvpn_tcp_flow_t *f);
static tcp_lane_flow_status_t tcp_lane_downlink_drain(mqvpn_tcp_flow_t *f);
/* Defined with the close/error-mapping machinery below; needed by
 * mqvpn_tcp_lane_free (DRY: shares the exact detach-then-abort sequence)
 * and mqvpn_tcp_lane_lwip_accept's cap-exceeded defense branch above their
 * definitions. */
static int tcp_lane_silent_abort_pcb(mqvpn_tcp_flow_t *f);
static void tcp_lane_remove_flow(mqvpn_tcp_lane_t *lane, mqvpn_tcp_flow_t *f);
static void tcp_lane_close_h3(mqvpn_tcp_flow_t *f);
static tcp_lane_flow_status_t tcp_lane_teardown_flow(mqvpn_tcp_flow_t *f, int close_h3);
/* Defined at the very end of this file (thin dispatcher onto
 * tcp_lane_uplink.c); mqvpn_tcp_lane_lwip_accept registers it as the pcb's
 * recv callback before that point in the file. */
static err_t mqvpn_tcp_lane_on_lwip_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p,
                                         err_t err);

/* Power-of-two bucket count from the table's total capacity (load factor
 * ~1), capped at 2^20 buckets. Identical to reorder_tx.c's pick_buckets —
 * kept as a
 * separate copy deliberately: TX/RX/TCP-lane have DIFFERENT eviction
 * policies (idle-only / LRU / cap+idle+abort respectively), so the
 * surrounding structs diverge even though this helper doesn't. */
static uint32_t
pick_buckets(uint32_t max_flows)
{
    uint32_t n = 16;
    while (n < max_flows && n < (1u << 20)) {
        n <<= 1;
    }
    return n;
}

mqvpn_tcp_lane_t *
mqvpn_tcp_lane_new(const mqvpn_hybrid_config_t *cfg, uint64_t hash_seed, void *client_ctx,
                   mqvpn_lwip_clock_fn clock_fn, void *clock_ctx)
{
    if (!cfg) {
        return NULL;
    }
    mqvpn_tcp_lane_t *lane = calloc(1, sizeof(*lane));
    if (!lane) {
        return NULL;
    }
    lane->cfg = *cfg;
    /* Pool-coupling clamp: the lane's cap check below (on_syn) is the
     * documented enforcement point — reject → tcp_abort (RST), never a
     * silent hang — but it is only reachable while lwIP can still allocate
     * pcbs. MEMP_NUM_TCP_PCB backs tracked flows PLUS TIME_WAIT/half-open
     * pcbs the table no longer (or does not yet) count, so a cap above
     * pool/2 lets tcp_alloc() start failing inbound SYNs (no callback, no
     * RST — the inner connection just hangs) before the cap ever fires.
     * Matters on the iOS profile, where the pool (128) sits BELOW the
     * library's default tcp_max_flows (256); on the default profile the
     * bound (512/2 = 256) equals the DEFAULT value, so only explicitly
     * configured values above it are (deliberately) clamped — the caller
     * can compare mqvpn_tcp_lane_effective_max_flows() against its
     * configured value to surface that. */
    if (lane->cfg.tcp_max_flows > MEMP_NUM_TCP_PCB / 2) {
        lane->cfg.tcp_max_flows = MEMP_NUM_TCP_PCB / 2;
    }
    lane->hash_seed = hash_seed;
    lane->client_ctx = client_ctx;
    lane->clock_fn = clock_fn;
    lane->clock_ctx = clock_ctx;
    /* Size for BOTH populations sharing the table: up to tcp_max_flows
     * TCP-lane flows plus up to TCP_LANE_RAW_MARKER_CAP sticky-RAW markers
     * (which are exactly what accumulates in the tcp=auto single-path hot
     * case). Defaults: 256 + 4096 → 8192 buckets = 64 KB of pointers.
     * MUST read the CLAMPED lane->cfg value, not the caller's cfg: sizing
     * from the raw input would let a huge configured value allocate the
     * 2^20-bucket cap (8 MB of pointers — a real dent in the NE memory
     * ceiling) for a table whose admission cap is 64, and a value near
     * UINT32_MAX would wrap the sum to a tiny bucket count. */
    lane->n_buckets = pick_buckets(lane->cfg.tcp_max_flows + TCP_LANE_RAW_MARKER_CAP);
    lane->buckets = calloc(lane->n_buckets, sizeof(*lane->buckets));
    if (!lane->buckets) {
        free(lane);
        return NULL;
    }
    return lane;
}

void
mqvpn_tcp_lane_free(mqvpn_tcp_lane_t *lane)
{
    if (!lane) {
        return;
    }
    for (uint32_t i = 0; i < lane->n_buckets; i++) {
        mqvpn_tcp_flow_t *f = lane->buckets[i];
        while (f) {
            mqvpn_tcp_flow_t *next = f->next;
            /* Glue teardown contract (lwip_glue.h): the lane owns every
             * accepted pcb and must abort them all BEFORE the caller
             * frees the lwip ctx — lwIP's pcb lists are process-global,
             * so an orphaned pcb would survive into a reconnect's new
             * ctx with callback_arg pointing at freed flow memory.
             * Shares the exact detach-then-abort sequence the
             * close/error-mapping paths use below — whole-lane teardown
             * deliberately does NOT also close the H3 side: the caller
             * tears the entire xquic connection down separately (which
             * naturally closes every request, including these). */
            tcp_lane_silent_abort_pcb(f);
            tcp_lane_uplink_queue_free(f);
            tcp_lane_downlink_stash_free(f);
            free(f);
            f = next;
        }
    }
    free(lane->buckets);
    free(lane);
}

static mqvpn_tcp_flow_t *
find_flow(mqvpn_tcp_lane_t *lane, const mqvpn_flow_key_t *key, uint32_t *bucket_out)
{
    uint32_t b =
        (uint32_t)(mqvpn_flow_key_hash(key, lane->hash_seed) & (lane->n_buckets - 1));
    if (bucket_out) {
        *bucket_out = b;
    }
    for (mqvpn_tcp_flow_t *f = lane->buckets[b]; f; f = f->next) {
        if (mqvpn_flow_key_eq(&f->key, key)) {
            return f;
        }
    }
    return NULL;
}

int
mqvpn_tcp_lane_lookup(mqvpn_tcp_lane_t *lane, const mqvpn_flow_key_t *key, int *out_raw,
                      int *out_closing)
{
    if (!lane || !key) {
        return 0;
    }
    mqvpn_tcp_flow_t *f = find_flow(lane, key, NULL);
    if (!f) {
        return 0;
    }
    if (out_raw) {
        *out_raw = (f->state == TCP_FLOW_STICKY_RAW) ? 1 : 0;
    }
    if (out_closing) {
        *out_closing = (f->state == TCP_FLOW_CLOSING) ? 1 : 0;
    }
    return 1;
}

uint32_t
mqvpn_tcp_lane_marker_isn(mqvpn_tcp_lane_t *lane, const mqvpn_flow_key_t *key)
{
    if (!lane || !key) {
        return 0;
    }
    mqvpn_tcp_flow_t *f = find_flow(lane, key, NULL);
    if (!f || f->state != TCP_FLOW_STICKY_RAW) {
        return 0;
    }
    return f->syn_isn;
}

int
mqvpn_tcp_lane_on_syn(mqvpn_tcp_lane_t *lane, const mqvpn_flow_key_t *key, int to_tcp,
                      uint32_t syn_isn)
{
    if (!lane || !key) {
        return -1;
    }

    /* Resolve an existing entry FIRST, before the cap checks below — a
     * stale marker being replaced by a genuinely new connection must not
     * look like a net-new insert against the cap, nor a caller-bug
     * duplicate. Two cases tolerate an existing key here, both requiring
     * the CALLER (tun_decide_lane) to have already confirmed this is a
     * pure SYN before reaching on_syn — this function does not re-verify
     * SYN-ness itself:
     *   - C1: TCP_FLOW_CLOSING — a post-close routing-residency marker;
     *     the prior connection on this 5-tuple already finished.
     *   - I2: TCP_FLOW_STICKY_RAW with a DIFFERENT stored ISN than
     *     `syn_isn` — the caller already compared syn_isn against
     *     mqvpn_tcp_lane_marker_isn's return; a matching ISN (same
     *     handshake retransmitting) is handled entirely by the caller
     *     staying sticky-RAW and never reaching on_syn at all. */
    uint32_t bucket;
    mqvpn_tcp_flow_t *existing = find_flow(lane, key, &bucket);
    if (existing) {
        if (existing->state == TCP_FLOW_CLOSING ||
            existing->state == TCP_FLOW_STICKY_RAW) {
            tcp_lane_remove_flow(lane, existing);
            existing = NULL;
        } else {
            /* Duplicate commit is a caller bug: the protocol is lookup-
             * then-commit, so on_syn must only ever see brand-new keys
             * (or a stale CLOSING/sticky-RAW entry, handled above).
             * Refuse rather than insert a shadowing duplicate. */
            lane->stats.flows_rejected_other++;
            return -1;
        }
    }

    if (to_tcp) {
        /* Reject-before-side-effect: this runs BEFORE lwIP sees the SYN. */
        if (lane->n_tcp_flows >= lane->cfg.tcp_max_flows) {
            lane->stats.flows_rejected_cap++;
            return -1;
        }
    } else {
        /* Marker-cap hit is NOT a TCP-lane rejection (no flows_rejected_cap):
         * the flow simply stays unsticky and re-evaluates on each SYN. */
        if (lane->n_raw_markers >= TCP_LANE_RAW_MARKER_CAP) {
            return -1;
        }
    }
    mqvpn_tcp_flow_t *f = calloc(1, sizeof(*f));
    if (!f) {
        lane->stats.flows_rejected_other++;
        return -1;
    }
    f->key = *key;
    f->state = to_tcp ? TCP_FLOW_PENDING_ACCEPT : TCP_FLOW_STICKY_RAW;
    /* I2: only meaningful for STICKY_RAW markers (mqvpn_tcp_flow_t's field
     * comment) — stored unconditionally anyway, same "harmless, avoids a
     * needless if" rationale as the last_activity_us stamp just below. */
    f->syn_isn = syn_isn;
    /* Stamp-at-creation: without this, a to_tcp=1 flow parked
     * in PENDING_ACCEPT (SYN committed here, but lwIP hasn't yet driven the
     * accept callback that would otherwise stamp it — see
     * mqvpn_tcp_lane_lwip_accept below) carries last_activity_us == 0 from
     * calloc and would be evicted on the very first idle sweep regardless of
     * its true age. Stamped unconditionally (both to_tcp values, not just
     * to_tcp=1) rather than branching: sticky-RAW markers are excluded from
     * the sweep by f->state == TCP_FLOW_STICKY_RAW regardless of what
     * last_activity_us holds, so stamping them too costs nothing and avoids
     * a needless if. Same NULL-tolerant clock idiom as every other stamp
     * site in this file. */
    f->last_activity_us = lane->clock_fn ? lane->clock_fn(lane->clock_ctx) : 0;
    if (to_tcp) {
        /* The idle sweep can now reach a PENDING_ACCEPT flow (SYN
         * committed, lwIP hasn't yet driven the accept callback) through the
         * teardown funnel (tcp_lane_teardown_flow -> tcp_lane_remove_flow),
         * which dereferences f->lane and asserts it non-NULL. Previously
         * f->lane was set ONLY in mqvpn_tcp_lane_lwip_accept, because every
         * OTHER teardown call site only ever ran on a flow that had already
         * reached that callback. Set it here instead — the accept callback's
         * own `f->lane = lane` assignment becomes a harmless re-affirmation
         * of the same value. Sticky-RAW markers deliberately do NOT get
         * this: they never reach the teardown funnel at all (excluded from
         * the sweep by state, and never bound to a pcb/h3_request — see
         * tcp_lane_remove_flow's STICKY_RAW comment), so the "f->lane ==
         * NULL for markers" invariant documented in tcp_lane_internal.h
         * stays intact. */
        f->lane = lane;
    }

    f->next = lane->buckets[bucket];
    lane->buckets[bucket] = f;
    lane->stats.flows_total++;
    if (to_tcp) {
        lane->n_tcp_flows++;
    } else {
        lane->n_raw_markers++;
    }
    return 0;
}

/* Idle-timeout eviction sweep + CLOSING routing-marker grace
 * sweep (C1) — one bucket walk serves both. Runs from mqvpn_client_tick,
 * i.e. neither a lwIP-invoked frame nor an xquic-context notify: this is a
 * THIRD calling context tcp_lane_flow_status_t's contract never
 * anticipated, but the existing xquic-context idiom already fits — there
 * is no ERR_ABRT to translate and no xquic frame to avoid re-entering, so
 * the idle-eviction status is simply discarded (void-cast), same as
 * on_stream_rejected/on_h3_closing/on_h3_writable above.
 *
 * The two sweeps are independently gated: cfg.tcp_idle_timeout_sec == 0
 * ("never evict" — classifier.h's field comment documents tcp_lane as the
 * consumer; a deliberate opt-out, e.g. a deployment that wants tcp=stream
 * flows to live for the whole connection lifetime, not an instant-timeout
 * footgun) disables ONLY the idle-eviction half. The CLOSING grace sweep
 * is a DIFFERENT mechanism with a different rationale (bounding routing-
 * marker residency, not relay-flow idleness) and must keep running
 * regardless — see the doc note below for why this matters even when
 * tcp_idle_timeout_sec == 0. */
void
mqvpn_tcp_lane_tick(mqvpn_tcp_lane_t *lane, uint64_t now_us)
{
    if (!lane) {
        return;
    }
    /* Nothing evictable by EITHER sweep: markers (STICKY_RAW) are excluded
     * from both regardless of population, so an idle lane with no
     * TCP-lane flows and no CLOSING residency has no work — skip the
     * bucket walk entirely. Checked before the cadence gate so a fully
     * idle lane never even consumes a last_sweep_us update.
     *
     * Doc note: PENDING_ACCEPT flows also rely on this sweep to be
     * reaped if the accept callback never arrives (a half-open SYN whose
     * lwIP accept callback is somehow lost) — with
     * cfg.tcp_idle_timeout_sec == 0, such an orphan lingers for the
     * connection's whole lifetime and consumes a tcp_max_flows slot. This
     * is a SEPARATE, pre-existing tradeoff of the 0 opt-out (not something
     * C1's n_closing accounting mitigates — n_closing only tracks CLOSING
     * routing markers, which PENDING_ACCEPT flows never become); documented
     * here rather than changed, since 0 is an intentional "never evict my
     * relay flows" choice a deployment opts into. */
    if (lane->n_tcp_flows == 0 && lane->n_closing == 0) {
        return;
    }
    /* Cadence gate: the caller (mqvpn_client_tick) fires per event-loop
     * iteration — including after every recv batch, i.e. potentially
     * thousands of times per second under load — while eviction has
     * seconds-granularity semantics. An ungated sweep walks all n_buckets
     * heads (64 KB of pointer touches at the default sizing) every call:
     * pure hot-path cache pollution. Gate it internally to at most once per
     * second, keeping the caller dumb — the same pattern as lwip_glue.c's
     * internal 250 ms tcp_tmr gate. Wraparound/backwards-clock note: if
     * now_us regresses below last_sweep_us, the unsigned difference goes
     * huge and the sweep RUNS — harmless (the per-flow age tests below are
     * independently underflow-guarded), and it self-heals by re-latching
     * last_sweep_us to the new clock. */
    if (now_us - lane->last_sweep_us < 1000000ULL) {
        return;
    }
    lane->last_sweep_us = now_us;
    int idle_evict_enabled = lane->cfg.tcp_idle_timeout_sec != 0;
    uint64_t idle_us = (uint64_t)lane->cfg.tcp_idle_timeout_sec * 1000000ULL;
    for (uint32_t b = 0; b < lane->n_buckets; b++) {
        mqvpn_tcp_flow_t *f = lane->buckets[b];
        while (f) {
            /* tcp_lane_teardown_flow / tcp_lane_remove_flow
             * unlink and free f — save next BEFORE either call, never
             * dereference f again afterward. */
            mqvpn_tcp_flow_t *next = f->next;
            if (f->state == TCP_FLOW_CLOSING) {
                /* C1 grace sweep: a CLOSING entry is pure routing residency
                 * (no relay resource to reclaim, no teardown funnel needed
                 * — pcb already NULL, h3_request/stream already cleared by
                 * tcp_lane_finish_clean_close) — plain unlink+free is safe.
                 * Wraparound-safe age test, same form as the idle-eviction
                 * one below. */
                if (now_us > f->last_activity_us &&
                    now_us - f->last_activity_us > TCP_LANE_CLOSING_GRACE_US) {
                    tcp_lane_remove_flow(lane, f);
                }
            } else if (idle_evict_enabled && f->state != TCP_FLOW_STICKY_RAW &&
                       now_us > f->last_activity_us &&
                       now_us - f->last_activity_us > idle_us) {
                /* STICKY_RAW is excluded by design (never idle-evicted —
                 * see the marker-cap comment on TCP_LANE_RAW_MARKER_CAP
                 * above: markers must outlive the sweep or a tcp=auto
                 * single-path client would permanently thrash the RAW/TCP
                 * verdict). Wraparound-safe age test, same form as
                 * reorder_tx.c's evict_one_idle: a backwards-clock blip
                 * (now_us < last_activity_us) must not underflow and
                 * spuriously evict a live flow. */
                lane->stats.flows_idle_evicted++; /* before teardown frees f */
                (void)tcp_lane_teardown_flow(f, /*close_h3=*/1);
            } else if (f->downlink_paused) {
                /* I3: the sent-notify driver (mqvpn_tcp_lane_on_lwip_sent)
                 * only fires if THIS pcb still has un-ACKed data in flight,
                 * and the xquic-context driver (tcp_lane_downlink_pump_status's
                 * paused branch) only fires on a new READ_BODY/EMPTY_FIN
                 * notify — if the flow's own sndbuf is already empty (no
                 * more ACKs coming) AND xquic's per-stream flow-control
                 * window has filled (we stopped consuming recv_body, so
                 * those notifies stopped too), NEITHER driver ever fires
                 * again and the flow would stall holding its stash until
                 * idle eviction (or forever with tcp_idle_timeout_sec == 0).
                 * This 1 Hz sweep is the guaranteed third retry driver —
                 * same retry-then-resume-drain idiom as the pump's paused
                 * branch above (tcp_lane_downlink_pump_status,
                 * ~line 699). */
                tcp_lane_flow_status_t st = tcp_lane_downlink_stash_retry(f);
                if (st == TCP_LANE_FLOW_LIVE && !f->downlink_paused &&
                    f->state == TCP_FLOW_ACTIVE && f->h3_request && f->pcb) {
                    /* Stash flushed — resume draining recv_body, same as the
                     * pump's paused branch does after a successful retry. */
                    st = tcp_lane_downlink_drain(f);
                }
                if (st != TCP_LANE_FLOW_LIVE) {
                    /* A non-LIVE status here means `f` was either freed
                     * (ABORTED — a fatal retry/drain error tore it down) OR
                     * transitioned to a CLOSING routing marker still in the
                     * table (GONE via a clean bidi-FIN reached from the
                     * resumed drain: tcp_lane_downlink_maybe_shutdown ->
                     * tcp_lane_finish_clean_close -> tcp_lane_mark_closing).
                     * The saved `next` is NOT safe to trust in the GONE case:
                     * mark_closing, when n_closing is already at
                     * TCP_LANE_CLOSING_CAP, calls
                     * tcp_lane_evict_oldest_closing which frees the
                     * GLOBALLY-oldest CLOSING flow — an ARBITRARY node that
                     * may be `next` itself (same bucket) or any other
                     * still-to-be-visited entry. This is the ONE tick path
                     * that can free a flow OTHER than the current `f` (idle
                     * eviction and the CLOSING grace sweep above only ever
                     * free `f` itself, which the saved-`next` idiom handles).
                     * Restart this bucket from its head rather than
                     * dereferencing a possibly-freed `next`: flows already
                     * handled this tick are naturally skipped by the branch
                     * guards (a no-longer-paused/no-longer-idle flow won't
                     * re-enter these branches; the idle re-check is
                     * idempotent within one tick), and with load factor < 1
                     * over 8192 buckets a bucket holds ~1 entry so the
                     * restart is effectively O(1). The ABORTED case (only
                     * `f` freed) is also correctly handled by the restart —
                     * `f` is already unlinked, so re-walking from head simply
                     * skips it. */
                    f = lane->buckets[b];
                    continue;
                }
            }
            f = next;
        }
    }
}

void
mqvpn_tcp_lane_get_stats(const mqvpn_tcp_lane_t *lane, mqvpn_tcp_lane_stats_t *out)
{
    if (!lane || !out) {
        return;
    }
    *out = lane->stats;
    /* Gauges are DERIVED from the live counters, not tracked in parallel:
     * removal sites only maintain n_tcp_flows/n_raw_markers
     * and can never leave the stats snapshot out of sync. */
    out->flows_active = lane->n_tcp_flows;
    out->raw_markers_active = lane->n_raw_markers;
}

uint32_t
mqvpn_tcp_lane_effective_max_flows(const mqvpn_tcp_lane_t *lane)
{
    return lane ? lane->cfg.tcp_max_flows : 0;
}

uint32_t
mqvpn_tcp_lane_pool_flow_bound(void)
{
    return MEMP_NUM_TCP_PCB / 2;
}

/* ─── Downlink relay: H3 recv_body → lwIP tcp_write ─── */

/* Save one just-read, not-yet-writable chunk. Lazily allocates the flow's
 * single stash slot (kept for the flow's lifetime once allocated — see the
 * field comment on mqvpn_tcp_flow_t). Returns -1 only on malloc failure,
 * which the caller must treat as fatal: these bytes were already
 * destructively pulled out of xquic's recv_body and cannot be re-fetched,
 * so losing them here would silently corrupt the relayed stream (same
 * "already-committed, cannot undo" hazard the uplink side's alloc-failure
 * path documents). */
static int
tcp_lane_downlink_stash(mqvpn_tcp_flow_t *f, const uint8_t *buf, uint16_t len)
{
    if (!f->downlink_stash) {
        f->downlink_stash = malloc(TCP_MSS);
        if (!f->downlink_stash) {
            return -1;
        }
    }
    memcpy(f->downlink_stash, buf, len);
    f->downlink_stash_len = len;
    return 0;
}

static void
tcp_lane_downlink_stash_free(mqvpn_tcp_flow_t *f)
{
    free(f->downlink_stash);
    f->downlink_stash = NULL;
    f->downlink_stash_len = 0;
}

/* Fin observed from cli_tcp_lane_h3_recv (with or without accompanying data
 * in the same call — see the MQVPN_TCP_LANE_H3_RECV_* contract). TX-side
 * half-close only (shut_rx=0): the inner app's peer may still have more to
 * say in the OTHER direction. Idempotent via fin_received_from_h3 —
 * tcp_shutdown must fire exactly once per pcb (vendored tcp.c's
 * tcp_close_shutdown switches on pcb->state, which tcp_shutdown itself
 * transitions away from FIN-capable states).
 *
 * Failure semantics, verified against the vendored tcp.c: for the states we
 * can be in here (ESTABLISHED / CLOSE_WAIT / SYN_RCVD), a FIN-enqueue
 * allocation failure NEVER surfaces at this call site —
 * tcp_close_shutdown_fin swallows tcp_send_fin's ERR_MEM into ERR_OK and
 * latches TF_CLOSEPEND instead (tcp.c:449-457). The pending FIN is then
 * retried by tcp_fasttmr's "send pending FIN" pass (tcp.c:1522-1526; runs
 * on every tcp_tmr, tcp.c:237 — i.e. within one ~250 ms tick of our manual
 * cadence, lwip_glue.c) and opportunistically by tcp_handle_closepend when
 * pcb allocation fails (tcp.c:1840-1842, called from tcp_alloc,
 * tcp.c:1864-1865). Net: under memory pressure the FIN is silently
 * DEFERRED, not delivered-or-errored — we set fin_received_from_h3 and move
 * on with no detection hook, an accepted OOM-adjacent edge (bounded by the
 * timer retry; worst case the peer's read blocks until the FIN lands or its
 * own timeout fires). The only real non-OK return reachable here is
 * ERR_CONN (pcb no longer in a shutdown-eligible state — tcp.c:537-549, or
 * LISTEN, tcp.c:521-523): that FIN can never be sent, so it routes to
 * on_relay_error (returns -1). The route covers ANY non-OK return as cheap
 * future-proofing against vendored-lwIP changes.
 *
 * Return (tcp_lane_flow_status_t): LIVE on success with nothing further to
 * do; non-LIVE if `f` was torn down inside this call and must not be
 * touched again — ABORTED for a fatal error (mqvpn_tcp_lane_on_relay_error
 * tcp_abort()ed the pcb: the enclosing lwIP frame, if any, must return
 * ERR_ABRT) or GONE when, per the semantics documented below, both directions just
 * completed a clean bidi FIN (tcp_lane_finish_clean_close — pcb gracefully
 * tcp_close()d, NOT freed, so ERR_OK stays correct). Callers
 * (tcp_lane_downlink_drain) treat any non-LIVE as "stop, don't touch f,
 * propagate up" — see mqvpn_tcp_lane_downlink_pump's header comment for
 * why neither status must ever become an xquic stream/connection error. */
static tcp_lane_flow_status_t
tcp_lane_downlink_maybe_shutdown(mqvpn_tcp_flow_t *f)
{
    if (f->fin_received_from_h3) {
        return TCP_LANE_FLOW_LIVE;
    }
    f->fin_received_from_h3 = 1;
    err_t err = MQVPN_TCP_LANE_TCP_SHUTDOWN(f->pcb, 0, 1);
    if (err != ERR_OK) {
        return mqvpn_tcp_lane_on_relay_error(f);
    }
    if (f->fin_sent_to_h3) {
        /* The uplink direction already forwarded ITS FIN
         * to H3 (tcp_lane_uplink.c's maybe_fin) before this one completed —
         * both directions are now cleanly closed. */
        tcp_lane_finish_clean_close(f);
        return TCP_LANE_FLOW_GONE;
    }
    return TCP_LANE_FLOW_LIVE;
}

/* Drain the flow's H3 response body into lwIP. Stops at the first
 * would-block (MQVPN_TCP_LANE_H3_RECV_AGAIN — nothing more buffered right
 * now; the next READ_BODY/EMPTY_FIN notify re-fires) or the first
 * sndbuf/ERR_MEM backpressure signal (stash the chunk, latch
 * downlink_paused, stop — mirrors the uplink's EAGAIN-stops-the-loop
 * design). A fatal recv/write error (ABORTED) OR a clean bidi-FIN
 * completion (GONE — see tcp_lane_downlink_maybe_shutdown above) stops the
 * drain with `f` already freed; see mqvpn_tcp_lane_downlink_pump's header
 * comment for why callers must not propagate either into an xquic
 * stream/connection error, and mqvpn_tcp_lane_on_lwip_sent for the one
 * caller that DOES need the ABORTED/GONE distinction (ERR_ABRT).
 * tcp_output is called AT MOST ONCE, after the loop — lwIP defers actual
 * segment transmission to tcp_output/tcp_tmr (vendored tcp_out.c: tcp_write
 * only appends to the unsent list), and with LWIP_TIMERS=0 the manual
 * tcp_tmr cadence (lwip_glue.c, every 250 ms) would otherwise sit on
 * freshly-written downlink data for up to that long. */
static tcp_lane_flow_status_t
tcp_lane_downlink_drain(mqvpn_tcp_flow_t *f)
{
    uint8_t buf[TCP_MSS];
    int wrote_any = 0;

    for (;;) {
        int fin = 0;
        ssize_t n = cli_tcp_lane_h3_recv(f->h3_request, buf, sizeof(buf), &fin);
        if (n == MQVPN_TCP_LANE_H3_RECV_AGAIN) {
            break;
        }
        if (n == MQVPN_TCP_LANE_H3_RECV_ERR) {
            return mqvpn_tcp_lane_on_relay_error(f);
        }
        /* Contract pin (tcp_lane.h H3_RECV): a non-AGAIN/ERR return is
         * either data (n > 0) or a fin-only delivery (n == 0 && fin) —
         * a bare n == 0 without fin would spin this loop forever.
         *
         * This used to be assert(n > 0 || fin), but Release builds
         * (build.sh) compile with NDEBUG, silently no-op'ing the check —
         * a future xquic behavior change violating this contract (this
         * repo bumps its xquic submodule regularly) would spin the tick
         * loop instead of failing loud. Treat a violation as a fatal
         * relay error instead: same "tear the flow down" outcome as every
         * other h3_recv/pcb failure in this loop, just triggered by a
         * contract violation rather than an I/O error. */
        if (n <= 0 && !fin) {
            return mqvpn_tcp_lane_on_relay_error(f);
        }
        if (n > 0) {
            if ((size_t)MQVPN_TCP_LANE_TCP_SNDBUF(f->pcb) < (size_t)n) {
                if (tcp_lane_downlink_stash(f, buf, (uint16_t)n) < 0) {
                    return mqvpn_tcp_lane_on_relay_error(f);
                }
                f->downlink_paused = 1;
                break;
            }
            err_t werr =
                MQVPN_TCP_LANE_TCP_WRITE(f->pcb, buf, (uint16_t)n, TCP_WRITE_FLAG_COPY);
            if (werr == ERR_MEM) {
                /* Transient — the write_checks gate (queuelen or a stricter
                 * internal check than the sndbuf test above) said not now.
                 * Same stash-and-pause handling as the sndbuf gate. */
                if (tcp_lane_downlink_stash(f, buf, (uint16_t)n) < 0) {
                    return mqvpn_tcp_lane_on_relay_error(f);
                }
                f->downlink_paused = 1;
                break;
            }
            if (werr != ERR_OK) {
                return mqvpn_tcp_lane_on_relay_error(f);
            }
            wrote_any = 1;
        }
        if (fin) {
            tcp_lane_flow_status_t st = tcp_lane_downlink_maybe_shutdown(f);
            if (st != TCP_LANE_FLOW_LIVE) {
                return st; /* f torn down (relay error OR clean-close) above */
            }
            break; /* request fully consumed; nothing more to read */
        }
    }

    if (wrote_any) {
        MQVPN_TCP_LANE_TCP_OUTPUT(f->pcb);
    }
    return TCP_LANE_FLOW_LIVE;
}

/* Attempt to flush the flow's one stashed downlink chunk into the pcb —
 * the exact retry mqvpn_tcp_lane_on_lwip_sent performs, factored out
 * so tcp_lane_downlink_pump_status's paused branch below can ALSO attempt
 * it inline instead of unconditionally waiting for a sent-notify that may
 * never arrive (an ERR_MEM'd retry has nothing further to be ACKed if
 * nothing further was ever written — ACKs, and therefore tcp_sent
 * notifies, only happen for data already on the wire). PRECONDITION:
 * f->downlink_paused is true (both call sites check this first).
 *
 * Returns LIVE with downlink_paused cleared on success, LIVE with
 * downlink_paused still set if there still isn't room (retry later), or
 * the teardown status (ABORTED — GONE cannot happen here, f->pcb is
 * always live on entry) if the retry write failed fatally. */
static tcp_lane_flow_status_t
tcp_lane_downlink_stash_retry(mqvpn_tcp_flow_t *f)
{
    if ((size_t)MQVPN_TCP_LANE_TCP_SNDBUF(f->pcb) < (size_t)f->downlink_stash_len) {
        return TCP_LANE_FLOW_LIVE; /* still not enough room; wait and retry later */
    }
    err_t werr = MQVPN_TCP_LANE_TCP_WRITE(f->pcb, f->downlink_stash,
                                          f->downlink_stash_len, TCP_WRITE_FLAG_COPY);
    if (werr == ERR_MEM) {
        return TCP_LANE_FLOW_LIVE; /* transient; retry later */
    }
    if (werr != ERR_OK) {
        return mqvpn_tcp_lane_on_relay_error(f);
    }
    MQVPN_TCP_LANE_TCP_OUTPUT(f->pcb);
    f->downlink_stash_len = 0;
    f->downlink_paused = 0;
    return TCP_LANE_FLOW_LIVE;
}

/* Status-returning pump core. The public mqvpn_tcp_lane_downlink_pump
 * below collapses this to its documented 0/-1 contract for xquic-context
 * callers; mqvpn_tcp_lane_on_lwip_sent calls THIS directly because a lwIP
 * frame needs the ABORTED/GONE distinction (ERR_ABRT vs ERR_OK — see
 * tcp_lane_flow_status_t). */
static tcp_lane_flow_status_t
tcp_lane_downlink_pump_status(mqvpn_tcp_lane_t *lane, void *stream)
{
    if (!lane || !stream) {
        return TCP_LANE_FLOW_LIVE;
    }
    mqvpn_tcp_flow_t *f = find_flow_by_stream(lane, stream);
    if (!f) {
        return TCP_LANE_FLOW_LIVE;
    }
    /* CLOSING: belt-and-suspenders only — a CLOSING flow's f->stream is
     * always NULL (tcp_lane_finish_clean_close clears it before the
     * transition), so find_flow_by_stream above can never actually match
     * one; a real caller always passes a non-NULL stream. Kept as a guard
     * against a future change to that invariant. */
    if (f->state == TCP_FLOW_CLOSING) {
        return TCP_LANE_FLOW_LIVE;
    }
    /* Paused: this entry point is called from BOTH xquic-context notifies
     * (READ_BODY/EMPTY_FIN — more response body became available upstream,
     * independent of any TCP-side event) and the lwIP sent-notify resume
     * path below. Attempt the stash retry inline here too (guarded —
     * calls tcp_lane_downlink_stash_retry directly, never recurses back
     * into this function) rather than only reacting to sent-notifies: an
     * ERR_MEM'd retry must not be stranded until a sent-notify that may
     * never come (nothing further gets ACKed, hence no further tcp_sent
     * fires, if nothing further was ever written while paused). */
    if (f->downlink_paused) {
        tcp_lane_flow_status_t st = tcp_lane_downlink_stash_retry(f);
        if (st != TCP_LANE_FLOW_LIVE) {
            return st; /* f torn down (fatal write error) */
        }
        if (f->downlink_paused) {
            /* Still not enough sndbuf room — this xquic-side notify alone
             * can't force it open; wait for the next lwIP sent-notify. Not
             * data loss: xquic's own per-stream flow control backpressures
             * the server the same way the uplink's EAGAIN path does in the
             * other direction. A FIN cannot be lost across the pause,
             * in either shape: (a) fin still UNREAD in xquic's buffer at
             * pause time — the resumed drain simply reaches it on a later
             * recv call; (b) fin already READ, arriving ON the very chunk
             * that got stashed (n>0 && fin) — the drain's stash path DOES
             * discard that local fin flag (it breaks before the fin
             * check), deliberately relying on recv's level-triggered
             * re-report at the resumed drain (MQVPN_TCP_LANE_H3_RECV_*
             * contract in tcp_lane.h: xquic re-reports *fin=1 on every
             * call once the transport FIN arrived,
             * xqc_h3_request.c:795-801). */
            return TCP_LANE_FLOW_LIVE;
        }
        /* Stash flushed — fall through to resume draining recv_body below,
         * same as the sent-notify resume path always did. */
    }
    if (f->state != TCP_FLOW_ACTIVE || !f->h3_request || !f->pcb) {
        return TCP_LANE_FLOW_LIVE;
    }
    return tcp_lane_downlink_drain(f);
}

int
mqvpn_tcp_lane_downlink_pump(mqvpn_tcp_lane_t *lane, void *stream)
{
    /* Public 0/-1 contract (tcp_lane.h): callers here are xquic-context
     * (READ_BODY/EMPTY_FIN notify) — they only need "flow no longer live"
     * and must not forward it to xquic as an error; the finer
     * ABORTED-vs-GONE distinction is a lwIP-frame concern only. */
    return tcp_lane_downlink_pump_status(lane, stream) == TCP_LANE_FLOW_LIVE ? 0 : -1;
}

/* Real downlink resume: once sndbuf recovers enough to fit the
 * stashed chunk, flush it and resume draining recv_body. lwIP-invoked
 * frame: any teardown that tcp_abort()s f->pcb inside this call MUST
 * surface as ERR_ABRT — on ERR_OK, tcp_in.c's TCP_EVENT_SENT site
 * continues into recv_data/TF_GOT_FIN/tcp_output on the freed pcb
 * (tcp_lane_flow_status_t contract, tcp_lane_internal.h). Two such spots
 * below: the stash-rewrite fatal and the resumed drain's fatal. A GONE
 * teardown (clean bidi-FIN inside the resumed drain — pcb tcp_close()d,
 * not freed) correctly stays ERR_OK. */
static err_t
mqvpn_tcp_lane_on_lwip_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    (void)len;
    mqvpn_tcp_flow_t *f = (mqvpn_tcp_flow_t *)arg;
    if (!f) {
        return ERR_OK;
    }
    (void)pcb; /* f->pcb is the same pointer; kept for signature parity */

    /* Activity signal, same rationale as on_lwip_recv's stamp. */
    if (f->lane && f->lane->clock_fn) {
        f->last_activity_us = f->lane->clock_fn(f->lane->clock_ctx);
    }

    if (!f->downlink_paused) {
        return ERR_OK;
    }
    /* The retry itself is shared with tcp_lane_downlink_pump_status's
     * paused branch (tcp_lane_downlink_stash_retry) — this frame is the
     * ORIGINAL driver of that retry (a sent-notify is the one real signal
     * that sndbuf room may have opened up). */
    tcp_lane_flow_status_t rst = tcp_lane_downlink_stash_retry(f);
    if (rst != TCP_LANE_FLOW_LIVE) {
        /* f torn down (fatal write error). GONE is not actually reachable
         * from this helper (f->pcb is always live entering it — see its
         * own comment), but treat it the same defensively rather than
         * assume. */
        return rst == TCP_LANE_FLOW_ABORTED ? ERR_ABRT : ERR_OK;
    }
    if (f->downlink_paused) {
        return ERR_OK; /* still not enough room; wait for the next sent notify */
    }

    /* Resume draining recv_body via the status-returning pump core (same
     * single "pump the downlink" code path as the public entry point, but
     * this lwIP frame needs the ABORTED distinction the public 0/-1
     * contract deliberately collapses). f->lane/f->stream are stable for
     * the lifetime of an ACTIVE flow. */
    if (tcp_lane_downlink_pump_status(f->lane, f->stream) == TCP_LANE_FLOW_ABORTED) {
        return ERR_ABRT;
    }
    return ERR_OK;
}

/* ─── Close/error mapping + flow removal ───
 *
 * Every path that decides a flow is dead funnels through
 * tcp_lane_teardown_flow (locally-initiated: we detach + tcp_abort the pcb
 * ourselves) or tcp_lane_finish_clean_close (a clean bidi-FIN completion —
 * see its own comment). mqvpn_tcp_lane_on_lwip_err is the ONE exception:
 * lwIP itself already freed the pcb before invoking it (see its comment).
 *
 * Re-entrancy hazard: tcp_abort (vendored tcp.c ->
 * tcp_abandon) frees the pcb and THEN synchronously invokes the pcb's own
 * err callback (mqvpn_tcp_lane_on_lwip_err) with ERR_ABRT — clearing
 * tcp_err(pcb, NULL) first (tcp_lane_silent_abort_pcb below) makes
 * tcp_priv.h's TCP_EVENT_ERR macro a no-op (`if (errf != NULL)`), so a
 * self-initiated abort never re-enters here. This is why every LOCAL kill
 * detaches callbacks BEFORE calling tcp_abort, never after. */

/* Returns 1 if a live pcb was tcp_abort()ed (the enclosing lwIP-invoked
 * frame, if any, must then return ERR_ABRT — tcp_lane_flow_status_t's
 * contract in tcp_lane_internal.h), 0 if there was no pcb to abort. */
static int
tcp_lane_silent_abort_pcb(mqvpn_tcp_flow_t *f)
{
    if (!f->pcb) {
        return 0;
    }
    tcp_arg(f->pcb, NULL);
    tcp_recv(f->pcb, NULL);
    tcp_sent(f->pcb, NULL);
    tcp_err(f->pcb, NULL);
    MQVPN_TCP_LANE_TCP_ABORT(f->pcb);
    f->pcb = NULL;
    return 1;
}

/* RST the H3 side (best-effort — the caller has already decided the flow is
 * dead regardless of the outcome) and guard against a double-close: once
 * called, f->h3_request/f->stream are cleared so a later teardown call on
 * the same (about-to-be-removed) flow is a no-op here. */
static void
tcp_lane_close_h3(mqvpn_tcp_flow_t *f)
{
    if (f->h3_request) {
        cli_tcp_lane_h3_close(f->h3_request);
        f->h3_request = NULL;
        f->stream = NULL;
    }
}

/* The one locally-initiated "kill this flow" sequence:
 * (1) RST the H3 request (close_h3=1) or just forget the pointers without
 * closing (close_h3=0 — the caller already closed it, or
 * never created one); (2) detach + tcp_abort the pcb; (3) unlink + free the
 * flow. Used by on_relay_error, abort_pending, on_h3_closing, and
 * on_stream_rejected — see each call site's comment for which close_h3
 * value applies and why.
 *
 * Returns ABORTED when step (2) actually tcp_abort()ed a live pcb, GONE
 * when there was none — the caller chain must carry this to the enclosing
 * lwIP-invoked frame (if any), which returns ERR_ABRT on ABORTED; see
 * tcp_lane_flow_status_t (tcp_lane_internal.h) for the lwIP contract this
 * implements. */
static tcp_lane_flow_status_t
tcp_lane_teardown_flow(mqvpn_tcp_flow_t *f, int close_h3)
{
    if (close_h3) {
        tcp_lane_close_h3(f);
    } else {
        f->h3_request = NULL;
        f->stream = NULL;
    }
    int aborted = tcp_lane_silent_abort_pcb(f);
    tcp_lane_remove_flow(f->lane, f);
    return aborted ? TCP_LANE_FLOW_ABORTED : TCP_LANE_FLOW_GONE;
}

/* Unlink f from its hash bucket, free its uplink queue + downlink stash,
 * decrement the matching population counter, and free f. Callers must have
 * already cleared f->pcb (tcp_lane_teardown_flow / tcp_lane_finish_
 * clean_close both do) — this function does not touch the pcb.
 *
 * Idempotence: every caller reaches this via a flow
 * pointer it just found (find_flow_by_stream) or was handed directly
 * (tcp_arg) — never a re-lookup after a prior removal — so a flow is never
 * torn down twice from the SAME event. Two DIFFERENT events racing for the
 * same flow (e.g. the H3 side rejects it the same tick lwIP RSTs it) can't
 * happen either: once the first event's tcp_lane_silent_abort_pcb clears
 * tcp_arg(pcb, NULL), the flow is unreachable as a callback argument, and
 * once removed here, the SECOND event's own find_flow_by_stream lookup (the
 * only other way to reach a flow) simply misses — a lookup miss is exactly
 * every public API function's existing no-op contract, not a new case to
 * handle.
 *
 * Sticky-RAW markers are unreachable through the FOUR TEARDOWN call sites
 * above (on_relay_error, abort_pending, on_h3_closing, on_stream_rejected,
 * all funneled through tcp_lane_teardown_flow): they have no pcb and never
 * bind an h3_request/stream (mqvpn_tcp_lane_bind_h3_request is only ever
 * called from the accept callback's stream-open path), so none of those
 * four can ever reach here with f->state == TCP_FLOW_STICKY_RAW — for
 * THEM the branch below is defensive completeness (matches lane_free's
 * separate, correct handling of markers via the plain free() in its own
 * loop), not a path the close/error-mapping teardown exercises.
 *
 * I2 DOES reach here directly with a STICKY_RAW f, bypassing
 * tcp_lane_teardown_flow entirely (no pcb/H3 side to detach) — see
 * mqvpn_tcp_lane_on_syn's stale-marker-replacement branch. Same shape as
 * C1's CLOSING removal just below it in that function. */
static void
tcp_lane_remove_flow(mqvpn_tcp_lane_t *lane, mqvpn_tcp_flow_t *f)
{
    /* Loud, not lenient: a NULL lane here would mean a teardown path ran on
     * a flow that never went through the accept callback (the only place
     * f->lane is set) — silently returning would LEAK f (its queue/stash
     * too) and desync the population counters. Every real caller passes a
     * non-NULL pair by construction; crash-fast in release, assert in
     * debug. */
    assert(lane != NULL);
    assert(f != NULL);
    uint32_t b =
        (uint32_t)(mqvpn_flow_key_hash(&f->key, lane->hash_seed) & (lane->n_buckets - 1));
    mqvpn_tcp_flow_t **pp = &lane->buckets[b];
    while (*pp && *pp != f) {
        pp = &(*pp)->next;
    }
    if (*pp == f) {
        *pp = f->next;
    }
    if (f->state == TCP_FLOW_STICKY_RAW) {
        lane->n_raw_markers--;
    } else if (f->state == TCP_FLOW_CLOSING) {
        /* C1: a CLOSING routing marker was already excluded from
         * n_tcp_flows at the mark_closing transition — decrement its OWN
         * counter here instead, whether this removal is the grace sweep,
         * cap eviction, or tuple-reuse-after-close (on_syn). */
        lane->n_closing--;
    } else {
        lane->n_tcp_flows--;
    }
    tcp_lane_uplink_queue_free(f);
    tcp_lane_downlink_stash_free(f);
    free(f);
}

/* C1: evict the single OLDEST CLOSING routing marker (smallest
 * last_activity_us) to make room under TCP_LANE_CLOSING_CAP. A full
 * bucket walk is acceptable here — this only runs at cap-overflow
 * frequency (churn bound by TCP_LANE_CLOSING_CAP itself), not per-packet
 * or per-tick. Never called when n_closing == 0 (see the only call site,
 * tcp_lane_mark_closing), so `oldest` is always found. */
static void
tcp_lane_evict_oldest_closing(mqvpn_tcp_lane_t *lane)
{
    mqvpn_tcp_flow_t *oldest = NULL;
    for (uint32_t b = 0; b < lane->n_buckets; b++) {
        for (mqvpn_tcp_flow_t *f = lane->buckets[b]; f; f = f->next) {
            if (f->state == TCP_FLOW_CLOSING &&
                (!oldest || f->last_activity_us < oldest->last_activity_us)) {
                oldest = f;
            }
        }
    }
    if (oldest) {
        tcp_lane_remove_flow(lane, oldest);
    }
}

/* C1: transition f (already detached from the pcb/H3 side by the caller —
 * tcp_lane_finish_clean_close) into TCP_FLOW_CLOSING routing-marker
 * residency: stays in the table, stops counting toward n_tcp_flows, starts
 * counting toward n_closing, and is stamped so the grace sweep
 * (mqvpn_tcp_lane_tick) and cap eviction (this function) can age it.
 *
 * Also releases the downlink stash here rather than leaving it to
 * tcp_lane_remove_flow: a CLOSING marker can reside for up to 2*TCP_MSL
 * (TCP_LANE_CLOSING_GRACE_US) before the grace sweep frees it, and holding
 * a live flow's ~TCP_MSS stash for that whole window would blow the
 * ~0.82 MB "CLOSING entries are cheap" bound this table's cap comment
 * relies on (TCP_LANE_CLOSING_CAP above). Safe to free now: the only caller is
 * tcp_lane_finish_clean_close, reached from whichever direction observes
 * the SECOND FIN of a clean bidi close — either the downlink side
 * (tcp_lane_downlink_maybe_shutdown, here in this TU) or the uplink side
 * (tcp_lane_uplink.c's maybe_fin). Both require fin_received_from_h3, and
 * that flag is only set once the downlink drain has fully consumed the H3
 * response and shut the pcb down — which can only happen with
 * f->downlink_paused == 0 (the pump never lets tcp_lane_downlink_drain run,
 * and therefore never reaches the fin-handling branch that calls
 * maybe_shutdown, while a stash retry is still pending). So
 * downlink_stash_len is always 0 here regardless of which direction drove
 * the close; any allocated buffer is just an idle cached slot (see its
 * field comment, tcp_lane_internal.h) that will never be consumed again
 * from CLOSING residency onward — pure routing residency has no relay
 * left to drain. */
static void
tcp_lane_mark_closing(mqvpn_tcp_flow_t *f)
{
    mqvpn_tcp_lane_t *lane = f->lane;
    if (lane->n_closing >= TCP_LANE_CLOSING_CAP) {
        tcp_lane_evict_oldest_closing(lane);
    }
    lane->n_tcp_flows--;
    lane->n_closing++;
    f->state = TCP_FLOW_CLOSING;
    f->last_activity_us = lane->clock_fn ? lane->clock_fn(lane->clock_ctx) : 0;
    tcp_lane_downlink_stash_free(f);
}

tcp_lane_flow_status_t
mqvpn_tcp_lane_on_relay_error(mqvpn_tcp_flow_t *f)
{
    /* Fatal relay failure (H3 send/recv error, a pcb write/shutdown error,
     * or an allocation failure that would otherwise force dropping
     * already-ACKed TCP bytes — silent data loss). This is a full
     * local-initiated teardown: RST the pcb, RST the H3 request, unlink +
     * free the flow. Every call site stops touching `f` immediately after
     * this call AND propagates the returned status toward its own caller,
     * so the lwIP-invoked frame at the top of the chain (recv/sent/accept)
     * can return ERR_ABRT when the pcb was aborted here — the lwIP core
     * would otherwise keep dereferencing the freed pcb (see
     * tcp_lane_flow_status_t's contract, tcp_lane_internal.h).
     * xquic-context chains (downlink read notify, writable notify,
     * closing-notify, response gating) legally ignore the status. */
    return tcp_lane_teardown_flow(f, /*close_h3=*/1);
}

void
tcp_lane_finish_clean_close(mqvpn_tcp_flow_t *f)
{
    /* Verified against the vendored lwIP tcp.c. By the
     * time both fin_sent_to_h3 && fin_received_from_h3 are true, the
     * downlink direction's tcp_shutdown(pcb, 0, 1) has ALREADY run (that
     * call is what set fin_received_from_h3) and already drove the pcb
     * into FIN_WAIT_1 (if the uplink FIN — tcp_fin_seen — arrived after) or
     * LAST_ACK (if tcp_fin_seen was already true, i.e. RX had already
     * reached CLOSE_WAIT, when tcp_shutdown ran) — either way PAST
     * SYN_RCVD/ESTABLISHED/CLOSE_WAIT. tcp_close() here is therefore a
     * proven no-op status-wise: tcp_close_shutdown's forced-RST-on-
     * unacked-data branch only fires for ESTABLISHED/CLOSE_WAIT (tcp.c:352,
     * already left by construction), and tcp_close_shutdown_fin's switch
     * has no case for FIN_WAIT_1/LAST_ACK (tcp.c:414-440 — falls to
     * "already closed, do nothing"). It still unconditionally sets
     * TF_RXCLOSED first (tcp.c's tcp_close, before delegating) — a pure
     * field write, and a safety net against any straggling data silently
     * piling into pcb->refused_data forever after we detach below; lwIP's
     * own timers carry the pcb the rest of the way to CLOSED without ever
     * invoking our (already-cleared) callbacks.
     *
     * No RST, and no second H3 close either: both directions completed a
     * bidi FIN on the h3_request too (we sent one via send_body(fin=1), we
     * received one via recv_body's *fin), so xquic's own stream teardown
     * will fire cb_request_close once it finishes tearing down the
     * fully-closed stream on its own — calling the RST-sending close
     * wrapper here would be a spurious RESET_STREAM after a graceful
     * finish. Clear the pointers (not via tcp_lane_close_h3, which WOULD
     * RST) so on_h3_closing/cb_request_close's later, idempotent lookup
     * (which matches on f->stream) misses this flow from here on —
     * f->stream == NULL never matches a real stream pointer.
     *
     * C1: f is NOT freed below — tcp_lane_mark_closing transitions it to
     * TCP_FLOW_CLOSING, a TIME_WAIT-adjacent routing marker that stays in
     * the table (see that state's comment) so a stray post-close inner-OS
     * packet on this 5-tuple (the LAST_ACK final ACK, a TIME_WAIT-era
     * duplicate) still finds an entry and gets routed to lwip_input
     * instead of leaking out as RAW to the already-closed origin. */
    if (f->pcb) {
        tcp_arg(f->pcb, NULL);
        tcp_recv(f->pcb, NULL);
        tcp_sent(f->pcb, NULL);
        tcp_err(f->pcb, NULL);
        MQVPN_TCP_LANE_TCP_CLOSE(f->pcb);
        f->pcb = NULL;
    }
    f->h3_request = NULL;
    f->stream = NULL;
    tcp_lane_mark_closing(f);
}

/* lwIP-initiated close (peer RST, retransmit-timeout give-up, or any other
 * internal error tcp_abandon reports) — the ONLY teardown path where WE did
 * not decide to kill the flow. */
static void
mqvpn_tcp_lane_on_lwip_err(void *arg, err_t err)
{
    (void)err; /* RST vs timeout vs any other lwIP-internal error all mean
                * the same thing to us: the connection is dead, tear the
                * flow down — no err-code-specific handling needed. */
    mqvpn_tcp_flow_t *f = (mqvpn_tcp_flow_t *)arg;
    if (!f) {
        return;
    }
    /* lwIP already freed the pcb before invoking this callback — vendored
     * tcp_abandon (tcp.c): tcp_free(pcb) precedes TCP_EVENT_ERR. The
     * pointer is dangling; unlike every locally-initiated teardown path
     * above (which detach callbacks THEN call tcp_abort themselves), this
     * path must NOT call tcp_arg/tcp_recv/tcp_sent/tcp_err/tcp_abort on it
     * — that would touch already-freed memory. Just forget it.
     * (This callback can also only ever fire for a pcb we did NOT already
     * self-abort — see the comment on tcp_lane_silent_abort_pcb's ordering
     * above for why a self-initiated abort can't re-enter here.) */
    f->pcb = NULL;
    tcp_lane_close_h3(f); /* RST the H3 side; no-op if already closed */
    tcp_lane_remove_flow(f->lane, f);
}

/* O(n) walk scanning every bucket for the entry whose stored f->stream
 * back-pointer matches — see the rationale in tcp_lane.h above
 * mqvpn_tcp_lane_on_stream_established. n <= cfg.tcp_max_flows +
 * TCP_LANE_RAW_MARKER_CAP (256 + 4096 by default; markers have
 * f->stream == NULL so never false-match), and this only runs once per H3
 * response/writable event (not per-packet), so the linear scan is cheap. */
static mqvpn_tcp_flow_t *
find_flow_by_stream(mqvpn_tcp_lane_t *lane, void *stream)
{
    for (uint32_t i = 0; i < lane->n_buckets; i++) {
        for (mqvpn_tcp_flow_t *f = lane->buckets[i]; f; f = f->next) {
            if (f->stream == stream) {
                return f;
            }
        }
    }
    return NULL;
}

void
mqvpn_tcp_lane_bind_h3_request(void *flow_handle, void *h3_request, void *stream)
{
    mqvpn_tcp_flow_t *f = (mqvpn_tcp_flow_t *)flow_handle;
    f->h3_request = h3_request;
    f->stream = stream;
    /* Stay PENDING_STREAM: the request is sent but no response has arrived.
     * mqvpn_tcp_lane_on_stream_established/_rejected do the actual
     * 2xx/4xx-gated transition. */
}

int
mqvpn_tcp_lane_abort_pending(void *flow_handle)
{
    mqvpn_tcp_flow_t *f = (mqvpn_tcp_flow_t *)flow_handle;
    if (!f) {
        return 0;
    }
    /* Never close H3 here. cli_tcp_lane_open_stream (the
     * only caller) either never created a request yet (no live H3 conn /
     * stream calloc failure / xqc_h3_request_create failure — all three
     * pre-bind) or already closed the just-created one itself on the
     * send-headers-failure path (post-bind) — closing it again here would
     * double-close. Just forget the pointers (they may point at a request
     * already mid-close) and tear the pcb + flow down.
     *
     * Return 1 iff the pcb was tcp_abort()ed: this whole chain runs inside
     * lwIP's accept callback frame (accept -> cli_tcp_lane_open_stream ->
     * here), which must then return ERR_ABRT — on ERR_OK, tcp_process's
     * SYN_RCVD path proceeds to tcp_receive() on the freed pcb (vendored
     * tcp_in.c; see tcp_lane.h's contract on this function). */
    return tcp_lane_teardown_flow(f, /*close_h3=*/0) == TCP_LANE_FLOW_ABORTED ? 1 : 0;
}

void
mqvpn_tcp_lane_on_stream_established(mqvpn_tcp_lane_t *lane, void *stream)
{
    if (!lane || !stream) {
        return;
    }
    mqvpn_tcp_flow_t *f = find_flow_by_stream(lane, stream);
    if (!f) {
        /* Flow already gone (e.g. a race with a future removal) —
         * nothing to gate. */
        return;
    }
    f->state = TCP_FLOW_ACTIVE;
    f->last_activity_us = lane->clock_fn ? lane->clock_fn(lane->clock_ctx) : 0;
    /* Flush the uplink bytes buffered while the flow sat in PENDING_STREAM
     * waiting for the 2xx gate to open — same queue + flush the writable
     * notify uses (pre-2xx buffering and EAGAIN retry are ONE mechanism),
     * including a FIN the inner app already sent. Status discarded:
     * xquic-context frame (response-headers notify), not a lwIP callback —
     * f just must not be touched after a non-LIVE return (it isn't). */
    (void)tcp_lane_uplink_flush(f);
}

void
mqvpn_tcp_lane_on_stream_rejected(mqvpn_tcp_lane_t *lane, void *stream)
{
    if (!lane || !stream) {
        return;
    }
    mqvpn_tcp_flow_t *f = find_flow_by_stream(lane, stream);
    if (!f) {
        return;
    }
    /* A non-2xx response is a LOCAL decision to abandon this flow (distinct
     * from mqvpn_tcp_lane_on_h3_closing below, which is xquic's OWN
     * decision) — full locally-initiated teardown: RST the pcb
     * and RST the H3 request (the server may have sent a
     * body we're not going to read). Status discarded: this is an
     * xquic-context frame (response-headers notify), not a lwIP callback —
     * no ERR_ABRT translation applies (tcp_lane_flow_status_t contract). */
    (void)tcp_lane_teardown_flow(f, /*close_h3=*/1);
}

/* H3 closing-notify: xquic is already tearing this request down —
 * verified against the vendored source that this notify fires ONLY on
 * RESET_STREAM frame RECEPTION (xqc_process_reset_stream_frame ->
 * xqc_stream_closing -> xqc_h3_stream_closing_notify ->
 * xqc_h3_request_closing, third_party/xquic/src/transport/xqc_frame.c and
 * src/http3/xqc_h3_stream.c/xqc_h3_request.c) — NEVER for STOP_SENDING
 * reception alone (that only makes xquic send back a RESET_STREAM of our
 * own, xqc_process_stop_sending_frame; if the peer then also resets, THAT
 * inbound RESET_STREAM is what fires this) and NEVER for a clean bidi-FIN
 * completion (see tcp_lane_finish_clean_close). RST our local pcb side;
 * must NOT close the H3 request again (it's already being reset). */
void
mqvpn_tcp_lane_on_h3_closing(mqvpn_tcp_lane_t *lane, void *stream)
{
    if (!lane || !stream) {
        return;
    }
    mqvpn_tcp_flow_t *f = find_flow_by_stream(lane, stream);
    if (!f) {
        return; /* already gone — idempotent (races with any other
                 * teardown path, or a stale/duplicate notify) */
    }
    /* Status discarded — xquic-context frame, no ERR_ABRT translation. */
    (void)tcp_lane_teardown_flow(f, /*close_h3=*/0);
}

int
mqvpn_tcp_lane_on_h3_writable(mqvpn_tcp_lane_t *lane, void *stream)
{
    if (!lane || !stream) {
        return 0;
    }
    mqvpn_tcp_flow_t *f = find_flow_by_stream(lane, stream);
    if (!f) {
        return 0;
    }
    /* Retry-queue drain + low-water recved resume + pending-FIN send all
     * live in flush (see its comment). Status discarded: xquic-context
     * frame (write notify), not a lwIP callback. */
    (void)tcp_lane_uplink_flush(f);
    return 0;
}

err_t
mqvpn_tcp_lane_lwip_accept(void *arg, struct tcp_pcb *newpcb, err_t err)
{
    mqvpn_tcp_lane_t *lane = (mqvpn_tcp_lane_t *)arg;

    /* pcb-pool exhaustion: tcp_listen_input invokes the accept callback with
     * (NULL, ERR_MEM) and ignores the return value (tcp_in.c). Nothing to
     * track or abort — the peer's SYN retransmit retries, and the flow entry
     * stays PENDING_ACCEPT so the retransmit is re-fed into lwIP. */
    if (!newpcb || err != ERR_OK) {
        return ERR_MEM;
    }

    /* Rebuild the SYN-time flow key from the accepted pcb — the fork's
     * wildcard bind means local_ip/local_port ARE the true original
     * destination. Byte-order contract (must be byte-identical to the key
     * mqvpn_hybrid_classify built from the raw SYN, or find_flow below
     * misses every time; pinned by test_tcp_lane's correspondence tests,
     * v4 and v6):
     *   - pcb ports are HOST order (tcp_input ntohs's the header before
     *     tcp_listen_input copies src/dest — tcp_in.c), matching the key's
     *     documented host-order ports (reorder.h);
     *   - ip_addr_t is a tagged union (LWIP_IPV6=1), so switch on the pcb's
     *     actual family instead of one whole-struct memcpy (which would
     *     also copy the union's type tag / unused arm into the key's raw
     *     byte array):
     *       - v4: ip_2_ip4(...)->addr is the bare ip4_addr_t, one u32_t in
     *         NETWORK order — same 4 raw header bytes the classifier
     *         memcpy'd.
     *       - v6: ip_2_ip6(...)->addr is u32_t addr[4], 16 bytes total in
     *         NETWORK order — same 16 raw header bytes the classifier
     *         memcpy'd (reorder.h's mqvpn_parse_l3l4, v6 branch). */
    mqvpn_flow_key_t key;
    memset(&key, 0, sizeof(key));
    key.proto = MQVPN_IPPROTO_TCP;
    key.src_port = newpcb->remote_port;
    key.dst_port = newpcb->local_port;
    if (IP_IS_V6(&newpcb->local_ip)) {
        key.ip_version = 6;
        memcpy(key.src_ip, ip_2_ip6(&newpcb->remote_ip)->addr, 16); /* addr[4], array */
        memcpy(key.dst_ip, ip_2_ip6(&newpcb->local_ip)->addr, 16);  /* addr[4], array */
    } else {
        key.ip_version = 4;
        memcpy(key.src_ip, &ip_2_ip4(&newpcb->remote_ip)->addr, 4); /* scalar u32 */
        memcpy(key.dst_ip, &ip_2_ip4(&newpcb->local_ip)->addr, 4);  /* scalar u32 */
    }

    mqvpn_tcp_flow_t *f = find_flow(lane, &key, NULL);
    if (!f || f->state != TCP_FLOW_PENDING_ACCEPT) {
        /* Shouldn't happen — every lwIP-fed SYN was committed by on_syn
         * first. Refuse rather than leak an untracked pcb. Post-SYN-ACK, so
         * NEVER a RAW fallback. Return convention (vendored tcp_in.c,
         * tcp_process SYN_RCVD): any non-ERR_OK return other than ERR_ABRT
         * makes the stack tcp_abort() the pcb itself (RST + free); ERR_ABRT
         * would instead claim WE already called tcp_abort — we didn't. */
        return ERR_VAL;
    }

    if (lane->n_tcp_flows > lane->cfg.tcp_max_flows) {
        /* Defense only — the cap is enforced pre-lwIP in on_syn; strict >
         * because this flow itself is already counted in n_tcp_flows. Same
         * abort-not-RAW return convention as above. f->pcb is still NULL
         * here (set below on the success path only), so remove_flow just
         * unlinks + frees — nothing pcb-side to touch. */
        lane->stats.flows_rejected_cap++;
        tcp_lane_remove_flow(lane, f);
        return ERR_MEM;
    }

    f->pcb = newpcb;
    f->target_ip = newpcb->local_ip; /* whole union: family + address */
    f->target_port = newpcb->local_port;
    f->state = TCP_FLOW_PENDING_STREAM;
    f->last_activity_us = lane->clock_fn ? lane->clock_fn(lane->clock_ctx) : 0;
    /* Back-pointer so the lwIP callbacks below (which only receive
     * f as tcp_arg, never the lane) can reach lane->clock_fn and re-enter
     * mqvpn_tcp_lane_downlink_pump(lane, stream).
     * mqvpn_tcp_lane_on_syn already set this for every to_tcp=1 flow at
     * creation (PENDING_ACCEPT needs it too, for the idle sweep) — this is a
     * harmless re-affirmation of the same pointer, kept for locality with
     * the other per-accept field writes above. */
    f->lane = lane;

    tcp_arg(newpcb, f);
    tcp_recv(newpcb, mqvpn_tcp_lane_on_lwip_recv);
    tcp_sent(newpcb, mqvpn_tcp_lane_on_lwip_sent);
    tcp_err(newpcb, mqvpn_tcp_lane_on_lwip_err);

    /* Direct .c-to-.c call — see the prototype's comment in tcp_lane.h.
     * Nonzero means a failure path inside already tcp_abort()ed newpcb
     * (via mqvpn_tcp_lane_abort_pending): this accept frame must then
     * return ERR_ABRT — on ERR_OK, tcp_process's SYN_RCVD path proceeds to
     * tcp_receive(pcb) on the freed pcb, and any other non-ERR_OK value
     * makes it tcp_abort() the already-freed pcb a second time (vendored
     * tcp_in.c, TCP_EVENT_ACCEPT error handling). */
    if (cli_tcp_lane_open_stream(lane->client_ctx, f, &key) != 0) {
        return ERR_ABRT;
    }
    return ERR_OK;
}

/* Thin dispatcher onto tcp_lane_uplink.c (the uplink QUEUE + SEND
 * + FLUSH + FIN machinery itself lives there; this file keeps only the
 * per-notify bookkeeping and the two-way branch on p == NULL).
 *
 * lwIP-invoked frame: when flush/deliver tore the flow down AND
 * tcp_abort()ed the pcb, this callback MUST return ERR_ABRT — on ERR_OK
 * lwIP's tcp_in.c continues into TF_GOT_FIN/tcp_output on the freed pcb
 * (tcp_lane_flow_status_t contract, tcp_lane_internal.h). ERR_ABRT on the
 * data path is correct even though deliver consumed/freed the pbuf: lwIP
 * gives up its inseg reference on the `aborted` path either way. A GONE
 * teardown (clean bidi-FIN via the FIN branch — pcb tcp_close()d, not
 * freed) correctly stays ERR_OK. */
static err_t
mqvpn_tcp_lane_on_lwip_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    mqvpn_tcp_flow_t *f = (mqvpn_tcp_flow_t *)arg;
    (void)pcb;
    (void)err;

    /* Activity signal (the idle sweep's target) — any recv notify,
     * data or peer FIN, counts. f->lane is set at accept time; NULL-guarded
     * the same way the accept/establish stamps already are. */
    if (f->lane && f->lane->clock_fn) {
        f->last_activity_us = f->lane->clock_fn(f->lane->clock_ctx);
    }

    if (!p) {
        /* Peer FIN from the lwIP side (recv(NULL) → H3 half-close).
         * flush() drains queued data first and sends the FIN only after; if
         * still PENDING_STREAM there is nothing to FIN yet — the
         * established-flush completes it. */
        f->tcp_fin_seen = 1;
        if (tcp_lane_uplink_flush(f) == TCP_LANE_FLOW_ABORTED) {
            return ERR_ABRT;
        }
        return ERR_OK;
    }

    if (f->state != TCP_FLOW_ACTIVE && f->state != TCP_FLOW_PENDING_STREAM) {
        /* CLOSING (belt-and-suspenders — nothing assigns it,
         * and every teardown path detaches tcp_recv in the same call that
         * frees the flow, so lwIP can never actually redeliver here for a
         * dead flow) or a state that shouldn't reach a live pcb at all
         * (STICKY_RAW/PENDING_ACCEPT never get a recv callback registered).
         * Drop; the close mapping above owns teardown. */
        pbuf_free(p);
        return ERR_OK;
    }

    if (tcp_lane_uplink_deliver(f, p) == TCP_LANE_FLOW_ABORTED) {
        return ERR_ABRT;
    }
    return ERR_OK;
}
