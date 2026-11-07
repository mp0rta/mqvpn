// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_conn_settings.c — pins mqvpn_build_conn_settings() caller contract:
 * scheduler / init_max_path_id propagate and the four asymmetric fields
 * (ping_on, enable_multipath, mp_ping_on, max_path_id_grant_max_value)
 * take the documented per-side values.
 */

#include "libmqvpn.h"
#include "mqvpn_conn_settings.h"
#include "mqvpn_internal.h"
#include "mqvpn_scheduler.h"

#include <stdio.h>
#include <string.h>

#include <xquic/xquic.h>

#define FAIL(fmt, ...)                                                               \
    do {                                                                             \
        fprintf(stderr, "FAIL %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
        return 1;                                                                    \
    } while (0)

#define ASSERT_EQ(a, b)                                                              \
    do {                                                                             \
        if ((a) != (b))                                                              \
            FAIL("%s != %s (%lld != %lld)", #a, #b, (long long)(a), (long long)(b)); \
    } while (0)

/* Function-pointer comparison: skips the (long long) cast that ASSERT_EQ
 * uses for its diagnostic so callers can compare pointer-typed fields
 * without -Wint-conversion noise. */
#define ASSERT_PTR_EQ(a, b)                                          \
    do {                                                             \
        if ((a) != (b)) FAIL("%s != %s (pointer mismatch)", #a, #b); \
    } while (0)

static int
test_asymmetry_server_vs_client(void)
{
    xqc_conn_settings_t srv, cli_mp_on, cli_mp_off;

    mqvpn_conn_settings_input_t s = {
        .is_server = true,
        .enable_multipath = true,
        .scheduler = MQVPN_SCHED_WLB,
        .init_max_path_id = 0,
    };
    mqvpn_build_conn_settings(&s, &srv);

    mqvpn_conn_settings_input_t c_on = {
        .is_server = false,
        .enable_multipath = true,
        .scheduler = MQVPN_SCHED_WLB,
        .init_max_path_id = 0,
    };
    mqvpn_build_conn_settings(&c_on, &cli_mp_on);

    mqvpn_conn_settings_input_t c_off = c_on;
    c_off.enable_multipath = false;
    mqvpn_build_conn_settings(&c_off, &cli_mp_off);

    /* Server side: MP always on, grant capped at 64, ping_on absent. */
    ASSERT_EQ(srv.enable_multipath, 1);
    ASSERT_EQ(srv.mp_ping_on, 1);
    ASSERT_EQ(srv.max_path_id_grant_max_value, 128);
    ASSERT_EQ(srv.ping_on, 0);

    /* Client side mp-on: MP gated, ping_on set, no grant cap. */
    ASSERT_EQ(cli_mp_on.enable_multipath, 1);
    ASSERT_EQ(cli_mp_on.mp_ping_on, 1);
    ASSERT_EQ(cli_mp_on.ping_on, 1);
    ASSERT_EQ(cli_mp_on.max_path_id_grant_max_value, 0);

    /* Client side mp-off: MP off, mp_ping_on follows. */
    ASSERT_EQ(cli_mp_off.enable_multipath, 0);
    ASSERT_EQ(cli_mp_off.mp_ping_on, 0);
    ASSERT_EQ(cli_mp_off.ping_on, 1);
    return 0;
}

static int
test_propagation_scheduler(void)
{
    xqc_conn_settings_t cs;
    mqvpn_conn_settings_input_t in = {
        .is_server = false,
        .enable_multipath = true,
        .scheduler = MQVPN_SCHED_MINRTT,
        .init_max_path_id = 0,
    };

    /* Use a representative field-pointer rather than a whole-struct memcmp:
     * struct layout / future-padding portability matches test_scheduler.c. */
    in.scheduler = MQVPN_SCHED_MINRTT;
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_PTR_EQ(cs.scheduler_callback.xqc_scheduler_get_path,
                  xqc_minrtt_scheduler_cb.xqc_scheduler_get_path);

    in.scheduler = MQVPN_SCHED_WLB;
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_PTR_EQ(cs.scheduler_callback.xqc_scheduler_get_path,
                  xqc_wlb_scheduler_cb.xqc_scheduler_get_path);
    return 0;
}

static int
test_propagation_cc(void)
{
    xqc_conn_settings_t cs;
    mqvpn_conn_settings_input_t in = {
        .is_server = false,
        .enable_multipath = true,
        .scheduler = MQVPN_SCHED_WLB,
        .cc = MQVPN_CC_BBR2,
        .init_max_path_id = 0,
    };

    /* default: BBR2 — also verify optimization flags are set */
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_PTR_EQ(cs.cong_ctrl_callback.xqc_cong_ctl_init, xqc_bbr2_cb.xqc_cong_ctl_init);
    ASSERT_EQ(cs.cc_params.cc_optimization_flags,
              XQC_BBR2_FLAG_RTTVAR_COMPENSATION | XQC_BBR2_FLAG_FAST_CONVERGENCE);

    /* BBR — RTT-variance compensation, as BBR2 */
    in.cc = MQVPN_CC_BBR;
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_PTR_EQ(cs.cong_ctrl_callback.xqc_cong_ctl_init, xqc_bbr_cb.xqc_cong_ctl_init);
    ASSERT_EQ(cs.cc_params.cc_optimization_flags, XQC_BBR_FLAG_RTTVAR_COMPENSATION);

    /* CUBIC — no optimization flags */
    in.cc = MQVPN_CC_CUBIC;
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_PTR_EQ(cs.cong_ctrl_callback.xqc_cong_ctl_init,
                  xqc_cubic_cb.xqc_cong_ctl_init);
    ASSERT_EQ(cs.cc_params.cc_optimization_flags, 0);

#ifdef XQC_ENABLE_UNLIMITED
    /* NONE (unlimited) — no optimization flags */
    in.cc = MQVPN_CC_NONE;
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_PTR_EQ(cs.cong_ctrl_callback.xqc_cong_ctl_init,
                  xqc_unlimited_cc_cb.xqc_cong_ctl_init);
    ASSERT_EQ(cs.cc_params.cc_optimization_flags, 0);
#endif

    return 0;
}

static int
test_propagation_init_max_path_id(void)
{
    xqc_conn_settings_t cs;
    mqvpn_conn_settings_input_t in = {
        .is_server = true,
        .enable_multipath = true,
        .scheduler = MQVPN_SCHED_WLB,
        .init_max_path_id = 0,
    };

    /* 0 -> field stays 0 (xquic default applies inside xqc_server_set_conn_settings) */
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_EQ(cs.init_max_path_id, 0);

    in.init_max_path_id = 16;
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_EQ(cs.init_max_path_id, 16);
    return 0;
}

static int
test_path_mtu_sizes_packets(void)
{
    xqc_conn_settings_t cs;
    mqvpn_conn_settings_input_t in = {
        .is_server = false,
        .enable_multipath = true,
        .scheduler = MQVPN_SCHED_WLB,
    };
    static const struct {
        int path_mtu;
        size_t pkt;
    } cases[] = {
        {0, MQVPN_MAX_PKT_OUT_SIZE},
        {1280, 1200},
        {1492, 1412},
        {1499, 1419},
        {1500, 1436},
        {9000, 1436},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        in.path_mtu = cases[i].path_mtu;
        mqvpn_build_conn_settings(&in, &cs);
        ASSERT_EQ(cs.max_pkt_out_size, cases[i].pkt);
    }
    /* the largest packet on the wire fits the path, IPv6 header included */
    for (int mtu = 1280; mtu <= 1500; mtu++) {
        size_t pkt = mqvpn_pkt_out_size(mtu);
        size_t ack = pkt < MQVPN_XQC_MAX_PKT_OUT_SIZE ? 16 : 0;
        ASSERT_EQ(pkt + ack + MQVPN_AEAD_TAG_LEN + 48 <= (size_t)mtu, 1);
    }
    return 0;
}

/* The server forces multipath ON unconditionally — mqvpn's client is the active
 * path creator, so the server allows MP regardless of its input flag
 * (src/mqvpn_conn_settings.c:88-95). test_asymmetry_server_vs_client only feeds
 * the server enable_multipath=true; this pins the "ignore the input flag" half,
 * so a regression that made the server honour in->enable_multipath (silently
 * disabling server-side multipath when a caller passes false) fails here. */
/* PMTUD: packets start at the base size, probing goes up to the PathMTU
 * size (or the xquic cap), both ends probe, and nothing changes without it */
static int
test_pmtud_sizes(void)
{
    xqc_conn_settings_t cs;
    mqvpn_conn_settings_input_t in = {
        .is_server = false,
        .enable_multipath = true,
        .scheduler = MQVPN_SCHED_WLB,
    };
    static const struct {
        int path_mtu;
        size_t start;
        size_t cap;
    } cases[] = {
        {0, MQVPN_PMTUD_BASE_PKT_OUT_SIZE, MQVPN_XQC_MAX_PKT_OUT_SIZE},
        {1280, 1200, 1200},
        {1400, MQVPN_PMTUD_BASE_PKT_OUT_SIZE, 1320},
        {1500, MQVPN_PMTUD_BASE_PKT_OUT_SIZE, MQVPN_XQC_MAX_PKT_OUT_SIZE},
    };

    in.pmtud = true;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        in.path_mtu = cases[i].path_mtu;
        for (int server = 0; server <= 1; server++) {
            in.is_server = server;
            mqvpn_build_conn_settings(&in, &cs);
            ASSERT_EQ(cs.enable_pmtud, 0x3);
            ASSERT_EQ(cs.max_pkt_out_size, cases[i].start);
            ASSERT_EQ(cs.probing_pkt_out_size, cases[i].cap);
        }
    }
    /* the base size still gives IPv6 its 1280-byte inner MTU */
    ASSERT_EQ(MQVPN_PMTUD_BASE_PKT_OUT_SIZE - MQVPN_DGRAM_HEADROOM, 1280);

    /* with reorder, the start size (also where xquic goes back to when a
     * path shrinks) leaves room for its header, PathMTU still capping it */
    static const struct {
        int path_mtu;
        size_t start;
    } reorder_cases[] = {
        {0, MQVPN_PMTUD_BASE_PKT_OUT_SIZE + MQVPN_REORDER_HDR_LEN},
        {1280, 1200},
        {1380, 1300}, /* between the two start sizes: the PathMTU size */
        {1400, MQVPN_PMTUD_BASE_PKT_OUT_SIZE + MQVPN_REORDER_HDR_LEN},
    };
    in.reorder = true;
    for (size_t i = 0; i < sizeof(reorder_cases) / sizeof(reorder_cases[0]); i++) {
        in.path_mtu = reorder_cases[i].path_mtu;
        for (int server = 0; server <= 1; server++) {
            in.is_server = server;
            mqvpn_build_conn_settings(&in, &cs);
            ASSERT_EQ(cs.max_pkt_out_size, reorder_cases[i].start);
        }
    }
    in.reorder = false;

    in.pmtud = false;
    in.is_server = false;
    in.path_mtu = 1500;
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_EQ(cs.enable_pmtud, 0);
    ASSERT_EQ(cs.probing_pkt_out_size, 0);
    ASSERT_EQ(cs.max_pkt_out_size, MQVPN_XQC_MAX_PKT_OUT_SIZE);
    return 0;
}

static int
test_server_forces_multipath_regardless_of_input(void)
{
    xqc_conn_settings_t cs;
    mqvpn_conn_settings_input_t in = {
        .is_server = true,
        .enable_multipath = false, /* client-style "off" — the server must ignore it */
        .scheduler = MQVPN_SCHED_WLB,
        .init_max_path_id = 0,
    };

    mqvpn_build_conn_settings(&in, &cs);

    ASSERT_EQ(cs.enable_multipath, 1);
    ASSERT_EQ(cs.mp_ping_on, 1);
    ASSERT_EQ(cs.max_path_id_grant_max_value, 128);
    ASSERT_EQ(cs.ping_on, 0); /* server never takes the client keep-alive role */
    return 0;
}

static int
test_recv_rate_limit_wiring(void)
{
    xqc_conn_settings_t cli, srv;
    mqvpn_conn_settings_input_t c = {
        .is_server = false,
        .enable_multipath = true,
        .scheduler = MQVPN_SCHED_WLB,
        .recv_rate_bytes_per_sec = 125000000ULL,
    };
    mqvpn_build_conn_settings(&c, &cli);
    ASSERT_EQ(cli.recv_rate_bytes_per_sec, 125000000ULL);

    /* server MUST stay 0 even if a caller passes a value: a server-side
     * conn-level cap throttles every client's uplink. */
    mqvpn_conn_settings_input_t s = {
        .is_server = true,
        .enable_multipath = true,
        .scheduler = MQVPN_SCHED_WLB,
        .recv_rate_bytes_per_sec = 125000000ULL,
    };
    mqvpn_build_conn_settings(&s, &srv);
    ASSERT_EQ(srv.recv_rate_bytes_per_sec, 0);
    return 0;
}

static int
test_reinjection_mapping(void)
{
    xqc_conn_settings_t cs;
    mqvpn_conn_settings_input_t in = {
        .is_server = false,
        .enable_multipath = true,
        .scheduler = MQVPN_SCHED_WLB,
        .reinjection = MQVPN_REINJ_OFF,
    };

    /* off: no reinjection bits, ctl slot untouched (zeroed) */
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_EQ(cs.mp_enable_reinjection, 0);
    ASSERT_PTR_EQ(cs.reinj_ctl_callback.xqc_reinj_ctl_can_reinject, NULL);

    /* idle */
    in.reinjection = MQVPN_REINJ_IDLE;
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_EQ(cs.mp_enable_reinjection, XQC_REINJ_UNACK_AFTER_SCHED);
    ASSERT_PTR_EQ(cs.reinj_ctl_callback.xqc_reinj_ctl_can_reinject,
                  xqc_default_reinj_ctl_cb.xqc_reinj_ctl_can_reinject);

    /* deadline: explicit BEFORE_SCHED|AFTER_SEND + unit conversions */
    in.reinjection = MQVPN_REINJ_DEADLINE;
    in.reinj_srtt_factor_pct = 150;
    in.reinj_hard_deadline_ms = 300;
    in.reinj_deadline_lower_bound_ms = 10;
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_EQ(cs.mp_enable_reinjection,
              XQC_REINJ_UNACK_BEFORE_SCHED | XQC_REINJ_UNACK_AFTER_SEND);
    ASSERT_PTR_EQ(cs.reinj_ctl_callback.xqc_reinj_ctl_can_reinject,
                  xqc_deadline_reinj_ctl_cb.xqc_reinj_ctl_can_reinject);
    if (cs.reinj_flexible_deadline_srtt_factor < 1.49 ||
        cs.reinj_flexible_deadline_srtt_factor > 1.51)
        FAIL("factor conversion wrong: %f", cs.reinj_flexible_deadline_srtt_factor);
    ASSERT_EQ(cs.reinj_hard_deadline, 300000);       /* ms -> us */
    ASSERT_EQ(cs.reinj_deadline_lower_bound, 10000); /* ms -> us */

    /* deadline with zero params -> engine defaults 110/500/20 */
    in.reinj_srtt_factor_pct = 0;
    in.reinj_hard_deadline_ms = 0;
    in.reinj_deadline_lower_bound_ms = 0;
    mqvpn_build_conn_settings(&in, &cs);
    if (cs.reinj_flexible_deadline_srtt_factor < 1.09 ||
        cs.reinj_flexible_deadline_srtt_factor > 1.11)
        FAIL("default factor wrong: %f", cs.reinj_flexible_deadline_srtt_factor);
    ASSERT_EQ(cs.reinj_hard_deadline, 500000);
    ASSERT_EQ(cs.reinj_deadline_lower_bound, 20000);

    /* negative input pins the `> 0` guard direction: a negative value must
     * NOT be treated as "explicitly set" and must fall back to the engine
     * default, same as 0. */
    in.reinj_hard_deadline_ms = -1;
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_EQ(cs.reinj_hard_deadline, 500000);

    /* lower > hard clamps down to hard; rationale on mqvpn_apply_reinjection */
    in.reinj_hard_deadline_ms = 100;
    in.reinj_deadline_lower_bound_ms = 200;
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_EQ(cs.reinj_hard_deadline, 100000);
    ASSERT_EQ(cs.reinj_deadline_lower_bound, 100000);

    /* 3 was the removed dgram value: now invalid -> off, WLB survives */
    in.reinjection = (mqvpn_reinjection_t)3;
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_EQ(cs.mp_enable_reinjection, 0);
    ASSERT_PTR_EQ(cs.reinj_ctl_callback.xqc_reinj_ctl_can_reinject, NULL);
    ASSERT_PTR_EQ(cs.scheduler_callback.xqc_scheduler_get_path,
                  xqc_wlb_scheduler_cb.xqc_scheduler_get_path);

    /* invalid enum value -> off */
    in.reinjection = (mqvpn_reinjection_t)99;
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_EQ(cs.mp_enable_reinjection, 0);
    ASSERT_PTR_EQ(cs.reinj_ctl_callback.xqc_reinj_ctl_can_reinject, NULL);

    return 0;
}

/* The escape hatch: with UdpGso=false no batched send callback is
 * registered, so xquic emits one syscall per packet no matter when the flush
 * happens — deferring would only move the flush, for zero benefit. The
 * builder must therefore carry a false input through as 0, which is what
 * keeps "UdpGso=false behaves exactly as it did before the deferral patches"
 * true for both the datagram and the hybrid TCP lane.
 *
 * SCOPE — this pins the BUILDER, not the gating. The builder is handed the
 * flag directly here, so nothing below exercises the registration decision
 * itself; that the callers pass the same stored tx_batch they gated
 * cb_write_mmsg_ex registration on is asserted by neither this test nor the
 * e2e, and stays a review-time invariant (see the field comment in
 * mqvpn_conn_settings.h). What this test does buy is that the builder cannot
 * quietly become the thing that decides: no local condition may widen or
 * narrow the caller's answer. */
static int
test_defer_flush_tracks_batch_registration(void)
{
    xqc_conn_settings_t cs;

    mqvpn_conn_settings_input_t in = {
        .is_server = false,
        .enable_multipath = true,
        .scheduler = MQVPN_SCHED_WLB,
        .defer_send_flush = false,
    };
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_EQ(cs.defer_send_flush, 0);

    in.defer_send_flush = true;
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_EQ(cs.defer_send_flush, 1);

    /* Server path shares the builder but is reached by its own call site. */
    in.is_server = true;
    in.defer_send_flush = false;
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_EQ(cs.defer_send_flush, 0);

    in.defer_send_flush = true;
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_EQ(cs.defer_send_flush, 1);

    /* Carried, not synthesised: the builder must not AND the caller's flag
     * with any condition of its own.
     *
     * The input stays TRUE across these permutations deliberately. Asserting 0
     * while flipping unrelated inputs would prove nothing — an implementation
     * like `in->defer_send_flush && in->enable_multipath` satisfies that just
     * as well. Only a true input that survives every permutation rules it
     * out. */
    in.defer_send_flush = true;
    in.enable_multipath = false;
    in.scheduler = MQVPN_SCHED_MINRTT;
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_EQ(cs.defer_send_flush, 1);

    in.is_server = false;
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_EQ(cs.defer_send_flush, 1);

    in.cc = MQVPN_CC_CUBIC;
    in.reinjection = MQVPN_REINJ_DEADLINE;
    in.recv_rate_bytes_per_sec = 125000000ULL;
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_EQ(cs.defer_send_flush, 1);

    /* Absent from a designated initializer = 0: a future call site that
     * forgets the field gets the pre-patch behavior, never deferral. */
    mqvpn_conn_settings_input_t unset = {
        .is_server = false,
        .scheduler = MQVPN_SCHED_WLB,
    };
    mqvpn_build_conn_settings(&unset, &cs);
    ASSERT_EQ(cs.defer_send_flush, 0);
    return 0;
}

/* Both sides cap their stream backlog: the client's bounds the upload,
 * the server's the download. */
static int
test_stream_unsent_cap_both_sides(void)
{
    for (int server = 0; server <= 1; server++) {
        xqc_conn_settings_t cs;
        mqvpn_conn_settings_input_t in = {
            .is_server = server,
            .enable_multipath = true,
            .scheduler = MQVPN_SCHED_WLB,
        };
        mqvpn_build_conn_settings(&in, &cs);
        ASSERT_EQ(cs.max_stream_unsent_packets, MQVPN_STREAM_UNSENT_PACKETS);
    }
    return 0;
}

/* The two BBR2 optimisation flags are independent opt-outs. A zeroed input
 * keeps both set (the long-standing behaviour); each disable clears exactly
 * its own bit, on both endpoints, and never leaks onto another CC. */
static int
test_bbr2_flag_opt_outs(void)
{
    const uint32_t both =
        XQC_BBR2_FLAG_RTTVAR_COMPENSATION | XQC_BBR2_FLAG_FAST_CONVERGENCE;

    for (int side = 0; side < 2; side++) {
        xqc_conn_settings_t cs;
        mqvpn_conn_settings_input_t in = {
            .is_server = (side == 1),
            .enable_multipath = true,
            .scheduler = MQVPN_SCHED_WLB,
            .cc = MQVPN_CC_BBR2,
        };

        mqvpn_build_conn_settings(&in, &cs);
        ASSERT_EQ(cs.cc_params.cc_optimization_flags, both);

        in.disable_bbr2_fast_convergence = true;
        mqvpn_build_conn_settings(&in, &cs);
        ASSERT_EQ(cs.cc_params.cc_optimization_flags, XQC_BBR2_FLAG_RTTVAR_COMPENSATION);

        in.disable_bbr2_fast_convergence = false;
        in.disable_bbr2_rttvar_compensation = true;
        mqvpn_build_conn_settings(&in, &cs);
        ASSERT_EQ(cs.cc_params.cc_optimization_flags, XQC_BBR2_FLAG_FAST_CONVERGENCE);

        in.disable_bbr2_fast_convergence = true;
        mqvpn_build_conn_settings(&in, &cs);
        ASSERT_EQ(cs.cc_params.cc_optimization_flags, 0);
        ASSERT_PTR_EQ(cs.cong_ctrl_callback.xqc_cong_ctl_init,
                      xqc_bbr2_cb.xqc_cong_ctl_init);

        /* Inert on any other congestion controller. */
        in.disable_bbr2_fast_convergence = false;
        in.disable_bbr2_rttvar_compensation = false;
        in.cc = MQVPN_CC_CUBIC;
        mqvpn_build_conn_settings(&in, &cs);
        ASSERT_EQ(cs.cc_params.cc_optimization_flags, 0);
    }
    return 0;
}

int
main(void)
{
    int failed = 0;
    failed += test_asymmetry_server_vs_client();
    failed += test_defer_flush_tracks_batch_registration();
    failed += test_propagation_scheduler();
    failed += test_propagation_cc();
    failed += test_bbr2_flag_opt_outs();
    failed += test_propagation_init_max_path_id();
    failed += test_path_mtu_sizes_packets();
    failed += test_pmtud_sizes();
    failed += test_server_forces_multipath_regardless_of_input();
    failed += test_recv_rate_limit_wiring();
    failed += test_reinjection_mapping();
    failed += test_stream_unsent_cap_both_sides();
    if (failed) {
        fprintf(stderr, "test_conn_settings: %d FAILED\n", failed);
        return 1;
    }
    fprintf(stderr, "test_conn_settings: PASS\n");
    return 0;
}
