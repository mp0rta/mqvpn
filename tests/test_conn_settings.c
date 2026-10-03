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

    /* BBR — no optimization flags */
    in.cc = MQVPN_CC_BBR;
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_PTR_EQ(cs.cong_ctrl_callback.xqc_cong_ctl_init, xqc_bbr_cb.xqc_cong_ctl_init);
    ASSERT_EQ(cs.cc_params.cc_optimization_flags, 0);

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

/* The server forces multipath ON unconditionally — mqvpn's client is the active
 * path creator, so the server allows MP regardless of its input flag
 * (src/mqvpn_conn_settings.c:88-95). test_asymmetry_server_vs_client only feeds
 * the server enable_multipath=true; this pins the "ignore the input flag" half,
 * so a regression that made the server honour in->enable_multipath (silently
 * disabling server-side multipath when a caller passes false) fails here. */
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

    /* dgram: AFTER_SEND only; scheduler_callback must NOT be overridden */
    in.reinjection = MQVPN_REINJ_DGRAM;
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_EQ(cs.mp_enable_reinjection, XQC_REINJ_UNACK_AFTER_SEND);
    ASSERT_PTR_EQ(cs.reinj_ctl_callback.xqc_reinj_ctl_can_reinject,
                  xqc_dgram_reinj_ctl_cb.xqc_reinj_ctl_can_reinject);
    ASSERT_PTR_EQ(cs.scheduler_callback.xqc_scheduler_get_path,
                  xqc_wlb_scheduler_cb.xqc_scheduler_get_path); /* WLB survives */

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

int
main(void)
{
    int failed = 0;
    failed += test_asymmetry_server_vs_client();
    failed += test_defer_flush_tracks_batch_registration();
    failed += test_propagation_scheduler();
    failed += test_propagation_cc();
    failed += test_propagation_init_max_path_id();
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
