// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and contributors

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

int
main(void)
{
    int failed = 0;
    failed += test_asymmetry_server_vs_client();
    failed += test_propagation_scheduler();
    failed += test_propagation_cc();
    failed += test_propagation_init_max_path_id();
    if (failed) {
        fprintf(stderr, "test_conn_settings: %d FAILED\n", failed);
        return 1;
    }
    fprintf(stderr, "test_conn_settings: PASS\n");
    return 0;
}
