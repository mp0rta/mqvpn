#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "libmqvpn.h"
#include "mqvpn_internal.h"  /* mqvpn_check_scheduler_preconditions (xquic-free) */
#include "mqvpn_scheduler.h" /* xquic-dependent helper + macros */

#include <xquic/xquic.h>

#define ASSERT_EQ(a, b)                                                            \
    do {                                                                           \
        if ((a) != (b)) {                                                          \
            fprintf(stderr, "FAIL %s:%d: %s != %s\n", __FILE__, __LINE__, #a, #b); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

#define ASSERT_NE(a, b)                                                            \
    do {                                                                           \
        if ((a) == (b)) {                                                          \
            fprintf(stderr, "FAIL %s:%d: %s == %s\n", __FILE__, __LINE__, #a, #b); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

static int
test_minrtt_dispatch(void)
{
    xqc_conn_settings_t cs;
    memset(&cs, 0, sizeof(cs));
    mqvpn_apply_scheduler(&cs, MQVPN_SCHED_MINRTT);
    ASSERT_EQ(cs.scheduler_callback.xqc_scheduler_get_path,
              xqc_minrtt_scheduler_cb.xqc_scheduler_get_path);
    return 0;
}

static int
test_wlb_dispatch(void)
{
    xqc_conn_settings_t cs;
    memset(&cs, 0, sizeof(cs));
    mqvpn_apply_scheduler(&cs, MQVPN_SCHED_WLB);
    ASSERT_EQ(cs.scheduler_callback.xqc_scheduler_get_path,
              xqc_wlb_scheduler_cb.xqc_scheduler_get_path);
    return 0;
}

#if defined(XQC_ENABLE_FEC) && defined(XQC_ENABLE_XOR)
static int
test_backup_fec_dispatch(void)
{
    xqc_conn_settings_t cs;
    memset(&cs, 0, sizeof(cs));
    mqvpn_apply_scheduler(&cs, MQVPN_SCHED_BACKUP_FEC);
    ASSERT_EQ(cs.scheduler_callback.xqc_scheduler_get_path,
              xqc_backup_fec_scheduler_cb.xqc_scheduler_get_path);
    ASSERT_EQ(cs.enable_encode_fec, 1);
    ASSERT_EQ(cs.enable_decode_fec, 1);
    ASSERT_EQ(cs.fec_params.fec_encoder_schemes_num, 1);
    ASSERT_EQ(cs.fec_params.fec_encoder_schemes[0], XQC_XOR_CODE);
    ASSERT_EQ(cs.fec_params.fec_decoder_schemes_num, 1);
    ASSERT_EQ(cs.fec_params.fec_decoder_schemes[0], XQC_XOR_CODE);
    ASSERT_EQ(cs.fec_params.fec_max_symbol_num_per_block, 3);
    ASSERT_EQ(cs.fec_params.fec_mp_mode, XQC_FEC_MP_USE_STB);
    if (cs.fec_params.fec_code_rate < 0.09f || cs.fec_params.fec_code_rate > 0.11f) {
        fprintf(stderr, "FAIL %s:%d: fec_code_rate=%f not ~0.1\n", __FILE__, __LINE__,
                cs.fec_params.fec_code_rate);
        return 1;
    }
    return 0;
}
#else /* FEC disabled at build — verify silent MINRTT fallback */
static int
test_backup_fec_falls_back_to_minrtt_when_no_fec(void)
{
    xqc_conn_settings_t cs;
    memset(&cs, 0, sizeof(cs));
    mqvpn_apply_scheduler(&cs, MQVPN_SCHED_BACKUP_FEC);
    /* Fallback: scheduler_callback set to minrtt, FEC fields untouched (zero). */
    ASSERT_EQ(cs.scheduler_callback.xqc_scheduler_get_path,
              xqc_minrtt_scheduler_cb.xqc_scheduler_get_path);
    ASSERT_EQ(cs.enable_encode_fec, 0);
    ASSERT_EQ(cs.enable_decode_fec, 0);
    ASSERT_EQ(cs.fec_params.fec_encoder_schemes_num, 0);
    ASSERT_EQ(cs.fec_params.fec_decoder_schemes_num, 0);
    return 0;
}
#endif

static int
test_unknown_falls_back_to_minrtt(void)
{
    xqc_conn_settings_t cs;
    memset(&cs, 0, sizeof(cs));
    mqvpn_apply_scheduler(&cs, (mqvpn_scheduler_t)999);
    ASSERT_EQ(cs.scheduler_callback.xqc_scheduler_get_path,
              xqc_minrtt_scheduler_cb.xqc_scheduler_get_path);
    return 0;
}

static int
test_backup_fec_single_path_needs_warn(void)
{
    ASSERT_EQ(mqvpn_check_scheduler_preconditions(MQVPN_SCHED_BACKUP_FEC, 1), true);
    return 0;
}

static int
test_backup_fec_two_paths_no_warn(void)
{
    ASSERT_EQ(mqvpn_check_scheduler_preconditions(MQVPN_SCHED_BACKUP_FEC, 2), false);
    return 0;
}

static int
test_wlb_single_path_no_warn(void)
{
    ASSERT_EQ(mqvpn_check_scheduler_preconditions(MQVPN_SCHED_WLB, 1), false);
    return 0;
}

static int
test_minrtt_zero_paths_no_warn(void)
{
    ASSERT_EQ(mqvpn_check_scheduler_preconditions(MQVPN_SCHED_MINRTT, 0), false);
    return 0;
}

#if defined(XQC_ENABLE_FEC) && defined(XQC_ENABLE_XOR)
static int
test_dgram_qos_for_backup_fec(void)
{
    ASSERT_EQ(mqvpn_dgram_qos_level(MQVPN_SCHED_BACKUP_FEC), XQC_DATA_QOS_NORMAL);
    return 0;
}
#endif

static int
test_dgram_qos_for_other_schedulers(void)
{
    ASSERT_EQ(mqvpn_dgram_qos_level(MQVPN_SCHED_MINRTT), XQC_DATA_QOS_HIGH);
    ASSERT_EQ(mqvpn_dgram_qos_level(MQVPN_SCHED_WLB), XQC_DATA_QOS_HIGH);
    ASSERT_EQ(mqvpn_dgram_qos_level((mqvpn_scheduler_t)999), XQC_DATA_QOS_HIGH);
    return 0;
}

int
main(void)
{
    int failed = 0;
    failed += test_minrtt_dispatch();
    failed += test_wlb_dispatch();
#if defined(XQC_ENABLE_FEC) && defined(XQC_ENABLE_XOR)
    failed += test_backup_fec_dispatch();
#else
    failed += test_backup_fec_falls_back_to_minrtt_when_no_fec();
#endif
    failed += test_unknown_falls_back_to_minrtt();
    failed += test_backup_fec_single_path_needs_warn();
    failed += test_backup_fec_two_paths_no_warn();
#if defined(XQC_ENABLE_FEC) && defined(XQC_ENABLE_XOR)
    failed += test_dgram_qos_for_backup_fec();
#endif
    failed += test_dgram_qos_for_other_schedulers();
    failed += test_wlb_single_path_no_warn();
    failed += test_minrtt_zero_paths_no_warn();
    if (failed) {
        fprintf(stderr, "test_scheduler: %d FAILED\n", failed);
        return 1;
    }
    fprintf(stderr, "test_scheduler: PASS\n");
    return 0;
}
