/*
 * mqvpn_scheduler.h — Scheduler dispatch helper + FEC tuning knobs.
 *
 * NOT part of the public API. Do not install. xquic-dependent.
 */
#ifndef MQVPN_SCHEDULER_H
#define MQVPN_SCHEDULER_H

#include "libmqvpn.h"
#include <xquic/xquic.h> /* brings in xqc_configure.h with XQC_ENABLE_* defines */
#include <stdlib.h>      /* getenv */
#include <string.h>      /* strcmp */

/* ===========================================================================
 * MQVPN_SCHED_BACKUP_FEC tuning knobs (only meaningful on FEC-enabled builds)
 *
 * Defaults match xquic's reference client (third_party/xquic/tests/test_client.c
 * L5273-5298). xquic computes per-block repair count as
 *   repair_n = max(1, BLOCK_SIZE * CODE_RATE)
 * With defaults (BLOCK_SIZE=3, CODE_RATE=0.1) the floor dominates:
 *   max(1, 3 * 0.1) = max(1, 0.3) = 1 repair / 3 source ≈ 33% overhead.
 * Lowering CODE_RATE further has no effect until BLOCK_SIZE grows past 1/CODE_RATE.
 *
 * To experiment: change values, rebuild, re-run perf-weekly bench.
 *
 * TODO: Task 14 (FEC-downgrade warning at ESTABLISHED) was deferred — xquic
 * has no public API to query negotiated FEC status post-handshake. Revisit
 * when xquic exposes one (or via xqc_conn_get_lastest_settings()-style API).
 * =========================================================================== */
#if defined(XQC_ENABLE_FEC) && defined(XQC_ENABLE_XOR)
#  define MQVPN_FEC_SCHEME     XQC_XOR_CODE
#  define MQVPN_FEC_CODE_RATE  0.1f /* repair-to-source ratio (xquic semantic) */
#  define MQVPN_FEC_BLOCK_SIZE 3    /* max source symbols per FEC block */
#endif

/* Apply scheduler-specific xquic conn settings (callback + FEC params).
 * Used by both client (mqvpn_client.c) and server (mqvpn_server.c). */
void mqvpn_apply_scheduler(xqc_conn_settings_t *cs, mqvpn_scheduler_t sched);

/* Map scheduler choice → DATAGRAM send-time QoS level.
 *
 * xquic only enables FEC encoding for DATAGRAMs when qos > XQC_DATA_QOS_HIGH
 * (third_party/xquic/src/transport/xqc_packet_out.c:1317-1326). On FEC-enabled
 * builds with MQVPN_SCHED_BACKUP_FEC selected, return NORMAL so repair packets
 * actually get generated. All other cases keep HIGH (current default).
 */
static inline xqc_data_qos_level_t
mqvpn_dgram_qos_level(mqvpn_scheduler_t s)
{
#ifdef MQVPN_DEBUG_QOS_OVERRIDE
    {
        const char *override = getenv("MQVPN_DGRAM_QOS_OVERRIDE");
        if (override) {
            if (strcmp(override, "high") == 0) return XQC_DATA_QOS_HIGH;
            if (strcmp(override, "medium") == 0) return XQC_DATA_QOS_MEDIUM;
            if (strcmp(override, "normal") == 0) return XQC_DATA_QOS_NORMAL;
            if (strcmp(override, "low") == 0) return XQC_DATA_QOS_LOW;
            if (strcmp(override, "lowest") == 0) return XQC_DATA_QOS_LOWEST;
        }
    }
#endif
#if defined(XQC_ENABLE_FEC) && defined(XQC_ENABLE_XOR)
    if (s == MQVPN_SCHED_BACKUP_FEC) {
        return XQC_DATA_QOS_NORMAL;
    }
#endif
    (void)s;
    return XQC_DATA_QOS_HIGH;
}

#endif /* MQVPN_SCHEDULER_H */
