// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * mqvpn_conn_settings.c — implementation. See mqvpn_conn_settings.h for
 * the contract; tests/test_conn_settings.c pins the asymmetric fields.
 */

#include "mqvpn_conn_settings.h"

#include "libmqvpn.h"
#include "mqvpn_internal.h"
#include "mqvpn_scheduler.h"
#include "mqvpn_sched_names.h"

#include <string.h>

#include <xquic/xquic.h>

/* Send-queue cap. Same value the previous inline blocks used; kept here
 * so adding new mqvpn-wide xquic-tuning knobs lives next to the builder. */
#define XQC_SNDQ_MAX_PKTS 16384

void
mqvpn_apply_scheduler(xqc_conn_settings_t *cs, mqvpn_scheduler_t sched)
{
    /* Invalid/out-of-range values (e.g. a direct API caller bypassing
     * mqvpn_config_set_scheduler()'s validation) fall back to MINRTT,
     * matching the old `default:` case below. Handled up front so the
     * switch itself can drop `default:` and get compile-time coverage:
     * with -Werror -Wswitch (see AGENTS.md build gate), a new
     * mqvpn_scheduler_t enumerator added to libmqvpn.h without a
     * corresponding case here becomes a build failure instead of a
     * silently-missed dispatch. */
    if (!mqvpn_sched_is_valid(sched)) {
        cs->scheduler_callback = xqc_minrtt_scheduler_cb;
        return;
    }

    switch (sched) {
    case MQVPN_SCHED_WLB:
    case MQVPN_SCHED_WLB_UDP_PIN: cs->scheduler_callback = xqc_wlb_scheduler_cb; break;
    case MQVPN_SCHED_BACKUP_FEC:
#if defined(XQC_ENABLE_FEC) && defined(XQC_ENABLE_XOR)
        cs->scheduler_callback = xqc_backup_fec_scheduler_cb;
        cs->enable_encode_fec = 1;
        cs->enable_decode_fec = 1;
        cs->fec_params.fec_encoder_schemes_num = 1;
        cs->fec_params.fec_encoder_schemes[0] = MQVPN_FEC_SCHEME;
        cs->fec_params.fec_decoder_schemes_num = 1;
        cs->fec_params.fec_decoder_schemes[0] = MQVPN_FEC_SCHEME;
        cs->fec_params.fec_code_rate = MQVPN_FEC_CODE_RATE;
        cs->fec_params.fec_max_symbol_num_per_block = MQVPN_FEC_BLOCK_SIZE;
        cs->fec_params.fec_mp_mode = XQC_FEC_MP_USE_STB;
        /* fec_callback intentionally left zero — xqc_set_valid_*_scheme_cb()
           fills it after FEC scheme negotiation completes. */
#else
        /* Built without FEC — silently degrade to MINRTT. main.c parser
           also rejects "backup_fec" at the CLI surface in this case, so this
           branch only protects against direct API callers. */
        cs->scheduler_callback = xqc_minrtt_scheduler_cb;
#endif
        break;
    case MQVPN_SCHED_MINRTT: cs->scheduler_callback = xqc_minrtt_scheduler_cb; break;
    }
}

/* Wires the stock xquic reinjection ctls. Never touches scheduler_callback:
 * Scheduler and Reinjection are orthogonal axes (see the design doc; the
 * xquic datagram_redundancy switch is NOT used precisely because it would
 * override the scheduler). */
static void
mqvpn_apply_reinjection(const mqvpn_conn_settings_input_t *in, xqc_conn_settings_t *cs)
{
    /* Invalid/out-of-range values fall back to OFF (same treatment as
     * mqvpn_apply_scheduler above). */
    mqvpn_reinjection_t mode = in->reinjection;
    if (!mqvpn_reinj_is_valid(mode)) mode = MQVPN_REINJ_OFF;

    switch (mode) {
    case MQVPN_REINJ_OFF: break;
    case MQVPN_REINJ_IDLE:
        cs->reinj_ctl_callback = xqc_default_reinj_ctl_cb;
        cs->mp_enable_reinjection = XQC_REINJ_UNACK_AFTER_SCHED;
        break;
    case MQVPN_REINJ_DEADLINE:
        cs->reinj_ctl_callback = xqc_deadline_reinj_ctl_cb;
        /* AFTER_SEND set explicitly rather than relying on xquic's
         * BEFORE_SCHED auto-add (xqc_conn.c) so the intent is visible here. */
        cs->mp_enable_reinjection =
            XQC_REINJ_UNACK_BEFORE_SCHED | XQC_REINJ_UNACK_AFTER_SEND;
        cs->reinj_flexible_deadline_srtt_factor =
            (in->reinj_srtt_factor_pct > 0 ? in->reinj_srtt_factor_pct : 110) / 100.0;
        cs->reinj_hard_deadline =
            (uint64_t)(in->reinj_hard_deadline_ms > 0 ? in->reinj_hard_deadline_ms
                                                      : 500) *
            1000;
        cs->reinj_deadline_lower_bound =
            (uint64_t)(in->reinj_deadline_lower_bound_ms > 0
                           ? in->reinj_deadline_lower_bound_ms
                           : 20) *
            1000;
        /* xquic computes max(min(factor*min_srtt, hard), lower) — an
         * unclamped lower > hard would silently dominate the max() and
         * defeat the documented "hard is the upper clamp" semantics. */
        if (cs->reinj_deadline_lower_bound > cs->reinj_hard_deadline) {
            cs->reinj_deadline_lower_bound = cs->reinj_hard_deadline;
        }
        break;
    case MQVPN_REINJ_DGRAM:
        cs->reinj_ctl_callback = xqc_dgram_reinj_ctl_cb;
        cs->mp_enable_reinjection = XQC_REINJ_UNACK_AFTER_SEND;
        break;
    }
}

void
mqvpn_build_conn_settings(const mqvpn_conn_settings_input_t *in, xqc_conn_settings_t *out)
{
    memset(out, 0, sizeof(*out));

    /* --- shared hardcoded fields --- */
    out->max_datagram_frame_size = 65535;
    out->proto_version = XQC_VERSION_V1;
    out->pacing_on = 1;
    out->max_pkt_out_size = MQVPN_MAX_PKT_OUT_SIZE;
    out->sndq_packets_used_max = XQC_SNDQ_MAX_PKTS;
    out->so_sndbuf = 8 * 1024 * 1024;
    out->idle_time_out = 120000;
    out->init_idle_time_out = 10000;

    /* Caller-gated, never derived here: see the field comment in
     * mqvpn_conn_settings.h for why this must equal the batched-send
     * registration decision rather than any locally recomputed condition. */
    out->defer_send_flush = in->defer_send_flush ? 1 : 0;

    /* --- congestion control ---
     * Invalid/out-of-range values fall back to BBR2, matching the old
     * `default:` case. Normalized up front so the switch can drop
     * `default:` and get -Wswitch coverage (same treatment as
     * mqvpn_apply_scheduler above). */
    mqvpn_cc_t cc = in->cc;
    if (!mqvpn_cc_is_valid(cc)) cc = MQVPN_CC_BBR2;
#ifndef XQC_ENABLE_UNLIMITED
    /* Built without UNLIMITED — NONE degrades to BBR2, as the old
     * default: case did (main.c's CLI gate rejects "none" up front; this
     * only protects direct API callers). */
    if (cc == MQVPN_CC_NONE) cc = MQVPN_CC_BBR2;
#endif
    switch (cc) {
    case MQVPN_CC_BBR: out->cong_ctrl_callback = xqc_bbr_cb; break;
    case MQVPN_CC_CUBIC: out->cong_ctrl_callback = xqc_cubic_cb; break;
    case MQVPN_CC_NONE:
#ifdef XQC_ENABLE_UNLIMITED
        out->cong_ctrl_callback = xqc_unlimited_cc_cb;
#endif
        /* unreachable when UNLIMITED is off (normalized above); the case
         * label stays so -Wswitch coverage holds in both build configs. */
        break;
    case MQVPN_CC_BBR2:
        out->cong_ctrl_callback = xqc_bbr2_cb;
        out->cc_params.cc_optimization_flags =
            XQC_BBR2_FLAG_RTTVAR_COMPENSATION | XQC_BBR2_FLAG_FAST_CONVERGENCE;
        break;
    }

    /* --- intentional client/server asymmetry (4) ---
     * Each branch documents why these fields differ between sides. Do not
     * collapse without revisiting tests/test_conn_settings.c
     * test_asymmetry_server_vs_client. */
    if (in->is_server) {
        /* server allows multipath unconditionally; client side gates on
         * cfg->multipath. draft-21 §3.2.1 ¶7 PATHS_BLOCKED auto-grant
         * (max_path_id_grant_max_value) is server-only because mqvpn's
         * client is the active path creator. */
        out->enable_multipath = 1;
        out->mp_ping_on = 1;
        out->max_path_id_grant_max_value = 128;
    } else {
        /* client carries the keep-alive role (ping_on=1) and gates MP on
         * cfg->multipath. */
        out->enable_multipath = in->enable_multipath ? 1 : 0;
        out->mp_ping_on = in->enable_multipath ? 1 : 0;
        out->ping_on = 1;

        if (in->recv_rate_bytes_per_sec) {
            out->recv_rate_bytes_per_sec = in->recv_rate_bytes_per_sec;
        }
    }

    /* --- scheduler / FEC params --- */
    mqvpn_apply_scheduler(out, in->scheduler);

    /* --- reinjection --- */
    mqvpn_apply_reinjection(in, out);

    /* --- init_max_path_id: 0 = keep xquic default (XQC_DEFAULT_INIT_MAX_PATH_ID=8) ---
     */
    if (in->init_max_path_id > 0) {
        out->init_max_path_id = in->init_max_path_id;
    }
}

#if defined(__linux__)

/* The bundled binds accept at most 32 datagrams per send (BIND_POSIX_MAX_BATCH
 * in src/bind/posix.c == MQVPN_OFFLOAD_MAX_BATCH); a bigger xquic burst would
 * be re-offered in two calls and quietly halve the batching factor. */
_Static_assert(XQC_MAX_SEND_MSG_ONCE <= 32,
               "raise the bundled binds' batch cap with xquic's burst");

int
mqvpn_tx_batch_register(int udp_gso, xqc_send_mmsg_ex_pt cb,
                        xqc_transport_callbacks_t *tcbs, xqc_config_t *xconfig)
{
    /* mqvpn_tx_batch_enabled's MQVPN_MAX_PKT_OUT_SIZE <= 1500 term is a
     * compatibility guard for the Linux GSO run bound (a full burst of
     * XQC_MAX_SEND_MSG_ONCE datagrams must stay far below the ~64KB kernel
     * ceiling so the bind can skip run splitting). It is not an xquic
     * constraint; it can go once the bind splits runs itself. */
    if (!mqvpn_tx_batch_enabled(udp_gso)) return 0;
    tcbs->write_mmsg_ex = cb;
    xconfig->sendmmsg_on = 1;
    return 1;
}

#endif /* __linux__ */
