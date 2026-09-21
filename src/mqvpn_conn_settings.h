// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * mqvpn_conn_settings.h — single source of truth for mqvpn's xquic
 * connection settings construction. To add a knob, extend the input
 * struct, the helper body, and tests/test_conn_settings.c in lock-step.
 */

#ifndef MQVPN_CONN_SETTINGS_H
#define MQVPN_CONN_SETTINGS_H

#include "mqvpn_internal.h"
#include <stdbool.h>
#include <stdint.h>
#include <xquic/xquic.h>

/* Caller-driven inputs. The bools are parameterised (not a single
 * `is_server` flag) so each call site documents its intent. */
typedef struct {
    bool is_server;
    bool enable_multipath; /* server callers pass true */
    mqvpn_scheduler_t scheduler;
    mqvpn_cc_t cc;                    /* congestion control algorithm */
    uint64_t init_max_path_id;        /* 0 = leave xquic default */
    uint64_t recv_rate_bytes_per_sec; /* 0 = no cap. Client-only: the
        builder hard-zeroes it for servers (a server-side conn-level cap
        would throttle client uplink). */
    mqvpn_reinjection_t reinjection;  /* MQVPN_REINJ_OFF = feature disabled */
    /* reinj_srtt_factor_pct / reinj_hard_deadline_ms /
     * reinj_deadline_lower_bound_ms: deadline mode only; 0 = engine default
     * (110 / 500 / 20 respectively). The config layer validates these to
     * [100,1000] / [1,60000] / [1,60000] and never passes 0 through, so 0
     * can only arrive via a direct API caller bypassing config parsing —
     * and any other out-of-range NONZERO value is likewise that caller's
     * responsibility to have validated; the builder only handles the
     * 0-means-default fallback and clamps reinj_deadline_lower_bound_ms
     * down to reinj_hard_deadline_ms when it would otherwise exceed it. */
    int reinj_srtt_factor_pct;
    int reinj_hard_deadline_ms;
    int reinj_deadline_lower_bound_ms;
    /* defer_send_flush: hold the engine flush until the caller drives the
     * engine, so a run of sends forms one sendmmsg/GSO batch instead of one
     * syscall per packet. Covers both lanes — the DATAGRAM lane (raw IP) and
     * the hybrid TCP lane's QUIC STREAM writes, which measured a 1.00 batching
     * factor before this, i.e. UdpGso bought hybrid mode nothing at all.
     *
     * MUST track the batched-send (write_mmsg_ex) registration exactly: with
     * no batch callback registered xquic sends one packet per syscall
     * regardless, so deferring would move the flush for no benefit at all.
     * Every call site therefore passes the SAME stored flag it gated that
     * registration on — never a re-derived condition, which is what would let
     * them drift apart. */
    bool defer_send_flush;
} mqvpn_conn_settings_input_t;

/* Populates *out with mqvpn-canonical xquic conn settings. Always begins
 * with memset(0), so the caller is not required to zero `out` first. */
MQVPN_INTERNAL void mqvpn_build_conn_settings(const mqvpn_conn_settings_input_t *in,
                                              xqc_conn_settings_t *out);

#if defined(__linux__)
/* One definition of the batched-send registration for both endpoints (it is
 * the engine-create half of the decision defer_send_flush mirrors above, so
 * it lives in this header with it). When mqvpn_tx_batch_enabled(udp_gso)
 * holds, registers `cb` as tcbs->write_mmsg_ex, sets xconfig->sendmmsg_on
 * and returns 1; otherwise touches nothing and returns 0. The callback stays
 * a caller parameter because each TU registers its own static
 * cb_write_mmsg_ex. Callers record the result (tx_batch) and feed that same
 * stored flag to conn_settings.defer_send_flush. The kernel probe and the
 * `udp-gso: ` marker are the POSIX bind's job. */
MQVPN_INTERNAL int mqvpn_tx_batch_register(int udp_gso, xqc_send_mmsg_ex_pt cb,
                                           xqc_transport_callbacks_t *tcbs,
                                           xqc_config_t *xconfig);
#endif

#endif /* MQVPN_CONN_SETTINGS_H */
