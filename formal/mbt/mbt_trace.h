// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* formal/mbt/mbt_trace.h — the types of the client-glue traces that
 * formal/mbt/gen_traces.py generates from the TLC state graph of
 * formal/MqvpnPathSlot.tla (path_slot_traces.inc). Include this header, then
 * the .inc. Every field is uint8_t / uint16_t, so the table does not depend
 * on pointer size or packing. */

#ifndef MQVPN_FORMAL_MBT_TRACE_H
#define MQVPN_FORMAL_MBT_TRACE_H

#include <stdint.h>

enum { MBT_MAX_INC = 3 }; /* = MaxIncarnations of the MBT cfg */

/* path_lifecycle_t and mqvpn_path_status_t, value for value; the replay
 * driver static-asserts each against its C twin. */
typedef enum {
    MBT_ST_PENDING,
    MBT_ST_CREATE_WAIT,
    MBT_ST_VALIDATING,
    MBT_ST_ACTIVE,
    MBT_ST_STANDBY,
    MBT_ST_DEGRADED,
    MBT_ST_CLOSED_RECOVERABLE,
    MBT_ST_CLOSED_DROPPED,
    MBT_ST_CLOSED_FREE,
} mbt_state_t;
typedef enum {
    MBT_STATUS_PENDING = 0,
    MBT_STATUS_ACTIVE = 1,
    MBT_STATUS_DEGRADED = 2,
    MBT_STATUS_STANDBY = 3,
    MBT_STATUS_CLOSED = 4,
} mbt_status_t;

typedef enum {
    MBT_CONN_IDLE,
    MBT_CONN_CONNECTING,
    MBT_CONN_TUNNEL_READY,
    MBT_CONN_ESTABLISHED,
    MBT_CONN_RECONNECTING,
    MBT_CONN_CLOSED
} mbt_conn_t;
typedef enum {
    MBT_OP_CONNECT,
    MBT_OP_MP_READY,
    MBT_OP_TUNNEL_READY,
    MBT_OP_ESTABLISH,
    MBT_OP_PEER_CLOSE,
    MBT_OP_DISCONNECT,
    MBT_OP_RECONNECT_TICK,
    MBT_OP_RECONNECT_API,
    MBT_OP_RETRY_FIRE,
    MBT_OP_POLL,
    MBT_OP_STABLE,
    MBT_OP_REACTIVATE,
    MBT_OP_XQC_VALIDATE, /* fake path -> xquic-ACTIVE, no client call */
    MBT_OP_XQC_LOSE,     /* spontaneous abandon / idle reap / remove-active: fake path not
                            ACTIVE, no client call */
    MBT_OP_DELIVER_REMOVAL,
    MBT_OP_ADD,
    MBT_OP_DROP,
    MBT_OP_REMOVE,
    MBT_OP_DELIVER_RELEASE,
    MBT_OP_DESTROY,
    MBT_PROBE_TICK,
    MBT_PROBE_POLL_ID,
    MBT_PROBE_REACTIVATE,
    MBT_PROBE_REMOVAL_ID,
    MBT_PROBE_TICK_AFTER_DISCONNECT,
} mbt_op_t;
enum { MBT_RES_NONE, MBT_RES_OK, MBT_RES_TRANSIENT, MBT_RES_PERMANENT, MBT_RES_FAIL };

typedef struct {
    uint8_t mp, mp_credit, req_sched, backup_fec, reconnect;
} mbt_config_t;
typedef struct {
    uint8_t op, result; /* activation / connect / close_path outcome */
    uint8_t arg_id;     /* new model id (OK activation), removal id, probe id */
    uint8_t arg_inc;    /* incarnation: a release's / probe's handle, the slot's (ADD: the
                           new one) for slot ops and every activation row */
    /* expected post-state */
    uint8_t state, attached, live, released, retries, retry_armed, stable_armed;
    uint8_t xqc_id; /* model id, exact (the fake returns model ids) */
    uint8_t conn, mp_ready, hold, ops_set, status;
    uint8_t release_count[MBT_MAX_INC];
    uint8_t cmd_connect, cmd_create_path, cmd_close_path,
        cmd_conn_close;      /* expected counts */
    uint8_t path_event_rule; /* 1: the weak path_event rule applies to this step */
} mbt_step_t;
typedef struct {
    mbt_config_t cfg;
    uint16_t first, n;
} mbt_trace_t;
/* path_slot_traces.inc defines: static const mbt_step_t MBT_STEPS[]; static const
 * mbt_trace_t MBT_TRACES[]; #define MBT_N_STEPS / MBT_N_TRACES; MBT_GEN_MAX_RETRIES. */

#endif
