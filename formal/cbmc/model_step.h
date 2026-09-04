// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* formal/cbmc/model_step.h — C transliteration of the TLA+ transition
 * relation in formal/MqvpnPathSlot.tla, over an abstract slot tuple.
 *
 * The TLA+ module is normative: each function below names the TLA operator
 * it mirrors and its line range in formal/MqvpnPathSlot.tla. On any
 * divergence between this file and the module, fix whichever one drifted
 * from the OTHER's semantics — the CBMC harness exists precisely to detect
 * that drift against src/path_state_machine.c.
 *
 * Abstraction map (C path_entry_t -> abstract tuple):
 *   state       <-> p->state                       (identity)
 *   attached    <-> p->platform_attached != 0
 *   live        <-> p->xquic_path_live != 0
 *   xqc_id      <-> p->xqc_path_id                 (exact uint64, NOT boolean)
 *   fd_platform <-> p->fd >= 0                     (TLA fdOwner = "platform")
 *   retries     <-> min(p->recreate_retries, PATH_RECREATE_MAX_RETRIES)
 *                   (TLA saturates retries for TypeOK; C increments
 *                    unboundedly — see formal/README.md)
 *   retry_armed <-> p->recreate_after_us != 0
 *   stable_armed<-> p->path_stable_since_us != 0
 *
 * Out of scope (not part of the TLA slot state): state_entered_at_us,
 * last_residence_warn_at_us, statistics fields, name/handle/addr fields.
 */

#ifndef MQVPN_FORMAL_MODEL_STEP_H
#define MQVPN_FORMAL_MODEL_STEP_H

#include "path_state_machine.h"

typedef struct {
    path_lifecycle_t state;
    int attached;     /* boolean */
    int live;         /* boolean */
    uint64_t xqc_id;  /* exact id; 0 = unassigned (TLA NULL) */
    int fd_platform;  /* boolean: platform owns an open fd */
    int retries;      /* saturated at PATH_RECREATE_MAX_RETRIES */
    int retry_armed;  /* boolean */
    int stable_armed; /* boolean */
} abs_slot_t;

static inline abs_slot_t
abs_of_entry(const path_entry_t *p)
{
    abs_slot_t s;
    s.state = p->state;
    s.attached = (p->platform_attached != 0);
    s.live = (p->xquic_path_live != 0);
    s.xqc_id = p->xqc_path_id;
    s.fd_platform = (p->fd >= 0);
    s.retries = (p->recreate_retries < PATH_RECREATE_MAX_RETRIES)
                    ? p->recreate_retries
                    : PATH_RECREATE_MAX_RETRIES;
    s.retry_armed = (p->recreate_after_us != 0);
    s.stable_armed = (p->path_stable_since_us != 0);
    return s;
}

/* ApplyFailure(target) — formal/MqvpnPathSlot.tla:94-104
 * (apply_failure_with_retry_check, src/path_state_machine.c:380-397).
 * Threshold check uses the PRE retries value with >= (not >). */
static inline abs_slot_t
model_apply_failure(abs_slot_t s, path_lifecycle_t target)
{
    int pre_retries = s.retries;
    s.live = 0;
    s.xqc_id = 0;
    s.stable_armed = 0;
    s.retries = (pre_retries < PATH_RECREATE_MAX_RETRIES) ? pre_retries + 1 : pre_retries;
    if (pre_retries + 1 >= PATH_RECREATE_MAX_RETRIES) {
        s.retry_armed = 0;
        s.state = PATH_LC_CLOSED_RECOVERABLE;
    } else {
        s.retry_armed = 1;
        s.state = target;
    }
    return s;
}

/* Shared OK branch of activation-shaped events: enter Validating with the
 * freshly allocated id (OnActivateRequested / OnRetryTimer /
 * OnManualReactivate OK cases). */
static inline abs_slot_t
model_enter_validating(abs_slot_t s, uint64_t new_id)
{
    s.xqc_id = new_id;
    s.live = 1;
    s.retry_armed = 0;
    s.state = PATH_LC_VALIDATING;
    return s;
}

/* Shared PERMANENT branch: retries untouched, timers cleared, straight to
 * ClosedRecoverable (OnActivateRequested / OnRetryTimer OTHER cases). */
static inline abs_slot_t
model_permanent_fail(abs_slot_t s)
{
    s.live = 0;
    s.xqc_id = 0;
    s.stable_armed = 0;
    s.retry_armed = 0;
    s.state = PATH_LC_CLOSED_RECOVERABLE;
    return s;
}

/* model_step — one FSM event handler dispatch, mirroring the event-handler
 * operators of formal/MqvpnPathSlot.tla applied to the slot tuple.
 * Environment bookkeeping (pending sets, allocator, caps) is TLC's job and
 * deliberately absent here. */
static inline abs_slot_t
model_step(abs_slot_t s, path_event_t ev, activate_result_t result, uint64_t new_id,
           path_lifecycle_t validated_target)
{
    switch (ev) {
    case PATH_EVENT_ACTIVATE_REQUESTED:
        /* OnActivateRequested — formal/MqvpnPathSlot.tla:111-127 */
        if (s.state != PATH_LC_PENDING) return s; /* WARN no-op */
        if (result == ACTIVATE_OK) return model_enter_validating(s, new_id);
        if (result == ACTIVATE_TRANSIENT_FAIL)
            return model_apply_failure(s, PATH_LC_CREATE_WAIT);
        return model_permanent_fail(s);

    case PATH_EVENT_RETRY_TIMER:
        /* OnRetryTimer — formal/MqvpnPathSlot.tla:131-147; retry target is
         * the current state (self-loop on TRANSIENT below the cap) */
        if (s.state != PATH_LC_CREATE_WAIT && s.state != PATH_LC_DEGRADED)
            return s; /* WARN no-op */
        if (result == ACTIVATE_OK) return model_enter_validating(s, new_id);
        if (result == ACTIVATE_TRANSIENT_FAIL) return model_apply_failure(s, s.state);
        return model_permanent_fail(s);

    case PATH_EVENT_VALIDATION_OK:
        /* OnValidationOk — formal/MqvpnPathSlot.tla:150-155 */
        if (s.state != PATH_LC_VALIDATING) return s; /* LOG_D no-op */
        s.stable_armed = 1;
        s.state = validated_target;
        return s;

    case PATH_EVENT_XQUIC_REMOVED:
        /* OnXquicRemoved — formal/MqvpnPathSlot.tla:158-167 */
        if (s.state == PATH_LC_VALIDATING)
            return model_apply_failure(s, PATH_LC_CREATE_WAIT);
        if (s.state == PATH_LC_ACTIVE || s.state == PATH_LC_STANDBY)
            return model_apply_failure(s, PATH_LC_DEGRADED);
        if (s.state == PATH_LC_CLOSED_DROPPED) {
            s.live = 0;
            s.xqc_id = 0;
            s.state = s.fd_platform ? PATH_LC_CLOSED_DROPPED : PATH_LC_CLOSED_FREE;
            return s;
        }
        return s; /* WARN no-op */

    case PATH_EVENT_MANUAL_REACTIVATE:
        /* OnManualReactivate — formal/MqvpnPathSlot.tla:172-181; failures
         * are a strict no-op (no retry consumption, timer left intact) */
        if (s.state != PATH_LC_CLOSED_RECOVERABLE && s.state != PATH_LC_CREATE_WAIT &&
            s.state != PATH_LC_DEGRADED)
            return s; /* WARN no-op */
        if (result == ACTIVATE_OK) return model_enter_validating(s, new_id);
        return s;

    case PATH_EVENT_PLATFORM_DROP:
    case PATH_EVENT_REMOVE_API:
        /* OnDropLike — formal/MqvpnPathSlot.tla:186-193 (same field effects
         * for both events; they differ only in reason code / env actions) */
        if (s.state == PATH_LC_CLOSED_DROPPED || s.state == PATH_LC_CLOSED_FREE)
            return s; /* idempotent */
        s.attached = 0;
        s.retry_armed = 0;
        s.stable_armed = 0;
        s.state = PATH_LC_CLOSED_DROPPED;
        return s;

    case PATH_EVENT_ADD_FD:
        /* ApiAddFd — formal/MqvpnPathSlot.tla:429-445. The TLA action is the
         * whole mqvpn_client_add_path_fd_with_outcome composite; the harness
         * reproduces the caller prefix (path_entry_init + fresh fd), so by
         * dispatch time the slot is ClosedFree-shaped with fd_platform = 1
         * and the handler contributes only attached + state. */
        if (s.state != PATH_LC_CLOSED_FREE) return s; /* WARN no-op */
        s.attached = 1;
        s.state = PATH_LC_PENDING;
        return s;

    case PATH_EVENT_CONN_RESET:
        /* OnConnReset — formal/MqvpnPathSlot.tla:198-209 */
        s.live = 0;
        s.xqc_id = 0;
        s.retry_armed = 0;
        s.retries = 0;
        s.stable_armed = 0;
        if (s.attached) {
            s.state = PATH_LC_PENDING;
        } else if (s.state == PATH_LC_CLOSED_DROPPED && !s.fd_platform) {
            s.state = PATH_LC_CLOSED_FREE;
        }
        return s;

    case PATH_EVENT_FD_CLOSED:
        /* OnFdClosed — formal/MqvpnPathSlot.tla:213-220 */
        if (s.state != PATH_LC_CLOSED_DROPPED) return s; /* LOG_D no-op */
        s.fd_platform = 0;
        s.state =
            (!s.live && s.xqc_id == 0) ? PATH_LC_CLOSED_FREE : PATH_LC_CLOSED_DROPPED;
        return s;
    }
    return s; /* unreachable for in-range events */
}

/* g_p15_xqc_app_status_for — src/path_state_machine.c:317-325 shape pin.
 * Expected xquic app-status notification for a real transition from -> to;
 * 0 = no notification. */
static inline int
model_g_p15_status(path_lifecycle_t from, path_lifecycle_t to)
{
    if (from == PATH_LC_ACTIVE && to == PATH_LC_STANDBY) return 1;
    if (from == PATH_LC_STANDBY && to == PATH_LC_ACTIVE) return 2;
    if ((from == PATH_LC_ACTIVE || from == PATH_LC_STANDBY) && to == PATH_LC_DEGRADED)
        return 3;
    return 0;
}

#endif /* MQVPN_FORMAL_MODEL_STEP_H */
