/*
 * path_state_machine.h — Path lifecycle internal state machine.
 *
 * PR1 (Phase 1) introduced invariant checks, transition logging, and
 * state-residence timers against the legacy 5-value `mqvpn_path_status_t`.
 * PR2 added the internal 7-value `path_lifecycle_t` (defined in
 * `path_entry_internal.h`) that splits MQVPN_PATH_CLOSED into
 * RECOVERABLE / DROPPED / FREE, with `path_invariant_check()` enforcing
 * the per-state field constraints + the denormalization invariant
 * `status == path_public_status_from_lifecycle(state)`.
 *
 * PR3 will further split PENDING into PENDING / CREATE_WAIT / VALIDATING.
 * PR4 will consolidate transitions through a single `path_on_event()`
 * aggregator and forbid direct field assignment via CI lint.
 */

#ifndef MQVPN_PATH_STATE_MACHINE_H
#define MQVPN_PATH_STATE_MACHINE_H

#include "libmqvpn.h"
#include "path_entry_internal.h"
#include <stdint.h>

/* Reason tag for transition logs. Phase 4 will extend this. */
typedef enum {
    PATH_REASON_ADD_FD = 0,
    PATH_REASON_ACTIVATE_OK,
    PATH_REASON_ACTIVATE_FAILED,
    PATH_REASON_XQUIC_REMOVED,
    PATH_REASON_PLATFORM_DROPPED,
    PATH_REASON_REMOVE_API,
    PATH_REASON_REACTIVATE,
    PATH_REASON_CONN_RESET,
    PATH_REASON_RETRY_RESET,
} path_transition_reason_t;

/* Phase 2 (PR2): internal 7-state lifecycle helpers.
 * The enum `path_lifecycle_t` is defined in path_entry_internal.h to avoid
 * a circular include (path_state_machine.h includes path_entry_internal.h
 * for path_entry_t, which contains a path_lifecycle_t field).
 *
 * PR3 will further split PENDING into PENDING / CREATE_WAIT / VALIDATING
 * (→ 9 states total). */

/* Map internal lifecycle → public 5-state. Pure function. */
mqvpn_path_status_t path_public_status_from_lifecycle(path_lifecycle_t s);

/* Human-readable name (for logs). */
const char *path_lifecycle_name(path_lifecycle_t s);

/* Debug-build 7-state invariant check. Asserts the (state, platform_attached,
 * xquic_path_live, fd_valid, xqc_path_id, recreate_after_us,
 * path_stable_since_us) tuple is legal AND that p->status ==
 * path_public_status_from_lifecycle(p->state) (denormalization invariant).
 * No-op in release builds. */
void path_invariant_check(const path_entry_t *p);

/* Human-readable name of an mqvpn_path_status_t value. */
const char *mqvpn_path_status_name(mqvpn_path_status_t s);

/* Reason tag → string. */
const char *mqvpn_path_transition_reason_name(path_transition_reason_t r);

/* Debug-build invariant check for the legacy 5-state model.
 * Asserts that the (status, platform_attached, xquic_path_live,
 * fd_valid, xqc_path_id, recreate_after_us, path_stable_since_us)
 * tuple is in a known-legal combination. No-op in release builds
 * (uses assert()). MUST be called only after all coupled field
 * updates of a transition are complete — never mid-mutation. */
void path_invariant_check_legacy(const path_entry_t *p);

/* Set state_entered_at_us = now_us; reset last_residence_warn_at_us = 0.
 * Call after every transition that changes status. */
void path_mark_state_entry(path_entry_t *p, uint64_t now_us);

/* Pure boolean: should the residence-warn fire for `p` at `now_us`?
 * No logging side effect, no field mutation. Wrapper in mqvpn_client.c
 * combines this with LOG_W. Exposed for unit testing without a
 * mqvpn_client_t. */
int path_should_warn_residence(const path_entry_t *p, uint64_t now_us);

/* Pure boolean: is a status assignment from `old` to `new_status` a real
 * transition (1) or a self-loop to suppress (0)?
 *
 * Self-loops are only suppressed when state_entered_at_us has already been
 * recorded — first entry to a fresh slot (memset zero-init leaves both
 * status==PENDING==0 and state_entered_at_us==0) MUST be treated as a real
 * transition so path_mark_state_entry runs and the residence-warn timer
 * starts ticking.
 *
 * Pure helper used by mqvpn_client.c's set_path_status_with_log wrapper —
 * extracted so the decision can be unit-tested without a mqvpn_client_t. */
int path_is_real_transition(mqvpn_path_status_t old, mqvpn_path_status_t new_status,
                            uint64_t state_entered_at_us);

/* Residence thresholds (microseconds). */
#define PATH_RESIDENCE_PENDING_WARN_US   ((uint64_t)30 * 1000 * 1000)
#define PATH_RESIDENCE_DEGRADED_GRACE_US ((uint64_t)60 * 1000 * 1000)

#endif /* MQVPN_PATH_STATE_MACHINE_H */
