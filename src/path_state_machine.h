/*
 * path_state_machine.h — Observability helpers for path lifecycle (Phase 1)
 *
 * Phase 1 provides invariant checks, transition logging support, and
 * state-residence timers for the legacy 5-value `mqvpn_path_status_t`
 * model. Future phases will introduce an internal multi-state lifecycle
 * and consolidate transitions through a single aggregator.
 */

#ifndef MQVPN_PATH_STATE_MACHINE_H
#define MQVPN_PATH_STATE_MACHINE_H

#include "libmqvpn.h"
#include <stdint.h>

/* Forward decl — internal type defined in mqvpn_client.c. */
typedef struct path_entry_s path_entry_t;

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

/* Residence thresholds (microseconds). */
#define PATH_RESIDENCE_PENDING_WARN_US   ((uint64_t)30 * 1000 * 1000)
#define PATH_RESIDENCE_DEGRADED_GRACE_US ((uint64_t)60 * 1000 * 1000)

#endif /* MQVPN_PATH_STATE_MACHINE_H */
