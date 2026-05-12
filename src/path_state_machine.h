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

/* PR4: Event-driven transition API.
 *
 * Caller passes (path_entry_t*, event, ctx); path_on_event() resolves the
 * next state per spec §5.1/§5.1.1, mutates all lifecycle fields atomically,
 * fires residence-timer hooks, logs the transition, and emits the public
 * path_event callback. Direct field assignment from outside
 * path_state_machine.c is forbidden (lint enforced — spec §7.1).
 *
 * EVENT_FD_CLOSED is intentionally absent — spec §7.2 (PR5) introduces both
 * the event and its emitter together.
 */
typedef enum {
    PATH_EVENT_ACTIVATE_REQUESTED = 0,
    PATH_EVENT_RETRY_TIMER,
    PATH_EVENT_VALIDATION_OK,
    PATH_EVENT_XQUIC_REMOVED,
    PATH_EVENT_MANUAL_REACTIVATE,
    PATH_EVENT_PLATFORM_DROP,
    PATH_EVENT_REMOVE_API,
    PATH_EVENT_ADD_FD,
    PATH_EVENT_CONN_RESET,
    PATH_EVENT_FD_CLOSED, /* PR5 - platform reports fd close completion */
} path_event_t;

/* Activation attempt classification (spec §6.6). */
typedef enum {
    ACTIVATE_OK = 0,
    ACTIVATE_TRANSIENT_FAIL, /* retry counter consumed */
    ACTIVATE_PERMANENT_FAIL, /* CLOSED_RECOVERABLE direct, retries unchanged */
} activate_result_t;

/* Per-event context. Members valid by event type:
 *   ACTIVATE_REQUESTED / RETRY_TIMER / MANUAL_REACTIVATE:
 *     result, new_xqc_path_id (OK only), now_us
 *   VALIDATION_OK:
 *     validated_target (ACTIVE or STANDBY per initial_app_status), now_us
 *   XQUIC_REMOVED / PLATFORM_DROP / REMOVE_API / ADD_FD / CONN_RESET:
 *     now_us only
 *
 * Caller MUST always populate now_us (FSM does not call client_now_us()
 * internally so the clock stays injectable for tests). */
typedef struct {
    activate_result_t result;
    uint64_t new_xqc_path_id;
    path_lifecycle_t validated_target;
    uint64_t now_us;
} path_event_ctx_t;

struct mqvpn_client_s; /* forward decl - full type lives in mqvpn_client.c */

/* PR4 - Event-driven transition aggregator. Spec §5.0-§5.3, §6. */
void path_on_event(struct mqvpn_client_s *c, path_entry_t *p, path_event_t ev,
                   const path_event_ctx_t *ctx);

const char *path_event_name(path_event_t ev);

/* PR4 - Compile-time pin for FSM design shape (rev5 / bc1fa8d pattern).
 * If path_lifecycle_t grows a new state, or CLOSED_FREE is reordered, this
 * assert breaks so the author must revisit every switch-on-lifecycle site
 * (add_path_outcome_from_state, path_on_event handlers, etc.). Same logic
 * pins path_event_t to catch unannounced event-list expansion.
 * ASCII-only message for MSVC compatibility. */
_Static_assert(PATH_LC_CLOSED_FREE == 8,
               "path_lifecycle_t shape changed - review all FSM switches");
_Static_assert(PATH_EVENT_CONN_RESET == 8,
               "path_event_t shape changed - review path_on_event dispatch");
_Static_assert(PATH_EVENT_FD_CLOSED == 9,
               "path_event_t shape changed - review path_on_event dispatch + "
               "path_on_fd_closed handler");

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
    PATH_REASON_FD_CLOSED, /* PR5 - symmetric with PATH_REASON_XQUIC_REMOVED */
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

/* PR4 - Path retry/stability constants (relocated from mqvpn_client.c).
 * Both mqvpn_client.c (for logging) and path_state_machine.c (for retry
 * helper + stable timer) need these. */
#define PATH_RECREATE_DELAY_US     (5ULL * 1000000)  /* 5 sec initial */
#define PATH_RECREATE_MAX_DELAY_US (60ULL * 1000000) /* 60 sec max backoff */
#define PATH_RECREATE_MAX_RETRIES  6                 /* max consecutive failures */
#define PATH_STABLE_THRESHOLD_US   (30ULL * 1000000) /* 30 sec to confirm stable */

/* PR4 - Relocated from mqvpn_client.c (originally static). path_on_event()
 * body and the residual callsites that still emit explicit reason tags
 * share these entries. */
void set_path_state_with_log(struct mqvpn_client_s *c, path_entry_t *p,
                             path_lifecycle_t new_state, path_transition_reason_t reason);
void path_log_state_change(struct mqvpn_client_s *c, const path_entry_t *p,
                           path_lifecycle_t old, path_transition_reason_t reason);
uint64_t path_recreate_backoff(int retries);
void path_entry_init(path_entry_t *p);

/* Residence thresholds (microseconds). */
#define PATH_RESIDENCE_PENDING_WARN_US   ((uint64_t)30 * 1000 * 1000)
#define PATH_RESIDENCE_DEGRADED_GRACE_US ((uint64_t)60 * 1000 * 1000)

/* PR4 - Accessors used by path_on_event() in path_state_machine.c to talk
 * back to the owning mqvpn_client_t. Implementations live in mqvpn_client.c
 * with __attribute__((visibility("hidden"))) so libmqvpn.so does not export
 * them. */
uint64_t client_now_us(const struct mqvpn_client_s *c);
void client_log(struct mqvpn_client_s *c, mqvpn_log_level_t level, const char *fmt, ...);
void path_fsm_fire_path_event(struct mqvpn_client_s *c, const path_entry_t *p);

/* PR4 - Per-tick stable-budget reset (relocated from mqvpn_client.c for
 * §7.1 file-scope allow on path_stable_since_us / recreate_retries writes).
 * Called per path slot from tick_path_recovery. */
void path_fsm_tick_confirm_stable(struct mqvpn_client_s *c, path_entry_t *p,
                                  uint64_t now_us);

#endif /* MQVPN_PATH_STATE_MACHINE_H */
