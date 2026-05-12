/* src/path_state_machine.c — Phase 1 observability helpers. */

#include "path_state_machine.h"
#include <assert.h>
#include <string.h>

const char *
mqvpn_path_status_name(mqvpn_path_status_t s)
{
    switch (s) {
    case MQVPN_PATH_PENDING: return "PENDING";
    case MQVPN_PATH_ACTIVE: return "ACTIVE";
    case MQVPN_PATH_STANDBY: return "STANDBY";
    case MQVPN_PATH_DEGRADED: return "DEGRADED";
    case MQVPN_PATH_CLOSED: return "CLOSED";
    }
    return "UNKNOWN";
}

const char *
mqvpn_path_transition_reason_name(path_transition_reason_t r)
{
    switch (r) {
    case PATH_REASON_ADD_FD: return "ADD_FD";
    case PATH_REASON_ACTIVATE_OK: return "ACTIVATE_OK";
    case PATH_REASON_ACTIVATE_FAILED: return "ACTIVATE_FAILED";
    case PATH_REASON_XQUIC_REMOVED: return "XQUIC_REMOVED";
    case PATH_REASON_PLATFORM_DROPPED: return "PLATFORM_DROPPED";
    case PATH_REASON_REMOVE_API: return "REMOVE_API";
    case PATH_REASON_REACTIVATE: return "REACTIVATE";
    case PATH_REASON_CONN_RESET: return "CONN_RESET";
    case PATH_REASON_RETRY_RESET: return "RETRY_RESET";
    case PATH_REASON_FD_CLOSED: return "FD_CLOSED";
    }
    return "UNKNOWN";
}

/* Other helpers stubbed; will be filled in B7/B10. */
void
path_invariant_check_legacy(const path_entry_t *p)
{
#ifndef NDEBUG
    int fd_valid = (p->fd >= 0);
    switch (p->status) {
    case MQVPN_PATH_PENDING:
        assert(p->platform_attached == 1);
        assert(p->xquic_path_live == 0);
        assert(fd_valid);
        assert(p->xqc_path_id == 0);
        assert(p->recreate_after_us == 0); /* PENDING is not retry-armed */
        assert(p->path_stable_since_us == 0);
        break;
    case MQVPN_PATH_ACTIVE:
    case MQVPN_PATH_STANDBY:
        assert(p->platform_attached == 1);
        assert(p->xquic_path_live == 1);
        assert(fd_valid);
        /* xqc_path_id == 0 is legal for the primary path (initial QUIC
         * connection path); secondary paths always receive a non-zero ID
         * from xqc_conn_create_path(). No per-slot "is_primary" flag
         * exists in Phase 1, so we cannot tighten this further here. */
        assert(p->recreate_after_us == 0); /* usable states have no pending retry */
        break;
    case MQVPN_PATH_DEGRADED:
        assert(p->platform_attached == 1);
        assert(p->xquic_path_live == 0);
        assert(fd_valid);
        assert(p->xqc_path_id == 0);
        assert(p->recreate_after_us != 0); /* DEGRADED MUST be retry-armed */
        assert(p->path_stable_since_us == 0);
        break;
    case MQVPN_PATH_CLOSED:
        /* Two legal sub-cases (recoverable vs dropped), distinguished
         * by platform_attached. Fields beyond platform_attached are
         * lazy in the dropped case. */
        if (p->platform_attached == 1) {
            /* CLOSED_RECOVERABLE: retry exhausted, fd still valid */
            assert(p->xquic_path_live == 0);
            assert(fd_valid);
            assert(p->xqc_path_id == 0);
            assert(p->recreate_after_us == 0); /* retry NOT re-armed */
            assert(p->path_stable_since_us == 0);
        } else {
            /* CLOSED_DROPPED: cleanup may be lazy */
            assert(p->recreate_after_us == 0);
            assert(p->path_stable_since_us == 0);
        }
        break;
    }
#else
    (void)p;
#endif
}

void
path_mark_state_entry(path_entry_t *p, uint64_t now_us)
{
    p->state_entered_at_us = now_us;
    p->last_residence_warn_at_us = 0; /* clear residence warn debounce */
}

int
path_is_real_transition(mqvpn_path_status_t old, mqvpn_path_status_t new_status,
                        uint64_t state_entered_at_us)
{
    /* Different states → always a real transition. */
    if (old != new_status) return 1;

    /* Same state, but state_entered_at_us not yet recorded → first entry
     * to a fresh slot (zero-init pattern). MUST run path_mark_state_entry
     * so the residence-warn timer can fire later. */
    if (state_entered_at_us == 0) return 1;

    /* Same state, already recorded → idempotent self-loop, suppress. */
    return 0;
}

mqvpn_path_status_t
path_public_status_from_lifecycle(path_lifecycle_t s)
{
    switch (s) {
    case PATH_LC_PENDING:
    case PATH_LC_CREATE_WAIT:
    case PATH_LC_VALIDATING: return MQVPN_PATH_PENDING;
    case PATH_LC_ACTIVE: return MQVPN_PATH_ACTIVE;
    case PATH_LC_STANDBY: return MQVPN_PATH_STANDBY;
    case PATH_LC_DEGRADED: return MQVPN_PATH_DEGRADED;
    case PATH_LC_CLOSED_RECOVERABLE:
    case PATH_LC_CLOSED_DROPPED:
    case PATH_LC_CLOSED_FREE: return MQVPN_PATH_CLOSED;
    }
    /* unreachable; keep the compiler happy */
    return MQVPN_PATH_CLOSED;
}

void
path_invariant_check(const path_entry_t *p)
{
#ifndef NDEBUG
    /* Denormalization invariant: status must always be the public projection
     * of state. Drift is a bug. */
    assert(p->status == path_public_status_from_lifecycle(p->state));

    int fd_valid = (p->fd >= 0);

    switch (p->state) {
    case PATH_LC_PENDING:
        assert(p->platform_attached == 1);
        assert(p->xquic_path_live == 0);
        assert(fd_valid);
        assert(p->xqc_path_id == 0);
        assert(p->recreate_after_us == 0);
        assert(p->path_stable_since_us == 0);
        break;
    case PATH_LC_CREATE_WAIT:
        assert(p->platform_attached == 1);
        assert(!p->xquic_path_live);
        assert(fd_valid);
        /* xqc_path_id is intentionally NOT asserted: a CREATE_WAIT entered
         * after a previous validation cycle on the primary path may still
         * carry id=0. Same exception as PR2 ACTIVE/STANDBY (commit e4d5dc6)
         * and VALIDATING. */
        assert(p->recreate_after_us != 0);
        break;
    case PATH_LC_VALIDATING:
        assert(p->platform_attached == 1);
        assert(p->xquic_path_live == 1);
        assert(fd_valid);
        /* xqc_path_id is intentionally NOT asserted: primary path keeps id=0
         * through validation. Same exception as PR2 ACTIVE/STANDBY. */
        assert(p->recreate_after_us == 0);
        break;
    case PATH_LC_ACTIVE:
    case PATH_LC_STANDBY:
        assert(p->platform_attached == 1);
        assert(p->xquic_path_live == 1);
        assert(fd_valid);
        /* xqc_path_id == 0 is legal for the primary path (initial QUIC
         * connection path); secondary paths always receive a non-zero ID
         * from xqc_conn_create_path(). No per-slot "is_primary" flag
         * exists yet, so we cannot tighten this further here. */
        assert(p->recreate_after_us == 0);
        break;
    case PATH_LC_DEGRADED:
        assert(p->platform_attached == 1);
        assert(p->xquic_path_live == 0);
        assert(fd_valid);
        assert(p->xqc_path_id == 0);
        assert(p->recreate_after_us != 0);
        assert(p->path_stable_since_us == 0);
        break;
    case PATH_LC_CLOSED_RECOVERABLE:
        assert(p->platform_attached == 1);
        assert(p->xquic_path_live == 0);
        assert(fd_valid);
        assert(p->xqc_path_id == 0);
        assert(p->recreate_after_us == 0);
        assert(p->path_stable_since_us == 0);
        break;
    case PATH_LC_CLOSED_DROPPED:
        /* Lazy: only enforce platform_attached=0 + recreate_after_us=0 +
         * path_stable_since_us=0. Other fields may carry over from prior
         * state until xquic-removed and fd-closed events finish cleanup
         * (PR3 spec §5.1). */
        assert(p->platform_attached == 0);
        assert(p->recreate_after_us == 0);
        assert(p->path_stable_since_us == 0);
        break;
    case PATH_LC_CLOSED_FREE:
        /* All zero — slot reusable. */
        assert(p->platform_attached == 0);
        assert(p->xquic_path_live == 0);
        assert(p->fd < 0);
        assert(p->xqc_path_id == 0);
        assert(p->recreate_after_us == 0);
        assert(p->path_stable_since_us == 0);
        break;
    }
#else
    (void)p;
#endif
}

const char *
path_lifecycle_name(path_lifecycle_t s)
{
    switch (s) {
    case PATH_LC_PENDING: return "PENDING";
    case PATH_LC_CREATE_WAIT: return "CREATE_WAIT";
    case PATH_LC_VALIDATING: return "VALIDATING";
    case PATH_LC_ACTIVE: return "ACTIVE";
    case PATH_LC_STANDBY: return "STANDBY";
    case PATH_LC_DEGRADED: return "DEGRADED";
    case PATH_LC_CLOSED_RECOVERABLE: return "CLOSED_RECOVERABLE";
    case PATH_LC_CLOSED_DROPPED: return "CLOSED_DROPPED";
    case PATH_LC_CLOSED_FREE: return "CLOSED_FREE";
    }
    return "UNKNOWN";
}

int
path_should_warn_residence(const path_entry_t *p, uint64_t now_us)
{
    if (p->state_entered_at_us == 0) return 0;

    uint64_t anchor = p->last_residence_warn_at_us != 0 ? p->last_residence_warn_at_us
                                                        : p->state_entered_at_us;
    uint64_t since_anchor = now_us - anchor;

    switch (p->status) {
    case MQVPN_PATH_PENDING: return since_anchor > PATH_RESIDENCE_PENDING_WARN_US;
    case MQVPN_PATH_DEGRADED:
        return p->recreate_after_us != 0 &&
               now_us > p->recreate_after_us + PATH_RESIDENCE_DEGRADED_GRACE_US &&
               since_anchor > PATH_RESIDENCE_DEGRADED_GRACE_US;
    default: return 0;
    }
}

const char *
path_event_name(path_event_t ev)
{
    switch (ev) {
    case PATH_EVENT_ACTIVATE_REQUESTED: return "ACTIVATE_REQUESTED";
    case PATH_EVENT_RETRY_TIMER: return "RETRY_TIMER";
    case PATH_EVENT_VALIDATION_OK: return "VALIDATION_OK";
    case PATH_EVENT_XQUIC_REMOVED: return "XQUIC_REMOVED";
    case PATH_EVENT_MANUAL_REACTIVATE: return "MANUAL_REACTIVATE";
    case PATH_EVENT_PLATFORM_DROP: return "PLATFORM_DROP";
    case PATH_EVENT_REMOVE_API: return "REMOVE_API";
    case PATH_EVENT_ADD_FD: return "ADD_FD";
    case PATH_EVENT_CONN_RESET: return "CONN_RESET";
    case PATH_EVENT_FD_CLOSED: return "FD_CLOSED";
    }
    return "?";
}

/* ─── PR4: relocated helpers + path_on_event() body ─── */

/* PR2 — transition log emitter using internal 7-state names. Relocated from
 * mqvpn_client.c in PR4; client_log/client_now_us are now non-static
 * accessors (declared in path_state_machine.h). */
void
path_log_state_change(mqvpn_client_t *c, const path_entry_t *p,
                      path_lifecycle_t old_state, path_transition_reason_t reason)
{
    client_log(c, MQVPN_LOG_DEBUG,
               "path[handle=%lld name=%s] %s -> %s reason=%s "
               "retries=%d fd=%d xqc_path_id=%llu",
               (long long)p->handle, p->name, path_lifecycle_name(old_state),
               path_lifecycle_name(p->state), mqvpn_path_transition_reason_name(reason),
               p->recreate_retries, p->fd, (unsigned long long)p->xqc_path_id);
}

/* PR2 — internal helper. Updates both `status` (public ABI projection) and
 * `state` (internal 7-state lifecycle) atomically. Maintains the
 * denormalization invariant `status == path_public_status_from_lifecycle(state)`
 * at every transition exit.
 *
 * Real-transition detection uses the LIFECYCLE pair (old_state, new_state),
 * not the public status pair. Without this, internal-only CLOSED→CLOSED
 * transitions (e.g. CLOSED_RECOVERABLE → CLOSED_DROPPED on remove_path
 * after retry exhausted) would be silently suppressed as self-loops:
 * the state field would update but no transition log fires and
 * path_mark_state_entry never re-anchors the residence timer. */
void
set_path_state_with_log(mqvpn_client_t *c, path_entry_t *p, path_lifecycle_t new_state,
                        path_transition_reason_t reason)
{
    path_lifecycle_t old_state = p->state;
    int real = (old_state != new_state) || (p->state_entered_at_us == 0);

    if (!real) return; /* self-loop: both fields already correct, skip timer+log */
    p->status = path_public_status_from_lifecycle(new_state);
    p->state = new_state;
    path_mark_state_entry(p, client_now_us(c));
    path_log_state_change(c, p, old_state, reason);
}

/* PR4 — relocated from mqvpn_client.c. Exponential backoff cap. */
uint64_t
path_recreate_backoff(int retries)
{
    uint64_t delay = PATH_RECREATE_DELAY_US;
    for (int r = 1; r < retries && delay < PATH_RECREATE_MAX_DELAY_US; r++)
        delay *= 2;
    if (delay > PATH_RECREATE_MAX_DELAY_US) delay = PATH_RECREATE_MAX_DELAY_US;
    return delay;
}

/* PR4 - Slot zero-init helper used at allocation time in
 * mqvpn_client_add_path_fd. Spec §7.1 explicitly allows direct field writes
 * here because the slot has no prior state to preserve. Starting state =
 * CLOSED_FREE so EVENT_ADD_FD transitions cleanly to PENDING. */
void
path_entry_init(path_entry_t *p)
{
    memset(p, 0, sizeof(*p));
    p->fd = -1;
    p->state = PATH_LC_CLOSED_FREE;
    p->status = path_public_status_from_lifecycle(PATH_LC_CLOSED_FREE);
}

/* PR4 - Internal helper: apply a (transient) activation/validation failure
 * with the shared retry+backoff bookkeeping, then transition to either
 * `retry_target` (CREATE_WAIT or DEGRADED) or CLOSED_RECOVERABLE based on
 * spec §5.1 MAX guard.
 *
 *   retry_target: PATH_LC_CREATE_WAIT (caller is PENDING/CREATE_WAIT/VALIDATING)
 *                 or PATH_LC_DEGRADED (caller is ACTIVE/STANDBY/DEGRADED)
 *   reason:       transition reason tag for the log
 *
 * Clears xquic-side fields (xquic_path_live, xqc_path_id,
 * path_stable_since_us) defensively. Spec §5.1 "MAX guard atomicity":
 * retries++ and threshold check happen inside this single call. */
static void
apply_failure_with_retry_check(mqvpn_client_t *c, path_entry_t *p,
                               path_lifecycle_t retry_target,
                               path_transition_reason_t reason, uint64_t now_us)
{
    p->xquic_path_live = 0;
    p->xqc_path_id = 0;
    p->path_stable_since_us = 0;

    p->recreate_retries++;
    if (p->recreate_retries >= PATH_RECREATE_MAX_RETRIES) {
        p->recreate_after_us = 0;
        set_path_state_with_log(c, p, PATH_LC_CLOSED_RECOVERABLE, reason);
    } else {
        p->recreate_after_us = now_us + path_recreate_backoff(p->recreate_retries);
        set_path_state_with_log(c, p, retry_target, reason);
    }
}

/* Forward declarations for path_on_event() dispatch. */
static void path_on_activate_requested(mqvpn_client_t *, path_entry_t *,
                                       const path_event_ctx_t *);
static void path_on_retry_timer(mqvpn_client_t *, path_entry_t *,
                                const path_event_ctx_t *);
static void path_on_validation_ok(mqvpn_client_t *, path_entry_t *,
                                  const path_event_ctx_t *);
static void path_on_xquic_removed(mqvpn_client_t *, path_entry_t *,
                                  const path_event_ctx_t *);
static void path_on_manual_reactivate(mqvpn_client_t *, path_entry_t *,
                                      const path_event_ctx_t *);
static void path_on_platform_drop(mqvpn_client_t *, path_entry_t *,
                                  const path_event_ctx_t *);
static void path_on_remove_api(mqvpn_client_t *, path_entry_t *,
                               const path_event_ctx_t *);
static void path_on_add_fd(mqvpn_client_t *, path_entry_t *, const path_event_ctx_t *);
static void path_on_conn_reset(mqvpn_client_t *, path_entry_t *,
                               const path_event_ctx_t *);
static void path_on_fd_closed(mqvpn_client_t *, path_entry_t *, const path_event_ctx_t *);
static void maybe_transition_dropped_to_free(mqvpn_client_t *, path_entry_t *,
                                             path_transition_reason_t);

void
path_on_event(mqvpn_client_t *c, path_entry_t *p, path_event_t ev,
              const path_event_ctx_t *ctx)
{
    if (!ctx) {
        client_log(c, MQVPN_LOG_ERROR, "path[%s] path_on_event: NULL ctx for event=%s",
                   p->name, path_event_name(ev));
        return;
    }

    path_lifecycle_t prior = p->state;

    switch (ev) {
    case PATH_EVENT_ACTIVATE_REQUESTED: path_on_activate_requested(c, p, ctx); break;
    case PATH_EVENT_RETRY_TIMER: path_on_retry_timer(c, p, ctx); break;
    case PATH_EVENT_VALIDATION_OK: path_on_validation_ok(c, p, ctx); break;
    case PATH_EVENT_XQUIC_REMOVED: path_on_xquic_removed(c, p, ctx); break;
    case PATH_EVENT_MANUAL_REACTIVATE: path_on_manual_reactivate(c, p, ctx); break;
    case PATH_EVENT_PLATFORM_DROP: path_on_platform_drop(c, p, ctx); break;
    case PATH_EVENT_REMOVE_API: path_on_remove_api(c, p, ctx); break;
    case PATH_EVENT_ADD_FD: path_on_add_fd(c, p, ctx); break;
    case PATH_EVENT_CONN_RESET: path_on_conn_reset(c, p, ctx); break;
    case PATH_EVENT_FD_CLOSED: path_on_fd_closed(c, p, ctx); break;
    }

    /* Single invariant + path_event emission point. */
    path_invariant_check(p);
    if (prior != p->state) path_fsm_fire_path_event(c, p);
}

static void
path_on_activate_requested(mqvpn_client_t *c, path_entry_t *p,
                           const path_event_ctx_t *ctx)
{
    if (p->state != PATH_LC_PENDING) {
        client_log(c, MQVPN_LOG_WARN,
                   "path[%s] ACTIVATE_REQUESTED in unexpected state %s", p->name,
                   path_lifecycle_name(p->state));
        return;
    }
    switch (ctx->result) {
    case ACTIVATE_OK:
        p->xqc_path_id = ctx->new_xqc_path_id;
        p->xquic_path_live = 1;
        p->recreate_after_us = 0;
        set_path_state_with_log(c, p, PATH_LC_VALIDATING, PATH_REASON_ACTIVATE_OK);
        break;
    case ACTIVATE_TRANSIENT_FAIL:
        apply_failure_with_retry_check(c, p, PATH_LC_CREATE_WAIT,
                                       PATH_REASON_ACTIVATE_FAILED, ctx->now_us);
        break;
    case ACTIVATE_PERMANENT_FAIL:
        p->xquic_path_live = 0;
        p->xqc_path_id = 0;
        p->path_stable_since_us = 0;
        p->recreate_after_us = 0;
        set_path_state_with_log(c, p, PATH_LC_CLOSED_RECOVERABLE,
                                PATH_REASON_ACTIVATE_FAILED);
        break;
    }
}

static void
path_on_retry_timer(mqvpn_client_t *c, path_entry_t *p, const path_event_ctx_t *ctx)
{
    /* PR3 base behavior: CREATE_WAIT (never validated) and DEGRADED (was
     * validated) share the retry timer. retry_target is determined by
     * current state. */
    if (p->state != PATH_LC_CREATE_WAIT && p->state != PATH_LC_DEGRADED) {
        client_log(c, MQVPN_LOG_WARN, "path[%s] RETRY_TIMER in unexpected state %s",
                   p->name, path_lifecycle_name(p->state));
        return;
    }
    path_lifecycle_t retry_target = p->state; /* self-loop on transient fail */
    switch (ctx->result) {
    case ACTIVATE_OK:
        p->xqc_path_id = ctx->new_xqc_path_id;
        p->xquic_path_live = 1;
        p->recreate_after_us = 0;
        set_path_state_with_log(c, p, PATH_LC_VALIDATING, PATH_REASON_ACTIVATE_OK);
        break;
    case ACTIVATE_TRANSIENT_FAIL:
        apply_failure_with_retry_check(c, p, retry_target, PATH_REASON_ACTIVATE_FAILED,
                                       ctx->now_us);
        break;
    case ACTIVATE_PERMANENT_FAIL:
        p->xquic_path_live = 0;
        p->xqc_path_id = 0;
        p->path_stable_since_us = 0;
        p->recreate_after_us = 0;
        set_path_state_with_log(c, p, PATH_LC_CLOSED_RECOVERABLE,
                                PATH_REASON_ACTIVATE_FAILED);
        break;
    }
}

static void
path_on_validation_ok(mqvpn_client_t *c, path_entry_t *p, const path_event_ctx_t *ctx)
{
    if (p->state != PATH_LC_VALIDATING) {
        /* late async — slot was REMOVE_API'd between dispatch and arrival */
        client_log(c, MQVPN_LOG_DEBUG,
                   "path[%s] VALIDATION_OK (late) in state %s, ignoring", p->name,
                   path_lifecycle_name(p->state));
        return;
    }
    /* validated_target must be ACTIVE or STANDBY (caller branches on
     * initial_app_status). */
    p->path_stable_since_us = ctx->now_us;
    set_path_state_with_log(c, p, ctx->validated_target, PATH_REASON_ACTIVATE_OK);
}

static void
path_on_xquic_removed(mqvpn_client_t *c, path_entry_t *p, const path_event_ctx_t *ctx)
{
    /* Spec §5.2 + reviewer Important — retry_target is state-aware:
     *   prior == VALIDATING → CREATE_WAIT (never validated)
     *   prior == ACTIVE/STANDBY → DEGRADED (was validated)
     * CLOSED_DROPPED is the cleanup re-evaluation path. */
    switch (p->state) {
    case PATH_LC_VALIDATING:
        apply_failure_with_retry_check(c, p, PATH_LC_CREATE_WAIT,
                                       PATH_REASON_XQUIC_REMOVED, ctx->now_us);
        break;
    case PATH_LC_ACTIVE:
    case PATH_LC_STANDBY:
        apply_failure_with_retry_check(c, p, PATH_LC_DEGRADED, PATH_REASON_XQUIC_REMOVED,
                                       ctx->now_us);
        break;
    case PATH_LC_CLOSED_DROPPED:
        p->xquic_path_live = 0;
        p->xqc_path_id = 0;
        maybe_transition_dropped_to_free(c, p, PATH_REASON_XQUIC_REMOVED);
        break;
    default:
        client_log(c, MQVPN_LOG_WARN, "path[%s] XQUIC_REMOVED in unexpected state %s",
                   p->name, path_lifecycle_name(p->state));
        break;
    }
}

static void
path_on_manual_reactivate(mqvpn_client_t *c, path_entry_t *p, const path_event_ctx_t *ctx)
{
    /* rev5: live regression `ci_bench_failover.sh` proved that platform-driven
     * reactivate must accept CREATE_WAIT / DEGRADED in addition to
     * CLOSED_RECOVERABLE. Spec §5.1 / §6.5 (rev6 Chunk 1 Task 1.2 (b))
     * describe the 3-state entry.
     *
     * rev6: state gate is now the single source of truth at
     * `reactivate_slot_eligible(p)` (mqvpn_client.c) called from the public
     * API entry. This handler only LOG_W's invariant-trip cases (event
     * arriving on unexpected state = upstream bug). No early return — fall
     * through to the switch which is itself state-safe (read-only of
     * ctx->result, no field mutation outside the 3-state range produces
     * harmful side effect since `set_path_state_with_log` is the only
     * mutation site and is invoked only on OK). */
    if (p->state != PATH_LC_CLOSED_RECOVERABLE && p->state != PATH_LC_CREATE_WAIT &&
        p->state != PATH_LC_DEGRADED) {
        client_log(c, MQVPN_LOG_WARN,
                   "path[%s] MANUAL_REACTIVATE in unexpected state %s "
                   "(API gate bug — reactivate_slot_eligible should have rejected)",
                   p->name, path_lifecycle_name(p->state));
        return; /* still bail to avoid touching an invalid-state slot */
    }
    /* spec §6.5: retries counter unchanged regardless of result. */
    switch (ctx->result) {
    case ACTIVATE_OK:
        p->xqc_path_id = ctx->new_xqc_path_id;
        p->xquic_path_live = 1;
        p->recreate_after_us = 0; /* consume any pending auto retry */
        set_path_state_with_log(c, p, PATH_LC_VALIDATING, PATH_REASON_REACTIVATE);
        break;
    case ACTIVATE_TRANSIENT_FAIL:
    case ACTIVATE_PERMANENT_FAIL:
        /* self, no state change, no retry increment.
         * recreate_after_us is NOT reset here — the auto retry timer (if
         * armed in CREATE_WAIT/DEGRADED) continues to count down toward
         * the next library-driven attempt. */
        client_log(c, MQVPN_LOG_INFO,
                   "path[%s] MANUAL_REACTIVATE fail (%s) from %s, no state change",
                   p->name,
                   ctx->result == ACTIVATE_PERMANENT_FAIL ? "PERMANENT" : "TRANSIENT",
                   path_lifecycle_name(p->state));
        break;
    }
}

static void
path_on_platform_drop(mqvpn_client_t *c, path_entry_t *p, const path_event_ctx_t *ctx)
{
    (void)ctx;
    /* Spec §4.3 CLOSED_DROPPED: platform_attached=0 strict, lazy xquic clear */
    if (p->state == PATH_LC_CLOSED_DROPPED) return; /* idempotent */
    if (p->state == PATH_LC_CLOSED_FREE) return;    /* idempotent */
    p->platform_attached = 0;
    p->recreate_after_us = 0;
    p->path_stable_since_us = 0;
    /* xquic close not called — §5.0 contract for PLATFORM_DROP */
    set_path_state_with_log(c, p, PATH_LC_CLOSED_DROPPED, PATH_REASON_PLATFORM_DROPPED);
}

static void
path_on_remove_api(mqvpn_client_t *c, path_entry_t *p, const path_event_ctx_t *ctx)
{
    (void)ctx;
    /* Spec §5.0: caller (mqvpn_client_remove_path) already invoked
     * xqc_conn_close_path() before dispatch. FSM only does state mutation.
     * CLOSED_DROPPED invariant requires platform_attached=0. */
    if (p->state == PATH_LC_CLOSED_DROPPED) return;
    if (p->state == PATH_LC_CLOSED_FREE) return;
    p->platform_attached = 0;
    p->recreate_after_us = 0;
    p->path_stable_since_us = 0;
    set_path_state_with_log(c, p, PATH_LC_CLOSED_DROPPED, PATH_REASON_REMOVE_API);
}

static void
path_on_add_fd(mqvpn_client_t *c, path_entry_t *p, const path_event_ctx_t *ctx)
{
    (void)ctx;
    if (p->state != PATH_LC_CLOSED_FREE) {
        client_log(c, MQVPN_LOG_WARN,
                   "path[%s] ADD_FD in unexpected state %s (expected CLOSED_FREE)",
                   p->name, path_lifecycle_name(p->state));
        return;
    }
    p->platform_attached = 1;
    set_path_state_with_log(c, p, PATH_LC_PENDING, PATH_REASON_ADD_FD);
}

static void
path_on_conn_reset(mqvpn_client_t *c, path_entry_t *p, const path_event_ctx_t *ctx)
{
    (void)ctx;
    /* Drop xquic-side state regardless of branch. */
    p->xquic_path_live = 0;
    p->xqc_path_id = 0;
    p->recreate_after_us = 0;
    p->recreate_retries = 0;
    p->path_stable_since_us = 0;

    if (p->platform_attached) {
        set_path_state_with_log(c, p, PATH_LC_PENDING, PATH_REASON_CONN_RESET);
    }
    /* else: state unchanged (CLOSED_DROPPED/CLOSED_FREE lazy invariants permit
     * pre-cleared xquic-side fields). */
}

static void
path_on_fd_closed(mqvpn_client_t *c, path_entry_t *p, const path_event_ctx_t *ctx)
{
    (void)ctx;
    /* Spec sec 5.1 CLOSED_DROPPED:
     *   [EVENT_FD_CLOSED] -> self (set fd=-1; re-evaluate cleanup)
     * Other states: late async race - LOG_D + no-op (spec sec 5.1 tail
     * "Late async callback no atsukai"). CLOSED_FREE also late-event
     * idempotent (state unchanged, cleanup already complete). */
    if (p->state != PATH_LC_CLOSED_DROPPED) {
        client_log(c, MQVPN_LOG_DEBUG, "path[%s] FD_CLOSED (late) in state %s, ignoring",
                   p->name, path_lifecycle_name(p->state));
        return;
    }
    /* fd is NOT in spec sec 3.3 lifecycle field list - direct write allowed. */
    p->fd = -1;
    maybe_transition_dropped_to_free(c, p, PATH_REASON_FD_CLOSED);
}

static void
maybe_transition_dropped_to_free(mqvpn_client_t *c, path_entry_t *p,
                                 path_transition_reason_t reason)
{
    if (p->state != PATH_LC_CLOSED_DROPPED) return;
    if (p->fd >= 0) return;
    if (p->xquic_path_live) return;
    if (p->xqc_path_id != 0) return;
    set_path_state_with_log(c, p, PATH_LC_CLOSED_FREE, reason);
}

/* Spec sec 6.3 re-arm semantic: after firing the 30s reset, set
 * `path_stable_since_us = now` so the next 30s window starts counting
 * from now (NOT 0, which would disarm the timer until the path drops
 * back through VALIDATING and returns to ACTIVE/STANDBY). A path that
 * stays usable for 60s+ thus experiences 2 resets. */
void
path_fsm_tick_confirm_stable(mqvpn_client_t *c, path_entry_t *p, uint64_t now)
{
    if (p->state != PATH_LC_ACTIVE && p->state != PATH_LC_STANDBY) return;
    if (p->path_stable_since_us == 0 || !p->xquic_path_live ||
        now - p->path_stable_since_us < PATH_STABLE_THRESHOLD_US)
        return;

    client_log(c, MQVPN_LOG_INFO, "path %s: stable for 30s, resetting retry budget",
               p->name);
    p->recreate_retries = 0;
    p->path_stable_since_us = now; /* sec 6.3 re-arm: next 30s window starts now */
}
