/* src/path_state_machine.c — Phase 1 observability helpers. */

#include "path_state_machine.h"
#include <assert.h>

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
