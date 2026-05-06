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
        assert(p->xqc_path_id != 0);
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
    (void)p;
    (void)now_us;
}

int
path_should_warn_residence(const path_entry_t *p, uint64_t now_us)
{
    (void)p;
    (void)now_us;
    return 0;
}
