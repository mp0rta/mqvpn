/* src/path_state_machine.c — Phase 1 observability helpers. */

#include "path_state_machine.h"

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

/* Other helpers stubbed; will be filled in B6/B7/B10. */
void
path_invariant_check_legacy(const path_entry_t *p)
{
    (void)p;
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
