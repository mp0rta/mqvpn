/* tests/test_path_state_machine.c */
#include "path_entry_internal.h"
#include "path_state_machine.h"
#include "libmqvpn.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static path_entry_t
make_slot(void)
{
    path_entry_t p = {0};
    p.fd = 7;
    return p;
}

static void
test_status_name_known(void)
{
    assert(strcmp(mqvpn_path_status_name(MQVPN_PATH_PENDING), "PENDING") == 0);
    assert(strcmp(mqvpn_path_status_name(MQVPN_PATH_ACTIVE), "ACTIVE") == 0);
    assert(strcmp(mqvpn_path_status_name(MQVPN_PATH_DEGRADED), "DEGRADED") == 0);
    assert(strcmp(mqvpn_path_status_name(MQVPN_PATH_STANDBY), "STANDBY") == 0);
    assert(strcmp(mqvpn_path_status_name(MQVPN_PATH_CLOSED), "CLOSED") == 0);
}

static void
test_status_name_unknown(void)
{
    /* Out-of-range value should return non-NULL "UNKNOWN" or similar. */
    const char *s = mqvpn_path_status_name((mqvpn_path_status_t)999);
    assert(s != NULL);
    assert(strlen(s) > 0);
}

static void
test_reason_name_known(void)
{
    assert(strcmp(mqvpn_path_transition_reason_name(PATH_REASON_ADD_FD), "ADD_FD") == 0);
    assert(strcmp(mqvpn_path_transition_reason_name(PATH_REASON_ACTIVATE_OK),
                  "ACTIVATE_OK") == 0);
    assert(strcmp(mqvpn_path_transition_reason_name(PATH_REASON_RETRY_RESET),
                  "RETRY_RESET") == 0);
}

/* ─── Invariant tests (legacy 5-state) ─── */

static void
test_invariant_pending_legal(void)
{
    path_entry_t p = make_slot();
    p.status = MQVPN_PATH_PENDING;
    p.platform_attached = 1;
    p.xquic_path_live = 0;
    p.xqc_path_id = 0;
    p.recreate_after_us = 0;
    p.path_stable_since_us = 0;
    path_invariant_check_legacy(&p); /* must not abort */
}

static void
test_invariant_active_legal(void)
{
    path_entry_t p = make_slot();
    p.status = MQVPN_PATH_ACTIVE;
    p.platform_attached = 1;
    p.xquic_path_live = 1;
    p.xqc_path_id = 42;
    p.recreate_after_us = 0;
    /* path_stable_since_us is (any) for ACTIVE — leave 0 */
    path_invariant_check_legacy(&p);
}

static void
test_invariant_standby_legal(void)
{
    path_entry_t p = make_slot();
    p.status = MQVPN_PATH_STANDBY;
    p.platform_attached = 1;
    p.xquic_path_live = 1;
    p.xqc_path_id = 99;
    p.recreate_after_us = 0;
    path_invariant_check_legacy(&p);
}

static void
test_invariant_degraded_legal(void)
{
    path_entry_t p = make_slot();
    p.status = MQVPN_PATH_DEGRADED;
    p.platform_attached = 1;
    p.xquic_path_live = 0;
    p.xqc_path_id = 0;
    p.recreate_after_us = 1000; /* MUST be != 0 */
    p.path_stable_since_us = 0;
    path_invariant_check_legacy(&p);
}

static void
test_invariant_closed_recoverable_legal(void)
{
    path_entry_t p = make_slot();
    p.status = MQVPN_PATH_CLOSED;
    p.platform_attached = 1;
    p.xquic_path_live = 0;
    p.xqc_path_id = 0;
    p.recreate_after_us = 0;
    p.path_stable_since_us = 0;
    path_invariant_check_legacy(&p);
}

static void
test_invariant_closed_dropped_legal(void)
{
    path_entry_t p = {0};
    p.fd = -1;
    p.status = MQVPN_PATH_CLOSED;
    p.platform_attached = 0;
    /* recreate_after_us = path_stable_since_us = 0 by zero-init.
     * xquic_path_live / xqc_path_id / fd may be lazy — leave 0. */
    path_invariant_check_legacy(&p);
}

int
main(void)
{
    test_status_name_known();
    test_status_name_unknown();
    test_reason_name_known();
    test_invariant_pending_legal();
    test_invariant_active_legal();
    test_invariant_standby_legal();
    test_invariant_degraded_legal();
    test_invariant_closed_recoverable_legal();
    test_invariant_closed_dropped_legal();
    printf("PASS\n");
    return 0;
}
