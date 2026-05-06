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

static void
test_reason_name_full_table(void)
{
    /* Pin every reason → string mapping so a future enum addition that
     * forgets to update the switch in path_state_machine.c is caught here. */
    assert(strcmp(mqvpn_path_transition_reason_name(PATH_REASON_ACTIVATE_FAILED),
                  "ACTIVATE_FAILED") == 0);
    assert(strcmp(mqvpn_path_transition_reason_name(PATH_REASON_XQUIC_REMOVED),
                  "XQUIC_REMOVED") == 0);
    assert(strcmp(mqvpn_path_transition_reason_name(PATH_REASON_PLATFORM_DROPPED),
                  "PLATFORM_DROPPED") == 0);
    assert(strcmp(mqvpn_path_transition_reason_name(PATH_REASON_REMOVE_API),
                  "REMOVE_API") == 0);
    assert(strcmp(mqvpn_path_transition_reason_name(PATH_REASON_REACTIVATE),
                  "REACTIVATE") == 0);
    assert(strcmp(mqvpn_path_transition_reason_name(PATH_REASON_CONN_RESET),
                  "CONN_RESET") == 0);
}

static void
test_reason_name_unknown(void)
{
    /* Out-of-range reason should still return a non-NULL non-empty string. */
    const char *s = mqvpn_path_transition_reason_name((path_transition_reason_t)999);
    assert(s != NULL);
    assert(strlen(s) > 0);
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

/* ─── B7: path_mark_state_entry ─── */

static void
test_mark_state_entry_records_time(void)
{
    path_entry_t p = make_slot();
    p.state_entered_at_us = 0;
    p.last_residence_warn_at_us = 999; /* dirty; expect reset */
    path_mark_state_entry(&p, 12345);
    assert(p.state_entered_at_us == 12345);
    assert(p.last_residence_warn_at_us == 0);
}

/* ─── B11: path_should_warn_residence ─── */

static void
test_should_warn_pending_below_threshold(void)
{
    path_entry_t p = make_slot();
    p.status = MQVPN_PATH_PENDING;
    p.platform_attached = 1;
    p.state_entered_at_us = 1000;
    assert(path_should_warn_residence(&p, 1000 + 10ULL * 1000000) == 0);
}

static void
test_should_warn_pending_at_threshold_exact(void)
{
    /* Boundary: condition is `since_anchor > PATH_RESIDENCE_PENDING_WARN_US`
     * (strict greater). At exactly the threshold we MUST stay silent — pin
     * this so a future relaxation to `>=` does not silently double-trigger
     * around timer wake-ups that land on the boundary. */
    path_entry_t p = make_slot();
    p.status = MQVPN_PATH_PENDING;
    p.platform_attached = 1;
    p.state_entered_at_us = 1000;
    assert(path_should_warn_residence(&p, 1000 + PATH_RESIDENCE_PENDING_WARN_US) == 0);
}

static void
test_should_warn_pending_above_threshold(void)
{
    path_entry_t p = make_slot();
    p.status = MQVPN_PATH_PENDING;
    p.platform_attached = 1;
    p.state_entered_at_us = 1000;
    assert(path_should_warn_residence(&p, 1000 + 31ULL * 1000000) == 1);
}

static void
test_should_warn_pending_debounce(void)
{
    path_entry_t p = make_slot();
    p.status = MQVPN_PATH_PENDING;
    p.platform_attached = 1;
    p.state_entered_at_us = 1000;
    p.last_residence_warn_at_us = 1000 + 31ULL * 1000000;
    assert(path_should_warn_residence(&p, 1000 + 36ULL * 1000000) == 0);
}

static void
test_should_warn_active_never(void)
{
    path_entry_t p = make_slot();
    p.status = MQVPN_PATH_ACTIVE;
    p.platform_attached = 1;
    p.xquic_path_live = 1;
    p.xqc_path_id = 42;
    p.state_entered_at_us = 1000;
    assert(path_should_warn_residence(&p, 1000 + 3600ULL * 1000000) == 0);
}

static void
test_should_warn_standby_never(void)
{
    /* STANDBY hits the default-case `return 0`; pin so a future addition of
     * an explicit STANDBY arm cannot accidentally start emitting warnings on
     * the deliberately-quiescent path. */
    path_entry_t p = make_slot();
    p.status = MQVPN_PATH_STANDBY;
    p.platform_attached = 1;
    p.xquic_path_live = 1;
    p.xqc_path_id = 99;
    p.state_entered_at_us = 1000;
    assert(path_should_warn_residence(&p, 1000 + 3600ULL * 1000000) == 0);
}

static void
test_should_warn_closed_never(void)
{
    /* CLOSED is terminal — the slot is either retries-exhausted or
     * platform-removed. The residence check must never fire; the lifecycle
     * has already ended and observers were notified via path_event. */
    path_entry_t p = make_slot();
    p.status = MQVPN_PATH_CLOSED;
    p.platform_attached = 1;
    p.state_entered_at_us = 1000;
    assert(path_should_warn_residence(&p, 1000 + 3600ULL * 1000000) == 0);
}

static void
test_should_warn_degraded_overdue(void)
{
    /* DEGRADED with retry timer overdue by > grace AND last warn was long ago. */
    path_entry_t p = make_slot();
    p.status = MQVPN_PATH_DEGRADED;
    p.platform_attached = 1;
    p.state_entered_at_us = 1000;
    p.recreate_after_us = 1000 + 5ULL * 1000000; /* retry was scheduled for now+5s */
    /* now = 1000 + 70s — recreate_after_us was 5s in, so 65s overdue, > 60s grace */
    assert(path_should_warn_residence(&p, 1000 + 70ULL * 1000000) == 1);
}

static void
test_should_warn_degraded_within_grace(void)
{
    /* DEGRADED retry overdue by less than grace — should NOT warn. */
    path_entry_t p = make_slot();
    p.status = MQVPN_PATH_DEGRADED;
    p.platform_attached = 1;
    p.state_entered_at_us = 1000;
    p.recreate_after_us = 1000 + 5ULL * 1000000;
    /* now = 1000 + 30s — only 25s past recreate_after_us, well within 60s grace */
    assert(path_should_warn_residence(&p, 1000 + 30ULL * 1000000) == 0);
}

static void
test_should_warn_degraded_no_retry_armed(void)
{
    /* The DEGRADED arm gates on `recreate_after_us != 0`. If a defensive
     * caller ever lands on DEGRADED with the timer cleared (invariant
     * violation, but the helper is pure and must not depend on the
     * invariant holding), the check must stay silent rather than divide
     * `now_us > 0 + GRACE` against an arbitrary now. */
    path_entry_t p = make_slot();
    p.status = MQVPN_PATH_DEGRADED;
    p.platform_attached = 1;
    p.state_entered_at_us = 1000;
    p.recreate_after_us = 0;
    assert(path_should_warn_residence(&p, 1000 + 3600ULL * 1000000) == 0);
}

static void
test_should_warn_degraded_debounce(void)
{
    /* Symmetric to the PENDING debounce: once a DEGRADED warn has fired,
     * a follow-up tick still inside the grace window from last_warn must
     * suppress. Without this, the residence-warn could fan out per-tick
     * and flood the log on a stuck DEGRADED slot. */
    path_entry_t p = make_slot();
    p.status = MQVPN_PATH_DEGRADED;
    p.platform_attached = 1;
    p.state_entered_at_us = 1000;
    p.recreate_after_us = 1000 + 5ULL * 1000000; /* retry was scheduled at +5s */
    /* Pretend a warn already fired at +70s. */
    p.last_residence_warn_at_us = 1000 + 70ULL * 1000000;
    /* now = +75s — only 5s since last warn, well below the 60s grace. */
    assert(path_should_warn_residence(&p, 1000 + 75ULL * 1000000) == 0);
}

static void
test_should_warn_degraded_rewarn_after_debounce(void)
{
    /* After a debounce window expires, the next overdue tick MUST re-warn.
     * Pins the rearm side of debounce so a future change to "warn at most
     * once per state entry" is caught here. */
    path_entry_t p = make_slot();
    p.status = MQVPN_PATH_DEGRADED;
    p.platform_attached = 1;
    p.state_entered_at_us = 1000;
    p.recreate_after_us = 1000 + 5ULL * 1000000;
    p.last_residence_warn_at_us = 1000 + 70ULL * 1000000;
    /* now = +135s — 65s since last warn (> 60s grace) AND 130s overdue from
     * recreate_after_us (also > grace). */
    assert(path_should_warn_residence(&p, 1000 + 135ULL * 1000000) == 1);
}

/* ─── path_is_real_transition: self-loop suppression + first-entry exception ─── */

static void
test_is_real_transition_different_states(void)
{
    /* PENDING -> ACTIVE: always a real transition */
    assert(path_is_real_transition(MQVPN_PATH_PENDING, MQVPN_PATH_ACTIVE, 1000) == 1);
    assert(path_is_real_transition(MQVPN_PATH_PENDING, MQVPN_PATH_ACTIVE, 0) == 1);
    /* ACTIVE -> DEGRADED: real */
    assert(path_is_real_transition(MQVPN_PATH_ACTIVE, MQVPN_PATH_DEGRADED, 1000) == 1);
    /* DEGRADED -> CLOSED: real */
    assert(path_is_real_transition(MQVPN_PATH_DEGRADED, MQVPN_PATH_CLOSED, 1000) == 1);
}

static void
test_is_real_transition_self_loop_after_entry(void)
{
    /* Same state, already recorded → suppress self-loop. */
    assert(path_is_real_transition(MQVPN_PATH_PENDING, MQVPN_PATH_PENDING, 1000) == 0);
    assert(path_is_real_transition(MQVPN_PATH_ACTIVE, MQVPN_PATH_ACTIVE, 1000) == 0);
    assert(path_is_real_transition(MQVPN_PATH_DEGRADED, MQVPN_PATH_DEGRADED, 1000) == 0);
    assert(path_is_real_transition(MQVPN_PATH_CLOSED, MQVPN_PATH_CLOSED, 1000) == 0);
}

static void
test_is_real_transition_first_entry_zero_init(void)
{
    /* Same state, state_entered_at_us == 0 → first entry to fresh slot,
     * MUST be treated as real transition.
     *
     * This pins down the I1 bug fix: mqvpn_client_add_path_fd memsets the
     * slot (status == MQVPN_PATH_PENDING == 0, state_entered_at_us == 0)
     * then calls set_path_status_with_log(..., PENDING, ADD_FD). Without
     * the first-entry exception, this is suppressed as a self-loop and
     * state_entered_at_us never gets recorded — so the "stuck in PENDING"
     * residence-warn never fires. */
    assert(path_is_real_transition(MQVPN_PATH_PENDING, MQVPN_PATH_PENDING, 0) == 1);
    /* Also for any other zero-init case (defensive — currently only PENDING
     * happens via memset, but the contract holds for all values). */
    assert(path_is_real_transition(MQVPN_PATH_ACTIVE, MQVPN_PATH_ACTIVE, 0) == 1);
}

static void
test_should_warn_state_entered_zero_is_silent(void)
{
    /* state_entered_at_us == 0 means "not yet recorded". The function must
     * short-circuit with no warn — but mqvpn_client.c's set_path_status_with_log()
     * is responsible for ensuring this state is transient (it must call
     * path_mark_state_entry() on first entry, even when old==new is the
     * trivially-true MQVPN_PATH_PENDING==0 zero-init case).
     *
     * This test pins down the contract here so the integration site cannot
     * regress without one of these tests changing. */
    path_entry_t p = {0};
    p.fd = 7;
    p.status = MQVPN_PATH_PENDING;
    p.platform_attached = 1;
    /* state_entered_at_us is 0 by zero-init */
    assert(path_should_warn_residence(&p, 1000 + 3600ULL * 1000000) == 0);
}

int
main(void)
{
    test_status_name_known();
    test_status_name_unknown();
    test_reason_name_known();
    test_reason_name_full_table();
    test_reason_name_unknown();
    test_invariant_pending_legal();
    test_invariant_active_legal();
    test_invariant_standby_legal();
    test_invariant_degraded_legal();
    test_invariant_closed_recoverable_legal();
    test_invariant_closed_dropped_legal();
    test_mark_state_entry_records_time();
    test_should_warn_pending_below_threshold();
    test_should_warn_pending_at_threshold_exact();
    test_should_warn_pending_above_threshold();
    test_should_warn_pending_debounce();
    test_should_warn_active_never();
    test_should_warn_standby_never();
    test_should_warn_closed_never();
    test_should_warn_degraded_overdue();
    test_should_warn_degraded_within_grace();
    test_should_warn_degraded_no_retry_armed();
    test_should_warn_degraded_debounce();
    test_should_warn_degraded_rewarn_after_debounce();
    test_is_real_transition_different_states();
    test_is_real_transition_self_loop_after_entry();
    test_is_real_transition_first_entry_zero_init();
    test_should_warn_state_entered_zero_is_silent();
    printf("PASS\n");
    return 0;
}
