// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* tests/test_path_slot_oracle.c — the path-slot FSM against the transition
 * oracle generated from formal/PathSlotFsm.tla (formal/oracle/).
 *
 * For every row of the table (every invariant-legal abstract pre-state x
 * every event/context class) it builds the canonical concrete slot, applies
 * the caller's own writes where the caller would, dispatches, and checks the
 * result against the row: the abstract post-state, the two observable calls
 * (public path event, xquic app-status mirror), how each timer and the retry
 * counter was updated, the state-entry stamp, and the transport ops/ctx. It
 * then checks that path_invariant_check() rejects every abstract shape the
 * model calls illegal, so the model's invariant and the C one are the same
 * set. formal/cbmc/ extends the row results from the canonical slot to every
 * concrete slot with the same abstraction (formal/README.md).
 *
 * Linux-only (CMakeLists.txt builds unit tests in its Linux block): the
 * rejection checks fork a child per shape and expect it to abort. */

/* Keep assert() live: CI also runs ctest on Release builds. The target is
 * compiled with -UNDEBUG too, so path_invariant_check() in the FSM translation
 * unit stays live; the canary below proves it. */
#undef NDEBUG
#include <assert.h>

#include "oracle_abs.h" /* includes path_state_machine.h */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(PATH_SLOT_ORACLE_MAX_RETRIES == PATH_RECREATE_MAX_RETRIES,
               "oracle generated for a different PATH_RECREATE_MAX_RETRIES - rerun "
               "formal/run_tlc.sh oracle");
_Static_assert(PATH_SLOT_ORACLE_N_ROWS ==
                   PATH_SLOT_ORACLE_N_PRE * PATH_SLOT_ORACLE_N_EVCTX,
               "every legal pre-state needs one row per event/context class");

/* ─── Accessor stubs (path_state_machine.c links against these) ─── */

oracle_obs_t oracle_obs;

uint64_t
client_now_us(const struct mqvpn_client_s *c)
{
    (void)c;
    return ORACLE_T_STUB_CLOCK;
}

void
client_log(struct mqvpn_client_s *c, mqvpn_log_level_t level, const char *fmt, ...)
{
    (void)c;
    (void)level;
    (void)fmt;
}

void
path_fsm_fire_path_event(struct mqvpn_client_s *c, const path_entry_t *p)
{
    (void)c;
    (void)p;
    oracle_obs.fires++;
}

void
client_notify_xqc_path_state(struct mqvpn_client_s *c, const path_entry_t *p,
                             int app_status)
{
    (void)c;
    (void)p;
    oracle_obs.notifies++;
    oracle_obs.notify_status = app_status;
}

/* ─── Reporting ─── */

static const char *const EV_NAME[OEV_COUNT] = {
    "ACTIVATE",      "RETRY",      "VALIDATION_OK", "XQUIC_REMOVED", "MANUAL_REACTIVATE",
    "PLATFORM_DROP", "REMOVE_API", "ADD",           "CONN_RESET",    "TRANSPORT_RELEASED",
    "STABLE_TICK",
};

static int failures;

static void
print_slot(const char *tag, const oracle_slot_t *s)
{
    fprintf(stderr,
            "    %s: %s att=%u live=%u rel=%u id=%u retries=%u retry=%u stable=%u\n", tag,
            path_lifecycle_name((path_lifecycle_t)s->state), s->attached, s->live,
            s->released, s->id, s->retries, s->retry_armed, s->stable_armed);
}

static void
fail_row(size_t i, const oracle_row_t *row, const char *what)
{
    if (failures++ < 20) {
        fprintf(stderr, "FAIL row %zu (%s ctx=%u): %s\n", i, EV_NAME[row->ev], row->ctx,
                what);
        print_slot("pre ", &row->pre);
        print_slot("want", &row->post);
    }
}

#define CHECK_ROW(cond, what)                  \
    do {                                       \
        if (!(cond)) fail_row(i, row, (what)); \
    } while (0)

/* ─── Policy constants ───
 * The model abstracts time away, and the update classes check that the FSM
 * applies path_recreate_backoff() and PATH_STABLE_THRESHOLD_US, not what
 * they are. Their values are pinned here, so changing the retry schedule or
 * the stability window is a deliberate edit of this test too. */

static void
check_policy_constants(void)
{
    static const uint64_t backoff_s[] = {5, 5, 10, 20, 40, 60, 60, 60, 60};
    for (int r = 0; r < (int)(sizeof(backoff_s) / sizeof(backoff_s[0])); r++) {
        if (path_recreate_backoff(r) != backoff_s[r] * 1000000ULL) {
            fprintf(stderr, "FAIL policy: path_recreate_backoff(%d) = %llu us\n", r,
                    (unsigned long long)path_recreate_backoff(r));
            failures++;
        }
    }
    if (PATH_STABLE_THRESHOLD_US != 30ULL * 1000000ULL) {
        fprintf(stderr, "FAIL policy: PATH_STABLE_THRESHOLD_US changed\n");
        failures++;
    }
}

/* ─── Canary: the invariant is compiled in ─── */

/* A failed assert() calls abort(); the child turns that into this exit code,
 * so no core dump (or crash reporter such as apport) runs per shape. */
#define ABORT_EXIT 86

static void
on_abort(int sig)
{
    (void)sig;
    _exit(ABORT_EXIT);
}

/* Returns 1 when path_invariant_check() aborts on the concretization of `a`
 * (run in a child: the abort would otherwise end this test). */
static int
invariant_rejects(const oracle_slot_t *a)
{
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(2);
    }
    if (pid == 0) {
        signal(SIGABRT, on_abort);
        /* The expected assertion message would flood the log. */
        if (!freopen("/dev/null", "w", stderr)) _exit(3);
        path_entry_t p;
        oracle_conc(a, &p);
        path_invariant_check(&p);
        _exit(0);
    }
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        exit(2);
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == ABORT_EXIT;
}

static void
check_canary(void)
{
    /* CLOSED_FREE that claims an attached transport: illegal in both models. */
    const oracle_slot_t bad = {PATH_LC_CLOSED_FREE, 1, 0, 1, 0, 0, 0, 0};
    if (!invariant_rejects(&bad)) {
        fprintf(stderr, "FAIL canary: path_invariant_check() did not abort on an "
                        "illegal slot - is NDEBUG defined for path_state_machine.c?\n");
        exit(1);
    }
}

/* ─── One row ─── */

static void
check_row(size_t i, const oracle_row_t *row)
{
    path_entry_t pre, p;
    oracle_slot_t got;

    /* (a) The canonical concretization is in the verified domain, is legal
     * for the C invariant, and abstracts back to the row's pre-state. */
    oracle_conc(&row->pre, &pre);
    CHECK_ROW(oracle_abs_pre(&pre, &got) && oracle_slot_eq(&got, &row->pre),
              "abs(conc(pre)) != pre");
    CHECK_ROW(oracle_in_dom(&pre), "conc(pre) outside Dom");
    CHECK_ROW(pre.state_entered_at_us != 0,
              "conc(pre) has no recorded state entry (Dom item 9)");
    path_invariant_check(&pre);

    /* (b) The composed dispatch. */
    CHECK_ROW(oracle_prefix_applies(&row->pre, row->ev) == row->prefix,
              "caller prefix condition disagrees with CallerPrefix");
    p = pre;
    if (row->prefix) {
        const mqvpn_path_ops_t add_ops = oracle_canonical_add_ops();
        oracle_prefix_apply(row->ev, &p, &add_ops, &oracle_ctx_marker_add);
    }
    const mqvpn_path_ops_t ops_before = p.ops;
    void *const ctx_before = p.transport_ctx;

    const uint64_t now = oracle_conc_now(&pre, row->ev, row->ctx);
    CHECK_ROW(oracle_no_collision(&pre, now), "canonical constants collide (Dom item 8)");
    const path_event_ctx_t e = oracle_event_ctx(row->ctx, now, ORACLE_NEW_ID);
    memset(&oracle_obs, 0, sizeof(oracle_obs));
    oracle_dispatch(&p, row->ev, &e);

    CHECK_ROW(oracle_abs_post(&p, pre.xqc_path_id, ORACLE_NEW_ID, &got) &&
                  oracle_slot_eq(&got, &row->post),
              "abstract post-state");
    CHECK_ROW(oracle_obs.fires == row->fires, "public path event");
    CHECK_ROW(row->notify
                  ? (oracle_obs.notifies == 1 && oracle_obs.notify_status == row->notify)
                  : oracle_obs.notifies == 0,
              "xquic app-status mirror");
    CHECK_ROW(oracle_retry_class(&pre, &p, now) == row->retry_upd,
              "recreate_after_us update");
    CHECK_ROW(oracle_stable_class(&pre, &p, now) == row->stable_upd,
              "path_stable_since_us update");
    CHECK_ROW(oracle_retries_class(&pre, &p) == row->retries_upd,
              "recreate_retries update");
    CHECK_ROW(p.state_entered_at_us ==
                  (p.state != pre.state ? ORACLE_T_STUB_CLOCK : pre.state_entered_at_us),
              "state_entered_at_us");
    /* The handler never writes ops; it clears ctx only when it releases. */
    CHECK_ROW(oracle_ops_eq(&p.ops, &ops_before), "ops");
    CHECK_ROW(p.transport_ctx == (p.transport_released ? NULL : ctx_before),
              "transport_ctx");
    CHECK_ROW(oracle_conc_rule(&p), "post-state breaks the concretization rule");
    CHECK_ROW(p.status == path_public_status_from_lifecycle(p.state), "public status");
    CHECK_ROW(p.last_residence_warn_at_us == oracle_expected_residence_warn(&pre, &p),
              "last_residence_warn_at_us");
    CHECK_ROW(oracle_frame_eq(&pre, &p), "a field outside the FSM changed");
    /* The whole invariant on every post-state, STABLE_TICK's included
     * (path_fsm_tick_confirm_stable does not check it itself). */
    path_invariant_check(&p);
}

int
main(void)
{
    check_canary();
    check_policy_constants();

    for (size_t i = 0; i < PATH_SLOT_ORACLE_N_ROWS; i++)
        check_row(i, &PATH_SLOT_ORACLE_ROWS[i]);

    /* (c) Every abstract shape outside the table's pre-states is one the C
     * invariant rejects. With (a), the C invariant accepts exactly PRE_SET. */
    unsigned shapes = 0, rejected = 0;
    oracle_slot_t a;
    for (unsigned st = 0; st <= PATH_LC_CLOSED_FREE; st++)
        for (unsigned bits = 0; bits < 64; bits++)
            for (unsigned r = 0; r <= PATH_RECREATE_MAX_RETRIES; r++) {
                a.state = (uint8_t)st;
                a.attached = bits & 1;
                a.live = (bits >> 1) & 1;
                a.released = (bits >> 2) & 1;
                a.id = (bits >> 3) & 1;
                a.retry_armed = (bits >> 4) & 1;
                a.stable_armed = (bits >> 5) & 1;
                a.retries = (uint8_t)r;
                shapes++;
                if (oracle_in_pre_set(&a)) continue;
                if (invariant_rejects(&a)) {
                    rejected++;
                } else if (failures++ < 20) {
                    fprintf(stderr, "FAIL shape accepted by path_invariant_check but "
                                    "illegal in the model:\n");
                    print_slot("shape", &a);
                }
            }

    if (failures) {
        fprintf(stderr, "test_path_slot_oracle: %d failure(s)\n", failures);
        return 1;
    }
    printf("test_path_slot_oracle: %d rows OK; %u of %u abstract shapes illegal and "
           "rejected; "
           "canary OK\n",
           PATH_SLOT_ORACLE_N_ROWS, rejected, shapes);
    return 0;
}
