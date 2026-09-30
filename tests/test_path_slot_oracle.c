// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* tests/test_path_slot_oracle.c — the path-slot FSM against the transition
 * oracle generated from formal/PathSlotFsm.tla (formal/oracle/).
 *
 * For every row of the table (every invariant-legal abstract pre-state x
 * every event/context class) it builds the canonical concrete slot, applies
 * the caller's own writes where the caller would, dispatches with a non-NULL
 * client token (which every accessor call must receive), and checks the
 * result against the row: the abstract post-state, the two observable calls
 * (public path event, xquic app-status mirror), how each timer and the retry
 * counter was updated, the state-entry stamp, the transport ops and ctx, the
 * concretization rule, the public status (the model's Projection of the
 * post-state, from the row), the residence-warn debounce, the frame (the
 * fields the FSM must not write), and path_invariant_check() on the
 * post-state. It then checks that path_invariant_check() rejects every
 * abstract shape the model calls illegal, so the model's invariant and the C
 * one agree on every abstract shape (checked on its canonical
 * concretization). formal/cbmc/ extends the row results from the
 * canonical slot to every slot of the verified domain (formal/README.md).
 *
 * Linux-only (CMakeLists.txt builds unit tests in its Linux block): the
 * rejection checks fork a child per shape and expect it to abort. */

/* This file calls no assert() itself: the #undef follows the tests/
 * convention (tests/check_ndebug_guard.sh), so one added later stays live in
 * Release builds. path_invariant_check() is kept live by the target's own
 * -UNDEBUG (CMakeLists.txt), which reaches its copy of path_state_machine.c;
 * the canary below proves it. */
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
               "oracle generated for a different PATH_RECREATE_MAX_RETRIES - set "
               "MaxRetries in formal/oracle/PathSlotOracle.cfg, then rerun "
               "formal/run_tlc.sh oracle");
_Static_assert(PATH_SLOT_ORACLE_N_ROWS ==
                   PATH_SLOT_ORACLE_N_PRE * PATH_SLOT_ORACLE_N_EVCTX,
               "every legal pre-state needs one row per event/context class");
_Static_assert(PATH_SLOT_ORACLE_N_EVCTX == 19,
               "the model's event/context classes changed - review EV_NAME, CTX_NAME "
               "and the checks below");
_Static_assert(sizeof(oracle_slot_t) == 8,
               "oracle_slot_t changed - enumerate the new field in the shape loop (c)");

/* ─── Accessor stubs (path_state_machine.c links against these) ─── */

oracle_obs_t oracle_obs;

/* The client every dispatch passes: a non-NULL token, never dereferenced
 * (mqvpn_client_t is incomplete here), as a production caller passes its
 * client. The stubs count the calls that receive any other pointer. */
static char client_token;
#define ORACLE_CLIENT ((mqvpn_client_t *)&client_token)
static unsigned foreign_client_calls;

static void
note_client(const struct mqvpn_client_s *c)
{
    if (c != ORACLE_CLIENT) foreign_client_calls++;
}

uint64_t
client_now_us(const struct mqvpn_client_s *c)
{
    note_client(c);
    return ORACLE_T_STUB_CLOCK;
}

void
client_log(struct mqvpn_client_s *c, mqvpn_log_level_t level, const char *fmt, ...)
{
    note_client(c);
    (void)level;
    (void)fmt;
}

void
path_fsm_fire_path_event(struct mqvpn_client_s *c, const path_entry_t *p)
{
    note_client(c);
    (void)p;
    oracle_obs.fires++;
}

void
client_notify_xqc_path_state(struct mqvpn_client_s *c, const path_entry_t *p,
                             int app_status)
{
    note_client(c);
    (void)p;
    oracle_obs.notifies++;
    oracle_obs.notify_status = app_status;
}

/* ─── Reporting ───
 * A failed check prints one line that starts with "FAIL", then indented
 * detail lines that contain neither "FAIL" nor the test's name, so a filter
 * on those two words keeps one line per failure, besides the summary lines
 * that start with the test's name (a broken canary child thus leaves two).
 * A child rerun for its own report writes to stderr as it is, and its stack
 * frames may name this file. An in-process abort is announced by glibc's
 * assertion line, which starts with the program name, so the filter keeps
 * it only when the binary is named test_path_slot_oracle; the "ABORT" line
 * after it names the row and contains neither word. */

static const char *const EV_NAME[OEV_COUNT] = {
    [OEV_ACTIVATE] = "ACTIVATE",
    [OEV_RETRY] = "RETRY",
    [OEV_VALIDATION_OK] = "VALIDATION_OK",
    [OEV_XQUIC_REMOVED] = "XQUIC_REMOVED",
    [OEV_MANUAL_REACTIVATE] = "MANUAL_REACTIVATE",
    [OEV_PLATFORM_DROP] = "PLATFORM_DROP",
    [OEV_REMOVE_API] = "REMOVE_API",
    [OEV_ADD] = "ADD",
    [OEV_CONN_RESET] = "CONN_RESET",
    [OEV_TRANSPORT_RELEASED] = "TRANSPORT_RELEASED",
    [OEV_STABLE_TICK] = "STABLE_TICK",
};

static const char *const CTX_NAME[] = {
    [OCTX_NONE] = "NONE",           [OCTX_OK] = "OK",
    [OCTX_TRANSIENT] = "TRANSIENT", [OCTX_PERMANENT] = "PERMANENT",
    [OCTX_ACTIVE] = "ACTIVE",       [OCTX_STANDBY] = "STANDBY",
    [OCTX_REACHED] = "REACHED",     [OCTX_BELOW] = "BELOW",
};

static const char *const UPD_NAME[] = {
    [UPD_KEEP] = "KEEP", [UPD_ZERO] = "ZERO", [UPD_NOW] = "NOW",
    [UPD_ARM] = "ARM",   [UPD_INC] = "INC",   [UPD_OTHER] = "OTHER",
};

/* Pre-state ids are ZERO/NZ; post-state ids are ZERO/OLD/NEW. */
static const char *const PRE_ID_NAME[] = {
    [ORACLE_ID_ZERO] = "ZERO", [ORACLE_ID_NZ] = "NZ"};
static const char *const POST_ID_NAME[] = {
    [ORACLE_ID_ZERO] = "ZERO", [ORACLE_ID_OLD] = "OLD", [ORACLE_ID_NEW] = "NEW"};

#define NAME_OF(tab, v)                                                             \
    ((unsigned)(v) < sizeof(tab) / sizeof((tab)[0]) && (tab)[(unsigned)(v)] != NULL \
         ? (tab)[(unsigned)(v)]                                                     \
         : "?")

static const char *
id_name(unsigned id, int post)
{
    return post ? NAME_OF(POST_ID_NAME, id) : NAME_OF(PRE_ID_NAME, id);
}

/* The id class of a concrete xqc_path_id, as the abstraction would read it. */
static const char *
conc_id_name(uint64_t id, int post)
{
    if (id == 0) return "ZERO";
    if (!post) return "NZ";
    if (id == ORACLE_PRE_ID) return "OLD";
    if (id == ORACLE_NEW_ID) return "NEW";
    return "?";
}

static void
print_slot(const char *tag, const oracle_slot_t *s, int post)
{
    fprintf(
        stderr, "    %s: %s att=%u live=%u rel=%u id=%s retries=%u retry=%u stable=%u\n",
        tag, path_lifecycle_name((path_lifecycle_t)s->state), s->attached, s->live,
        s->released, id_name(s->id, post), s->retries, s->retry_armed, s->stable_armed);
}

/* The concrete fields a failed check may be about. */
static void
print_entry(const char *tag, const path_entry_t *p, int post)
{
    const char *ctx = p->transport_ctx == NULL                     ? "NULL"
                      : p->transport_ctx == &oracle_ctx_marker_pre ? "pre"
                      : p->transport_ctx == &oracle_ctx_marker_add ? "add"
                                                                   : "other";
    fprintf(stderr,
            "    %s: %s status=%s att=%d live=%d rel=%d xqc_path_id=%llu (%s) "
            "retries=%d send=%s ctx=%s\n"
            "          recreate_after_us=%llu path_stable_since_us=%llu "
            "state_entered_at_us=%llu last_residence_warn_at_us=%llu\n",
            tag, path_lifecycle_name(p->state), mqvpn_path_status_name(p->status),
            p->transport_attached, p->xquic_path_live, p->transport_released,
            (unsigned long long)p->xqc_path_id, conc_id_name(p->xqc_path_id, post),
            p->recreate_retries,
            p->ops.send == NULL               ? "NULL"
            : p->ops.send == oracle_send_stub ? "stub"
                                              : "other",
            ctx, (unsigned long long)p->recreate_after_us,
            (unsigned long long)p->path_stable_since_us,
            (unsigned long long)p->state_entered_at_us,
            (unsigned long long)p->last_residence_warn_at_us);
}

static int failures;

/* The row being checked, for the failure reports and the abort handler. */
static struct {
    size_t i;
    const oracle_row_t *row;  /* NULL outside the row loop */
    const path_entry_t *slot; /* the concrete slot the checks read */
    int post;                 /* slot is the dispatched (post-)state */
} cur;

static void
print_row_context(void)
{
    print_slot("pre ", &cur.row->pre, 0);
    print_slot("want", &cur.row->post, 1);
    print_entry(cur.post ? "got " : "conc", cur.slot, cur.post);
}

/* A failed check of the current row; `detail` is its got/want line or NULL.
 * Only the first 20 failures are printed. */
static void
fail_row(const char *what, const char *detail)
{
    if (failures++ >= 20) return;
    fprintf(stderr, "FAIL row %zu (%s ctx=%s): %s\n", cur.i,
            NAME_OF(EV_NAME, cur.row->ev), NAME_OF(CTX_NAME, cur.row->ctx), what);
    if (detail) fprintf(stderr, "    %s\n", detail);
    print_row_context();
}

static void
expect(int ok, const char *what)
{
    if (!ok) fail_row(what, NULL);
}

static void
expect_eq(uint64_t got, uint64_t want, const char *what)
{
    if (got == want) return;
    char d[80];
    snprintf(d, sizeof(d), "got %llu, want %llu", (unsigned long long)got,
             (unsigned long long)want);
    fail_row(what, d);
}

static void
expect_upd(int got, int want, const char *what)
{
    if (got == want) return;
    char d[80];
    snprintf(d, sizeof(d), "got %s, want %s", NAME_OF(UPD_NAME, got),
             NAME_OF(UPD_NAME, want));
    fail_row(what, d);
}

/* An assert() that fires in this process (in path_on_event's own invariant
 * check or in one of check_row's) ends the test: name the row first. The
 * default action then runs, so the exit stays abnormal. */
static void
on_parent_abort(int sig)
{
    if (cur.row) {
        fprintf(stderr, "ABORT while checking row %zu (%s ctx=%s)\n", cur.i,
                NAME_OF(EV_NAME, cur.row->ev), NAME_OF(CTX_NAME, cur.row->ctx));
        print_row_context();
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

/* ─── Policy constants ───
 * The model abstracts time away, and the update classes check that the FSM
 * applies path_recreate_backoff() and PATH_STABLE_THRESHOLD_US, not what
 * they are. Their values are pinned here, so changing the retry schedule or
 * the stability window is a deliberate edit of this test too. */

_Static_assert(PATH_STABLE_THRESHOLD_US == 30ULL * 1000000ULL,
               "the stability window changed - update this test deliberately");

static void
check_policy_constants(void)
{
    static const uint64_t backoff_s[] = {5, 5, 10, 20, 40, 60, 60, 60, 60};
    for (int r = 0; r < (int)(sizeof(backoff_s) / sizeof(backoff_s[0])); r++) {
        const uint64_t want = backoff_s[r] * 1000000ULL;
        if (path_recreate_backoff(r) != want) {
            fprintf(stderr,
                    "FAIL policy: path_recreate_backoff(%d) = %llu us, want %llu us\n", r,
                    (unsigned long long)path_recreate_backoff(r),
                    (unsigned long long)want);
            failures++;
        }
    }
}

/* ─── The invariant in a child ─── */

/* A failed assert() calls abort(); the child turns that into this exit code,
 * so no core dump (or crash reporter such as apport) runs per shape. */
#define ABORT_EXIT 86

static void
on_abort(int sig)
{
    (void)sig;
    _exit(ABORT_EXIT);
}

/* Runs path_invariant_check() on the concretization of `a` in a child (the
 * abort would otherwise end this test) and returns its wait status. `quiet`
 * silences the child's stderr: the expected assertion messages would flood
 * the log. */
static int
run_child(const oracle_slot_t *a, int quiet)
{
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(2);
    }
    if (pid == 0) {
        signal(SIGABRT, on_abort);
        if (quiet && !freopen("/dev/null", "w", stderr)) _exit(3);
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
    return status;
}

static void
describe_status(int status, char *buf, size_t n)
{
    if (WIFEXITED(status))
        snprintf(buf, n, "exited with status %d", WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        snprintf(buf, n, "was killed by signal %d (%s)", WTERMSIG(status),
                 strsignal(WTERMSIG(status)));
    else
        snprintf(buf, n, "ended with wait status 0x%x", (unsigned)status);
}

enum { INV_ACCEPTS, INV_REJECTS, INV_BROKEN };

/* path_invariant_check() on the concretization of `a`: INV_REJECTS when it
 * aborts, INV_ACCEPTS when it returns. Any other end of the child (a
 * sanitizer report, a signal, a failed freopen) is neither: it counts as a
 * failure, reported here with the decoded status, and the child is rerun
 * once with its stderr, so its own report shows. */
static int
invariant_verdict(const oracle_slot_t *a, const char *who)
{
    const int status = run_child(a, 1);
    if (WIFEXITED(status) && WEXITSTATUS(status) == ABORT_EXIT) return INV_REJECTS;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return INV_ACCEPTS;
    if (failures++ < 20) {
        char d[128];
        describe_status(status, d, sizeof(d));
        fprintf(stderr,
                "FAIL %s: the path_invariant_check() child %s, neither the abort "
                "exit %d nor 0\n",
                who, d, ABORT_EXIT);
        print_slot("shape", a, 0);
        fprintf(stderr, "    rerunning it with its stderr:\n");
        describe_status(run_child(a, 0), d, sizeof(d));
        fprintf(stderr, "    the rerun %s\n", d);
    }
    return INV_BROKEN;
}

/* ─── Canary: the invariant is compiled in ─── */

static void
check_canary(void)
{
    /* CLOSED_FREE that claims an attached transport: illegal in both models. */
    const oracle_slot_t bad = {
        .state = PATH_LC_CLOSED_FREE, .attached = 1, .released = 1};
    switch (invariant_verdict(&bad, "canary")) {
    case INV_REJECTS: return;
    case INV_ACCEPTS:
        fprintf(stderr, "FAIL canary: path_invariant_check() did not abort on an "
                        "illegal slot - is NDEBUG defined for path_state_machine.c?\n");
        exit(1);
    default:
        fprintf(stderr, "test_path_slot_oracle: the canary child did not end cleanly "
                        "(see above)\n");
        exit(1);
    }
}

/* ─── One row ─── */

static void
check_row(size_t i, const oracle_row_t *row)
{
    /* Static, not on the stack: the abort handler reads them through cur. */
    static path_entry_t pre, p;
    oracle_slot_t got;

    cur.i = i;
    cur.row = row;
    cur.slot = &pre;
    cur.post = 0;

    /* (a) The canonical concretization is in the verified domain, is legal
     * for the C invariant, and abstracts back to the row's pre-state. */
    oracle_conc(&row->pre, &pre);
    expect(oracle_abs_pre(&pre, &got) && oracle_slot_eq(&got, &row->pre),
           "abs(conc(pre)) != pre");
    expect(oracle_in_dom(&pre), "conc(pre) outside Dom");
    expect(pre.state_entered_at_us != 0,
           "conc(pre) has no recorded state entry (Dom item 9)");
    path_invariant_check(&pre);

    /* (b) The composed dispatch. */
    expect(oracle_prefix_applies(&row->pre, row->ev) == row->prefix,
           "caller prefix condition disagrees with CallerPrefix");
    const uint64_t now = oracle_conc_now(&pre, row->ev, row->ctx);
    expect(oracle_no_collision(&pre, now), "canonical constants collide (Dom item 8)");

    p = pre;
    if (row->prefix) {
        const mqvpn_path_ops_t add_ops = oracle_canonical_add_ops();
        oracle_prefix_apply(row->ev, &p, &add_ops, &oracle_ctx_marker_add);
    }
    const mqvpn_path_ops_t ops_before = p.ops;
    void *const ctx_before = p.transport_ctx;

    const path_event_ctx_t e = oracle_event_ctx(row->ctx, now, ORACLE_NEW_ID);
    memset(&oracle_obs, 0, sizeof(oracle_obs));
    foreign_client_calls = 0;
    cur.slot = &p;
    cur.post = 1;
    oracle_dispatch(ORACLE_CLIENT, &p, row->ev, &e);
    expect_eq(foreign_client_calls, 0, "accessor calls with another client");

    expect(oracle_abs_post(&p, pre.xqc_path_id, ORACLE_NEW_ID, &got) &&
               oracle_slot_eq(&got, &row->post),
           "abstract post-state");
    expect_eq(oracle_obs.fires, row->fires, "public path event");
    const unsigned want_calls = row->notify ? 1 : 0;
    if (oracle_obs.notifies != want_calls ||
        (want_calls && oracle_obs.notify_status != row->notify)) {
        char d[128];
        snprintf(d, sizeof(d),
                 "got %u call(s), app_status %d; want %u call(s), app_status %u",
                 oracle_obs.notifies, oracle_obs.notify_status, want_calls, row->notify);
        fail_row("xquic app-status mirror", d);
    }
    expect_upd(oracle_retry_class(&pre, &p, now), row->retry_upd,
               "recreate_after_us update");
    expect_upd(oracle_stable_class(&pre, &p, now), row->stable_upd,
               "path_stable_since_us update");
    expect_upd(oracle_retries_class(&pre, &p), row->retries_upd,
               "recreate_retries update");
    expect_eq(p.state_entered_at_us,
              p.state != pre.state ? ORACLE_T_STUB_CLOCK : pre.state_entered_at_us,
              "state_entered_at_us");
    /* The handler never writes ops; it clears ctx only when it releases. */
    expect(oracle_ops_eq(&p.ops, &ops_before), "ops");
    expect(p.transport_ctx == (p.transport_released ? NULL : ctx_before),
           "transport_ctx");
    expect(oracle_conc_rule(&p), "post-state breaks the concretization rule");
    /* The model's Projection, not path_public_status_from_lifecycle():
     * path_invariant_check() below pins status to the C projection, so a row
     * that passes shows that the two projections agree on its post-state. */
    if (p.status != (mqvpn_path_status_t)row->status) {
        char d[80];
        snprintf(d, sizeof(d), "got %s, want %s", mqvpn_path_status_name(p.status),
                 mqvpn_path_status_name((mqvpn_path_status_t)row->status));
        fail_row("public status", d);
    }
    expect_eq(p.last_residence_warn_at_us, oracle_expected_residence_warn(&pre, &p),
              "last_residence_warn_at_us");
    expect(oracle_frame_eq(&pre, &p), "a field outside the FSM changed");
    /* The whole invariant on every post-state, STABLE_TICK's included
     * (path_fsm_tick_confirm_stable does not check it itself). */
    path_invariant_check(&p);
}

int
main(void)
{
    check_canary();
    check_policy_constants();
    signal(SIGABRT, on_parent_abort);

    for (size_t i = 0; i < PATH_SLOT_ORACLE_N_ROWS; i++)
        check_row(i, &PATH_SLOT_ORACLE_ROWS[i]);
    cur.row = NULL;

    /* (c) Every abstract shape outside the table's pre-states is one the C
     * invariant rejects. With (a), the C invariant accepts exactly PRE_SET. */
    unsigned shapes = 0, rejected = 0;
    for (unsigned st = 0; st <= PATH_LC_CLOSED_FREE; st++)
        for (unsigned bits = 0; bits < 64; bits++)
            for (unsigned r = 0; r <= PATH_RECREATE_MAX_RETRIES; r++) {
                const oracle_slot_t a = {
                    .state = (uint8_t)st,
                    .attached = bits & 1,
                    .live = (bits >> 1) & 1,
                    .released = (bits >> 2) & 1,
                    .id = (bits >> 3) & 1,
                    .retry_armed = (bits >> 4) & 1,
                    .stable_armed = (bits >> 5) & 1,
                    .retries = (uint8_t)r,
                };
                shapes++;
                if (oracle_in_pre_set(&a)) continue;
                switch (invariant_verdict(&a, "shape")) {
                case INV_REJECTS: rejected++; break;
                case INV_ACCEPTS:
                    if (failures++ < 20) {
                        fprintf(stderr, "FAIL shape accepted by path_invariant_check but "
                                        "illegal in the model:\n");
                        print_slot("shape", &a, 0);
                    }
                    break;
                default: break; /* reported by invariant_verdict */
                }
            }
    /* Every legal pre-state was enumerated once, every other shape rejected. */
    if (rejected + PATH_SLOT_ORACLE_N_PRE != shapes) {
        fprintf(stderr,
                "FAIL shape count: %u rejected + %d legal pre-states != %u shapes\n",
                rejected, PATH_SLOT_ORACLE_N_PRE, shapes);
        failures++;
    }

    if (failures) {
        fprintf(stderr,
                "test_path_slot_oracle: %d failure(s) (see formal/README.md, "
                "\"Changing the FSM and reading failures\")\n",
                failures);
        return 1;
    }
    printf("test_path_slot_oracle: %d rows OK; %u of %u abstract shapes illegal and "
           "rejected; canary OK\n",
           PATH_SLOT_ORACLE_N_ROWS, rejected, shapes);
    return 0;
}
