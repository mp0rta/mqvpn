// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* formal/cbmc/harness_path_on_event.c — CBMC conformance harness pinning
 * src/path_state_machine.c path_on_event() to the TLA+ transition relation
 * (formal/MqvpnPathSlot.tla, transliterated in model_step.h).
 *
 * Shape generation is nondeterministic: the initial slot ranges over every
 * shape path_invariant_check() (src/path_state_machine.c:140-225) accepts,
 * the event ranges over all 10 events, and the event context ranges over the
 * documented caller contract (see "Assumptions" in formal/README.md). For
 * every such combination CBMC proves:
 *   1. the post-state equals the model prediction field by field (P15);
 *   2. the assert()s inside path_invariant_check hold on the post-state,
 *      including the status == projection(state) denormalization (P2);
 *   3. the public path_event callback fires exactly on state change;
 *   4. the xquic app-status mirror (G-P15) matches its documented table;
 *   5. no out-of-bounds access, pointer misuse, signed overflow, undefined
 *      shift, or division by zero within the assumed domain.
 *
 * Run via formal/cbmc/run.sh (the flag set there is normative).
 */

#include "model_step.h"
#include "path_state_machine.h"

/* Observation counters maintained by stubs.c. */
extern unsigned stub_fired_count;
extern unsigned stub_notify_count;
extern int stub_notify_status;

/* CBMC nondet value sources. */
int nondet_int(void);
uint64_t nondet_uint64(void);

/* Caller clock upper bound: recreate_after_us = now_us + backoff(<= 60s)
 * must not wrap uint64 (a wrap to 0 would disarm the retry timer). 2^62 us
 * is ~146,000 years of monotonic clock — unreachable on real hardware. */
#define HARNESS_NOW_MAX (1ULL << 62)

static void
assume_legal_shape(path_entry_t *p)
{
    int st = nondet_int();
    __CPROVER_assume(st >= PATH_LC_PENDING && st <= PATH_LC_CLOSED_FREE);
    p->state = (path_lifecycle_t)st;
    p->status = path_public_status_from_lifecycle(p->state);

    /* Writer discipline: both flags are only ever written 0 or 1 by the FSM
     * and its callers. */
    p->platform_attached = nondet_int();
    __CPROVER_assume(p->platform_attached == 0 || p->platform_attached == 1);
    p->xquic_path_live = nondet_int();
    __CPROVER_assume(p->xquic_path_live == 0 || p->xquic_path_live == 1);

    p->fd = nondet_int();
    p->xqc_path_id = nondet_uint64();
    p->recreate_after_us = nondet_uint64();
    p->recreate_retries = nondet_int();
    p->path_stable_since_us = nondet_uint64();
    p->state_entered_at_us = nondet_uint64();
    p->last_residence_warn_at_us = nondet_uint64();

    /* retries domain: the abstraction saturates at PATH_RECREATE_MAX_RETRIES;
     * MAX+1 additionally represents "entered already past the threshold"
     * (higher concrete values map to the same abstract state). The concrete
     * counter is unbounded in the implementation — see formal/README.md,
     * "Assumptions". */
    __CPROVER_assume(p->recreate_retries >= 0 &&
                     p->recreate_retries <= PATH_RECREATE_MAX_RETRIES + 1);

    /* Transliteration of path_invariant_check
     * (src/path_state_machine.c:140-225), as assumptions on the pre-state. */
    switch (p->state) {
    case PATH_LC_PENDING:
        __CPROVER_assume(p->platform_attached == 1);
        __CPROVER_assume(p->xquic_path_live == 0);
        __CPROVER_assume(p->fd >= 0);
        __CPROVER_assume(p->xqc_path_id == 0);
        __CPROVER_assume(p->recreate_after_us == 0);
        __CPROVER_assume(p->path_stable_since_us == 0);
        break;
    case PATH_LC_CREATE_WAIT:
        __CPROVER_assume(p->platform_attached == 1);
        __CPROVER_assume(p->xquic_path_live == 0);
        __CPROVER_assume(p->fd >= 0);
        __CPROVER_assume(p->recreate_after_us != 0);
        break;
    case PATH_LC_VALIDATING:
        __CPROVER_assume(p->platform_attached == 1);
        __CPROVER_assume(p->xquic_path_live == 1);
        __CPROVER_assume(p->fd >= 0);
        __CPROVER_assume(p->recreate_after_us == 0);
        break;
    case PATH_LC_ACTIVE:
    case PATH_LC_STANDBY:
        __CPROVER_assume(p->platform_attached == 1);
        __CPROVER_assume(p->xquic_path_live == 1);
        __CPROVER_assume(p->fd >= 0);
        __CPROVER_assume(p->recreate_after_us == 0);
        break;
    case PATH_LC_DEGRADED:
        __CPROVER_assume(p->platform_attached == 1);
        __CPROVER_assume(p->xquic_path_live == 0);
        __CPROVER_assume(p->fd >= 0);
        __CPROVER_assume(p->xqc_path_id == 0);
        __CPROVER_assume(p->recreate_after_us != 0);
        __CPROVER_assume(p->path_stable_since_us == 0);
        break;
    case PATH_LC_CLOSED_RECOVERABLE:
        __CPROVER_assume(p->platform_attached == 1);
        __CPROVER_assume(p->xquic_path_live == 0);
        __CPROVER_assume(p->fd >= 0);
        __CPROVER_assume(p->xqc_path_id == 0);
        __CPROVER_assume(p->recreate_after_us == 0);
        __CPROVER_assume(p->path_stable_since_us == 0);
        break;
    case PATH_LC_CLOSED_DROPPED:
        /* Lazy cleanup: fd / live / xqc_path_id unconstrained. */
        __CPROVER_assume(p->platform_attached == 0);
        __CPROVER_assume(p->recreate_after_us == 0);
        __CPROVER_assume(p->path_stable_since_us == 0);
        break;
    case PATH_LC_CLOSED_FREE:
        __CPROVER_assume(p->platform_attached == 0);
        __CPROVER_assume(p->xquic_path_live == 0);
        __CPROVER_assume(p->fd < 0);
        __CPROVER_assume(p->xqc_path_id == 0);
        __CPROVER_assume(p->recreate_after_us == 0);
        __CPROVER_assume(p->path_stable_since_us == 0);
        break;
    }
}

void
harness(void)
{
    path_entry_t p;
    path_entry_init(&p); /* zero base: fields outside the tuple stay benign */

    int ev_raw = nondet_int();
    __CPROVER_assume(ev_raw >= PATH_EVENT_ACTIVATE_REQUESTED &&
                     ev_raw <= PATH_EVENT_FD_CLOSED);
    path_event_t ev = (path_event_t)ev_raw;

    if (ev == PATH_EVENT_ADD_FD) {
        /* Caller-composed pre-state (mqvpn_client_add_path_fd_with_outcome,
         * src/mqvpn_client.c:2616-2691): weak-fence reuse scan, then
         * path_entry_init, fresh handle, and p->fd = fd all happen BEFORE
         * the ADD_FD dispatch. The handler itself never touches fd, so the
         * PENDING invariant's fd >= 0 is the caller's contribution. The TLA
         * ApiAddFd action models this composite atomically. */
        int fd = nondet_int();
        __CPROVER_assume(fd >= 0);
        p.fd = fd;
    } else {
        assume_legal_shape(&p);
    }

    /* Event context per the caller contract (formal/README.md,
     * "Assumptions"). */
    path_event_ctx_t ctx;
    ctx.now_us = nondet_uint64();
    __CPROVER_assume(ctx.now_us >= 1 && ctx.now_us <= HARNESS_NOW_MAX);

    int result_raw = nondet_int();
    __CPROVER_assume(result_raw >= ACTIVATE_OK && result_raw <= ACTIVATE_PERMANENT_FAIL);
    ctx.result = (activate_result_t)result_raw;

    ctx.new_xqc_path_id = nondet_uint64();
    if (ctx.result == ACTIVATE_OK) {
        /* External xquic guarantee, not a caller-side check: see
         * formal/README.md, "Assumptions". */
        __CPROVER_assume(ctx.new_xqc_path_id >= 1);
    }

    int target_is_standby = nondet_int();
    ctx.validated_target = target_is_standby ? PATH_LC_STANDBY : PATH_LC_ACTIVE;

    abs_slot_t pre = abs_of_entry(&p);

    /* Concrete pre-values for the exact-value pins below (the abstract
     * tuple alone would let a sign/nonzero-preserving wrong write pass). */
    int pre_fd = p.fd;
    int pre_retries_concrete = p.recreate_retries;
    uint64_t pre_after = p.recreate_after_us;
    uint64_t pre_stable = p.path_stable_since_us;

    /* NULL-ctx defensive branch (path_on_event, src/path_state_machine.c:
     * 425-429): must leave the slot untouched and fire nothing. */
    if (nondet_int()) {
        path_on_event((struct mqvpn_client_s *)0, &p, ev, (void *)0);
        abs_slot_t post_null = abs_of_entry(&p);
        __CPROVER_assert(post_null.state == pre.state, "nullctx state");
        __CPROVER_assert(post_null.attached == pre.attached, "nullctx attached");
        __CPROVER_assert(post_null.live == pre.live, "nullctx live");
        __CPROVER_assert(post_null.xqc_id == pre.xqc_id, "nullctx xqc_id");
        __CPROVER_assert(post_null.fd_platform == pre.fd_platform, "nullctx fd_platform");
        __CPROVER_assert(post_null.retries == pre.retries, "nullctx retries");
        __CPROVER_assert(post_null.retry_armed == pre.retry_armed, "nullctx retry_armed");
        __CPROVER_assert(post_null.stable_armed == pre.stable_armed,
                         "nullctx stable_armed");
        __CPROVER_assert(stub_fired_count == 0, "nullctx no event fired");
        __CPROVER_assert(stub_notify_count == 0, "nullctx no notify");
        return;
    }

    abs_slot_t expected =
        model_step(pre, ev, ctx.result, ctx.new_xqc_path_id, ctx.validated_target);

    path_on_event((struct mqvpn_client_s *)0, &p, ev, &ctx);

    abs_slot_t post = abs_of_entry(&p);

    /* P15: field-by-field conformance with the model prediction. */
    __CPROVER_assert(post.state == expected.state, "conformance: state");
    __CPROVER_assert(post.attached == expected.attached, "conformance: attached");
    __CPROVER_assert(post.live == expected.live, "conformance: live");
    __CPROVER_assert(post.xqc_id == expected.xqc_id, "conformance: xqc_id");
    __CPROVER_assert(post.fd_platform == expected.fd_platform,
                     "conformance: fd_platform");
    __CPROVER_assert(post.retries == expected.retries, "conformance: retries");
    __CPROVER_assert(post.retry_armed == expected.retry_armed,
                     "conformance: retry_armed");
    __CPROVER_assert(post.stable_armed == expected.stable_armed,
                     "conformance: stable_armed");

    /* ── Exact-value pins ──
     * The abstract tuple compares fd/timers/retries through sign / nonzero /
     * saturation abstractions (matching the TLA state space). The pins below
     * additionally fix the CONCRETE values, so a wrong-but-same-sign fd
     * write, a wrong nonzero timestamp, or a wrong over-cap retry count
     * cannot pass. They intentionally re-encode the handler guards — a
     * drift in either encoding fails the check. */

    /* apply_failure_with_retry_check runs exactly on these guard-passed
     * dispatches (src/path_state_machine.c:468-470,502-504,540-548). */
    int ran_apply_failure =
        (ev == PATH_EVENT_ACTIVATE_REQUESTED && pre.state == PATH_LC_PENDING &&
         ctx.result == ACTIVATE_TRANSIENT_FAIL) ||
        (ev == PATH_EVENT_RETRY_TIMER &&
         (pre.state == PATH_LC_CREATE_WAIT || pre.state == PATH_LC_DEGRADED) &&
         ctx.result == ACTIVATE_TRANSIENT_FAIL) ||
        (ev == PATH_EVENT_XQUIC_REMOVED &&
         (pre.state == PATH_LC_VALIDATING || pre.state == PATH_LC_ACTIVE ||
          pre.state == PATH_LC_STANDBY));

    /* recreate_retries: incremented by apply_failure (unconditionally, even
     * past the cap — src/path_state_machine.c:389), zeroed by CONN_RESET,
     * untouched otherwise. */
    int expected_retries_concrete =
        (ev == PATH_EVENT_CONN_RESET)
            ? 0
            : (ran_apply_failure ? pre_retries_concrete + 1 : pre_retries_concrete);
    __CPROVER_assert(p.recreate_retries == expected_retries_concrete,
                     "exact: recreate_retries");

    /* recreate_after_us: freshly armed only by apply_failure below the cap
     * (now + backoff, src/path_state_machine.c:394); every path that
     * disarms writes literal 0; otherwise carried over (e.g. failed
     * MANUAL_REACTIVATE keeps the pending auto-retry deadline). */
    uint64_t expected_after =
        (ran_apply_failure && expected.retry_armed)
            ? ctx.now_us + path_recreate_backoff(expected_retries_concrete)
            : (expected.retry_armed ? pre_after : 0);
    __CPROVER_assert(p.recreate_after_us == expected_after, "exact: recreate_after_us");

    /* path_stable_since_us: set to now only by VALIDATION_OK in VALIDATING
     * (src/path_state_machine.c:529); cleared to 0 wherever disarmed. */
    uint64_t expected_stable =
        (ev == PATH_EVENT_VALIDATION_OK && pre.state == PATH_LC_VALIDATING)
            ? ctx.now_us
            : (expected.stable_armed ? pre_stable : 0);
    __CPROVER_assert(p.path_stable_since_us == expected_stable,
                     "exact: path_stable_since_us");

    /* fd: written by the FSM only in path_on_fd_closed (-1,
     * src/path_state_machine.c:687); every other handler must leave it. */
    int expected_fd =
        (ev == PATH_EVENT_FD_CLOSED && pre.state == PATH_LC_CLOSED_DROPPED) ? -1 : pre_fd;
    __CPROVER_assert(p.fd == expected_fd, "exact: fd");

    /* Residence-timer anchor: every real state change must re-anchor
     * state_entered_at_us via path_mark_state_entry (stub clock returns 1).
     * Same-state re-anchoring (state_entered_at_us == 0 self-loops) is a
     * logging/residence-timer concern outside this harness's scope — see
     * formal/README.md. */
    if (pre.state != post.state) {
        __CPROVER_assert(p.state_entered_at_us == 1,
                         "state change re-anchors residence timer");
    }

    /* Public callback fires exactly on lifecycle-state change
     * (path_on_event, src/path_state_machine.c:446-448). */
    __CPROVER_assert(stub_fired_count == ((pre.state != post.state) ? 1u : 0u),
                     "path_event fired iff state changed");

    /* G-P15 app-status mirror shape pin: notification occurs exactly when a
     * real transition matches the documented table, with the table's value.
     * (g_p15_xqc_app_status_for, src/path_state_machine.c:317-325). */
    int expected_notify =
        (pre.state != post.state) ? model_g_p15_status(pre.state, post.state) : 0;
    __CPROVER_assert(stub_notify_count == ((expected_notify != 0) ? 1u : 0u),
                     "xqc app-status notify iff table hit");
    if (expected_notify != 0) {
        __CPROVER_assert(stub_notify_status == expected_notify,
                         "xqc app-status notify value");
    }
}
