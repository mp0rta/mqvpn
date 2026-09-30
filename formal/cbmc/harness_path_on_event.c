// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* formal/cbmc/harness_path_on_event.c — CBMC harnesses for the path-slot FSM.
 *
 * harness: abstraction consistency by self-composition. Two arbitrary
 * concrete slots with the same abstract state receive the same event and
 * context class (with independent concrete now, accessor clock, new id and
 * timer values);
 * their abstract post-states and observable calls must agree, and so must
 * their update classes where both runs meet Dom item 8.
 * With tests/test_path_slot_oracle.c (every row holds on the canonical slot)
 * this extends the oracle to every slot in the domain (formal/README.md).
 * Along the way CBMC proves path_invariant_check()'s assertions and, for
 * every such input, the checks run.sh enables: array bounds, pointers,
 * signed overflow, shifts and division by zero.
 *
 * harness_null_ctx: the defensive NULL-context branch changes no field of
 * any slot, in the domain or not, and makes no call.
 *
 * NDEBUG must not be defined (run.sh): it removes every assert(), this
 * file's own and path_invariant_check()'s, and they are the proof
 * obligations here. "Dom item N" refers to the numbered domain in
 * formal/README.md. */

#include "oracle_abs.h"
#include <assert.h>

/* ─── Accessor stubs ───
 * The FSM is called with an arbitrary non-NULL c that points to no client;
 * that is safe only because these stubs never dereference it (the real
 * accessors in mqvpn_client.c do). */

oracle_obs_t oracle_obs;

/* What client_now_us returns during the current run. Each run draws its own
 * (arbitrary_clock), so the proof covers every value the accessor can
 * return, and the two runs of harness may see different ones. */
static uint64_t stub_clock;

uint64_t
client_now_us(const struct mqvpn_client_s *c)
{
    (void)c;
    return stub_clock;
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

/* ─── Nondeterminism ─── */

int nondet_int(void);
uint64_t nondet_u64(void);
void *nondet_ptr(void);
path_entry_t nondet_path_entry(void);
mqvpn_path_ops_t nondet_path_ops(void);

/* The client pointer of one run: arbitrary and non-NULL, as every production
 * caller passes its client. The FSM only hands it to the stubs, which ignore
 * it; with an independent pointer per run of harness, the abstract result
 * cannot depend on its value. */
static mqvpn_client_t *
arbitrary_client(void)
{
    mqvpn_client_t *const c = (mqvpn_client_t *)nondet_ptr();
    __CPROVER_assume(c != NULL);
    return c;
}

/* The accessor clock of one run: arbitrary, independent of the event's
 * now_us, and nonzero. Nonzero is an assumption of the proof, the one Dom
 * item 9 makes of the injectable clock (mqvpn_config_set_clock): the API
 * does not enforce it, and client_now_us returns the clock's value
 * unchecked. */
static uint64_t
arbitrary_clock(void)
{
    const uint64_t t = nondet_u64();
    __CPROVER_assume(t != 0);
    return t;
}

/* A slot with every field arbitrary — handle, name, addresses, statistics,
 * every ops pointer and the ctx included — so the proof covers every slot
 * of the domain, the unit test's canonical ones among them. harness narrows
 * it with oracle_in_dom(); harness_null_ctx takes it as it is. No pointer is
 * ever dereferenced. */
static void
nondet_slot(path_entry_t *p)
{
    *p = nondet_path_entry();
}

/* Make the context fields the class does not use arbitrary, so the proof
 * also covers "the handler does not read them" (real callers leave them 0). */
static void
havoc_unread(path_event_ctx_t *e, int ctx)
{
    if (ctx != OCTX_OK && ctx != OCTX_TRANSIENT && ctx != OCTX_PERMANENT)
        e->result = (activate_result_t)nondet_int();
    if (ctx != OCTX_OK) e->new_xqc_path_id = nondet_u64();
    if (ctx != OCTX_ACTIVE && ctx != OCTX_STANDBY)
        e->validated_target = (path_lifecycle_t)nondet_int();
}

/* The context classes an event reads (oracle_ctx_t). ctx_valid and
 * havoc_unread copy the model's event/context pairs by hand; a new class
 * would go unexplored. */
_Static_assert(PATH_SLOT_ORACLE_N_EVCTX == 19,
               "the model's event/context classes changed - review ctx_valid and "
               "havoc_unread");

/* The longest loop, oracle_in_pre_set's scan, runs PATH_SLOT_ORACLE_N_PRE
 * times; run.sh's --unwind 200 covers a loop of at most 199 iterations. */
_Static_assert(
    PATH_SLOT_ORACLE_N_PRE < 200,
    "the pre-state table outgrew --unwind 200: raise it in formal/cbmc/run.sh");

static int
ctx_valid(int ev, int ctx)
{
    switch (ev) {
    case OEV_ACTIVATE:
    case OEV_RETRY:
    case OEV_MANUAL_REACTIVATE:
        return ctx == OCTX_OK || ctx == OCTX_TRANSIENT || ctx == OCTX_PERMANENT;
    case OEV_VALIDATION_OK: return ctx == OCTX_ACTIVE || ctx == OCTX_STANDBY;
    case OEV_STABLE_TICK: return ctx == OCTX_REACHED || ctx == OCTX_BELOW;
    default: return ctx == OCTX_NONE;
    }
}

typedef struct {
    path_entry_t pre;
    path_entry_t post;
    uint64_t now;
    uint64_t clock;         /* what client_now_us returns during this run */
    mqvpn_client_t *client; /* the client pointer this run dispatches with */
    uint64_t new_id;
    oracle_obs_t obs;
    oracle_slot_t abs_post;
} run_t;

/* One composed dispatch of (ev, ctx) on the Dom slot `pre`: the caller's
 * prefix where it applies, the handler, then every per-run obligation.
 * Per-run assumptions: now in [1, 2^62] and a new id that is neither 0 nor
 * the slot's id (both Dom item 7); an accessor clock of its own, arbitrary
 * and nonzero (arbitrary_clock); for STABLE_TICK, whether the stable window
 * has elapsed at now is assumed to match ctx, the same class in both runs. */
static void
run_one(run_t *r, int ev, int ctx, int prefix)
{
    r->now = nondet_u64();
    __CPROVER_assume(r->now >= 1 && r->now <= (1ULL << 62)); /* Dom item 7 */
    r->clock = arbitrary_clock();
    stub_clock = r->clock;
    r->client = arbitrary_client();
    r->new_id = nondet_u64();
    __CPROVER_assume(r->new_id != 0 && r->new_id != r->pre.xqc_path_id);
    if (ev == OEV_STABLE_TICK) {
        int reached =
            (uint64_t)(r->now - r->pre.path_stable_since_us) >= PATH_STABLE_THRESHOLD_US;
        __CPROVER_assume(reached == (ctx == OCTX_REACHED));
    }

    r->post = r->pre;
    if (prefix) {
        /* ADD: whatever transport the platform installs, send non-NULL, the
         * optional callbacks and the ctx arbitrary. TRANSPORT_RELEASED's
         * prefix ignores add_ops and the ctx (it clears both). */
        mqvpn_path_ops_t add_ops = nondet_path_ops();
        __CPROVER_assume(add_ops.send != NULL);
        oracle_prefix_apply(ev, &r->post, &add_ops, nondet_ptr());
    }
    const mqvpn_path_ops_t ops_before = r->post.ops;
    void *const ctx_before = r->post.transport_ctx;

    path_event_ctx_t e = oracle_event_ctx(ctx, r->now, r->new_id);
    havoc_unread(&e, ctx);
    memset(&oracle_obs, 0, sizeof(oracle_obs));
    oracle_dispatch(r->client, &r->post, ev, &e);
    r->obs = oracle_obs;

    const int abs_defined =
        oracle_abs_post(&r->post, r->pre.xqc_path_id, r->new_id, &r->abs_post);
    assert(abs_defined);
    assert(r->obs.fires <= 1 && r->obs.notifies <= 1);
    assert(oracle_conc_rule(&r->post));
    /* The whole invariant on every post-state, STABLE_TICK's included
     * (path_fsm_tick_confirm_stable does not check it itself), status among
     * it. */
    path_invariant_check(&r->post);
    /* The frame: the fields the FSM must not write. */
    assert(oracle_frame_eq(&r->pre, &r->post));
    assert(oracle_ops_eq(&r->post.ops, &ops_before));
    assert(r->post.transport_ctx == (r->post.transport_released ? NULL : ctx_before));
    /* The state-entry bookkeeping, for a recorded entry (Dom item 9): with
     * state_entered_at_us == 0, set_path_state_with_log treats a same-state
     * write as a first entry and stamps both fields. */
    if (r->pre.state_entered_at_us != 0) {
        assert(r->post.state_entered_at_us ==
               (r->post.state != r->pre.state ? r->clock : r->pre.state_entered_at_us));
        assert(r->post.last_residence_warn_at_us ==
               oracle_expected_residence_warn(&r->pre, &r->post));
    }
}

void
harness(void)
{
    const int ev = nondet_int();
    const int ctx = nondet_int();
    __CPROVER_assume(ev >= 0 && ev < OEV_COUNT);
    __CPROVER_assume(ctx_valid(ev, ctx));

    run_t r1, r2;
    nondet_slot(&r1.pre);
    nondet_slot(&r2.pre);
    /* Dom items 1-6 */
    __CPROVER_assume(oracle_in_dom(&r1.pre) && oracle_in_dom(&r2.pre));
    /* oracle_abs_pre succeeds on both: oracle_in_dom returns 0 when it fails. */
    oracle_slot_t a1, a2;
    oracle_abs_pre(&r1.pre, &a1);
    oracle_abs_pre(&r2.pre, &a2);
    __CPROVER_assume(oracle_slot_eq(&a1, &a2));

    const int prefix = oracle_prefix_applies(&a1, ev);
    run_one(&r1, ev, ctx, prefix);
    run_one(&r2, ev, ctx, prefix);

    /* The theorem: same abstract pre-state -> same abstract result. */
    assert(oracle_slot_eq(&r1.abs_post, &r2.abs_post));
    assert(r1.obs.fires == r2.obs.fires);
    assert(r1.obs.notifies == r2.obs.notifies);
    assert(r1.obs.notifies == 0 || r1.obs.notify_status == r2.obs.notify_status);

    /* Update classes, under Dom item 8 only. */
    if (oracle_no_collision(&r1.pre, r1.now) && oracle_no_collision(&r2.pre, r2.now)) {
        const int rc1 = oracle_retry_class(&r1.pre, &r1.post, r1.now);
        const int sc1 = oracle_stable_class(&r1.pre, &r1.post, r1.now);
        const int nc1 = oracle_retries_class(&r1.pre, &r1.post);
        assert(rc1 != UPD_OTHER && sc1 != UPD_OTHER && nc1 != UPD_OTHER);
        assert(rc1 == oracle_retry_class(&r2.pre, &r2.post, r2.now));
        assert(sc1 == oracle_stable_class(&r2.pre, &r2.post, r2.now));
        assert(nc1 == oracle_retries_class(&r2.pre, &r2.post));
    }
}

void
harness_null_ctx(void)
{
    const int ev = nondet_int();
    __CPROVER_assume(ev >= 0 && ev < OEV_STABLE_TICK); /* path_on_event events */
    path_entry_t p;
    nondet_slot(&p);
    const path_entry_t before = p;
    stub_clock = arbitrary_clock(); /* the branch reads no clock today */

    memset(&oracle_obs, 0, sizeof(oracle_obs));
    oracle_dispatch(arbitrary_client(), &p, ev, NULL);

    /* Field by field (a struct memcmp would also compare padding): the
     * lifecycle and bookkeeping fields, ops and ctx here, the rest through the
     * frame — together the 22 fields path_entry_t has today. The size pin in
     * oracle_abs.h catches only a new field that grows the struct; one of 4
     * bytes or less placed in one of its three padding holes keeps the size
     * and must be classified by hand (see the pin's comment). */
    assert(p.state == before.state && p.status == before.status &&
           p.transport_attached == before.transport_attached &&
           p.transport_released == before.transport_released &&
           p.xquic_path_live == before.xquic_path_live &&
           p.xqc_path_id == before.xqc_path_id &&
           p.recreate_after_us == before.recreate_after_us &&
           p.recreate_retries == before.recreate_retries &&
           p.path_stable_since_us == before.path_stable_since_us &&
           p.state_entered_at_us == before.state_entered_at_us &&
           p.last_residence_warn_at_us == before.last_residence_warn_at_us &&
           p.transport_ctx == before.transport_ctx && oracle_ops_eq(&p.ops, &before.ops));
    assert(oracle_frame_eq(&before, &p));
    assert(oracle_obs.fires == 0 && oracle_obs.notifies == 0);
}
