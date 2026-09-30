// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* formal/oracle/oracle_abs.h — the one definition of how a concrete
 * path_entry_t relates to the abstract slot of formal/PathSlotFsm.tla, shared
 * by the exhaustive oracle test (tests/test_path_slot_oracle.c) and the CBMC
 * harness (formal/cbmc/harness_path_on_event.c). Keeping it in one place is
 * the point: a second copy would be a new translation gap.
 *
 * It provides the abstraction (oracle_abs_pre / oracle_abs_post), a canonical
 * concretization (oracle_conc), the caller's own slot writes that precede a
 * dispatch (oracle_prefix_*), the update classes of the timers and the retry
 * counter, and the verified domain (oracle_in_dom). The table itself is
 * generated: path_slot_oracle.inc. "Dom item N" refers to the numbered list
 * in formal/README.md.
 *
 * Consumers define the four accessors path_state_machine.c links against and
 * record what they observe in oracle_obs (see oracle_obs_t). */

#ifndef MQVPN_FORMAL_ORACLE_ABS_H
#define MQVPN_FORMAL_ORACLE_ABS_H

#include "path_state_machine.h"
#include <limits.h>
#include <stdint.h>
#include <string.h>

/* ─── The FSM's enums, as the model knows them ───
 * A value appended to one of these enums is in neither PathSlotFsm.tla nor
 * the table, so no row or shape would exercise it. Each switch below lists
 * every enumerator and has no default, and -Wswitch is an error here: gcc
 * and clang reject the unit test's compile with an error that names the new
 * value on the line of its switch, with or without -Wall and -Werror. (CBMC
 * does not check -Wswitch.) The existing pins on the last value of
 * path_lifecycle_t and path_event_t (src/path_state_machine.h:93-99) catch
 * an insertion or a reorder, not an appended value. The functions are never
 * called. */
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"

/* A new event: add it to PathSlotFsm.tla (Events, Handle) and
 * PathSlotOracle.tla's EvCtx, to oracle_event_t and oracle_dispatch below,
 * and to gen_oracle.py (EVENTS, EVCTX). */
static inline int
oracle_known_event(path_event_t ev)
{
    switch (ev) {
    case PATH_EVENT_ACTIVATE_REQUESTED:
    case PATH_EVENT_RETRY_TIMER:
    case PATH_EVENT_VALIDATION_OK:
    case PATH_EVENT_XQUIC_REMOVED:
    case PATH_EVENT_MANUAL_REACTIVATE:
    case PATH_EVENT_PLATFORM_DROP:
    case PATH_EVENT_REMOVE_API:
    case PATH_EVENT_ADD:
    case PATH_EVENT_CONN_RESET:
    case PATH_EVENT_TRANSPORT_RELEASED: return 1;
    }
    return 0;
}

/* A new state: add it to PathSlotFsm.tla (States, Legal, Projection and the
 * handlers), to gen_oracle.py's STATE_C, to the range check in
 * oracle_abs_common below and to the shape loop (c) of
 * tests/test_path_slot_oracle.c. */
static inline int
oracle_known_state(path_lifecycle_t s)
{
    switch (s) {
    case PATH_LC_PENDING:
    case PATH_LC_CREATE_WAIT:
    case PATH_LC_VALIDATING:
    case PATH_LC_ACTIVE:
    case PATH_LC_STANDBY:
    case PATH_LC_DEGRADED:
    case PATH_LC_CLOSED_RECOVERABLE:
    case PATH_LC_CLOSED_DROPPED:
    case PATH_LC_CLOSED_FREE: return 1;
    }
    return 0;
}

/* A new activation result: add a context class for it (oracle_ctx_t and
 * oracle_event_ctx below, PathSlotFsm.tla's Results, gen_oracle.py's CTX
 * and EVCTX, and ctx_valid and havoc_unread in the CBMC harness). */
static inline int
oracle_known_result(activate_result_t r)
{
    switch (r) {
    case ACTIVATE_OK:
    case ACTIVATE_TRANSIENT_FAIL:
    case ACTIVATE_PERMANENT_FAIL: return 1;
    }
    return 0;
}

/* A new public status: add it to PathSlotFsm.tla's Projection and to
 * gen_oracle.py's STATUS_C. */
static inline int
oracle_known_status(mqvpn_path_status_t st)
{
    switch (st) {
    case MQVPN_PATH_PENDING:
    case MQVPN_PATH_ACTIVE:
    case MQVPN_PATH_DEGRADED:
    case MQVPN_PATH_STANDBY:
    case MQVPN_PATH_CLOSED: return 1;
    }
    return 0;
}

#pragma GCC diagnostic pop

/* An abstract slot, as in PathSlotFsm.tla. id: pre-state 0 = ZERO, 1 = NZ;
 * post-state 0 = ZERO, 1 = OLD (the pre-state id), 2 = NEW (the context's
 * new id). retries saturates at PATH_RECREATE_MAX_RETRIES. */
typedef struct {
    uint8_t state; /* path_lifecycle_t */
    uint8_t attached;
    uint8_t live;
    uint8_t released;
    uint8_t id;
    uint8_t retries;
    uint8_t retry_armed;
    uint8_t stable_armed;
} oracle_slot_t;

enum { ORACLE_ID_ZERO = 0, ORACLE_ID_NZ = 1, ORACLE_ID_OLD = 1, ORACLE_ID_NEW = 2 };

typedef enum {
    OEV_ACTIVATE = 0,
    OEV_RETRY,
    OEV_VALIDATION_OK,
    OEV_XQUIC_REMOVED,
    OEV_MANUAL_REACTIVATE,
    OEV_PLATFORM_DROP,
    OEV_REMOVE_API,
    OEV_ADD,
    OEV_CONN_RESET,
    OEV_TRANSPORT_RELEASED,
    OEV_STABLE_TICK, /* path_fsm_tick_confirm_stable, not path_on_event */
    OEV_COUNT
} oracle_event_t;

typedef enum {
    OCTX_NONE = 0,
    OCTX_OK,
    OCTX_TRANSIENT,
    OCTX_PERMANENT,
    OCTX_ACTIVE,  /* VALIDATION_OK target */
    OCTX_STANDBY, /* VALIDATION_OK target */
    OCTX_REACHED, /* STABLE_TICK: (now - since) >= PATH_STABLE_THRESHOLD_US */
    OCTX_BELOW,   /* STABLE_TICK: below the threshold */
} oracle_ctx_t;

/* How a timer or the retry counter was updated. KEEP = unchanged,
 * ZERO = cleared, NOW = the event's now, ARM = now + backoff(post retries),
 * INC = pre + 1. OTHER is never in the table. */
typedef enum {
    UPD_KEEP = 0,
    UPD_ZERO,
    UPD_NOW,
    UPD_ARM,
    UPD_INC,
    UPD_OTHER
} oracle_upd_t;

typedef struct {
    oracle_slot_t pre;
    uint8_t ev;     /* oracle_event_t */
    uint8_t ctx;    /* oracle_ctx_t */
    uint8_t prefix; /* the caller's slot writes precede this dispatch */
    oracle_slot_t post;
    uint8_t status; /* mqvpn_path_status_t of post: the model's Projection */
    uint8_t fires;  /* path_fsm_fire_path_event called */
    uint8_t notify; /* client_notify_xqc_path_state app_status, 0 = not called */
    uint8_t retry_upd;
    uint8_t stable_upd;
    uint8_t retries_upd;
} oracle_row_t;

#include "path_slot_oracle.inc"

/* What the consumer's accessor stubs observed during one dispatch. */
typedef struct {
    unsigned fires;
    unsigned notifies;
    int notify_status;
} oracle_obs_t;
extern oracle_obs_t oracle_obs;

/* ─── Concretization constants ───
 * Chosen so that no two of now, now + backoff(r), 0 and the pre-state timer
 * values coincide: the update classes are then unambiguous (Dom item 8 holds
 * for every canonical concretization). */
#define ORACLE_T_NOW        1000000000000ULL /* now for every event but STABLE_TICK */
#define ORACLE_T_RETRY      777ULL           /* an armed pre-state recreate_after_us */
#define ORACLE_T_STABLE     3000000000ULL    /* an armed pre-state path_stable_since_us */
#define ORACLE_T_ENTERED    99ULL     /* pre-state state_entered_at_us (Dom item 9) */
#define ORACLE_T_STUB_CLOCK 424242ULL /* the unit test's client_now_us stub clock */
#define ORACLE_PRE_ID       7ULL      /* a nonzero pre-state xqc_path_id */
#define ORACLE_NEW_ID       11ULL     /* the context's new xqc_path_id */

/* A pre-state last_residence_warn_at_us (a debounce the client armed). Not 0,
 * so a state change that fails to clear it is visible, and none of the stamp,
 * now and timer values, so a stray copy of one of them is visible too. */
#define ORACLE_T_RESIDENCE_WARN 555ULL

_Static_assert(ORACLE_T_STUB_CLOCK != ORACLE_T_ENTERED,
               "state entry stamp must be distinguishable from the pre-state value");
/* Every now: ORACLE_T_NOW and the four STABLE_TICK values oracle_conc_now
 * can produce (since 0 or ORACLE_T_STABLE, threshold reached or not). */
_Static_assert(
    ORACLE_T_STUB_CLOCK != ORACLE_T_NOW && ORACLE_T_STUB_CLOCK != ORACLE_T_RETRY &&
        ORACLE_T_STUB_CLOCK != ORACLE_T_STABLE &&
        ORACLE_T_STUB_CLOCK != ORACLE_T_ENTERED &&
        ORACLE_T_STUB_CLOCK != PATH_STABLE_THRESHOLD_US - 1 &&
        ORACLE_T_STUB_CLOCK != PATH_STABLE_THRESHOLD_US &&
        ORACLE_T_STUB_CLOCK != ORACLE_T_STABLE + PATH_STABLE_THRESHOLD_US - 1 &&
        ORACLE_T_STUB_CLOCK != ORACLE_T_STABLE + PATH_STABLE_THRESHOLD_US,
    "state entry stamp must be distinguishable from every now and timer value");
_Static_assert(
    ORACLE_T_RESIDENCE_WARN != 0 && ORACLE_T_RESIDENCE_WARN != ORACLE_T_STUB_CLOCK &&
        ORACLE_T_RESIDENCE_WARN != ORACLE_T_ENTERED &&
        ORACLE_T_RESIDENCE_WARN != ORACLE_T_NOW &&
        ORACLE_T_RESIDENCE_WARN != ORACLE_T_RETRY &&
        ORACLE_T_RESIDENCE_WARN != ORACLE_T_STABLE &&
        ORACLE_T_RESIDENCE_WARN != PATH_STABLE_THRESHOLD_US - 1 &&
        ORACLE_T_RESIDENCE_WARN != PATH_STABLE_THRESHOLD_US &&
        ORACLE_T_RESIDENCE_WARN != ORACLE_T_STABLE + PATH_STABLE_THRESHOLD_US - 1 &&
        ORACLE_T_RESIDENCE_WARN != ORACLE_T_STABLE + PATH_STABLE_THRESHOLD_US,
    "the pre-state residence-warn debounce must be distinguishable from 0 and from "
    "every stamp, now and timer value");
_Static_assert(ORACLE_PRE_ID != 0 && ORACLE_NEW_ID != 0 && ORACLE_PRE_ID != ORACLE_NEW_ID,
               "abstract id classes need distinct nonzero ids");
_Static_assert(ORACLE_T_STABLE + PATH_STABLE_THRESHOLD_US < ORACLE_T_NOW,
               "STABLE_TICK now values must stay apart from ORACLE_T_NOW");
_Static_assert(ORACLE_T_RETRY < PATH_RECREATE_DELAY_US,
               "an armed pre-state retry deadline must not equal any now + backoff");

static char oracle_ctx_marker_pre; /* transport_ctx of an attached pre-state */
/* transport_ctx installed by the ADD prefix; unused by a consumer without one */
static char oracle_ctx_marker_add __attribute__((unused));

static int
oracle_send_stub(void *ctx, const mqvpn_datagram_t *bufs, unsigned n,
                 const struct sockaddr *peer, socklen_t peer_len)
{
    (void)ctx;
    (void)bufs;
    (void)n;
    (void)peer;
    (void)peer_len;
    return MQVPN_TX_FAILED;
}

/* ─── Abstraction ─── */

static inline int
oracle_is_bool(int v)
{
    return v == 0 || v == 1;
}

/* Fields shared by the pre- and post-state abstraction. Returns 0 when the
 * slot is outside the abstract domain (a non-boolean flag, a state out of
 * range, a negative retry count). */
static inline int
oracle_abs_common(const path_entry_t *p, oracle_slot_t *a)
{
    if ((unsigned)p->state > (unsigned)PATH_LC_CLOSED_FREE) return 0;
    if (!oracle_is_bool(p->transport_attached) ||
        !oracle_is_bool(p->transport_released) || !oracle_is_bool(p->xquic_path_live) ||
        p->recreate_retries < 0)
        return 0;
    a->state = (uint8_t)p->state;
    a->attached = (uint8_t)p->transport_attached;
    a->live = (uint8_t)p->xquic_path_live;
    a->released = (uint8_t)p->transport_released;
    a->retries = (uint8_t)(p->recreate_retries < PATH_RECREATE_MAX_RETRIES
                               ? p->recreate_retries
                               : PATH_RECREATE_MAX_RETRIES);
    a->retry_armed = p->recreate_after_us != 0;
    a->stable_armed = p->path_stable_since_us != 0;
    return 1;
}

static inline int
oracle_abs_pre(const path_entry_t *p, oracle_slot_t *a)
{
    if (!oracle_abs_common(p, a)) return 0;
    a->id = p->xqc_path_id != 0 ? ORACLE_ID_NZ : ORACLE_ID_ZERO;
    return 1;
}

/* The post-state id is classified against the pre-state id and the new id;
 * any other value is outside the abstraction (returns 0). */
static inline int
oracle_abs_post(const path_entry_t *p, uint64_t pre_id, uint64_t new_id, oracle_slot_t *a)
{
    if (!oracle_abs_common(p, a)) return 0;
    if (p->xqc_path_id == 0)
        a->id = ORACLE_ID_ZERO;
    else if (p->xqc_path_id == pre_id)
        a->id = ORACLE_ID_OLD;
    else if (p->xqc_path_id == new_id)
        a->id = ORACLE_ID_NEW;
    else
        return 0;
    return 1;
}

static inline int
oracle_slot_eq(const oracle_slot_t *x, const oracle_slot_t *y)
{
    return x->state == y->state && x->attached == y->attached && x->live == y->live &&
           x->released == y->released && x->id == y->id && x->retries == y->retries &&
           x->retry_armed == y->retry_armed && x->stable_armed == y->stable_armed;
}

static inline int
oracle_in_pre_set(const oracle_slot_t *a)
{
    for (int i = 0; i < PATH_SLOT_ORACLE_N_PRE; i++)
        if (oracle_slot_eq(a, &PATH_SLOT_ORACLE_PRE[i])) return 1;
    return 0;
}

/* The concretization rule: a slot owes a release exactly while a transport
 * is installed. Holds on every pre- and post-state of a dispatch. */
static inline int
oracle_conc_rule(const path_entry_t *p)
{
    if (p->transport_released) return p->ops.send == NULL && p->transport_ctx == NULL;
    return p->ops.send != NULL;
}

/* Dom items 1-6 (formal/README.md): the concrete slots the theorem is
 * about. Item 7 constrains the event context and is assumed where the context
 * is built; items 8 (no accidental timer-value collision) and 9 (a recorded
 * state entry) are preconditions of the update-class and state_entered_at_us
 * checks only. recreate_retries may take any value below INT_MAX: it grows
 * without bound in the code (formal/README.md, finding 3), and the bound only
 * keeps the increment itself from overflowing. */
static inline int
oracle_in_dom(const path_entry_t *p)
{
    oracle_slot_t a;
    if (!oracle_abs_pre(p, &a)) return 0;
    if (p->status != path_public_status_from_lifecycle(p->state)) return 0;
    if (p->recreate_retries == INT_MAX) return 0;
    if (!oracle_conc_rule(p)) return 0;
    return oracle_in_pre_set(&a);
}

/* ─── Concretization ─── */

/* The canonical concrete slot of an abstract one: the abstraction's fields
 * take the constants above, the state entry is recorded (Dom item 9) and the
 * residence-warn debounce is armed. The frame fields (flags, the byte
 * counters, srtt_ms, platform_net_id, local_addr*) stay 0: a handler that
 * reads them, or writes the 0 they already hold, is formal/cbmc/'s to catch,
 * over arbitrary slots. */
static inline void
oracle_conc(const oracle_slot_t *a, path_entry_t *p)
{
    memset(p, 0, sizeof(*p));
    p->handle = 1;
    memcpy(p->name, "oracle", sizeof("oracle"));
    p->state = (path_lifecycle_t)a->state;
    p->status = path_public_status_from_lifecycle(p->state);
    p->transport_attached = a->attached;
    p->transport_released = a->released;
    p->xquic_path_live = a->live;
    p->xqc_path_id = a->id ? ORACLE_PRE_ID : 0;
    p->recreate_retries = a->retries;
    p->recreate_after_us = a->retry_armed ? ORACLE_T_RETRY : 0;
    p->path_stable_since_us = a->stable_armed ? ORACLE_T_STABLE : 0;
    p->state_entered_at_us = ORACLE_T_ENTERED;
    p->last_residence_warn_at_us = ORACLE_T_RESIDENCE_WARN;
    if (!a->released) {
        p->ops.struct_size = sizeof(p->ops);
        p->ops.send = oracle_send_stub;
        p->transport_ctx = &oracle_ctx_marker_pre;
    }
}

/* The now of a canonical dispatch. STABLE_TICK takes it relative to the
 * pre-state since (0 when disarmed) so the C predicate's value is the row's
 * class for every pre-state. */
static inline uint64_t
oracle_conc_now(const path_entry_t *pre, int ev, int ctx)
{
    if (ev != OEV_STABLE_TICK) return ORACLE_T_NOW;
    return pre->path_stable_since_us + (ctx == OCTX_REACHED
                                            ? PATH_STABLE_THRESHOLD_US
                                            : PATH_STABLE_THRESHOLD_US - 1);
}

/* ─── The caller's writes that precede a dispatch ─── */

/* Mirrors PathSlotOracle.tla's CallerPrefix: mqvpn_client_add_path installs
 * a transport on a CLOSED_FREE slot before ADD; on_platform_path_released
 * finalises only a CLOSED_DROPPED slot that still owes a release before
 * TRANSPORT_RELEASED. The ctest checks this against the table on every row.
 *
 * The ADD prefix is deliberately not all of add_path's setup. add_path first
 * runs path_entry_init, which zeroes the whole slot (the retry count, the
 * timers and the stamps included) and sets transport_released and
 * CLOSED_FREE, then writes the handle, name, address, net id and flags. The
 * oracle instead starts ADD from every legal CLOSED_FREE slot, a superset of
 * the one path_entry_init leaves, so add_path's slot is covered without
 * modelling those writes: do not add them here. */
static inline int
oracle_prefix_applies(const oracle_slot_t *pre, int ev)
{
    if (ev == OEV_ADD) return pre->state == PATH_LC_CLOSED_FREE;
    if (ev == OEV_TRANSPORT_RELEASED)
        return pre->state == PATH_LC_CLOSED_DROPPED && !pre->released;
    return 0;
}

/* The slot effect of client_copy_path_ops + the ctx store in
 * mqvpn_client_add_path (the caller's ops and ctx: `ops->send` is non-NULL,
 * the rest is the platform's), and of client_finalize_transport. */
static inline void
oracle_prefix_apply(int ev, path_entry_t *p, const mqvpn_path_ops_t *ops, void *ctx)
{
    if (ev == OEV_ADD) {
        p->ops = *ops;
        p->transport_ctx = ctx;
    } else if (ev == OEV_TRANSPORT_RELEASED) {
        memset(&p->ops, 0, sizeof(p->ops));
        p->transport_ctx = NULL;
    }
}

/* The transport the unit test's ADD rows install. */
static inline mqvpn_path_ops_t
oracle_canonical_add_ops(void)
{
    mqvpn_path_ops_t ops;
    memset(&ops, 0, sizeof(ops));
    ops.struct_size = sizeof(ops);
    ops.send = oracle_send_stub;
    return ops;
}

/* The frame: every path_entry_t field the FSM must not write. The others are
 * checked elsewhere — the abstract slot, the update classes, status (against
 * the row in the unit test, through path_invariant_check in both), the
 * state-entry bookkeeping, ops and ctx.
 *
 * 304 is the LP64 size. The pin catches a new field that grows the struct,
 * not one of 4 bytes or less placed in one of its three 4-byte padding holes
 * (LP64: after local_addr_len, after flags and after recreate_retries): such
 * a field keeps the size and must be classified here by hand. */
_Static_assert(sizeof(path_entry_t) == 304,
               "path_entry_t is no longer 304 bytes (its LP64 size) - classify the new "
               "field in formal/oracle/oracle_abs.h");

static inline int
oracle_frame_eq(const path_entry_t *x, const path_entry_t *y)
{
    return x->handle == y->handle && memcmp(x->name, y->name, sizeof(x->name)) == 0 &&
           memcmp(&x->local_addr, &y->local_addr, sizeof(x->local_addr)) == 0 &&
           x->local_addr_len == y->local_addr_len &&
           x->platform_net_id == y->platform_net_id && x->flags == y->flags &&
           x->srtt_ms == y->srtt_ms && x->bytes_tx == y->bytes_tx &&
           x->bytes_rx == y->bytes_rx;
}

/* path_mark_state_entry clears the residence-warn debounce on every state
 * change; nothing else within a dispatch writes it (the client writes it
 * outside the FSM). Valid for a recorded entry (Dom item 9):
 * a first entry (state_entered_at_us == 0) clears it without a change. */
static inline uint64_t
oracle_expected_residence_warn(const path_entry_t *pre, const path_entry_t *post)
{
    return post->state != pre->state ? 0 : pre->last_residence_warn_at_us;
}

static inline int
oracle_ops_eq(const mqvpn_path_ops_t *x, const mqvpn_path_ops_t *y)
{
    return x->struct_size == y->struct_size && x->send == y->send &&
           x->get_stats == y->get_stats && x->release == y->release;
}

/* ─── Dispatch ─── */

static inline path_event_ctx_t
oracle_event_ctx(int ctx, uint64_t now, uint64_t new_id)
{
    path_event_ctx_t e;
    memset(&e, 0, sizeof(e));
    e.now_us = now;
    switch (ctx) {
    case OCTX_OK:
        e.result = ACTIVATE_OK;
        e.new_xqc_path_id = new_id;
        break;
    case OCTX_TRANSIENT: e.result = ACTIVATE_TRANSIENT_FAIL; break;
    case OCTX_PERMANENT: e.result = ACTIVATE_PERMANENT_FAIL; break;
    case OCTX_ACTIVE: e.validated_target = PATH_LC_ACTIVE; break;
    case OCTX_STANDBY: e.validated_target = PATH_LC_STANDBY; break;
    default: break;
    }
    return e;
}

/* One dispatch of ev on p for the client c. c must not be NULL: every
 * production caller passes its client. The FSM never dereferences c, it only
 * hands it to the four accessors, and both checks stub those, so c is
 * opaque here. */
static inline void
oracle_dispatch(mqvpn_client_t *c, path_entry_t *p, int ev, const path_event_ctx_t *e)
{
    static const path_event_t map[OEV_COUNT] = {
        [OEV_ACTIVATE] = PATH_EVENT_ACTIVATE_REQUESTED,
        [OEV_RETRY] = PATH_EVENT_RETRY_TIMER,
        [OEV_VALIDATION_OK] = PATH_EVENT_VALIDATION_OK,
        [OEV_XQUIC_REMOVED] = PATH_EVENT_XQUIC_REMOVED,
        [OEV_MANUAL_REACTIVATE] = PATH_EVENT_MANUAL_REACTIVATE,
        [OEV_PLATFORM_DROP] = PATH_EVENT_PLATFORM_DROP,
        [OEV_REMOVE_API] = PATH_EVENT_REMOVE_API,
        [OEV_ADD] = PATH_EVENT_ADD,
        [OEV_CONN_RESET] = PATH_EVENT_CONN_RESET,
        [OEV_TRANSPORT_RELEASED] = PATH_EVENT_TRANSPORT_RELEASED,
    };
    if (ev == OEV_STABLE_TICK)
        path_fsm_tick_confirm_stable(c, p, e->now_us);
    else
        path_on_event(c, p, map[ev], e);
}

/* ─── Update classes ─── */

static inline int
oracle_retry_class(const path_entry_t *pre, const path_entry_t *post, uint64_t now)
{
    if (post->recreate_after_us == pre->recreate_after_us) return UPD_KEEP;
    if (post->recreate_after_us == 0) return UPD_ZERO;
    if (post->recreate_after_us == now + path_recreate_backoff(post->recreate_retries))
        return UPD_ARM;
    return UPD_OTHER;
}

static inline int
oracle_stable_class(const path_entry_t *pre, const path_entry_t *post, uint64_t now)
{
    if (post->path_stable_since_us == pre->path_stable_since_us) return UPD_KEEP;
    if (post->path_stable_since_us == 0) return UPD_ZERO;
    if (post->path_stable_since_us == now) return UPD_NOW;
    return UPD_OTHER;
}

static inline int
oracle_retries_class(const path_entry_t *pre, const path_entry_t *post)
{
    if (post->recreate_retries == pre->recreate_retries) return UPD_KEEP;
    if (post->recreate_retries == 0) return UPD_ZERO;
    if (post->recreate_retries == pre->recreate_retries + 1) return UPD_INC;
    return UPD_OTHER;
}

/* Dom item 8: no accidental coincidence between now, now + backoff(r) and
 * the pre-state timer values, so a class read off the values is the class
 * of the operation. The backoff is constant from r = 5 on, so r up to
 * PATH_RECREATE_MAX_RETRIES + 2 covers every value it can take. */
_Static_assert(PATH_RECREATE_MAX_RETRIES + 2 >= 5,
               "oracle_no_collision must reach the constant tail of the backoff");

static inline int
oracle_no_collision(const path_entry_t *pre, uint64_t now)
{
    if (now == pre->recreate_after_us || now == pre->path_stable_since_us) return 0;
    for (int r = 0; r <= PATH_RECREATE_MAX_RETRIES + 2; r++)
        if (now + path_recreate_backoff(r) == pre->recreate_after_us) return 0;
    return 1;
}

#endif /* MQVPN_FORMAL_ORACLE_ABS_H */
