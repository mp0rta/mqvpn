// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* tests/test_path_slot_mbt.c — replays the traces that formal/mbt/gen_traces.py
 * generates from the path-slot model (formal/mbt/path_slot_traces.inc)
 * against the client glue: a private copy of src/mqvpn_client.c compiled
 * against the scripted fake xquic (tests/mbt_client_tu.c, tests/fake_xquic.c).
 * After every step it compares the client's abstract slot, connection stage,
 * readiness and hold, public status, transport bookkeeping, xquic commands
 * and a few callback rules with the model's expected post-state. */
#undef NDEBUG
#include <assert.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <xquic/xqc_errno.h>

#include "fake_transport.h"
#include "fake_xquic.h"
#include "mbt_client_tu.h"
#include "oracle_abs.h" /* path_entry_t, oracle_abs_common, oracle_conc */

#include "mbt_trace.h"
#include "path_slot_traces.inc"

_Static_assert(MBT_GEN_MAX_RETRIES == PATH_RECREATE_MAX_RETRIES,
               "traces generated for a different PATH_RECREATE_MAX_RETRIES - set "
               "MaxRetries in formal/mbt/MqvpnPathSlotMbt.cfg, then rerun "
               "formal/run_tlc.sh mbt");
/* (int) casts: newer clang rejects comparing different enum types (-Wenum-compare). */
_Static_assert((int)MBT_ST_PENDING == (int)PATH_LC_PENDING &&
                   (int)MBT_ST_CREATE_WAIT == (int)PATH_LC_CREATE_WAIT &&
                   (int)MBT_ST_VALIDATING == (int)PATH_LC_VALIDATING &&
                   (int)MBT_ST_ACTIVE == (int)PATH_LC_ACTIVE &&
                   (int)MBT_ST_STANDBY == (int)PATH_LC_STANDBY &&
                   (int)MBT_ST_DEGRADED == (int)PATH_LC_DEGRADED &&
                   (int)MBT_ST_CLOSED_RECOVERABLE == (int)PATH_LC_CLOSED_RECOVERABLE &&
                   (int)MBT_ST_CLOSED_DROPPED == (int)PATH_LC_CLOSED_DROPPED &&
                   (int)MBT_ST_CLOSED_FREE == (int)PATH_LC_CLOSED_FREE,
               "mbt_state_t drifted from path_lifecycle_t");
_Static_assert((int)MBT_STATUS_PENDING == (int)MQVPN_PATH_PENDING &&
                   (int)MBT_STATUS_ACTIVE == (int)MQVPN_PATH_ACTIVE &&
                   (int)MBT_STATUS_DEGRADED == (int)MQVPN_PATH_DEGRADED &&
                   (int)MBT_STATUS_STANDBY == (int)MQVPN_PATH_STANDBY &&
                   (int)MBT_STATUS_CLOSED == (int)MQVPN_PATH_CLOSED,
               "mbt_status_t drifted from mqvpn_path_status_t");

#define SEC           1000000ULL
#define T0            (1000ULL * SEC) /* nonzero, like Dom item 9 */
#define RECONNECT_ADV (61ULL * SEC)   /* > RECONNECT_BACKOFF_MAX_SEC */
#define ABORT_EXIT    86

/* path_recreate_backoff by the retry count after the failure that armed the
 * timer; pinned here, never read from the implementation. */
static const uint64_t BACKOFF_US[PATH_RECREATE_MAX_RETRIES] = {
    0, 5 * SEC, 10 * SEC, 20 * SEC, 40 * SEC, 60 * SEC};

static const char *const OP_NAME[] = {"CONNECT",
                                      "MP_READY",
                                      "TUNNEL_READY",
                                      "ESTABLISH",
                                      "PEER_CLOSE",
                                      "DISCONNECT",
                                      "RECONNECT_TICK",
                                      "RECONNECT_API",
                                      "RETRY_FIRE",
                                      "POLL",
                                      "STABLE",
                                      "REACTIVATE",
                                      "XQC_VALIDATE",
                                      "XQC_LOSE",
                                      "DELIVER_REMOVAL",
                                      "ADD",
                                      "DROP",
                                      "REMOVE",
                                      "DELIVER_RELEASE",
                                      "DESTROY",
                                      "PROBE_TICK",
                                      "PROBE_POLL_ID",
                                      "PROBE_REACTIVATE",
                                      "PROBE_REMOVAL_ID",
                                      "PROBE_TICK_AFTER_DISCONNECT"};
_Static_assert(sizeof(OP_NAME) / sizeof(OP_NAME[0]) ==
                   MBT_PROBE_TICK_AFTER_DISCONNECT + 1,
               "OP_NAME misses an mbt_op_t");

/* ─── Clock and callback recorder ─── */

static uint64_t g_now;
static mqvpn_client_t *g_c;
static mqvpn_path_handle_t g_cur_handle;

static struct {
    unsigned path_events;
    mqvpn_path_handle_t ev_handle;
    int ev_status;
    unsigned tunnel_ready;
    /* snapshot taken inside tunnel_config_ready */
    int snap_state, snap_status, snap_hold;
    unsigned snap_create_path;
} rec;

#define LOG_RING 8
static char g_log[LOG_RING][256];
static unsigned g_nlog;

static uint64_t
test_clock(void *ctx)
{
    (void)ctx;
    return g_now;
}

static void
on_tun_output(const uint8_t *pkt, size_t len, void *ctx)
{
    (void)pkt;
    (void)len;
    (void)ctx;
}

static int
public_status(const mqvpn_client_t *c, mqvpn_path_handle_t h)
{
    mqvpn_path_info_t info[MQVPN_MAX_PATHS];
    int n = 0;
    if (mqvpn_client_get_paths(c, info, MQVPN_MAX_PATHS, &n) != MQVPN_OK) return -1;
    for (int i = 0; i < n; i++)
        if (info[i].handle == h) return (int)info[i].status;
    return -1;
}

static void
on_tunnel_config_ready(const mqvpn_tunnel_info_t *info, void *ctx)
{
    (void)info;
    (void)ctx;
    rec.tunnel_ready++;
    rec.snap_state = (int)mqvpn_client_get_state(g_c);
    rec.snap_status = public_status(g_c, g_cur_handle);
    rec.snap_hold = mbt_hold(g_c);
    rec.snap_create_path = fake_xqc_cmds.create_path;
}

static void
on_path_event(mqvpn_path_handle_t h, mqvpn_path_status_t status, void *ctx)
{
    (void)ctx;
    rec.path_events++;
    rec.ev_handle = h;
    rec.ev_status = (int)status;
}

static void
on_log(mqvpn_log_level_t level, const char *msg, void *ctx)
{
    (void)level;
    (void)ctx;
    snprintf(g_log[g_nlog++ % LOG_RING], sizeof(g_log[0]), "%s", msg);
}

static mqvpn_client_t *
new_client(const mbt_config_t *cfg)
{
    g_now = T0;
    g_nlog = 0;
    fake_xqc_reset(cfg->mp_credit);

    mqvpn_config_t *mc = mqvpn_config_new();
    assert(mc);
    mqvpn_config_set_server(mc, "1.2.3.4", 443);
    mqvpn_config_set_clock(mc, test_clock, NULL);
    mqvpn_config_set_log_level(mc, MQVPN_LOG_DEBUG);
    mqvpn_config_set_multipath(mc, cfg->mp);
    mqvpn_config_set_request_server_scheduler(mc, cfg->req_sched);
    mqvpn_config_set_scheduler(mc, cfg->backup_fec ? MQVPN_SCHED_BACKUP_FEC
                                                   : MQVPN_SCHED_WLB);
    mqvpn_config_set_reconnect(mc, cfg->reconnect, 1);

    mqvpn_client_callbacks_t cbs = MQVPN_CLIENT_CALLBACKS_INIT;
    cbs.tun_output = on_tun_output;
    cbs.tunnel_config_ready = on_tunnel_config_ready;
    cbs.path_event = on_path_event;
    cbs.log = on_log;
    mqvpn_client_t *c = mqvpn_client_new(mc, &cbs, NULL);
    mqvpn_config_free(mc);
    assert(c);
    return c;
}

/* ─── Canary: both private TUs keep their asserts ─── */

static void
on_abort(int sig)
{
    (void)sig;
    _exit(ABORT_EXIT);
}

static int
canary_child(int which)
{
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(2);
    }
    if (pid == 0) {
        signal(SIGABRT, on_abort);
        if (!freopen("/dev/null", "w", stderr)) _exit(3);
        if (which == 0) {
            /* VALIDATING without a transport: illegal for the FSM invariant */
            const oracle_slot_t bad = {
                .state = PATH_LC_VALIDATING, .attached = 0, .live = 1};
            path_entry_t p;
            oracle_conc(&bad, &p);
            path_invariant_check(&p);
        } else {
            const mbt_config_t cfg = {0};
            mqvpn_client_t *c = new_client(&cfg);
            mbt_canary_bad_transition(c); /* IDLE -> ESTABLISHED */
        }
        _exit(0);
    }
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        exit(2);
    }
    return status;
}

static int
check_canary(void)
{
    static const char *const who[] = {"fsm", "client"};
    int bad = 0;
    for (int i = 0; i < 2; i++) {
        int st = canary_child(i);
        if (!(WIFEXITED(st) && WEXITSTATUS(st) == ABORT_EXIT)) {
            fprintf(stderr,
                    "FAIL canary (%s): wait status 0x%x, want exit %d - is "
                    "NDEBUG defined for that TU?\n",
                    who[i], (unsigned)st, ABORT_EXIT);
            bad++;
        }
    }
    if (!bad) printf("canary OK\n");
    return bad;
}

/* ─── Replay ─── */

typedef struct {
    int t, s;
    const mbt_step_t *pre, *st;
    unsigned fails;
} step_ctx_t;

static void
fail(step_ctx_t *x, const char *check, long long got, long long want)
{
    x->fails++;
    fprintf(stderr, "FAIL trace %d step %d (%s): %s got=%lld want=%lld\n", x->t, x->s,
            OP_NAME[x->st->op], check, got, want);
}

#define CHK(x, name, got, want)                                  \
    do {                                                         \
        long long g_ = (long long)(got), w_ = (long long)(want); \
        if (g_ != w_) fail((x), (name), g_, w_);                 \
    } while (0)

static void
print_row(const char *tag, const mbt_step_t *r)
{
    fprintf(stderr,
            "    model %s: state=%d attached=%d live=%d released=%d retries=%d "
            "retry_armed=%d stable_armed=%d xqc_id=%d conn=%d mp_ready=%d hold=%d "
            "ops_set=%d status=%d release_count={%d,%d,%d}\n",
            tag, r->state, r->attached, r->live, r->released, r->retries, r->retry_armed,
            r->stable_armed, r->xqc_id, r->conn, r->mp_ready, r->hold, r->ops_set,
            r->status, r->release_count[0], r->release_count[1], r->release_count[2]);
}

static void
print_log(void)
{
    for (unsigned i = g_nlog > LOG_RING ? g_nlog - LOG_RING : 0; i < g_nlog; i++)
        fprintf(stderr, "    log: %s\n", g_log[i % LOG_RING]);
}

/* An assert in the client or the fake ends the run: name the step first.
 * The default action then runs, so the exit stays abnormal. */
static const step_ctx_t *g_step;

static void
on_parent_abort(int sig)
{
    if (g_step) {
        fprintf(stderr, "ABORT in trace %d step %d (%s)\n", g_step->t, g_step->s,
                OP_NAME[g_step->st->op]);
        print_row("pre", g_step->pre);
        print_row("post", g_step->st);
        print_log();
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

static const path_entry_t *
find_slot(const mqvpn_client_t *c, mqvpn_path_handle_t h)
{
    for (int i = 0; i < mbt_n_paths(c); i++)
        if (mbt_slot(c, i)->handle == h) return mbt_slot(c, i);
    return NULL;
}

static mqvpn_client_state_t
conn_c(uint8_t conn)
{
    static const mqvpn_client_state_t map[] = {
        [MBT_CONN_IDLE] = MQVPN_STATE_IDLE,
        [MBT_CONN_CONNECTING] = MQVPN_STATE_AUTHENTICATING,
        [MBT_CONN_TUNNEL_READY] = MQVPN_STATE_TUNNEL_READY,
        [MBT_CONN_ESTABLISHED] = MQVPN_STATE_ESTABLISHED,
        [MBT_CONN_RECONNECTING] = MQVPN_STATE_RECONNECTING,
        [MBT_CONN_CLOSED] = MQVPN_STATE_CLOSED};
    return map[conn];
}

static void
script_activation(const mbt_step_t *st)
{
    switch (st->result) {
    case MBT_RES_OK: fake_xqc_script_create_path(0, st->arg_id); break;
    case MBT_RES_TRANSIENT: fake_xqc_script_create_path(-1, 0); break;
    case MBT_RES_PERMANENT: fake_xqc_script_create_path(-XQC_EMP_CREATE_PATH, 0); break;
    default: break;
    }
}

/* After a connection start: the handshake completes at once (the C client's
 * CONNECTING does not persist; the model's Connecting is AUTHENTICATING). */
static void
finish_handshake(mqvpn_client_t *c)
{
    if (mqvpn_client_get_state(c) == MQVPN_STATE_CONNECTING)
        fake_xqc_fire_handshake_finished();
}

static int
run_trace(int t)
{
    const mbt_trace_t *tr = &MBT_TRACES[t];
    /* the model's Init slot: never added */
    static const mbt_step_t init = {.state = MBT_ST_CLOSED_FREE,
                                    .released = 1,
                                    .conn = MBT_CONN_IDLE,
                                    .status = MBT_STATUS_CLOSED};
    fake_transport_t transports[MBT_MAX_INC + 1];
    mqvpn_path_handle_t handles[MBT_MAX_INC + 1];
    memset(transports, 0, sizeof(transports));
    memset(handles, 0xff, sizeof(handles));
    int cur_inc = 0, tunnel_seen = 0;
    uint64_t arm_time = 0, stable_anchor = 0;
    unsigned fails = 0;

    mqvpn_client_t *c = new_client(&tr->cfg);
    g_c = c;
    const mbt_step_t *pre = &init;

    for (int s = 0; s < tr->n; s++) {
        const mbt_step_t *st = &MBT_STEPS[tr->first + s];
        step_ctx_t x = {.t = t, .s = s, .pre = pre, .st = st};
        g_step = &x;
        memset(&fake_xqc_cmds, 0, sizeof(fake_xqc_cmds));
        memset(&rec, 0, sizeof(rec));
        g_cur_handle = cur_inc ? handles[cur_inc] : -1;
        int rc;

        switch ((mbt_op_t)st->op) {
        case MBT_OP_CONNECT:
        case MBT_OP_RECONNECT_API:
            if (st->result != MBT_RES_NONE)
                fake_xqc_script_connect(st->result == MBT_RES_OK);
            tunnel_seen = 0;
            rc = mqvpn_client_connect(c);
            CHK(&x, "connect() == MQVPN_OK", rc == MQVPN_OK, st->result == MBT_RES_OK);
            finish_handshake(c);
            break;
        case MBT_OP_RECONNECT_TICK:
            if (st->result != MBT_RES_NONE)
                fake_xqc_script_connect(st->result == MBT_RES_OK);
            tunnel_seen = 0;
            g_now += RECONNECT_ADV;
            mqvpn_client_tick(c);
            finish_handshake(c);
            break;
        case MBT_OP_MP_READY:
            script_activation(st);
            fake_xqc_fire_ready_to_create_path();
            break;
        case MBT_OP_TUNNEL_READY:
            script_activation(st);
            fake_xqc_fire_tunnel_response();
            break;
        case MBT_OP_ESTABLISH:
            CHK(&x, "tunnel_config_ready seen before set_tun_active", tunnel_seen, 1);
            mqvpn_client_set_tun_active(c, 1, -1);
            break;
        case MBT_OP_PEER_CLOSE: fake_xqc_fire_peer_close(); break;
        case MBT_OP_DISCONNECT: mqvpn_client_disconnect(c); break;
        case MBT_OP_RETRY_FIRE: {
            /* an armed timer: 1..5 failures so far */
            assert(pre->retries >= 1 && pre->retries < PATH_RECREATE_MAX_RETRIES);
            const uint64_t deadline = arm_time + BACKOFF_US[pre->retries];
            script_activation(st);
            if (g_now < deadline - 1) {
                g_now = deadline - 1;
                mqvpn_client_tick(c);
                CHK(&x, "commands at deadline - 1us",
                    fake_xqc_cmds.h3_connect + fake_xqc_cmds.create_path +
                        fake_xqc_cmds.close_path + fake_xqc_cmds.conn_close +
                        fake_xqc_cmds.h3_conn_close,
                    0);
            }
            if (g_now < deadline) g_now = deadline;
            mqvpn_client_tick(c);
            break;
        }
        case MBT_OP_POLL: mqvpn_client_tick(c); break;
        case MBT_OP_STABLE:
            if (g_now < stable_anchor + PATH_STABLE_THRESHOLD_US)
                g_now = stable_anchor + PATH_STABLE_THRESHOLD_US;
            mqvpn_client_tick(c);
            break;
        case MBT_OP_REACTIVATE:
            script_activation(st);
            rc = mqvpn_client_reactivate_path(c, handles[st->arg_inc]);
            CHK(&x, "reactivate_path() == MQVPN_OK", rc == MQVPN_OK,
                st->result == MBT_RES_OK);
            break;
        case MBT_OP_XQC_VALIDATE: fake_xqc_set_path_active(pre->xqc_id, 1); break;
        case MBT_OP_XQC_LOSE: fake_xqc_set_path_active(st->arg_id, 0); break;
        case MBT_OP_DELIVER_REMOVAL: fake_xqc_fire_path_removed(st->arg_id); break;
        case MBT_OP_ADD:
            assert(st->arg_inc >= 1 && st->arg_inc <= MBT_MAX_INC);
            fake_transport_init(&transports[st->arg_inc]);
            script_activation(st);
            handles[st->arg_inc] = mqvpn_client_add_path(c, NULL, fake_path_ops(),
                                                         &transports[st->arg_inc], NULL);
            CHK(&x, "add_path() handle >= 0", handles[st->arg_inc] >= 0, 1);
            cur_inc = st->arg_inc;
            g_cur_handle = handles[cur_inc];
            break;
        case MBT_OP_DROP:
        case MBT_OP_REMOVE:
            if (st->result != MBT_RES_NONE)
                fake_xqc_script_close_path(st->result == MBT_RES_OK);
            if (st->op == MBT_OP_DROP)
                mqvpn_client_on_platform_path_dropped(c, handles[st->arg_inc], NULL);
            else
                mqvpn_client_remove_path(c, handles[st->arg_inc]);
            break;
        case MBT_OP_DELIVER_RELEASE:
            mqvpn_client_on_platform_path_released(c, handles[st->arg_inc]);
            break;
        case MBT_OP_DESTROY:
            mqvpn_client_destroy(c);
            c = g_c = NULL;
            break;
        case MBT_PROBE_TICK:
            if (pre->retry_armed) {
                assert(pre->retries >= 1 && pre->retries < PATH_RECREATE_MAX_RETRIES);
                if (g_now < arm_time + BACKOFF_US[pre->retries])
                    g_now = arm_time + BACKOFF_US[pre->retries];
            }
            mqvpn_client_tick(c);
            break;
        case MBT_PROBE_POLL_ID:
            fake_xqc_set_decoy_active_path(st->arg_id);
            fake_xqc_set_path_active(pre->xqc_id, 0);
            mqvpn_client_tick(c);
            break;
        case MBT_PROBE_REACTIVATE:
            rc = mqvpn_client_reactivate_path(c, handles[st->arg_inc]);
            CHK(&x, "reactivate_path() rejected", rc != MQVPN_OK, 1);
            break;
        case MBT_PROBE_REMOVAL_ID: fake_xqc_fire_path_removed(st->arg_id); break;
        case MBT_PROBE_TICK_AFTER_DISCONNECT:
            g_now += RECONNECT_ADV;
            mqvpn_client_tick(c);
            break;
        }
        if (rec.tunnel_ready) tunnel_seen = 1;

        /* ── Checks (§6.5.3) ── */
        const int probe = st->op >= MBT_PROBE_TICK;
        const path_entry_t *p = NULL;
        if (c) {
            p = find_slot(c, handles[cur_inc]);
            if (!p) {
                fail(&x, "slot of the current handle exists", 0, 1);
            } else {
                oracle_slot_t a;
                if (!oracle_abs_common(p, &a)) {
                    fail(&x, "slot inside the abstract domain", 0, 1);
                } else {
                    CHK(&x, "slot.state", a.state, st->state);
                    CHK(&x, "slot.attached", a.attached, st->attached);
                    CHK(&x, "slot.live", a.live, st->live);
                    CHK(&x, "slot.released", a.released, st->released);
                    CHK(&x, "slot.retries", a.retries, st->retries);
                    CHK(&x, "slot.retry_armed", a.retry_armed, st->retry_armed);
                    CHK(&x, "slot.stable_armed", a.stable_armed, st->stable_armed);
                }
                CHK(&x, "slot.xqc_path_id", p->xqc_path_id, st->xqc_id);
                CHK(&x, "public status", public_status(c, p->handle), st->status);
                CHK(&x, "ops installed", p->ops.send != NULL, st->ops_set);
            }
            CHK(&x, "client state", mqvpn_client_get_state(c), conn_c(st->conn));
            CHK(&x, "multipath_ready", mbt_multipath_ready(c), st->mp_ready);
            CHK(&x, "hold_extra_paths", mbt_hold(c), st->hold);
        }
        for (int i = 0; i < MBT_MAX_INC; i++) {
            char name[32];
            snprintf(name, sizeof(name), "release_calls[inc %d]", i + 1);
            CHK(&x, name, transports[i + 1].release_calls, st->release_count[i]);
        }

        CHK(&x, "cmd xqc_h3_connect", fake_xqc_cmds.h3_connect, st->cmd_connect);
        CHK(&x, "cmd xqc_conn_create_path", fake_xqc_cmds.create_path,
            st->cmd_create_path);
        CHK(&x, "cmd xqc_conn_close_path", fake_xqc_cmds.close_path, st->cmd_close_path);
        CHK(&x, "cmd xqc_conn_close", fake_xqc_cmds.conn_close, st->cmd_conn_close);
        CHK(&x, "cmd xqc_h3_conn_close", fake_xqc_cmds.h3_conn_close, 0);
        if (fake_xqc_cmds.create_path == 1 && st->cmd_create_path == 1)
            CHK(&x, "create_path path_status", fake_xqc_cmds.last_path_status,
                tr->cfg.backup_fec ? 1 : 0);
        if (fake_xqc_cmds.close_path == 1 && st->cmd_close_path == 1)
            CHK(&x, "close_path id", fake_xqc_cmds.last_close_path_id, pre->xqc_id);

        if (probe) CHK(&x, "path_event on a probe", rec.path_events, 0);
        if (st->path_event_rule && pre->state != st->state) {
            if (rec.path_events == 0) {
                fail(&x, "path_event delivered", 0, 1);
            } else {
                CHK(&x, "last path_event handle", rec.ev_handle, handles[cur_inc]);
                CHK(&x, "last path_event status", rec.ev_status, st->status);
            }
        }
        if (st->op == MBT_OP_TUNNEL_READY) {
            CHK(&x, "tunnel_config_ready calls", rec.tunnel_ready, 1);
            if (rec.tunnel_ready == 1) {
                CHK(&x, "in tunnel_config_ready: client state", rec.snap_state,
                    MQVPN_STATE_TUNNEL_READY);
                /* the primary's validation is applied, a hold-released
                 * activation (a fused row) is not yet */
                CHK(&x, "in tunnel_config_ready: public status", rec.snap_status,
                    st->result == MBT_RES_NONE ? st->status : pre->status);
                CHK(&x, "in tunnel_config_ready: hold", rec.snap_hold, pre->hold);
                CHK(&x, "in tunnel_config_ready: create_path so far",
                    rec.snap_create_path, 0);
            }
        } else {
            CHK(&x, "tunnel_config_ready calls", rec.tunnel_ready, 0);
        }

        if (x.fails) {
            fprintf(stderr, "    now=%llu arm_time=%llu stable_anchor=%llu\n",
                    (unsigned long long)g_now, (unsigned long long)arm_time,
                    (unsigned long long)stable_anchor);
            if (p)
                fprintf(stderr,
                        "    slot: handle=%lld xqc_path_id=%llu retries=%d "
                        "recreate_after_us=%llu path_stable_since_us=%llu\n",
                        (long long)p->handle, (unsigned long long)p->xqc_path_id,
                        p->recreate_retries, (unsigned long long)p->recreate_after_us,
                        (unsigned long long)p->path_stable_since_us);
            fprintf(stderr, "    path_events=%u last=(handle %lld, status %d)\n",
                    rec.path_events, (long long)rec.ev_handle, rec.ev_status);
            print_row("pre", pre);
            print_row("post", st);
            print_log();
            fails += x.fails;
            break; /* later steps would only cascade */
        }

        /* the timers' anchors: the step that armed or re-armed them */
        if (st->retry_armed && (!pre->retry_armed || st->retries != pre->retries))
            arm_time = g_now;
        if (st->stable_armed && (!pre->stable_armed || st->op == MBT_OP_STABLE))
            stable_anchor = g_now;
        pre = st;
    }

    g_step = NULL;
    if (c) mqvpn_client_destroy(c); /* clean-up, not checked (§6.5.4) */
    g_c = NULL;
    return (int)fails;
}

int
main(void)
{
    if (check_canary()) return 1;
    signal(SIGABRT, on_parent_abort);

    int failed = 0, steps = 0;
    for (int t = 0; t < MBT_N_TRACES; t++) {
        int f = run_trace(t);
        if (f) failed++;
        steps += MBT_TRACES[t].n;
    }
    if (failed) {
        fprintf(stderr, "test_path_slot_mbt: %d of %d traces failed\n", failed,
                MBT_N_TRACES);
        return 1;
    }
    if (steps != MBT_N_STEPS) {
        fprintf(stderr, "test_path_slot_mbt: replayed %d steps, the table has %d\n",
                steps, MBT_N_STEPS);
        return 1;
    }
    printf("%d traces, %d steps OK\n", MBT_N_TRACES, steps);
    return 0;
}
