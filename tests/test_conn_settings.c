/*
 * test_conn_settings.c — pins mqvpn_build_conn_settings() shape.
 *
 * Two responsibilities, both essential to gap #d:
 *
 *   (1) Diff tests (commit 1 only, deleted in the follow-up commit)
 *       memcmp the v0 hoist of each pre-extraction inline block against
 *       the new helper to prove byte-identical behaviour. Why memcmp is
 *       safe within one process: xqc_*_cb globals are EXTERN const,
 *       linked once from libxquic, so struct copies are bit-equal;
 *       memset(0) + sequential assignment leaves padding deterministic.
 *
 *   (2) Propagation / asymmetry tests
 *       Pin the caller-facing contract: scheduler & init_max_path_id
 *       propagate; the four asymmetric fields (ping_on, enable_multipath,
 *       mp_ping_on, max_path_id_grant_max_value) take the documented
 *       per-side values. These survive the commit-2 v0 deletion.
 */

#include "libmqvpn.h"
#include "mqvpn_conn_settings.h"
#include "mqvpn_internal.h"
#include "mqvpn_scheduler.h"

#include <stdio.h>
#include <string.h>

#include <xquic/xquic.h>

/* Forward decls of the v0 hoists. Bodies live next to the original
 * inline blocks (src/mqvpn_client.c / src/mqvpn_server.c) so a future
 * grep for "v0" lands at the production code being preserved. */
void mqvpn_build_conn_settings_v0_client(const mqvpn_config_t *cfg,
                                         xqc_conn_settings_t *cs);
void mqvpn_build_conn_settings_v0_server(const mqvpn_config_t *cfg,
                                         xqc_conn_settings_t *cs);

#define FAIL(fmt, ...)                                                               \
    do {                                                                             \
        fprintf(stderr, "FAIL %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
        return 1;                                                                    \
    } while (0)

#define ASSERT_EQ(a, b)                                                              \
    do {                                                                             \
        if ((a) != (b))                                                              \
            FAIL("%s != %s (%lld != %lld)", #a, #b, (long long)(a), (long long)(b)); \
    } while (0)

/* ─── Diff tests (commit 1 only) ─────────────────────────────────────── */

static int
diff_case(const char *name, const mqvpn_config_t *cfg,
          const mqvpn_conn_settings_input_t *in,
          void (*v0)(const mqvpn_config_t *, xqc_conn_settings_t *))
{
    xqc_conn_settings_t old_cs, new_cs;
    v0(cfg, &old_cs);
    mqvpn_build_conn_settings(in, &new_cs);
    if (memcmp(&old_cs, &new_cs, sizeof(old_cs)) != 0) {
        FAIL("%s: v0 vs new diverged", name);
    }
    return 0;
}

static int
test_diff_server_default(void)
{
    mqvpn_config_t cfg = {0};
    cfg.scheduler = MQVPN_SCHED_WLB;
    cfg.init_max_path_id = 0;
    mqvpn_conn_settings_input_t in = {
        .is_server = true,
        .enable_multipath = true,
        .scheduler = MQVPN_SCHED_WLB,
        .init_max_path_id = 0,
    };
    return diff_case("server_default", &cfg, &in, mqvpn_build_conn_settings_v0_server);
}

static int
test_diff_client_mp_on_default(void)
{
    mqvpn_config_t cfg = {0};
    cfg.multipath = 1;
    cfg.scheduler = MQVPN_SCHED_WLB;
    cfg.init_max_path_id = 0;
    mqvpn_conn_settings_input_t in = {
        .is_server = false,
        .enable_multipath = true,
        .scheduler = MQVPN_SCHED_WLB,
        .init_max_path_id = 0,
    };
    return diff_case("client_mp_on_default", &cfg, &in,
                     mqvpn_build_conn_settings_v0_client);
}

static int
test_diff_client_mp_off_backup_fec(void)
{
    mqvpn_config_t cfg = {0};
    cfg.multipath = 0;
    cfg.scheduler = MQVPN_SCHED_BACKUP_FEC;
    cfg.init_max_path_id = 0;
    mqvpn_conn_settings_input_t in = {
        .is_server = false,
        .enable_multipath = false,
        .scheduler = MQVPN_SCHED_BACKUP_FEC,
        .init_max_path_id = 0,
    };
    return diff_case("client_mp_off_backup_fec", &cfg, &in,
                     mqvpn_build_conn_settings_v0_client);
}

/* ─── Propagation / asymmetry tests (survive commit 2) ───────────────── */

static int
test_asymmetry_server_vs_client(void)
{
    xqc_conn_settings_t srv, cli_mp_on, cli_mp_off;

    mqvpn_conn_settings_input_t s = {
        .is_server = true,
        .enable_multipath = true,
        .scheduler = MQVPN_SCHED_WLB,
        .init_max_path_id = 0,
    };
    mqvpn_build_conn_settings(&s, &srv);

    mqvpn_conn_settings_input_t c_on = {
        .is_server = false,
        .enable_multipath = true,
        .scheduler = MQVPN_SCHED_WLB,
        .init_max_path_id = 0,
    };
    mqvpn_build_conn_settings(&c_on, &cli_mp_on);

    mqvpn_conn_settings_input_t c_off = c_on;
    c_off.enable_multipath = false;
    mqvpn_build_conn_settings(&c_off, &cli_mp_off);

    /* Server side: MP always on, grant capped at 64, ping_on absent. */
    ASSERT_EQ(srv.enable_multipath, 1);
    ASSERT_EQ(srv.mp_ping_on, 1);
    ASSERT_EQ(srv.max_path_id_grant_max_value, 64);
    ASSERT_EQ(srv.ping_on, 0);

    /* Client side mp-on: MP gated, ping_on set, no grant cap. */
    ASSERT_EQ(cli_mp_on.enable_multipath, 1);
    ASSERT_EQ(cli_mp_on.mp_ping_on, 1);
    ASSERT_EQ(cli_mp_on.ping_on, 1);
    ASSERT_EQ(cli_mp_on.max_path_id_grant_max_value, 0);

    /* Client side mp-off: MP off, mp_ping_on follows. */
    ASSERT_EQ(cli_mp_off.enable_multipath, 0);
    ASSERT_EQ(cli_mp_off.mp_ping_on, 0);
    ASSERT_EQ(cli_mp_off.ping_on, 1);
    return 0;
}

static int
test_propagation_scheduler(void)
{
    xqc_conn_settings_t cs;
    mqvpn_conn_settings_input_t in = {
        .is_server = false,
        .enable_multipath = true,
        .scheduler = MQVPN_SCHED_MINRTT,
        .init_max_path_id = 0,
    };

    in.scheduler = MQVPN_SCHED_MINRTT;
    mqvpn_build_conn_settings(&in, &cs);
    if (memcmp(&cs.scheduler_callback, &xqc_minrtt_scheduler_cb,
               sizeof(xqc_minrtt_scheduler_cb)) != 0) {
        FAIL("scheduler MINRTT did not propagate");
    }

    in.scheduler = MQVPN_SCHED_WLB;
    mqvpn_build_conn_settings(&in, &cs);
    if (memcmp(&cs.scheduler_callback, &xqc_wlb_scheduler_cb,
               sizeof(xqc_wlb_scheduler_cb)) != 0) {
        FAIL("scheduler WLB did not propagate");
    }
    return 0;
}

static int
test_propagation_init_max_path_id(void)
{
    xqc_conn_settings_t cs;
    mqvpn_conn_settings_input_t in = {
        .is_server = true,
        .enable_multipath = true,
        .scheduler = MQVPN_SCHED_WLB,
        .init_max_path_id = 0,
    };

    /* 0 -> field stays 0 (xquic default applies inside xqc_server_set_conn_settings) */
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_EQ(cs.init_max_path_id, 0);

    in.init_max_path_id = 16;
    mqvpn_build_conn_settings(&in, &cs);
    ASSERT_EQ(cs.init_max_path_id, 16);
    return 0;
}

int
main(void)
{
    int failed = 0;
    failed += test_diff_server_default();
    failed += test_diff_client_mp_on_default();
    failed += test_diff_client_mp_off_backup_fec();
    failed += test_asymmetry_server_vs_client();
    failed += test_propagation_scheduler();
    failed += test_propagation_init_max_path_id();
    if (failed) {
        fprintf(stderr, "test_conn_settings: %d FAILED\n", failed);
        return 1;
    }
    fprintf(stderr, "test_conn_settings: PASS\n");
    return 0;
}
