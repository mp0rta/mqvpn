// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_config_bridge.c — parity test for the shared CLI→library config
 * bridge (mqvpn_platform_apply_client_config, src/platform/
 * client_config_bridge.c).
 *
 * The bridge replaced three per-platform copies of the same setter block.
 * This test pins the forwarding of every common field, so a knob added to
 * mqvpn_client_cfg_t but not to the bridge fails here instead of shipping
 * as a silently-dropped option (the Windows InitMaxPathId regression this
 * refactor descends from). Reaches the built config through
 * mqvpn_internal.h (links src/mqvpn_config.c, so the opaque struct is
 * visible) — same idiom as test_reorder_config.c.
 */
#include "libmqvpn.h"
#include "mqvpn_internal.h"
#include "vpn_client.h"

#include <stdio.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;

#define ASSERT_EQ_INT(a, b, msg)                                              \
    do {                                                                      \
        if ((long long)(a) == (long long)(b)) {                               \
            g_pass++;                                                         \
        } else {                                                              \
            g_fail++;                                                         \
            fprintf(stderr, "FAIL [%s]: %lld != %lld\n", msg, (long long)(a), \
                    (long long)(b));                                          \
        }                                                                     \
    } while (0)

#define ASSERT_EQ_STR(a, b, msg)                                             \
    do {                                                                     \
        if (strcmp((a), (b)) == 0) {                                         \
            g_pass++;                                                        \
        } else {                                                             \
            g_fail++;                                                        \
            fprintf(stderr, "FAIL [%s]: \"%s\" != \"%s\"\n", msg, (a), (b)); \
        }                                                                    \
    } while (0)

/* Every common field set to a distinctive non-default value. */
static void
test_all_fields_forwarded(void)
{
    mqvpn_client_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    mqvpn_reorder_config_default(&cfg.reorder);
    mqvpn_hybrid_config_default(&cfg.hybrid);

    cfg.server_addr = "203.0.113.7";
    cfg.server_port = 4433;
    cfg.tls_server_name = "sni.example";
    cfg.auth_key = "k3y";
    cfg.insecure = 1;
    cfg.n_paths = 2;
    cfg.scheduler = 2; /* BACKUP_FEC */
    cfg.reconnect = 1;
    cfg.reconnect_interval = 7;
    cfg.kill_switch = 1;
    cfg.log_level = (int)MQVPN_LOG_WARN;
    cfg.cc = 1;
    cfg.reinjection = 1;
    cfg.reinj_srtt_factor_pct = 111;
    cfg.reinj_hard_deadline_ms = 502;
    cfg.reinj_deadline_lower_bound_ms = 21;
    cfg.init_max_path_id = 17;
    cfg.tun_mtu = 1400;
    cfg.reorder.max_wait_ms = 33; /* spot-check: apply_reorder ran */
    cfg.hybrid.enabled = 1;       /* spot-check: apply_hybrid ran */
    cfg.hybrid.tcp_max_flows = 77;
    cfg.recv_rate_limit = 123456;
    cfg.udp_gso = 0; /* platform-only knob: must NOT be bridged */

    mqvpn_config_t *lc = mqvpn_config_new();
    if (!lc) {
        g_fail++;
        fprintf(stderr, "FAIL: mqvpn_config_new\n");
        return;
    }
    mqvpn_platform_apply_client_config(lc, &cfg);

    ASSERT_EQ_STR(lc->server_host, "203.0.113.7", "server_host");
    ASSERT_EQ_INT(lc->server_port, 4433, "server_port");
    ASSERT_EQ_STR(lc->tls_server_name, "sni.example", "tls_server_name");
    ASSERT_EQ_STR(lc->auth_key, "k3y", "auth_key");
    ASSERT_EQ_INT(lc->insecure, 1, "insecure");
    ASSERT_EQ_INT(lc->multipath, 1, "multipath (n_paths=2)");
    ASSERT_EQ_INT(lc->reconnect_enable, 1, "reconnect_enable");
    ASSERT_EQ_INT(lc->reconnect_interval_sec, 7, "reconnect_interval_sec");
    ASSERT_EQ_INT(lc->killswitch_hint, 1, "killswitch_hint");
    ASSERT_EQ_INT(lc->log_level, MQVPN_LOG_WARN, "log_level");
    ASSERT_EQ_INT(lc->scheduler, MQVPN_SCHED_BACKUP_FEC, "scheduler map 2");
    ASSERT_EQ_INT(lc->cc, 1, "cc");
    ASSERT_EQ_INT(lc->reinjection, 1, "reinjection");
    ASSERT_EQ_INT(lc->reinj_srtt_factor_pct, 111, "reinj_srtt_factor_pct");
    ASSERT_EQ_INT(lc->reinj_hard_deadline_ms, 502, "reinj_hard_deadline_ms");
    ASSERT_EQ_INT(lc->reinj_deadline_lower_bound_ms, 21, "reinj_deadline_lower_bound_ms");
    ASSERT_EQ_INT(lc->init_max_path_id, 17, "init_max_path_id");
    ASSERT_EQ_INT(lc->tun_mtu, 1400, "tun_mtu");
    ASSERT_EQ_INT(lc->reorder.mode, cfg.reorder.mode, "reorder.mode bridged");
    ASSERT_EQ_INT(lc->reorder.max_wait_ms, 33, "reorder.max_wait_ms bridged");
    ASSERT_EQ_INT(lc->hybrid.enabled, 1, "hybrid.enabled bridged");
    ASSERT_EQ_INT(lc->hybrid.tcp_max_flows, 77, "hybrid.tcp_max_flows bridged");
    ASSERT_EQ_INT(lc->recv_rate_limit, 123456, "recv_rate_limit");
    /* udp_gso stays at the library default (1) — the bridge must not touch
     * it even though cfg.udp_gso is 0 (Linux-only knob, set at call site). */
    ASSERT_EQ_INT(lc->udp_gso, 1, "udp_gso NOT bridged");

    mqvpn_config_free(lc);
}

/* Default/edge mappings: single path, interval fallback, NULL strings,
 * scheduler fallback, recv_rate_limit=0 left untouched. */
static void
test_defaults_and_fallbacks(void)
{
    mqvpn_client_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    mqvpn_reorder_config_default(&cfg.reorder);
    mqvpn_hybrid_config_default(&cfg.hybrid);

    cfg.server_addr = "198.51.100.9";
    cfg.server_port = 443;
    cfg.n_paths = 1;    /* → multipath 0 */
    cfg.scheduler = 99; /* unknown → MINRTT fallback */
    cfg.reconnect = 1;
    cfg.reconnect_interval = 0; /* → default 5 */

    mqvpn_config_t *lc = mqvpn_config_new();
    if (!lc) {
        g_fail++;
        fprintf(stderr, "FAIL: mqvpn_config_new\n");
        return;
    }
    uint64_t rrl_default = lc->recv_rate_limit;
    mqvpn_platform_apply_client_config(lc, &cfg);

    ASSERT_EQ_INT(lc->multipath, 0, "multipath (n_paths=1)");
    ASSERT_EQ_INT(lc->scheduler, MQVPN_SCHED_MINRTT, "scheduler fallback");
    ASSERT_EQ_INT(lc->reconnect_interval_sec, 5, "reconnect interval default 5");
    ASSERT_EQ_INT(lc->tls_server_name[0], '\0', "tls_server_name NULL → unset");
    ASSERT_EQ_INT(lc->auth_key[0], '\0', "auth_key NULL → unset");
    ASSERT_EQ_INT(lc->recv_rate_limit, rrl_default, "recv_rate_limit 0 → untouched");

    /* remaining scheduler codepoints */
    cfg.scheduler = 1;
    mqvpn_platform_apply_client_config(lc, &cfg);
    ASSERT_EQ_INT(lc->scheduler, MQVPN_SCHED_WLB, "scheduler map 1");
    cfg.scheduler = 3;
    mqvpn_platform_apply_client_config(lc, &cfg);
    ASSERT_EQ_INT(lc->scheduler, MQVPN_SCHED_WLB_UDP_PIN, "scheduler map 3");
    cfg.scheduler = 0;
    mqvpn_platform_apply_client_config(lc, &cfg);
    ASSERT_EQ_INT(lc->scheduler, MQVPN_SCHED_MINRTT, "scheduler map 0");

    mqvpn_config_free(lc);
}

int
main(void)
{
    test_all_fields_forwarded();
    test_defaults_and_fallbacks();
    printf("test_config_bridge: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
