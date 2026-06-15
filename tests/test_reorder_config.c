// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_reorder_config.c — unit tests for the reorder config surfaces
 * (design spec v2.5 §16.1 / §16.2):
 *
 *   - Task 4.1: public builder API setters (mqvpn_config_set_reorder_*),
 *     each writing the right field of the embedded mqvpn_reorder_config_t,
 *     with the result still passing mqvpn_reorder_config_validate().
 *   - Task 4.2: INI [Reorder] / repeated [ReorderRule] parsing into the
 *     file-config struct, including the Enabled off/on/true/auto mapping
 *     (auto → ON with a LOG_WRN, per the §16 scope decision) and the
 *     unknown-key-warns-but-does-not-fail forward-compat rule.
 *
 * Builder-side tests reach the embedded config through mqvpn_internal.h
 * (the test links src/mqvpn_config.c, so the opaque struct is visible).
 * INI-side tests read the file-config struct's embedded reorder config.
 */
#include "config.h"
#include "libmqvpn.h"
#include "mqvpn_internal.h"
#include "reorder.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

#define ASSERT_TRUE(cond, msg)                   \
    do {                                         \
        if (cond) {                              \
            g_pass++;                            \
        } else {                                 \
            g_fail++;                            \
            fprintf(stderr, "FAIL [%s]\n", msg); \
        }                                        \
    } while (0)

/* ──────────────────────── Task 4.1: builder setters ───────────────────────── */

static void
test_builder_default_embedded(void)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    ASSERT_TRUE(cfg != NULL, "config_new");
    if (!cfg) return;

    /* mqvpn_config_new must seed the embedded reorder config with defaults. */
    ASSERT_EQ_INT(cfg->reorder.mode, MQVPN_REORDER_OFF, "default mode OFF");
    ASSERT_EQ_INT(cfg->reorder.max_wait_ms, 30, "default max_wait_ms");
    ASSERT_EQ_INT(cfg->reorder.cap_packets_per_flow, 1024, "default cap");
    ASSERT_EQ_INT(cfg->reorder.n_rules, 0, "default n_rules");
    ASSERT_EQ_INT(mqvpn_reorder_config_validate(&cfg->reorder), 0, "default valid");

    mqvpn_config_free(cfg);
}

static void
test_builder_set_enabled(void)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    if (!cfg) return;

    ASSERT_EQ_INT(mqvpn_config_set_reorder_enabled(cfg, MQVPN_REORDER_ON), MQVPN_OK,
                  "set_enabled ON rc");
    ASSERT_EQ_INT(cfg->reorder.mode, MQVPN_REORDER_ON, "mode ON");

    ASSERT_EQ_INT(mqvpn_config_set_reorder_enabled(cfg, MQVPN_REORDER_OFF), MQVPN_OK,
                  "set_enabled OFF rc");
    ASSERT_EQ_INT(cfg->reorder.mode, MQVPN_REORDER_OFF, "mode OFF");

    /* NULL cfg is rejected. */
    ASSERT_EQ_INT(mqvpn_config_set_reorder_enabled(NULL, MQVPN_REORDER_ON),
                  MQVPN_ERR_INVALID_ARG, "set_enabled NULL");

    ASSERT_EQ_INT(mqvpn_reorder_config_validate(&cfg->reorder), 0, "valid after enabled");
    mqvpn_config_free(cfg);
}

static void
test_builder_set_wait(void)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    if (!cfg) return;

    ASSERT_EQ_INT(mqvpn_config_set_reorder_wait(cfg, 50), MQVPN_OK, "set_wait rc");
    ASSERT_EQ_INT(cfg->reorder.max_wait_ms, 50, "max_wait_ms");
    ASSERT_EQ_INT(mqvpn_reorder_config_validate(&cfg->reorder), 0, "valid after wait");
    mqvpn_config_free(cfg);
}

static void
test_builder_set_cap(void)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    if (!cfg) return;

    ASSERT_EQ_INT(mqvpn_config_set_reorder_cap(cfg, 2048, 3145728ULL), MQVPN_OK,
                  "set_cap rc");
    ASSERT_EQ_INT(cfg->reorder.cap_packets_per_flow, 2048, "cap_packets");
    ASSERT_TRUE(cfg->reorder.max_buffer_bytes_per_flow == 3145728ULL,
                "max_bytes_per_flow");
    ASSERT_EQ_INT(mqvpn_reorder_config_validate(&cfg->reorder), 0,
                  "valid after cap (pow2)");
    mqvpn_config_free(cfg);
}

static void
test_builder_set_classify(void)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    if (!cfg) return;

    ASSERT_EQ_INT(mqvpn_config_set_reorder_classify(cfg, 128, 5, 250), MQVPN_OK,
                  "set_classify rc");
    ASSERT_EQ_INT(cfg->reorder.classify_window, 128, "classify_window");
    ASSERT_EQ_INT(cfg->reorder.ack_demote_max_large_packets, 5, "max_large");
    ASSERT_EQ_INT(cfg->reorder.small_packet_threshold_bytes, 250, "small_threshold");
    ASSERT_EQ_INT(mqvpn_reorder_config_validate(&cfg->reorder), 0,
                  "valid after classify");
    mqvpn_config_free(cfg);
}

static void
test_builder_set_reset(void)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    if (!cfg) return;

    ASSERT_EQ_INT(mqvpn_config_set_reorder_reset(cfg, 4, 8000), MQVPN_OK, "set_reset rc");
    ASSERT_EQ_INT(cfg->reorder.reset_mark_packets, 4, "reset_mark_packets");
    ASSERT_EQ_INT(cfg->reorder.reset_idle_grace_ms, 8000, "reset_idle_grace_ms");
    ASSERT_EQ_INT(mqvpn_reorder_config_validate(&cfg->reorder), 0, "valid after reset");
    mqvpn_config_free(cfg);
}

static void
test_builder_set_limits(void)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    if (!cfg) return;

    ASSERT_EQ_INT(mqvpn_config_set_reorder_limits(cfg, 32768, 134217728ULL, 20, 200),
                  MQVPN_OK, "set_limits rc");
    ASSERT_EQ_INT(cfg->reorder.max_flows, 32768, "max_flows");
    ASSERT_TRUE(cfg->reorder.global_max_buffer_bytes == 134217728ULL, "global_max_bytes");
    ASSERT_EQ_INT(cfg->reorder.ingress_idle_timeout_sec, 20, "ingress_idle");
    ASSERT_EQ_INT(cfg->reorder.egress_idle_timeout_sec, 200, "egress_idle");
    /* ingress (20) < egress (200) → validate passes. */
    ASSERT_EQ_INT(mqvpn_reorder_config_validate(&cfg->reorder), 0, "valid after limits");
    mqvpn_config_free(cfg);
}

static void
test_builder_add_rule(void)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    if (!cfg) return;

    ASSERT_EQ_INT(mqvpn_config_add_reorder_rule(cfg, 17, 443, MQVPN_RPROF_QUIC_BULK),
                  MQVPN_OK, "add_rule 0 rc");
    ASSERT_EQ_INT(mqvpn_config_add_reorder_rule(cfg, 17, 53, MQVPN_RPROF_LOW_LATENCY),
                  MQVPN_OK, "add_rule 1 rc");
    ASSERT_EQ_INT(cfg->reorder.n_rules, 2, "n_rules == 2");
    ASSERT_EQ_INT(cfg->reorder.rules[0].port, 443, "rule0 port");
    ASSERT_EQ_INT(cfg->reorder.rules[0].profile, MQVPN_RPROF_QUIC_BULK, "rule0 profile");
    ASSERT_EQ_INT(cfg->reorder.rules[1].port, 53, "rule1 port");
    ASSERT_EQ_INT(cfg->reorder.rules[1].profile, MQVPN_RPROF_LOW_LATENCY,
                  "rule1 profile");
    ASSERT_EQ_INT(cfg->reorder.rules[0].proto, 17, "rule0 proto");

    mqvpn_config_free(cfg);
}

static void
test_builder_add_rule_overflow(void)
{
    mqvpn_config_t *cfg = mqvpn_config_new();
    if (!cfg) return;

    int i;
    for (i = 0; i < MQVPN_REORDER_MAX_RULES; i++) {
        ASSERT_EQ_INT(mqvpn_config_add_reorder_rule(cfg, 17, (uint16_t)(1000 + i),
                                                    MQVPN_RPROF_QUIC_BULK),
                      MQVPN_OK, "add_rule fill");
    }
    ASSERT_EQ_INT(cfg->reorder.n_rules, MQVPN_REORDER_MAX_RULES, "n_rules at cap");

    /* One past the cap must be rejected and must not grow n_rules. */
    ASSERT_EQ_INT(mqvpn_config_add_reorder_rule(cfg, 17, 9999, MQVPN_RPROF_QUIC_BULK),
                  MQVPN_ERR_INVALID_ARG, "add_rule over cap rejected");
    ASSERT_EQ_INT(cfg->reorder.n_rules, MQVPN_REORDER_MAX_RULES, "n_rules unchanged");

    mqvpn_config_free(cfg);
}

/* ──────────────────────── Task 4.2: INI parsing ───────────────────────────── */

static char *
write_tmp(const char *content)
{
    static char path[256];
    snprintf(path, sizeof(path), "/tmp/test_reorder_cfg_XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0) {
        perror("mkstemp");
        return NULL;
    }
    ssize_t n = write(fd, content, strlen(content));
    (void)n;
    close(fd);
    return path;
}

static void
test_ini_defaults_no_section(void)
{
    /* No [Reorder] section → reorder stays at defaults (mode OFF). */
    const char *ini = "[Server]\nAddress = host:443\n";
    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    if (path) unlink(path);

    ASSERT_EQ_INT(rc, 0, "parse ok");
    ASSERT_EQ_INT(cfg.reorder.mode, MQVPN_REORDER_OFF, "no section → OFF");
    ASSERT_EQ_INT(cfg.reorder.max_wait_ms, 30, "no section → default wait");
    ASSERT_EQ_INT(cfg.reorder.n_rules, 0, "no section → no rules");
}

static void
test_ini_reorder_full(void)
{
    const char *ini = "[Reorder]\n"
                      "Enabled = on\n"
                      "MaxWaitMs = 40\n"
                      "CapPackets = 2048\n"
                      "MaxBytesPerFlow = 3145728\n"
                      "ClassifyWindow = 96\n"
                      "AckDemoteMaxLarge = 4\n"
                      "SmallPacketThreshold = 220\n"
                      "ResetMarkPackets = 6\n"
                      "ResetIdleGraceMs = 9000\n"
                      "MaxFlows = 32768\n"
                      "GlobalMaxBytes = 134217728\n"
                      "IngressIdleSec = 25\n"
                      "EgressIdleSec = 250\n";
    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    if (path) unlink(path);

    ASSERT_EQ_INT(rc, 0, "parse ok");
    ASSERT_EQ_INT(cfg.reorder.mode, MQVPN_REORDER_ON, "Enabled=on → ON");
    ASSERT_EQ_INT(cfg.reorder.max_wait_ms, 40, "MaxWaitMs");
    ASSERT_EQ_INT(cfg.reorder.cap_packets_per_flow, 2048, "CapPackets");
    ASSERT_TRUE(cfg.reorder.max_buffer_bytes_per_flow == 3145728ULL, "MaxBytesPerFlow");
    ASSERT_EQ_INT(cfg.reorder.classify_window, 96, "ClassifyWindow");
    ASSERT_EQ_INT(cfg.reorder.ack_demote_max_large_packets, 4, "AckDemoteMaxLarge");
    ASSERT_EQ_INT(cfg.reorder.small_packet_threshold_bytes, 220, "SmallPacketThreshold");
    ASSERT_EQ_INT(cfg.reorder.reset_mark_packets, 6, "ResetMarkPackets");
    ASSERT_EQ_INT(cfg.reorder.reset_idle_grace_ms, 9000, "ResetIdleGraceMs");
    ASSERT_EQ_INT(cfg.reorder.max_flows, 32768, "MaxFlows");
    ASSERT_TRUE(cfg.reorder.global_max_buffer_bytes == 134217728ULL, "GlobalMaxBytes");
    ASSERT_EQ_INT(cfg.reorder.ingress_idle_timeout_sec, 25, "IngressIdleSec");
    ASSERT_EQ_INT(cfg.reorder.egress_idle_timeout_sec, 250, "EgressIdleSec");
    ASSERT_EQ_INT(mqvpn_reorder_config_validate(&cfg.reorder), 0, "parsed config valid");
}

static void
test_ini_enabled_mapping(void)
{
    struct {
        const char *val;
        mqvpn_reorder_mode_t want;
    } cases[] = {
        {"off", MQVPN_REORDER_OFF}, {"false", MQVPN_REORDER_OFF},
        {"on", MQVPN_REORDER_ON},   {"true", MQVPN_REORDER_ON},
        {"auto", MQVPN_REORDER_ON}, /* §16 scope: auto → ON + LOG_WRN */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char ini[64];
        snprintf(ini, sizeof(ini), "[Reorder]\nEnabled = %s\n", cases[i].val);
        char *path = write_tmp(ini);
        mqvpn_file_config_t cfg;
        mqvpn_config_defaults(&cfg);
        int rc = mqvpn_config_load(&cfg, path);
        if (path) unlink(path);
        ASSERT_EQ_INT(rc, 0, "parse ok");
        ASSERT_EQ_INT(cfg.reorder.mode, cases[i].want, cases[i].val);
    }
}

static void
test_ini_reorder_rules(void)
{
    const char *ini = "[Reorder]\n"
                      "Enabled = on\n"
                      "[ReorderRule]\n"
                      "Proto = udp\n"
                      "Port = 443\n"
                      "Profile = quic_bulk\n"
                      "[ReorderRule]\n"
                      "Proto = udp\n"
                      "Port = 53\n"
                      "Profile = low_latency\n";
    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    if (path) unlink(path);

    ASSERT_EQ_INT(rc, 0, "parse ok");
    ASSERT_EQ_INT(cfg.reorder.n_rules, 2, "two rules in order");
    ASSERT_EQ_INT(cfg.reorder.rules[0].proto, 17, "rule0 proto udp");
    ASSERT_EQ_INT(cfg.reorder.rules[0].port, 443, "rule0 port 443");
    ASSERT_EQ_INT(cfg.reorder.rules[0].profile, MQVPN_RPROF_QUIC_BULK, "rule0 quic_bulk");
    ASSERT_EQ_INT(cfg.reorder.rules[1].port, 53, "rule1 port 53");
    ASSERT_EQ_INT(cfg.reorder.rules[1].profile, MQVPN_RPROF_LOW_LATENCY,
                  "rule1 low_latency");
}

static void
test_ini_unknown_key_warns_no_fail(void)
{
    /* Unknown keys in [Reorder] / [ReorderRule] warn but do not fail (forward
     * compat), mirroring the existing section behaviour. */
    const char *ini = "[Reorder]\n"
                      "Enabled = on\n"
                      "FutureKnob = 123\n"
                      "[ReorderRule]\n"
                      "Proto = udp\n"
                      "Port = 443\n"
                      "Profile = quic_bulk\n"
                      "FutureRuleKnob = x\n";
    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    if (path) unlink(path);

    ASSERT_EQ_INT(rc, 0, "parse ok despite unknown keys");
    ASSERT_EQ_INT(cfg.reorder.mode, MQVPN_REORDER_ON, "known key still applied");
    ASSERT_EQ_INT(cfg.reorder.n_rules, 1, "rule still added");
}

static void
test_ini_validate_rejects_idle_inversion(void)
{
    /* ingress >= egress must be rejected by validate (§14.2). The parser stores
     * the raw values; validate is the gate. */
    const char *ini = "[Reorder]\n"
                      "Enabled = on\n"
                      "IngressIdleSec = 300\n"
                      "EgressIdleSec = 300\n";
    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    if (path) unlink(path);

    ASSERT_EQ_INT(rc, 0, "parse ok");
    ASSERT_EQ_INT(cfg.reorder.ingress_idle_timeout_sec, 300, "ingress stored");
    ASSERT_EQ_INT(cfg.reorder.egress_idle_timeout_sec, 300, "egress stored");
    ASSERT_TRUE(mqvpn_reorder_config_validate(&cfg.reorder) != 0,
                "validate rejects ingress >= egress");
}

int
main(void)
{
    /* Task 4.1 */
    test_builder_default_embedded();
    test_builder_set_enabled();
    test_builder_set_wait();
    test_builder_set_cap();
    test_builder_set_classify();
    test_builder_set_reset();
    test_builder_set_limits();
    test_builder_add_rule();
    test_builder_add_rule_overflow();

    /* Task 4.2 */
    test_ini_defaults_no_section();
    test_ini_reorder_full();
    test_ini_enabled_mapping();
    test_ini_reorder_rules();
    test_ini_unknown_key_warns_no_fail();
    test_ini_validate_rejects_idle_inversion();

    fprintf(stderr, "test_reorder_config: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
