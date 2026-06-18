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

#include <stdarg.h>
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

/* Safe accumulating append for the config-string builders below. Manages the
 * running offset internally so the size argument can never be derived from a
 * prior snprintf return value (which would underflow `bufsz - *n` once a write
 * truncates). On truncation it fails an assertion and stops appending — that
 * means the fixed test buffer is too small for the case (a test-setup bug), not
 * a silent overflow. */
static void cfg_append(char *buf, size_t bufsz, size_t *n, const char *fmt, ...)
    __attribute__((__format__(__printf__, 4, 5)));

static void
cfg_append(char *buf, size_t bufsz, size_t *n, const char *fmt, ...)
{
    if (*n >= bufsz) {
        ASSERT_TRUE(0, "cfg_append: buffer already full");
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    int w = vsnprintf(buf + *n, bufsz - *n, fmt, ap);
    va_end(ap);
    if (w < 0 || (size_t)w >= bufsz - *n) {
        ASSERT_TRUE(0, "cfg_append: append truncated (test buffer too small)");
        return;
    }
    *n += (size_t)w;
}

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
test_ini_reorder_profile_names(void)
{
    /* cellular_bond / fiber_lte profile names parse into the new enum values. */
    const char *ini = "[Reorder]\n"
                      "Enabled = on\n"
                      "[ReorderRule]\n"
                      "Proto = udp\n"
                      "Port = 443\n"
                      "Profile = cellular_bond\n"
                      "[ReorderRule]\n"
                      "Proto = udp\n"
                      "Port = 8443\n"
                      "Profile = fiber_lte\n";
    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    if (path) unlink(path);

    ASSERT_EQ_INT(rc, 0, "parse ok");
    ASSERT_EQ_INT(cfg.reorder.n_rules, 2, "two rules");
    ASSERT_EQ_INT(cfg.reorder.rules[0].port, 443, "rule0 port 443");
    ASSERT_EQ_INT(cfg.reorder.rules[0].profile, MQVPN_RPROF_CELLULAR_BOND,
                  "rule0 cellular_bond");
    ASSERT_EQ_INT(cfg.reorder.rules[1].port, 8443, "rule1 port 8443");
    ASSERT_EQ_INT(cfg.reorder.rules[1].profile, MQVPN_RPROF_FIBER_LTE, "rule1 fiber_lte");
}

static void
test_ini_reorder_invalid_profile_keeps_quic_bulk(void)
{
    /* A typo'd profile name warns (no hard error) and the rule keeps its
     * begin-time default MQVPN_RPROF_QUIC_BULK (still reorder-eligible). */
    const char *ini = "[Reorder]\n"
                      "Enabled = on\n"
                      "[ReorderRule]\n"
                      "Proto = udp\n"
                      "Port = 443\n"
                      "Profile = celluar_bond\n"; /* typo */
    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    if (path) unlink(path);

    ASSERT_EQ_INT(rc, 0, "parse ok despite typo profile");
    ASSERT_EQ_INT(cfg.reorder.n_rules, 1, "rule still added");
    ASSERT_EQ_INT(cfg.reorder.rules[0].profile, MQVPN_RPROF_QUIC_BULK,
                  "typo keeps QUIC_BULK default");
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

static void
test_ini_over_cap_rule_rejected(void)
{
    /* Emit MQVPN_REORDER_MAX_RULES + 1 [ReorderRule] sections with distinct
     * ports (8000..8000+cap). The over-cap section must be dropped entirely:
     * n_rules stays at the cap AND the last accepted rule (rules[cap-1]) keeps
     * its own port (8000 + cap - 1), NOT the over-cap section's port. A
     * regression where the over-cap keys land on rules[cap-1] would clobber it
     * to 8000 + cap (the 17th port). */
    char ini[2048];
    size_t n = 0;
    cfg_append(ini, sizeof(ini), &n, "[Reorder]\nEnabled = on\n");
    for (int i = 0; i <= MQVPN_REORDER_MAX_RULES; i++) {
        cfg_append(ini, sizeof(ini), &n,
                   "[ReorderRule]\nProto = udp\nPort = %d\nProfile = quic_bulk\n",
                   8000 + i);
    }
    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    if (path) unlink(path);

    ASSERT_EQ_INT(rc, 0, "parse ok despite over-cap rule");
    ASSERT_EQ_INT(cfg.reorder.n_rules, MQVPN_REORDER_MAX_RULES, "n_rules at cap");
    /* The last accepted rule must keep its own port, not the over-cap one. */
    ASSERT_EQ_INT(cfg.reorder.rules[MQVPN_REORDER_MAX_RULES - 1].port,
                  8000 + MQVPN_REORDER_MAX_RULES - 1, "last accepted rule not clobbered");
}

static void
test_ini_rule_out_of_range_keeps_defaults(void)
{
    /* A [ReorderRule] with an invalid Profile and an out-of-range Proto must
     * warn (not fail); the rule keeps its begin-time defaults (proto UDP,
     * profile QUIC_BULK). */
    const char *ini = "[Reorder]\n"
                      "Enabled = on\n"
                      "[ReorderRule]\n"
                      "Proto = 999\n"
                      "Profile = bogus\n"
                      "Port = 4242\n";
    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    if (path) unlink(path);

    ASSERT_EQ_INT(rc, 0, "parse ok despite invalid profile/proto");
    ASSERT_EQ_INT(cfg.reorder.n_rules, 1, "rule still added");
    ASSERT_EQ_INT(cfg.reorder.rules[0].proto, MQVPN_IPPROTO_UDP,
                  "proto keeps UDP default");
    ASSERT_EQ_INT(cfg.reorder.rules[0].profile, MQVPN_RPROF_QUIC_BULK,
                  "profile keeps QUIC_BULK default");
    /* The valid Port= still applies. */
    ASSERT_EQ_INT(cfg.reorder.rules[0].port, 4242, "valid port applied");
}

/* ──────────────────────── Task: JSON parsing ──────────────────────────────
 *
 * The JSON loader (mqvpn_config_load_json_filecfg) must populate
 * file_cfg.reorder identically to the INI parser, reusing the same value
 * mappers (parse_reorder_enabled/proto/profile). JSON keys are snake_case;
 * the reorder object holds the 13 scalar knobs and "reorder_rules" is an array
 * of {proto, port, profile} objects. */

static void
test_json_reorder_basic(void)
{
    const char *json = "{\n"
                       "  \"mode\": \"client\",\n"
                       "  \"reorder\": {\n"
                       "    \"enabled\": \"on\",\n"
                       "    \"max_wait_ms\": 40,\n"
                       "    \"cap_packets\": 2048,\n"
                       "    \"max_bytes_per_flow\": 3145728,\n"
                       "    \"classify_window\": 96,\n"
                       "    \"ack_demote_max_large\": 4,\n"
                       "    \"small_packet_threshold\": 220,\n"
                       "    \"reset_mark_packets\": 6,\n"
                       "    \"reset_idle_grace_ms\": 9000,\n"
                       "    \"max_flows\": 32768,\n"
                       "    \"global_max_bytes\": 134217728,\n"
                       "    \"ingress_idle_sec\": 25,\n"
                       "    \"egress_idle_sec\": 250\n"
                       "  }\n"
                       "}\n";
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load_json_filecfg(&cfg, json);

    /* Smoke test: parses, validates, and a few representative fields land. The
     * exhaustive per-field check (and full INI↔JSON equality) is covered by
     * test_json_ini_parity. */
    ASSERT_EQ_INT(rc, 0, "json parse ok");
    ASSERT_EQ_INT(mqvpn_reorder_config_validate(&cfg.reorder), 0, "json config valid");
    ASSERT_EQ_INT(cfg.reorder.mode, MQVPN_REORDER_ON, "json enabled=on → ON");
    ASSERT_EQ_INT(cfg.reorder.max_wait_ms, 40, "json max_wait_ms");
    ASSERT_EQ_INT(cfg.reorder.cap_packets_per_flow, 2048, "json cap_packets");
}

static void
test_json_reorder_enabled_mapping(void)
{
    struct {
        const char *val;
        mqvpn_reorder_mode_t want;
    } cases[] = {
        {"off", MQVPN_REORDER_OFF}, {"false", MQVPN_REORDER_OFF},
        {"on", MQVPN_REORDER_ON},   {"true", MQVPN_REORDER_ON},
        {"auto", MQVPN_REORDER_ON}, /* §16 scope: auto → ON + LOG_WRN, same as INI */
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char json[128];
        snprintf(json, sizeof(json), "{\"reorder\":{\"enabled\":\"%s\"}}", cases[i].val);
        mqvpn_file_config_t cfg;
        mqvpn_config_defaults(&cfg);
        int rc = mqvpn_config_load_json_filecfg(&cfg, json);
        ASSERT_EQ_INT(rc, 0, "json parse ok");
        ASSERT_EQ_INT(cfg.reorder.mode, cases[i].want, cases[i].val);
    }
}

static void
test_json_reorder_rules_over_cap(void)
{
    /* Emit MQVPN_REORDER_MAX_RULES + 1 rule objects with distinct ports.
     * The over-cap rule must be dropped: n_rules stays at the cap AND the last
     * accepted rule keeps its own port (not clobbered by the over-cap one). */
    char json[4096];
    size_t n = 0;
    cfg_append(json, sizeof(json), &n,
               "{ \"reorder\": {\"enabled\":\"on\"}, \"reorder_rules\": [");
    for (int i = 0; i <= MQVPN_REORDER_MAX_RULES; i++) {
        cfg_append(json, sizeof(json), &n,
                   "%s{\"proto\":\"udp\",\"port\":%d,\"profile\":\"quic_bulk\"}",
                   i ? "," : "", 8000 + i);
    }
    cfg_append(json, sizeof(json), &n, "] }");

    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load_json_filecfg(&cfg, json);

    ASSERT_EQ_INT(rc, 0, "json parse ok despite over-cap rule");
    ASSERT_EQ_INT(cfg.reorder.n_rules, MQVPN_REORDER_MAX_RULES, "n_rules at cap");
    ASSERT_EQ_INT(cfg.reorder.rules[MQVPN_REORDER_MAX_RULES - 1].port,
                  8000 + MQVPN_REORDER_MAX_RULES - 1, "last accepted rule not clobbered");
}

static void
test_json_reorder_absent(void)
{
    /* JSON without a reorder object → reorder stays at defaults (mode OFF). */
    const char *json = "{ \"mode\": \"client\", \"server_addr\": \"host:443\" }";
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load_json_filecfg(&cfg, json);

    ASSERT_EQ_INT(rc, 0, "json parse ok");
    ASSERT_EQ_INT(cfg.reorder.mode, MQVPN_REORDER_OFF, "absent → OFF");
    ASSERT_EQ_INT(cfg.reorder.max_wait_ms, 30, "absent → default wait");
    ASSERT_EQ_INT(cfg.reorder.n_rules, 0, "absent → no rules");
}

/* JSON and INI must produce an identical mqvpn_reorder_config_t for equivalent
 * inputs — proving the shared mappers give the two surfaces parity. */
static void
test_json_ini_parity(void)
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
                      /* Above INT_MAX (0x7fffffff) but below 2^32: exercises the
                       * u32 range parity between INI (parse_u32_strict, accepts up
                       * to 0xffffffff) and JSON. max_flows has no upper-bound
                       * validation, so 3e9 survives validate(). */
                      "MaxFlows = 3000000000\n"
                      "GlobalMaxBytes = 134217728\n"
                      "IngressIdleSec = 25\n"
                      "EgressIdleSec = 250\n"
                      "[ReorderRule]\n"
                      "Proto = udp\nPort = 443\nProfile = quic_bulk\n"
                      "[ReorderRule]\n"
                      "Proto = udp\nPort = 53\nProfile = low_latency\n";
    const char *json =
        "{\n"
        "  \"reorder\": {\n"
        "    \"enabled\": \"on\", \"max_wait_ms\": 40, \"cap_packets\": 2048,\n"
        "    \"max_bytes_per_flow\": 3145728, \"classify_window\": 96,\n"
        "    \"ack_demote_max_large\": 4, \"small_packet_threshold\": 220,\n"
        "    \"reset_mark_packets\": 6, \"reset_idle_grace_ms\": 9000,\n"
        "    \"max_flows\": 3000000000, \"global_max_bytes\": 134217728,\n"
        "    \"ingress_idle_sec\": 25, \"egress_idle_sec\": 250\n"
        "  },\n"
        "  \"reorder_rules\": [\n"
        "    {\"proto\":\"udp\",\"port\":443,\"profile\":\"quic_bulk\"},\n"
        "    {\"proto\":\"udp\",\"port\":53,\"profile\":\"low_latency\"}\n"
        "  ]\n"
        "}\n";

    mqvpn_file_config_t icfg, jcfg;
    mqvpn_config_defaults(&icfg);
    mqvpn_config_defaults(&jcfg);

    char *path = write_tmp(ini);
    int irc = mqvpn_config_load(&icfg, path);
    if (path) unlink(path);
    int jrc = mqvpn_config_load_json_filecfg(&jcfg, json);

    ASSERT_EQ_INT(irc, 0, "ini parse ok");
    ASSERT_EQ_INT(jrc, 0, "json parse ok");
    /* The reorder sub-structs must be byte-identical. */
    ASSERT_EQ_INT(memcmp(&icfg.reorder, &jcfg.reorder, sizeof(icfg.reorder)), 0,
                  "INI and JSON reorder configs identical");
}

/* ──────────────── Bridge: INI file_cfg.reorder → libmqvpn config ──────────────
 *
 * The CLI path copies mqvpn_file_config_t.reorder into the platform cfg, and the
 * platform builder calls mqvpn_config_apply_reorder() to translate it into the
 * libmqvpn config via the public setters. This exercises that exact translation
 * function on a config parsed from INI, proving [Reorder]/[ReorderRule] reaches
 * the engine config (mode ON + rule present) rather than being silently ignored. */
static void
test_bridge_ini_reaches_libmqvpn_config(void)
{
    const char *ini = "[Reorder]\n"
                      "Enabled = on\n"
                      "MaxWaitMs = 45\n"
                      "CapPackets = 2048\n"
                      "ClassifyWindow = 80\n"
                      "[ReorderRule]\n"
                      "Proto = udp\n"
                      "Port = 443\n"
                      "Profile = quic_bulk\n";
    char *path = write_tmp(ini);
    mqvpn_file_config_t fc;
    mqvpn_config_defaults(&fc);
    int rc = mqvpn_config_load(&fc, path);
    if (path) unlink(path);
    ASSERT_EQ_INT(rc, 0, "parse ok");

    /* Fresh libmqvpn config starts at the OFF default; the bridge must flip it. */
    mqvpn_config_t *lib = mqvpn_config_new();
    ASSERT_TRUE(lib != NULL, "config_new");
    ASSERT_EQ_INT(lib->reorder.mode, MQVPN_REORDER_OFF, "lib starts OFF");

    mqvpn_config_apply_reorder(lib, &fc.reorder);

    ASSERT_EQ_INT(lib->reorder.mode, MQVPN_REORDER_ON, "bridge: mode ON reaches lib");
    ASSERT_EQ_INT(lib->reorder.max_wait_ms, 45, "bridge: max_wait_ms");
    ASSERT_EQ_INT(lib->reorder.cap_packets_per_flow, 2048, "bridge: cap");
    ASSERT_EQ_INT(lib->reorder.classify_window, 80, "bridge: classify_window");
    ASSERT_EQ_INT(lib->reorder.n_rules, 1, "bridge: rule present in lib");
    ASSERT_EQ_INT(lib->reorder.rules[0].proto, MQVPN_IPPROTO_UDP, "bridge: rule proto");
    ASSERT_EQ_INT(lib->reorder.rules[0].port, 443, "bridge: rule port");
    ASSERT_EQ_INT(lib->reorder.rules[0].profile, MQVPN_RPROF_QUIC_BULK,
                  "bridge: rule profile");
    ASSERT_EQ_INT(mqvpn_reorder_config_validate(&lib->reorder), 0, "bridge: lib valid");

    mqvpn_config_free(lib);
}

/* ──────────────────── Chunk 1: profile→preset helper ─────────────────────── */

static void
test_profile_preset(void)
{
    uint32_t wait_ms = 0, cap = 0;

    /* quic_bulk & cellular_bond → 50 / 1024 */
    wait_ms = 0;
    cap = 0;
    ASSERT_EQ_INT(mqvpn_reorder_profile_preset(MQVPN_RPROF_QUIC_BULK, &wait_ms, &cap), 1,
                  "quic_bulk has preset");
    ASSERT_EQ_INT(wait_ms, 50, "quic_bulk wait");
    ASSERT_EQ_INT(cap, 1024, "quic_bulk cap");

    wait_ms = 0;
    cap = 0;
    ASSERT_EQ_INT(mqvpn_reorder_profile_preset(MQVPN_RPROF_CELLULAR_BOND, &wait_ms, &cap),
                  1, "cellular_bond has preset");
    ASSERT_EQ_INT(wait_ms, 50, "cellular_bond wait");
    ASSERT_EQ_INT(cap, 1024, "cellular_bond cap");

    /* fiber_lte → 50 / 2048 */
    wait_ms = 0;
    cap = 0;
    ASSERT_EQ_INT(mqvpn_reorder_profile_preset(MQVPN_RPROF_FIBER_LTE, &wait_ms, &cap), 1,
                  "fiber_lte has preset");
    ASSERT_EQ_INT(wait_ms, 50, "fiber_lte wait");
    ASSERT_EQ_INT(cap, 2048, "fiber_lte cap");

    /* low_latency & default_udp → return 0, outputs untouched */
    wait_ms = 7;
    cap = 9;
    ASSERT_EQ_INT(mqvpn_reorder_profile_preset(MQVPN_RPROF_LOW_LATENCY, &wait_ms, &cap),
                  0, "low_latency no preset");
    ASSERT_EQ_INT(wait_ms, 7, "low_latency wait untouched");
    ASSERT_EQ_INT(cap, 9, "low_latency cap untouched");

    wait_ms = 7;
    cap = 9;
    ASSERT_EQ_INT(mqvpn_reorder_profile_preset(MQVPN_RPROF_DEFAULT_UDP, &wait_ms, &cap),
                  0, "default_udp no preset");
    ASSERT_EQ_INT(wait_ms, 7, "default_udp wait untouched");
    ASSERT_EQ_INT(cap, 9, "default_udp cap untouched");
}

/* ──────────────────── Task 2.2: finalize precedence ─────────────────────── */

static void
test_param_precedence(void)
{
    mqvpn_reorder_config_t cfg;

    /* fiber_lte preset → 50 / 2048 when nothing else overrides. */
    mqvpn_reorder_config_default(&cfg);
    cfg.n_rules = 1;
    cfg.rules[0].profile = MQVPN_RPROF_FIBER_LTE;
    mqvpn_reorder_config_finalize(&cfg);
    ASSERT_EQ_INT(cfg.rules[0].resolved_wait_ms, 50, "fiber_lte preset wait");
    ASSERT_EQ_INT(cfg.rules[0].resolved_cap, 2048, "fiber_lte preset cap");

    /* rule-explicit wait=80 wins over the preset. */
    mqvpn_reorder_config_default(&cfg);
    cfg.n_rules = 1;
    cfg.rules[0].profile = MQVPN_RPROF_FIBER_LTE;
    cfg.rules[0].explicit_wait_ms = 80;
    mqvpn_reorder_config_finalize(&cfg);
    ASSERT_EQ_INT(cfg.rules[0].resolved_wait_ms, 80, "rule-explicit wait beats preset");
    ASSERT_EQ_INT(cfg.rules[0].resolved_cap, 2048, "cap still from preset");

    /* default_udp (no preset) → builtin 30 / 1024. */
    mqvpn_reorder_config_default(&cfg);
    cfg.n_rules = 1;
    cfg.rules[0].profile = MQVPN_RPROF_DEFAULT_UDP;
    mqvpn_reorder_config_finalize(&cfg);
    ASSERT_EQ_INT(cfg.rules[0].resolved_wait_ms, 30, "default_udp builtin wait");
    ASSERT_EQ_INT(cfg.rules[0].resolved_cap, 1024, "default_udp builtin cap");

    /* global-explicit wait masks the preset, but rule-explicit still wins. */
    mqvpn_reorder_config_default(&cfg);
    cfg.has_explicit_wait = 1;
    cfg.max_wait_ms = 120;
    cfg.n_rules = 2;
    cfg.rules[0].profile = MQVPN_RPROF_FIBER_LTE; /* no rule-explicit */
    cfg.rules[1].profile = MQVPN_RPROF_FIBER_LTE;
    cfg.rules[1].explicit_wait_ms = 80; /* rule-explicit still wins */
    mqvpn_reorder_config_finalize(&cfg);
    ASSERT_EQ_INT(cfg.rules[0].resolved_wait_ms, 120, "global-explicit masks preset");
    ASSERT_EQ_INT(cfg.rules[1].resolved_wait_ms, 80, "rule-explicit beats global");
}

static void
test_resolved_cap_pow2(void)
{
    mqvpn_reorder_config_t cfg;

    /* (i) invalid explicit_cap=1000 + global-explicit cap=2048 → global tier. */
    mqvpn_reorder_config_default(&cfg);
    cfg.has_explicit_cap = 1;
    cfg.cap_packets_per_flow = 2048;
    cfg.n_rules = 1;
    cfg.rules[0].profile = MQVPN_RPROF_FIBER_LTE;
    cfg.rules[0].explicit_cap = 1000; /* non-pow2, parser would reject; bypass */
    mqvpn_reorder_config_finalize(&cfg);
    ASSERT_EQ_INT(cfg.rules[0].resolved_cap, 2048,
                  "bad rule cap falls through to global tier");

    /* (ii) invalid explicit_cap=1000 + NO global-explicit + fiber_lte → preset. */
    mqvpn_reorder_config_default(&cfg);
    cfg.n_rules = 1;
    cfg.rules[0].profile = MQVPN_RPROF_FIBER_LTE;
    cfg.rules[0].explicit_cap = 1000;
    mqvpn_reorder_config_finalize(&cfg);
    ASSERT_EQ_INT(cfg.rules[0].resolved_cap, 2048,
                  "bad rule cap falls through to preset tier");
}

/* ──────────────── Task 2.3: INI per-rule params + global explicit ──────────── */

static void
test_ini_rule_profile_only_resolves_preset(void)
{
    /* (a) Profile=fiber_lte, no explicit keys → preset 50/2048 after finalize. */
    const char *ini = "[Reorder]\n"
                      "Enabled = on\n"
                      "[ReorderRule]\n"
                      "Proto = udp\n"
                      "Port = 443\n"
                      "Profile = fiber_lte\n";
    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    if (path) unlink(path);
    ASSERT_EQ_INT(rc, 0, "parse ok");
    mqvpn_reorder_config_finalize(&cfg.reorder);
    ASSERT_EQ_INT(cfg.reorder.rules[0].resolved_wait_ms, 50, "(a) fiber_lte wait");
    ASSERT_EQ_INT(cfg.reorder.rules[0].resolved_cap, 2048, "(a) fiber_lte cap");
}

static void
test_ini_global_explicit_beats_preset(void)
{
    /* (b) harness-compat: global MaxWaitMs=30 sets has_explicit_wait and masks
     * the quic_bulk preset (50). Pins benchmarks/sweep_reorder.sh. */
    const char *ini = "[Reorder]\n"
                      "Enabled = on\n"
                      "MaxWaitMs = 30\n"
                      "CapPackets = 1024\n"
                      "[ReorderRule]\n"
                      "Profile = quic_bulk\n";
    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    if (path) unlink(path);
    ASSERT_EQ_INT(rc, 0, "parse ok");
    ASSERT_EQ_INT(cfg.reorder.has_explicit_wait, 1, "(b) global wait explicit flag");
    mqvpn_reorder_config_finalize(&cfg.reorder);
    ASSERT_EQ_INT(cfg.reorder.rules[0].resolved_wait_ms, 30,
                  "(b) global-explicit beats quic_bulk preset");
}

static void
test_ini_rule_explicit_wait(void)
{
    /* (c) per-rule MaxWaitMs=80 → explicit_wait_ms set, resolves to 80. */
    const char *ini = "[Reorder]\n"
                      "Enabled = on\n"
                      "[ReorderRule]\n"
                      "Profile = cellular_bond\n"
                      "MaxWaitMs = 80\n";
    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    if (path) unlink(path);
    ASSERT_EQ_INT(rc, 0, "parse ok");
    ASSERT_EQ_INT(cfg.reorder.rules[0].explicit_wait_ms, 80, "(c) rule explicit_wait_ms");
    mqvpn_reorder_config_finalize(&cfg.reorder);
    ASSERT_EQ_INT(cfg.reorder.rules[0].resolved_wait_ms, 80, "(c) resolved 80");
}

static void
test_ini_rule_cap_nonpow2_rejected(void)
{
    /* (d) per-rule CapPackets=1000 (non-pow2) → warns, explicit_cap stays 0,
     * resolves to a pow2 preset/builtin. */
    const char *ini = "[Reorder]\n"
                      "Enabled = on\n"
                      "[ReorderRule]\n"
                      "Profile = fiber_lte\n"
                      "CapPackets = 1000\n";
    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    if (path) unlink(path);
    ASSERT_EQ_INT(rc, 0, "parse ok despite non-pow2 cap");
    ASSERT_EQ_INT(cfg.reorder.rules[0].explicit_cap, 0, "(d) non-pow2 cap rejected");
    mqvpn_reorder_config_finalize(&cfg.reorder);
    ASSERT_EQ_INT(cfg.reorder.rules[0].resolved_cap, 2048, "(d) resolves to preset pow2");
}

static void
test_ini_rule_wait_zero_rejected(void)
{
    /* (e) per-rule MaxWaitMs=0 → warns, explicit_wait_ms stays 0 (unset),
     * resolves to profile/global/builtin, NOT 0. */
    const char *ini = "[Reorder]\n"
                      "Enabled = on\n"
                      "[ReorderRule]\n"
                      "Profile = fiber_lte\n"
                      "MaxWaitMs = 0\n";
    char *path = write_tmp(ini);
    mqvpn_file_config_t cfg;
    mqvpn_config_defaults(&cfg);
    int rc = mqvpn_config_load(&cfg, path);
    if (path) unlink(path);
    ASSERT_EQ_INT(rc, 0, "parse ok despite per-rule wait=0");
    ASSERT_EQ_INT(cfg.reorder.rules[0].explicit_wait_ms, 0, "(e) wait=0 left unset");
    mqvpn_reorder_config_finalize(&cfg.reorder);
    ASSERT_EQ_INT(cfg.reorder.rules[0].resolved_wait_ms, 50,
                  "(e) resolves to preset, not 0");
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
    test_ini_reorder_profile_names();
    test_ini_reorder_invalid_profile_keeps_quic_bulk();
    test_ini_unknown_key_warns_no_fail();
    test_ini_validate_rejects_idle_inversion();
    test_ini_over_cap_rule_rejected();
    test_ini_rule_out_of_range_keeps_defaults();

    /* JSON parsing */
    test_json_reorder_basic();
    test_json_reorder_enabled_mapping();
    test_json_reorder_rules_over_cap();
    test_json_reorder_absent();
    test_json_ini_parity();

    /* Bridge: INI → file_cfg → libmqvpn config (apply_reorder translation) */
    test_bridge_ini_reaches_libmqvpn_config();

    /* Chunk 1: profile→preset helper */
    test_profile_preset();

    /* Task 2.2: finalize precedence + cap pow2 defense */
    test_param_precedence();
    test_resolved_cap_pow2();

    /* Task 2.3: INI per-rule params + global explicit flag */
    test_ini_rule_profile_only_resolves_preset();
    test_ini_global_explicit_beats_preset();
    test_ini_rule_explicit_wait();
    test_ini_rule_cap_nonpow2_rejected();
    test_ini_rule_wait_zero_rejected();

    fprintf(stderr, "test_reorder_config: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
