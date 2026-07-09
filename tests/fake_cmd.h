// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * fake_cmd.h — PATH-injected fake command harness for the Darwin platform
 * twin integration tests (test_dns_state_darwin.c, test_routing_seq_darwin.c,
 * test_killswitch_rules_darwin.c).
 *
 * The twins under test (darwin/dns.c, darwin/routing.c, darwin/killswitch.c)
 * drive external commands (networksetup / route / pfctl) via fork+execvp,
 * which resolves the command name through $PATH. This harness creates a
 * temp dir, writes an executable "#!/bin/sh" script there named after the
 * real command, and prepends the dir to PATH so execvp() finds the fake
 * instead. Each installed script:
 *
 *   - appends one line per invocation to $MQVPN_FAKE_LOG: the command name
 *     followed by every argv element, '|'-joined. '|' (not a space) is the
 *     separator so an arg containing a space (e.g. "Thunderbolt Bridge")
 *     stays unambiguous when a test greps the log for an exact call;
 *   - exits 1 — before running its command-specific body — when
 *     $MQVPN_FAKE_FAIL_SUBSTR is non-empty and is a substring of the
 *     joined line, or when $MQVPN_FAKE_FAIL_NTH equals this invocation's
 *     1-based ordinal (ordinal tracked in $MQVPN_FAKE_COUNT_FILE, shared
 *     by every install under one fake_cmd_env_t — i.e. it counts THIS
 *     command's total invocations, not any one verb's);
 *   - otherwise runs the caller-supplied body (verb-dependent stdout /
 *     stdin capture) and exits 0.
 *
 * Env manipulation is via setenv()/unsetenv() before calling the function
 * under test: a fork()ed child inherits the parent's environment, so the
 * fake scripts see whatever fail-injection / content-file vars are set at
 * the moment of the call.
 */
#ifndef MQVPN_TEST_FAKE_CMD_H
#define MQVPN_TEST_FAKE_CMD_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define FAKE_CMD_PATH_MAX 512

typedef struct {
    char dir[FAKE_CMD_PATH_MAX];        /* mkdtemp'd scratch dir */
    char log_path[FAKE_CMD_PATH_MAX];   /* $MQVPN_FAKE_LOG */
    char count_path[FAKE_CMD_PATH_MAX]; /* $MQVPN_FAKE_COUNT_FILE */
} fake_cmd_env_t;

/* PATH as it was before the first fake_cmd_env_init() call in this process
 * — saved once so repeated env_init() calls (one per test scenario) don't
 * grow PATH unboundedly by re-prepending onto an already-prepended value. */
static char fake_cmd_g_orig_path[8192];
static int fake_cmd_g_orig_path_saved = 0;

__attribute__((unused)) static void
fake_cmd_save_orig_path(void)
{
    if (fake_cmd_g_orig_path_saved) return;
    const char *p = getenv("PATH");
    snprintf(fake_cmd_g_orig_path, sizeof(fake_cmd_g_orig_path), "%s", p ? p : "");
    fake_cmd_g_orig_path_saved = 1;
}

/* Creates the scratch dir + control files and prepends the dir to PATH.
 * Returns 0 on success, -1 on failure (mkdtemp/fopen). */
__attribute__((unused)) static int
fake_cmd_env_init(fake_cmd_env_t *e)
{
    fake_cmd_save_orig_path();

    char tmpl[] = "/tmp/mqvpn_fakecmd_XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir) return -1;
    snprintf(e->dir, sizeof(e->dir), "%s", dir);
    snprintf(e->log_path, sizeof(e->log_path), "%s/log", e->dir);
    snprintf(e->count_path, sizeof(e->count_path), "%s/count", e->dir);

    FILE *fp = fopen(e->log_path, "w");
    if (fp) fclose(fp);
    fp = fopen(e->count_path, "w");
    if (fp) fclose(fp);

    setenv("MQVPN_FAKE_LOG", e->log_path, 1);
    setenv("MQVPN_FAKE_COUNT_FILE", e->count_path, 1);
    unsetenv("MQVPN_FAKE_FAIL_SUBSTR");
    unsetenv("MQVPN_FAKE_FAIL_NTH");

    char newpath[8192];
    snprintf(newpath, sizeof(newpath), "%s:%s", e->dir, fake_cmd_g_orig_path);
    setenv("PATH", newpath, 1);
    return 0;
}

/* Writes an executable fake script for `cmd` (e.g. "networksetup") into
 * e->dir. `body` is POSIX sh, appended after the shared logging +
 * fail-injection boilerplate; it sees the same "$1" "$2" ... positions as
 * the real command's argv[1], argv[2], ... . Returns 0 on success. */
__attribute__((unused)) static int
fake_cmd_install(fake_cmd_env_t *e, const char *cmd, const char *body)
{
    char path[FAKE_CMD_PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", e->dir, cmd);

    FILE *fp = fopen(path, "w");
    if (!fp) return -1;
    fprintf(
        fp,
        "#!/bin/sh\n"
        "line=\"%s\"\n"
        "for a in \"$@\"; do line=\"$line|$a\"; done\n"
        "echo \"$line\" >> \"$MQVPN_FAKE_LOG\"\n"
        "count=0\n"
        "[ -s \"$MQVPN_FAKE_COUNT_FILE\" ] && count=$(cat \"$MQVPN_FAKE_COUNT_FILE\")\n"
        "count=$((count+1))\n"
        "echo \"$count\" > \"$MQVPN_FAKE_COUNT_FILE\"\n"
        "if [ -n \"$MQVPN_FAKE_FAIL_SUBSTR\" ]; then\n"
        "  case \"$line\" in\n"
        "    *\"$MQVPN_FAKE_FAIL_SUBSTR\"*) exit 1 ;;\n"
        "  esac\n"
        "fi\n"
        "if [ -n \"$MQVPN_FAKE_FAIL_NTH\" ] && [ \"$count\" = \"$MQVPN_FAKE_FAIL_NTH\" "
        "]; "
        "then\n"
        "  exit 1\n"
        "fi\n"
        "%s\n"
        "exit 0\n",
        cmd, body);
    fclose(fp);
    chmod(path, 0755);
    return 0;
}

/* Truncates the log/count files and clears fail-injection vars between
 * scenarios; the installed scripts and PATH are left as-is. */
__attribute__((unused)) static void
fake_cmd_reset(fake_cmd_env_t *e)
{
    FILE *fp = fopen(e->log_path, "w");
    if (fp) fclose(fp);
    fp = fopen(e->count_path, "w");
    if (fp) fclose(fp);
    unsetenv("MQVPN_FAKE_FAIL_SUBSTR");
    unsetenv("MQVPN_FAKE_FAIL_NTH");
}

__attribute__((unused)) static void
fake_cmd_set_fail_substr(const char *substr)
{
    setenv("MQVPN_FAKE_FAIL_SUBSTR", substr, 1);
}

__attribute__((unused)) static void
fake_cmd_set_fail_nth(int n)
{
    char buf[16];
    snprintf(buf, sizeof(buf), "%d", n);
    setenv("MQVPN_FAKE_FAIL_NTH", buf, 1);
}

__attribute__((unused)) static void
fake_cmd_clear_fail(void)
{
    unsetenv("MQVPN_FAKE_FAIL_SUBSTR");
    unsetenv("MQVPN_FAKE_FAIL_NTH");
}

/* Reads the whole log file into buf (NUL-terminated). Returns the number
 * of bytes read, or -1 if the file couldn't be opened. */
__attribute__((unused)) static int
fake_cmd_read_log(fake_cmd_env_t *e, char *buf, size_t bufsize)
{
    FILE *fp = fopen(e->log_path, "r");
    if (!fp) return -1;
    size_t n = fread(buf, 1, bufsize - 1, fp);
    buf[n] = '\0';
    fclose(fp);
    return (int)n;
}

/* Writes `content` to a fresh file under e->dir named `name` and returns
 * its full path in `out_path` — used for the query-verb content files
 * (networksetup -listallnetworkservices / -getdnsservers, pfctl -E token)
 * that the fake scripts `cat`. Returns 0 on success. */
__attribute__((unused)) static int
fake_cmd_write_content_file(fake_cmd_env_t *e, const char *name, const char *content,
                            char *out_path, size_t out_path_len)
{
    snprintf(out_path, out_path_len, "%s/%s", e->dir, name);
    FILE *fp = fopen(out_path, "w");
    if (!fp) return -1;
    fputs(content, fp);
    fclose(fp);
    return 0;
}

/* Removes the scratch dir and everything in it (a handful of small script
 * and control files — a shallow `rm -rf` via system() is simplest here). */
__attribute__((unused)) static void
fake_cmd_env_cleanup(fake_cmd_env_t *e)
{
    char cmd[FAKE_CMD_PATH_MAX + 16];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", e->dir);
    if (system(cmd) != 0) {
        /* Best-effort cleanup only; a leaked /tmp dir across test runs is
         * not worth failing the test suite over. */
    }
}

#endif /* MQVPN_TEST_FAKE_CMD_H */
