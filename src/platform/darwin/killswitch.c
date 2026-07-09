// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * killswitch.c — pf anchor kill switch for Darwin, twin of
 * linux/killswitch.c (iptables).
 *
 * Blocks all outbound traffic outside the VPN tunnel via a pf anchor
 * ("com.apple/250.mqvpn") loaded through `pfctl -a <anchor> -f -`. Rule
 * semantics (allow tun / allow lo / allow UDP-to-server / drop rest, with
 * the two-axis IPv4/IPv6 family gating) are copied EXACTLY from
 * linux/killswitch.c:48-113 — this is a syntax port, not a policy change.
 * In particular the KNOWN gap is inherited as-is: a v4-only tunnel with no
 * v6 config does NOT block native v6 traffic (no utun-inet6 pass rule is
 * ever emitted in that case, so nothing here stops v6 from routing around
 * the tunnel via the host's normal v6 route). Do not fix this unilaterally
 * in a Darwin-only slice — it's a cross-platform follow-up.
 *
 * UNVERIFIED ON REAL MACOS HARDWARE (no Darwin machine in this dev
 * environment) — three separate items, each flagged again at its exact
 * use site below:
 *   1. That macOS's stock /etc/pf.conf evaluates every anchor whose name
 *      starts with "com.apple" followed by a slash (so loading rules into
 *      "com.apple/250.mqvpn" actually takes effect without this code also
 *      touching the main ruleset). This is the
 *      entire wiring strategy and is unverified end to end.
 *   2. Which stream (stdout or stderr) `pfctl -E`'s "Token : <N>" line
 *      is printed on, and the exact line format/casing.
 *   3. That `pfctl -X <token>` is the correct precise-decrement complement
 *      of `pfctl -E`'s reference-counted enable, and that a token-less
 *      cleanup (anchor flush only, `-X` skipped) truly leaves the host in
 *      a safe state — see the rationale in cleanup_killswitch().
 *
 * Anchor rules are NOT tied to this process's lifetime: pf state lives in
 * the kernel, so a crashed mqvpn leaves the anchor (and, if this process
 * was also the one that ran `pfctl -E`, pf itself) resident and blocking
 * — fail-closed by design, the same as Linux's iptables rules surviving a
 * crash. kill_switch_flush_stale_anchor() below is the self-recovery path;
 * it is wired into the startup stale-recovery block in
 * darwin_platform_run_client, not called from
 * setup_killswitch() — see kill_switch_flush_stale_anchor()'s doc comment
 * for why it cannot live inside setup_killswitch().
 */

#include "platform_internal.h"
#include "log.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>

#define MQVPN_PF_ANCHOR "com.apple/250.mqvpn"

/* ------------------------------------------------------------------ */
/* exec helpers — twins of routing.c's run_route_cmd / dns.c's         */
/* run_networksetup_capture, targeting "pfctl".                        */
/* ------------------------------------------------------------------ */

static int
run_pfctl(const char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        execvp("pfctl", (char *const *)argv);
        _exit(127);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0)
        if (errno != EINTR) return -1;
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/* Pipes `text` into the child's stdin (used for `pfctl -a <anchor> -f -`,
 * which reads the ruleset from stdin rather than a file/argv). Reverse of
 * routing.c's discover_route (which captures the child's stdout): here the
 * parent is the writer and the child is the reader. */
static int
run_pfctl_stdin(const char *const argv[], const char *text)
{
    int fds[2];
    if (pipe(fds) < 0) return -1;

    /* Parent-side SIGPIPE protection: if the child dies before consuming
     * its stdin (execvp failure, pfctl bailing out early on a failed
     * /dev/pf open when not root), the parent's write() below would raise
     * SIGPIPE — and mqvpn installs no process-wide SIGPIPE ignore
     * (suppression is per-socket SO_NOSIGPIPE only, see
     * compat/socket_compat.h; the CLI's evsignal handlers cover
     * SIGINT/SIGTERM only), so the default disposition would kill the
     * whole client mid-setup, with routes/DNS already mutated and no
     * cleanup run. F_SETNOSIGPIPE (Darwin-native fcntl; this file is
     * Darwin-only, so no ifdef) makes that write fail with EPIPE instead,
     * turning the write_failed path below into the live error path. */
    if (fcntl(fds[1], F_SETNOSIGPIPE, 1) < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }

    if (pid == 0) {
        close(fds[1]);
        if (dup2(fds[0], STDIN_FILENO) < 0) _exit(127);
        close(fds[0]);
        execvp("pfctl", (char *const *)argv);
        _exit(127);
    }

    close(fds[0]);

    size_t len = strlen(text);
    size_t off = 0;
    int write_failed = 0;
    while (off < len) {
        ssize_t w = write(fds[1], text + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            /* EPIPE (child gone — F_SETNOSIGPIPE above converted the
             * would-be SIGPIPE) or any other write error: report failure
             * after reaping the child. */
            write_failed = 1;
            break;
        }
        off += (size_t)w;
    }
    close(fds[1]); /* EOF for the child's read of stdin, whether or not the write loop
                      above succeeded */

    int status = 0;
    while (waitpid(pid, &status, 0) < 0)
        if (errno != EINTR) return -1;

    if (write_failed) return -1;
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/* Runs argv and captures its output for parsing (used for `pfctl -E`,
 * whose "Token : <N>" line's stream is unverified — see item 2 in the
 * file header). Captures BOTH stdout and stderr through ONE pipe by
 * dup2'ing its write end onto both fd 1 and fd 2 in the child, so the
 * caller can find the token line regardless of which stream it landed on.
 * Parent loop-reads to EOF with EINTR retry, twin of dns.c's
 * run_networksetup_capture but with a simpler buffer-full policy: dns.c
 * probes one extra byte and fails loudly on overflow; here the parent
 * just stops reading and closes the pipe. What happens next depends on
 * the child: if it had already written its (small) output into the pipe
 * buffer and exited, this returns 0 with a truncated capture and a
 * missing token falls through to setup_killswitch's NON-fatal empty-token
 * path; if it was still writing, the closed read end kills it with
 * SIGPIPE (default disposition — mqvpn never sets a process-wide SIG_IGN;
 * SIGPIPE suppression is per-socket only, see compat/socket_compat.h), so
 * WIFEXITED is false, this returns -1, and setup_killswitch treats it as
 * a FATAL `pfctl -E` failure (active=1 → cleanup). Both outcomes are
 * safe, and both are practically unreachable for `pfctl -E`'s ~2-line
 * output against the 256-byte capture buffer. */
static int
run_pfctl_capture(const char *const argv[], char *out, size_t outlen)
{
    int fds[2];
    if (pipe(fds) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }

    if (pid == 0) {
        close(fds[0]);
        if (dup2(fds[1], STDOUT_FILENO) < 0) _exit(127);
        if (dup2(fds[1], STDERR_FILENO) < 0) _exit(127);
        close(fds[1]);
        execvp("pfctl", (char *const *)argv);
        _exit(127);
    }

    close(fds[1]);

    size_t used = 0;
    int read_failed = 0;
    for (;;) {
        if (used >= outlen - 1)
            break; /* stop before overflowing `out`; see comment above */
        ssize_t r = read(fds[0], out + used, outlen - 1 - used);
        if (r < 0) {
            if (errno == EINTR) continue;
            read_failed = 1;
            break;
        }
        if (r == 0) break; /* EOF */
        used += (size_t)r;
    }
    close(fds[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0)
        if (errno != EINTR) return -1;

    if (read_failed) return -1;
    out[used] = '\0';
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* rule text builder                                                    */
/* ------------------------------------------------------------------ */

/* Builds the pf ruleset text for the anchor, replicating
 * linux/killswitch.c's iptables OUTPUT chain family gating exactly (see
 * the file header). pf's `quick` keyword makes each anchor a first-match-
 * wins list, so every "pass" line for a family MUST precede that family's
 * trailing "block" line; the relative order *among* the pass lines is
 * otherwise inert (lo0/tun/server-udp match disjoint traffic), so this
 * builder always emits them as: lo0 pass, [tun pass], [server pass],
 * block — same shape for both inet and inet6.
 *
 * inet (v4) is unconditional: lo0 pass, tun pass, [server pass iff the
 * server is v4], block.
 *
 * inet6 is emitted only when `is_v6` (server is v6) or `has_v6` (tunnel
 * carries v6) — this single guarded block is algebraically equivalent to
 * the Linux code's two separately-triggered branches (verified case by
 * case against killswitch.c:70-112; see the gating truth table in the
 * task report / commit message):
 *   - the tun pass line is gated on `has_v6` alone (Linux's
 *     "IPv6 data plane TUN rule" block, killswitch.c:97-101);
 *   - the server pass line is gated on `is_v6` alone (Linux's
 *     `else { ip6tables ... }` branch, killswitch.c:79-94);
 *   - lo0 pass + block are gated on `is_v6 || has_v6`: Linux emits them
 *     unconditionally inside the is_v6 branch (killswitch.c:84-90), and
 *     AGAIN inside the has_v6 branch but only `if (!is_v6)`
 *     (killswitch.c:102-111) — so across all four (is_v6, has_v6)
 *     combinations they appear exactly once whenever is_v6 OR has_v6 is
 *     true, and never when both are false.
 *
 * Uses a plain host match ("to <ip>") rather than Linux's explicit
 * "<ip>/<prefix>" CIDR for the server exception — pf's `to <addr>` with no
 * mask already matches that single host only (default /32 or /128), so
 * this is a syntax simplification, not a policy change.
 *
 * Returns 0 on success, -1 if `buf` was too small (defensive; ~1024 bytes
 * is generous for the <= 8 lines this ever produces).
 */
static int
build_pf_rules(const platform_ctx_t *p, char *buf, size_t buflen)
{
    int is_v6 = (p->server_addr.ss_family == AF_INET6);
    size_t off = 0;
    int n;

#define APPEND(...)                                         \
    do {                                                    \
        n = snprintf(buf + off, buflen - off, __VA_ARGS__); \
        if (n < 0 || (size_t)n >= buflen - off) return -1;  \
        off += (size_t)n;                                   \
    } while (0)

    APPEND("pass out quick on lo0 inet\n");
    APPEND("pass out quick on %s inet\n", p->tun.name);
    if (!is_v6)
        APPEND("pass out quick inet proto udp to %s port = %d\n", p->server_ip_str,
               p->server_port);
    APPEND("block drop out quick inet\n");

    if (is_v6 || p->has_v6) {
        APPEND("pass out quick on lo0 inet6\n");
        if (p->has_v6) APPEND("pass out quick on %s inet6\n", p->tun.name);
        if (is_v6)
            APPEND("pass out quick inet6 proto udp to %s port = %d\n", p->server_ip_str,
                   p->server_port);
        APPEND("block drop out quick inet6\n");
    }

#undef APPEND
    return 0;
}

/* ------------------------------------------------------------------ */
/* public API                                                           */
/* ------------------------------------------------------------------ */

int
setup_killswitch(platform_ctx_t *p)
{
    if (!p->killswitch_enabled || p->killswitch_active) return 0;

    char rules[1024];
    if (build_pf_rules(p, rules, sizeof(rules)) < 0) {
        LOG_WRN("failed to build pf kill switch rule text (buffer too small)");
        return -1;
    }

    /* `-f -` is a single atomic ruleset replace on the pfctl side (unlike
     * Linux's sequential iptables -I/-A calls, which can leave a partial
     * chain on a mid-sequence failure): a pfctl PARSE failure leaves the
     * anchor untouched. But run_pfctl_stdin returning -1 does not prove
     * the child loaded nothing — a parent-side failure (waitpid error, or
     * a partial write whose truncated text still parsed as a valid
     * pass-only ruleset and made the child exit 0) can coexist with a
     * loaded anchor. "active=0 but rules loaded" would be unrecoverable
     * until the next startup flush (cleanup_killswitch early-returns on
     * !killswitch_active), so take the conservative Linux-canon shape
     * (killswitch.c:57-60) on load failure too: mark active and unwind.
     * One extra flush of an empty/absent anchor is harmless. */
    p->ks_pf_token[0] = '\0'; /* before the failure path below can reach cleanup */
    const char *load_argv[] = {"pfctl", "-a", MQVPN_PF_ANCHOR, "-f", "-", NULL};
    if (run_pfctl_stdin(load_argv, rules) < 0) {
        LOG_WRN("failed to load pf kill switch rules into anchor %s", MQVPN_PF_ANCHOR);
        p->killswitch_active = 1;
        cleanup_killswitch(p);
        return -1;
    }

    /* From this point on the anchor IS loaded (item 1 in the file header:
     * unverified whether macOS's stock pf.conf actually evaluates it, but
     * we must assume it might). Set killswitch_active BEFORE calling
     * cleanup_killswitch on any failure below — WITHOUT that,
     * cleanup_killswitch's `!killswitch_active` early-return would skip
     * the anchor flush and leave the block-everything rules resident (and
     * live, if pf happens to already be enabled by another holder), with
     * no later call site left to remove them. Exactly the pattern Linux's
     * setup_killswitch uses on its own first failure (killswitch.c:57-60). */
    char cap[256];
    const char *enable_argv[] = {"pfctl", "-E", NULL};
    if (run_pfctl_capture(enable_argv, cap, sizeof(cap)) < 0) {
        LOG_WRN("failed to enable pf (pfctl -E)");
        p->killswitch_active = 1;
        cleanup_killswitch(p);
        return -1;
    }

    /* Token line format ("Token : <N>") and which stream it lands on are
     * both unverified on real hardware (item 2, file header) —
     * run_pfctl_capture already merged both streams into `cap`. Keep the
     * match strict (exact "Token : " casing/spacing) rather than guessing
     * at case-insensitive variants; if the real format differs this simply
     * falls through to the non-fatal empty-token path below. */
    const char *tok = strstr(cap, "Token : ");
    if (tok) {
        tok += strlen("Token : ");
        /* Every tok[i] read below is bounded by toklen first (cap is
         * NUL-terminated by run_pfctl_capture, so strlen is safe), keeping
         * the index-before-bound ordering explicit. */
        size_t toklen = strlen(tok);
        size_t i = 0;
        while (i < toklen && i < sizeof(p->ks_pf_token) - 1 && tok[i] >= '0' &&
               tok[i] <= '9') {
            p->ks_pf_token[i] = tok[i];
            i++;
        }
        p->ks_pf_token[i] = '\0';
        /* Digit run truncated (buffer filled while the next source char is
         * still a digit): a wrong token is worse than none — cleanup's
         * `pfctl -X <wrong>` would fail (or decrement the wrong reference)
         * with no diagnostic, whereas the empty-token path below at least
         * WRNs and documents the leaked reference. Discard it. */
        if (i == sizeof(p->ks_pf_token) - 1 && i < toklen && tok[i] >= '0' &&
            tok[i] <= '9')
            p->ks_pf_token[0] = '\0';
    }
    if (p->ks_pf_token[0] == '\0') {
        /* NON-FATAL: pf is already enabled and the anchor already loaded,
         * so the kill switch IS active regardless of whether the token was
         * captured. Losing the token only degrades cleanup's precision —
         * see cleanup_killswitch for what happens then. */
        LOG_WRN("pfctl -E enabled pf but no reference token could be parsed from its "
                "output; kill switch remains active with an empty token");
    }

    p->killswitch_active = 1;
    LOG_INF("kill switch enabled (pf anchor %s)", MQVPN_PF_ANCHOR);
    return 0;
}

void
cleanup_killswitch(platform_ctx_t *p)
{
    if (!p->killswitch_active) return;

    /* Idempotent by design (fixed anchor name; flushing an already-empty
     * or nonexistent anchor is a harmless no-op), so failures here are not
     * treated specially. */
    const char *flush_argv[] = {"pfctl", "-a", MQVPN_PF_ANCHOR, "-F", "all", NULL};
    (void)run_pfctl(flush_argv);

    if (p->ks_pf_token[0] != '\0') {
        const char *disable_argv[] = {"pfctl", "-X", p->ks_pf_token, NULL};
        (void)run_pfctl(disable_argv);
        p->ks_pf_token[0] = '\0';
    } else {
        /* No token (setup_killswitch's non-fatal empty-token path, or a
         * partial-failure path that never reached the `pfctl -E` call at
         * all) — item 3 (file header): `pfctl -X <token>` is the correct
         * precise decrement of the reference count `pfctl -E` incremented,
         * but with no token we cannot issue it. `pfctl -d` is NOT an
         * acceptable substitute: it force-disables pf outright, dropping
         * every OTHER holder's enable reference too (macOS's own
         * Application Firewall / other VPN clients / a user's manual
         * `pfctl -e`), which is a strictly worse outcome than what we're
         * trying to avoid. The judgment call is that this is safe to leave
         * alone: the anchor flush above already removed every filtering
         * rule this process ever added, so the lingering +1 reference
         * count has no observable effect on traffic — it only means `pfctl
         * -d` (issued by someone else, later) will leave pf enabled one
         * reference longer than it "should". UNVERIFIED on real hardware
         * (item 3, file header): confirm pf's reference counting actually
         * behaves this way before relying on it in production. */
        LOG_WRN("kill switch cleanup: no pf enable token captured; flushed anchor %s "
                "but leaving pf's enable reference count as-is (leaked +1, harmless — "
                "no filtering rules remain after the flush)",
                MQVPN_PF_ANCHOR);
    }

    p->killswitch_active = 0;
    LOG_INF("kill switch rules removed");
}

void
kill_switch_flush_stale_anchor(void)
{
    /* Unconditional flush, independent of any platform_ctx_t state — see
     * the file header's crash-residue note. This is deliberately a startup
     * step (darwin_platform_run_client's stale-recovery block) and NOT
     * part of setup_killswitch(), for two reasons:
     *   (a) setup_killswitch only runs once the tunnel is up, but a stale
     *       blocking anchor can prevent the connection from ever reaching
     *       tunnel-up in the first place (e.g. this run's server differs
     *       from the one the stale rules whitelist);
     *   (b) a restart WITHOUT --kill-switch never calls setup_killswitch
     *       at all, yet must still recover the host's connectivity.
     * A nonexistent/empty anchor failing this call is the NORMAL case
     * (most starts are not recovering from a crash), so failures are
     * logged at DBG, not WRN/ERR. */
    const char *argv[] = {"pfctl", "-a", MQVPN_PF_ANCHOR, "-F", "all", NULL};
    if (run_pfctl(argv) < 0)
        LOG_DBG("pf anchor %s flush at startup: no-op (anchor empty/absent) or pfctl "
                "unavailable",
                MQVPN_PF_ANCHOR);
}
