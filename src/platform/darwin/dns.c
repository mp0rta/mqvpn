// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * dns.c — networksetup(8)-driven DNS override for the Darwin (macOS) client
 *
 * Twin of linux/dns.c, but macOS has no single resolv.conf to swap: DNS is
 * configured per network *service* (e.g. "Wi-Fi", "USB 10/100/1000 LAN")
 * via `networksetup -setdnsservers <service> <server...>`, and those
 * changes are written into each service's persistent preferences — they
 * survive a reboot, unlike Linux's /etc/resolv.conf rewrite. That single
 * fact drives every divergence from the Linux implementation below:
 *
 *   - the backup file MUST live in a persistent location (/var/db), not
 *     the tmpfs /var/run that Linux-style code might reach for by default;
 *   - because networksetup changes outlive a crash AND a reboot, the
 *     startup stale-backup recovery path (mqvpn_dns_restore_stale) is the
 *     ONLY crash-recovery mechanism — there is no "next boot rewrites it
 *     anyway" safety net;
 *   - backup covers N independent services instead of 1 file, so partial
 *     failure (some services reverted, some not) is a real, meaningful
 *     state that Linux's single-file copy never has to represent.
 *
 * State machine fields (mqvpn_dns_t, shared with Linux/Windows):
 *   active   — 1 iff system DNS may currently be dirtied by our changes.
 *   lock_fd  — flock() fd on lock_path, held for the entire "may be
 *              dirtied" interval; -1 when not held.
 *   file existence of backup_path — the sole third bit of state (no
 *   additional flags are introduced here; see the "one writer" note).
 */
#include "dns.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>

/* Service names as reported by `networksetup -listallnetworkservices`. */
#define MQVPN_DNS_SVC_MAX 128
/* `-listallnetworkservices` output capture (one name per line). */
#define MQVPN_DNS_LIST_CAP 4096
/* `-getdnsservers <service>` output capture / joined-servers value. */
#define MQVPN_DNS_GETDNS_CAP 512
/* One backup line: "<service>\t<servers>\n" + NUL. Derived from the
 * component caps so the constants always compose: worst case is
 * (SVC_MAX-1) service bytes + '\t' + (GETDNS_CAP-1) servers bytes +
 * '\n' + NUL = SVC_MAX + GETDNS_CAP + 1; the +2 leaves one spare byte. */
#define MQVPN_DNS_BACKUP_LINE (MQVPN_DNS_SVC_MAX + MQVPN_DNS_GETDNS_CAP + 2)
/* Upper bound on enumerated network services; deliberately generous —
 * truncation only logs a warning, it never corrupts state. */
#define MQVPN_DNS_MAX_SERVICES 64
/* Upper bound on whitespace-separated server tokens when restoring a
 * saved value (a machine's *original* DNS config, before mqvpn touched
 * it, is not bounded by MQVPN_DNS_MAX_SERVERS — that constant only caps
 * how many VPN-provided servers mqvpn itself will configure). */
#define MQVPN_DNS_RESTORE_MAX_TOKENS 16
/* "<backup_path>.tmp" scratch buffer. */
#define MQVPN_DNS_TMP_PATH_MAX 512

struct dns_service {
    char name[MQVPN_DNS_SVC_MAX];
};

/* ------------------------------------------------------------------ */
/* exec helpers — twins of routing.c's run_route_cmd / discover_route,  */
/* targeting "networksetup" instead of "route".                        */
/* ------------------------------------------------------------------ */

static int
run_networksetup(const char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        /* Child inherits the client's process-wide SIGPIPE ignore (SIG_IGN
         * survives exec) DELIBERATELY: during shutdown our stdout/stderr
         * can be a dead pipe, and networksetup(8) writing diagnostics
         * there must get EPIPE, not die before restoring DNS — same
         * rationale as routing.c's run_route_cmd. */
        execvp("networksetup", (char *const *)argv);
        _exit(127);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0)
        if (errno != EINTR) return -1;
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

static int
run_networksetup_capture(const char *const argv[], char *out, size_t outlen)
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
        close(fds[1]);
        /* SIGPIPE stays SIG_IGN (inherited) — see run_networksetup. */
        execvp("networksetup", (char *const *)argv);
        _exit(127);
    }

    close(fds[1]);

    /* Read until EOF — a single read() may return only a partial pipe
     * buffer, and a partially captured `-getdnsservers` output could
     * record a real DNS config as "Empty" in the authoritative backup
     * (a later restore would then clear the user's actual DNS). Retry
     * EINTR; if the buffer fills before EOF, fail loudly rather than
     * silently truncating. */
    size_t used = 0;
    int read_failed = 0;
    int overflowed = 0;
    for (;;) {
        if (used >= outlen - 1) {
            /* Buffer full — probe one more byte to distinguish "output
             * exactly fits" from truncation. */
            char probe;
            ssize_t r = read(fds[0], &probe, 1);
            if (r < 0) {
                if (errno == EINTR) continue;
                read_failed = 1;
            } else if (r > 0) {
                overflowed = 1;
            }
            break;
        }
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
    if (read_failed || overflowed) {
        LOG_ERR("dns: networksetup output capture %s",
                overflowed ? "overflowed the buffer" : "read failed");
        return -1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return -1;

    out[used] = '\0';
    return 0;
}

/* ------------------------------------------------------------------ */
/* durability                                                           */
/* ------------------------------------------------------------------ */

static int
durability_flush(int fd)
{
    /* F_FULLFSYNC asks the drive itself to flush its write cache to
     * stable storage. Plain fsync() on macOS only pushes dirty pages out
     * of the kernel page cache to the drive's *volatile* write buffer —
     * it does NOT guarantee the data has reached platter/flash, so a
     * power loss immediately after a "successful" fsync() can still lose
     * the write. F_FULLFSYNC is the primitive that gives an actual
     * durability guarantee on APFS/HFS+. */
    if (fcntl(fd, F_FULLFSYNC) == 0) return 0;

    if (errno == ENOTSUP || errno == EINVAL || errno == ENOTTY) {
        /* The underlying filesystem doesn't implement F_FULLFSYNC (some
         * network/exotic filesystems) — fall back to the weaker fsync().
         * Any OTHER F_FULLFSYNC failure is a real I/O error and must
         * propagate as-is: a strong primitive's reported error must never
         * be silently overridden by a weak primitive's success. */
        return fsync(fd);
    }
    return -1;
}

/* Parent directory of `path`, for fsync-ing the directory entry after a
 * rename(). Falls back to "." if `path` has no '/'. */
static void
parent_dir(const char *path, char *out, size_t outlen)
{
    const char *slash = strrchr(path, '/');
    if (!slash) {
        snprintf(out, outlen, ".");
        return;
    }
    if (slash == path) {
        snprintf(out, outlen, "/");
        return;
    }
    size_t len = (size_t)(slash - path);
    if (len >= outlen) len = outlen - 1;
    memcpy(out, path, len);
    out[len] = '\0';
}

static int
write_all(int fd, const char *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* backup line format — single source of truth shared with dns.h's     */
/* mqvpn_dns_backup_format_line / mqvpn_dns_backup_parse_line, so unit  */
/* tests can exercise them directly.                                    */
/* ------------------------------------------------------------------ */

int
mqvpn_dns_backup_format_line(char *buf, size_t buflen, const char *service,
                             const char *servers)
{
    if (!buf || buflen == 0 || !service || !servers) return -1;
    if (service[0] == '\0') return -1;
    /* TAB is the field separator and newline is the line terminator —
     * either inside `service` would corrupt the one-line-per-service
     * format. `servers` is our own joined-IP-literal value (or the
     * literal "Empty") and never contains a TAB, but a stray newline
     * would still split one logical record into two lines, so guard it
     * too. */
    if (strchr(service, '\t') || strchr(service, '\n')) return -1;
    if (strchr(servers, '\n')) return -1;

    int n = snprintf(buf, buflen, "%s\t%s\n", service, servers);
    if (n < 0 || (size_t)n >= buflen) return -1;
    return 0;
}

int
mqvpn_dns_backup_parse_line(const char *line, char *service, size_t svc_len,
                            char *servers, size_t srv_len)
{
    if (!line || !service || !servers || svc_len == 0 || srv_len == 0) return -1;

    const char *tab = strchr(line, '\t');
    if (!tab) return -1;

    size_t slen = (size_t)(tab - line);
    if (slen == 0 || slen >= svc_len) return -1;
    memcpy(service, line, slen);
    service[slen] = '\0';

    const char *val = tab + 1;
    size_t vlen = strlen(val);
    while (vlen > 0 && (val[vlen - 1] == '\n' || val[vlen - 1] == '\r'))
        vlen--;
    if (vlen >= srv_len) return -1;
    memcpy(servers, val, vlen);
    servers[vlen] = '\0';
    return 0;
}

/* ------------------------------------------------------------------ */
/* service enumeration                                                  */
/* ------------------------------------------------------------------ */

static int
list_services(struct dns_service *out, int max_out)
{
    const char *argv[] = {"networksetup", "-listallnetworkservices", NULL};
    char cap[MQVPN_DNS_LIST_CAP];
    if (run_networksetup_capture(argv, cap, sizeof(cap)) < 0) {
        LOG_ERR("dns: networksetup -listallnetworkservices failed");
        return -1;
    }

    /* Verified on macOS 26.5: output is one explanatory header line —
     * "An asterisk (*) denotes that a network service is disabled." —
     * followed by one service name per line, with a leading '*' marking
     * a disabled service. Skip the header (first line) unconditionally and
     * any '*'-prefixed (disabled) service. */
    int n = 0;
    int first = 1;
    char *saveptr = NULL;
    for (char *line = strtok_r(cap, "\r\n", &saveptr); line;
         line = strtok_r(NULL, "\r\n", &saveptr)) {
        if (first) {
            first = 0;
            continue;
        }
        if (line[0] == '\0' || line[0] == '*') continue;

        if (n >= max_out) {
            LOG_WRN("dns: more than %d network services enumerated, truncating", max_out);
            break;
        }
        if (strlen(line) >= sizeof(out[n].name)) {
            /* A truncated name would target a nonexistent service in
             * every later networksetup call — downstream failure is safe
             * (set fails → rollback; snapshot fails → apply aborts) but
             * would be undiagnosable without this breadcrumb. */
            LOG_WRN("dns: service name longer than %zu bytes truncated: '%s'",
                    sizeof(out[n].name) - 1, line);
        }
        snprintf(out[n].name, sizeof(out[n].name), "%s", line);
        n++;
    }
    return n;
}

/* Fetch the current DNS servers for `service` and format them into `out`
 * as the backup "servers" value: space-joined IP literals, or the literal
 * "Empty" for an unset/unrecognized state. */
static int
get_dns_servers(const char *service, char *out, size_t outlen)
{
    const char *argv[] = {"networksetup", "-getdnsservers", service, NULL};
    char cap[MQVPN_DNS_GETDNS_CAP];
    if (run_networksetup_capture(argv, cap, sizeof(cap)) < 0) {
        LOG_ERR("dns: networksetup -getdnsservers '%s' failed", service);
        return -1;
    }

    /* Verified on macOS 26.5: the "no servers configured" output is the
     * sentence "There aren't any DNS Servers set on <service>." Rather than
     * matching that exact string (fragile across locales/macOS versions),
     * match liberally: ANY output that isn't a clean list of IP literals
     * (one per line, per `-getdnsservers`'s documented success format) is
     * treated as "Empty". This is intentionally permissive so an
     * unrecognized or localized sentence can never be misparsed as a bogus
     * DNS server. */
    char joined[MQVPN_DNS_GETDNS_CAP];
    joined[0] = '\0';
    size_t used = 0;
    int have_any = 0;
    int all_ip = 1;

    char *saveptr = NULL;
    for (char *line = strtok_r(cap, "\r\n", &saveptr); line;
         line = strtok_r(NULL, "\r\n", &saveptr)) {
        while (*line == ' ' || *line == '\t')
            line++;
        if (line[0] == '\0') continue;

        unsigned char scratch[sizeof(struct in6_addr)];
        if (inet_pton(AF_INET, line, scratch) != 1 &&
            inet_pton(AF_INET6, line, scratch) != 1) {
            all_ip = 0;
            break;
        }
        have_any = 1;

        size_t llen = strlen(line);
        size_t need = used + (used > 0 ? 1 : 0) + llen;
        if (need >= sizeof(joined)) {
            /* Joining would overflow: a truncated snapshot would silently
             * misrepresent the service's original config, and the backup
             * is the sole restore authority — fail loudly instead. The
             * caller (write_backup) aborts backup creation, which aborts
             * apply() before any setdnsservers runs (hard precondition). */
            LOG_ERR("dns: DNS server list for service '%s' exceeds %zu bytes; "
                    "refusing lossy backup",
                    service, sizeof(joined));
            return -1;
        }
        if (used > 0) joined[used++] = ' ';
        memcpy(joined + used, line, llen);
        used += llen;
        joined[used] = '\0';
    }

    if (!have_any || !all_ip) {
        snprintf(out, outlen, "Empty");
        return 0;
    }
    if (used >= outlen) {
        /* Same loud-failure rule for the caller-supplied buffer. */
        LOG_ERR("dns: DNS server list for service '%s' exceeds %zu bytes; "
                "refusing lossy backup",
                service, outlen);
        return -1;
    }
    snprintf(out, outlen, "%s", joined);
    return 0;
}

/* ------------------------------------------------------------------ */
/* lock                                                                  */
/* ------------------------------------------------------------------ */

static int
acquire_lock(mqvpn_dns_t *dns)
{
    /* If we already hold the lock (e.g. a previous restore() attempt
     * failed and left active=1 + lock_fd held, and the caller is now
     * retrying apply()), reuse the existing fd rather than re-acquiring:
     * flock() is per-*process* on the BSDs' semantics we rely on here in
     * the sense that a second LOCK_EX from the same already-holding
     * process context would otherwise need careful fd bookkeeping to
     * avoid a double-acquire hang or leaking the original fd. */
    if (dns->lock_fd >= 0) return 0;

    int lfd = open(dns->lock_path, O_CREAT | O_RDWR, 0644);
    if (lfd < 0) {
        /* %m is a glibc extension — Apple Libc prints it literally, so
         * all errno diagnostics in this file use strerror() instead
         * (errno captured immediately, before any call can clobber it).
         *
         * Intentional divergence from Linux dns.c (which warns and
         * continues WITHOUT the lock when the lock file can't be
         * created): here the lock protects the authoritative backup
         * that is a hard precondition for mutating DNS at all, so
         * proceeding unlocked is not acceptable — abort instead. */
        int e = errno;
        LOG_ERR("dns: cannot open lock file %s: %s", dns->lock_path, strerror(e));
        return -1;
    }
    if (flock(lfd, LOCK_EX | LOCK_NB) < 0) {
        LOG_ERR("dns: another mqvpn instance is managing DNS (lock: %s)", dns->lock_path);
        close(lfd);
        return -1;
    }
    dns->lock_fd = lfd;
    return 0;
}

static void
release_lock(mqvpn_dns_t *dns)
{
    if (dns->lock_fd < 0) return;
    close(dns->lock_fd);
    dns->lock_fd = -1;
    unlink(dns->lock_path);
}

/* FAILURE POLICY (applies to every mqvpn_dns_apply() abort path): lock
 * lifetime is "the interval during which system DNS may be dirtied by our
 * changes" — i.e. exactly while `active` is 1. If we're aborting with
 * active still 0 (nothing was ever mutated), the lock must be released so
 * it doesn't block later recovery or another process. If active is 1
 * (step-5 rollback failed, or a failed re-apply after an earlier failed
 * restore), the lock must be kept. */
static void
release_lock_if_inactive(mqvpn_dns_t *dns)
{
    if (!dns->active) release_lock(dns);
}

/* ------------------------------------------------------------------ */
/* backup file: validate / write / restore-from                        */
/* ------------------------------------------------------------------ */

static int
validate_existing_backup(const mqvpn_dns_t *dns)
{
    FILE *fp = fopen(dns->backup_path, "r");
    if (!fp) {
        int e = errno;
        LOG_ERR("dns: backup %s exists but could not be opened: %s", dns->backup_path,
                strerror(e));
        return -1;
    }

    char line[MQVPN_DNS_BACKUP_LINE];
    char svc[MQVPN_DNS_SVC_MAX], srv[MQVPN_DNS_GETDNS_CAP];
    int lineno = 0;
    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        /* Overlong-line fragment guard: an fgets() that fills the buffer
         * without reaching '\n' (and not at EOF) returned only a fragment
         * of a physical line — the logical line is unparseable as a
         * whole, and the leftover tail must not be misread as a second
         * line. */
        if (!strchr(line, '\n') && !feof(fp)) {
            LOG_ERR("dns: existing backup %s line %d exceeds %d bytes — it may be the "
                    "only copy of your original DNS settings; inspect or move the file "
                    "manually, then retry",
                    dns->backup_path, lineno, MQVPN_DNS_BACKUP_LINE - 1);
            fclose(fp);
            return -1;
        }
        if (mqvpn_dns_backup_parse_line(line, svc, sizeof(svc), srv, sizeof(srv)) < 0) {
            LOG_ERR("dns: existing backup %s line %d is unparseable — it may be the "
                    "only copy of your original DNS settings; inspect or move the file "
                    "manually, then retry",
                    dns->backup_path, lineno);
            fclose(fp);
            return -1;
        }
    }
    /* An I/O error can end the fgets loop early, silently vouching for
     * lines that were never actually read — that must not count as a
     * successful validation. */
    if (ferror(fp)) {
        LOG_ERR("dns: read error while validating backup %s", dns->backup_path);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

static int
write_backup(const mqvpn_dns_t *dns, const char *tmp_path, const struct dns_service *svcs,
             int n)
{
    /* Only ENOENT ("nothing to clean up") is success-equivalent here; any
     * other unlink() errno means we can't be sure O_EXCL below will
     * actually create a fresh file, so it's a hard failure. */
    if (unlink(tmp_path) < 0 && errno != ENOENT) {
        int e = errno;
        LOG_ERR("dns: cannot remove stale %s: %s", tmp_path, strerror(e));
        return -1;
    }

    int fd = open(tmp_path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0) {
        int e = errno;
        LOG_ERR("dns: cannot create %s: %s", tmp_path, strerror(e));
        return -1;
    }

    for (int i = 0; i < n; i++) {
        char servers_val[MQVPN_DNS_GETDNS_CAP];
        if (get_dns_servers(svcs[i].name, servers_val, sizeof(servers_val)) < 0) {
            close(fd);
            unlink(tmp_path);
            return -1;
        }
        char line[MQVPN_DNS_BACKUP_LINE];
        if (mqvpn_dns_backup_format_line(line, sizeof(line), svcs[i].name, servers_val) <
            0) {
            LOG_ERR("dns: cannot format backup line for service '%s'", svcs[i].name);
            close(fd);
            unlink(tmp_path);
            return -1;
        }
        if (write_all(fd, line, strlen(line)) < 0) {
            int e = errno;
            LOG_ERR("dns: write to %s failed: %s", tmp_path, strerror(e));
            close(fd);
            unlink(tmp_path);
            return -1;
        }
    }

    if (durability_flush(fd) < 0) {
        int e = errno;
        LOG_ERR("dns: durability flush of %s failed: %s", tmp_path, strerror(e));
        close(fd);
        unlink(tmp_path);
        return -1;
    }
    close(fd);

    if (rename(tmp_path, dns->backup_path) < 0) {
        int e = errno;
        LOG_ERR("dns: rename %s -> %s failed: %s", tmp_path, dns->backup_path,
                strerror(e));
        unlink(tmp_path);
        return -1;
    }

    /* Durability also requires flushing the parent directory: a renamed
     * file whose data has been fsync'd but whose containing directory
     * entry hasn't can, on crash, leave the directory pointing at the old
     * name (or nothing) even though the file's own bytes reached disk. */
    char dirbuf[MQVPN_DNS_TMP_PATH_MAX];
    parent_dir(dns->backup_path, dirbuf, sizeof(dirbuf));
    int dirfd = open(dirbuf, O_RDONLY);
    if (dirfd < 0) {
        int e = errno;
        LOG_ERR("dns: cannot open %s for durability flush: %s", dirbuf, strerror(e));
        return -1;
    }
    int rc = durability_flush(dirfd);
    int flush_errno = errno; /* capture before close() can clobber it */
    close(dirfd);
    if (rc < 0) {
        LOG_ERR("dns: durability flush of %s failed: %s", dirbuf, strerror(flush_errno));
        return -1;
    }
    return 0;
}

/* Does the (already validated) pre-existing backup contain a line for
 * `name`? GUARD-path helper for mqvpn_dns_apply step 4: a service with no
 * backup line has NO restore path — once its DNS is overwritten, nothing
 * ever reverts it, and a later successful restore unlinks the backup while
 * that service is still dirty. validate_existing_backup() already rejected
 * unparseable/overlong lines, so a plain per-line parse suffices here. */
static int
backup_has_service(const mqvpn_dns_t *dns, const char *name)
{
    FILE *fp = fopen(dns->backup_path, "r");
    if (!fp) return 0;

    char line[MQVPN_DNS_BACKUP_LINE];
    char svc[MQVPN_DNS_SVC_MAX], srv[MQVPN_DNS_GETDNS_CAP];
    int found = 0;
    while (!found && fgets(line, sizeof(line), fp)) {
        if (mqvpn_dns_backup_parse_line(line, svc, sizeof(svc), srv, sizeof(srv)) == 0 &&
            strcmp(svc, name) == 0)
            found = 1;
    }
    fclose(fp);
    return found;
}

/* Issue `networksetup -setdnsservers <service> <servers...>` for one
 * saved backup value. `servers` is either the literal "Empty" (passed
 * through as-is) or a space-joined list of IP literals, which we split
 * back into separate argv entries. Shared by apply()'s self-rollback,
 * mqvpn_dns_restore(), and mqvpn_dns_restore_stale().
 *
 * UNVERIFIED on real macOS hardware: the "Empty" unset semantics —
 * `networksetup -setdnsservers <service> Empty` clearing the service's
 * DNS override back to "no servers set" — is taken from networksetup(8)
 * documentation and common usage, not verified against a real Mac.
 * Confirm before relying on this in production. */
static int
restore_one(const char *service, const char *servers)
{
    const char *argv[3 + MQVPN_DNS_RESTORE_MAX_TOKENS + 1];
    int argc = 0;
    argv[argc++] = "networksetup";
    argv[argc++] = "-setdnsservers";
    argv[argc++] = service;

    char buf[MQVPN_DNS_GETDNS_CAP];
    snprintf(buf, sizeof(buf), "%s", servers);

    if (strcmp(buf, "Empty") == 0) {
        argv[argc++] = "Empty";
    } else {
        char *saveptr = NULL;
        for (char *tok = strtok_r(buf, " ", &saveptr); tok;
             tok = strtok_r(NULL, " ", &saveptr)) {
            if (argc >= (int)(sizeof(argv) / sizeof(argv[0])) - 1) {
                /* More saved tokens than we can pass — restoring only a
                 * prefix would silently misrepresent the original config;
                 * fail loudly instead (counts as a restore failure, so
                 * the backup is kept). */
                LOG_ERR("dns: backup entry for service '%s' has more than %d server "
                        "tokens; refusing lossy restore",
                        service, MQVPN_DNS_RESTORE_MAX_TOKENS);
                return -1;
            }
            argv[argc++] = tok;
        }
    }
    argv[argc] = NULL;

    if (run_networksetup(argv) < 0) {
        LOG_ERR("dns: networksetup -setdnsservers restore failed for service '%s'",
                service);
        return -1;
    }
    return 0;
}

/* Reads dns->backup_path and restores each listed service's original DNS
 * setting via restore_one().
 *
 * If `filter` is non-NULL, only services whose name appears in
 * filter[0..filter_n) are restored — used ONLY by apply()'s FRESH-path
 * self-rollback, where the backup was created by that same apply() call
 * and therefore exactly matches the pre-apply state, so touching only
 * the subset possibly changed is complete by construction. Pass
 * filter=NULL to restore every line in the backup (mqvpn_dns_restore(),
 * mqvpn_dns_restore_stale(), and apply()'s GUARD-path rollback, where a
 * pre-existing backup may cover services dirtied before this process's
 * apply ever ran — see the step-5 comment in mqvpn_dns_apply()).
 *
 * An unparseable backup line is logged and treated as a failed restore
 * for that service (its data can't be recovered), but does not abort the
 * remaining lines — every line gets a restore attempt.
 *
 * Returns 0 iff every attempted restore succeeded, -1 otherwise. */
static int
restore_from_backup_file(const mqvpn_dns_t *dns, const struct dns_service *filter,
                         int filter_n)
{
    FILE *fp = fopen(dns->backup_path, "r");
    if (!fp) {
        int e = errno;
        LOG_ERR("dns: cannot open backup %s: %s", dns->backup_path, strerror(e));
        return -1;
    }

    int ok = 1;
    char line[MQVPN_DNS_BACKUP_LINE];
    int lineno = 0;
    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        /* Overlong-line fragment guard (see validate_existing_backup):
         * treat the whole logical line as unparseable, and consume the
         * remainder of the physical line so its tail isn't misread as
         * the next record. */
        if (!strchr(line, '\n') && !feof(fp)) {
            LOG_ERR("dns: backup %s line %d exceeds %d bytes, skipping that service",
                    dns->backup_path, lineno, MQVPN_DNS_BACKUP_LINE - 1);
            ok = 0;
            int c;
            while ((c = fgetc(fp)) != EOF && c != '\n')
                ;
            continue;
        }
        char svc[MQVPN_DNS_SVC_MAX], srv[MQVPN_DNS_GETDNS_CAP];
        if (mqvpn_dns_backup_parse_line(line, svc, sizeof(svc), srv, sizeof(srv)) < 0) {
            LOG_ERR("dns: backup %s line %d is unparseable, skipping that service",
                    dns->backup_path, lineno);
            ok = 0;
            continue;
        }

        if (filter) {
            int found = 0;
            for (int i = 0; i < filter_n; i++) {
                if (strcmp(filter[i].name, svc) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found) continue;
        }

        if (restore_one(svc, srv) < 0) ok = 0;
    }
    /* An I/O error can end the fgets loop before every backup line was
     * seen — services on the unread lines got no restore attempt, so
     * this must NOT count as full restore success (the backup has to
     * survive for a retry). */
    if (ferror(fp)) {
        LOG_ERR("dns: read error while restoring from backup %s", dns->backup_path);
        ok = 0;
    }
    fclose(fp);
    return ok ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* public API                                                           */
/* ------------------------------------------------------------------ */

void
mqvpn_dns_init(mqvpn_dns_t *dns)
{
    memset(dns, 0, sizeof(*dns));
    dns->lock_fd = -1;

    /* Darwin has no single resolv.conf to swap out; DNS is driven
     * entirely per-service via networksetup(8). */
    dns->resolv_path = NULL;
    dns->use_resolvectl = 0;

    /* Backup MUST live in /var/db (persistent storage), NOT /var/run:
     * macOS mounts /var/run as tmpfs and wipes it on every boot, but
     * networksetup DNS changes are written into each network service's
     * persistent preferences and DO survive a reboot. If the backup lived
     * in /var/run and mqvpn crashed mid-apply, a reboot would silently
     * destroy the only record of the user's original DNS settings before
     * mqvpn_dns_restore_stale() ever got a chance to run — permanently
     * stranding the dirtied services. /var/db is the durable location
     * this crash-recovery design requires. */
    dns->backup_path = "/var/db/mqvpn-dns.bak";

    /* The lock, by contrast, is correctly volatile: flock() is scoped to
     * process liveness and is released by the kernel the moment the
     * holding process dies, so a stale lock can never survive to falsely
     * block startup recovery — /var/run is the right (and simpler)
     * location for it. */
    dns->lock_path = "/var/run/mqvpn-dns.lock";
}

int
mqvpn_dns_apply(mqvpn_dns_t *dns)
{
    if (dns->n_servers == 0) return 0; /* nothing to do */

    /* Step 1: exclusive lock, protecting against a second mqvpn instance
     * destroying our backup (or us destroying its backup). Reuses an
     * already-held lock instead of re-acquiring — see acquire_lock(). */
    if (acquire_lock(dns) < 0) return -1;

    /* Step 2: enumerate services, skipping the explanatory header line
     * and any service prefixed '*' (disabled). Used both for the step-3
     * snapshot and the step-4 set loop. */
    struct dns_service svcs[MQVPN_DNS_MAX_SERVICES];
    int n = list_services(svcs, MQVPN_DNS_MAX_SERVICES);
    if (n < 0) {
        release_lock_if_inactive(dns);
        return -1;
    }
    if (n == 0) {
        /* No network services to configure DNS on at all — there is
         * nothing meaningful step 4 could do, and proceeding would set
         * `active` only if at least one set succeeds, which can never
         * happen with zero services. Treat as a failure rather than a
         * silent success that leaves nothing configured. */
        LOG_ERR("dns: no network services enumerated, nothing to configure");
        release_lock_if_inactive(dns);
        return -1;
    }

    char tmp_path[MQVPN_DNS_TMP_PATH_MAX];
    if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", dns->backup_path) >=
        (int)sizeof(tmp_path)) {
        LOG_ERR("dns: backup path too long");
        release_lock_if_inactive(dns);
        return -1;
    }

    /* Step 3 GUARD: an existing backup is the authoritative original from
     * a prior (crashed or otherwise incomplete) run — it must never be
     * overwritten. `preexisting_backup` is a function-local (not a new
     * struct field — the persistent state stays exactly active/lock_fd/
     * backup-file-existence) recording which case we're in, because
     * step 5's rollback SCOPE depends on it. */
    int preexisting_backup = 0;
    if (access(dns->backup_path, F_OK) == 0) {
        preexisting_backup = 1;
        /* (a) Unconditionally clean up a stale .tmp — the cleanup
         * invariant holds on the guard path too, even though we're not
         * about to write a fresh backup ourselves. */
        if (unlink(tmp_path) < 0 && errno != ENOENT) {
            int e = errno;
            LOG_ERR("dns: cannot remove stale %s: %s", tmp_path, strerror(e));
            release_lock_if_inactive(dns);
            return -1;
        }
        /* (b) Parse-validate EVERY line before doing anything else: the
         * file may be the only copy of the original DNS settings, so we
         * can neither discard it nor mutate DNS while its authority is
         * unprovable. */
        if (validate_existing_backup(dns) < 0) {
            release_lock_if_inactive(dns);
            return -1;
        }
        /* Existing backup validated OK — it is the authoritative
         * original; skip snapshot+backup creation entirely and fall
         * through to step 4. */
    } else {
        /* No existing backup: snapshot every enumerated service's current
         * DNS setting and write it out atomically + durably. */
        if (write_backup(dns, tmp_path, svcs, n) < 0) {
            /* Hard precondition: never mutate a single service's DNS
             * without a valid, durable, authoritative backup on disk.
             * Unlike Linux dns.c's mqvpn_dns_apply (which warns and
             * continues when the resolv.conf backup fails — there's
             * always a live resolv.conf to eventually restore, worst
             * case by hand),
             * Darwin's backup is the ONLY record of N independent
             * services' original settings; losing it isn't recoverable
             * the same way, so we abort before touching anything. */
            release_lock_if_inactive(dns);
            return -1;
        }
    }

    /* Step 4: set the VPN's DNS servers on every enumerated service. */
    int applied;
    int set_count = 0;
    for (applied = 0; applied < n; applied++) {
        /* GUARD path: never touch a service the pre-existing backup has
         * no line for. It appeared after that backup was written (e.g.
         * between a crash and this restart), so no restore path could
         * ever revert it — overwriting would strand it on VPN DNS
         * permanently once the backup is consumed. */
        if (preexisting_backup && !backup_has_service(dns, svcs[applied].name)) {
            LOG_WRN("dns: service '%s' has no line in pre-existing backup %s; "
                    "leaving its DNS untouched",
                    svcs[applied].name, dns->backup_path);
            continue;
        }

        const char *argv[3 + MQVPN_DNS_MAX_SERVERS + 1];
        int argc = 0;
        argv[argc++] = "networksetup";
        argv[argc++] = "-setdnsservers";
        argv[argc++] = svcs[applied].name;
        for (int i = 0; i < dns->n_servers; i++)
            argv[argc++] = dns->servers[i];
        argv[argc] = NULL;

        if (run_networksetup(argv) < 0) {
            LOG_ERR("dns: networksetup -setdnsservers failed for service '%s'",
                    svcs[applied].name);
            break;
        }
        /* `active` transitions to 1 at the FIRST successful set, not at
         * loop completion: it means "system DNS may be dirtied by our
         * changes", which becomes true the instant we mutate anything —
         * not only once every service is done. */
        dns->active = 1;
        set_count++;
    }

    if (applied == n) {
        if (set_count == 0) {
            /* Every enumerated service was skipped by the GUARD filter:
             * nothing was dirtied (`active` never set), so nothing needs
             * rolling back — but reporting success would be a lie, and
             * the stale backup needs a later restore/startup attempt to
             * finally clear it. */
            LOG_WRN("dns: pre-existing backup %s covers none of the %d enumerated "
                    "service(s); DNS left untouched",
                    dns->backup_path, n);
            release_lock_if_inactive(dns);
            return -1;
        }
        LOG_INF("dns: configured %d server(s) across %d network service(s), backup at %s",
                dns->n_servers, set_count, dns->backup_path);
        return 0;
    }

    /* Step 5: a set failed mid-loop (services [0, applied) were already
     * changed) — self-rollback using the backup validated/created above.
     * The rollback SCOPE depends on which step-3 path we took:
     *
     *   FRESH path (this apply created the backup): before this call, all
     *   services matched the backup exactly, so only the [0, applied]
     *   subset — INCLUDING the service whose set was reported failed (a
     *   signal-killed networksetup can mutate state and still exit
     *   nonzero) — can be dirty; a subset-filtered rollback over those
     *   applied+1 services is complete by construction (applied < n
     *   always holds here, so applied+1 <= n, and restoring an unmutated
     *   service to its own fresh snapshot is idempotent).
     *
     *   GUARD path (backup pre-existed): the file is the authoritative
     *   original from an earlier run whose restore may itself have
     *   partially failed, i.e. services OUTSIDE [0, applied) may already
     *   be dirty from before this apply ever ran. A subset rollback here
     *   can "succeed" vacuously (worst case applied == 0, empty filter)
     *   while the system is still dirty — deleting the backup on that
     *   basis would permanently destroy the only record of the still-
     *   dirty services. So on the guard path the rollback must restore
     *   the FULL backup (filter=NULL), and only a fully successful full
     *   restore may declare DNS clean. */
    LOG_WRN("dns: apply failed after %d/%d service(s); rolling back", applied, n);
    int rolled_back;
    if (preexisting_backup)
        rolled_back = restore_from_backup_file(dns, NULL, 0);
    else
        rolled_back = restore_from_backup_file(dns, svcs, applied + 1);
    if (rolled_back == 0) {
        /* Rollback success: every service the backup covers is back to
         * its original setting — DNS is clean again, so the backup is no
         * longer needed and the lock can be released. */
        dns->active = 0;
        unlink(dns->backup_path);
        release_lock_if_inactive(dns);
        return -1;
    }

    /* Rollback failure: some services are still left with our VPN DNS
     * settings applied. Keep the backup file, keep `active` = 1, and keep
     * the lock — per the FAILURE POLICY, only the in-process restore
     * paths (disconnect cleanup and shutdown, both of which call
     * mqvpn_dns_restore()) should retry this, gated by `active`; a
     * follow-up connect attempt's apply() will also see lock_fd >= 0 and
     * reuse it rather than hang. Startup stale-backup recovery
     * (mqvpn_dns_restore_stale) is the post-crash last resort, not the
     * primary path for an in-process failure like this one. */
    dns->active = 1;
    LOG_ERR("dns: rollback failed; backup and lock retained for retry via restore");
    return -1;
}

void
mqvpn_dns_restore(mqvpn_dns_t *dns)
{
    if (!dns->active) return;

    if (restore_from_backup_file(dns, NULL, 0) == 0) {
        unlink(dns->backup_path);
        dns->active = 0;
        release_lock(dns);
        LOG_INF("dns: restored original DNS settings from %s", dns->backup_path);
        return;
    }

    /* Intentional divergence from Linux dns.c's mqvpn_dns_restore (which
     * clears `active` unconditionally, even on failure): a single resolv.conf copy
     * has no notion of partial failure, but a Darwin backup spans N
     * independent services, so a partial restore failure is a real and
     * meaningful state — some services now carry our VPN DNS settings
     * while others were reverted. Clearing `active` here would let a
     * caller believe DNS is fully clean and let the backup be discarded
     * or the lock released, permanently losing the only record of the
     * services that are still dirty. Keep backup + active + lock so a
     * later mqvpn_dns_restore() call can retry. */
    LOG_ERR("dns: restore incomplete; some service(s) could not be reverted — backup "
            "retained at %s for retry",
            dns->backup_path);
}

int
mqvpn_dns_has_stale_backup(const mqvpn_dns_t *dns)
{
    return !dns->active && access(dns->backup_path, F_OK) == 0;
}

void
mqvpn_dns_restore_stale(mqvpn_dns_t *dns)
{
    if (!mqvpn_dns_has_stale_backup(dns)) return;

    /* This startup path is the ONLY crash-recovery mechanism for Darwin
     * DNS: networksetup writes changes into each service's persistent
     * preferences, so they survive a reboot (unlike Linux's
     * resolv.conf-copy version, which the next boot's own network config
     * simply overwrites) — dependence on this path recovering correctly
     * is therefore higher here than on Linux. */
    LOG_WRN("dns: stale backup found at %s (crash or unclean shutdown), restoring at "
            "startup",
            dns->backup_path);

    /* mqvpn_dns_restore()'s `if (!active) return;` guard would make it a
     * no-op here (active is 0 at startup, before any connect), so drive
     * the restore machinery directly instead of calling it. */
    if (acquire_lock(dns) < 0) {
        LOG_ERR("dns: cannot acquire lock for stale-backup restore, leaving backup in "
                "place for the next attempt");
        return;
    }

    if (restore_from_backup_file(dns, NULL, 0) == 0) {
        unlink(dns->backup_path);
        LOG_INF("dns: restored original DNS settings from stale backup %s",
                dns->backup_path);
    } else {
        LOG_ERR("dns: stale-backup restore incomplete; some service(s) could not be "
                "reverted — backup retained at %s for the next attempt",
                dns->backup_path);
    }

    /* `active` stays 0 through this entire function (it was 0 on entry
     * and this path never sets it): unlike apply()'s FAILURE POLICY,
     * there is no in-process retry loop to hand off to at startup — the
     * connection hasn't even been attempted yet. Holding the lock forever
     * with active==0 would violate the lock's own lifetime contract
     * ("the interval during which system DNS may be dirtied by our
     * changes"), which is never true on this path. Release unconditionally,
     * on both success and partial failure. */
    release_lock(dns);
}
