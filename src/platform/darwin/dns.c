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
#include <errno.h>
#include <arpa/inet.h>

/* Service names as reported by `networksetup -listallnetworkservices`. */
#define MQVPN_DNS_SVC_MAX 128
/* `-listallnetworkservices` output capture (one name per line). */
#define MQVPN_DNS_LIST_CAP 4096
/* `-getdnsservers <service>` output capture / joined-servers value. */
#define MQVPN_DNS_GETDNS_CAP 512
/* One backup line: "<service>\t<servers>\n". */
#define MQVPN_DNS_BACKUP_LINE 640
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
        execvp("networksetup", (char *const *)argv);
        _exit(127);
    }

    close(fds[1]);
    ssize_t nread = read(fds[0], out, outlen - 1);
    close(fds[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0)
        if (errno != EINTR) return -1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || nread < 0) return -1;

    out[nread] = '\0';
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

    /* UNVERIFIED on real macOS hardware (no Darwin machine in this dev
     * environment): assumed output is one explanatory header line —
     * "An asterisk (*) denotes that a network service is disabled." —
     * followed by one service name per line, with a leading '*' marking
     * a disabled service. Skip both unconditionally. Verify against real
     * `networksetup -listallnetworkservices` output before relying on
     * this in production. */
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

    /* UNVERIFIED on real macOS hardware: the documented "no servers
     * configured" output is a sentence of the form "There aren't any DNS
     * Servers set on <service>.". Rather than matching that exact string
     * (fragile across locales/macOS versions), match liberally: ANY
     * output that isn't a clean list of IP literals (one per line, per
     * `-getdnsservers`'s documented success format) is treated as
     * "Empty". This is intentionally permissive so an unrecognized or
     * localized sentence can never be misparsed as a bogus DNS server. */
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
        if (used > 0 && used + 1 < sizeof(joined)) {
            joined[used++] = ' ';
            joined[used] = '\0';
        }
        if (used + llen < sizeof(joined)) {
            memcpy(joined + used, line, llen);
            used += llen;
            joined[used] = '\0';
        }
    }

    if (!have_any || !all_ip) {
        snprintf(out, outlen, "Empty");
        return 0;
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
        LOG_ERR("dns: cannot open lock file %s: %m", dns->lock_path);
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
        LOG_ERR("dns: backup %s exists but could not be opened: %m", dns->backup_path);
        return -1;
    }

    char line[MQVPN_DNS_BACKUP_LINE];
    char svc[MQVPN_DNS_SVC_MAX], srv[MQVPN_DNS_GETDNS_CAP];
    int lineno = 0;
    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        if (mqvpn_dns_backup_parse_line(line, svc, sizeof(svc), srv, sizeof(srv)) < 0) {
            LOG_ERR("dns: existing backup %s line %d is unparseable — it may be the "
                    "only copy of your original DNS settings; inspect or move the file "
                    "manually, then retry",
                    dns->backup_path, lineno);
            fclose(fp);
            return -1;
        }
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
        LOG_ERR("dns: cannot remove stale %s: %m", tmp_path);
        return -1;
    }

    int fd = open(tmp_path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0) {
        LOG_ERR("dns: cannot create %s: %m", tmp_path);
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
            LOG_ERR("dns: write to %s failed: %m", tmp_path);
            close(fd);
            unlink(tmp_path);
            return -1;
        }
    }

    if (durability_flush(fd) < 0) {
        LOG_ERR("dns: durability flush of %s failed: %m", tmp_path);
        close(fd);
        unlink(tmp_path);
        return -1;
    }
    close(fd);

    if (rename(tmp_path, dns->backup_path) < 0) {
        LOG_ERR("dns: rename %s -> %s failed: %m", tmp_path, dns->backup_path);
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
        LOG_ERR("dns: cannot open %s for durability flush: %m", dirbuf);
        return -1;
    }
    int rc = durability_flush(dirfd);
    close(dirfd);
    if (rc < 0) {
        LOG_ERR("dns: durability flush of %s failed: %m", dirbuf);
        return -1;
    }
    return 0;
}

/* Issue `networksetup -setdnsservers <service> <servers...>` for one
 * saved backup value. `servers` is either the literal "Empty" (passed
 * through as-is — that's networksetup's own "unset" argument) or a
 * space-joined list of IP literals, which we split back into separate
 * argv entries. Shared by apply()'s self-rollback, mqvpn_dns_restore(),
 * and mqvpn_dns_restore_stale(). */
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
        for (char *tok = strtok_r(buf, " ", &saveptr);
             tok && argc < (int)(sizeof(argv) / sizeof(argv[0])) - 1;
             tok = strtok_r(NULL, " ", &saveptr)) {
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
 * filter[0..filter_n) are restored (used by apply()'s self-rollback,
 * which must touch only the subset of services it actually changed
 * before the failure). Pass filter=NULL to restore every line in the
 * backup (used by mqvpn_dns_restore() and mqvpn_dns_restore_stale()).
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
        LOG_ERR("dns: cannot open backup %s: %m", dns->backup_path);
        return -1;
    }

    int ok = 1;
    char line[MQVPN_DNS_BACKUP_LINE];
    int lineno = 0;
    while (fgets(line, sizeof(line), fp)) {
        lineno++;
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
     * overwritten. */
    if (access(dns->backup_path, F_OK) == 0) {
        /* (a) Unconditionally clean up a stale .tmp — the cleanup
         * invariant holds on the guard path too, even though we're not
         * about to write a fresh backup ourselves. */
        if (unlink(tmp_path) < 0 && errno != ENOENT) {
            LOG_ERR("dns: cannot remove stale %s: %m", tmp_path);
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
             * Unlike Linux dns.c:273-275 (which warns and continues when
             * the resolv.conf backup fails — there's always a live
             * resolv.conf to eventually restore, worst case, by hand),
             * Darwin's backup is the ONLY record of N independent
             * services' original settings; losing it isn't recoverable
             * the same way, so we abort before touching anything. */
            release_lock_if_inactive(dns);
            return -1;
        }
    }

    /* Step 4: set the VPN's DNS servers on every enumerated service. */
    int applied;
    for (applied = 0; applied < n; applied++) {
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
    }

    if (applied == n) {
        LOG_INF("dns: configured %d server(s) across %d network service(s), backup at %s",
                dns->n_servers, n, dns->backup_path);
        return 0;
    }

    /* Step 5: a set failed mid-loop (services [0, applied) were already
     * changed) — self-rollback using the backup validated/created above.
     * Note: if `applied` services collectively don't fully match the
     * backup's service set (only possible on the guard path, if the
     * network service list changed since an earlier crash), the
     * unmatched services are simply left as-is by restore_from_backup_file
     * — the pre-existing backup is treated as sole authority per step 3's
     * guard, and this is an accepted, inherent limitation of that design,
     * not something apply() can second-guess. */
    LOG_WRN("dns: apply failed after %d/%d service(s); rolling back", applied, n);
    if (restore_from_backup_file(dns, svcs, applied) == 0) {
        /* Rollback success: everything we dirtied is back to original —
         * DNS is clean again, so the backup is no longer needed and the
         * lock can be released. */
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

    /* Intentional divergence from Linux dns.c:330 (mqvpn_dns_restore()
     * there clears `active` unconditionally): a single resolv.conf copy
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
