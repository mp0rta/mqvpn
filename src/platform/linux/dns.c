/*
 * dns.c — DNS resolv.conf management for mqvpn client
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
#include <netdb.h>

int
mqvpn_resolve_host(const char *host, struct sockaddr_storage *out, socklen_t *out_len)
{
    if (!host || !host[0]) {
        return -1;
    }

    memset(out, 0, sizeof(*out));

    /* Fast path: try IPv4 literal */
    struct in_addr addr4;
    if (inet_pton(AF_INET, host, &addr4) == 1) {
        struct sockaddr_in *sin = (struct sockaddr_in *)out;
        sin->sin_family = AF_INET;
        sin->sin_addr = addr4;
        *out_len = sizeof(struct sockaddr_in);
        return 0;
    }

    /* Fast path: try IPv6 literal */
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, host, &addr6) == 1) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = addr6;
        *out_len = sizeof(struct sockaddr_in6);
        return 0;
    }

    /* Slow path: hostname resolution via getaddrinfo (dual-stack) */
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    int ret = getaddrinfo(host, NULL, &hints, &res);
    if (ret != 0 || !res) {
        LOG_WRN("dns: failed to resolve '%s': %s", host, gai_strerror(ret));
        if (res) freeaddrinfo(res);
        return -1;
    }

    memcpy(out, res->ai_addr, res->ai_addrlen);
    *out_len = res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

void
mqvpn_sa_set_port(struct sockaddr_storage *ss, uint16_t port)
{
    if (ss->ss_family == AF_INET) {
        ((struct sockaddr_in *)ss)->sin_port = htons(port);
    } else if (ss->ss_family == AF_INET6) {
        ((struct sockaddr_in6 *)ss)->sin6_port = htons(port);
    }
}

const char *
mqvpn_sa_ntop(const struct sockaddr_storage *ss, char *buf, size_t buflen)
{
    if (ss->ss_family == AF_INET) {
        return inet_ntop(AF_INET, &((const struct sockaddr_in *)ss)->sin_addr, buf,
                         (socklen_t)buflen);
    } else if (ss->ss_family == AF_INET6) {
        return inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)ss)->sin6_addr, buf,
                         (socklen_t)buflen);
    }
    return NULL;
}

int
mqvpn_sa_host_prefix(const struct sockaddr_storage *ss)
{
    if (ss->ss_family == AF_INET) return 32;
    if (ss->ss_family == AF_INET6) return 128;
    return 0;
}

/* Run an external command. Returns 0 on success (exit code 0), -1 otherwise. */
static int
run_cmd(const char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0)
        if (errno != EINTR) return -1;
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

static int
detect_resolvectl(void)
{
    const char *argv[] = {"resolvectl", "status", NULL};
    return run_cmd(argv) == 0 ? 1 : 0;
}

static int
apply_resolvectl(mqvpn_dns_t *dns)
{
    if (dns->tun_name[0] == '\0') {
        LOG_ERR("dns: resolvectl requires TUN interface name");
        return -1;
    }

    /* resolvectl dns <tun> <server1> [server2] ... */
    const char *argv[MQVPN_DNS_MAX_SERVERS + 4];
    int argc = 0;
    argv[argc++] = "resolvectl";
    argv[argc++] = "dns";
    argv[argc++] = dns->tun_name;
    for (int i = 0; i < dns->n_servers; i++)
        argv[argc++] = dns->servers[i];
    argv[argc] = NULL;

    if (run_cmd(argv) < 0) {
        LOG_ERR("dns: resolvectl dns failed");
        return -1;
    }

    /* resolvectl default-route <tun> true */
    const char *dr_argv[] = {"resolvectl", "default-route", dns->tun_name, "true", NULL};
    if (run_cmd(dr_argv) < 0) {
        LOG_WRN("dns: resolvectl default-route failed (continuing)");
    }

    LOG_INF("dns: configured %d server(s) via resolvectl on %s", dns->n_servers,
            dns->tun_name);
    return 0;
}

static void
restore_resolvectl(mqvpn_dns_t *dns)
{
    if (dns->tun_name[0] == '\0') return;
    const char *argv[] = {"resolvectl", "revert", dns->tun_name, NULL};
    if (run_cmd(argv) < 0)
        LOG_WRN("dns: resolvectl revert failed (interface may already be gone)");
    else
        LOG_INF("dns: reverted DNS via resolvectl on %s", dns->tun_name);
}

void
mqvpn_dns_init(mqvpn_dns_t *dns)
{
    memset(dns, 0, sizeof(*dns));
    dns->lock_fd = -1;
    dns->resolv_path = "/etc/resolv.conf";
    dns->backup_path = "/etc/resolv.conf.mqvpn.bak";
    dns->lock_path = "/run/mqvpn-dns.lock";
}

int
mqvpn_dns_add_server(mqvpn_dns_t *dns, const char *addr)
{
    if (dns->n_servers >= MQVPN_DNS_MAX_SERVERS) {
        LOG_WRN("dns: max %d servers supported", MQVPN_DNS_MAX_SERVERS);
        return -1;
    }
    snprintf(dns->servers[dns->n_servers], sizeof(dns->servers[0]), "%s", addr);
    dns->n_servers++;
    return 0;
}

/* Copy file src to dst */
static int
copy_file(const char *src, const char *dst)
{
    FILE *in = fopen(src, "r");
    if (!in) return -1;
    int out_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        fclose(in);
        return -1;
    }
    FILE *out = fdopen(out_fd, "w");
    if (!out) {
        close(out_fd);
        fclose(in);
        return -1;
    }
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            fclose(in);
            fclose(out);
            return -1;
        }
    }
    fclose(in);
    fclose(out);
    return 0;
}

int
mqvpn_dns_apply(mqvpn_dns_t *dns)
{
    if (dns->n_servers == 0) {
        return 0; /* nothing to do */
    }

    /* Try resolvectl first */
    if (detect_resolvectl()) {
        dns->use_resolvectl = 1;
        int rc = apply_resolvectl(dns);
        if (rc == 0) {
            dns->active = 1;
            return 0;
        }
        LOG_WRN("dns: resolvectl failed, falling back to resolv.conf");
        dns->use_resolvectl = 0;
    }

    /* Acquire exclusive lock — prevents multiple mqvpn instances from
     * clobbering each other's resolv.conf backup.  flock() is automatically
     * released by the kernel if the process dies. */
    int lfd = open(dns->lock_path, O_CREAT | O_RDWR, 0644);
    if (lfd >= 0) {
        if (flock(lfd, LOCK_EX | LOCK_NB) < 0) {
            LOG_ERR("dns: another mqvpn instance is managing DNS (lock: %s)",
                    dns->lock_path);
            close(lfd);
            return -1;
        }
        dns->lock_fd = lfd;
    } else {
        LOG_WRN("dns: could not create lock file %s: %m (continuing without lock)",
                dns->lock_path);
    }

    /* Check for systemd-resolved symlink */
    struct stat st;
    if (lstat(dns->resolv_path, &st) == 0 && S_ISLNK(st.st_mode)) {
        LOG_WRN("dns: %s is a symlink (possibly systemd-resolved). "
                "Overwriting anyway.",
                dns->resolv_path);
    }

    /* Backup original resolv.conf */
    if (copy_file(dns->resolv_path, dns->backup_path) < 0) {
        LOG_WRN("dns: could not backup %s (file may not exist)", dns->resolv_path);
        /* Continue anyway — new installation may not have resolv.conf */
    }

    /* Write new resolv.conf */
    int resolv_fd = open(dns->resolv_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (resolv_fd < 0) {
        LOG_ERR("dns: cannot open %s: %m", dns->resolv_path);
        if (dns->lock_fd >= 0) {
            close(dns->lock_fd);
            dns->lock_fd = -1;
        }
        return -1;
    }
    FILE *fp = fdopen(resolv_fd, "w");
    if (!fp) {
        close(resolv_fd);
        LOG_ERR("dns: cannot write %s: %m", dns->resolv_path);
        if (dns->lock_fd >= 0) {
            close(dns->lock_fd);
            dns->lock_fd = -1;
        }
        return -1;
    }

    fprintf(fp, "# Generated by mqvpn — do not edit\n");
    fprintf(fp, "# Original saved to %s\n", dns->backup_path);
    for (int i = 0; i < dns->n_servers; i++) {
        fprintf(fp, "nameserver %s\n", dns->servers[i]);
    }
    fclose(fp);

    dns->active = 1;
    LOG_INF("dns: configured %d server(s), backed up to %s", dns->n_servers,
            dns->backup_path);
    return 0;
}

void
mqvpn_dns_restore(mqvpn_dns_t *dns)
{
    if (!dns->active) return;

    if (dns->use_resolvectl) {
        restore_resolvectl(dns);
        dns->active = 0;
        return;
    }

    if (copy_file(dns->backup_path, dns->resolv_path) < 0) {
        LOG_ERR("dns: failed to restore %s from %s", dns->resolv_path, dns->backup_path);
    } else {
        unlink(dns->backup_path);
        LOG_INF("dns: restored %s", dns->resolv_path);
    }

    dns->active = 0;

    /* Always release lock */
    if (dns->lock_fd >= 0) {
        close(dns->lock_fd);
        dns->lock_fd = -1;
        unlink(dns->lock_path);
    }
}

int
mqvpn_dns_has_stale_backup(const mqvpn_dns_t *dns)
{
    return access(dns->backup_path, F_OK) == 0;
}

void
mqvpn_dns_restore_stale(mqvpn_dns_t *dns)
{
    if (!mqvpn_dns_has_stale_backup(dns)) return;

    LOG_WRN("dns: stale backup found at %s, restoring", dns->backup_path);
    if (copy_file(dns->backup_path, dns->resolv_path) < 0) {
        LOG_ERR("dns: failed to restore from stale backup");
        return;
    }
    unlink(dns->backup_path);
    LOG_INF("dns: restored %s from stale backup", dns->resolv_path);
}
