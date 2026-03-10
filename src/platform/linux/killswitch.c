/*
 * killswitch.c — iptables/ip6tables kill switch for Linux
 *
 * Blocks all traffic outside the VPN tunnel using iptables OUTPUT chain rules.
 * Rules are tagged with PID-based comment for reliable cleanup.
 */

#include "platform_internal.h"
#include "log.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

static int
run_iptables_cmd(const char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0)
        if (errno != EINTR) return -1;
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

int
setup_killswitch(platform_ctx_t *p)
{
    if (!p->killswitch_enabled || p->killswitch_active) return 0;

    snprintf(p->ks_comment, sizeof(p->ks_comment), "mqvpn-ks:%d", (int)getpid());
    int is_v6 = (p->server_addr.ss_family == AF_INET6);

    /* IPv4 rules (always needed) */
    const char *at[] = {"iptables", "-I", "OUTPUT",  "-o",        p->tun.name,   "-j",
                        "ACCEPT",   "-m", "comment", "--comment", p->ks_comment, NULL};
    const char *al[] = {"iptables", "-I", "OUTPUT",  "-o",        "lo",          "-j",
                        "ACCEPT",   "-m", "comment", "--comment", p->ks_comment, NULL};
    const char *da[] = {"iptables", "-A",      "OUTPUT",    "-j",          "DROP",
                        "-m",       "comment", "--comment", p->ks_comment, NULL};

    if (run_iptables_cmd(at) < 0 || run_iptables_cmd(al) < 0 ||
        run_iptables_cmd(da) < 0) {
        LOG_WRN("failed to set up iptables kill switch rules");
        p->killswitch_active = 1;
        cleanup_killswitch(p);
        return -1;
    }
    p->killswitch_active = 1;

    int pfx = mqvpn_sa_host_prefix(&p->server_addr);
    char sc[INET6_ADDRSTRLEN + 5];
    snprintf(sc, sizeof(sc), "%s/%d", p->server_ip_str, pfx);
    char ps[8];
    snprintf(ps, sizeof(ps), "%d", p->server_port);

    if (!is_v6) {
        const char *as[] = {
            "iptables", "-I",      "OUTPUT",  "-p",        "udp",         "-d",
            sc,         "--dport", ps,        "-o",        p->orig_iface, "-j",
            "ACCEPT",   "-m",      "comment", "--comment", p->ks_comment, NULL};
        if (run_iptables_cmd(as) < 0) {
            cleanup_killswitch(p);
            return -1;
        }
    } else {
        const char *v6s[] = {
            "ip6tables", "-I",      "OUTPUT",  "-p",        "udp",         "-d",
            sc,          "--dport", ps,        "-o",        p->orig_iface, "-j",
            "ACCEPT",    "-m",      "comment", "--comment", p->ks_comment, NULL};
        const char *v6l[] = {"ip6tables", "-I",        "OUTPUT",      "-o",
                             "lo",        "-j",        "ACCEPT",      "-m",
                             "comment",   "--comment", p->ks_comment, NULL};
        const char *v6d[] = {"ip6tables", "-A",      "OUTPUT",    "-j",          "DROP",
                             "-m",        "comment", "--comment", p->ks_comment, NULL};
        if (run_iptables_cmd(v6s) < 0 || run_iptables_cmd(v6l) < 0 ||
            run_iptables_cmd(v6d) < 0) {
            cleanup_killswitch(p);
            return -1;
        }
    }

    /* IPv6 data plane TUN rule */
    if (p->has_v6) {
        const char *v6t[] = {"ip6tables", "-I",        "OUTPUT",      "-o",
                             p->tun.name, "-j",        "ACCEPT",      "-m",
                             "comment",   "--comment", p->ks_comment, NULL};
        (void)run_iptables_cmd(v6t);
        if (!is_v6) {
            const char *v6l[] = {"ip6tables", "-I",        "OUTPUT",      "-o",
                                 "lo",        "-j",        "ACCEPT",      "-m",
                                 "comment",   "--comment", p->ks_comment, NULL};
            const char *v6d[] = {"ip6tables",   "-A", "OUTPUT",  "-j",
                                 "DROP",        "-m", "comment", "--comment",
                                 p->ks_comment, NULL};
            (void)run_iptables_cmd(v6l);
            (void)run_iptables_cmd(v6d);
        }
    }
    LOG_INF("kill switch enabled (comment=%s)", p->ks_comment);
    return 0;
}

void
cleanup_killswitch(platform_ctx_t *p)
{
    if (!p->killswitch_active) return;

    int is_v6 = (p->server_addr.ss_family == AF_INET6);
    int pfx = mqvpn_sa_host_prefix(&p->server_addr);
    char sc[INET6_ADDRSTRLEN + 5];
    snprintf(sc, sizeof(sc), "%s/%d", p->server_ip_str, pfx);
    char ps[8];
    snprintf(ps, sizeof(ps), "%d", p->server_port);

    /* Remove IPv4 rules */
    const char *dt[] = {"iptables", "-D", "OUTPUT",  "-o",        p->tun.name,   "-j",
                        "ACCEPT",   "-m", "comment", "--comment", p->ks_comment, NULL};
    while (run_iptables_cmd(dt) == 0) {}
    const char *dl[] = {"iptables", "-D", "OUTPUT",  "-o",        "lo",          "-j",
                        "ACCEPT",   "-m", "comment", "--comment", p->ks_comment, NULL};
    while (run_iptables_cmd(dl) == 0) {}
    const char *dd[] = {"iptables", "-D",      "OUTPUT",    "-j",          "DROP",
                        "-m",       "comment", "--comment", p->ks_comment, NULL};
    while (run_iptables_cmd(dd) == 0) {}

    if (!is_v6) {
        const char *ds[] = {
            "iptables", "-D",      "OUTPUT",  "-p",        "udp",         "-d",
            sc,         "--dport", ps,        "-o",        p->orig_iface, "-j",
            "ACCEPT",   "-m",      "comment", "--comment", p->ks_comment, NULL};
        while (run_iptables_cmd(ds) == 0) {}
    } else {
        const char *v6s[] = {
            "ip6tables", "-D",      "OUTPUT",  "-p",        "udp",         "-d",
            sc,          "--dport", ps,        "-o",        p->orig_iface, "-j",
            "ACCEPT",    "-m",      "comment", "--comment", p->ks_comment, NULL};
        while (run_iptables_cmd(v6s) == 0) {}
        const char *v6l[] = {"ip6tables", "-D",        "OUTPUT",      "-o",
                             "lo",        "-j",        "ACCEPT",      "-m",
                             "comment",   "--comment", p->ks_comment, NULL};
        while (run_iptables_cmd(v6l) == 0) {}
        const char *v6d[] = {"ip6tables", "-D",      "OUTPUT",    "-j",          "DROP",
                             "-m",        "comment", "--comment", p->ks_comment, NULL};
        while (run_iptables_cmd(v6d) == 0) {}
    }

    /* IPv6 data plane TUN rule */
    const char *v6dt[] = {"ip6tables", "-D", "OUTPUT",  "-o",        p->tun.name,   "-j",
                          "ACCEPT",    "-m", "comment", "--comment", p->ks_comment, NULL};
    while (run_iptables_cmd(v6dt) == 0) {}

    if (!is_v6) {
        const char *v6l2[] = {"ip6tables", "-D",        "OUTPUT",      "-o",
                              "lo",        "-j",        "ACCEPT",      "-m",
                              "comment",   "--comment", p->ks_comment, NULL};
        while (run_iptables_cmd(v6l2) == 0) {}
        const char *v6d2[] = {"ip6tables", "-D",      "OUTPUT",    "-j",          "DROP",
                              "-m",        "comment", "--comment", p->ks_comment, NULL};
        while (run_iptables_cmd(v6d2) == 0) {}
    }
    p->killswitch_active = 0;
    LOG_INF("kill switch rules removed");
}
