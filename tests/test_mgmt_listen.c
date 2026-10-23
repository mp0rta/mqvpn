// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_mgmt_listen.c — POSIX management listener: permissions, ownership
 * lock, stale detection, removal. The production TU is included so listen()
 * can be intercepted (record-before-listen proof, crash before listen).
 */
#include <stdio.h>

#ifdef _WIN32
int
main(void)
{
    printf("test_mgmt_listen: skipped on Windows\n");
    return 0;
}
#else

#  include <errno.h>
#  include <fcntl.h>
#  include <grp.h>
#  include <signal.h>
#  include <stdlib.h>
#  include <string.h>
#  include <sys/file.h>
#  include <sys/socket.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <sys/un.h>
#  include <sys/wait.h>
#  include <unistd.h>

int real_listen(int fd, int backlog); /* tests/test_mgmt_listen_real.c */

static int g_failed = 0;
static char g_path[512]; /* socket path of the open call in flight */
static int g_crash_in_listen = 0;
static int g_listen_calls = 0;

#  define CHECK(cond)                                                         \
      do {                                                                    \
          if (!(cond)) {                                                      \
              fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
              g_failed++;                                                     \
          }                                                                   \
      } while (0)

static int mgmt_test_listen(int fd, int backlog);
#  define listen mgmt_test_listen
#  include "mgmt_listen.c"
#  undef listen

static int
record_matches_path(const char *path)
{
    char lp[600], buf[64];
    struct stat st;
    snprintf(lp, sizeof(lp), "%s.lock", path);
    int lf = open(lp, O_RDONLY);
    if (lf < 0 || lstat(path, &st) != 0) {
        if (lf >= 0) close(lf);
        return 0;
    }
    ssize_t n = read(lf, buf, sizeof(buf) - 1);
    close(lf);
    if (n <= 0) return 0;
    buf[n] = '\0';
    char want[64];
    snprintf(want, sizeof(want), "%llu %llu\n", (unsigned long long)st.st_dev,
             (unsigned long long)st.st_ino);
    return strcmp(buf, want) == 0;
}

static int
mgmt_test_listen(int fd, int backlog)
{
    g_listen_calls++;
    CHECK(record_matches_path(g_path));
    if (g_crash_in_listen) _exit(g_failed ? 4 : 0);
    return real_listen(fd, backlog);
}

/* ── helpers ──────────────────────────────────────────────────────────────── */

static char g_dir[256];

static void
fresh_dir(void)
{
    snprintf(g_dir, sizeof(g_dir), "/tmp/mgmtlisten.XXXXXX");
    if (!mkdtemp(g_dir)) {
        perror("mkdtemp");
        exit(2);
    }
}

static void
rm_dir(void)
{
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) { /* best effort */
    }
}

static void
sock_path(char *out, size_t n, const char *name)
{
    snprintf(out, n, "%s/%s", g_dir, name);
}

static mgmt_listen_t *
open_at(const char *path, int mode, const char *group, char *err, size_t errlen)
{
    mgmt_listen_opts_t o = {path, mode, group};
    snprintf(g_path, sizeof(g_path), "%s", path);
    err[0] = '\0';
    return mgmt_listen_open(&o, err, errlen);
}

/* Returns a connected fd, or -1. nonblock: always returns the fd (backlog fill). */
static int
connect_to(const char *path, int nonblock)
{
    struct sockaddr_un sa;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
    if (nonblock) fcntl(fd, F_SETFL, O_NONBLOCK);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 && !nonblock) {
        close(fd);
        return -1;
    }
    return fd;
}

static int
connectable(const char *path)
{
    int fd = connect_to(path, 0);
    if (fd < 0) return 0;
    close(fd);
    return 1;
}

static int
bind_sock(const char *path, int do_listen)
{
    struct sockaddr_un sa;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    if (do_listen) real_listen(fd, 4);
    return fd;
}

static ino_t
ino_of(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0 ? st.st_ino : 0;
}

static void
write_lock_record(int lf, const char *path)
{
    struct stat st;
    char buf[64];
    if (stat(path, &st) != 0) return;
    int n = snprintf(buf, sizeof(buf), "%llu %llu\n", (unsigned long long)st.st_dev,
                     (unsigned long long)st.st_ino);
    if (write(lf, buf, (size_t)n) != n) { /* test child: ignore */
    }
}

/* ── tests ────────────────────────────────────────────────────────────────── */

static void
test_open_creates_socket_with_mode(void)
{
    char p[300], lp[320], err[256];
    struct stat st;
    fresh_dir();
    sock_path(p, sizeof(p), "a.sock");
    snprintf(lp, sizeof(lp), "%s.lock", p);
    mgmt_listen_t *l = open_at(p, 0640, NULL, err, sizeof(err));
    CHECK(l != NULL);
    CHECK(lstat(p, &st) == 0 && S_ISSOCK(st.st_mode));
    CHECK((st.st_mode & 07777) == 0640);
    CHECK(record_matches_path(p));
    CHECK(l && mgmt_listen_fd(l) >= 0);
    mgmt_listen_close(l);
    CHECK(lstat(p, &st) == -1 && errno == ENOENT);
    CHECK(stat(lp, &st) == 0 && st.st_size == 0);
    rm_dir();
    printf("PASS listen_open_creates_socket_with_mode\n");
}

static void
test_regular_file_not_removed(void)
{
    char p[300], err[256], buf[8] = {0};
    fresh_dir();
    sock_path(p, sizeof(p), "a.sock");
    int f = open(p, O_CREAT | O_WRONLY, 0600);
    CHECK(write(f, "keep", 4) == 4);
    close(f);
    mgmt_listen_t *l = open_at(p, 0660, NULL, err, sizeof(err));
    CHECK(l == NULL);
    CHECK(err[0] != '\0');
    f = open(p, O_RDONLY);
    CHECK(f >= 0 && read(f, buf, 7) == 4 && memcmp(buf, "keep", 4) == 0);
    if (f >= 0) close(f);
    rm_dir();
    printf("PASS listen_regular_file_not_removed\n");
}

static void
test_second_opener_does_not_steal(void)
{
    char p[300], err[256];
    fresh_dir();
    sock_path(p, sizeof(p), "a.sock");
    mgmt_listen_t *a = open_at(p, 0660, NULL, err, sizeof(err));
    CHECK(a != NULL);
    ino_t ino = ino_of(p);
    mgmt_listen_t *b = open_at(p, 0660, NULL, err, sizeof(err));
    CHECK(b == NULL);
    CHECK(strstr(err, "another endpoint") != NULL);
    CHECK(record_matches_path(p)); /* a losing opener leaves the record alone */
    CHECK(connectable(p));
    CHECK(ino_of(p) == ino);
    mgmt_listen_close(a);
    mgmt_listen_t *c = open_at(p, 0660, NULL, err, sizeof(err));
    CHECK(c != NULL);
    mgmt_listen_close(c);
    rm_dir();
    printf("PASS listen_second_opener_does_not_steal\n");
}

static void
test_full_backlog_not_stolen(void)
{
    char p[300], err[256];
    int fds[CMP_LISTEN_BACKLOG + 8];
    fresh_dir();
    sock_path(p, sizeof(p), "a.sock");
    mgmt_listen_t *a = open_at(p, 0660, NULL, err, sizeof(err));
    CHECK(a != NULL);
    ino_t ino = ino_of(p);
    for (int i = 0; i < CMP_LISTEN_BACKLOG + 8; i++)
        fds[i] = connect_to(p, 1);
    mgmt_listen_t *b = open_at(p, 0660, NULL, err, sizeof(err));
    CHECK(b == NULL);
    CHECK(ino_of(p) == ino);
    for (int i = 0; i < CMP_LISTEN_BACKLOG + 8; i++)
        if (fds[i] >= 0) close(fds[i]);
    mgmt_listen_close(a);
    rm_dir();
    printf("PASS listen_live_owner_with_full_backlog_not_stolen\n");
}

static void
test_stopped_between_bind_and_listen_not_stolen(void)
{
    char p[300], lp[320], err[256];
    int pp[2];
    fresh_dir();
    sock_path(p, sizeof(p), "a.sock");
    snprintf(lp, sizeof(lp), "%s.lock", p);
    CHECK(pipe(pp) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid < 0) {
        close(pp[0]);
        close(pp[1]);
        rm_dir();
        return;
    }
    if (pid == 0) {
        int lf = open(lp, O_CREAT | O_RDWR, 0644);
        if (lf < 0 || flock(lf, LOCK_EX | LOCK_NB) != 0) _exit(1);
        int s = bind_sock(p, 0);
        if (s < 0) _exit(1);
        write_lock_record(lf, p);
        if (write(pp[1], "x", 1) != 1) _exit(1);
        for (;;)
            pause();
    }
    close(pp[1]); /* a dead child now yields EOF instead of a hang */
    char c;
    CHECK(read(pp[0], &c, 1) == 1);
    ino_t ino = ino_of(p);
    mgmt_listen_t *b = open_at(p, 0660, NULL, err, sizeof(err));
    CHECK(b == NULL);
    CHECK(ino_of(p) == ino);
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    mgmt_listen_t *r = open_at(p, 0660, NULL, err, sizeof(err));
    CHECK(r != NULL);
    CHECK(connectable(p));
    mgmt_listen_close(r);
    close(pp[0]);
    rm_dir();
    printf("PASS listen_owner_stopped_between_bind_and_listen_not_stolen\n");
}

static void
test_record_written_before_listen(void)
{
    char p[300], err[256];
    fresh_dir();
    sock_path(p, sizeof(p), "a.sock");
    int before = g_failed, calls = g_listen_calls;
    mgmt_listen_t *l = open_at(p, 0660, NULL, err, sizeof(err));
    CHECK(l != NULL);
    CHECK(g_listen_calls == calls + 1); /* the interceptor (and its CHECK) ran */
    CHECK(g_failed == before);
    mgmt_listen_close(l);
    rm_dir();
    printf("PASS listen_record_written_before_listen\n");
}

static void
test_crash_after_bind_before_listen_recovered(void)
{
    char p[300], err[256];
    fresh_dir();
    sock_path(p, sizeof(p), "a.sock");
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid < 0) {
        rm_dir();
        return;
    }
    if (pid == 0) {
        g_crash_in_listen = 1;
        open_at(p, 0660, NULL, err, sizeof(err));
        _exit(3); /* not reached */
    }
    int status = 0;
    waitpid(pid, &status, 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    struct stat st;
    CHECK(lstat(p, &st) == 0 && S_ISSOCK(st.st_mode)); /* left behind */
    mgmt_listen_t *l = open_at(p, 0660, NULL, err, sizeof(err));
    CHECK(l != NULL);
    CHECK(connectable(p));
    mgmt_listen_close(l);
    rm_dir();
    printf("PASS listen_crash_after_bind_before_listen_recovered\n");
}

static void
test_foreign_socket_not_removed(void)
{
    char p[300], err[256];
    struct stat st;
    fresh_dir();
    sock_path(p, sizeof(p), "a.sock");
    int s = bind_sock(p, 1);
    CHECK(s >= 0);
    ino_t ino = ino_of(p);
    mgmt_listen_t *l = open_at(p, 0660, NULL, err, sizeof(err));
    CHECK(l == NULL);
    CHECK(err[0] != '\0');
    CHECK(lstat(p, &st) == 0 && S_ISSOCK(st.st_mode) && st.st_ino == ino);
    CHECK(connectable(p));
    close(s);
    rm_dir();
    printf("PASS listen_foreign_socket_not_removed\n");
}

static void
test_own_stale_socket_recovered(void)
{
    char p[300], err[256];
    fresh_dir();
    sock_path(p, sizeof(p), "a.sock");
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid < 0) {
        rm_dir();
        return;
    }
    if (pid == 0) {
        mgmt_listen_t *l = open_at(p, 0660, NULL, err, sizeof(err));
        _exit(l ? 0 : 1); /* no close: simulated crash */
    }
    int status = 0;
    waitpid(pid, &status, 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    struct stat st;
    CHECK(lstat(p, &st) == 0 && S_ISSOCK(st.st_mode));
    mgmt_listen_t *l = open_at(p, 0660, NULL, err, sizeof(err));
    CHECK(l != NULL);
    CHECK(connectable(p));
    mgmt_listen_close(l);
    rm_dir();
    printf("PASS listen_own_stale_socket_recovered\n");
}

static void
test_lock_only_leftover_starts(void)
{
    char p[300], lp[320], err[256];
    fresh_dir();
    sock_path(p, sizeof(p), "a.sock");
    snprintf(lp, sizeof(lp), "%s.lock", p);
    int f = open(lp, O_CREAT | O_WRONLY, 0644);
    CHECK(write(f, "1 2\n", 4) == 4);
    close(f);
    mgmt_listen_t *l = open_at(p, 0660, NULL, err, sizeof(err));
    CHECK(l != NULL);
    mgmt_listen_close(l);
    rm_dir();
    printf("PASS listen_lock_only_leftover_starts\n");
}

static void
test_close_keeps_rebound_foreign_path(void)
{
    char p[300], err[256];
    fresh_dir();
    sock_path(p, sizeof(p), "a.sock");
    mgmt_listen_t *a = open_at(p, 0660, NULL, err, sizeof(err));
    CHECK(a != NULL);
    CHECK(unlink(p) == 0);
    int s = bind_sock(p, 1);
    CHECK(s >= 0);
    ino_t ino = ino_of(p);
    mgmt_listen_close(a);
    struct stat st;
    CHECK(lstat(p, &st) == 0 && S_ISSOCK(st.st_mode) && st.st_ino == ino);
    close(s);
    rm_dir();
    printf("PASS listen_close_keeps_rebound_foreign_path\n");
}

static char g_logbuf[1024];
static int g_logcount = 0;
static void
log_sink(mqvpn_log_level_t level, const char *msg, void *ctx)
{
    (void)ctx;
    if (level == MQVPN_LOG_WARN) {
        g_logcount++;
        snprintf(g_logbuf, sizeof(g_logbuf), "%s", msg);
    }
}

static void
test_unknown_group_warns_and_continues(void)
{
    char p[300], err[256];
    struct stat st;
    fresh_dir();
    sock_path(p, sizeof(p), "a.sock");
    mqvpn_log_set_sink(log_sink, NULL);
    mgmt_listen_t *l = open_at(p, 0660, "no-such-group-xyz", err, sizeof(err));
    mqvpn_log_set_sink(NULL, NULL);
    CHECK(l != NULL);
    CHECK(lstat(p, &st) == 0 && st.st_gid == getegid());
    CHECK(g_logcount == 1);
    CHECK(strstr(g_logbuf, "group") != NULL && strstr(g_logbuf, "not found") != NULL);
    mgmt_listen_close(l);
    rm_dir();
    printf("PASS listen_unknown_group_warns_and_continues\n");
}

static void
test_path_too_long(void)
{
    char p[300], err[256];
    fresh_dir();
    memset(p, 'a', 120);
    p[120] = '\0';
    mgmt_listen_t *l = open_at(p, 0660, NULL, err, sizeof(err));
    CHECK(l == NULL);
    CHECK(strstr(err, "too long") != NULL);
    rm_dir();
    printf("PASS listen_path_too_long\n");
}

static void
test_parent_dir_created_0755(void)
{
    char p[300], sub[300], err[256];
    struct stat st;
    fresh_dir();
    snprintf(p, sizeof(p), "%s/dir/sub/x.sock", g_dir);
    snprintf(sub, sizeof(sub), "%s/dir/sub", g_dir);
    mgmt_listen_t *l = open_at(p, 0660, NULL, err, sizeof(err));
    CHECK(l != NULL);
    CHECK(stat(sub, &st) == 0 && (st.st_mode & 07777) == 0755);
    mgmt_listen_close(l);
    rm_dir();
    printf("PASS listen_parent_dir_created_0755\n");
}

static void
test_parse_mode(void)
{
    g_logcount = 0;
    mqvpn_log_set_sink(log_sink, NULL);
    CHECK(mgmt_listen_parse_mode("") == 0660);
    CHECK(mgmt_listen_parse_mode(NULL) == 0660);
    CHECK(mgmt_listen_parse_mode("0640") == 0640);
    CHECK(mgmt_listen_parse_mode("640") == 0640);
    CHECK(g_logcount == 0); /* valid and empty inputs are silent */
    CHECK(mgmt_listen_parse_mode("abc") == 0660);
    CHECK(g_logcount == 1);
    CHECK(strstr(g_logbuf, "invalid ClientManagement SocketMode 'abc'") != NULL);
    mqvpn_log_set_sink(log_sink, NULL);
    CHECK(mgmt_listen_parse_mode("10000") == 0660);
    CHECK(mgmt_listen_parse_mode("0660x") == 0660);
    mqvpn_log_set_sink(NULL, NULL);
    printf("PASS listen_parse_mode\n");
}

int
main(void)
{
    umask(022);
    test_open_creates_socket_with_mode();
    test_regular_file_not_removed();
    test_second_opener_does_not_steal();
    test_full_backlog_not_stolen();
    test_stopped_between_bind_and_listen_not_stolen();
    test_record_written_before_listen();
    test_crash_after_bind_before_listen_recovered();
    test_foreign_socket_not_removed();
    test_own_stale_socket_recovered();
    test_lock_only_leftover_starts();
    test_close_keeps_rebound_foreign_path();
    test_unknown_group_warns_and_continues();
    test_path_too_long();
    test_parent_dir_created_0755();
    test_parse_mode();
    if (g_failed) {
        fprintf(stderr, "%d check(s) failed\n", g_failed);
        return 1;
    }
    printf("all mgmt_listen tests passed\n");
    return 0;
}

#endif /* _WIN32 */
