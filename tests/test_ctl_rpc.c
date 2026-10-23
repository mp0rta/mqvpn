// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* mqvpnctl RPC client against a scripted peer on a socketpair (POSIX only). */

#include "cmp_error.h"
#include "ctl_rpc.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c)                                                                  \
    do {                                                                          \
        if (!(c)) {                                                               \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #c); \
            exit(1);                                                              \
        }                                                                         \
    } while (0)

typedef struct {
    ctl_sock_t s;
    int peer;
} pair_t;

static void
pair_open(pair_t *p)
{
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    memset(p, 0, sizeof(*p));
    p->s.fd = sv[0];
    p->peer = sv[1];
}

static void
pair_close(pair_t *p)
{
    ctl_sock_close(&p->s);
    if (p->peer >= 0) close(p->peer);
}

static void
peer_write(pair_t *p, const char *str)
{
    size_t n = strlen(str);
    CHECK(write(p->peer, str, n) == (ssize_t)n);
}

/* Read one request line the client sent and parse it. */
static yyjson_doc *
peer_read_request(pair_t *p)
{
    static char buf[4096];
    size_t n = 0;
    while (n < sizeof(buf)) {
        CHECK(read(p->peer, buf + n, 1) == 1);
        if (buf[n++] == '\n') break;
    }
    CHECK(buf[n - 1] == '\n');
    yyjson_doc *d = yyjson_read(buf, n - 1, 0);
    CHECK(d != NULL);
    return d;
}

static int
call_ping(pair_t *p, int timeout_ms, ctl_reply_t *r, ctl_sock_err_t *se)
{
    yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *params = yyjson_mut_obj(d);
    CHECK(d && params);
    int st = ctl_rpc_call(&p->s, 1, "system.ping", d, params, timeout_ms, r, se);
    yyjson_mut_doc_free(d);
    return st;
}

static void
rpc_call_ok(void)
{
    pair_t p;
    pair_open(&p);
    peer_write(&p, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"x\":1}}\n");
    ctl_reply_t r;
    ctl_sock_err_t se = CTL_SOCK_OK;
    CHECK(call_ping(&p, 1000, &r, &se) == CTL_RPC_OK);
    int x = 0;
    CHECK(json_get_int(yyjson_obj_get(r.result, "x"), &x) == 0 && x == 1);
    ctl_reply_free(&r);

    yyjson_doc *req = peer_read_request(&p);
    yyjson_val *root = yyjson_doc_get_root(req);
    CHECK(strcmp(yyjson_get_str(yyjson_obj_get(root, "jsonrpc")), "2.0") == 0);
    CHECK(yyjson_get_sint(yyjson_obj_get(root, "id")) == 1);
    CHECK(strcmp(yyjson_get_str(yyjson_obj_get(root, "method")), "system.ping") == 0);
    CHECK(yyjson_is_obj(yyjson_obj_get(root, "params")));
    yyjson_doc_free(req);
    pair_close(&p);
}

static void
rpc_no_params_member_when_null(void)
{
    pair_t p;
    pair_open(&p);
    peer_write(&p, "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}\n");
    ctl_reply_t r;
    ctl_sock_err_t se = CTL_SOCK_OK;
    CHECK(ctl_rpc_call(&p.s, 7, "system.version", NULL, NULL, 1000, &r, &se) ==
          CTL_RPC_OK);
    ctl_reply_free(&r);
    yyjson_doc *req = peer_read_request(&p);
    CHECK(yyjson_obj_get(yyjson_doc_get_root(req), "params") == NULL);
    yyjson_doc_free(req);
    pair_close(&p);
}

static void
rpc_call_remote_error(void)
{
    pair_t p;
    pair_open(&p);
    peer_write(
        &p, "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32003,\"message\":\"m\","
            "\"data\":{\"name\":\"MQVPN_CLIENT_PERMISSION_DENIED\"}}}\n");
    ctl_reply_t r;
    ctl_sock_err_t se = CTL_SOCK_OK;
    CHECK(call_ping(&p, 1000, &r, &se) == CTL_RPC_E_REMOTE);
    CHECK(r.error != NULL && r.error_code == -32003);
    CHECK(ctl_exit_code_for(CTL_RPC_E_REMOTE, 0, -32003) == 4);
    ctl_reply_free(&r);
    pair_close(&p);
}

static void
expect_protocol(const char *reply_line)
{
    pair_t p;
    pair_open(&p);
    peer_write(&p, reply_line);
    ctl_reply_t r;
    ctl_sock_err_t se = CTL_SOCK_OK;
    CHECK(call_ping(&p, 1000, &r, &se) == CTL_RPC_E_PROTOCOL);
    pair_close(&p);
}

static void
rpc_call_id_mismatch_is_protocol(void)
{
    expect_protocol("{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n");
    expect_protocol("{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":{}}\n");
}

static void
rpc_call_malformed_is_protocol(void)
{
    expect_protocol("not json\n");
    expect_protocol("{\"jsonrpc\":\"2.0\",\"id\":1}\n");
    expect_protocol(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":1,\"error\":{\"code\":1}}\n");
    expect_protocol("{\"jsonrpc\":\"1.0\",\"id\":1,\"result\":1}\n");
    expect_protocol("{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":\"x\"}}\n");
}

static void
rpc_recv_line_keeps_trailing_bytes(void)
{
    pair_t p;
    pair_open(&p);
    peer_write(&p, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n{\"junk\":1}\r\n");
    ctl_reply_t r;
    ctl_sock_err_t se = CTL_SOCK_OK;
    CHECK(call_ping(&p, 1000, &r, &se) == CTL_RPC_OK);
    ctl_reply_free(&r);
    CHECK(p.s.rlen > 0);
    const char *line;
    size_t n;
    CHECK(ctl_sock_recv_line(&p.s, 4096, 1000, &line, &n) == CTL_SOCK_OK);
    CHECK(n == 10 && memcmp(line, "{\"junk\":1}", 10) == 0 && line[n] == '\0');
    pair_close(&p);
}

/* Writes "<head>" + len filler bytes + "<tail>" from a child so the peer never
 * blocks on a full socket buffer. */
static pid_t
spawn_big_writer(pair_t *p, size_t len)
{
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        const char *head = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"";
        const char *tail = "\"}\n";
        char *chunk = malloc(8192);
        if (!chunk) _exit(1);
        memset(chunk, 'a', 8192);
        int fl = MSG_NOSIGNAL;
        if (send(p->peer, head, strlen(head), fl) < 0) _exit(0);
        for (size_t left = len; left > 0;) {
            size_t c = left < 8192 ? left : 8192;
            ssize_t w = send(p->peer, chunk, c, fl);
            if (w < 0) _exit(0); /* reader gave up (too long) */
            left -= (size_t)w;
        }
        (void)!send(p->peer, tail, strlen(tail), fl);
        _exit(0);
    }
    return pid;
}

static void
rpc_recv_line_grows_heap(void)
{
    pair_t p;
    pair_open(&p);
    pid_t pid = spawn_big_writer(&p, 100 * 1024);
    ctl_reply_t r;
    ctl_sock_err_t se = CTL_SOCK_OK;
    CHECK(call_ping(&p, 5000, &r, &se) == CTL_RPC_OK);
    CHECK(strlen(yyjson_get_str(r.result)) == 100 * 1024);
    ctl_reply_free(&r);
    CHECK(p.s.rcap >= 100 * 1024);
    size_t k = p.s.rcap / 4096;
    CHECK(p.s.rcap % 4096 == 0 && (k & (k - 1)) == 0);
    pair_close(&p);
    waitpid(pid, NULL, 0);

    pair_open(&p);
    pid = spawn_big_writer(&p, 300 * 1024);
    int st = call_ping(&p, 5000, &r, &se);
    CHECK(st == CTL_RPC_E_SOCK && se == CTL_SOCK_E_TOO_LONG);
    CHECK(ctl_exit_code_for(CTL_RPC_E_SOCK, CTL_SOCK_E_TOO_LONG, 0) == 1);
    pair_close(&p);
    waitpid(pid, NULL, 0);
}

static void
rpc_timeout(void)
{
    pair_t p;
    pair_open(&p);
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    ctl_reply_t r;
    ctl_sock_err_t se = CTL_SOCK_OK;
    CHECK(call_ping(&p, 100, &r, &se) == CTL_RPC_E_TIMEOUT);
    clock_gettime(CLOCK_MONOTONIC, &b);
    long ms = (b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000;
    CHECK(ms >= 100 && ms <= 500);
    CHECK(ctl_exit_code_for(CTL_RPC_E_TIMEOUT, se, 0) == 8);
    pair_close(&p);
}

static void
rpc_eof(void)
{
    pair_t p;
    pair_open(&p);
    close(p.peer);
    p.peer = -1;
    ctl_reply_t r;
    ctl_sock_err_t se = CTL_SOCK_OK;
    int st = call_ping(&p, 1000, &r, &se);
    CHECK(st == CTL_RPC_E_SOCK);
    CHECK(se == CTL_SOCK_E_EOF || se == CTL_SOCK_E_IO); /* send may fail first (EPIPE) */
    CHECK(ctl_exit_code_for((ctl_rpc_status_t)st, se, 0) == 1);
    pair_close(&p);

    /* peer closes with nothing sent: plain EOF on read */
    pair_open(&p);
    close(p.peer);
    p.peer = -1;
    const char *line;
    size_t n;
    CHECK(ctl_sock_recv_line(&p.s, 4096, 1000, &line, &n) == CTL_SOCK_E_EOF);
    pair_close(&p);
}

static void
rpc_hello_params_shape(void)
{
    pair_t p;
    pair_open(&p);
    peer_write(&p, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n");
    ctl_reply_t r;
    ctl_sock_err_t se = CTL_SOCK_OK;
    CHECK(ctl_rpc_hello(&p.s, 1000, &r, &se) == CTL_RPC_OK);
    ctl_reply_free(&r);
    yyjson_doc *req = peer_read_request(&p);
    yyjson_val *root = yyjson_doc_get_root(req);
    CHECK(strcmp(yyjson_get_str(yyjson_obj_get(root, "method")), "system.hello") == 0);
    yyjson_val *pr = yyjson_obj_get(root, "params");
    CHECK(strcmp(yyjson_get_str(yyjson_obj_get(pr, "client_name")), "mqvpnctl") == 0);
    yyjson_val *v = yyjson_obj_get(pr, "cmp_versions");
    CHECK(yyjson_arr_size(v) == 1 &&
          strcmp(yyjson_get_str(yyjson_arr_get_first(v)), "1.0") == 0);
    yyjson_doc_free(req);
    pair_close(&p);
}

static void
exit_code_table(void)
{
    CHECK(ctl_exit_code_for(CTL_RPC_OK, 0, 0) == 0);
    CHECK(ctl_exit_code_for(CTL_RPC_E_CONNECT, CTL_SOCK_E_NOENT, 0) == 5);
    CHECK(ctl_exit_code_for(CTL_RPC_E_CONNECT, CTL_SOCK_E_REFUSED, 0) == 5);
    CHECK(ctl_exit_code_for(CTL_RPC_E_CONNECT, CTL_SOCK_E_IO, 0) == 5);
    CHECK(ctl_exit_code_for(CTL_RPC_E_CONNECT, CTL_SOCK_E_ACCESS, 0) == 4);
    CHECK(ctl_exit_code_for(CTL_RPC_E_CONNECT, CTL_SOCK_E_TIMEOUT, 0) == 8);
    CHECK(ctl_exit_code_for(CTL_RPC_E_SOCK, CTL_SOCK_E_IO, 0) == 1);
    CHECK(ctl_exit_code_for(CTL_RPC_E_SOCK, CTL_SOCK_E_EOF, 0) == 1);
    CHECK(ctl_exit_code_for(CTL_RPC_E_TIMEOUT, CTL_SOCK_E_TIMEOUT, 0) == 8);
    CHECK(ctl_exit_code_for(CTL_RPC_E_REMOTE, 0, -32002) == 9);
    CHECK(ctl_exit_code_for(CTL_RPC_E_REMOTE, 0, 1009) == 6);
    CHECK(ctl_exit_code_for(CTL_RPC_E_REMOTE, 0, -32601) == 1);
    CHECK(ctl_exit_code_for(CTL_RPC_E_PROTOCOL, 0, 0) == 9);
}

static void
rpc_connect_enoent(void)
{
    ctl_sock_t s;
    ctl_sock_err_t se = CTL_SOCK_OK;
    CHECK(ctl_rpc_connect(&s, "/nonexistent-mqvpn-dir/client.sock", 1000, &se) ==
          CTL_RPC_E_CONNECT);
    CHECK(se == CTL_SOCK_E_NOENT);
}

int
main(void)
{
    signal(SIGPIPE, SIG_IGN);
    rpc_call_ok();
    rpc_no_params_member_when_null();
    rpc_call_remote_error();
    rpc_call_id_mismatch_is_protocol();
    rpc_call_malformed_is_protocol();
    rpc_recv_line_keeps_trailing_bytes();
    rpc_recv_line_grows_heap();
    rpc_timeout();
    rpc_eof();
    rpc_hello_params_shape();
    exit_code_table();
    rpc_connect_enoent();
    printf("test_ctl_rpc: all passed\n");
    return 0;
}
