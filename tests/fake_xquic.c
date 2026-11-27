// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* tests/fake_xquic.c — a scripted, state-based stand-in for the xquic calls
 * that src/mqvpn_client.c makes (list: tests/fake_xquic_redirect.h). One
 * engine, at most one connection. Notifications reach the client only when
 * the driver fires them (fake_xquic.h) or, for a local close, at the next
 * xqc_engine_main_logic. Every fire reads the fake's state afresh after each
 * callback, since the client calls back into the fake from inside them. */
#undef NDEBUG
#include "fake_xquic_redirect.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>

#include "fake_xquic.h"
#include "mqvpn_internal.h"

#define FAKE_MAX_PATHS 16
#define FAKE_MAX_REQS  16
#define FAKE_DGRAM_MSS 1200

/* xquic's opaque handles; the client never looks inside them. */
struct xqc_engine_s {
    int unused;
};
struct xqc_connection_s {
    int unused;
};
struct xqc_h3_conn_s {
    int unused;
};
struct xqc_h3_request_s {
    int in_use;
    void *user_data; /* the client's cli_stream_t */
};

typedef struct {
    int in_use;
    uint64_t id;
    int active;
} fake_path_t;

fake_xqc_cmds_t fake_xqc_cmds;

static struct {
    int engine_live;
    int mp_negotiated;
    xqc_engine_callback_t engine_cbs;
    xqc_transport_callbacks_t transport_cbs;
    xqc_h3_callbacks_t h3_cbs;

    int conn_open;
    int close_pending; /* local close: delivered by the next main_logic */
    void *conn_user_data;
    xqc_cid_t cid;
    fake_path_t paths[FAKE_MAX_PATHS];
    struct xqc_h3_request_s reqs[FAKE_MAX_REQS];
    uint64_t next_path_id;
    uint64_t decoy_id; /* ~0: none */

    int script_connect; /* -1 unscripted, else ok */
    int script_create_set;
    int script_create_ret;
    uint64_t script_create_id;
    int script_close_path; /* -1 unscripted, else ok */
} F;

static struct xqc_engine_s fake_engine;
static struct xqc_connection_s fake_conn;
static struct xqc_h3_conn_s fake_h3_conn;

static void
clear_state(int mp_negotiated)
{
    memset(&F, 0, sizeof(F));
    F.mp_negotiated = mp_negotiated;
    F.decoy_id = UINT64_MAX;
    F.script_connect = -1;
    F.script_close_path = -1;
}

static fake_path_t *
find_path(uint64_t id)
{
    for (int i = 0; i < FAKE_MAX_PATHS; i++)
        if (F.paths[i].in_use && F.paths[i].id == id) return &F.paths[i];
    return NULL;
}

static fake_path_t *
add_path(uint64_t id)
{
    for (int i = 0; i < FAKE_MAX_PATHS; i++) {
        if (F.paths[i].in_use) continue;
        F.paths[i] = (fake_path_t){.in_use = 1, .id = id, .active = 0};
        if (id >= F.next_path_id) F.next_path_id = id + 1;
        return &F.paths[i];
    }
    abort(); /* more live paths than any trace needs */
}

/* Stream close notifies, then the conn close notify, each exactly once (the
 * order of xqc_conn.c). The h3 conn object stays valid throughout: the
 * client reads its errno inside the conn close notify, which frees the
 * client's cli_conn_t, so nothing may be delivered after it. */
static void
deliver_conn_close(void)
{
    if (!F.conn_open) return;
    F.conn_open = 0;
    F.close_pending = 0;
    for (int i = 0; i < FAKE_MAX_REQS; i++) {
        struct xqc_h3_request_s *r = &F.reqs[i];
        if (!r->in_use) continue;
        r->in_use = 0;
        if (F.h3_cbs.h3r_cbs.h3_request_close_notify)
            F.h3_cbs.h3r_cbs.h3_request_close_notify(r, r->user_data);
    }
    void *ud = F.conn_user_data;
    F.conn_user_data = NULL;
    memset(F.paths, 0, sizeof(F.paths));
    if (F.h3_cbs.h3c_cbs.h3_conn_close_notify)
        F.h3_cbs.h3c_cbs.h3_conn_close_notify(&fake_h3_conn, &F.cid, ud);
}

/* ─── driver controls ─── */

void
fake_xqc_reset(int multipath_negotiated)
{
    assert(!F.engine_live); /* destroy the previous client first */
    clear_state(multipath_negotiated);
    memset(&fake_xqc_cmds, 0, sizeof(fake_xqc_cmds));
}

void
fake_xqc_script_connect(int ok)
{
    F.script_connect = ok ? 1 : 0;
}

void
fake_xqc_script_create_path(int xqc_ret, uint64_t id)
{
    F.script_create_set = 1;
    F.script_create_ret = xqc_ret;
    F.script_create_id = id;
}

void
fake_xqc_script_close_path(int ok)
{
    F.script_close_path = ok ? 1 : 0;
}

void
fake_xqc_set_path_active(uint64_t id, int active)
{
    fake_path_t *p = find_path(id);
    assert(p);
    p->active = active;
}

void
fake_xqc_set_decoy_active_path(uint64_t id)
{
    F.decoy_id = id;
}

void
fake_xqc_fire_handshake_finished(void)
{
    assert(F.conn_open);
    fake_path_t *p = find_path(0);
    if (p) p->active = 1; /* the handshake validated the initial path */
    if (F.h3_cbs.h3c_cbs.h3_conn_handshake_finished)
        F.h3_cbs.h3c_cbs.h3_conn_handshake_finished(&fake_h3_conn, F.conn_user_data);
}

void
fake_xqc_fire_ready_to_create_path(void)
{
    assert(F.conn_open);
    if (!F.mp_negotiated) return; /* xquic never announces it then */
    if (F.transport_cbs.ready_to_create_path_notify)
        F.transport_cbs.ready_to_create_path_notify(&F.cid, F.conn_user_data);
}

void
fake_xqc_fire_tunnel_response(void)
{
    assert(F.conn_open);
    struct xqc_h3_request_s *r = &F.reqs[0]; /* the CONNECT-IP request is first */
    assert(r->in_use);
    if (F.h3_cbs.h3r_cbs.h3_request_read_notify)
        F.h3_cbs.h3r_cbs.h3_request_read_notify(
            r, XQC_REQ_NOTIFY_READ_HEADER | XQC_REQ_NOTIFY_READ_BODY, r->user_data);
}

void
fake_xqc_fire_peer_close(void)
{
    assert(F.conn_open);
    deliver_conn_close();
}

void
fake_xqc_fire_path_removed(uint64_t id)
{
    assert(F.conn_open);
    fake_path_t *p = find_path(id);
    if (p) p->in_use = 0;
    if (F.transport_cbs.path_removed_notify)
        F.transport_cbs.path_removed_notify(&F.cid, id, F.conn_user_data);
}

/* ─── engine ─── */

xqc_engine_t *
xqc_engine_create(xqc_engine_type_t engine_type, const xqc_config_t *engine_config,
                  const xqc_engine_ssl_config_t *ssl_config,
                  const xqc_engine_callback_t *engine_callback,
                  const xqc_transport_callbacks_t *transport_cbs, void *user_data)
{
    (void)engine_type;
    (void)engine_config;
    (void)ssl_config;
    (void)user_data;
    assert(!F.engine_live);
    F.engine_live = 1;
    F.engine_cbs = *engine_callback; /* the caller's tables live on its stack */
    F.transport_cbs = *transport_cbs;
    return &fake_engine;
}

/* Like xquic: a still-open connection is torn down with its notifies. */
void
xqc_engine_destroy(xqc_engine_t *engine)
{
    assert(engine == &fake_engine && F.engine_live);
    deliver_conn_close();
    clear_state(F.mp_negotiated);
}

void
xqc_engine_main_logic(xqc_engine_t *engine)
{
    assert(engine == &fake_engine);
    if (F.close_pending) deliver_conn_close();
}

xqc_int_t
xqc_engine_packet_process(xqc_engine_t *engine, const unsigned char *packet_in_buf,
                          size_t packet_in_size, const struct sockaddr *local_addr,
                          socklen_t local_addrlen, const struct sockaddr *peer_addr,
                          socklen_t peer_addrlen, xqc_usec_t recv_time, void *user_data)
{
    (void)engine;
    (void)packet_in_buf;
    (void)packet_in_size;
    (void)local_addr;
    (void)local_addrlen;
    (void)peer_addr;
    (void)peer_addrlen;
    (void)recv_time;
    (void)user_data;
    return XQC_OK;
}

xqc_int_t
xqc_h3_ctx_init(xqc_engine_t *engine, xqc_h3_callbacks_t *h3_cbs)
{
    assert(engine == &fake_engine);
    F.h3_cbs = *h3_cbs;
    return XQC_OK;
}

void
xqc_h3_engine_set_local_settings(xqc_engine_t *engine,
                                 const xqc_h3_conn_settings_t *h3_conn_settings)
{
    (void)engine;
    (void)h3_conn_settings;
}

/* ─── connection ─── */

const xqc_cid_t *
xqc_h3_connect(xqc_engine_t *engine, const xqc_conn_settings_t *conn_settings,
               const unsigned char *token, unsigned token_len, const char *server_host,
               int no_crypto_flag, const xqc_conn_ssl_config_t *conn_ssl_config,
               const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user_data)
{
    (void)conn_settings;
    (void)token;
    (void)token_len;
    (void)server_host;
    (void)no_crypto_flag;
    (void)conn_ssl_config;
    (void)peer_addr;
    (void)peer_addrlen;
    assert(engine == &fake_engine && !F.conn_open);
    fake_xqc_cmds.h3_connect++;
    int ok = F.script_connect != 0;
    F.script_connect = -1;
    if (!ok) return NULL;

    F.conn_open = 1;
    F.close_pending = 0;
    F.conn_user_data = user_data;
    memset(F.reqs, 0, sizeof(F.reqs));
    memset(F.paths, 0, sizeof(F.paths));
    F.next_path_id = 0;
    add_path(0); /* xquic creates the initial path with the connection */
    memset(&F.cid, 0, sizeof(F.cid));
    F.cid.cid_len = 8;
    F.cid.cid_buf[0] = (uint8_t)fake_xqc_cmds.h3_connect;
    /* xqc_client_connect: the create notify runs before connect returns */
    if (F.h3_cbs.h3c_cbs.h3_conn_create_notify)
        F.h3_cbs.h3c_cbs.h3_conn_create_notify(&fake_h3_conn, &F.cid, user_data);
    return &F.cid;
}

xqc_int_t
xqc_conn_close(xqc_engine_t *engine, const xqc_cid_t *cid)
{
    (void)engine;
    (void)cid;
    fake_xqc_cmds.conn_close++;
    if (!F.conn_open) return -XQC_ECONN_NFOUND;
    F.close_pending = 1;
    return XQC_OK;
}

xqc_int_t
xqc_h3_conn_close(xqc_engine_t *engine, const xqc_cid_t *cid)
{
    (void)engine;
    (void)cid;
    fake_xqc_cmds.h3_conn_close++;
    if (!F.conn_open) return -XQC_ECONN_NFOUND;
    F.close_pending = 1;
    return XQC_OK;
}

xqc_int_t
xqc_h3_conn_get_errno(xqc_h3_conn_t *h3c)
{
    assert(h3c == &fake_h3_conn);
    return 0;
}

xqc_connection_t *
xqc_h3_conn_get_xqc_conn(xqc_h3_conn_t *h3c)
{
    (void)h3c;
    return &fake_conn;
}

void
xqc_conn_set_dgram_flow_hash(xqc_connection_t *conn, uint32_t flow_hash)
{
    (void)conn;
    (void)flow_hash;
}

xqc_int_t
xqc_conn_create_path(xqc_engine_t *engine, const xqc_cid_t *cid, uint64_t *new_path_id,
                     int path_status)
{
    (void)engine;
    (void)cid;
    fake_xqc_cmds.create_path++;
    fake_xqc_cmds.last_path_status = path_status;
    int ret = F.script_create_set ? F.script_create_ret : 0;
    uint64_t id = F.script_create_set ? F.script_create_id : F.next_path_id;
    F.script_create_set = 0;
    if (!F.conn_open) return -XQC_ECONN_NFOUND;
    if (ret != 0) return ret;
    assert(!find_path(id));
    add_path(id);
    *new_path_id = id;
    return XQC_OK;
}

xqc_int_t
xqc_conn_close_path(xqc_engine_t *engine, const xqc_cid_t *cid, uint64_t closed_path_id)
{
    (void)engine;
    (void)cid;
    fake_xqc_cmds.close_path++;
    fake_xqc_cmds.last_close_path_id = closed_path_id;
    int ok = F.script_close_path != 0;
    F.script_close_path = -1;
    return ok ? XQC_OK : -XQC_ECONN_NFOUND;
}

/* paths_info is malloc'd on every call (the caller frees it): the decoy
 * first, then every live path. Consumes no script. */
xqc_conn_stats_t
xqc_conn_get_stats(xqc_engine_t *engine, const xqc_cid_t *cid)
{
    (void)engine;
    (void)cid;
    xqc_conn_stats_t st;
    memset(&st, 0, sizeof(st));
    st.paths_info = calloc(FAKE_MAX_PATHS + 1, sizeof(*st.paths_info));
    assert(st.paths_info);
    uint32_t n = 0;
    if (F.decoy_id != UINT64_MAX) {
        st.paths_info[n].path_id = F.decoy_id;
        st.paths_info[n++].path_state = MQVPN_XQC_PATH_STATE_ACTIVE;
    }
    for (int i = 0; i < FAKE_MAX_PATHS; i++) {
        if (!F.paths[i].in_use) continue;
        st.paths_info[n].path_id = F.paths[i].id;
        st.paths_info[n++].path_state = F.paths[i].active
                                            ? MQVPN_XQC_PATH_STATE_ACTIVE
                                            : MQVPN_XQC_PATH_STATE_VALIDATING;
    }
    st.paths_info_count = n;
    return st;
}

/* ─── datagram ─── */

size_t
xqc_h3_ext_datagram_get_mss(xqc_h3_conn_t *conn)
{
    (void)conn;
    return FAKE_DGRAM_MSS;
}

void
xqc_h3_ext_datagram_set_user_data(xqc_h3_conn_t *conn, void *user_data)
{
    (void)conn;
    (void)user_data;
}

xqc_int_t
xqc_h3_ext_datagram_send(xqc_h3_conn_t *conn, void *data, size_t data_len,
                         uint64_t *dgram_id, xqc_data_qos_level_t qos_level)
{
    (void)conn;
    (void)data;
    (void)data_len;
    (void)dgram_id;
    (void)qos_level;
    return XQC_OK;
}

xqc_int_t
xqc_h3_ext_datagram_send_on_path(xqc_h3_conn_t *conn, void *data, size_t data_len,
                                 uint64_t *dgram_id, xqc_data_qos_level_t qos_level,
                                 uint64_t path_id)
{
    (void)conn;
    (void)data;
    (void)data_len;
    (void)dgram_id;
    (void)qos_level;
    (void)path_id;
    return XQC_OK;
}

/* ─── requests ─── */

xqc_h3_request_t *
xqc_h3_request_create(xqc_engine_t *engine, const xqc_cid_t *cid,
                      xqc_stream_settings_t *settings, void *user_data)
{
    (void)engine;
    (void)cid;
    (void)settings;
    if (!F.conn_open) return NULL;
    for (int i = 0; i < FAKE_MAX_REQS; i++) {
        if (F.reqs[i].in_use) continue;
        F.reqs[i] = (struct xqc_h3_request_s){.in_use = 1, .user_data = user_data};
        return &F.reqs[i];
    }
    return NULL;
}

/* The close notify (which frees the client's stream) comes with the
 * connection's teardown; a trace never needs it earlier. */
xqc_int_t
xqc_h3_request_close(xqc_h3_request_t *h3_request)
{
    (void)h3_request;
    return XQC_OK;
}

ssize_t
xqc_h3_request_send_headers(xqc_h3_request_t *h3_request, xqc_http_headers_t *headers,
                            uint8_t fin)
{
    (void)h3_request;
    (void)fin;
    return (ssize_t)headers->count;
}

ssize_t
xqc_h3_request_send_body(xqc_h3_request_t *h3_request, unsigned char *data,
                         size_t data_size, uint8_t fin)
{
    (void)h3_request;
    (void)data;
    (void)fin;
    return (ssize_t)data_size;
}

xqc_http_headers_t *
xqc_h3_request_recv_headers(xqc_h3_request_t *h3_request, uint8_t *fin)
{
    (void)h3_request;
    static xqc_http_header_t hdr = {
        .name = {.iov_base = ":status", .iov_len = 7},
        .value = {.iov_base = "200", .iov_len = 3},
    };
    static xqc_http_headers_t hdrs = {.headers = &hdr, .count = 1, .capacity = 1};
    *fin = 0;
    return &hdrs;
}

/* One ADDRESS_ASSIGN capsule (RFC 9484 §4.7.1): request id 0, IPv4
 * 10.0.0.2/24, with fin. */
ssize_t
xqc_h3_request_recv_body(xqc_h3_request_t *h3_request, unsigned char *recv_buf,
                         size_t recv_buf_size, uint8_t *fin)
{
    (void)h3_request;
    static const unsigned char body[] = {
        XQC_H3_CAPSULE_ADDRESS_ASSIGN, 7, 0, 4, 10, 0, 0, 2, 24};
    assert(recv_buf_size >= sizeof(body));
    memcpy(recv_buf, body, sizeof(body));
    *fin = 1;
    return (ssize_t)sizeof(body);
}

xqc_stream_id_t
xqc_h3_stream_id(xqc_h3_request_t *h3_request)
{
    return (xqc_stream_id_t)(h3_request - F.reqs) * 4; /* client-initiated bidi */
}

/* ─── link stub (not xquic) ─── */

/* Not part of the fake: src/bind/posix.c, linked because fake_transport.c's
 * recorder needs mqvpn_bind_posix_server_ops, calls this server entry point,
 * and this target leaves mqvpn_server.c out. The client never reaches it. */
int
mqvpn_server_on_socket_recv(mqvpn_server_t *server, const uint8_t *pkt, size_t len,
                            const struct sockaddr *peer, socklen_t peer_len)
{
    (void)server;
    (void)pkt;
    (void)len;
    (void)peer;
    (void)peer_len;
    abort();
}
