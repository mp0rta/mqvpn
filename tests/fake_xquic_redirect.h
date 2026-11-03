// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* tests/fake_xquic_redirect.h — renames the stateful xquic calls of
 * src/mqvpn_client.c to the scripted fake in tests/fake_xquic.c.
 *
 * Include it before any xquic header: the renamed names then also rename
 * xquic's own declarations, so each fake_xqc_* definition is type-checked
 * against the real signature and an xquic signature change is a compile
 * error. Used by tests/mbt_client_tu.c and tests/fake_xquic.c only.
 *
 * Classification of every xqc_*( token in src/mqvpn_client.c:
 *
 *   faked (state, or an engine/conn/h3/request object the fake owns):
 *     xqc_engine_create  xqc_engine_destroy  xqc_engine_main_logic
 *     xqc_engine_packet_process  xqc_h3_ctx_init
 *     xqc_h3_engine_set_local_settings  xqc_h3_connect  xqc_h3_conn_close
 *     xqc_h3_conn_get_errno  xqc_h3_conn_get_xqc_conn  xqc_conn_close
 *     xqc_conn_create_path  xqc_conn_close_path  xqc_conn_get_stats
 *     xqc_conn_set_dgram_flow_hash  xqc_h3_ext_datagram_get_mss
 *     xqc_h3_ext_datagram_set_user_data  xqc_h3_ext_datagram_send
 *     xqc_h3_ext_datagram_send_on_path  xqc_h3_request_create
 *     xqc_h3_request_close  xqc_h3_request_send_headers
 *     xqc_h3_request_send_body  xqc_h3_request_recv_headers
 *     xqc_h3_request_recv_body  xqc_h3_stream_id
 *   real libxquic (pure functions of their arguments):
 *     xqc_engine_get_default_config  xqc_h3_ext_capsule_decode
 *     xqc_h3_ext_connectip_parse_address_assign
 *     xqc_h3_ext_connectip_validate_route_advertisement
 *     xqc_h3_ext_masque_udp_mss  xqc_h3_ext_masque_unframe_udp
 *     xqc_h3_ext_masque_frame_udp (reached through the inline in
 *     src/dgram_frame.h)
 *   not xquic (mqvpn_client.c's own code under test):
 *     xqc_find_path_metrics
 *   not a call (named in a comment only):
 *     xqc_conn_should_close
 */
#ifndef MQVPN_FAKE_XQUIC_REDIRECT_H
#define MQVPN_FAKE_XQUIC_REDIRECT_H

#define xqc_engine_create                 fake_xqc_engine_create
#define xqc_engine_destroy                fake_xqc_engine_destroy
#define xqc_engine_main_logic             fake_xqc_engine_main_logic
#define xqc_engine_packet_process         fake_xqc_engine_packet_process
#define xqc_h3_ctx_init                   fake_xqc_h3_ctx_init
#define xqc_h3_engine_set_local_settings  fake_xqc_h3_engine_set_local_settings
#define xqc_h3_connect                    fake_xqc_h3_connect
#define xqc_h3_conn_close                 fake_xqc_h3_conn_close
#define xqc_h3_conn_get_errno             fake_xqc_h3_conn_get_errno
#define xqc_h3_conn_get_xqc_conn          fake_xqc_h3_conn_get_xqc_conn
#define xqc_conn_close                    fake_xqc_conn_close
#define xqc_conn_create_path              fake_xqc_conn_create_path
#define xqc_conn_close_path               fake_xqc_conn_close_path
#define xqc_conn_get_stats                fake_xqc_conn_get_stats
#define xqc_conn_set_dgram_flow_hash      fake_xqc_conn_set_dgram_flow_hash
#define xqc_h3_ext_datagram_get_mss       fake_xqc_h3_ext_datagram_get_mss
#define xqc_h3_ext_datagram_set_user_data fake_xqc_h3_ext_datagram_set_user_data
#define xqc_h3_ext_datagram_send          fake_xqc_h3_ext_datagram_send
#define xqc_h3_ext_datagram_send_on_path  fake_xqc_h3_ext_datagram_send_on_path
#define xqc_h3_request_create             fake_xqc_h3_request_create
#define xqc_h3_request_close              fake_xqc_h3_request_close
#define xqc_h3_request_send_headers       fake_xqc_h3_request_send_headers
#define xqc_h3_request_send_body          fake_xqc_h3_request_send_body
#define xqc_h3_request_recv_headers       fake_xqc_h3_request_recv_headers
#define xqc_h3_request_recv_body          fake_xqc_h3_request_recv_body
#define xqc_h3_stream_id                  fake_xqc_h3_stream_id

#endif /* MQVPN_FAKE_XQUIC_REDIRECT_H */
