# xquic MASQUE API Audit — mqvpn M1

Audit date: 2026-02-16
Branch: `mp0rta/xquic` `feature/masque`
Pinned commit: `3a159b0a4b43ba07752ed2d9eb83b5bdf1c355fe`

## Summary

**All MASQUE APIs required for mqvpn M1 are publicly exported** in
`include/xquic/xqc_http3.h` and `include/xquic/xquic.h`.
No additional header file is needed.

## APIs Used by Test Case 800 (Single-Path MASQUE CONNECT-IP)

### Engine / Configuration

| Function | Header | Purpose |
|---|---|---|
| `xqc_engine_get_default_config()` | `xquic.h` | Default engine config |
| `xqc_engine_create()` | `xquic.h` | Create QUIC engine |
| `xqc_engine_destroy()` | `xquic.h` | Destroy engine |
| `xqc_engine_packet_process()` | `xquic.h` | Feed incoming UDP packet |
| `xqc_engine_finish_recv()` | `xquic.h` | Signal end of recv batch |
| `xqc_engine_main_logic()` | `xquic.h` | Process timers / pending work |
| `xqc_h3_ctx_init()` | `xqc_http3.h` | Initialize H3 context with callbacks |
| `xqc_h3_engine_set_local_settings()` | `xqc_http3.h` | Set H3 settings (Extended CONNECT, Datagram) |
| `xqc_server_set_conn_settings()` | `xquic.h` | Server connection settings |

### Connection Lifecycle (Client)

| Function | Header | Purpose |
|---|---|---|
| `xqc_h3_connect()` | `xqc_http3.h` | Create H3 client connection |
| `xqc_h3_conn_close()` | `xqc_http3.h` | Close H3 connection |
| `xqc_h3_conn_send_ping()` | `xqc_http3.h` | Send PING frame |
| `xqc_conn_get_stats()` | `xquic.h` | Get connection statistics |
| `xqc_conn_continue_send()` | `xquic.h` | Continue sending after EAGAIN |

### Connection Lifecycle (Server)

| Function | Header | Purpose |
|---|---|---|
| `xqc_conn_set_transport_user_data()` | `xquic.h` | Set transport user data in accept |
| `xqc_conn_get_peer_addr()` | `xquic.h` | Get peer address |
| `xqc_h3_conn_set_user_data()` | `xqc_http3.h` | Set H3 conn user data |
| `xqc_h3_conn_get_peer_addr()` | `xqc_http3.h` | Get peer address (H3 level) |
| `xqc_h3_get_conn_user_data_by_request()` | `xqc_http3.h` | Get conn user data from request |
| `xqc_h3_conn_get_errno()` | `xqc_http3.h` | Get connection error code |

### H3 Request (Extended CONNECT)

| Function | Header | Purpose |
|---|---|---|
| `xqc_h3_request_create()` | `xqc_http3.h` | Create H3 request |
| `xqc_h3_request_send_headers()` | `xqc_http3.h` | Send Extended CONNECT headers |
| `xqc_h3_request_recv_headers()` | `xqc_http3.h` | Receive response headers |
| `xqc_h3_request_send_body()` | `xqc_http3.h` | Send capsules on stream body |
| `xqc_h3_request_recv_body()` | `xqc_http3.h` | Receive capsules from stream body |
| `xqc_h3_stream_id()` | `xqc_http3.h` | Get QUIC stream ID (for datagram framing) |

### MASQUE Framing (all in `xqc_http3.h` lines 1020–1101)

| Function | Purpose |
|---|---|
| `xqc_h3_ext_masque_frame_udp()` | Frame payload with Quarter-Stream-ID + Context-ID=0 |
| `xqc_h3_ext_masque_unframe_udp()` | Unframe received datagram |
| `xqc_h3_ext_masque_udp_mss()` | Calculate max payload after framing overhead |

### Capsule Protocol

| Function | Purpose |
|---|---|
| `xqc_h3_ext_capsule_encode()` | Encode `[type : varint][length : varint][payload]` |
| `xqc_h3_ext_capsule_decode()` | Decode capsule from stream body |
| `xqc_h3_ext_connectip_parse_address_assign()` | Parse ADDRESS_ASSIGN payload |
| `xqc_h3_ext_connectip_build_address_request()` | Build ADDRESS_ASSIGN/ADDRESS_REQUEST payload |
| `xqc_h3_ext_connectip_parse_route_advertisement()` | Parse ROUTE_ADVERTISEMENT payload |

### Capsule Constants

```c
#define XQC_H3_CAPSULE_DATAGRAM              0x00
#define XQC_H3_CAPSULE_ADDRESS_ASSIGN        0x01
#define XQC_H3_CAPSULE_ADDRESS_REQUEST       0x02
#define XQC_H3_CAPSULE_ROUTE_ADVERTISEMENT   0x03
```

### HTTP Datagram Send/Receive

| Function | Header | Purpose |
|---|---|---|
| `xqc_h3_ext_datagram_send()` | `xqc_http3.h` | Send raw datagram (caller must frame) |
| `xqc_h3_ext_datagram_get_mss()` | `xqc_http3.h` | Get max datagram payload size |
| `xqc_h3_ext_datagram_set_user_data()` | `xqc_http3.h` | Set datagram callback user data |

### Datagram Callback Types

```c
typedef struct {
    xqc_h3_ext_datagram_read_notify_pt       dgram_read_notify;
    xqc_h3_ext_datagram_write_notify_pt      dgram_write_notify;
    xqc_h3_ext_datagram_acked_notify_pt      dgram_acked_notify;
    xqc_h3_ext_datagram_lost_notify_pt       dgram_lost_notify;
    xqc_h3_ext_datagram_mss_updated_notify_pt dgram_mss_updated_notify;
} xqc_h3_ext_dgram_callbacks_t;
```

## Important Implementation Notes

1. **Manual framing required**: `xqc_h3_ext_datagram_send()` sends raw bytes.
   Caller MUST call `xqc_h3_ext_masque_frame_udp()` before sending and
   `xqc_h3_ext_masque_unframe_udp()` when receiving.

2. **Capsules travel on the H3 stream body**, not as QUIC DATAGRAMs.
   Send with `xqc_h3_request_send_body()`, receive via
   `h3_request_read_notify` + `xqc_h3_request_recv_body()`.

3. **MSS chain**: `xqc_h3_ext_datagram_get_mss(conn)` → raw datagram MSS;
   `xqc_h3_ext_masque_udp_mss(mss, stream_id)` → max tunneled IP packet size.

4. **Event loop**: Tests use libevent2. xquic is event-loop-agnostic — needs:
   - `set_event_timer` callback to schedule `xqc_engine_main_logic()`
   - `write_socket` / `write_socket_ex` callbacks for UDP output
   - Feed packets via `xqc_engine_packet_process()` + `xqc_engine_finish_recv()`

5. **H3 settings for MASQUE**:
   ```c
   xqc_h3_conn_settings_t h3s = {
       .enable_connect_protocol = 1,
       .h3_datagram             = 1,
   };
   xqc_h3_engine_set_local_settings(engine, &h3s);
   ```

6. **Connection settings for datagram**:
   ```c
   conn_settings.max_datagram_frame_size = 65535;
   ```

## Test 801 (Multipath) Additional APIs

| Function | Header | Purpose |
|---|---|---|
| `xqc_conn_create_path()` | `xquic.h` | Create additional QUIC path |
| `xqc_conn_close_path()` | `xquic.h` | Close a path |
| `xqc_h3_ext_datagram_send_on_path()` | `xqc_http3.h` | Path-pinned datagram send |
