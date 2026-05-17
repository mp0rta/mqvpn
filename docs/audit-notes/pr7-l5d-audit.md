# PR7 (L5d send-side + low-urgency SHOULDs) — findings

> Verified against `mqvpn-dev` head 595bf3b (xquic) + mqvpn `main` 99080da.

**Pre-verified clean** (forensic anchors, no further action):
G-N4 (xqc_conn.c:5435,5447 use `xqc_conn_get_max_pto` for key-update),
G-N5 (xqc_conn.c:3200-3202 conn drain = `3 * xqc_conn_get_max_pto`),
G-P13 (xqc_multipath.c:539-550 path drain timer 3*PTO + xqc_path_closed),
G-P18 (xqc_frame.c + xqc_multipath.c immediate-close paths invoked from CONNECTION_CLOSE/PATH_ABANDON handlers).

| ID | spec § | verdict | note |
|---|---|---|---|
| G-N1 | §2.1 ¶8 | VERIFY-CLEAN by design isolation | `xqc_conn_public_remote_trans_settings_t` (include/xquic/xquic_typedef.h:258) exposes ONLY `max_datagram_frame_size` to the session-restore API — `init_max_path_id` cannot round-trip across sessions. Each new handshake re-learns it via `xqc_conn_set_remote_transport_params`. Earlier scope note claimed "TP whitelist excludes init_max_path_id" — wrong framing (the binary encoder at xqc_transport_params.c:425,428 DOES serialize); the real safety is at the resumption-cache boundary. |
| G-N6 | §2.3 | TBD per re-audit in PR8 | xqc_engine.c:771 `xqc_write_ack_or_mp_ack_or_ext_ack_to_packets` call site exists but doesn't prove the spec predicate (post-handshake PATH_ACK for unacked 0-RTT). Same "verdict ↔ rationale mismatch" shape as the G-N1 plan rev2 issue. PR8 will trace the `conn->ack_flag` carry across handshake completion. |
| G-P10 | §3.2.1 ¶1 | fixed in PR7 xquic-side | xqc_conn.c principle #3 issues CIDs for all unused path_ids up to curr_max_path_id. |
| G-P14 | §3.4 ¶3 | fixed in PR7 xquic-side (with STANDBY 2-tier) | `xqc_conn_pick_alt_active_path` returns AVAILABLE > STANDBY > NULL per §3 state model. Dual-lens review caught the initial AVAILABLE-only narrowing and the STANDBY fallback was added. |
| G-P15 | §3.3 ¶6 | fixed in this mqvpn-side PR | `src/path_state_machine.c::set_path_state_with_log` dispatches to `xqc_conn_mark_path_{standby,available,frozen}` per the lifecycle transition. xquic-side API was pre-existing. |
| G-P16 | §3.2.1 ¶7 | deferred to PR8 | Budget gate: M-effort, wire-format addition (new frame type + writer + trigger + rate-limit). PATHS_BLOCKED parser already exists (xquic commit 029368c); only send-side missing. |
| G-S1 | §5.x | out of scope | Already covered by PR3 (L3 three-stage `xqc_path_create`). Redundant entry in the residual-gaps doc. |

**Test debt → PR8**: PR7 xquic-side ships with helper-level unit tests only. Integration tests (real engine + wire-level frame check for G-P10 + G-P14) are deferred to PR8 along with engine-equipped mp21 fixture work that PR8 G-P16 also needs.
