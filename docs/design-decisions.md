# Design decisions

Rationale and history behind the rules in [AGENTS.md](../AGENTS.md). Sections
are cited from AGENTS.md as `[DD §n]`. Keep rules there and reasons here.
Section numbers are positional: when a section is inserted or removed,
renumber every `DD §n` reference in the same change —
`scripts/lint/check_dd_refs.sh` (CI) fails on a reference to a missing
section. The month after each title shows when the decision it describes
was made; for a section that lists several rules, it is the range of months
in which they were made. If a reason is older than the code it explains,
check it again.

## §1 Sans-I/O library and `tick()` (2026-09)

libmqvpn does not have its own event loop or threads. The platform layer runs
the reactor: libevent on Linux, macOS and Windows, a `poll()` reactor on the
engine thread on Android, and a RunLoop thread in the iOS Network Extension.
The platform drives the xquic engine by calling `tick()`.

`connect()` only sets up the connection. Do not call
`xqc_engine_main_logic()` from `connect()`. Every API call and every callback
runs on one thread, the tick thread, and Debug builds check this
(`ASSERT_TICK_THREAD`). The rule is about staying on the same thread, not
only about never running two calls at once. A GCD serial queue only gives the
second, so it is not enough; iOS runs a dedicated `Thread` for this reason.
Callbacks are ABI-versioned (currently v3).

Platform layers:

- `src/platform/linux/` (libevent, netlink)
- `src/platform/windows/` (wintun, IP Helper)
- `src/platform/darwin/`
- `src/platform/android/` (the engine-thread reactor)
- `src/platform/posix/` (shared by Linux and macOS)

The shared library links shared xquic because static xquic is built without
`-fPIC`. Signal handling lives only in the CLI, never in the library.

## §2 Sans-I/O in both directions: transport ops and bundled binds (2026-09)

The core does not hold any file descriptors or `SOCKET`s, and it never makes
a socket system call.

Every send goes through transport ops that the platform installs: a
`mqvpn_path_ops_t` per path on the client (with `mqvpn_client_add_path()`),
and one shared `mqvpn_server_transport_ops_t` on the server (with
`mqvpn_server_set_transport()`). Every receive is pushed into the core with
`mqvpn_client_on_socket_recv()` or `mqvpn_server_on_socket_recv()`.

`send` returns one of these:

- the part of the data it accepted;
- `MQVPN_TX_WOULD_BLOCK`;
- `MQVPN_TX_FAILED`.

xquic needs this result. If a send error reaches xquic as a socket error,
xquic can close the whole connection. So the core keeps the rule that turns a
failed send into "would block": a send error never proves that a path is
dead. Buffers passed to `send` are valid only during that call.

For ordinary UDP sockets the library ships two implementations of these ops,
outside the core:

1. `include/mqvpn_bind_posix.h` (`src/bind/`): Linux GSO, `sendmmsg` and
   GRO, socket buffers, errno mapping, and the `udp-gso:` log marker. On
   other POSIX systems it makes one `sendto()` call per datagram.
2. `include/mqvpn_bind_winsock.h`: one `sendto()` per datagram, and a helper
   that drains `recvfrom()`.

A bind ctx borrows the platform's socket and never closes it. The platform
creates, binds, pins and `protect()`s the socket, runs the reactor, and calls
the bind's receive helpers when the socket is readable.

`scripts/lint/check_sansio_core.sh` keeps socket system calls out of the core
sources. The one exception is `src/hybrid/tcp_egress.c`: the server egress
lane owns its TCP sockets by design.

There are two ways to tear down, and they must never be mixed:

- **Platform drop.** Call `drop_path()` or `remove_path()`. The platform stops
  the path's I/O and closes its socket, then calls
  `mqvpn_client_on_platform_path_released()`. The core collects the stats
  with `ops.get_stats` and calls `ops.release` exactly once (DD §3).
- **Whole-object destroy.** The platform stops receiving, then calls
  `mqvpn_client_destroy()` or `mqvpn_server_destroy()`. The final flush still
  sends, and every transport ctx that was not released yet is finished
  inside, including a dropped or removed path whose release was never
  reported. Then the platform closes its sockets.
  `on_platform_path_released()` is never called after destroy.

**Why the platform owns both directions.** A survey of 20 production VPN,
QUIC and network-stack projects (2026-09-16) found none where the library
sends and the platform receives. Projects that let the platform send return a
blocked-or-error status right away (Google quiche `WriteResult`, lsquic,
quinn, gVisor). GSO sits behind the transport interface (wireguard-go
`StdNetBind`, quiche `QuicGsoBatchWriter`). Mobile stacks keep the socket in
the core and let the platform only `protect()` it. mqvpn works the same way:
`send` reports its result right away, the send features (GSO with its sticky
fallback, send telemetry, socket buffers) are part of the POSIX bind, and a
relay (issue #218) or a test transport uses the same interface as a socket.

**Where a socket feature belongs.** `UdpGso` is the only user setting for
GSO. The core uses it to decide whether to batch sends (Linux only, with
the `MQVPN_MAX_PKT_OUT_SIZE <= 1500` guard for the GSO run bound), and the
POSIX bind uses the same value to decide whether GSO is allowed, so the two
cannot drift apart.

UDP GRO has no library API. It is an option of the POSIX bind, set by the
CLI's `UdpGro` key or by a JNI constant on Android. The bind sets the socket
option and splits the combined buffer, so the core only ever sees single
datagrams.

A socket feature that only a transport uses gets no library config setting.
Such a setting would be ABI that nothing in the library reads, and SemVer
would not let us remove it later.

## §3 Path removal: the platform drop lifecycle contract (2026-09)

When a platform loses an interface, it calls
`mqvpn_client_on_platform_path_dropped()` with a
`mqvpn_platform_path_event_info_t` that says why
(`MQVPN_PLATFORM_REASON_*`: the interface was removed, the carrier was lost,
an admin turned it off, or no usable address is left), so the drop is logged
with its reason. `drop_path()` is the same call without the info, kept for
ABI compatibility. Mobile platforms use `remove_path()`
(`PATH_EVENT_REMOVE_API`), the orderly, application-level removal (DD §4).

The drop contract, end to end:

1. The caller sends a **non-blocking** `PATH_ABANDON` (`xqc_conn_close_path`,
   queued on another path) while xquic still holds the path, *before* it
   dispatches the FSM event.
2. `PATH_EVENT_PLATFORM_DROP`: the FSM sets `transport_attached=0` and moves
   the slot to `CLOSED_DROPPED`. The FSM itself never calls xquic; the caller
   already did. This keeps the FSM free of xquic API calls by design.
3. The platform stops the path's I/O and closes its socket, then calls
   `mqvpn_client_on_platform_path_released()`. That function collects the
   transport's stats and calls `ops.release` itself, then dispatches
   `PATH_EVENT_TRANSPORT_RELEASED` (the event only clears the slot's fields).
4. `CLOSED_DROPPED → CLOSED_FREE` is a **lazy gate**, not a direct step. It
   fires only when `transport_released && xquic_path_live==0 &&
   xqc_path_id==0`. Two independent async completions each check the gate:
   the release above, and the `PATH_ABANDON` landing as
   `PATH_EVENT_XQUIC_REMOVED` (which clears the xquic-side fields). Whichever
   lands last moves the slot to `CLOSED_FREE`.

`remove_path()` uses the same close-then-dispatch pattern. Both drop and
remove send `PATH_ABANDON`, which frees the CID/path_id slot for reuse
(draft-21), and both leave the socket with the platform, so the two FSM
handlers differ only in their reason code. `PATH_ABANDON` does not hold up
the surviving paths: it is non-blocking, and the `MAX_PATH_ID` dynamic grant
lets the re-added path skip the drain wait (netns-verified, 0% loss).

## §4 Path lifecycle is per platform (2026-09)

Desktop and mobile handle paths in two different ways. Do not unify them:
desktop owns long-lived interface slots, while mobile is handed network
objects that come and go.

**Desktop (Linux, macOS, Windows).** The platform keeps one slot for each
configured interface for the whole session. When an interface event happens,
the path is dropped (DD §3) and the platform closes the socket. When the
interface is usable again, the slot is re-added: a new socket, a new
transport ctx, and `add_path()` under a new handle. A slot that still has its
socket (a degraded path that was never dropped) is reactivated with
`mqvpn_client_reactivate_path()` instead, and is never re-added: re-adding it
would overwrite the socket and leave its read event behind. The test that
chooses between re-add and reactivate lives in one place,
`src/platform/path_readd.h`, shared by the POSIX network monitor and the
Windows poll reconciler, so the two cannot disagree. On Windows a slot is
named by the adapter's FriendlyName, and the platform looks up the LUID when
it checks the adapter.

**Android and iOS.** The platform follows the OS network callbacks
(ConnectivityManager, NWPathMonitor). A network that goes away is removed
with `remove_path()`, and a network that appears is added with `add_path()`.
Nothing is reactivated.

## §5 Log level mapping (2026-05)

mqvpn INFO maps to xquic WARN. DEBUG, WARN and ERROR each map to xquic's
level of the same name.

xquic INFO logs every packet, which is DEBUG-level detail in practice. If
mqvpn INFO mapped to xquic INFO, throughput would drop by about 5× on a slow
console (Windows PowerShell) and `--log-level info` would be unusable, so
INFO stays one level lower. Users who want xquic's detail use
`--log-level debug`.

## §6 WLB scheduler (2026-09)

The WLB scheduler is production-grade. It learns path weights from
acknowledged goodput, spreads traffic with smooth weighted round-robin, pins
each inner TCP flow to one path, and spills over softly when a pinned path
is cwnd-blocked. `Scheduler = wlb_udp_pin` also pins inner UDP flows (by a
5-tuple hash), so the packets of one flow are not spread across paths.

WLB's measured performance is in the benchmark results: see
`docs/benchmarks_netns.md` and the benchmark pages on the website, which are
regenerated as the implementation changes.

Do not casually add BLEST/LLHD-style schedulers. For jitter-sensitive
real-time streams (SRT/RTP), recommend `Scheduler = minrtt` instead of
writing a new scheduler.

## §7 The hybrid TCP lane is scheduled by MinRTT, not by WLB — by construction (2026-09)

`po_flow_hash` is set only on the datagram write path
(`xqc_packet_out.c`), so every QUIC STREAM packet — i.e. all TCP-lane
traffic — reaches `xqc_wlb_scheduler_get_path` with hash 0 and takes the
MinRTT fallback: lowest-SRTT path with cwnd headroom, spilling to another
path only while that one is cwnd-blocked. Do not "fix" this by extending
WLB's pinning or WRR to streams. Pinning exists to keep one inner flow's
*datagrams* off two paths with different RTTs; the stream lane already has an
ordering layer (QUIC STREAM reassembly absorbs cross-path reordering before
any TCP stack sees it), so pinning would cap a single flow at one path's
capacity instead of adding aggregation, and weight-based WRR would only add
reassembly delay at equal throughput. MinRTT measures well: a netem-shaped
2-path stream lane reaches ~96% of the sum of its single-path legs (86.9 vs
36.7+54.2 Mbps, Test 3 in `tests/test_e2e_hybrid_h2.sh`).

Corollary for tests and bug reports: aggregation is only expected where a
single path cannot absorb the offered load. On an unshaped pair,
100%-on-one-path is correct behaviour, so a load-share assertion must shape
the legs (see Test 8 in `tests/test_e2e_hybrid_h2.sh`).

Both the reasoning and the measurements favour MinRTT for the stream lane.
Move it toward WLB only if a measurement on a shaped multi-path pair shows
WLB beating MinRTT; that the datagram lane uses WLB is not a reason on its
own. Without that measurement, leave the lane on MinRTT.

## §8 Reorder buffer scope (2026-06)

QUIC delivers data in order at the STREAM layer (RFC 9000 §2.2), and
multipath keeps that order across the whole connection. DATAGRAM frames have
no ordering at any QUIC layer (RFC 9221). CONNECT-IP uses them for exactly
that reason: no head-of-line blocking and no retransmission. The cost is that
datagrams spread over paths with different RTTs arrive out of order.

The optional `[Reorder]` buffer restores a bounded order for one case only: a
single inner connection (usually inner QUIC / HTTP/3) that cannot be split
into flows and is spread across paths for bandwidth. It only reorders: it
waits at most `MaxWaitMs`, never retransmits, and moves past a gap when the
time runs out.

Out of scope:

- inner TCP: WLB keeps each TCP flow on one path, and TCP handles reordering
  itself;
- latency-sensitive UDP such as DNS: waiting only adds delay;
- RTP/SRT: their own jitter buffers handle this.

FEC is a separate, sender-side mechanism in another layer.

## §9 Spec compliance, draft-21 and xquic naming (2026-05)

IETF RFC/draft compliance is the top priority. Never make a library change
that deviates from spec to suppress a symptom; if a deviation looks
unavoidable, stop and consult the maintainer first. Known scoping decision:
ECN accounting is out of scope for the draft-21 multipath work —
`PATH_ACK_ECN` keeps the PATH_ACK recovery semantics (draft-21 §4.1) and its
ECN counts are parsed and discarded.

xquic's `MULTIPATH_xx` / `dev/multipath_xx` names are xquic-internal version
labels, **not** IETF draft numbers — read the code to determine actual draft
semantics. The draft-21 wire codepoints use the label `XQC_MULTIPATH_3E`.
draft-21 path management is dynamic (a `PATHS_BLOCKED` ↔ `MAX_PATH_ID`
loop), so there is no fixed path cap to raise. The only limit,
`XQC_PATH_HARD_CAP`, is a safety bound, not a negotiated one.

## §10 Build, test and small decisions (2026-04 – 2026-07)

- `build.sh` forces `CMAKE_BUILD_TYPE=Release`, which defines `NDEBUG` and
  silently no-ops `assert()`-based unit tests. Never base a "tests pass"
  claim on a Release build — use a Debug/sanitizer build. Test files that
  use `assert()` carry `#undef NDEBUG`; `tests/check_ndebug_guard.sh` (a
  ctest target) enforces it.
- A plain gcc Debug build misses what the CI sanitizer job catches
  (`-Wcomment`, `-Wswitch`, alignment); that is why clang `-Werror` and
  ASan/UBSan are required before pushing non-trivial C changes (see the
  `sanitizer` and `msan` jobs in `.github/workflows/ci.yml`).
- Changes to the control API or connection lifecycle need the local sudo +
  netns e2e suite (`scripts/ci_e2e/`) before shipping; `ctest` alone is too
  shallow for those.
- e2e scripts wait on log messages with greps, so existing log wording is an
  observable invariant.
- When adding a new test target, make sure include paths resolve in a *clean
  checkout* — a stale system-installed `/usr/include/libmqvpn.h` can mask a
  missing `-I` locally and only fail in CI.
- `xqc_engine_destroy()` already frees the h3 context — calling
  `xqc_h3_ctx_destroy()` as well is a double free (ASan-verified).
- MTU config upper bound stays 9000 until `max_pkt_out_size` becomes
  configurable (then raise to 9216).
- To add a config key:
  - add one row to the config descriptor table in `src/config.c`;
  - add one key to the parity test (`test_ini_json_scalar_parity` in
    `tests/test_config.c`);
  - add the key to the website configuration pages.
- Benchmark outputs: `ci_sweep_results/` is transient (gitignored);
  `bench_results/` is the tracked archive for results worth keeping.

## §11 Git: branch bases and history (2026-09)

`main` is the release line: releases are tagged on it, and ordinary fixes and
features, outside contributions included, go to `main` through a pull
request.

`dev` collects a series of pull requests that belong together and must not
reach a release half-done (the transport-symmetry slices, for example). Each
part lands on `dev` through its own pull request; then `dev` merges into
`main` in one pull request with a merge commit, and `dev` is fast-forwarded
to `main` afterwards.

Choose the base of a bug-fix branch per fix: start from the tip of the line
where the bug was found. `main` is updated only by pull requests merged in
the GitHub web UI. Do not force-push once a pull request is open; add new
commits instead.

## §12 Fork divergence is re-paid at every upstream merge (2026-09)

The fork follows upstream by periodic full merges, not cherry-picks, so
**every line of divergence is paid for again at every merge**. Weigh a
fork-local change against that recurring cost. The best fix is one that can
land upstream; the next best touches only files upstream rarely changes.
Divergence in a widely edited public header is the most expensive kind. This
is why WLB lives in `src/transport/scheduler/` behind
`xqc_scheduler_callback_t` instead of spreading through `xqc_conn.c` and
`xqc_send_ctl.c`. The only WLB hooks outside that directory are the datagram
flow hash (`xqc_packet_out.c`) and the `on_app_packet_acked` callback
(`xqc_send_ctl.c`).

## §13 In the fork, ABI breaks are cheap and public API is not (2026-09)

Growing a struct that a public struct embeds by value — `xqc_scheduler_callback_t`
sits inside `xqc_conn_settings_t` — shifts every later field: source-compatible,
binary-incompatible, and *silent*, because `libxquic.so` carries no SONAME
version. That is acceptable: xquic and mqvpn ship as a pinned pair per
`mqvpn-vX.Y.Z`, and upstream grows `xqc_conn_settings_t` between releases too
(63 fields at v1.8.3, 72 at upstream main in 2026-09). A coordinated rebuild
plus a SemVer bump covers it. Exported *functions* are the opposite — adding
one is free (a new symbol breaks nothing), removing one needs a major bump.
So the irreversible direction is publishing API, not breaking ABI: never add
public accessors speculatively, and do not bundle them into an unrelated ABI
break on the theory that the window is closing. It never closes.

Per-path scheduler telemetry therefore has a home already: the "extended
metrics" block in `xqc_path_metrics_t`, reached via `xqc_conn_get_stats()` →
`paths_info[]`, which mqvpn already iterates (`mqvpn_client.c`,
`mqvpn_server.c`) and forwards
into `mqvpn_path_stats_t` and the control API. Put new scheduler
observability there rather than in a scheduler-specific API, so the retrieval
surface stays single. Caveat: `xqc_path_metrics_t` has no
`struct_size`/version field, so the caller's `sizeof` sets the
`paths_info[i]` stride — growing it is a coordinated-rebuild change like the
one above. Adding such a field is itself upstream divergence; propose it
upstream rather than carrying it.

## §14 Compatibility surfaces (2026-09)

mqvpn ships inside OpenMPTCProuter (OMR). OMR builds it from a downstream
fork, `Ysurac/mqvpn`, which merges mqvpn releases and adds OMR-specific
features. A change here therefore reaches OMR users when that fork next
merges mqvpn.

OMR relies on these parts of mqvpn, so they are compatibility surfaces:

- **Config files.** The VPS runs the server from a JSON file (including the
  `users` list and `control_listen`), which the installer edits with `grep`
  and `jq`. The router generates the client's INI file from UCI.
- **The control API.** OMR manages users with `add_user`, `remove_user` and
  `list_users`, and reads status and statistics with `get_status`,
  `get_stats`, `get_reorder_stats`, `get_build_info` and
  `get_all_fec_stats`. OMR's UI and scripts parse the JSON replies.
- **The command line**, `mqvpn --config <file>`.

A pull request that renames or removes a config key, a control command or a
reply field, or that changes a default, explains the compatibility impact in
its description. Log wording is a compatibility surface for a different
reason: the e2e tests wait for specific log lines (DD §10). OMR reads the
control API, not the logs.
