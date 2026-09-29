# Design decisions

Rationale and history behind the rules in [AGENTS.md](../AGENTS.md). Sections
are cited from AGENTS.md as `[DD §n]`. Keep rules there and reasons here.

## §1 Sans-I/O library and `tick()`

libmqvpn contains no libevent. The platform layer owns the reactor (libevent
on Linux, macOS and Windows; a `poll()` reactor on the engine thread on
Android; a RunLoop thread in the iOS Network Extension) and drives the xquic
engine by calling `tick()`. `connect()` only performs connection setup — never
call `xqc_engine_main_logic()` from `connect()`. Callbacks are ABI-versioned
(currently v3). Platform layers: `src/platform/linux/` (libevent, netlink),
`src/platform/windows/` (wintun, IP Helper), `src/platform/darwin/`,
`src/platform/android/` (the engine-thread reactor), `src/platform/posix/`
(shared by Linux and macOS).

The shared library links shared xquic because static xquic is built without
`-fPIC`. Signal handling lives only in the CLI, never in the library.

## §2 Sans-I/O in both directions: transport ops and bundled binds

The core never holds an fd or a `SOCKET` and never issues a socket syscall.
Every send goes through the per-path `mqvpn_path_ops_t` (client) or the shared
`mqvpn_server_transport_ops_t` (server) that the platform installs with
`mqvpn_client_add_path()` / `mqvpn_server_set_transport()`; every receive is
pushed in with `mqvpn_client_on_socket_recv()` /
`mqvpn_server_on_socket_recv()`. `send` returns the prefix it accepted
synchronously, `MQVPN_TX_WOULD_BLOCK` or `MQVPN_TX_FAILED`. That result is
what xquic needs — a send error reported to it as a socket error can close
the whole connection — so the policy that downgrades a failed send to
"would block" stays in the core: a send error is never proof that a path is
dead. Buffers passed to `send` are valid only for the call.

For ordinary UDP sockets the library ships two implementations of those ops,
outside the core: `include/mqvpn_bind_posix.h` (`src/bind/`: Linux GSO,
`sendmmsg` and GRO, socket buffers, errno mapping, the `udp-gso:` probe
marker; one `sendto()` per datagram elsewhere) and
`include/mqvpn_bind_winsock.h` (one `sendto()` per datagram and a
`recvfrom()` drain helper). A bind ctx borrows the platform's socket and never
closes it. The platform creates, binds, pins and `protect()`s the socket, runs
the reactor, and calls the bind's receive helpers when the socket is readable.
`scripts/lint/check_sansio_core.sh` keeps socket syscalls out of the core
sources; `src/hybrid/tcp_egress.c` is the one excluded core file (the server
egress lane owns its TCP sockets by design).

There are two teardown contracts, and they are never mixed. Platform drop:
`drop_path()` / `remove_path()`, then the platform stops the path's I/O and
closes its socket, then `mqvpn_client_on_platform_path_released()` — the core
harvests `ops.get_stats` and calls `ops.release` exactly once (DD §3).
Whole-object destroy: the platform stops receiving, then
`mqvpn_client_destroy()` / `mqvpn_server_destroy()` (the final flush still
sends, and every transport ctx not yet released is finalised inside,
including a dropped or removed path whose release was never reported), then
the platform closes its sockets; `on_platform_path_released()` is never
called after destroy.

**Why the 2026-08-08 decision was reversed.** Until ABI 3 the library sent on
the platform's fds itself while receives were pushed in, and this section
recorded the decision to keep that split: the only delegated-send hook,
`send_packet`, returned `void` and could not report "would block" versus a
hard error, and delegating TX looked like cost without a feature. A survey of
20 production VPN, QUIC and netstack projects (2026-09-16) found none in which
the library sends and the platform receives. Designs that delegate TX return a
synchronous blocked/error status (Google quiche `WriteResult`, lsquic, quinn,
gVisor); GSO lives behind the transport interface (wireguard-go `StdNetBind`,
quiche `QuicGsoBatchWriter`); mobile stacks keep the socket in the core and
let the platform only `protect()` it. ABI 3 took that shape: a send contract
with a synchronous result removes the reason for the split, the TX features
that had piled up on the library's side of it (GSO with its sticky fallback,
send telemetry, socket buffers) moved into the POSIX bind, and a relay (issue
#218) or a test transport now plugs into the same interface as a socket.

**Where a socket feature belongs.** `UdpGso` stays the single user-facing
knob: the core derives from it whether to batch sends (Linux only, with the
`MQVPN_MAX_PKT_OUT_SIZE <= 1500` guard for the GSO run bound), and the POSIX
bind derives whether GSO is allowed from the same value, so the two cannot
drift. UDP GRO has no library API: it is an option of the POSIX bind (fed
by the CLI's `UdpGro` key, and by a JNI constant on Android), which sets the
sockopt and splits the coalesced buffer, and the core only ever sees single
datagrams. A socket feature that only a transport uses gets no library config
knob — it would be ABI that nothing in the library reads and that SemVer does
not let us remove.

## §3 Path removal: the platform drop lifecycle contract

Platform-triggered removal uses `drop_path()` (a thin wrapper of
`mqvpn_client_on_platform_path_dropped(…, NULL)`), not `remove_path()`
(`EVENT_REMOVE_API`, orderly application-level close). The drop contract, end
to end:

1. the caller emits a **non-blocking** `PATH_ABANDON` (`xqc_conn_close_path`,
   queued on an alternate path) while the slot is still xquic-live — *before*
   dispatching the FSM event;
2. `EVENT_PLATFORM_DROP` → the FSM sets `transport_attached=0` and moves the
   slot to `CLOSED_DROPPED`. The FSM itself never calls xquic — the caller
   already did (the FSM stays xquic-API-free by design);
3. the platform stops the path's I/O and closes its socket, then calls
   `mqvpn_client_on_platform_path_released()`, which harvests the
   transport's stats and calls `ops.release` itself before dispatching
   `EVENT_TRANSPORT_RELEASED` (the event only clears the slot's fields);
4. `CLOSED_DROPPED → CLOSED_FREE` is a **lazy gate**, not a direct edge: it
   fires only once `transport_released && xquic_path_live==0 &&
   xqc_path_id==0`. Two independent async completions each re-evaluate the
   gate — the release above, and the `PATH_ABANDON` landing as
   `EVENT_XQUIC_REMOVED` (which clears the xquic-side fields). Whichever
   lands last drives `CLOSED_FREE`.

`RTM_DELLINK`/`RTM_DELADDR` → `drop_path()`; `path_removed_by_platform` is
*not* reset while RECONNECTING. `remove_path()` runs the same
close-then-dispatch shape with an orderly reason code; since draft-21 (commit
0cd4136) **both** drop and remove emit `PATH_ABANDON` to free the CID/path_id
slot for reuse, and since ABI 3 both leave the socket with the platform, so
the two differ only in the reason code (plus the diagnostic context
`on_platform_path_dropped()` can log) — *not* in close_path avoidance. The
old "never call close_path / 3×PTO stall" rationale is obsolete — the
non-blocking abandon no longer stalls surviving paths (the `MAX_PATH_ID`
dynamic grant lets the re-added path skip the drain wait — netns-verified, 0%
loss).

## §4 Path lifecycle is per platform

Linux/Windows/macOS use drop + reactivate; Android/iOS use remove + add
(ConnectivityManager semantics). Do not unify them. Windows keys paths by
interface LUID.

## §5 Log level mapping

mqvpn levels map one step down into xquic (mqvpn INFO → xquic WARN).
Reverting to a 1:1 mapping reintroduces a 5× throughput cliff on Windows from
per-packet logging.

## §6 WLB scheduler

The WLB scheduler is production-grade: weights learned from acknowledged
goodput, smooth weighted round-robin, inner-TCP flow pinning, and soft
spillover when a pinned path is cwnd-blocked. Its measured behaviour lives in
the benchmark results, not here:
see `docs/benchmarks_netns.md` and the benchmark pages on the website, which
are regenerated as the implementation changes. Do not casually add
BLEST/LLHD-style schedulers. For jitter-sensitive real-time streams
(SRT/RTP), recommend `Scheduler = minrtt` instead of writing a new
scheduler.

## §7 The hybrid TCP lane is scheduled by MinRTT, not by WLB — by construction

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

Both the conceptual case and the measured one favour the MinRTT fallback for
the stream lane, so the bar for moving it toward WLB is a measurement on a
shaped multi-path pair that beats MinRTT — not an argument from symmetry with
the datagram lane. This came out of WLB bug-fix work; without that
measurement, leave the lane on MinRTT.

## §8 Reorder buffer scope

The tunnel-layer reorder shim exists only for bandwidth-aggregating a *single
inner QUIC connection*; inner TCP and FEC are out of scope. Invariant:
in-order delivery is the QUIC STREAM layer's job; DATAGRAM bypasses ordering
at every layer.

## §9 Spec compliance, draft-21 and xquic naming

IETF RFC/draft compliance is the top priority. Never make a library change
that deviates from spec to suppress a symptom; if a deviation looks
unavoidable, stop and consult the maintainer first. Known scoping decision:
ECN accounting is out of scope for the draft-21 multipath work —
`PATH_ACK_ECN` keeps the PATH_ACK recovery semantics (draft-21 §4.1) and its
ECN counts are parsed and discarded.

xquic's `MULTIPATH_xx` / `dev/multipath_xx` names are xquic-internal version
labels, **not** IETF draft numbers — read the code to determine actual draft
semantics. draft-21 path management is dynamic (`PATHS_BLOCKED` ↔
`MAX_PATH_ID` loop); the old "bump `XQC_MAX_PATHS_COUNT`" strategy is
obsolete.

## §10 Build, test and small decisions

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
- Adding a config key = one row in the config descriptor table + one key in
  the parity test (see the config table refactor, PR #185) + the key on the
  website configuration pages.
- Benchmark outputs: `ci_sweep_results/` is transient (gitignored);
  `bench_results/` is the tracked archive for results worth keeping.

## §11 Git: branch bases and history

`dev` and `main` can diverge in both directions (at times one is simply
behind the other), so the base of a bug-fix branch is decided per fix: start
from the tip of the release line where the bug was found, not from whatever
checkout you happen to be on. External contributors
target `dev`; maintainers backport. `main` is updated only via GitHub PRs
merged in the web UI. No force-push once a PR is open; stack corrections as
new commits and squash only when asked.

## §12 Fork divergence is re-paid at every upstream merge

Upstream is tracked by periodic full merges, not cherry-picks, so **every
line of divergence is paid again at every merge**. Weigh a fork-local change
against that recurring cost: prefer a fix that can land upstream, then one
confined to files upstream rarely touches; treat divergence in a widely
edited public header as the expensive option. This is why WLB lives in
`src/transport/scheduler/` behind `xqc_scheduler_callback_t` instead of
spreading through `xqc_conn.c` / `xqc_send_ctl.c`.

## §13 In the fork, ABI breaks are cheap and public API is not

Growing a struct that a public struct embeds by value — `xqc_scheduler_callback_t`
sits inside `xqc_conn_settings_t` — shifts every later field: source-compatible,
binary-incompatible, and *silent*, because `libxquic.so` carries no SONAME
version. That is acceptable: xquic and mqvpn ship as a pinned pair per
`mqvpn-vX.Y.Z`, and upstream grows `xqc_conn_settings_t` between releases too
(63 fields at v1.8.3, 69 at main). A coordinated rebuild plus a SemVer bump
covers it. Exported *functions* are the opposite — adding one is free (a new
symbol breaks nothing), removing one needs a major bump. So the irreversible
direction is publishing API, not breaking ABI: never add public accessors
speculatively, and do not bundle them into an unrelated ABI break on the
theory that the window is closing. It never closes.

Per-path scheduler telemetry therefore has a home already: the "extended
metrics" block in `xqc_path_metrics_t`, reached via `xqc_conn_get_stats()` →
`paths_info[]`, which mqvpn already iterates (`mqvpn_server.c`) and forwards
into `mqvpn_path_stats_t` and the control API. Put new scheduler
observability there rather than in a scheduler-specific API, so the retrieval
surface stays single. Caveat: `xqc_path_metrics_t` has no
`struct_size`/version field, so the caller's `sizeof` sets the
`paths_info[i]` stride — growing it is a coordinated-rebuild change like the
one above. Adding such a field is itself upstream divergence; propose it
upstream rather than carrying it.
