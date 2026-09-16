# Design decisions

Rationale and history behind the rules in [AGENTS.md](../AGENTS.md). Sections
are cited from AGENTS.md as `[DD §n]`. Keep rules there and reasons here.

## §1 Sans-I/O library and `tick()`

libmqvpn contains no libevent. The platform layer owns the reactor
(libevent/epoll/GCD/IOCP) and drives the xquic engine by calling `tick()`.
`connect()` only performs connection setup — never call
`xqc_engine_main_logic()` from `connect()`. Callbacks are ABI-versioned
(currently v2). Platform layers: `src/platform/linux/` (libevent, netlink),
`src/platform/windows/` (wintun, IP Helper), `src/platform/darwin/`,
`src/platform/posix/` (shared).

The shared library links shared xquic because static xquic is built without
`-fPIC`. Signal handling lives only in the CLI, never in the library.

## §2 fd-path mode: RX belongs to the platform, TX to the library

The library calls `sendto()`/`sendmsg()` directly on path fds. A
`send_packet` callback exists in the ABI, but **every** consumer passes NULL —
Linux, Windows, macOS, Android JNI and iOS alike — and new platforms should
too. Do not "restore symmetry" by wiring it up. The decisive reason is the
signature: `mqvpn_send_packet_fn` returns `void`, so a delegated send cannot
report EAGAIN vs. hard error, and xquic requires exactly that distinction (an
`XQC_SOCKET_ERROR` return reaches `xqc_conn_should_close()` and can tear down
the whole connection — see `path_send_dead_retcode` in `src/mqvpn_client.c`).
Cost is only a secondary reason, and a narrower one than it looks: delegating
TX would add a per-packet **upcall** (C → Java, needing
`GetEnv`/`AttachCurrentThread` per call), whereas RX only ever does
**downcalls**. RX genuinely does cross the boundary per packet on Android —
Kotlin calls `recvFrom()` and then `onSocketRecv()`, two JNI downcalls plus
byte-array pinning — so "crossing is expensive" alone does not explain the
split. The void return does.

The platform owns the reactor, so only it can know when a socket is readable:
packets enter via `mqvpn_client_on_socket_recv()` /
`mqvpn_server_on_socket_recv()` and the library never calls `recv*()` on the
QUIC path sockets itself (its hybrid egress reads its own TCP sockets, which
is a different lane).
Receive is a *push* into `xqc_engine_packet_process`, so no return value has
to travel back — which is why RX keeps the sans-I/O rule while TX is its
deliberate exception.

This split decides where a new socket feature belongs. UDP GSO crosses the
public ABI (`mqvpn_config_set_udp_gso`) because the library issues the send;
UDP GRO has **no public API at all**, because setting the sockopt and
splitting the coalesced buffer both happen in the platform layer and the
library only ever sees one datagram at a time. Adding a config knob for a
platform-only feature would create ABI that nothing reads and SemVer will not
let us remove.

**When to revisit the split.** It is a deliberate trade, not a debt on a
schedule. Delegating TX buys conceptual symmetry and nothing else — no
feature, and Android measures ~400ns per packet for the added upcall (~3.6%
of a core at 1 Gbps; 1.09x what RX already pays per packet) — while costing
FSM rewiring (~22 `fd` sites), a full path-lifecycle e2e pass, and
formal-spec follow-up. Even a full migration would not remove the underlying
constraint: xquic's callback contract still demands a synchronous send
result. Reconsider only when one of these lands:

1. a delegated send path (issue #218, pairbond) has run in production long
   enough to be trusted — the cheapest on-ramp to a wider migration;
2. the path-lifecycle formal specs are merged, so the FSM has a spec to
   update rather than one to write from scratch;
3. a **second** bug is traced to the split — the first was the TX
   counterpart of the `udp-rx` telemetry going missing for a release; one is
   chance, two is a pattern;
4. a new platform cannot express its sockets as fds at all.

Until one of those, the split stays a documented decision rather than an
accident — which is the entire reason it is written down here.

## §3 Path removal: the platform drop lifecycle contract

Platform-triggered removal uses `drop_path()` (a thin wrapper of
`mqvpn_client_on_platform_path_dropped(…, NULL)`), not `remove_path()`
(`EVENT_REMOVE_API`, orderly application-level close). The drop contract, end
to end:

1. the caller emits a **non-blocking** `PATH_ABANDON` (`xqc_conn_close_path`,
   queued on an alternate path) while the slot is still xquic-live — *before*
   dispatching the FSM event;
2. `EVENT_PLATFORM_DROP` → the FSM sets `platform_attached=0` and moves the
   slot to `CLOSED_DROPPED`. The FSM itself never calls xquic — the caller
   already did (the FSM stays xquic-API-free by design);
3. the platform `close()`s the fd, then calls
   `mqvpn_client_on_platform_fd_closed()` → `EVENT_FD_CLOSED` sets `fd=-1`;
4. `CLOSED_DROPPED → CLOSED_FREE` is a **lazy gate**, not a direct edge: it
   fires only once `fd<0 && xquic_path_live==0 && xqc_path_id==0`. Two
   independent async completions each re-evaluate the gate — the fd-close
   above, and the `PATH_ABANDON` landing as `EVENT_XQUIC_REMOVED` (which
   clears the xquic-side fields). Whichever lands last drives `CLOSED_FREE`.

`RTM_DELLINK`/`RTM_DELADDR` → `drop_path()`; `path_removed_by_platform` is
*not* reset while RECONNECTING. `remove_path()` runs the same
close-then-dispatch shape with an orderly reason code; since draft-21 (commit
0cd4136) **both** drop and remove emit `PATH_ABANDON` to free the CID/path_id
slot for reuse, so the `drop_path` vs `remove_path` distinction is now reason
code + recoverability + fd ownership, *not* close_path avoidance. The old
"never call close_path / 3×PTO stall" rationale is obsolete — the non-blocking
abandon no longer stalls surviving paths (the `MAX_PATH_ID` dynamic grant lets
the re-added path skip the drain wait — netns-verified, 0% loss).

## §4 Path lifecycle is per platform

Linux/Windows/macOS use drop + reactivate; Android/iOS use remove + add
(ConnectivityManager semantics). Do not unify them. Windows keys paths by
interface LUID.

## §5 Log level mapping

mqvpn levels map one step down into xquic (mqvpn INFO → xquic WARN).
Reverting to a 1:1 mapping reintroduces a 5× throughput cliff on Windows from
per-packet logging.

## §6 WLB scheduler

The WLB scheduler is production-grade (LATE + OLB + flow pinning + soft
spillover; 2–4× throughput vs. glorytun/openvpn in real deployments). Do not
casually add BLEST/LLHD-style schedulers. For jitter-sensitive real-time
streams (SRT/RTP), recommend `Scheduler = minrtt` instead of writing a new
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
