# UI Task report: iOS PoC development dashboard

On-device development dashboard for the iOS PoC container app: a provider→app
snapshot IPC plus a single-screen dashboard (connection header, per-path cards,
stats row, sparse event log, bulk-download load tool). Goal is dev/demo
observability during SDK-phase device testing; product-grade styling is out of
scope.

## What was implemented

Stacked on `feat/ios-poc` (base `aa378d8`), one commit per task:

| Commit | Task |
|---|---|
| `1788d7c` | provider snapshot IPC via `handleAppMessage` |
| `c30254c` | poll tunnel snapshot from the container app |
| `bef1408` | dashboard UI with per-path cards |
| `22c297a` | sparse event log from snapshot diffs |
| `31eeb15` | bulk download progress view |

Files (8 changed, all additive to the extension side):

- `Shared/ProviderMessage.swift` — `TunnelSnapshot`/`PathSnapshot` schema + a
  single-point wire codec seam (JSON now, swappable to binary plist).
- `PacketTunnel/SnapshotCache.swift` — tick-thread producer of the snapshot
  (1 s timer, same cadence as the reconcile poll), lock-guarded hand-off cell.
- `PacketTunnel/PacketTunnelProvider.swift` — `handleAppMessage` (reads the
  cache under lock and serializes; never touches the engine) + `snapshot.start()`
  (additive, 0 deletions).
- `App/MqvpnPoCApp.swift` — App entry + `TunnelController` (snapshot polling
  gated by `scenePhase == .active` && connected, 1.5 s; per-path rate from
  consecutive snapshots).
- `App/DashboardView.swift`, `App/PathCardView.swift`, `App/EventLog.swift`,
  `App/BulkDownloadView.swift` — the dashboard, path card + status badge, the
  View-independent diff/ring-buffer event model, and the bulk load tool.

## Constraint compliance (diff-verified)

- C core (`src/`, `include/`) — untouched.
- `GateMetrics.swift`, `PathBinder.swift`, `MqvpnEngine.swift` — untouched.
- No `GATE|` log string changed (`git diff aa378d8..HEAD` — zero `+/-` on any
  `GATE|` line).
- Snapshot cache holds a single-writer (tick thread) / single-reader
  (`handleAppMessage`) invariant; no test-only flags or multi-writer state.

## Build verification

Each task built for the connected device before commit:

```
xcodebuild -project ios/poc/MqvpnPoC.xcodeproj -scheme MqvpnPoC \
  -destination 'platform=iOS,id=<device>' -allowProvisioningUpdates build
```

All five builds: `** BUILD SUCCEEDED **`, zero compile errors, zero code
warnings (only a pre-existing interface-orientation Info.plist warning). New
files verified present in the correct target(s) by inspecting the generated
`project.pbxproj` sources phases (`ProviderMessage.swift` in both App and
PacketTunnel; the rest App-only or PacketTunnel-only as intended).

## On-device acceptance

Device: physical iPhone, iOS 18.6.2. Server: test-server, UDP 443, tunnel
subnet 10.0.0.0/24 (inner gateway 10.0.0.1).

| # | Criterion | Result |
|---|---|---|
| 1 | Start → CONNECTED (green); `en0` + `pdp_ip0` cards both ACTIVE | PASS |
| 2 | Bulk Download: rate moves, progress/reqs/total update | PASS — ~8 MB/s (≈64 Mbps; sane under the server's 100 Mbps cap) |
| 3 | WiFi OFF → `en0` CLOSED (gray), one event; cellular continues, no crash | PASS — `en0` transitions to **CLOSED** (path retained, not dropped from the list); event logged |
| 4 | WiFi ON → `en0` back to ACTIVE, additional event | PASS |
| 5 | background → foreground: polling resumes, display refreshes | PASS |
| 6 | Stop → disconnected, cards gone / "no data", no crash | PASS |
| 7 | `GATE|` log format unchanged | PASS — see below |

### (7) GATE| log-format compatibility — runtime evidence

`idevicesyslog` captured during the session (11,876 lines). The `GATE|`
messages match the baseline wording, field order, and 10 s cadence exactly:

```
GATE| state=4 footprint=2949384 avail=49479416 path[en0] st=1 tx=28436 rx=41409 path[pdp_ip0] st=1 tx=2691 rx=2626
GATE| sockbuf[en0] sndbuf=6291456 rcvbuf=6291456
```

(`state=4` ESTABLISHED with both paths `st=1` ACTIVE also corroborates
criterion 1.)

## Verification-environment finding (not a code defect)

Initial Bulk Download runs failed with `could not connect to the server` while
the tunnel was CONNECTED. Investigation (systematic, boundary-by-boundary):

- The bulk logic is a faithful move of the previously-working code (identical
  guard, `URLSession.shared.data(from:)`, and URL).
- `could not connect to the server` (`cannotConnectToHost`) while connected
  means packets reached the server and got a TCP refusal — i.e. the tunnel /
  routing were working; a not-connected tunnel would time out instead.
- Root cause: the bulk HTTP file server on `10.0.0.1:8080` was not running
  (nothing listening; server-local `curl` refused). The file
  (`/srv/bulk/bulk-100M.bin`) and the tunnel interface (`mqvpn0` / `10.0.0.1`)
  were present.

After starting the file server (bound to the tunnel-inner gateway only), Bulk
Download sustained ~8 MB/s (criterion 2). No app change was needed.

## Notes

- WiFi failover was exercised both by backgrounding to Settings and by pulling
  Control Center over the app; both behaved correctly. The container app is a
  foreground dev tool — iOS suspends it in the background, so dashboard polling
  (intentionally `.active`-gated) and the foreground URLSession bulk load pause
  there while the tunnel and its path failover keep running in the extension.
- Core behavior observed (criterion 3): on WiFi loss the platform layer's
  `remove_path` leaves the slot reported as `CLOSED` rather than dropping it
  from `get_paths`, so the card stays visible in gray.
