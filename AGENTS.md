# AGENTS.md — guidance for AI coding agents

mqvpn is a multipath QUIC VPN built on a vendored xquic fork, speaking MASQUE
CONNECT-IP (RFC 9484). Components: libmqvpn (core C library), Linux CLI,
Android SDK, Windows/macOS/iOS ports, and a hybrid TCP lane (lwIP). It is
integrated into OpenMPTCProuter, so there are real users: the config format,
the control API and log wording are compatibility surfaces, and a PR that
renames or removes a config key or changes a default states the
compatibility impact in its description.

Human contributors: start with [CONTRIBUTING.md](CONTRIBUTING.md). This file
is the agent-facing map of the repository and the list of rules that must not
be re-litigated without new evidence. Rules that cite `[DD §n]` have their
rationale in [docs/design-decisions.md](docs/design-decisions.md); read the
cited section before changing the code a rule covers. Keep this file short:
rules belong here, reasons there.

## Map

- `include/libmqvpn.h` — public C API (callback ABI v2)
- `src/mqvpn_client.c`, `src/mqvpn_server.c`, `src/mqvpn_internal.h`,
  `src/mqvpn_scheduler.h` — library core
- `src/path_state_machine.c`, `src/path_mgr.c` — path lifecycle FSM
- `src/platform/{linux,windows,darwin,posix}/` — platform layers
- `src/hybrid/` — hybrid TCP lane on lwIP
- `third_party/xquic` — fork `mp0rta/xquic`, branch `mqvpn-main`;
  `third_party/lwip` — fork `mp0rta/heiher-lwip`, branch `mqvpn-main`
  (`git submodule update --init --recursive` after checkout)
- `tests/` (unit tests, e2e shell scripts), `scripts/ci_e2e/` (netns e2e),
  `.github/workflows/ci.yml`; build and test commands are in CONTRIBUTING.md
  sections 3 and 4 (the CI `sanitizer` job uses the same configure)
- `docs/design-decisions.md` (why), `docs/control-api.md`, `website/`
  (user docs, English plus `ja/`)

## Rules — architecture

- libmqvpn is sans-I/O: the platform drives the xquic engine by calling
  `tick()`. `connect()` performs connection setup only and MUST NOT call
  `xqc_engine_main_logic()`. [DD §1]
- On the QUIC path sockets RX belongs to the platform and TX to the library:
  the library never calls `recv*()` on them, platforms never send on them.
  Every platform passes NULL for the `send_packet` callback; do not wire it
  up. Platform-only socket features (UDP GRO) get no library config knob.
  [DD §2]
- Platform-triggered path removal uses `drop_path()`; orderly removal uses
  `remove_path()`. The FSM never calls xquic; the caller emits `PATH_ABANDON`
  before dispatching the event. Do not add a direct edge for
  `CLOSED_DROPPED → CLOSED_FREE` (it is a lazy gate). Since draft-21 both
  drop and remove emit `PATH_ABANDON`; do not reintroduce close_path
  avoidance. [DD §3]
- Path lifecycle is per platform: Linux/Windows/macOS use drop + reactivate,
  Android/iOS use remove + add. Do not unify them. [DD §4]
- Public structs that carry `struct_size` grow only by appending fields, each
  with an `appended under ABI N` comment. `MQVPN_MAX_PATHS` is ABI-frozen.
- In the xquic fork the trade is reversed: growing a struct is an acceptable
  ABI break (pinned pair, coordinated rebuild, SemVer bump), while publishing
  a new exported function is the irreversible direction. Never add public
  accessors speculatively. [DD §13]
- New per-path scheduler observability goes in the extended-metrics block of
  `xqc_path_metrics_t` (via `xqc_conn_get_stats()` → `paths_info[]`), not a
  scheduler-specific API. [DD §13]
- The shared library links shared xquic. Signal handling lives only in the
  CLI, never in the library. [DD §1]
- `xqc_engine_destroy()` frees the h3 context; do not also call
  `xqc_h3_ctx_destroy()`.
- mqvpn log levels map one step down into xquic (INFO → WARN). Do not
  revert to 1:1. [DD §5]
- WLB is the production scheduler. Do not casually add BLEST/LLHD-style
  schedulers; for jitter-sensitive streams recommend `Scheduler = minrtt`.
  [DD §6]
- The hybrid TCP lane is scheduled by MinRTT by construction. Do not extend
  WLB pinning or WRR to streams: both the conceptual and the measured case
  favour the MinRTT fallback, so the evidence that reopens this is a
  measurement on a shaped pair, not an argument. Aggregation is expected only
  where a single path cannot absorb the load. [DD §7]
- The reorder buffer serves a single inner QUIC connection only; DATAGRAM
  bypasses ordering at every layer; inner TCP and FEC are out of scope.
  [DD §8]
- IETF RFC/draft compliance is the top priority. Never deviate from spec to
  suppress a symptom; consult the maintainer first. draft-21 ECN accounting
  is out of scope: `PATH_ACK_ECN` keeps PATH_ACK recovery semantics and its
  ECN counts are parsed and discarded. [DD §9]
- xquic's `MULTIPATH_xx` names are internal labels, not draft numbers.
  draft-21 path management is dynamic (`PATHS_BLOCKED` / `MAX_PATH_ID`); do
  not bump `XQC_MAX_PATHS_COUNT`. [DD §9]
- The MTU config upper bound stays 9000 until `max_pkt_out_size` becomes
  configurable. [DD §10]

## Rules — change hygiene

- Log wording is an e2e invariant. When a log message changes, update the
  markers in `tests/test_e2e_*.sh`, `scripts/ci_e2e/*.sh` and
  `.github/workflows/ci.yml` in the same change. [DD §10]
- Adding a config key = one row in the descriptor table (`src/config.c`) +
  one key in `test_ini_json_scalar_parity` (`tests/test_config.c`) + the key
  in `website/guide/configuration.md` and `website/ja/guide/configuration.md`.
  [DD §10]
- Test files that call `assert()` carry `#undef NDEBUG` (CI-checked). Claim
  test results only from a Debug or sanitizer build, never from `build.sh`'s
  Release build. [DD §10]
- Before pushing non-trivial C changes, build with clang `-Werror` and
  ASan/UBSan (the CI `sanitizer` job). Control API or connection-lifecycle
  changes need the sudo netns e2e suite (`scripts/ci_e2e/`). [DD §10]
- A new test target must resolve its includes in a clean checkout. [DD §10]
- `ci_sweep_results/` is transient; `bench_results/` is the tracked archive.

## Rules — git

- `main` changes only through GitHub PRs; never push to it. PRs target
  `dev`. Never force-push a branch with an open PR; stack corrections as new
  commits. Commit subject is one line (`type: subject`, `type(scope): subject`
  or `[T] subject`); body only when the why is non-obvious; no tool or
  session trailers (CONTRIBUTING.md sections 5 and 8 say the same). Squash
  only when asked.
- A bug-fix branch starts from the tip of the release line where the bug was
  found; decide the base per fix (`dev` and `main` can diverge). [DD §11]
- A submodule bump PR names the fork PR or tag it comes from; the commit must
  be on the fork's `mqvpn-main`.
- In the xquic fork, `include/xquic/xqc_configure.h` is cmake-generated into
  the source tree: stage files explicitly (never `git add -A`), and any CI
  cache of the xquic build must include that header.
- xquic fork branches: `mqvpn-main` (pinned; tags `mqvpn-vX.Y.Z`),
  `mqvpn-dev` (integration), `main` (pure upstream mirror). Upstream is
  tracked by full merges, not cherry-picks, so every line of fork-local
  divergence is re-paid at every merge: prefer a fix that can land upstream,
  then one confined to files upstream rarely touches. [DD §12]

## Rules — licensing and release

- Copyright notice form: `Copyright (c) <year> <name> and contributors`
  (individual form, not "The X Authors").
- `NOTICE` is attribution-only and lists direct vendored deps only; never a
  change log; transitive deps stay in upstream's own LICENSE/NOTICE.
- GitHub Release notes are edited by hand; the automation leaves the body empty.

## Documentation

- End-user docs (`README.md`, `website/`, `fastlane/`) use end-user vocabulary:
  no PTO, goodput, cwnd or similar jargon without a plain explanation.
- `website/` content pages have `ja/` mirrors with the same file set; update
  both in the same change.

## Definition of done

A change is done when:

- the requested behavior is implemented and its acceptance criteria hold;
- the applicable verification or review for its change kind (CONTRIBUTING.md
  section 6) is complete, and command output was checked where a command
  applies;
- every compatibility surface it touches carries its companion change;
- the change modified or staged no unrelated file and left unrelated user
  changes and untracked files in place; and
- the pull request body names the verifications that ran and their outcome.
