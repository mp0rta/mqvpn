# Contributing to mqvpn

Thanks for helping. This page is for people; coding agents start at
[AGENTS.md](AGENTS.md).

## 1. Scope and license

mqvpn is Apache-2.0. Contributions are accepted under the same license
(inbound = outbound); there is no CLA. New first-party source files start
with the standard two-line header:

```c
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors
```

`scripts/dev/insert_spdx.sh` adds it to files that lack it.

## 2. Where to ask

- Questions and ideas: use GitHub Discussions or the Discord community (the
  link is in the README, section "Community").
- Security vulnerabilities: report them privately through GitHub, not in an
  issue or a discussion. See [SECURITY.md](SECURITY.md).

## 3. Prerequisites and the Release build

See README § Building for the dependencies, `git clone --recurse-submodules`
and `./build.sh`. If you already have a checkout, run
`git submodule update --init --recursive` once.

## 4. Testing

`./build.sh` produces a Release build, and `assert()` is compiled out there,
so tests must run on a Debug build. `ENABLE_SANITIZERS` adds clang `-Werror`,
ASan and UBSan, the same flags as the CI `sanitizer` job. Use a separate
build directory so `build.sh`'s Release cache is left untouched:

```bash
mkdir -p build-asan && cd build-asan
CC=clang cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON \
    -DMQVPN_ENABLE_HYBRID_TCP_LANE=ON \
    -DXQUIC_BUILD_DIR=../third_party/xquic/build .. && make -j"$(nproc)"
ctest --output-on-failure
```

Formatting is checked with clang-format 18.1.3 exactly; `mise install` pins
it, or `pipx install clang-format==18.1.3` without mise. When the
`format-check` job fails, the CI log prints the command that fixes it.
Android: `cd android && ./gradlew test`.

Changes to the control API or the connection lifecycle also need the netns
e2e suite in `scripts/ci_e2e/`. It needs Linux and root, plus the packages
the `netns-tests` job in `.github/workflows/ci.yml` installs. For the
control API run `run_control_api_test.sh`; for the connection lifecycle,
`run_reconnect_test.sh`, `run_dellink_test.sh`, `run_8paths_dellink_test.sh`,
`run_carrier_flap_test.sh`, `run_addr_del_failover_test.sh`,
`run_admin_down_test.sh`, `run_validation_blackhole_test.sh` and
`run_route_gate_test.sh`. If you cannot run them, say so under Validation
Cases and a maintainer will.

## 5. Branches and pull requests

- Create your branch from `main` and open the pull request against `main`,
  the default in GitHub's pull request form. If a maintainer wants your
  change on `dev` instead, they will tell you.
- For a bug fix, say which released version reproduces the bug.
- Title: `type: subject` or `type(scope): subject` with a lowercase type,
  as the history uses. The xquic fork's `[T] subject` / `[T]: subject` form
  (T one of `+` add, `-` remove, `=` no behaviour change, `~` behaviour
  change) is also accepted. Write it as a command (`Add X`, not `Added X`),
  with no trailing period and at most 72 characters. Squash merges reuse the
  title as the commit subject.
- Fill in the pull request template. To link an issue, write `Refs #123`.
  To close it automatically when the pull request merges into `main`, write
  `Fixes #123`.
- Once the pull request is open, do not force-push; add commits instead.
- CodeRabbit reviews every PR automatically. If new pushes stop getting
  reviewed, comment `@coderabbitai review`. Address each finding or explain
  why you are dismissing it.
- CI must be green. For a first-time contributor, GitHub holds the workflow
  runs until a maintainer approves them; that is normal.
- Maintainers merge on GitHub.

## 6. What to verify for each kind of change

| Change | Required in the same PR |
|---|---|
| C library (`src/`, `include/`) | Debug `ctest` in the sanitizer build above |
| Control API | `docs/control-api.md` updated; `scripts/ci_e2e/run_control_api_test.sh` |
| Connection lifecycle (paths, reconnect) | sudo netns e2e suite (`scripts/ci_e2e/`) |
| Any log message | search `tests/test_e2e_*.sh`, `scripts/ci_e2e/`, `.github/workflows/ci.yml` for the old wording and update every hit (no hits is fine) |
| Config key or default | companion changes per AGENTS.md (config key rule); compatibility impact stated in the PR description |
| `include/libmqvpn.h` | ABI-additive per AGENTS.md; no release version bump in a feature PR, but bump `MQVPN_SOVERSION` when `tests/test_abi_sizes.c` asks for it |
| xquic or lwIP submodule pin | name the fork PR or tag in the PR description |
| Android | `cd android && ./gradlew test` |
| Docs / website | keep English and `website/ja` in step |

### Adding a config key

Steps 1–3 apply to every key. A key the library reads also needs steps 4–6.
A key only the platform code reads (for example `UdpGro`) skips step 4 and,
in step 5, ends in the platform code that uses it instead of a setter call.

1. `src/config.h`: the field in `mqvpn_file_config_t`, and a non-zero default
   in `mqvpn_config_defaults()` (`src/config.c`). `[Reorder]` and `[Hybrid]`
   keys go in the struct it embeds and in that struct's own default function.
2. `src/config.c`: one row in the descriptor table, with the INI and the JSON
   name. `tests/test_config.c`: the key in `test_ini_json_scalar_parity`.
3. `website/guide/configuration.md` and `website/ja/guide/configuration.md`:
   both names. `scripts/lint/check_config_docs.sh` (CI) checks this.
4. The library: a `mqvpn_config_set_*()` setter that checks the value
   (`include/libmqvpn.h`, `src/mqvpn_config.c`), the field and its default in
   `struct mqvpn_config_s` (`src/mqvpn_internal.h`) and `mqvpn_config_new()`.
   `[Reorder]` and `[Hybrid]` keys are fields of the structs that
   `mqvpn_config_apply_reorder()` / `mqvpn_config_apply_hybrid()` copy, so the
   CLI needs no setter for them.
5. The CLI: the field in `src/vpn_client.h` and/or `src/vpn_server.h`, the copy
   in `src/main.c` (and a flag there, if the key has one), and the setter call
   in `src/platform/client_config_bridge.c` (client; `tests/test_config_bridge.c`
   pins it) and/or `linux_platform_run_server()` (server).
6. If the mobile apps expose it: Android `MqvpnConfig.kt`, `MqvpnTunnel.kt`,
   `NativeBridge.kt` and `mqvpn_jni.c`; iOS `MqvpnEngine.swift` and a settings
   section in `ios/app/Shared/`.

## 7. Design constraints

The rules are in [AGENTS.md](AGENTS.md); the reasons are in
[docs/design-decisions.md](docs/design-decisions.md). IETF RFC/draft
compliance comes first: if a fix seems to require deviating from a spec,
raise it with the maintainer before writing code.

## 8. Commit messages

One-line subject in one of the forms from section 5. Add a body only when
the why is not obvious from the diff. No tool or session trailers.
