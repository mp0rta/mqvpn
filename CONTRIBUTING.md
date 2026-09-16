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

- Questions and ideas: the Discord community linked from the README
  (section "Community").
- Bugs and feature requests: GitHub Discussions (issue creation is
  restricted to maintainers; a maintainer opens the tracking issue).
- Security vulnerabilities: do not open an issue; email
  `3p0rta26@gmail.com`.

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

Formatting is checked with clang-format 18.1.3 exactly (`mise install` pins
it); when the `format-check` job fails, the CI log prints the command that
fixes it. Android: `cd android && ./gradlew test`. Changes to the control API
or the connection lifecycle also need the netns e2e suite, which runs under
sudo: `scripts/ci_e2e/`.

## 5. Branches and pull requests

- Open pull requests against `dev`. GitHub's PR form defaults the base to
  `main`; change it to `dev`. Maintainers backport to release lines.
- For a bug fix, say which released version reproduces the bug.
- Title: either `[T] subject` / `[T]: subject` with T one of `+` (add),
  `-` (remove), `=` (no behaviour change), `~` (behaviour change), or
  `type: subject` / `type(scope): subject` with a lowercase type. Imperative
  mood, no trailing period, at most 72 characters. Squash merges reuse the
  title as the commit subject.
- Fill in the pull request template. Reference issues as `Refs #123`;
  closing keywords only work on PRs that target `main`, so issues are closed
  in the release PR.
- Once review has started, do not force-push; add commits instead.
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
| `include/libmqvpn.h` | ABI-additive per AGENTS.md; no version bump in a feature PR |
| xquic or lwIP submodule pin | name the fork PR or tag in the PR description |
| Android | `cd android && ./gradlew test` |
| Docs / website | keep English and `website/ja` in step |

## 7. Design constraints

The rules are in [AGENTS.md](AGENTS.md); the reasons are in
[docs/design-decisions.md](docs/design-decisions.md). IETF RFC/draft
compliance comes first: if a fix seems to require deviating from a spec,
raise it with the maintainer before writing code.

## 8. Commit messages

One-line subject in one of the forms from section 5. Add a body only when
the why is not obvious from the diff. No tool or session trailers.
