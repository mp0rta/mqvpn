### Mechanism

<!-- Explain the changed mechanism concisely. For protocol behaviour, cite the
exact RFC or draft section. Otherwise write `Not applicable`. Reference the
issue as `Refs #123`. -->

- RFC or draft: `<RFC/draft section, or Not applicable>`

### Validation Cases

<!-- One line per case: the verification from the CONTRIBUTING.md table that
ran and its concise outcome (for example `sanitizer ctest`,
`scripts/ci_e2e/run_control_api_test.sh`, `android ./gradlew test`). For a
documentation-only change, write `Not applicable` with a reason. -->

- `<verification>` — `<concise outcome>`

### Compatibility surfaces

<!-- Tick every surface this PR touches. The companion changes each one needs
are listed in the CONTRIBUTING.md table "What to verify for each kind of
change"; confirm they are in this PR. -->

- [ ] None
- [ ] Config key or default — compatibility impact: `<none / describe>`
- [ ] Control API
- [ ] Connection lifecycle
- [ ] Log wording
- [ ] `include/libmqvpn.h`
- [ ] Submodule pin — fork PR or tag: `<link>`
