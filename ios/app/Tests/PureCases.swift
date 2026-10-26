// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors
// Foundation-only cases shared by run-host-tests.sh (via main.swift) and
// run-pure-tests.sh (via pure_main.swift); must compile on Linux.
import Foundation

/// Returns the failure count. check() is nested so it cannot collide with
/// main.swift's global check() when both files are in one module.
func runPureCases() -> Int {
    var failures = 0
    func check(_ cond: Bool, _ msg: String) { if !cond { failures += 1; print("FAIL: \(msg)") } }

    check(1 + 1 == 2, "harness sanity")

    return failures
}
