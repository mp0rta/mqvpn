// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors
// Entry point for run-pure-tests.sh only. @main because top-level code is only
// allowed in main.swift; never add this file to run-host-tests.sh or Xcode.
import Foundation

@main struct PureMain {
    static func main() async {
        setvbuf(stdout, nil, _IONBF, 0)
        let n = runPureCases()
        print(n == 0 ? "pure tests: ALL PASS" : "pure tests: \(n) FAILURES")
        exit(n == 0 ? 0 : 1)
    }
}
