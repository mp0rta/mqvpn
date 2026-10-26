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

    // ServerAddressField
    for (text, h, p) in [
        ("example.net", "example.net", 443),
        ("example.net:8443", "example.net", 8443),
        ("fd00::1", "fd00::1", 443),
        ("[fd00::1]", "fd00::1", 443),
        ("[fd00::1]:8443", "fd00::1", 8443),
        (" example.net:443 ", "example.net", 443),
    ] {
        let r = ServerAddressField.parse(text)
        check(r?.host == h && r?.port == p, "address parse \(text)")
        let f = r.map { ServerAddressField.format(host: $0.host, port: $0.port) } ?? ""
        let r2 = ServerAddressField.parse(f)
        check(r2?.host == h && r2?.port == p, "address round-trip \(text)")
    }
    check(ServerAddressField.format(host: "203.0.113.10", port: 443) == "203.0.113.10:443", "format v4")
    check(ServerAddressField.format(host: "fd00::1", port: 8443) == "[fd00::1]:8443", "format v6")
    for t in ["", "  ", "[fd00::1", "example.net:0", "example.net:65536", "example.net:", ":443",
              "a b", "[fd00::1]x", "[example]:1", "1:2:xyz", "example.net:123456"] {
        check(ServerAddressField.parse(t) == nil, "address reject \(t)")
    }

    return failures
}
