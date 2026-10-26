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

    // TunnelPolicies
    do {
        let d = SplitSettings(providerConfiguration: [:])
        check(d.scheduler == nil && !d.redundantEnabled && d.redundantPorts.isEmpty && !d.redundantPortsMalformed, "split defaults")
        check(d.choice == .throughput, "legacy choice throughput")
        check(SplitSettings(providerConfiguration: nil) == d, "split nil dict")
        let legacy: [String: Any] = ["serverHost": "h", "reorderEnabled": NSNumber(value: true)]
        let ls = SplitSettings(providerConfiguration: legacy)
        var out: [String: Any] = [:]
        ls.merged(into: &out)
        check(out["scheduler"] == nil, "legacy nil scheduler stays absent")
        check(ls.tapped(.throughput).scheduler == 1, "tap throughput writes wlb")
        let pr = ProtectionSettings(providerConfiguration: legacy)
        check(!pr.killSwitch && pr.autoReconnect, "protection defaults")
        let pp = PathPolicy(providerConfiguration: legacy)
        check(pp.wifi && pp.cellular && pp.anyEnabled, "path defaults")
        for (w, c, any) in [(true, true, true), (true, false, true), (false, true, true), (false, false, false)] {
            check(PathPolicy(wifi: w, cellular: c).anyEnabled == any, "anyEnabled \(w) \(c)")
        }
        // read matrix
        func ch(_ s: Int32?, _ r: Bool) -> SplitChoice {
            SplitSettings(scheduler: s, redundantEnabled: r, redundantPorts: [], redundantPortsMalformed: false).choice
        }
        check(ch(1, false) == .throughput, "choice wlb")
        check(ch(0, false) == .lowLatency, "choice minrtt")
        check(ch(nil, false) == .throughput, "choice nil")
        check(ch(1, true) == .redundant && ch(0, true) == .redundant && ch(nil, true) == .redundant, "choice redundant")
        // write matrix; ports kept
        let base = SplitSettings(scheduler: nil, redundantEnabled: false, redundantPorts: [4200], redundantPortsMalformed: false)
        let t1 = base.tapped(.throughput), t2 = base.tapped(.lowLatency), t3 = base.tapped(.redundant)
        check(t1.scheduler == 1 && !t1.redundantEnabled, "tap throughput")
        check(t2.scheduler == 0 && !t2.redundantEnabled, "tap lowLatency")
        check(t3.scheduler == 0 && t3.redundantEnabled, "tap redundant")
        check(t1.redundantPorts == [4200] && t2.redundantPorts == [4200] && t3.redundantPorts == [4200], "tap keeps ports")
        // round trip
        for s in [base, t1, t2, t3] {
            var m: [String: Any] = [:]
            s.merged(into: &m)
            check(SplitSettings(providerConfiguration: m) == s, "split round-trip")
        }
        var m0: [String: Any] = [:]
        base.merged(into: &m0)
        check(m0["scheduler"] == nil, "nil scheduler omitted")
        var mk: [String: Any] = [:]
        ProtectionSettings(killSwitch: true, autoReconnect: false).merged(into: &mk)
        PathPolicy(wifi: false, cellular: true).merged(into: &mk)
        check(ProtectionSettings(providerConfiguration: mk) == ProtectionSettings(killSwitch: true, autoReconnect: false), "protection round-trip")
        check(PathPolicy(providerConfiguration: mk) == PathPolicy(wifi: false, cellular: true), "path round-trip")
        check(mk["pathWifi"] != nil && mk["pathCellular"] != nil && mk["killSwitch"] != nil && mk["autoReconnect"] != nil, "policy keys")
        // malformed ports
        let bad: [[Any]] = [[NSNumber(value: true)], [NSNumber(value: 0)], [NSNumber(value: 65536)],
                            [NSNumber(value: 80), "x"], [NSNumber(value: 1.5)],
                            (1...17).map { NSNumber(value: $0) }]
        for b in bad {
            check(SplitSettings(providerConfiguration: ["redundantPorts": b]).redundantPortsMalformed, "malformed ports \(b)")
        }
        check(SplitSettings(providerConfiguration: ["redundantPorts": "80"]).redundantPortsMalformed, "ports not array")
        let badDict: [String: Any] = ["redundantPorts": [NSNumber(value: 0)]]
        var saved = badDict
        SplitSettings(providerConfiguration: badDict).tapped(.throughput).merged(into: &saved)
        check(SplitSettings(providerConfiguration: saved).redundantPortsMalformed, "malformed ports survive save")
        check(SplitSettings(providerConfiguration: saved).scheduler == 1, "save still writes scheduler")
        let okp = SplitSettings(providerConfiguration: ["redundantPorts": [NSNumber(value: 80), NSNumber(value: 443)]])
        check(!okp.redundantPortsMalformed && okp.redundantPorts == [80, 443], "valid ports")
        // parse
        check(SplitSettings.parseRedundantPorts("") == [] && SplitSettings.parseRedundantPorts("  ") == [], "blank ports")
        check(SplitSettings.parseRedundantPorts(" 4200, 9000 ") == [4200, 9000], "parse ports")
        check(SplitSettings.parseRedundantPorts(String(repeating: "4200,", count: 15) + "4200") == [4200], "16 dup ok")
        for v in ["abc", "0", "65536", "80,,81", "80,x", "80,", "-1",
                  (1...17).map(String.init).joined(separator: ","),
                  String(repeating: "1", count: 255)] {
            check(SplitSettings.parseRedundantPorts(v) == nil, "reject ports \(v)")
        }
    }

    return failures
}
