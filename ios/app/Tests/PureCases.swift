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

    // MARK: snapshot v2 wire / SampleRing / SampleCursor
    do {
        func mk(_ seq: UInt64, tx: UInt64 = 0) -> TunnelSample {
            TunnelSample(seq: seq, wallMs: seq, monoMs: seq, paths: [SamplePath(name: "en0", txBytes: tx, rxBytes: tx)],
                         bytesTx: tx, bytesRx: tx, dgramSent: 0, dgramLost: 0, delivered: 0,
                         gapCount: 0, gapFilled: 0, gapTimeout: 0, ackDemote: 0, residenceBuckets: [1, 2])
        }
        let old = #"{"timestamp":1,"clientState":2,"footprint":3,"paths":[{"name":"en0","status":1,"txBytes":1,"rxBytes":2}]}"#
        if let d = try? ProviderMessage.decode(Data(old.utf8)) {
            check(d.tunnel == nil && d.stats == nil && d.samples.isEmpty && d.bootId == 0, "v2 old-wire defaults")
        } else { check(false, "v2 old-wire decode") }
        let big = UInt64.max
        var snap = TunnelSnapshot(timestamp: 1, clientState: 2, connectedSince: nil, footprint: big, paths: [],
                                  seq: big, reorderConfigured: true,
                                  reorder: ReorderStatsSnapshot(delivered: big, gapCount: 1, gapFilled: 2, gapTimeout: 3, ackDemote: 4,
                                                                bufferedP50Ms: 1, bufferedP99Ms: 2, residenceBuckets: [big]),
                                  tunnel: TunnelInfoSnapshot(assignedIp: "10.0.0.2", prefix: 24, assignedIp6: nil, prefix6: 0,
                                                             hasV6: false, mtu: 1280, serverScheduler: 1, requestedScheduler: nil),
                                  stats: StatsSnapshot(bytesTx: big, bytesRx: big, dgramSent: big, dgramLost: big, srttMs: 1.5),
                                  samples: [mk(big, tx: big)], bootId: big)
        if let d = try? ProviderMessage.decode(try! ProviderMessage.encode(snap)) {
            check(d.samples == snap.samples && d.samples[0].bytesTx == big && d.bootId == big, "v2 UInt64.max samples")
            check(d.stats == snap.stats && d.tunnel == snap.tunnel, "v2 tunnel/stats round-trip")
            check(d.reorder == snap.reorder && d.reorder?.residenceBuckets == [big], "v2 reorder buckets")
        } else { check(false, "v2 round-trip decode") }
        snap = TunnelSnapshot(timestamp: 1, clientState: 2, connectedSince: nil, footprint: 3, paths: [])
        check(snap.samples.isEmpty && snap.bootId == 0, "v2 init defaults")

        // request codec
        check(SnapshotRequest.encode(cursor: nil).isEmpty, "req nil -> empty")
        check(SnapshotRequest.decode(Data()) == nil, "req empty -> nil")
        check(SnapshotRequest.decode(Data("garbage".utf8)) == nil, "req garbage -> nil")
        let rd = SnapshotRequest.decode(SnapshotRequest.encode(cursor: (sinceSeq: big, bootId: 7)))
        check(rd?.sinceSeq == big && rd?.bootId == 7, "req round-trip")

        // ring
        let ring = SampleRing()
        check(ring.since(nil).isEmpty && ring.since(5).isEmpty, "ring empty")
        for i in 1...40 { ring.append(mk(UInt64(i))) }
        check(ring.since(nil).count == 31 && ring.since(nil).first?.seq == 10, "ring keeps last 31")
        check(ring.since(35).map { $0.seq } == [36, 37, 38, 39, 40], "ring since mid")
        check(ring.since(40).isEmpty, "ring since newest")
        check(ring.since(41).count == 31, "ring since ahead -> all (restart)")
        check(ring.since(9).count == 31, "ring since oldest-1 contiguous")
        check(ring.since(8).count == 31, "ring since older than oldest-1 -> all")
        ring.clear()
        check(ring.since(nil).isEmpty, "ring clear")

        // provider rule: bootId mismatch -> full ring
        for i in 1...5 { ring.append(mk(UInt64(i))) }
        func provider(_ req: (sinceSeq: UInt64, bootId: UInt64)?, boot: UInt64) -> [TunnelSample] {
            guard let r = req, r.bootId == boot else { return ring.since(nil) }
            return ring.since(r.sinceSeq)
        }
        check(provider((sinceSeq: 4, bootId: 9), boot: 9).map { $0.seq } == [5], "provider matching boot filters")
        check(provider((sinceSeq: 4, bootId: 8), boot: 9).count == 5, "provider boot mismatch -> full")
        check(provider(nil, boot: 9).count == 5, "provider nil -> full")

        // cursor
        var cur = SampleCursor()
        check(cur.request == nil, "cursor initial request nil")
        var r = cur.accept(bootId: 1, samples: [mk(1), mk(2)])
        check(r.reset && r.fresh.count == 2, "cursor first accept resets")
        check(cur.request?.sinceSeq == 2 && cur.request?.bootId == 1, "cursor request after accept")
        r = cur.accept(bootId: 1, samples: [mk(1), mk(2)])
        check(!r.reset && r.fresh.isEmpty, "cursor dedup")
        r = cur.accept(bootId: 1, samples: [mk(2), mk(3)])
        check(!r.reset && r.fresh.map { $0.seq } == [3] && cur.request?.sinceSeq == 3, "cursor overlap")
        r = cur.accept(bootId: 2, samples: [mk(1)])
        check(r.reset && r.fresh.count == 1 && cur.request?.sinceSeq == 1 && cur.request?.bootId == 2, "cursor bootId change resets")
        r = cur.accept(bootId: 2, samples: [])
        check(!r.reset && r.fresh.isEmpty && cur.request?.sinceSeq == 1, "cursor empty keeps position")
    }

    return failures
}
