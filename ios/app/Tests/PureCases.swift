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

    // MARK: BandwidthHistory (ports of BandwidthHistoryTest.kt, 11 cases)
    do {
        func p(_ n: String, _ tx: UInt64, _ rx: UInt64) -> (name: String, tx: UInt64, rx: UInt64) { (n, tx, rx) }
        let sec: UInt64 = 1000
        func tick(_ h: BandwidthHistory, _ ps: [(name: String, tx: UInt64, rx: UInt64)], _ mono: UInt64) {
            h.onTick(paths: ps, monoMs: mono, wallMs: Int64(mono))
        }
        var h = BandwidthHistory()
        tick(h, [p("wlan0", 1000, 2000)], sec)
        check(h.samples.count == 1 && h.samples.last!.dlBps == 0 && h.samples.last!.ulBps == 0
              && h.samples.last!.perPathUl["wlan0"] == 0 && h.samples.last!.wallMs == 1000, "bw first tick baseline")

        h = BandwidthHistory()
        tick(h, [p("wlan0", 0, 0)], sec)
        tick(h, [p("wlan0", 1000, 250)], 2 * sec)
        var s = h.samples.last!
        check(s.perPathUl["wlan0"] == 8000 && s.perPathDl["wlan0"] == 2000 && s.ulBps == 8000 && s.dlBps == 2000, "bw delta bps")

        h = BandwidthHistory()
        tick(h, [p("wlan0", 0, 0)], sec)
        tick(h, [p("wlan0", 2500, 0)], 3 * sec)
        check(h.samples.last!.perPathUl["wlan0"] == 10000, "bw longer elapsed scales")

        h = BandwidthHistory()
        tick(h, [p("wlan0", 0, 0), p("rmnet0", 0, 0)], sec)
        tick(h, [p("wlan0", 1250, 0), p("rmnet0", 250, 0)], 2 * sec)
        s = h.samples.last!
        check(s.perPathUl["wlan0"] == 10000 && s.perPathUl["rmnet0"] == 2000 && s.ulBps == 12000, "bw total sums paths")

        h = BandwidthHistory()
        tick(h, [p("wlan0", 100, 0), p("wlan0", 200, 0)], sec)
        tick(h, [p("wlan0", 600, 0), p("wlan0", 325, 0)], 2 * sec)
        check(h.samples.last!.perPathUl["wlan0"] == 5000, "bw duplicate ifaces summed")

        h = BandwidthHistory()
        tick(h, [p("wlan0", 9999, 0)], sec)
        tick(h, [p("wlan0", 10, 0)], 2 * sec)
        check(h.samples.last!.perPathUl["wlan0"] == 0, "bw regression re-baselines")
        tick(h, [p("wlan0", 1260, 0)], 3 * sec)
        check(h.samples.last!.perPathUl["wlan0"] == 10000, "bw new baseline used")

        h = BandwidthHistory()
        tick(h, [p("wlan0", 1000, 0)], sec)
        tick(h, [], 2 * sec)
        check(h.samples.last!.perPathUl.isEmpty && h.samples.last!.perPathDl.isEmpty, "bw vanished iface empty")
        tick(h, [p("wlan0", 9_000_000, 0)], 3 * sec)
        check(h.samples.last!.perPathUl["wlan0"] == 0, "bw reappear restarts at zero")

        h = BandwidthHistory()
        tick(h, [p("wlan0", 0, 0)], sec)
        tick(h, [p("wlan0", 999_999, 0)], sec)
        check(h.samples.count == 1 && h.samples.last!.ulBps == 0, "bw non-positive elapsed ignored")

        h = BandwidthHistory(windowMs: 3000)
        for i in 1...5 { tick(h, [p("wlan0", UInt64(i) * 100, 0)], UInt64(i) * sec) }
        tick(h, [p("wlan0", 600, 0)], 6 * sec)
        check(h.samples.map { $0.wallMs } == [3000, 4000, 5000, 6000], "bw samples expire by timestamp")

        h = BandwidthHistory()
        tick(h, [p("wlan0", 500, 500)], sec)
        tick(h, [p("wlan0", 1750, 10)], 2 * sec)
        check(h.samples.last!.dlBps == 0 && h.samples.last!.ulBps == 10000, "bw separate baselines")

        h = BandwidthHistory(windowMs: 1500)
        tick(h, [p("wlan0", 0, 0)], sec)
        tick(h, [p("wlan0", 0, 0), p("rmnet0", 0, 0)], 2 * sec)
        check(h.slots["wlan0"] == 0 && h.slots["rmnet0"] == 1, "bw slots first-seen order")
        tick(h, [p("rmnet0", 0, 0)], 3 * sec)
        tick(h, [p("rmnet0", 0, 0)], 4 * sec)
        check(h.slots["rmnet0"] == 1, "bw slots stable across scroll")
        h.clear()
        check(h.slots.isEmpty, "bw clear empties slots")
        tick(h, [p("rmnet0", 500, 0)], 5 * sec)
        check(h.samples.last!.ulBps == 0 && h.slots["rmnet0"] == 0, "bw after clear restarts")
    }

    // MARK: ReorderHistory + DgramLossWindow (ports of ReorderHistoryTest.kt, 14 cases)
    do {
        func bk(_ at: (Int, UInt64)...) -> [UInt64] {
            var l = [UInt64](repeating: 0, count: 12)
            for (i, v) in at { l[i] = v }
            return l
        }
        func tick(_ h: ReorderHistory, delivered: UInt64 = 0, gapCount: UInt64 = 0, filled: UInt64 = 0,
                  timeout: UInt64 = 0, b: [UInt64]? = nil, _ ms: Int64) {
            h.onTick(delivered: delivered, gapCount: gapCount, gapFilled: filled, gapTimeout: timeout,
                     ackDemote: 0, buckets: b ?? bk(), wallMs: ms)
        }
        func near(_ a: Double?, _ b: Double) -> Bool { a != nil && abs(a! - b) < 1e-9 }

        var h = ReorderHistory()
        tick(h, delivered: 100, 1000)
        check(h.samples.isEmpty, "rh first tick no sample")

        h = ReorderHistory()
        tick(h, filled: 10, timeout: 1, 1000)
        tick(h, filled: 15, timeout: 3, 2000)
        check(h.samples.count == 1 && near(h.samples[0].recoveredPerSec, 5) && near(h.samples[0].lostPerSec, 2)
              && h.samples[0].wallMs == 2000, "rh per-second deltas")

        h = ReorderHistory()
        tick(h, filled: 0, 1000)
        tick(h, filled: 30, 4000)
        check(near(h.samples.first?.recoveredPerSec, 10), "rh late tick real elapsed")

        h = ReorderHistory()
        tick(h, delivered: 500, filled: 50, 1000)
        tick(h, delivered: 10, filled: 2, 2000)
        check(h.samples.isEmpty, "rh reset no sample")
        tick(h, delivered: 20, filled: 4, 3000)
        check(h.samples.count == 1 && near(h.samples[0].recoveredPerSec, 2), "rh after reset rate")

        h = ReorderHistory()
        tick(h, delivered: 100, gapCount: 9, 1000)
        tick(h, delivered: 900, gapCount: 1, 2000)
        check(h.samples.isEmpty, "rh gapCount decrease re-baselines")

        h = ReorderHistory()
        tick(h, delivered: 100, b: bk((3, 10), (4, 10)), 1000)
        tick(h, delivered: 900, b: bk((3, 50), (4, 9)), 2000)
        check(h.samples.isEmpty, "rh one bucket decrease re-baselines")

        h = ReorderHistory()
        tick(h, b: bk((0, 5)), 1000)
        tick(h, b: bk((0, 500)), 2000)
        check(h.samples.count == 1 && h.samples[0].p50Ms == nil && h.samples[0].p99Ms == nil, "rh bucket0 only nil percentiles")

        h = ReorderHistory()
        tick(h, b: bk((0, 1000)), 1000)
        tick(h, b: bk((0, 2000), (1, 50), (2, 40), (3, 10)), 2000)
        check(near(h.samples.first?.p50Ms, 1.0) && near(h.samples.first?.p99Ms, 3.8), "rh percentiles interpolate")

        h = ReorderHistory()
        tick(h, 1000)
        tick(h, b: bk((1, 90), (11, 10)), 2000)
        check(h.samples.first?.p99Ms == Double.infinity && (h.samples.first?.p50Ms ?? 9) < 1.0 + 1e-9, "rh overflow bucket infinity")

        h = ReorderHistory()
        tick(h, filled: 1, b: [], 1000)
        tick(h, filled: 3, b: [], 2000)
        check(h.samples.count == 1 && near(h.samples[0].recoveredPerSec, 2) && h.samples[0].p50Ms == nil
              && h.samples[0].p99Ms == nil, "rh empty buckets nil percentiles")

        h = ReorderHistory(windowMs: 3000)
        tick(h, 0)
        for t in 1...5 { tick(h, filled: UInt64(t), Int64(t) * 1000) }
        check(h.samples.map { $0.wallMs } == [2000, 3000, 4000, 5000], "rh samples expire")

        h = ReorderHistory()
        tick(h, filled: 5, 1000)
        h.clear()
        tick(h, filled: 50, 2000)
        check(h.samples.isEmpty, "rh clear forgets baseline")

        var w = DgramLossWindow()
        check(w.onTick(sent: 100, lost: 1, wallMs: 1000) == nil, "dg first nil")
        check(w.onTick(sent: 100, lost: 1, wallMs: 2000) == nil, "dg no sends nil")
        check(near(w.onTick(sent: 200, lost: 11, wallMs: 3000), 0.1), "dg delta ratio")

        w = DgramLossWindow(windowMs: 2000)
        _ = w.onTick(sent: 0, lost: 0, wallMs: 0)
        _ = w.onTick(sent: 100, lost: 50, wallMs: 1000)
        check(near(w.onTick(sent: 300, lost: 50, wallMs: 4000), 0.0), "dg window drops old points")
        check(w.onTick(sent: 10, lost: 0, wallMs: 5000) == nil, "dg reset nil")
        check(near(w.onTick(sent: 20, lost: 5, wallMs: 6000), 0.5), "dg after reset")
    }

    do { // ChartGeometry + BandwidthFormat (port of ChartGeometryTest / BandwidthFormatTest)
        let now: Int64 = 100_000
        func nr(_ a: Double, _ b: Double) -> Bool { abs(a - b) < 0.01 }
        func bw(_ ms: Int64, _ dl: Double, _ ul: Double, wl: Double? = nil) -> BandwidthSample {
            BandwidthSample(wallMs: ms, dlBps: dl, ulBps: ul,
                            perPathDl: wl != nil ? ["wlan0": wl!, "rmnet0": dl - wl!] : ["rmnet0": dl],
                            perPathUl: ["wlan0": ul])
        }
        func rs(_ ms: Int64, _ rec: Double, _ lost: Double, _ p50: Double?, _ p99: Double?) -> ReorderSample {
            ReorderSample(wallMs: ms, recoveredPerSec: rec, lostPerSec: lost, p50Ms: p50, p99Ms: p99)
        }

        var c = rateChart(samples: [bw(70_000, 1_000_000, 0), bw(85_000, 4_000_000, 500_000, wl: 1_000_000), bw(100_000, 0, 0)],
                          slots: ["wlan0": 0, "rmnet0": 1], dir: .down, nowMs: now, w: 300, h: 100)
        check(c.yMaxLabel == "5 Mbps", "cg rate label")
        check(c.total.count == 5, "cg rate total count")
        if c.total.count == 5, let p0 = c.total[0], let p2 = c.total[2], let p4 = c.total[4] {
            check(nr(p0.x, 0) && nr(p2.x, 150) && nr(p4.x, 300), "cg rate x")
            check(nr(p2.y, 20) && nr(p4.y, 100), "cg rate y")
        } else { check(false, "cg rate points present") }
        check(c.gridYs == [0, 50, 100], "cg grid")
        check(c.series.count == 2, "cg series count")
        if c.series.count == 2, c.series[0].count > 2 {
            check(c.series[0][0] == nil && c.series[0][2] != nil, "cg series gap")
        } else { check(false, "cg series shape") }
        check(c.legend[0].label == "total", "cg legend total")

        c = rateChart(samples: [bw(100_000, 9_000_000, 20_000)], slots: ["wlan0": 0], dir: .up, nowMs: now, w: 300, h: 100)
        check(c.yMaxLabel == "20 Kbps", "cg upload fields")

        c = rateChart(samples: [bw(60_000, 1, 1), bw(100_000, 1, 1)], slots: [:], dir: .down, nowMs: now, w: 300, h: 100)
        check(c.total.count == 1, "cg window drop")

        var wb = waitBars(samples: [rs(98_000, 0, 0, 4, 8), rs(99_000, 0, 0, nil, nil), rs(100_000, 0, 0, 4, 8)],
                          nowMs: now, w: 300, h: 100)
        check(wb.yMaxLabel == "10 ms" && wb.bars.count == 3, "cg wait label/count")
        if wb.bars.count == 3 {
            check(wb.bars[1].h0 == nil && wb.bars[1].h1 == nil, "cg null percentile empty")
            check(nr(wb.bars[0].h0 ?? -1, 40) && nr(wb.bars[0].h1 ?? -1, 80), "cg wait heights")
        }

        wb = waitBars(samples: [rs(90_000, 0, 0, 1, 2), rs(100_000, 0, 0, 1, 2)], nowMs: now, w: 300, h: 100)
        check(wb.bars.count == 2 && nr(wb.bars[0].x, 200) && nr(wb.bars[1].x, 300), "cg missing tick spacing")

        wb = waitBars(samples: [rs(100_000, 0, 0, 1, .infinity)], nowMs: now, w: 300, h: 100)
        check(wb.yMaxLabel == "1000 ms" && wb.legend[1].valueText == ">512 ms", "cg overflow")

        let rb = reorderBars(samples: [rs(100_000, 6, 2, nil, nil), rs(99_000, 1, 0, nil, nil)], nowMs: now, w: 300, h: 80)
        check(rb.yMaxLabel == "8/s" && rb.bars.count == 2, "cg reorder label")
        if rb.bars.count == 2 { check(nr(rb.bars[0].greenH, 60) && nr(rb.bars[0].redH, 20), "cg reorder heights") }

        func rate(_ gap: Int64) -> [ChartPoint?] {
            rateChart(samples: [bw(100_000 - gap, 1, 1), bw(100_000, 1, 1)], slots: [:], dir: .down,
                      nowMs: now, w: 300, h: 100).total
        }
        check(rate(2_000).count == 3 && rate(2_000)[1] == nil, "cg missed tick breaks")
        check(rate(1_400).count == 2, "cg jitter keeps line")

        check(ceilNice(0) == 10_000 && ceilNice(9_999) == 10_000 && ceilNice(10_000) == 10_000, "bf ceil floor")
        check(ceilNice(10_001) == 20_000 && ceilNice(20_001) == 50_000 && ceilNice(50_001) == 100_000, "bf ceil ladder")
        check(ceilNice(42_100_000) == 50_000_000 && ceilNice(1_500_000_000) == 2_000_000_000, "bf ceil big")
        check(formatBps(0) == "0" && formatBps(750) == "750 bps" && formatBps(1_000) == "1 Kbps", "bf fmt small")
        check(formatBps(12_500) == "12.5 Kbps" && formatBps(250_000) == "250 Kbps", "bf fmt K")
        check(formatBps(42_100_000) == "42.1 Mbps" && formatBps(1_500_000_000) == "1.5 Gbps", "bf fmt M/G")
    }

    do { // Derive port (DeriveTest.kt + SchedulerStatusTest.kt + view-state matrix)
        var v = statusView(.connected, elapsed: "00:12:41")
        check(v.title == "Connected" && v.sub == "Protected · 00:12:41" && v.tone == .ok && !v.pulsing, "dv connected")
        v = statusView(.connected, elapsed: nil)
        check(v.sub == "Protected · 00:00", "dv connected nil elapsed")
        v = statusView(.disconnected, elapsed: nil)
        check(v.title == "Not Connected" && v.sub == "Tap the button to connect and protect your traffic" && !v.pulsing, "dv disconnected")
        for s in [VpnViewState.connecting, .reconnecting] {
            v = statusView(s, elapsed: nil)
            check(v.title == "Connecting…" && v.sub == "Contacting server…" && v.pulsing && v.tone == .muted, "dv pulse \(s)")
        }
        v = statusView(.error("PSK authentication failed"), elapsed: nil)
        check(v.title == "Not Connected" && v.sub == "PSK authentication failed" && v.tone == .warn, "dv error")

        check(deriveViewState(neStatus: 2, clientState: nil, surfacedError: nil) == .connecting, "vs connecting")
        check(deriveViewState(neStatus: 4, clientState: nil, surfacedError: nil) == .reconnecting, "vs reasserting")
        check(deriveViewState(neStatus: 3, clientState: 5, surfacedError: nil) == .reconnecting, "vs connected+reconnecting")
        check(deriveViewState(neStatus: 3, clientState: 3, surfacedError: "x") == .connected, "vs connected")
        check(deriveViewState(neStatus: 3, clientState: nil, surfacedError: nil) == .connected, "vs connected nil")
        for n in [0, 1, 5, 9] {
            check(deriveViewState(neStatus: n, clientState: nil, surfacedError: nil) == .disconnected, "vs disc \(n)")
            check(deriveViewState(neStatus: n, clientState: nil, surfacedError: "boom") == .error("boom"), "vs err \(n)")
        }

        func p(_ i: String, _ st: Int = 1) -> DerivePath { DerivePath(iface: i, status: st) }
        let smp = BandwidthSample(wallMs: 0, dlBps: 0, ulBps: 0,
                                  perPathDl: ["en0": 40_000_000, "pdp_ip0": 10_000_000, "utun9": 99_000_000],
                                  perPathUl: ["en0": 5_000_000])
        let cards = pathCardViews(paths: [p("en0"), p("pdp_ip0", 3), p("utun9")], available: [.wifi, .cellular], sample: smp)
        check(cards.map { $0.kind } == [.wifi, .cellular] && cards.map { $0.name } == ["Wi-Fi", "Cellular"], "pc order/names")
        check(cards.map { $0.available } == [true, true] && cards.map { $0.active } == [true, false], "pc avail/active")
        check(cards[0].rateBps == 40_000_000 && cards[0].barFraction == 1 && cards[1].barFraction == 0.25, "pc rate/bar")
        check(cards[0].sub == "en0" && cards[1].sub == "May use mobile data", "pc subs")
        let un = pathCardViews(paths: [], available: [.wifi], sample: nil)
        check(un[1].sub == "Not connected" && !un[1].available, "pc unavailable sub")
        check(un.allSatisfy { $0.rateBps == 0 && $0.barFraction == 0 }, "pc no sample")
        check(pathCardViews(paths: [], available: [.wifi], sample: nil)[0].sub == "Ready", "pc ready")
        let uc = usingCounts(cards: cards)
        check(uc.n == 2 && uc.m == 1, "using counts \(uc)")

        check(fmtMbps(46_300_000) == "46.3" && fmtMbps(123_400_000) == "123", "dv fmtMbps")
        check(fmtElapsed(761) == "12:41" && fmtElapsed(3600) == "1:00:00" && fmtElapsed(45) == "00:45", "dv fmtElapsed")
        check(fmtBytes(999_000_000) == "999 MB" && fmtBytes(1_000_000_000) == "1.00 GB" && fmtBytes(2_345_000_000) == "2.35 GB", "dv fmtBytes")

        check(serverSchedulerLine(requested: nil, server: nil) == nil, "ss none")
        check(serverSchedulerLine(requested: 1, server: nil) == "Server scheduler: unknown (the server does not report it)", "ss unknown")
        check(serverSchedulerLine(requested: nil, server: 0) == "Server scheduler: minrtt", "ss minrtt")
        check(serverSchedulerLine(requested: nil, server: 3) == "Server scheduler: wlb_udp_pin", "ss pin")
        check(serverSchedulerLine(requested: 1, server: 1) == "Server scheduler: wlb", "ss equal")
        check(serverSchedulerLine(requested: 1, server: 2) == "Server scheduler: backup_fec (your setting wlb is not applied — the server's backup_fec cannot be switched)", "ss fec")
        check(serverSchedulerLine(requested: 1, server: 0) == "Server scheduler: minrtt (your setting wlb is not applied — check AllowClientScheduler on the server)", "ss allow")
        check(!schedulerApplied(requested: nil, server: 0) && schedulerApplied(requested: 1, server: 1) && !schedulerApplied(requested: 1, server: 0) && !schedulerApplied(requested: 1, server: nil), "ss applied")
    }

    return failures
}
