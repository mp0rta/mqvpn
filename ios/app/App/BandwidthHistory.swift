// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation

/// One 1 s chart sample: per-direction total and per-iface throughput in bits per second.
struct BandwidthSample: Equatable {
    var wallMs: Int64
    var dlBps: Double
    var ulBps: Double
    var perPathDl: [String: Double]
    var perPathUl: [String: Double]
}

/// Port of android BandwidthHistory.kt. Rates use the monotonic clock; the
/// window uses wall time. Single writer (the UI ticker).
final class BandwidthHistory {
    private let windowMs: Int64
    private var lastMono: UInt64?
    private var rxBase: [String: UInt64] = [:]
    private var txBase: [String: UInt64] = [:]
    private(set) var samples: [BandwidthSample] = []
    private(set) var slots: [String: Int] = [:]

    init(windowMs: Int64 = 30_000) { self.windowMs = windowMs }

    func onTick(paths: [(name: String, tx: UInt64, rx: UInt64)], monoMs: UInt64, wallMs: Int64) {
        let prev = lastMono
        if let prev, monoMs <= prev { return }

        var rx: [String: UInt64] = [:], tx: [String: UInt64] = [:]
        var order: [String] = []
        for p in paths {
            if rx[p.name] == nil { order.append(p.name) }
            rx[p.name, default: 0] &+= p.rx
            tx[p.name, default: 0] &+= p.tx
        }
        for n in order where slots[n] == nil { slots[n] = slots.count }
        let dl = Self.rates(rx, &rxBase, prev, monoMs)
        let ul = Self.rates(tx, &txBase, prev, monoMs)
        lastMono = monoMs

        samples.append(BandwidthSample(wallMs: wallMs, dlBps: dl.values.reduce(0, +),
                                       ulBps: ul.values.reduce(0, +), perPathDl: dl, perPathUl: ul))
        while let f = samples.first, f.wallMs < wallMs - windowMs { samples.removeFirst() }
    }

    private static func rates(_ bytes: [String: UInt64], _ base: inout [String: UInt64],
                              _ prevMono: UInt64?, _ nowMono: UInt64) -> [String: Double] {
        var out: [String: Double] = [:]
        for (iface, b) in bytes {
            if let prevMono, let pb = base[iface], b >= pb {
                out[iface] = Double(b - pb) * 8.0 * 1000.0 / Double(nowMono - prevMono)
            } else {
                out[iface] = 0 // first tick, reappeared path, or counter reset: (re-)baseline only
            }
            base[iface] = b
        }
        base = base.filter { bytes[$0.key] != nil }
        return out
    }

    func clear() {
        lastMono = nil
        rxBase = [:]
        txBase = [:]
        slots = [:]
        samples = []
    }
}
