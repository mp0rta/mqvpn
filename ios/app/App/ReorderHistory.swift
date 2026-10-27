// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation

/// Mirrors reorder_lat_bound_us[] in src/reorder_rx.c — keep in sync by hand.
let REORDER_LAT_BOUND_US: [UInt64] = [
    0, 1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 64_000,
    128_000, 256_000, 512_000, UInt64.max,
]

struct ReorderSample: Equatable {
    var wallMs: Int64
    var recoveredPerSec: Double   // delta gapFilled / dt
    var lostPerSec: Double        // delta gapTimeout / dt
    var p50Ms: Double?            // this tick's bucket-delta percentile; nil = no buffered pkts
    var p99Ms: Double?            // .infinity = overflow bucket (render ">512 ms")
}

/// Port of android ReorderHistory.kt: cumulative counters -> rolling per-second samples.
final class ReorderHistory {
    private struct Snap {
        var delivered, gapCount, gapFilled, gapTimeout, ackDemote: UInt64
        var buckets: [UInt64]
    }

    private let windowMs: Int64
    private var prev: Snap?
    private var prevMs: Int64 = 0
    private(set) var samples: [ReorderSample] = []

    init(windowMs: Int64 = 30_000) { self.windowMs = windowMs }

    func onTick(delivered: UInt64, gapCount: UInt64, gapFilled: UInt64, gapTimeout: UInt64,
                ackDemote: UInt64, buckets: [UInt64], wallMs: Int64) {
        let cur = Snap(delivered: delivered, gapCount: gapCount, gapFilled: gapFilled,
                       gapTimeout: gapTimeout, ackDemote: ackDemote, buckets: buckets)
        guard let p = prev else { prev = cur; prevMs = wallMs; return }
        if wallMs <= prevMs { return }
        if Self.resetFrom(cur, p) { // new native session: baseline only, no sample
            prev = cur; prevMs = wallMs; return
        }
        let sec = Double(wallMs - prevMs) / 1000.0
        samples.append(ReorderSample(
            wallMs: wallMs,
            recoveredPerSec: Double(gapFilled - p.gapFilled) / sec,
            lostPerSec: Double(gapTimeout - p.gapTimeout) / sec,
            p50Ms: Self.percentileMs(p.buckets, buckets, 0.50),
            p99Ms: Self.percentileMs(p.buckets, buckets, 0.99)))
        prev = cur
        prevMs = wallMs
        while let f = samples.first, f.wallMs < wallMs - windowMs { samples.removeFirst() }
    }

    func clear() {
        prev = nil
        prevMs = 0
        samples = []
    }

    /// A decrease in ANY counter or bucket means the native stats were recreated.
    private static func resetFrom(_ s: Snap, _ p: Snap) -> Bool {
        if s.delivered < p.delivered || s.gapCount < p.gapCount || s.gapFilled < p.gapFilled
            || s.gapTimeout < p.gapTimeout || s.ackDemote < p.ackDemote { return true }
        return s.buckets.count == p.buckets.count && zip(s.buckets, p.buckets).contains { $0 < $1 }
    }

    /// Percentile of bucket deltas 1..11 (bucket 0 = in-order pass-through is excluded).
    private static func percentileMs(_ old: [UInt64], _ new: [UInt64], _ q: Double) -> Double? {
        let n = REORDER_LAT_BOUND_US.count
        if old.count != n || new.count != n { return nil } // stale lib / no bucket data
        let d = (0..<n).map { Double(new[$0]) - Double(old[$0]) }
        let total = d[1...].reduce(0, +)
        if total <= 0 { return nil }
        let rank = q * total
        var cum = 0.0
        for i in 1..<n {
            if d[i] > 0 && cum + d[i] >= rank {
                if i == n - 1 { return .infinity }
                let lo = Double(REORDER_LAT_BOUND_US[i - 1])
                let hi = Double(REORDER_LAT_BOUND_US[i])
                return (lo + (hi - lo) * (rank - cum) / d[i]) / 1000.0
            }
            cum += d[i]
        }
        return nil // unreachable: total > 0
    }
}

/// Upload DATAGRAM loss over a rolling window from cumulative sent/lost counters.
final class DgramLossWindow {
    private struct Point { var ms: Int64; var sent: UInt64; var lost: UInt64 }

    private let windowMs: Int64
    private var points: [Point] = []

    init(windowMs: Int64 = 30_000) { self.windowMs = windowMs }

    /// Loss over the window: delta lost / delta sent; nil when delta sent == 0.
    func onTick(sent: UInt64, lost: UInt64, wallMs: Int64) -> Double? {
        if let l = points.last, sent < l.sent || lost < l.lost { points.removeAll() }
        points.append(Point(ms: wallMs, sent: sent, lost: lost))
        // keep the newest point at/before the cutoff as the baseline
        while points.count > 1 && points[1].ms <= wallMs - windowMs { points.removeFirst() }
        let ds = sent - points[0].sent
        return ds > 0 ? Double(lost - points[0].lost) / Double(ds) : nil
    }

    func clear() { points = [] }
}
