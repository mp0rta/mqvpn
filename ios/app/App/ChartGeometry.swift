// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation

// Port of android ChartGeometry.kt + BandwidthFormat.kt. Pure layout: no drawing types.
// Plot models take the canvas size (built inside the Canvas closure); legends
// do not depend on it, so they are separate functions for the card header.

struct ChartPoint: Equatable { var x: Double; var y: Double }
struct LegendEntry: Equatable { var label: String; var slot: Int; var valueText: String }
struct LineChartModel: Equatable {
    var yMaxLabel: String
    var gridYs: [Double]            // top, mid, zero line
    var total: [ChartPoint?]        // nil = gap; empty when the chart has no total series
    var series: [[ChartPoint?]]     // per slot; nil = gap (break the polyline)
}
struct StackedBar: Equatable { var x: Double; var greenH: Double; var redH: Double }
struct BarChartModel: Equatable { var yMaxLabel: String; var bars: [StackedBar] }
struct PairedBar: Equatable { var x: Double; var h0: Double?; var h1: Double? }   // nil = no data that tick
struct PairedBarModel: Equatable { var yMaxLabel: String; var bars: [PairedBar] }
enum RateDir { case down, up }

let WINDOW_MS: Int64 = 30_000
let TOTAL_SLOT = -1
let TICK_MS: Int64 = 1_000
/// Sample slots across the window (bar width is a fraction of one slot).
let WINDOW_TICKS = Int(WINDOW_MS / TICK_MS)
/// Samples further apart than this (1.5 ticks) break the polyline.
let GAP_MS: Int64 = TICK_MS * 3 / 2
/// Residence above the last finite bucket bound; drawn at this height and labelled ">512 ms".
private let overflowMs = 512.0

/// Round up to 1/2/5 x 10^n, at least `floor` (default 10 Kbps, so an idle rate
/// chart keeps a stable axis).
func ceilNice(_ v: Double, floor: Double = 10_000) -> Double {
    var scale = floor
    while true {
        for m in [1.0, 2.0, 5.0] where v <= scale * m { return scale * m }
        scale *= 10
    }
}

/// SI (x1000) formatting: 0 -> "0", 750 -> "750 bps", 12_500 -> "12.5 Kbps".
func formatBps(_ v: Double) -> String {
    if v == 0 { return "0" }
    if v < 1_000 { return "\(Int64(v.rounded())) bps" }
    let (div, unit): (Double, String) = v < 1_000_000 ? (1_000, "Kbps")
        : v < 1_000_000_000 ? (1_000_000, "Mbps") : (1_000_000_000, "Gbps")
    var s = String(format: "%.1f", v / div)
    if s.hasSuffix(".0") { s.removeLast(2) }
    return "\(s) \(unit)"
}

/// One entry per sample, with a nil inserted wherever a tick is missing between two samples.
private func withGaps<S, T>(_ xs: [S], wallMs: (S) -> Int64, map: (S) -> T?) -> [T?] {
    var out: [T?] = []
    var prev: Int64?
    for s in xs {
        if let p = prev, wallMs(s) - p > GAP_MS { out.append(nil) }
        prev = wallMs(s)
        out.append(map(s))
    }
    return out
}

private func visible<S>(_ xs: [S], _ nowMs: Int64, wallMs: (S) -> Int64) -> [S] {
    xs.filter { wallMs($0) >= nowMs - WINDOW_MS }
}

private func xFor(_ wallMs: Int64, _ nowMs: Int64, _ w: Double) -> Double {
    Double(wallMs - (nowMs - WINDOW_MS)) / Double(WINDOW_MS) * w
}

private func total(_ s: BandwidthSample, _ dir: RateDir) -> Double { dir == .down ? s.dlBps : s.ulBps }
private func perPath(_ s: BandwidthSample, _ dir: RateDir) -> [String: Double] {
    dir == .down ? s.perPathDl : s.perPathUl
}

func rateChart(samples: [BandwidthSample], slots: [String: Int], dir: RateDir,
               nowMs: Int64, w: Double, h: Double) -> LineChartModel {
    let vis = visible(samples, nowMs) { $0.wallMs }
    func tot(_ s: BandwidthSample) -> Double { total(s, dir) }
    func per(_ s: BandwidthSample) -> [String: Double] { perPath(s, dir) }
    let top = ceilNice(vis.map { max(tot($0), per($0).values.max() ?? 0) }.max() ?? 0)
    func y(_ bps: Double) -> Double { h - bps / top * h }
    let slotCount = (slots.values.max() ?? -1) + 1
    let series: [[ChartPoint?]] = (0..<slotCount).map { slot in
        let iface = slots.first { $0.value == slot }?.key
        return withGaps(vis, wallMs: { $0.wallMs }) { s in
            iface.flatMap { per(s)[$0] }.map { ChartPoint(x: xFor(s.wallMs, nowMs, w), y: y($0)) }
        }
    }
    return LineChartModel(
        yMaxLabel: formatBps(top), gridYs: [0, h / 2, h],
        total: withGaps(vis, wallMs: { $0.wallMs }) { ChartPoint(x: xFor($0.wallMs, nowMs, w), y: y(tot($0))) },
        series: series)
}

/// "total" first, then one entry per path slot, valued at the newest visible sample.
func rateLegend(samples: [BandwidthSample], slots: [String: Int], dir: RateDir, nowMs: Int64) -> [LegendEntry] {
    let last = visible(samples, nowMs) { $0.wallMs }.last
    return [LegendEntry(label: "total", slot: TOTAL_SLOT, valueText: formatBps(last.map { total($0, dir) } ?? 0))]
        + slots.sorted { $0.value < $1.value }.map { iface, slot in
            LegendEntry(label: iface, slot: slot, valueText: formatBps(last.flatMap { perPath($0, dir)[iface] } ?? 0))
        }
}

private func fmtRate(_ v: Double?) -> String { v.map { String(format: "%.1f/s", $0) } ?? "-" }

func reorderBars(samples: [ReorderSample], nowMs: Int64, w: Double, h: Double) -> BarChartModel {
    let vis = visible(samples, nowMs) { $0.wallMs }
    let top = max(1.0, (vis.map { $0.recoveredPerSec + $0.lostPerSec }.max() ?? 0).rounded(.up))
    return BarChartModel(
        yMaxLabel: "\(Int64(top))/s",
        bars: vis.map { StackedBar(x: xFor($0.wallMs, nowMs, w), greenH: $0.recoveredPerSec / top * h,
                                   redH: $0.lostPerSec / top * h) })
}

func reorderLegend(samples: [ReorderSample], nowMs: Int64) -> [LegendEntry] {
    let last = visible(samples, nowMs) { $0.wallMs }.last
    return [LegendEntry(label: "recovered", slot: 0, valueText: fmtRate(last?.recoveredPerSec)),
            LegendEntry(label: "lost", slot: 1, valueText: fmtRate(last?.lostPerSec))]
}

private func capped(_ v: Double?) -> Double? { v.map { $0.isInfinite ? overflowMs : $0 } }

func waitBars(samples: [ReorderSample], nowMs: Int64, w: Double, h: Double) -> PairedBarModel {
    let vis = visible(samples, nowMs) { $0.wallMs }
    let maxMs = vis.map { max(capped($0.p50Ms) ?? 0, capped($0.p99Ms) ?? 0) }.max() ?? 0
    let top = ceilNice(maxMs, floor: 1)
    func bar(_ v: Double?) -> Double? { capped(v).map { $0 / top * h } }
    return PairedBarModel(
        yMaxLabel: "\(max(Int64(top), 1)) ms",
        bars: vis.map { PairedBar(x: xFor($0.wallMs, nowMs, w), h0: bar($0.p50Ms), h1: bar($0.p99Ms)) })
}

func waitLegend(samples: [ReorderSample], nowMs: Int64) -> [LegendEntry] {
    func txt(_ v: Double?) -> String {
        guard let v else { return "-" }
        return v.isInfinite ? ">512 ms" : String(format: "%.1f ms", v)
    }
    let last = visible(samples, nowMs) { $0.wallMs }.last
    return [LegendEntry(label: "p50", slot: 0, valueText: txt(last?.p50Ms)),
            LegendEntry(label: "p99", slot: 1, valueText: txt(last?.p99Ms))]
}
