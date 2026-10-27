// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

/// Canvas renderings of the ChartGeometry.swift models (port of android ui/Charts.kt).
/// Each plot model is built inside its Canvas from the canvas size, so no layout
/// is measured or duplicated here.

/// What a chart's draw closure needs besides the context and size.
private struct ChartInk {
    let mq: MqTheme
    let axisFont: Font
}

/// Card chrome (r12, pad 12, gap 6) + the legend; `draw` renders the plot below it.
private struct ChartCard: View {
    @Environment(\.mq) private var mq
    @ScaledMetric(relativeTo: .caption2) private var axisSize: CGFloat = 10
    let title: String
    let legend: [LegendEntry]
    let colorOf: (Int) -> Color
    let draw: (GraphicsContext, CGSize, ChartInk) -> Void
    private static let plotHeight: CGFloat = 120

    var body: some View {
        let ink = ChartInk(mq: mq, axisFont: .system(size: axisSize))
        VStack(alignment: .leading, spacing: 6) {
            Text(title).mqFont(15).foregroundColor(mq.text).accessibilityAddTraits(.isHeader)
            LegendRow(entries: legend, colorOf: colorOf)
            Canvas { ctx, size in draw(ctx, size, ink) }
                .frame(height: Self.plotHeight)
                .accessibilityHidden(true)   // the legend carries the current values
        }
        .padding(12).frame(maxWidth: .infinity, alignment: .leading)
        .background(mq.card, in: RoundedRectangle(cornerRadius: 12))
    }
}

private struct LegendRow: View {
    @Environment(\.mq) private var mq
    let entries: [LegendEntry]
    let colorOf: (Int) -> Color
    var body: some View {
        WrapLayout(spacing: 12) {
            ForEach(entries, id: \.slot) { e in
                HStack(spacing: 4) {
                    RoundedRectangle(cornerRadius: 4).fill(colorOf(e.slot)).frame(width: 8, height: 8)
                    Text("\(e.label) \(e.valueText)").mqFont(11).foregroundColor(mq.t2)
                }
            }
        }
    }
}

private func drawGrid(_ ctx: GraphicsContext, _ size: CGSize, _ ys: [Double], _ mq: MqTheme) {
    for (i, y) in ys.enumerated() {
        var p = Path(); p.move(to: CGPoint(x: 0, y: y)); p.addLine(to: CGPoint(x: size.width, y: y))
        let zero = i == ys.count - 1
        ctx.stroke(p, with: .color(mq.sep), style: StrokeStyle(lineWidth: 1, dash: zero ? [] : [6, 6]))
    }
}

private func drawAxisLabel(_ ctx: GraphicsContext, _ text: String, _ ink: ChartInk) {
    ctx.draw(Text(text).font(ink.axisFont).foregroundColor(ink.mq.t2), at: CGPoint(x: 4, y: 0), anchor: .topLeading)
}

/// A nil point breaks the line (never interpolated).
private func drawPolyline(_ ctx: GraphicsContext, _ pts: [ChartPoint?], _ color: Color, _ width: CGFloat) {
    var p = Path()
    var open = false
    for pt in pts {
        guard let pt else { open = false; continue }
        let c = CGPoint(x: pt.x, y: pt.y)
        if open { p.addLine(to: c) } else { p.move(to: c); open = true }
    }
    ctx.stroke(p, with: .color(color), lineWidth: width)
}

/// Width of one window tick on the canvas.
private func tickWidth(_ size: CGSize) -> CGFloat { size.width / CGFloat(WINDOW_TICKS) }

struct RateChartCard: View {
    @Environment(\.mq) private var mq
    let title: String
    let samples: [BandwidthSample]
    let slots: [String: Int]
    let dir: RateDir
    let nowMs: Int64

    private func color(_ slot: Int) -> Color { slot == TOTAL_SLOT ? mq.text : MqTheme.slotColor(slot) }

    var body: some View {
        ChartCard(title: title, legend: rateLegend(samples: samples, slots: slots, dir: dir, nowMs: nowMs),
                  colorOf: color) { ctx, size, ink in
            let model = rateChart(samples: samples, slots: slots, dir: dir, nowMs: nowMs,
                                  w: size.width, h: size.height)
            drawGrid(ctx, size, model.gridYs, ink.mq)
            for (slot, pts) in model.series.enumerated() { drawPolyline(ctx, pts, color(slot), 1.5) }
            if !model.total.isEmpty { drawPolyline(ctx, model.total, color(TOTAL_SLOT), 2.5) }
            drawAxisLabel(ctx, model.yMaxLabel, ink)
        }
    }
}

struct ReorderBarsCard: View {
    @Environment(\.mq) private var mq
    let samples: [ReorderSample]
    let nowMs: Int64
    var body: some View {
        ChartCard(title: "Reorder recovery", legend: reorderLegend(samples: samples, nowMs: nowMs),
                  colorOf: { $0 == 0 ? mq.green : mq.red }) { ctx, size, ink in
            let model = reorderBars(samples: samples, nowMs: nowMs, w: size.width, h: size.height)
            drawGrid(ctx, size, [0, size.height / 2, size.height], ink.mq)
            let barW = tickWidth(size) * 0.6
            for b in model.bars {
                // Edge samples stay fully on the canvas.
                let x = min(max(CGFloat(b.x), barW / 2), size.width - barW / 2)
                let green = CGFloat(b.greenH), red = CGFloat(b.redH)
                ctx.fill(Path(CGRect(x: x - barW / 2, y: size.height - green, width: barW, height: green)),
                         with: .color(ink.mq.green))
                ctx.fill(Path(CGRect(x: x - barW / 2, y: size.height - green - red, width: barW, height: red)),
                         with: .color(ink.mq.red))
            }
            drawAxisLabel(ctx, model.yMaxLabel, ink)
        }
    }
}

struct WaitBarsCard: View {
    @Environment(\.mq) private var mq
    let samples: [ReorderSample]
    let nowMs: Int64
    var body: some View {
        ChartCard(title: "Buffer wait", legend: waitLegend(samples: samples, nowMs: nowMs),
                  colorOf: { $0 == 0 ? mq.accent : mq.orange }) { ctx, size, ink in
            let model = waitBars(samples: samples, nowMs: nowMs, w: size.width, h: size.height)
            drawGrid(ctx, size, [0, size.height / 2, size.height], ink.mq)
            // Same footprint as the stacked bars, split into a p50|p99 pair around x.
            let barW = tickWidth(size) * 0.3
            for b in model.bars {
                let x = min(max(CGFloat(b.x), barW), size.width - barW)
                if let h = b.h0.map({ CGFloat($0) }) {
                    ctx.fill(Path(CGRect(x: x - barW, y: size.height - h, width: barW, height: h)), with: .color(ink.mq.accent))
                }
                if let h = b.h1.map({ CGFloat($0) }) {
                    ctx.fill(Path(CGRect(x: x, y: size.height - h, width: barW, height: h)), with: .color(ink.mq.orange))
                }
            }
            drawAxisLabel(ctx, model.yMaxLabel, ink)
        }
    }
}

/// Flow layout: children left to right, wrapping to a new row when the width runs out.
private struct WrapLayout: Layout {
    var spacing: CGFloat
    private func rows(_ subs: Subviews, _ maxW: CGFloat) -> (frames: [CGRect], size: CGSize) {
        var frames: [CGRect] = []
        var x: CGFloat = 0, y: CGFloat = 0, rowH: CGFloat = 0, usedW: CGFloat = 0
        for s in subs {
            let sz = s.sizeThatFits(.unspecified)
            if x > 0 && x + sz.width > maxW { x = 0; y += rowH + 4; rowH = 0 }
            frames.append(CGRect(origin: CGPoint(x: x, y: y), size: sz))
            x += sz.width + spacing; rowH = max(rowH, sz.height); usedW = max(usedW, x - spacing)
        }
        return (frames, CGSize(width: usedW, height: y + rowH))
    }
    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        rows(subviews, proposal.width ?? .infinity).size
    }
    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let r = rows(subviews, bounds.width)
        for (s, f) in zip(subviews, r.frames) {
            s.place(at: CGPoint(x: bounds.minX + f.minX, y: bounds.minY + f.minY), proposal: .unspecified)
        }
    }
}
