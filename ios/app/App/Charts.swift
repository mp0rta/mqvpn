// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

/// Canvas renderings of the ChartGeometry.swift models (port of android ui/Charts.kt).
/// The models arrive laid out for (card width - 2*12) x 120; nothing here computes layout.

private let chartHeight: CGFloat = 120

/// Card chrome (r12, pad 12, gap 6) + the legend; `canvas` draws below it.
private struct ChartCard<Plot: View>: View {
    @Environment(\.mq) private var mq
    let title: String
    let legend: [LegendEntry]
    let colorOf: (Int) -> Color
    let canvas: Plot
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.system(size: 15)).foregroundColor(mq.text)
            LegendRow(entries: legend, colorOf: colorOf)
            canvas.frame(height: chartHeight)
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
            ForEach(Array(entries.enumerated()), id: \.offset) { _, e in
                HStack(spacing: 0) {
                    RoundedRectangle(cornerRadius: 4).fill(colorOf(e.slot)).frame(width: 8, height: 8)
                    Text(" \(e.label) \(e.valueText)").font(.system(size: 11)).foregroundColor(mq.t2)
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

private func drawAxisLabel(_ ctx: GraphicsContext, _ text: String, _ mq: MqTheme) {
    ctx.draw(Text(text).font(.system(size: 10)).foregroundColor(mq.t2), at: CGPoint(x: 4, y: 0), anchor: .topLeading)
}

/// A nil point breaks the line (never interpolated).
private func drawPolyline(_ ctx: GraphicsContext, _ pts: [ChartPoint?], _ color: Color, _ width: CGFloat) {
    for i in pts.indices.dropFirst() {
        guard let a = pts[i - 1], let b = pts[i] else { continue }
        var p = Path(); p.move(to: CGPoint(x: a.x, y: a.y)); p.addLine(to: CGPoint(x: b.x, y: b.y))
        ctx.stroke(p, with: .color(color), lineWidth: width)
    }
}

struct RateChartCard: View {
    @Environment(\.mq) private var mq
    let title: String
    let model: LineChartModel
    private func color(_ slot: Int) -> Color { slot == TOTAL_SLOT ? mq.text : MqTheme.slotColor(slot) }
    var body: some View {
        ChartCard(title: title, legend: model.legend, colorOf: color, canvas:
            Canvas { ctx, size in
                drawGrid(ctx, size, model.gridYs, mq)
                for (slot, pts) in model.series.enumerated() { drawPolyline(ctx, pts, color(slot), 1.5) }
                if !model.total.isEmpty { drawPolyline(ctx, model.total, color(TOTAL_SLOT), 2.5) }
                drawAxisLabel(ctx, model.yMaxLabel, mq)
            })
    }
}

struct ReorderBarsCard: View {
    @Environment(\.mq) private var mq
    let model: BarChartModel
    var body: some View {
        ChartCard(title: "Reorder recovery", legend: model.legend,
                  colorOf: { $0 == 0 ? mq.green : mq.red }, canvas:
            Canvas { ctx, size in
                drawGrid(ctx, size, [0, size.height / 2, size.height], mq)
                let barW = size.width / 30 * 0.6
                for b in model.bars {
                    // Edge samples stay fully on the canvas.
                    let x = min(max(CGFloat(b.x), barW / 2), size.width - barW / 2)
                    ctx.fill(Path(CGRect(x: x - barW / 2, y: size.height - CGFloat(b.greenH), width: barW, height: CGFloat(b.greenH))), with: .color(mq.green))
                    ctx.fill(Path(CGRect(x: x - barW / 2, y: size.height - CGFloat(b.greenH) - CGFloat(b.redH), width: barW, height: CGFloat(b.redH))), with: .color(mq.red))
                }
                drawAxisLabel(ctx, model.yMaxLabel, mq)
            })
    }
}

struct WaitBarsCard: View {
    @Environment(\.mq) private var mq
    let model: PairedBarModel
    var body: some View {
        ChartCard(title: "Buffer wait", legend: model.legend,
                  colorOf: { $0 == 0 ? mq.accent : mq.orange }, canvas:
            Canvas { ctx, size in
                drawGrid(ctx, size, [0, size.height / 2, size.height], mq)
                // Same footprint as the stacked bars, split into a p50|p99 pair around x.
                let barW = size.width / 30 * 0.3
                for b in model.bars {
                    let x = min(max(CGFloat(b.x), barW), size.width - barW)
                    if let h = b.h0.map({ CGFloat($0) }) { ctx.fill(Path(CGRect(x: x - barW, y: size.height - h, width: barW, height: h)), with: .color(mq.accent)) }
                    if let h = b.h1.map({ CGFloat($0) }) { ctx.fill(Path(CGRect(x: x, y: size.height - h, width: barW, height: h)), with: .color(mq.orange)) }
                }
                drawAxisLabel(ctx, model.yMaxLabel, mq)
            })
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
