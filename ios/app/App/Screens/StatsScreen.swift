// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

private struct WidthKey: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = nextValue() }
}

/// Measures the card width so chart models are built for the exact canvas (card width - 24) x 120.
private struct Measured<Content: View>: View {
    @State private var w: CGFloat = 0
    let content: (Double) -> Content
    var body: some View {
        content(Double(max(w - 24, 0)))
            .background(GeometryReader { Color.clear.preference(key: WidthKey.self, value: $0.size.width) })
            .onPreferenceChange(WidthKey.self) { w = $0 }
    }
}

/// Port of android StatsScreen.kt.
struct StatsScreen: View {
    @Environment(\.mq) private var mq
    @ObservedObject var controller: TunnelController
    let onGoHome: () -> Void

    var body: some View {
        let vs = viewState(controller)
        let live = vs == .connected || vs == .reconnecting
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("Statistics").font(.system(size: 20, weight: .bold)).foregroundColor(mq.text)
                if live { liveBlock(vs) } else { empty }
            }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
        }.background(mq.win.ignoresSafeArea())
    }

    private var empty: some View {
        VStack(spacing: 10) {
            Image(systemName: "chart.bar.fill").font(.system(size: 22)).foregroundColor(mq.t2).padding(4)
            Text("Connect to see live statistics").font(.system(size: 13)).foregroundColor(mq.t2)
            Button(action: onGoHome) {
                Text("Go to Home").font(.system(size: 13, weight: .medium)).foregroundColor(mq.accent).padding(8)
            }.buttonStyle(.plain)
        }.frame(maxWidth: .infinity).padding(.top, 80)
    }

    @ViewBuilder private func liveBlock(_ vs: VpnViewState) -> some View {
        let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
        let bw = controller.bandwidthHistory
        let ro = controller.reorderHistory
        let stats = controller.snapshot?.stats
        if vs == .reconnecting {
            Text("Reconnecting…").font(.system(size: 13, weight: .medium)).foregroundColor(mq.orange)
        }
        Measured { w in
            RateChartCard(title: "Download", model: rateChart(samples: bw.samples, slots: bw.slots, dir: .down, nowMs: nowMs, w: w, h: 120))
        }
        Measured { w in
            RateChartCard(title: "Upload", model: rateChart(samples: bw.samples, slots: bw.slots, dir: .up, nowMs: nowMs, w: w, h: 120))
        }
        MqCard(vPad: 4) {
            VStack(spacing: 0) {
                KvRow(key: "Session time", value: elapsedText(controller, vs) ?? "—")
                KvRow(key: "Data received", value: stats.map { fmtBytes($0.bytesRx) } ?? "—")
                KvRow(key: "Data sent", value: stats.map { fmtBytes($0.bytesTx) } ?? "—")
                KvRow(key: "Latency", value: stats.map { "\(Int($0.srttMs.rounded())) ms" } ?? "—")
                KvRow(key: "Packet loss", value: controller.dgramLoss.map { String(format: "%.1f%%", $0 * 100) } ?? "—", last: true)
            }
        }
        if controller.draft.reorder.enabled {
            Measured { w in ReorderBarsCard(model: reorderBars(samples: ro.samples, nowMs: nowMs, w: w, h: 120)) }
            Measured { w in WaitBarsCard(model: waitBars(samples: ro.samples, nowMs: nowMs, w: w, h: 120)) }
            let r = controller.snapshot?.reorder   // cumulative counters: latest snapshot, not history
            MqCard(vPad: 4) {
                VStack(spacing: 0) {
                    KvRow(key: "Packets delivered", value: fmtInt(r?.delivered ?? 0))
                    KvRow(key: "Out-of-order gaps", value: fmtInt(r?.gapCount ?? 0))
                    KvRow(key: "Recovered in buffer", value: fmtInt(r?.gapFilled ?? 0))
                    KvRow(key: "Lost to timeout", value: fmtInt(r?.gapTimeout ?? 0), last: true)
                }
            }
        }
    }
}
