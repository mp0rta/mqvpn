// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

/// Port of android StatsScreen.kt.
struct StatsScreen: View {
    @Environment(\.mq) private var mq
    let viewState: VpnViewState
    let elapsed: String?
    let frame: LiveFrame
    /// Wall clock the 30 s chart window ends at.
    let nowMs: Int64
    let onGoHome: () -> Void

    var body: some View {
        let live = viewState == .connected || viewState == .reconnecting
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("Statistics").mqFont(20, .bold).foregroundColor(mq.text).accessibilityAddTraits(.isHeader)
                if live { liveBlock } else { empty }
            }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
        }.background(mq.win.ignoresSafeArea())
    }

    private var empty: some View {
        VStack(spacing: 10) {
            Image(systemName: "chart.bar.fill").mqFont(22).foregroundColor(mq.t2).padding(4)
                .accessibilityHidden(true)
            Text("Connect to see live statistics").mqFont(13).foregroundColor(mq.t2)
            Button(action: onGoHome) {
                Text("Go to Home").mqFont(13, .medium).foregroundColor(mq.accent).padding(8)
            }.buttonStyle(.plain)
        }.frame(maxWidth: .infinity).padding(.top, 80)
    }

    @ViewBuilder private var liveBlock: some View {
        let stats = frame.snapshot?.stats
        if viewState == .reconnecting {
            Text("Reconnecting…").mqFont(13, .medium).foregroundColor(mq.orange)
        }
        RateChartCard(title: "Download", samples: frame.bandwidth, slots: frame.slots, dir: .down, nowMs: nowMs)
        RateChartCard(title: "Upload", samples: frame.bandwidth, slots: frame.slots, dir: .up, nowMs: nowMs)
        MqCard(vPad: 4) {
            VStack(spacing: 0) {
                KvRow(key: "Session time", value: elapsed ?? "—")
                KvRow(key: "Data received", value: stats.map { fmtBytes($0.bytesRx) } ?? "—")
                KvRow(key: "Data sent", value: stats.map { fmtBytes($0.bytesTx) } ?? "—")
                KvRow(key: "Latency", value: stats.map { "\(Int($0.srttMs.rounded())) ms" } ?? "—")
                KvRow(key: "Packet loss", value: frame.dgramLoss.map { String(format: "%.1f%%", $0 * 100) } ?? "—", last: true)
            }
        }
        if frame.snapshot?.reorderConfigured == true {   // provider truth, as the history ingest uses
            ReorderBarsCard(samples: frame.reorder, nowMs: nowMs)
            WaitBarsCard(samples: frame.reorder, nowMs: nowMs)
            let r = frame.snapshot?.reorder   // cumulative counters: latest snapshot, not history
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
