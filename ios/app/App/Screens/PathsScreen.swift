// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

/// Last-connection guard copy (android LAST_PATH_CAPTION).
let lastPathCaption = "Keep at least one connection on."

/// Port of android PathsScreen.kt (two fixed rows: Wi-Fi, Cellular).
struct PathsScreen: View {
    @Environment(\.mq) private var mq
    @ObservedObject var controller: TunnelController
    @ObservedObject var availability: TransportAvailability
    @State private var blocked = false

    var body: some View {
        let live = viewState(controller) == .connected
        let paths = (controller.snapshot?.paths ?? []).map { DerivePath(iface: $0.name, status: Int($0.status)) }
        var avail = Set<TransportKind>()
        if availability.wifi { avail.insert(.wifi) }
        if availability.cellular { avail.insert(.cellular) }
        let cards = pathCardViews(paths: paths, available: avail, sample: controller.bandwidthHistory.samples.last)
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("Paths").font(.system(size: 20, weight: .bold)).foregroundColor(mq.text)
                Text("Use carries your traffic. If one connection fails, the others take over. Off leaves it out.")
                    .font(.system(size: 12.5)).lineSpacing(5).foregroundColor(mq.t2)
                ForEach(cards, id: \.name) { card in
                    let on = card.kind == .wifi ? controller.draft.paths.wifi : controller.draft.paths.cellular
                    let (label, dot): (String, Color) = !card.available ? ("Unavailable", mq.sep)
                        : !on ? ("Off", mq.t2) : card.active ? ("Active", mq.green) : ("Ready", mq.t2)
                    MqCard {
                        VStack(spacing: 10) {
                            HStack(spacing: 10) {
                                Image(systemName: card.kind == .wifi ? "wifi" : "antenna.radiowaves.left.and.right")
                                    .font(.system(size: 18)).frame(width: 22)
                                    .foregroundColor(on && card.available ? mq.accent : mq.t2)
                                VStack(alignment: .leading, spacing: 0) {
                                    Text(card.name).font(.system(size: 14, weight: .semibold)).foregroundColor(mq.text)
                                    Text(card.sub).font(.system(size: 11)).foregroundColor(mq.t2)
                                }
                                Spacer(minLength: 0)
                                HStack(spacing: 6) {
                                    StatusDot(color: dot)
                                    Text(label).font(.system(size: 12)).foregroundColor(mq.t2)
                                }
                            }
                            if live && card.available && on {
                                HStack(spacing: 8) {
                                    UsageBar(fraction: card.barFraction, color: mq.accent)
                                    Text("\(fmtMbps(Double(card.rateBps))) Mbps").font(.system(size: 11)).foregroundColor(mq.t2)
                                        .frame(width: 78, alignment: .trailing)
                                }
                            }
                            if card.available {
                                UseOffSegmented(isOn: on, enabled: controller.isEditable) { want in set(card.kind, want) }
                            }
                        }
                    }.opacity(card.available ? 1 : 0.55)
                }
                if blocked { Text(lastPathCaption).font(.system(size: 12)).foregroundColor(mq.red) }
            }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
        }.background(mq.win.ignoresSafeArea())
    }

    /// Turning the last connection Off would leave no path (never persistable): refuse.
    private func set(_ kind: TransportKind, _ want: Bool) {
        var p = controller.draft.paths
        if kind == .wifi { p.wifi = want } else { p.cellular = want }
        guard want || p.anyEnabled else { blocked = true; return }
        blocked = false
        controller.settingsModel.update { $0.paths = p }
    }
}
