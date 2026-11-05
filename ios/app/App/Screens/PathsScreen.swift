// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

/// Last-connection guard copy (android LAST_PATH_CAPTION).
let lastPathCaption = "Keep at least one connection on."

extension TransportKind {
    /// SF Symbol for the transport's row icon.
    var symbol: String {
        switch self {
        case .wifi: return "wifi"
        case .cellular: return "antenna.radiowaves.left.and.right"
        }
    }
}

/// Port of android PathsScreen.kt (one row per transport).
struct PathsScreen: View {
    @Environment(\.mq) private var mq
    let live: Bool                     // connected: show the per-path rate rows
    let cards: [PathCard]
    let policy: PathPolicy
    let editable: Bool
    let setPolicy: (PathPolicy) -> Void
    @State private var blocked = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("Paths").mqFont(20, .bold).foregroundColor(mq.text).accessibilityAddTraits(.isHeader)
                Text("Use carries your traffic. If one connection fails, the others take over. Off leaves it out.")
                    .mqFont(12.5).lineSpacing(5).foregroundColor(mq.t2)
                ForEach(cards, id: \.kind) { row($0) }
                if blocked { Text(lastPathCaption).mqFont(12).foregroundColor(mq.red) }
            }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
        }.background(mq.win.ignoresSafeArea())
    }

    private func row(_ card: PathCard) -> some View {
        let on = policy[card.kind]
        let (label, dot): (String, Color) = !card.available ? ("Unavailable", mq.sep)
            : !on ? ("Off", mq.t2) : card.active ? ("Active", mq.green) : ("Ready", mq.t2)
        return MqCard {
            VStack(spacing: 10) {
                HStack(spacing: 10) {
                    Image(systemName: card.kind.symbol).mqFont(18).frame(minWidth: 22)
                        .foregroundColor(on && card.available ? mq.accent : mq.t2)
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 0) {
                        Text(card.name).mqFont(14, .semibold).foregroundColor(mq.text)
                        Text(card.sub).mqFont(11).foregroundColor(mq.t2)
                    }
                    Spacer(minLength: 0)
                    HStack(spacing: 6) {
                        StatusDot(color: dot)
                        Text(label).mqFont(12).foregroundColor(mq.t2)
                    }
                }
                if live && card.available && on {
                    HStack(spacing: 8) {
                        UsageBar(fraction: card.barFraction, color: mq.accent)
                        Text(fmtDownloadRate(card.rateBps)).mqFont(11).foregroundColor(mq.t2)
                            .fixedSize()
                            .accessibilityLabel("Download \(fmtMbps(Double(card.rateBps))) megabits per second")
                    }
                }
                if card.available {
                    UseOffSegmented(isOn: on, enabled: editable) { set(card.kind, $0) }
                        .accessibilityLabel("\(card.name)")
                }
            }
        }.opacity(card.available ? 1 : 0.55)
    }

    private func set(_ kind: TransportKind, _ want: Bool) {
        guard let p = policy.setting(kind, on: want) else { blocked = true; return }
        blocked = false
        setPolicy(p)
    }
}
