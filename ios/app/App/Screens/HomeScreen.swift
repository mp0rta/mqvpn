// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

/// Everything Home shows; built by HomeTab from the controller and live data.
struct HomeModel {
    var viewState: VpnViewState
    var elapsed: String?
    var canConnect: Bool
    var errors: [String]              // manager load / stored config / autosave
    var serverAddress: String
    var cards: [PathCard]             // the transports in use (available, carrying an active path)
    var dlBps: Double
    var ulBps: Double
    var tunnel: TunnelInfoSnapshot?
    var srttMs: Double?
    var split: SplitChoice
}

struct HomeActions {
    var connect: () -> Void = {}
    var disconnect: () -> Void = {}
    var manage: () -> Void = {}
    var openSettings: () -> Void = {}
}

/// Port of android HomeScreen.kt.
struct HomeScreen: View {
    @Environment(\.mq) private var mq
    let model: HomeModel
    let actions: HomeActions

    var body: some View {
        let vs = model.viewState
        let status = statusLine(vs, elapsed: model.elapsed)
        let isOn = vs == .connected
        let canStop = isOn || vs == .reconnecting
        let tappable = vs != .connecting && (canStop || model.canConnect)
        let btn = isOn ? mq.green : mq.accent
        ScrollView {
            VStack(spacing: 0) {
                ZStack {
                    Button {
                        if canStop { actions.disconnect() } else { actions.connect() }
                    } label: {
                        // Fixed size by design: the button is the screen's anchor, not text.
                        Image(systemName: "power").font(.system(size: 52, weight: .regular)).foregroundColor(.white)
                            .frame(width: 148, height: 148).background(btn, in: Circle())
                            .shadow(color: btn.opacity(0.5), radius: 14)
                            .opacity(!isOn && !model.canConnect ? 0.5 : 1)
                    }
                    .buttonStyle(.plain).disabled(!tappable)
                    .accessibilityLabel(canStop ? "Disconnect" : "Connect")
                    if vs == .connecting { ProgressView().progressViewStyle(.circular).scaleEffect(2).tint(mq.accent) }
                }
                Text(status.title).mqFont(22, .bold).foregroundColor(mq.text).padding(.top, 22)
                Text(status.sub).mqFont(13).multilineTextAlignment(.center)
                    .foregroundColor(mq.color(status.tone)).opacity(status.pulsing ? 0.7 : 1).padding(.top, 5)
                ForEach(model.errors, id: \.self) { e in
                    Text(e).mqFont(12).foregroundColor(mq.red).multilineTextAlignment(.center).padding(.top, 6)
                }

                if isOn { connectedBlock }
                if Self.notProtected(vs) {
                    MqCard {
                        HStack(alignment: .top, spacing: 12) {
                            Image(systemName: "shield.slash").mqFont(18).foregroundColor(mq.t2)
                            (Text("Your traffic is ").foregroundColor(mq.t2)
                                + Text("not encrypted").fontWeight(.semibold).foregroundColor(mq.text)
                                + Text(" right now. Connect to protect it and combine your connections.").foregroundColor(mq.t2))
                                .mqFont(12.5).lineSpacing(4)
                        }
                    }.padding(.top, 22)
                }

                Button(action: actions.openSettings) {
                    (Text("Server ").foregroundColor(mq.t2)
                        + Text(model.serverAddress).fontWeight(.medium).foregroundColor(mq.text)
                        + Text(" ").foregroundColor(mq.t2) + Text("Change").foregroundColor(mq.accent))
                        .mqFont(12).padding(8)
                }.buttonStyle(.plain).padding(.top, 12)
            }
            .frame(maxWidth: .infinity)
            .padding(.horizontal, 20).padding(.top, 26).padding(.bottom, 16)
        }.background(mq.win.ignoresSafeArea())
    }

    @ViewBuilder private var connectedBlock: some View {
        let used = usingCounts(cards: model.cards)
        let applied = schedulerApplied(requested: model.tunnel?.requestedScheduler, server: model.tunnel?.serverScheduler)
        HStack(spacing: 10) {
            RateTile(label: "Download", mbps: fmtMbps(model.dlBps), arrowColor: mq.accent, arrow: "↓")
            RateTile(label: "Upload", mbps: fmtMbps(model.ulBps), arrowColor: mq.green)
        }.padding(.top, 22)
        MqCard {
            VStack(spacing: 10) {
                HStack {
                    Text("Using \(used.n) of \(model.cards.count) connections").mqFont(12, .semibold)
                        .foregroundColor(mq.text)
                    Spacer()
                    Button(action: actions.manage) { Text("Manage").mqFont(12).foregroundColor(mq.accent) }
                        .buttonStyle(.plain)
                }
                // Grid sizes the name and rate columns to their text, so larger type never truncates.
                Grid(horizontalSpacing: 8, verticalSpacing: 10) {
                    ForEach(model.cards, id: \.kind) { p in
                        GridRow {
                            Text(p.name).mqFont(12).foregroundColor(mq.text).gridColumnAlignment(.leading)
                            UsageBar(fraction: p.barFraction, color: p.kind == .cellular ? mq.green : mq.accent)
                            Text(fmtDownloadRate(p.rateBps)).mqFont(11).foregroundColor(mq.t2)
                                .gridColumnAlignment(.trailing)
                                .accessibilityLabel("Download \(fmtMbps(Double(p.rateBps))) megabits per second")
                        }
                    }
                }
            }
        }.padding(.top, 10)
        MqCard(vPad: 4) {
            VStack(spacing: 0) {
                KvRow(key: "VPN address", value: model.tunnel?.assignedIp ?? "—")
                if let v6 = model.tunnel?.assignedIp6 { KvRow(key: "IPv6 address", value: v6) }
                KvRow(key: "How traffic is split", value: model.split.title, tick: applied)
                KvRow(key: "Ping", value: model.srttMs.map { "\(Int($0.rounded())) ms" } ?? "—")
                KvRow(key: "MTU", value: model.tunnel.map { fmtInt($0.mtu) } ?? "—", last: true)
            }
        }.padding(.top, 10)
        if !applied, model.tunnel?.requestedScheduler != nil,
           let line = serverSchedulerLine(requested: model.tunnel?.requestedScheduler, server: model.tunnel?.serverScheduler) {
            Text(line).mqFont(11).foregroundColor(mq.t2).frame(maxWidth: .infinity, alignment: .leading)
                .padding(.top, 6)
        }
    }

    static func notProtected(_ vs: VpnViewState) -> Bool {
        switch vs { case .disconnected, .error: return true; default: return false }
    }
}

extension SplitChoice {
    var title: String {
        switch self {
        case .throughput: return "Throughput"
        case .lowLatency: return "Low latency"
        case .redundant: return "Redundant"
        case .backup: return "Backup"
        }
    }
}

/// 6pt rounded bar on a fill track (Home + Paths rows).
struct UsageBar: View {
    @Environment(\.mq) private var mq
    let fraction: Double
    let color: Color
    var body: some View {
        GeometryReader { g in
            ZStack(alignment: .leading) {
                Capsule().fill(mq.fill)
                Capsule().fill(color).frame(width: g.size.width * CGFloat(min(max(fraction, 0), 1)))
            }
        }
        .frame(height: 6)
        .accessibilityHidden(true)
    }
}
