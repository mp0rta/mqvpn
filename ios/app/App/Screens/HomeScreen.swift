// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

/// Port of android HomeScreen.kt.
struct HomeScreen: View {
    @Environment(\.mq) private var mq
    @ObservedObject var controller: TunnelController
    @ObservedObject var availability: TransportAvailability
    let onManage: () -> Void
    let onOpenSettings: () -> Void

    private var vs: VpnViewState { viewState(controller) }
    private var available: Set<TransportKind> {
        var s = Set<TransportKind>()
        if availability.wifi { s.insert(.wifi) }
        if availability.cellular { s.insert(.cellular) }
        return s
    }
    private var cards: [PathCardView2] {
        let paths = (controller.snapshot?.paths ?? []).map { DerivePath(iface: $0.name, status: Int($0.status)) }
        return pathCardViews(paths: paths, available: available, sample: controller.bandwidthHistory.samples.last)
            .filter { $0.available && $0.active }
    }

    var body: some View {
        let vs = self.vs
        let status = statusView(vs, elapsed: elapsedText(controller, vs))
        let isOn = vs == .connected
        let isConnecting = vs == .connecting
        let canConnect = controller.isConnectable
        let tappable = !isConnecting && (isOn || vs == .reconnecting || canConnect)
        let btn = isOn ? mq.green : mq.accent
        ScrollView {
            VStack(spacing: 0) {
                ZStack {
                    Button {
                        if isOn || vs == .reconnecting { controller.stop() } else { controller.start() }
                    } label: {
                        Image(systemName: "power").font(.system(size: 52, weight: .regular)).foregroundColor(.white)
                            .frame(width: 148, height: 148).background(btn, in: Circle())
                            .shadow(color: btn.opacity(0.5), radius: 14)
                            .opacity(!isOn && !canConnect ? 0.5 : 1)
                    }
                    .buttonStyle(.plain).disabled(!tappable)
                    .accessibilityLabel(isOn ? "Disconnect" : "Connect")
                    if isConnecting { ProgressView().progressViewStyle(.circular).scaleEffect(2).tint(mq.accent) }
                }
                Text(status.title).font(.system(size: 22, weight: .bold)).foregroundColor(mq.text).padding(.top, 22)
                Text(status.sub).font(.system(size: 13)).multilineTextAlignment(.center)
                    .foregroundColor(mq.color(status.tone)).opacity(status.pulsing ? 0.7 : 1).padding(.top, 5)
                if case .loadFailed = controller.state { errorLine(controller.statusText) }
                if let e = controller.configError { errorLine(e) }
                if let e = controller.settingsModel.saveError { errorLine(e) }

                if vs == .connected { connectedBlock }
                if Self.notProtected(vs) {
                    MqCard {
                        HStack(alignment: .top, spacing: 12) {
                            Image(systemName: "shield.slash").font(.system(size: 18)).foregroundColor(mq.t2)
                            (Text("Your traffic is ").foregroundColor(mq.t2)
                                + Text("not encrypted").fontWeight(.semibold).foregroundColor(mq.text)
                                + Text(" right now. Connect to protect it and combine your connections.").foregroundColor(mq.t2))
                                .font(.system(size: 12.5)).lineSpacing(4)
                        }
                    }.padding(.top, 22)
                }

                Button(action: onOpenSettings) {
                    (Text("Server ").foregroundColor(mq.t2)
                        + Text(controller.draft.addressText).fontWeight(.medium).foregroundColor(mq.text)
                        + Text(" ").foregroundColor(mq.t2) + Text("Change").foregroundColor(mq.accent))
                        .font(.system(size: 12)).padding(8)
                }.buttonStyle(.plain).padding(.top, 12)
            }
            .padding(.horizontal, 20).padding(.top, 26).padding(.bottom, 16)
        }.background(mq.win.ignoresSafeArea())
    }

    private func errorLine(_ t: String) -> some View {
        Text(t).font(.system(size: 12)).foregroundColor(mq.red).multilineTextAlignment(.center).padding(.top, 6)
    }

    @ViewBuilder private var connectedBlock: some View {
        let last = controller.bandwidthHistory.samples.last
        let cards = self.cards
        let used = usingCounts(cards: cards)
        HStack(spacing: 10) {
            RateTile(label: "Download", mbps: fmtMbps(last?.dlBps ?? 0), arrowColor: mq.accent, arrow: "↓")
            RateTile(label: "Upload", mbps: fmtMbps(last?.ulBps ?? 0), arrowColor: mq.green)
        }.padding(.top, 22)
        MqCard {
            VStack(spacing: 10) {
                HStack {
                    Text("Using \(used.n) of \(cards.count) connections").font(.system(size: 12, weight: .semibold))
                        .foregroundColor(mq.text)
                    Spacer()
                    Button(action: onManage) { Text("Manage").font(.system(size: 12)).foregroundColor(mq.accent) }
                        .buttonStyle(.plain)
                }
                ForEach(cards, id: \.name) { p in
                    HStack(spacing: 8) {
                        Text(p.name).font(.system(size: 12)).foregroundColor(mq.text).frame(width: 62, alignment: .leading)
                        UsageBar(fraction: p.barFraction, color: p.kind == .cellular ? mq.green : mq.accent)
                        Text("\(fmtMbps(Double(p.rateBps))) Mbps").font(.system(size: 11)).foregroundColor(mq.t2)
                            .frame(width: 66, alignment: .trailing)
                    }
                }
            }
        }.padding(.top, 10)
        let info = controller.snapshot?.tunnel
        let applied = schedulerApplied(requested: info?.requestedScheduler, server: info?.serverScheduler)
        MqCard(vPad: 4) {
            VStack(spacing: 0) {
                KvRow(key: "VPN address", value: info?.assignedIp ?? "—")
                if let v6 = info?.assignedIp6 { KvRow(key: "IPv6 address", value: v6) }
                KvRow(key: "How traffic is split", value: Self.splitLabel(controller.draft.split.choice), tick: applied)
                KvRow(key: "Ping", value: controller.snapshot?.stats.map { "\(Int($0.srttMs.rounded())) ms" } ?? "—")
                KvRow(key: "MTU", value: info.map { fmtInt($0.mtu) } ?? "—", last: true)
            }
        }.padding(.top, 10)
        if !applied, info?.requestedScheduler != nil,
           let line = serverSchedulerLine(requested: info?.requestedScheduler, server: info?.serverScheduler) {
            Text(line).font(.system(size: 11)).foregroundColor(mq.t2).frame(maxWidth: .infinity, alignment: .leading)
                .padding(.top, 6)
        }
    }

    static func notProtected(_ vs: VpnViewState) -> Bool {
        switch vs { case .disconnected, .error: return true; default: return false }
    }

    static func splitLabel(_ c: SplitChoice) -> String {
        switch c { case .throughput: return "Throughput"; case .lowLatency: return "Low latency"; case .redundant: return "Redundant" }
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
        }.frame(height: 6)
    }
}
