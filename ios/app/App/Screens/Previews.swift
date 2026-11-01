// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#if DEBUG
import SwiftUI

/// Canned data for the Xcode previews: screens take values, so none of these
/// needs a NETunnelProviderManager or a running tunnel.
private enum PreviewData {
    static let nowMs: Int64 = 1_800_000_000_000

    static let draft: AppDraft = {
        var d = AppDraft()
        d.addressText = "vpn.example.com:443"
        d.authKey = "preview-key"
        return d
    }()

    static let tunnel = TunnelInfoSnapshot(assignedIp: "10.0.0.2", assignedIp6: "fd00::2", mtu: 1280,
                                           serverScheduler: Scheduler.wlb.rawValue,
                                           requestedScheduler: Scheduler.wlb.rawValue)

    static let cards = [
        PathCard(kind: .wifi, sub: "en0", available: true, active: true, rateBps: 42_000_000, barFraction: 1),
        PathCard(kind: .cellular, sub: "May use mobile data", available: true, active: true,
                 rateBps: 12_000_000, barFraction: 0.29),
    ]

    /// Wall time of the i-th of 30 one-second samples ending at `nowMs`.
    private static func wall(_ i: Int) -> Int64 { nowMs - Int64(29 - i) * 1_000 }

    private static func bandwidthSample(_ i: Int) -> BandwidthSample {
        let wifi: Double = 30_000_000 + Double(i % 7) * 2_000_000
        let cell: Double = 10_000_000 + Double(i % 5) * 1_000_000
        let total: Double = wifi + cell
        return BandwidthSample(wallMs: wall(i), dlBps: total, ulBps: total / 8,
                               perPathDl: ["en0": wifi, "pdp_ip0": cell],
                               perPathUl: ["en0": wifi / 8, "pdp_ip0": cell / 8])
    }

    private static func reorderSample(_ i: Int) -> ReorderSample {
        let lost: Double = i % 9 == 0 ? 1 : 0
        return ReorderSample(wallMs: wall(i), recoveredPerSec: Double(i % 4), lostPerSec: lost,
                             p50Ms: 3, p99Ms: 18)
    }

    static let frame: LiveFrame = {
        let now: Double = Double(nowMs) / 1000
        let stats = StatsSnapshot(bytesTx: 120_000_000, bytesRx: 1_400_000_000,
                                  dgramSent: 1_000, dgramLost: 3, srttMs: 38)
        let snap = TunnelSnapshot(timestamp: now, clientState: CoreClientState.established.rawValue,
                                  connectedSince: now - 761, paths: [], seq: 1, reorderConfigured: true,
                                  tunnel: tunnel, stats: stats)
        let bandwidth: [BandwidthSample] = (0..<30).map(bandwidthSample)
        let reorder: [ReorderSample] = (0..<30).map(reorderSample)
        return LiveFrame(snapshot: snap, bandwidth: bandwidth, slots: ["en0": 0, "pdp_ip0": 1],
                         reorder: reorder, dgramLoss: 0.003)
    }()

    static func home(_ vs: VpnViewState) -> HomeModel {
        HomeModel(viewState: vs, elapsed: vs == .connected ? "12:41" : nil, canConnect: true, errors: [],
                  serverAddress: draft.addressText, cards: cards, dlBps: 54_000_000, ulBps: 6_000_000,
                  tunnel: tunnel, srttMs: 38, split: .throughput)
    }
}

private struct Themed<Content: View>: View {
    let content: Content
    init(@ViewBuilder _ content: () -> Content) { self.content = content() }
    var body: some View { MqThemeRoot { content } }
}

struct HomeScreen_Previews: PreviewProvider {
    static var previews: some View {
        Themed { HomeScreen(model: PreviewData.home(.connected), actions: HomeActions()) }
            .previewDisplayName("Connected")
        Themed { HomeScreen(model: PreviewData.home(.disconnected), actions: HomeActions()) }
            .previewDisplayName("Disconnected")
        Themed { HomeScreen(model: PreviewData.home(.connected), actions: HomeActions()) }
            .environment(\.dynamicTypeSize, .accessibility2)
            .previewDisplayName("Connected, large text")
    }
}

struct PathsScreen_Previews: PreviewProvider {
    static var previews: some View {
        Themed {
            PathsScreen(live: true, cards: PreviewData.cards, policy: PathPolicy(), editable: false, setPolicy: { _ in })
        }
    }
}

struct StatsScreen_Previews: PreviewProvider {
    static var previews: some View {
        Themed {
            StatsScreen(viewState: .connected, elapsed: "12:41", frame: PreviewData.frame,
                        nowMs: PreviewData.nowMs, onGoHome: {})
        }
        .preferredColorScheme(.dark)
    }
}

struct SettingsScreen_Previews: PreviewProvider {
    static var previews: some View {
        Themed {
            SettingsScreen(form: SettingsForm(draft: PreviewData.draft), events: [], tunnel: nil,
                           onNavigate: { _ in }, onRunSetup: {})
        }
    }
}

struct SetupScreen_Previews: PreviewProvider {
    static var previews: some View {
        Themed {
            SetupScreen(form: SettingsForm(draft: PreviewData.draft), available: [.wifi, .cellular],
                        finish: { nil }, onDone: {})
        }
    }
}
#endif
