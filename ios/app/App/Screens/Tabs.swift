// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI

// Tab containers: the only views that observe the app's objects. Each one
// observes just what its screen shows and hands the screen plain values and
// closures, so the 1 Hz LiveSession updates re-render Home / Paths / Stats only
// and every screen can be previewed without a NETunnelProviderManager.

/// Session seconds from provider-clock fields; nil while reconnecting / no data.
@MainActor private func elapsedText(_ vs: VpnViewState, _ snap: TunnelSnapshot?) -> String? {
    guard vs == .connected, let snap, let since = snap.connectedSince else { return nil }
    return fmtElapsed(Int64(max(0, snap.timestamp - since)))
}

@MainActor private func transportCards(_ frame: LiveFrame, available: Set<TransportKind>) -> [PathCard] {
    let paths = (frame.snapshot?.paths ?? []).map { LivePath(iface: $0.name, status: $0.status, kind: $0.kind) }
    return pathCards(paths: paths, available: available, sample: frame.bandwidth.last)
}

struct HomeTab: View {
    @ObservedObject var controller: TunnelController
    @ObservedObject var live: LiveSession
    @ObservedObject var availability: TransportAvailability
    let onManage: () -> Void
    let onOpenSettings: () -> Void

    var body: some View {
        let vs = controller.viewState
        let frame = live.frame
        let last = frame.bandwidth.last
        HomeScreen(
            model: HomeModel(
                viewState: vs, elapsed: elapsedText(vs, frame.snapshot), canConnect: controller.isConnectable,
                errors: errors, serverAddress: controller.settings.draft.addressText,
                cards: transportCards(frame, available: availability.kinds).filter { $0.available && $0.active },
                dlBps: last?.dlBps ?? 0, ulBps: last?.ulBps ?? 0,
                tunnel: controller.facts?.tunnel, srttMs: frame.snapshot?.stats?.srttMs,
                split: controller.settings.draft.split.choice),
            actions: HomeActions(connect: { controller.start() }, disconnect: { controller.stop() },
                                 manage: onManage, openSettings: onOpenSettings))
    }

    private var errors: [String] {
        var out: [String] = []
        if case .loadFailed(let e) = controller.state { out.append(e) }
        if let e = controller.configError { out.append(e) }
        if let e = controller.settings.saveError { out.append(e) }
        return out
    }
}

struct PathsTab: View {
    @ObservedObject var controller: TunnelController
    @ObservedObject var live: LiveSession
    @ObservedObject var availability: TransportAvailability

    var body: some View {
        PathsScreen(live: controller.viewState == .connected,
                    cards: transportCards(live.frame, available: availability.kinds),
                    policy: controller.settings.draft.paths, editable: controller.isEditable,
                    setPolicy: { p in controller.settings.update { $0.paths = p } })
    }
}

struct StatsTab: View {
    @ObservedObject var controller: TunnelController
    @ObservedObject var live: LiveSession
    let onGoHome: () -> Void

    var body: some View {
        let vs = controller.viewState
        StatsScreen(viewState: vs, elapsed: elapsedText(vs, live.frame.snapshot), frame: live.frame,
                    nowMs: Int64(Date().timeIntervalSince1970 * 1000), onGoHome: onGoHome)
    }
}

struct SettingsTab: View {
    @ObservedObject var controller: TunnelController
    @ObservedObject var eventLog: EventLog
    let onRunSetup: () -> Void
    @State private var path: [SettingsRoute] = []

    var body: some View {
        let form = SettingsForm(controller.settings, editable: controller.isEditable)
        NavigationStack(path: $path) {
            SettingsScreen(form: form, events: eventLog.events,
                           tunnel: controller.viewState == .connected ? controller.facts?.tunnel : nil,
                           onNavigate: { path.append($0) }, onRunSetup: onRunSetup)
                .toolbar(.hidden, for: .navigationBar)
                .navigationDestination(for: SettingsRoute.self) { route in
                    SettingsDetail(controller: controller, route: route, back: pop)
                        .toolbar(.hidden, for: .navigationBar)
                }
        }
    }

    private func pop() { if !path.isEmpty { path.removeLast() } }
}

/// Observes the controller itself: a pushed destination is not rebuilt when the
/// root form changes, so it must read the draft on its own.
private struct SettingsDetail: View {
    @ObservedObject var controller: TunnelController
    let route: SettingsRoute
    let back: () -> Void

    var body: some View {
        let form = SettingsForm(controller.settings, editable: controller.isEditable)
        switch route {
        case .reorder: ReorderDetailScreen(form: form, back: back)
        case .hybrid: HybridDetailScreen(form: form, back: back)
        case .redundant: RedundantDetailScreen(form: form, back: back)
        }
    }
}

struct SetupTab: View {
    @ObservedObject var controller: TunnelController
    @ObservedObject var availability: TransportAvailability
    let onDone: () -> Void

    var body: some View {
        let settings = controller.settings
        SetupScreen(form: SettingsForm(settings, editable: true), available: availability.kinds,
                    finish: {
                        if await settings.commitFirst() { return nil }
                        return settings.saveError ?? settings.fieldErrors.values.sorted().first
                            ?? "Settings could not be saved"
                    },
                    onDone: onDone)
    }
}
