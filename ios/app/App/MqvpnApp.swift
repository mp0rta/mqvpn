// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI
@preconcurrency import NetworkExtension

private enum Tab: Hashable { case home, paths, stats, settings }

@main
struct MqvpnApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var controller = TunnelController()
    @StateObject private var availability = TransportAvailability()

    var body: some Scene {
        WindowGroup {
            MqThemeRoot {
                RootView(controller: controller, availability: availability)
            }
            // Foreground-only polling: pause IPC when not active to avoid
            // battery drain and pointless sendProviderMessage churn.
            .onChange(of: scenePhase) { phase in
                controller.setScenePhaseActive(phase == .active)
            }
        }
    }
}

/// TabView shell + first-run setup cover. `showSetup` is explicit state (not derived from
/// manager existence) so "Run setup assistant again" works with an existing manager.
/// Observes nothing itself: each tab container observes what its screen shows.
private struct RootView: View {
    @Environment(\.mq) private var mq
    let controller: TunnelController
    let availability: TransportAvailability
    @State private var tab = Tab.home
    @State private var showSetup = false

    var body: some View {
        TabView(selection: $tab) {
            HomeTab(controller: controller, live: controller.live, availability: availability,
                    onManage: { tab = .paths }, onOpenSettings: { tab = .settings })
                .tabItem { Label("Home", systemImage: "power") }.tag(Tab.home)
            PathsTab(controller: controller, live: controller.live, availability: availability)
                .tabItem { Label("Paths", systemImage: "point.3.connected.trianglepath.dotted") }.tag(Tab.paths)
            StatsTab(controller: controller, live: controller.live, onGoHome: { tab = .home })
                .tabItem { Label("Stats", systemImage: "chart.bar") }.tag(Tab.stats)
            SettingsTab(controller: controller, eventLog: controller.eventLog, onRunSetup: { showSetup = true })
                .tabItem { Label("Settings", systemImage: "gearshape") }.tag(Tab.settings)
        }
        .tint(mq.accent)
        .task { await controller.loadOrCreateManager() }
        .onReceive(controller.$state) { st in
            if st == .absent { showSetup = true }
        }
        .onChange(of: showSetup) { controller.setupPresented = $0 }
        .fullScreenCover(isPresented: $showSetup) {
            MqThemeRoot {
                SetupTab(controller: controller, availability: availability) { showSetup = false }
            }
        }
    }
}
