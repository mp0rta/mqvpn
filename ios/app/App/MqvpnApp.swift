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
private struct RootView: View {
    @Environment(\.mq) private var mq
    @ObservedObject var controller: TunnelController
    @ObservedObject var availability: TransportAvailability
    @State private var tab = Tab.home
    @State private var showSetup = false
    @State private var path: [SettingsRoute] = []

    var body: some View {
        TabView(selection: $tab) {
            HomeScreen(controller: controller, availability: availability,
                       onManage: { tab = .paths }, onOpenSettings: { tab = .settings })
                .tabItem { Label("Home", systemImage: "power") }.tag(Tab.home)
            PathsScreen(controller: controller, availability: availability)
                .tabItem { Label("Paths", systemImage: "point.3.connected.trianglepath.dotted") }.tag(Tab.paths)
            StatsScreen(controller: controller, onGoHome: { tab = .home })
                .tabItem { Label("Stats", systemImage: "chart.bar") }.tag(Tab.stats)
            NavigationStack(path: $path) {
                SettingsScreen(controller: controller, eventLog: controller.eventLog,
                               onNavigate: { path.append($0) }, onRunSetup: { showSetup = true })
                    .toolbar(.hidden, for: .navigationBar)
                    .navigationDestination(for: SettingsRoute.self) { route in
                        Group {
                            switch route {
                            case .reorder: ReorderDetailScreen(controller: controller, back: pop)
                            case .hybrid: HybridDetailScreen(controller: controller, back: pop)
                            case .redundant: RedundantDetailScreen(controller: controller, back: pop)
                            }
                        }.toolbar(.hidden, for: .navigationBar)
                    }
            }
            .tabItem { Label("Settings", systemImage: "gearshape") }.tag(Tab.settings)
        }
        .tint(mq.accent)
        .task { await controller.loadOrCreateManager() }
        .onChange(of: controller.state) { st in
            if st == .absent { showSetup = true }
        }
        .onChange(of: showSetup) { controller.setupPresented = $0 }
        .fullScreenCover(isPresented: $showSetup) {
            MqThemeRoot {
                SetupScreen(controller: controller, availability: availability) { showSetup = false }
            }
        }
    }

    private func pop() { if !path.isEmpty { path.removeLast() } }
}
