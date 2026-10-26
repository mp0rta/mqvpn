// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI
@preconcurrency import NetworkExtension

@main
struct MqvpnApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var controller = TunnelController()

    var body: some Scene {
        WindowGroup {
            DashboardView(controller: controller, eventLog: controller.eventLog)
                // Foreground-only polling: pause IPC when not active to avoid
                // battery drain and pointless sendProviderMessage churn.
                .onChange(of: scenePhase) { phase in
                    controller.setScenePhaseActive(phase == .active)
                }
        }
    }
}
