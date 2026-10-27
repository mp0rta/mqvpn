// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI
import Network

/// Whether Wi-Fi / cellular currently has a satisfied path. Two monitors
/// (requiredInterfaceType), alive for the app process.
@MainActor
final class TransportAvailability: ObservableObject {
    @Published var wifi = false
    @Published var cellular = false
    private let wifiMonitor = NWPathMonitor(requiredInterfaceType: .wifi)
    private let cellularMonitor = NWPathMonitor(requiredInterfaceType: .cellular)

    var kinds: Set<TransportKind> {
        var s = Set<TransportKind>()
        if wifi { s.insert(.wifi) }
        if cellular { s.insert(.cellular) }
        return s
    }

    init() {
        wifiMonitor.pathUpdateHandler = { [weak self] path in
            let ok = path.status == .satisfied
            Task { @MainActor in self?.wifi = ok }
        }
        cellularMonitor.pathUpdateHandler = { [weak self] path in
            let ok = path.status == .satisfied
            Task { @MainActor in self?.cellular = ok }
        }
        wifiMonitor.start(queue: DispatchQueue(label: "org.mqvpn.avail.wifi"))
        cellularMonitor.start(queue: DispatchQueue(label: "org.mqvpn.avail.cellular"))
    }
}
