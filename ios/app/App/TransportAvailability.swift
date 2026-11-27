// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import SwiftUI
import Network

/// Which transports currently have a satisfied path: one NWPathMonitor per
/// TransportKind (requiredInterfaceType), alive for the app process.
@MainActor
final class TransportAvailability: ObservableObject {
    @Published private(set) var kinds: Set<TransportKind> = []
    private let monitors: [TransportKind: NWPathMonitor]

    init() {
        monitors = Dictionary(uniqueKeysWithValues: TransportKind.allCases.map {
            ($0, NWPathMonitor(requiredInterfaceType: $0.interfaceType))
        })
        let queue = DispatchQueue(label: "org.mqvpn.avail")
        for (kind, m) in monitors {
            m.pathUpdateHandler = { [weak self] path in
                let ok = path.status == .satisfied
                Task { @MainActor in self?.set(kind, ok) }
            }
            m.start(queue: queue)
        }
    }

    private func set(_ kind: TransportKind, _ ok: Bool) {
        guard kinds.contains(kind) != ok else { return }
        if ok { kinds.insert(kind) } else { kinds.remove(kind) }
    }
}
