// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Network

/// The one mapping between the app's transports and Network.framework's
/// interface types (Network is not importable in the pure Linux build).
extension TransportKind {
    var interfaceType: NWInterface.InterfaceType {
        switch self {
        case .wifi: return .wifi
        case .cellular: return .cellular
        }
    }

    init?(interfaceType: NWInterface.InterfaceType) {
        guard let k = Self.allCases.first(where: { $0.interfaceType == interfaceType }) else { return nil }
        self = k
    }
}
