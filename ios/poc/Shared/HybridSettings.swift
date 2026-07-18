// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation
import CoreFoundation

/// Hybrid-mode wire schema shared by app (writes providerConfiguration) and
/// extension (reads it). tcpMode is the native enum's plain int (0=stream /
/// 1=raw / 2=auto) — the app target does not link libmqvpn.
struct HybridSettings: Equatable {
    var enabled: Bool
    var tcpMode: Int

    static let disabled = HybridSettings(enabled: false, tcpMode: 2)
    static let modeStream = 0
    static let modeRaw = 1
    static let modeAuto = 2

    private enum Key {
        static let enabled = "hybridEnabled"
        static let tcpMode = "hybridTcpMode"
    }

    init(enabled: Bool, tcpMode: Int) {
        self.enabled = enabled
        self.tcpMode = tcpMode
    }

    func toProviderConfiguration() -> [String: Any] {
        [Key.enabled: NSNumber(value: enabled),
         Key.tcpMode: NSNumber(value: tcpMode)]
    }

    /// Validates on read; malformed dict -> nil (caller falls back to
    /// .disabled). Mode outside {0,1,2} clamps to auto (2).
    init?(providerConfiguration dict: [String: Any]?) {
        guard let dict else { return nil }
        var enabled = false
        if let n = dict[Key.enabled] as? NSNumber, ReorderSettings.isBool(n) {
            enabled = n.boolValue
        }
        var mode = Self.modeAuto
        if let n = dict[Key.tcpMode] as? NSNumber, let v = ReorderSettings.exactInt(n),
           (Self.modeStream...Self.modeAuto).contains(v) {
            mode = v
        }
        self.init(enabled: enabled, tcpMode: mode)
    }
}
