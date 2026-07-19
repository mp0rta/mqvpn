// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation

/// Runtime server config, persisted in providerConfiguration alongside reorder
/// settings. Mirrors ReorderSettings' validation-on-read discipline.
struct ServerSettings: Equatable {
    let host: String        // hostname or IP literal
    let port: Int
    let serverName: String  // TLS SNI / cert verify name; "" = use host (client.conf ServerName parity)
    let authKey: String     // "" = no Authorization header
    let insecure: Bool

    /// Trims host + serverName + authKey at construction (Android ConnectScreen parity).
    init(host: String, port: Int, serverName: String, authKey: String, insecure: Bool) {
        self.host = host.trimmingCharacters(in: .whitespacesAndNewlines)
        self.port = port
        self.serverName = serverName.trimmingCharacters(in: .whitespacesAndNewlines)
        self.authKey = authKey.trimmingCharacters(in: .whitespacesAndNewlines)
        self.insecure = insecure
    }

    static let emptyDraft = ServerSettings(host: "", port: 443, serverName: "",
                                           authKey: "", insecure: true)

    private enum Key {
        static let host = "serverHost", port = "serverPort"
        static let serverName = "serverName"
        static let authKey = "authKey", insecure = "tlsInsecure"
        static let all = [host, port, serverName, authKey, insecure]
    }

    static func fromBundle() throws -> ServerSettings {
        let c = try PoCConfig.fromBundle()
        return ServerSettings(host: c.serverHost, port: c.serverPort, serverName: c.serverName,
                              authKey: c.authKey, insecure: c.tlsInsecure)
    }

    /// EXISTENCE check (not typed parse): a present-but-wrong-type key must
    /// route to corrupt, never absent, so seeding can't overwrite it (D4).
    static func serverKeysPresent(in dict: [String: Any]?) -> Bool {
        guard let dict else { return false }
        return Key.all.contains { dict[$0] != nil }
    }

    /// All-or-nothing validated read. Reuses ReorderSettings' NSNumber discipline.
    /// serverName only: an ABSENT key reads as "" (configs saved before the key
    /// existed stay valid); a present-but-wrong-type key is still corrupt.
    init?(providerConfiguration dict: [String: Any]?) {
        guard let dict,
              let host = dict[Key.host] as? String,
              !host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              let portN = dict[Key.port] as? NSNumber, let port = ReorderSettings.exactInt(portN),
              (1...65535).contains(port),
              let authKey = dict[Key.authKey] as? String,
              let insecureN = dict[Key.insecure] as? NSNumber, ReorderSettings.isBool(insecureN)
        else { return nil }
        let rawName = dict[Key.serverName]
        guard rawName == nil || rawName is String else { return nil }
        self.init(host: host, port: port, serverName: (rawName as? String) ?? "",
                  authKey: authKey, insecure: insecureN.boolValue)
    }

    func toProviderConfiguration() -> [String: Any] {
        [Key.host: host, Key.port: NSNumber(value: port), Key.serverName: serverName,
         Key.authKey: authKey, Key.insecure: NSNumber(value: insecure)]
    }

    var isValid: Bool {
        !host.isEmpty && (1...65535).contains(port)   // host already trimmed in init
    }
}
