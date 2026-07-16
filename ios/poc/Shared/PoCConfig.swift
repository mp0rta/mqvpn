// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation

/// PoC server/tunnel configuration, read from the Info.plist keys injected
/// by Config.xcconfig at build time (see project.yml). App-side: bundle
/// read (build-time seed values) plus `bulkURL` (multipath load gate).
/// `serverHost` may be a hostname or an IP literal.
struct PoCConfig {
    let serverHost: String      // hostname or IP literal
    let serverPort: Int
    let authKey: String         // "" = no Authorization header
    let tlsInsecure: Bool       // test-server PoC: certificate check off
    let bulkURL: URL?           // nil in the extension (app-only key)

    static func fromBundle() throws -> PoCConfig {
        let d = Bundle.main.infoDictionary ?? [:]
        guard let host = d["MqvpnServerHost"] as? String, !host.isEmpty,
              let portS = d["MqvpnServerPort"] as? String, let port = Int(portS) else {
            throw NSError(domain: "mqvpn.poc", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "server config missing"])
        }
        guard (1...65535).contains(port) else {
            throw NSError(domain: "mqvpn.poc", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "server port out of range"])
        }
        let bulk = (d["MqvpnBulkURL"] as? String).flatMap(URL.init(string:))
        return PoCConfig(serverHost: host, serverPort: port,
                         authKey: (d["MqvpnAuthKey"] as? String) ?? "",
                         tlsInsecure: (d["MqvpnTLSInsecure"] as? String) == "1",
                         bulkURL: bulk)
    }

    /// Legacy extension-path support: assumes an IPv4-literal host. Slated
    /// for removal once the engine takes a pre-resolved address instead.
    var serverSockaddr: sockaddr_in {
        var sa = sockaddr_in()
        sa.sin_family = sa_family_t(AF_INET)
        sa.sin_port = in_port_t(UInt16(serverPort).bigEndian)
        inet_pton(AF_INET, serverHost, &sa.sin_addr)
        return sa
    }
}
