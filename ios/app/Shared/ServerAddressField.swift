// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation

/// Single "host[:port]" text field, as on desktop and Android. Pure so it is unit-testable.
struct ServerAddressField {
    static let defaultPort = 443

    /// Accepts host | host:port | v6literal | [v6] | [v6]:port; nil when malformed.
    static func parse(_ text: String) -> (host: String, port: Int)? {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty || t.contains(where: { $0.isWhitespace }) { return nil }
        if t.hasPrefix("[") {
            guard let close = t.firstIndex(of: "]") else { return nil }
            let host = String(t[t.index(after: t.startIndex)..<close])
            if !isV6(host) { return nil }
            let rest = t[t.index(after: close)...]
            if rest.isEmpty { return (host, defaultPort) }
            guard rest.hasPrefix(":"), let p = port(String(rest.dropFirst())) else { return nil }
            return (host, p)
        }
        switch t.filter({ $0 == ":" }).count {
        case 0: return (t, defaultPort)
        case 1:
            let parts = t.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            guard !parts[0].isEmpty, let p = port(String(parts[1])) else { return nil }
            return (String(parts[0]), p)
        default: return isV6(t) ? (t, defaultPort) : nil
        }
    }

    /// Always "host:port" (even :443); v6 literals are bracketed.
    static func format(host: String, port: Int) -> String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }

    private static func isV6(_ s: String) -> Bool {
        s.contains(":") && s.unicodeScalars.allSatisfy { ($0.isASCII && $0.properties.isASCIIHexDigit) || $0 == ":" || $0 == "." }
    }

    private static func port(_ s: String) -> Int? {
        guard !s.isEmpty, s.count <= 5, s.unicodeScalars.allSatisfy({ ("0"..."9").contains($0) }),
              let n = Int(s), (1...65535).contains(n) else { return nil }
        return n
    }
}
