// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// Owned, by-value resolved server address. The addrinfo pointer is never
/// retained (freeaddrinfo runs before return); mqvpn_client_set_server_addr
/// copies these bytes immediately, so there is no lifetime hazard.
struct ResolvedServerAddress {
    var storage: sockaddr_storage
    var len: socklen_t
}

/// Resolve host+port to an IPv4 sockaddr. AF_INET only (iOS PoC path fds and
/// the assigned tunnel address are v4). Returns nil on empty/whitespace host
/// (getaddrinfo("") resolves to 127.0.0.1 — must self-guard), resolver failure,
/// or a non-v4 / unexpected-length result.
func resolveServer(_ host: String, _ port: Int) -> ResolvedServerAddress? {
    let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return nil }

    var hints = addrinfo()
    hints.ai_family = AF_INET
    hints.ai_socktype = SOCK_DGRAM
    var res: UnsafeMutablePointer<addrinfo>?
    guard getaddrinfo(trimmed, String(port), &hints, &res) == 0, let ai = res else { return nil }
    defer { freeaddrinfo(res) }

    guard let addr = ai.pointee.ai_addr,
          ai.pointee.ai_family == AF_INET,
          ai.pointee.ai_addrlen == socklen_t(MemoryLayout<sockaddr_in>.size)
    else { return nil }

    var out = ResolvedServerAddress(storage: sockaddr_storage(), len: ai.pointee.ai_addrlen)
    withUnsafeMutableBytes(of: &out.storage) { dst in
        dst.baseAddress!.copyMemory(from: addr, byteCount: Int(ai.pointee.ai_addrlen))
    }
    return out
}
