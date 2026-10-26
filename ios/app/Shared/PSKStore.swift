// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation
import Security

/// The PSK as keychain items, shared by the app (writes) and the extension
/// (reads) through the keychain-access-groups entitlement both targets carry:
/// its first entry is the default group new items land in. The extension finds
/// the item by NETunnelProviderProtocol.passwordReference.
///
/// Each save adds a NEW item and the caller deletes the old one only after the
/// VPN configuration that references the new one is committed, so a failed
/// commit never leaves the saved configuration pointing at a changed PSK.
enum PSKStore {
    /// Adds `psk` as a new item and returns its persistent reference; an empty
    /// PSK stores nothing and returns nil.
    static func add(_ psk: String) throws -> Data? {
        guard !psk.isEmpty else { return nil }
        let attrs: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "org.mqvpn.app",
            kSecAttrAccount as String: "psk-\(UUID().uuidString)",
            kSecValueData as String: Data(psk.utf8),
            // The extension may start before the user unlocks (on-demand).
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecReturnPersistentRef as String: true,
        ]
        var ref: CFTypeRef?
        let st = SecItemAdd(attrs as CFDictionary, &ref)
        guard st == errSecSuccess, let data = ref as? Data else { throw error(st) }
        return data
    }

    /// Best-effort removal of the item behind `ref` (an orphan only wastes a
    /// keychain slot).
    static func delete(_ ref: Data?) {
        guard let ref else { return }
        SecItemDelete([kSecValuePersistentRef as String: ref] as CFDictionary)
    }

    /// The PSK behind `ref`; "" when there is no reference (no PSK configured).
    /// Throws when a reference exists but its item cannot be read, e.g. before
    /// the first unlock, so a tunnel never starts without its configured PSK.
    static func load(_ ref: Data?) throws -> String {
        guard let ref else { return "" }
        let query: [String: Any] = [kSecValuePersistentRef as String: ref,
                                    kSecReturnData as String: true]
        var out: CFTypeRef?
        let st = SecItemCopyMatching(query as CFDictionary, &out)
        guard st == errSecSuccess, let data = out as? Data else { throw error(st) }
        return String(decoding: data, as: UTF8.self)
    }

    private static func error(_ status: OSStatus) -> NSError {
        NSError(domain: NSOSStatusErrorDomain, code: Int(status),
                userInfo: [NSLocalizedDescriptionKey: "keychain error \(status)"])
    }
}
