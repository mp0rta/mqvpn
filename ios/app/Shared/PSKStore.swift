// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation
import Security

/// The PSK as one keychain item, shared by the app (writes) and the extension
/// (reads) through the keychain-access-groups entitlement both targets carry:
/// its first entry is the default group new items land in. The extension finds
/// the item by NETunnelProviderProtocol.passwordReference.
enum PSKStore {
    private static let item: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "org.mqvpn.app",
        kSecAttrAccount as String: "psk",
    ]

    /// Stores `psk` in place (the persistent reference stays the same across
    /// updates) and returns that reference; an empty PSK deletes the item.
    static func save(_ psk: String) throws -> Data? {
        guard !psk.isEmpty else {
            let st = SecItemDelete(item as CFDictionary)
            guard st == errSecSuccess || st == errSecItemNotFound else { throw error(st) }
            return nil
        }
        let value = Data(psk.utf8)
        var st = SecItemUpdate(item as CFDictionary,
                               [kSecValueData as String: value] as CFDictionary)
        if st == errSecItemNotFound {
            var add = item
            add[kSecValueData as String] = value
            // The extension may start before the user unlocks (on-demand).
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            st = SecItemAdd(add as CFDictionary, nil)
        }
        guard st == errSecSuccess else { throw error(st) }
        var query = item
        query[kSecReturnPersistentRef as String] = true
        var ref: CFTypeRef?
        st = SecItemCopyMatching(query as CFDictionary, &ref)
        guard st == errSecSuccess, let data = ref as? Data else { throw error(st) }
        return data
    }

    /// The PSK behind `ref`; "" when there is no reference or no item.
    static func load(_ ref: Data?) -> String {
        guard let ref else { return "" }
        let query: [String: Any] = [kSecValuePersistentRef as String: ref,
                                    kSecReturnData as String: true]
        var out: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess,
              let data = out as? Data else { return "" }
        return String(decoding: data, as: UTF8.self)
    }

    private static func error(_ status: OSStatus) -> NSError {
        NSError(domain: NSOSStatusErrorDomain, code: Int(status),
                userInfo: [NSLocalizedDescriptionKey: "keychain error \(status)"])
    }
}
