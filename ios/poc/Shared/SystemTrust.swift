// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation
import Security
import os.log

// Shared/ compiles into the app target and the host tests, where
// MqvpnEngine.swift's file-scope `log` is not visible — own Logger (D9).
private let trustLog = Logger(subsystem: "mqvpn.poc", category: "trust")

/// Platform certificate verification via SecTrust (spec D9). The sole judge
/// of chain and hostname when installed through
/// mqvpn_config_set_cert_verifier. Runs synchronously on the engine tick
/// thread inside the TLS handshake — it must not re-enter libmqvpn and it
/// must never touch the network: during reasserting the tunnel's default
/// route is dead, and an AIA/OCSP fetch would stall the tick thread until
/// timeout, turning one transient failure terminal. Consequence: the server
/// must present its full chain (leaf + intermediates; Let's Encrypt's
/// fullchain.pem does).
enum SystemTrust {
    static func evaluate(chain: [Data], hostname: String) -> Bool {
        var certs: [SecCertificate] = []
        for der in chain {
            guard let c = SecCertificateCreateWithData(nil, der as CFData) else {
                trustLog.error("certificate DER rejected by SecCertificateCreateWithData")
                return false
            }
            certs.append(c)
        }
        guard !certs.isEmpty else { return false }
        let policy = SecPolicyCreateSSL(true, hostname as CFString)
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(certs as CFArray, policy, &trust) == errSecSuccess,
              let trust else {
            trustLog.error("SecTrustCreateWithCertificates failed")
            return false
        }
        // Fail closed if the fetch ban cannot be installed: proceeding with
        // network fetch enabled would silently reintroduce the tick-thread
        // stall this ban exists to prevent.
        guard SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess else {
            trustLog.error("SecTrustSetNetworkFetchAllowed failed")
            return false
        }
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else {
            trustLog.notice("rejected: \(String(describing: error), privacy: .public)")
            return false
        }
        // CT observation point for gate G-t1 (not used for the decision):
        // Apple's CT policy is part of the SSL-policy evaluation for public
        // roots; only leaf-embedded SCTs can satisfy it through this path.
        let result = SecTrustCopyResult(trust) as? [String: Any]
        let ct = result?[kSecTrustCertificateTransparency as String] as? Bool
        trustLog.notice("kSecTrustCertificateTransparency=\(ct.map(String.init(describing:)) ?? "absent", privacy: .public)")
        return true
    }
}
