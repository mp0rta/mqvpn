// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation
import CoreFoundation

/// Single source of the reorder wire schema + validation, shared by the app
/// (writes providerConfiguration) and the extension (reads it, emits setter
/// calls). Plain Foundation — the app target does not link libmqvpn, so profile
/// values are plain ints matching the native enum (3=CELLULAR_BOND,
/// 4=FIBER_LTE) and proto is 17 (UDP).
struct ReorderSettings: Equatable {
    var enabled: Bool
    var profile: Int          // 3 = CELLULAR_BOND, 4 = FIBER_LTE
    var ports: [Int]

    // Explicit memberwise init: defining the custom `init?(providerConfiguration:)`
    // below would otherwise suppress Swift's synthesized memberwise init, which
    // `.disabled` and `init?` both call.
    init(enabled: Bool, profile: Int, ports: [Int]) {
        self.enabled = enabled
        self.profile = profile
        self.ports = ports
    }

    static let disabled = ReorderSettings(enabled: false, profile: 3, ports: [])
    static let profileCellularBond = 3
    static let profileFiberLTE = 4
    static let protoUDP = 17
    static let maxRules = 16

    private enum Key {
        static let enabled = "reorderEnabled"
        static let profile = "reorderProfile"
        static let ports = "reorderPorts"
    }

    func toProviderConfiguration() -> [String: Any] {
        [Key.enabled: NSNumber(value: enabled),
         Key.profile: NSNumber(value: profile),
         Key.ports: ports.map { NSNumber(value: $0) }]
    }

    /// Validates on read. A malformed top-level dict yields nil (caller falls
    /// back to `.disabled`). profile out of {3,4} clamps to 3; ports out of
    /// range / wrong type are dropped.
    init?(providerConfiguration dict: [String: Any]?) {
        guard let dict else { return nil }
        var enabled = false
        if let n = dict[Key.enabled] as? NSNumber, Self.isBool(n) { enabled = n.boolValue }
        var profile = Self.profileCellularBond
        if let n = dict[Key.profile] as? NSNumber, let v = Self.exactInt(n),
           v == Self.profileCellularBond || v == Self.profileFiberLTE {
            profile = v
        }
        var ports: [Int] = []
        if let arr = dict[Key.ports] as? [NSNumber] {
            for n in arr where !Self.isBool(n) {
                if let v = Self.exactInt(n), (1...65535).contains(v) { ports.append(v) }
            }
        }
        self.init(enabled: enabled, profile: profile, ports: ports)
    }

    /// True iff `n` is a genuine integer NSNumber (not boolean, not
    /// float/double-backed — CFNumberIsFloatType catches `NSNumber(3.0)`).
    static func exactInt(_ n: NSNumber) -> Int? {
        if isBool(n) { return nil }
        if CFNumberIsFloatType(n as CFNumber) { return nil }
        return n.intValue
    }

    static func isBool(_ n: NSNumber) -> Bool {
        CFGetTypeID(n as CFTypeRef) == CFBooleanGetTypeID()
    }

    /// Parse the comma-separated ports field. Non-numeric entries are skipped
    /// with a warning; range/dedupe happen in planReorder.
    static func parsePorts(_ text: String) -> (ports: [Int], warnings: [String]) {
        var ports: [Int] = []
        var warnings: [String] = []
        for raw in text.split(separator: ",") {
            let t = raw.trimmingCharacters(in: .whitespaces)
            if t.isEmpty { continue }
            if let v = Int(t) { ports.append(v) } else { warnings.append("not a number: \(t)") }
        }
        return (ports, warnings)
    }

    /// Empty plan when !enabled. Else dedupe, range-filter, cap at maxRules,
    /// map each surviving port to a UDP rule with `profile`.
    func planReorder(maxRules: Int = ReorderSettings.maxRules)
        -> (rules: [ReorderRuleSpec], warnings: [String]) {
        guard enabled else { return ([], []) }
        var warnings: [String] = []
        var seen = Set<Int>()
        var valid: [Int] = []
        for p in ports {
            guard (1...65535).contains(p) else { warnings.append("port out of range: \(p)"); continue }
            if seen.insert(p).inserted { valid.append(p) }
        }
        if valid.count > maxRules {
            warnings.append("ports exceed \(maxRules); dropping \(valid.count - maxRules)")
            valid = Array(valid.prefix(maxRules))
        }
        return (valid.map { ReorderRuleSpec(proto: Self.protoUDP, port: $0, profile: profile) },
                warnings)
    }

    /// Save-gate: enabling requires at least one rule.
    var isSavable: Bool { !enabled || !planReorder().rules.isEmpty }

    /// Fail-closed enable decision: reorder is enabled only if at least one
    /// add-rule call succeeded. `ruleResults[i] == true` means rule i landed.
    static func reorderEnableDecision(ruleResults: [Bool]) -> (enable: Bool, added: Int) {
        let added = ruleResults.filter { $0 }.count
        return (added > 0, added)
    }
}

struct ReorderRuleSpec: Equatable {
    let proto: Int
    let port: Int
    let profile: Int
}
