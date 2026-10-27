// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation

/// One group of keys in NETunnelProviderProtocol.providerConfiguration. The
/// container merges every section into one dict, so a new section is one
/// conformance plus one entry in the persist list (TunnelController).
protocol ProviderConfigSection {
    func merged(into dict: inout [String: Any])
}

extension ProviderConfigSection {
    func toProviderConfiguration() -> [String: Any] {
        var d: [String: Any] = [:]
        merged(into: &d)
        return d
    }
}

/// A transport the user can turn on or off. Declaration order is the primary
/// path preference (Wi-Fi first); the provider binds paths in this order.
enum TransportKind: String, CaseIterable, Codable {
    case wifi, cellular
}

enum SplitChoice: Equatable { case throughput, lowLatency, redundant }

/// Traffic-split settings. `scheduler` is minrtt or wlb; nil = key absent
/// (legacy), which reads as throughput and is never written back until the
/// user taps a choice.
struct SplitSettings: Equatable, ProviderConfigSection {
    var scheduler: Scheduler?
    var redundantEnabled: Bool
    var redundantPorts: [UInt16]          // [] = all UDP
    var redundantPortsMalformed: Bool     // stored array invalid -> provider fails closed

    static let maxRedundantPorts = 16     // MQVPN_REDUNDANT_MAX_PORTS

    private enum Key {
        static let scheduler = "scheduler"
        static let enabled = "redundantEnabled"
        static let ports = "redundantPorts"
    }

    init(scheduler: Scheduler?, redundantEnabled: Bool, redundantPorts: [UInt16],
         redundantPortsMalformed: Bool) {
        self.scheduler = scheduler
        self.redundantEnabled = redundantEnabled
        self.redundantPorts = redundantPorts
        self.redundantPortsMalformed = redundantPortsMalformed
    }

    init(providerConfiguration dict: [String: Any]?) {
        var sched: Scheduler?
        if let n = dict?[Key.scheduler] as? NSNumber, let v = ReorderSettings.exactInt(n),
           let s = Int32(exactly: v).flatMap(Scheduler.init(rawValue:)), s == .minrtt || s == .wlb {
            sched = s
        }
        var enabled = false
        if let n = dict?[Key.enabled] as? NSNumber, ReorderSettings.isBool(n) { enabled = n.boolValue }
        var ports: [UInt16] = []
        var malformed = false
        if let raw = dict?[Key.ports] {
            if let arr = raw as? [NSNumber], arr.count <= Self.maxRedundantPorts {
                for n in arr {
                    if let v = ReorderSettings.exactInt(n), (1...65535).contains(v) {
                        if !ports.contains(UInt16(v)) { ports.append(UInt16(v)) }
                    } else { malformed = true }
                }
            } else { malformed = true }
        }
        self.init(scheduler: sched, redundantEnabled: enabled,
                  redundantPorts: malformed ? [] : ports, redundantPortsMalformed: malformed)
    }

    var choice: SplitChoice {
        if redundantEnabled { return .redundant }
        return scheduler == .minrtt ? .lowLatency : .throughput
    }

    func tapped(_ c: SplitChoice) -> SplitSettings {
        var s = self
        switch c {
        case .throughput: s.scheduler = .wlb; s.redundantEnabled = false
        case .lowLatency: s.scheduler = .minrtt; s.redundantEnabled = false
        case .redundant: s.scheduler = .minrtt; s.redundantEnabled = true
        }
        return s
    }

    func merged(into dict: inout [String: Any]) {
        if let scheduler { dict[Key.scheduler] = NSNumber(value: scheduler.rawValue) }
        dict[Key.enabled] = NSNumber(value: redundantEnabled)
        // Malformed stored list is left as-is so the provider keeps failing closed.
        if !redundantPortsMalformed { dict[Key.ports] = redundantPorts.map { NSNumber(value: $0) } }
    }

    /// All-or-nothing (Android rule): nil = invalid, blank = [] (all UDP).
    static func parseRedundantPorts(_ s: String) -> [UInt16]? {
        let t = s.trimmingCharacters(in: .whitespaces)
        if t.isEmpty { return [] }
        let tokens = t.split(separator: ",", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespaces) }
        guard t.count < 255, tokens.count <= maxRedundantPorts else { return nil }
        var out: [UInt16] = []
        for tok in tokens {
            guard let v = UInt16(tok), v >= 1 else { return nil }
            if !out.contains(v) { out.append(v) }
        }
        return out
    }
}

struct ProtectionSettings: Equatable, ProviderConfigSection {
    var killSwitch: Bool = false
    var autoReconnect: Bool = true

    /// Whether the session reconnects after a transient close. The kill
    /// switch implies it: a protected session never ends itself, so it keeps
    /// trying instead of holding a dead tunnel. The core's reconnect flag and
    /// the coordinator's reconnectEnabled both read this.
    var reconnects: Bool { autoReconnect || killSwitch }

    private enum Key {
        static let killSwitch = "killSwitch"
        static let autoReconnect = "autoReconnect"
    }

    init(killSwitch: Bool = false, autoReconnect: Bool = true) {
        self.killSwitch = killSwitch
        self.autoReconnect = autoReconnect
    }

    init(providerConfiguration dict: [String: Any]?) {
        self.init(killSwitch: readBool(dict, Key.killSwitch, false),
                  autoReconnect: readBool(dict, Key.autoReconnect, true))
    }

    func merged(into dict: inout [String: Any]) {
        dict[Key.killSwitch] = NSNumber(value: killSwitch)
        dict[Key.autoReconnect] = NSNumber(value: autoReconnect)
    }
}

/// Which transports a session may use. All-off is a configuration error the
/// provider refuses to start with; it is never silently widened. A new
/// TransportKind adds one stored flag, one key and one subscript case here.
struct PathPolicy: Equatable, ProviderConfigSection {
    var wifi: Bool = true
    var cellular: Bool = true

    private enum Key {
        static let wifi = "pathWifi"
        static let cellular = "pathCellular"
    }

    init(wifi: Bool = true, cellular: Bool = true) {
        self.wifi = wifi
        self.cellular = cellular
    }

    init(providerConfiguration dict: [String: Any]?) {
        self.init(wifi: readBool(dict, Key.wifi, true), cellular: readBool(dict, Key.cellular, true))
    }

    subscript(kind: TransportKind) -> Bool {
        get {
            switch kind {
            case .wifi: return wifi
            case .cellular: return cellular
            }
        }
        set {
            switch kind {
            case .wifi: wifi = newValue
            case .cellular: cellular = newValue
            }
        }
    }

    /// Enabled transports in primary-path order.
    var enabledKinds: [TransportKind] { TransportKind.allCases.filter { self[$0] } }

    var anyEnabled: Bool { !enabledKinds.isEmpty }

    func merged(into dict: inout [String: Any]) {
        dict[Key.wifi] = NSNumber(value: wifi)
        dict[Key.cellular] = NSNumber(value: cellular)
    }
}

private func readBool(_ dict: [String: Any]?, _ key: String, _ def: Bool) -> Bool {
    if let n = dict?[key] as? NSNumber, ReorderSettings.isBool(n) { return n.boolValue }
    return def
}
