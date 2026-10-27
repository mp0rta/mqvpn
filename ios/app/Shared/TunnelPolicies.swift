// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation

enum SplitChoice: Equatable { case throughput, lowLatency, redundant }

/// Traffic-split settings. `scheduler` is the raw mqvpn_scheduler_t
/// (0 = minrtt, 1 = wlb); nil = key absent (legacy), which reads as
/// throughput and is never written back until the user taps a choice.
struct SplitSettings: Equatable {
    var scheduler: Int32?
    var redundantEnabled: Bool
    var redundantPorts: [UInt16]          // [] = all UDP
    var redundantPortsMalformed: Bool     // stored array invalid -> provider fails closed

    static let maxRedundantPorts = 16     // MQVPN_REDUNDANT_MAX_PORTS

    private enum Key {
        static let scheduler = "scheduler"
        static let enabled = "redundantEnabled"
        static let ports = "redundantPorts"
    }

    init(scheduler: Int32?, redundantEnabled: Bool, redundantPorts: [UInt16],
         redundantPortsMalformed: Bool) {
        self.scheduler = scheduler
        self.redundantEnabled = redundantEnabled
        self.redundantPorts = redundantPorts
        self.redundantPortsMalformed = redundantPortsMalformed
    }

    init(providerConfiguration dict: [String: Any]?) {
        var sched: Int32?
        if let n = dict?[Key.scheduler] as? NSNumber, let v = ReorderSettings.exactInt(n), v == 0 || v == 1 {
            sched = Int32(v)
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
        return scheduler == 0 ? .lowLatency : .throughput
    }

    func tapped(_ c: SplitChoice) -> SplitSettings {
        var s = self
        switch c {
        case .throughput: s.scheduler = 1; s.redundantEnabled = false
        case .lowLatency: s.scheduler = 0; s.redundantEnabled = false
        case .redundant: s.scheduler = 0; s.redundantEnabled = true
        }
        return s
    }

    func merged(into dict: inout [String: Any]) {
        if let scheduler { dict[Key.scheduler] = NSNumber(value: scheduler) }
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

struct ProtectionSettings: Equatable {
    var killSwitch: Bool = false
    var autoReconnect: Bool = true

    init(killSwitch: Bool = false, autoReconnect: Bool = true) {
        self.killSwitch = killSwitch
        self.autoReconnect = autoReconnect
    }

    init(providerConfiguration dict: [String: Any]?) {
        self.init(killSwitch: readBool(dict, "killSwitch", false),
                  autoReconnect: readBool(dict, "autoReconnect", true))
    }

    func merged(into dict: inout [String: Any]) {
        dict["killSwitch"] = NSNumber(value: killSwitch)
        dict["autoReconnect"] = NSNumber(value: autoReconnect)
    }
}

/// All-off is a configuration error the provider refuses to start with; it is
/// never silently widened.
struct PathPolicy: Equatable {
    var wifi: Bool = true
    var cellular: Bool = true

    init(wifi: Bool = true, cellular: Bool = true) {
        self.wifi = wifi
        self.cellular = cellular
    }

    init(providerConfiguration dict: [String: Any]?) {
        self.init(wifi: readBool(dict, "pathWifi", true), cellular: readBool(dict, "pathCellular", true))
    }

    var anyEnabled: Bool { wifi || cellular }

    func merged(into dict: inout [String: Any]) {
        dict["pathWifi"] = NSNumber(value: wifi)
        dict["pathCellular"] = NSNumber(value: cellular)
    }
}

private func readBool(_ dict: [String: Any]?, _ key: String, _ def: Bool) -> Bool {
    if let n = dict?[key] as? NSNumber, ReorderSettings.isBool(n) { return n.boolValue }
    return def
}
