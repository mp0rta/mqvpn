// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors
import Foundation

var failures = 0
func check(_ cond: Bool, _ msg: String) { if !cond { failures += 1; print("FAIL: \(msg)") } }

// planReorder
check(ReorderSettings(enabled: false, profile: 4, ports: [443]).planReorder().rules.isEmpty,
      "disabled -> empty plan")
let plan = ReorderSettings(enabled: true, profile: 4, ports: [443, 443, 0, 70000, 5401]).planReorder()
check(plan.rules.map { $0.port } == [443, 5401], "dedupe + range filter")
check(plan.rules.allSatisfy { $0.proto == 17 && $0.profile == 4 }, "proto=17 + profile passthrough")
check(plan.warnings.contains { $0.contains(": 0") } && plan.warnings.contains { $0.contains("70000") },
      "out-of-range warnings")
let many = ReorderSettings(enabled: true, profile: 3, ports: Array(1000..<1020)).planReorder()
check(many.rules.count == 16 && many.warnings.contains { $0.contains("exceed 16") }, "cap at 16 + warning")

// isSavable
check(ReorderSettings(enabled: true, profile: 3, ports: []).isSavable == false, "enabled+no-ports unsavable")
check(ReorderSettings(enabled: true, profile: 3, ports: [443]).isSavable, "enabled+port savable")
check(ReorderSettings(enabled: false, profile: 3, ports: []).isSavable, "disabled always savable")

// parsePorts
let pp = ReorderSettings.parsePorts(" 443, 5401 ,x, ")
check(pp.ports == [443, 5401] && pp.warnings.contains { $0.contains("x") }, "parsePorts trim/skip/warn")

// providerConfiguration round-trip
let s = ReorderSettings(enabled: true, profile: 4, ports: [443, 5401])
check(ReorderSettings(providerConfiguration: s.toProviderConfiguration()) == s, "round-trip")

// exact-int validation
check(ReorderSettings.exactInt(NSNumber(value: true)) == nil, "reject bool NSNumber")
check(ReorderSettings.exactInt(NSNumber(value: 3.0)) == nil, "reject double-backed NSNumber")
check(ReorderSettings.exactInt(NSNumber(value: 3)) == 3, "accept int NSNumber")
let bad: [String: Any] = ["reorderEnabled": NSNumber(value: true),
                          "reorderProfile": NSNumber(value: 3.9),
                          "reorderPorts": [NSNumber(value: true), NSNumber(value: 443)]]
let parsed = ReorderSettings(providerConfiguration: bad)!
check(parsed.profile == 3 && parsed.ports == [443], "double profile clamps; bool port dropped")

// reorderEnableDecision (fail-closed)
check(ReorderSettings.reorderEnableDecision(ruleResults: [false, false]).enable == false, "all-fail -> disabled")
check(ReorderSettings.reorderEnableDecision(ruleResults: [false, true]) == (true, 1), "partial -> enabled, added=1")
check(ReorderSettings.reorderEnableDecision(ruleResults: []).enable == false, "no rules -> disabled")

// old-wire decode: JSON missing the new keys -> safe defaults, no throw
let oldWire = #"{"timestamp":1.0,"clientState":4,"connectedSince":0.5,"footprint":100,"paths":[]}"#
    .data(using: .utf8)!
let old = try! JSONDecoder().decode(TunnelSnapshot.self, from: oldWire)
check(old.seq == 0 && old.reorderConfigured == false && old.reorder == nil, "old-wire safe defaults")

// new-wire round-trip
let full = TunnelSnapshot(timestamp: 2, clientState: 4, connectedSince: 1, footprint: 1, paths: [],
                          seq: 7, reorderConfigured: true,
                          reorder: ReorderStatsSnapshot(delivered: 5, gapCount: 1, gapFilled: 1,
                                                        gapTimeout: 0, ackDemote: 0,
                                                        bufferedP50Ms: 1.5, bufferedP99Ms: 9.0))
let rt = try! JSONDecoder().decode(TunnelSnapshot.self, from: try! JSONEncoder().encode(full))
check(rt.seq == 7 && rt.reorderConfigured && rt.reorder == full.reorder, "new-wire round-trip")

// saveGuard order
check(saveGuard(isSaving: true, isEditable: false, hasManager: false) == .inProgress, "inProgress first")
check(saveGuard(isSaving: false, isEditable: false, hasManager: true) == .notEditable, "notEditable")
check(saveGuard(isSaving: false, isEditable: true, hasManager: false) == .notReady, "notReady")
check(saveGuard(isSaving: false, isEditable: true, hasManager: true) == nil, "proceed")

// performAtomicSave (real rollback logic, fault-injected via a fake store)
enum TestErr: Error { case boom }
final class FakeStore: ReorderConfigStore {
    var providerConfiguration: [String: Any]?
    var commitThrows = false
    var refreshThrows = false
    func commit() async throws { if commitThrows { throw TestErr.boom } }
    func refresh() async throws { if refreshThrows { throw TestErr.boom } }
}
func runAsync(_ body: @escaping () async -> Void) {
    let sem = DispatchSemaphore(value: 0)
    Task { await body(); sem.signal() }
    sem.wait()
}
func boolOf(_ store: FakeStore, _ k: String) -> Bool? {
    (store.providerConfiguration?[k] as? NSNumber)?.boolValue
}
runAsync {
    // commit fails -> providerConfiguration rolled back to the backup value
    let store = FakeStore(); store.providerConfiguration = ["reorderEnabled": NSNumber(value: false)]
    store.commitThrows = true
    var threw = false
    do { try await performAtomicSave(store, merge: ["reorderEnabled": NSNumber(value: true)]) }
    catch { threw = true }
    check(threw && boolOf(store, "reorderEnabled") == false, "commit fail -> rethrow + rollback")
}
runAsync {
    // commit ok but refresh fails -> committed value stays (refresh non-fatal)
    let store = FakeStore(); store.providerConfiguration = [:]
    store.refreshThrows = true
    var threw = false
    do { try await performAtomicSave(store, merge: ["reorderEnabled": NSNumber(value: true)]) }
    catch { threw = true }
    check(!threw && boolOf(store, "reorderEnabled") == true, "refresh fail -> committed")
}

// IngestGate
check(!IngestGate.accept(capturedEpoch: 1, currentEpoch: 2, isUp: true, snapSeq: 5,
                         snapTimestamp: 9, lastSeq: 0, lastTimestamp: 0), "stale epoch rejected")
check(!IngestGate.accept(capturedEpoch: 1, currentEpoch: 1, isUp: false, snapSeq: 5,
                         snapTimestamp: 9, lastSeq: 0, lastTimestamp: 0), "not-up rejected")
check(!IngestGate.accept(capturedEpoch: 1, currentEpoch: 1, isUp: true, snapSeq: 5,
                         snapTimestamp: 9, lastSeq: 5, lastTimestamp: 0), "seq regression rejected")
check(IngestGate.accept(capturedEpoch: 1, currentEpoch: 1, isUp: true, snapSeq: 6,
                        snapTimestamp: 9, lastSeq: 5, lastTimestamp: 0), "seq advance accepted")
check(IngestGate.accept(capturedEpoch: 1, currentEpoch: 1, isUp: true, snapSeq: 0,
                        snapTimestamp: 2, lastSeq: 0, lastTimestamp: 1), "legacy ts advance accepted")
check(!IngestGate.accept(capturedEpoch: 1, currentEpoch: 1, isUp: true, snapSeq: 0,
                         snapTimestamp: 1, lastSeq: 0, lastTimestamp: 2), "legacy ts regression rejected")
// legacy response must NOT slip in after a modern snapshot (lastSeq != 0)
check(!IngestGate.accept(capturedEpoch: 1, currentEpoch: 1, isUp: true, snapSeq: 0,
                         snapTimestamp: 99, lastSeq: 5, lastTimestamp: 0), "legacy rejected once modern seen")

// ── ServerSettings ──
let ss = ServerSettings(host: "1.2.3.4", port: 443, authKey: "k", insecure: true)
check(ServerSettings(providerConfiguration: ss.toProviderConfiguration()) == ss, "server round-trip")
check(ServerSettings(host: " 1.2.3.4 ", port: 443, authKey: " k ", insecure: false).host == "1.2.3.4", "host trimmed")
check(ServerSettings(host: " 1.2.3.4 ", port: 443, authKey: " k ", insecure: false).authKey == "k", "authKey trimmed")
check(ss.isValid, "valid savable")
check(ServerSettings(host: "  ", port: 443, authKey: "", insecure: true).isValid == false, "empty host invalid")
check(ServerSettings(host: "h", port: 0, authKey: "", insecure: true).isValid == false, "port 0 invalid")
check(ServerSettings(host: "h", port: 70000, authKey: "", insecure: true).isValid == false, "port hi invalid")
check(ServerSettings(host: "h", port: 443, authKey: "", insecure: true).isValid, "empty authKey ok")
// read validation
check(ServerSettings(providerConfiguration: ["serverHost": "h", "serverPort": NSNumber(value: 443), "authKey": "k"]) == nil, "missing tlsInsecure → nil")
check(ServerSettings(providerConfiguration: ["serverHost": "h", "serverPort": NSNumber(value: true), "authKey": "k", "tlsInsecure": NSNumber(value: false)]) == nil, "bool port → nil")
check(ServerSettings(providerConfiguration: ["serverHost": "", "serverPort": NSNumber(value: 443), "authKey": "k", "tlsInsecure": NSNumber(value: false)]) == nil, "empty host → nil")
// existence (Rigor E): wrong-type key still counts as present → corrupt, not absent
check(ServerSettings.serverKeysPresent(in: ["serverPort": "not-a-number"]) == true, "wrong-type key present")
check(ServerSettings.serverKeysPresent(in: ["reorderEnabled": NSNumber(value: true)]) == false, "only reorder keys → absent")
check(ServerSettings.serverKeysPresent(in: nil) == false, "nil dict → absent")

// ── resolveServer (offline) ──
// Shared assertion: AF_INET, big-endian port, exact sockaddr_in length.
func check4(_ r: ResolvedServerAddress?, _ port: UInt16, _ label: String) {
    guard let r else { check(false, "\(label): returned nil"); return }
    var sa = r.storage
    let ok = withUnsafeBytes(of: &sa) { raw -> Bool in
        let sin = raw.baseAddress!.assumingMemoryBound(to: sockaddr_in.self).pointee
        return sin.sin_family == sa_family_t(AF_INET)
            && sin.sin_port == in_port_t(port.bigEndian)
            && r.len == socklen_t(MemoryLayout<sockaddr_in>.size)
    }
    check(ok, label)
}
check4(resolveServer("127.0.0.1", 443), 443, "resolve IP literal 127.0.0.1:443")
check4(resolveServer("localhost", 8080), 8080, "resolve hostname localhost:8080")  // /etc/hosts, offline; proves the name (non-literal) path + port propagation
check(resolveServer("", 443) == nil, "empty host → nil")       // Optional<T> == nil compiles for any T
check(resolveServer("   ", 443) == nil, "whitespace host → nil")

if failures == 0 { print("host tests: ALL PASS") } else { print("host tests: \(failures) FAILURES"); exit(1) }
