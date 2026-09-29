// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors
import Foundation

// Unbuffered: a trap must not discard buffered FAIL: lines on CI's piped stdout.
setvbuf(stdout, nil, _IONBF, 0)

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
let ss = ServerSettings(host: "1.2.3.4", port: 443, serverName: "vpn.example.com", authKey: "k", insecure: true)
check(ServerSettings(providerConfiguration: ss.toProviderConfiguration()) == ss, "server round-trip")
check(ServerSettings(host: " 1.2.3.4 ", port: 443, serverName: "", authKey: " k ", insecure: false).host == "1.2.3.4", "host trimmed")
check(ServerSettings(host: " 1.2.3.4 ", port: 443, serverName: "", authKey: " k ", insecure: false).authKey == "k", "authKey trimmed")
check(ServerSettings(host: "h", port: 443, serverName: " vpn.example.com ", authKey: "", insecure: false).serverName == "vpn.example.com", "serverName trimmed")
check(ss.isValid, "valid savable")
check(ServerSettings(host: "  ", port: 443, serverName: "", authKey: "", insecure: true).isValid == false, "empty host invalid")
check(ServerSettings(host: "h", port: 0, serverName: "", authKey: "", insecure: true).isValid == false, "port 0 invalid")
check(ServerSettings(host: "h", port: 70000, serverName: "", authKey: "", insecure: true).isValid == false, "port hi invalid")
check(ServerSettings(host: "h", port: 443, serverName: "", authKey: "", insecure: true).isValid, "empty authKey ok")
// read validation
check(ServerSettings(providerConfiguration: ["serverHost": "h", "serverPort": NSNumber(value: 443), "authKey": "k"]) == nil, "missing tlsInsecure → nil")
check(ServerSettings(providerConfiguration: ["serverHost": "h", "serverPort": NSNumber(value: true), "authKey": "k", "tlsInsecure": NSNumber(value: false)]) == nil, "bool port → nil")
check(ServerSettings(providerConfiguration: ["serverHost": "", "serverPort": NSNumber(value: 443), "authKey": "k", "tlsInsecure": NSNumber(value: false)]) == nil, "empty host → nil")
// serverName: pre-key configs (absent) stay valid and read as ""; wrong type is corrupt
let preKey = ServerSettings(providerConfiguration: ["serverHost": "h", "serverPort": NSNumber(value: 443), "authKey": "k", "tlsInsecure": NSNumber(value: false)])
check(preKey?.serverName == "", "absent serverName → \"\"")
check(ServerSettings(providerConfiguration: ["serverHost": "h", "serverPort": NSNumber(value: 443), "serverName": NSNumber(value: 1), "authKey": "k", "tlsInsecure": NSNumber(value: false)]) == nil, "non-string serverName → nil")
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

// ipString: NE requires an IP literal for tunnelRemoteAddress; hostnames must
// resolve to their dotted-decimal form, not pass through unresolved.
check(resolveServer("127.0.0.1", 443)?.ipString == "127.0.0.1", "ipString IP literal")
check(resolveServer("localhost", 8080)?.ipString == "127.0.0.1", "ipString from hostname")

// HybridSettings
let hy = HybridSettings(enabled: true, tcpMode: 0)
check(HybridSettings(providerConfiguration: hy.toProviderConfiguration()) == hy, "hybrid round-trip")
check(HybridSettings.disabled == HybridSettings(enabled: false, tcpMode: 2), "hybrid disabled default auto")
check(HybridSettings(providerConfiguration: nil) == nil, "hybrid nil dict -> nil")
let hyBad: [String: Any] = ["hybridEnabled": NSNumber(value: true), "hybridTcpMode": NSNumber(value: 9)]
check(HybridSettings(providerConfiguration: hyBad)!.tcpMode == 2, "out-of-range mode clamps to auto")
let hyBool: [String: Any] = ["hybridEnabled": NSNumber(value: 1), "hybridTcpMode": NSNumber(value: true)]
let hyParsed = HybridSettings(providerConfiguration: hyBool)!
check(hyParsed.enabled == false, "int-backed enabled rejected (isBool strict)")
check(hyParsed.tcpMode == 2, "bool-backed mode clamps to auto")

// ── TunnelSessionCoordinator (spec D6) ──────────────────────────────────
// Reason codes pinned here: -10 CLOSED / -6 PROTOCOL transient; -4 TLS /
// -5 AUTH / anything else terminal.
typealias TC = TunnelSessionCoordinator<Int>

func established() -> TC {
    var c = TC()
    _ = c.handle(.configReady(1))
    _ = c.handle(.settingsApplied(nil))
    return c
}
let settingsErr = NSError(domain: "t", code: 7)

// first start happy path
var c1 = TC()
check(c1.handle(.configReady(1)) == [.applySettings(1)], "start: configReady applies settings")
check(c1.handle(.settingsApplied(nil)) == [.tunActive, .resumeStart], "start: applied -> tunActive+resume")
check(c1.phase == .established, "start: phase established")
// second configReady while idle (reconnect) starts a fresh apply
check(c1.handle(.configReady(2)) == [.applySettings(2)], "reconnect configReady applies")
check(c1.handle(.settingsApplied(nil)) == [.tunActive], "established re-apply: tunActive only")
check(c1.phase == .established, "established stays established")

// close while starting fails the start, for transient and terminal reasons alike
var c2 = TC()
check(c2.handle(.closed(reason: -10)) == [.failStart(.core(-10))], "starting+CLOSED -> failStart")
check(c2.phase == .terminal, "starting close is terminal")
var c3 = TC()
check(c3.handle(.closed(reason: -4)) == [.failStart(.core(-4))], "starting+TLS -> failStart")

// established: transient reasons reassert, terminal reasons cancel
var c4 = established()
check(c4.handle(.closed(reason: -10)) == [.enterReasserting], "established+CLOSED reasserts")
check(c4.phase == .reasserting, "phase reasserting")
check(c4.handle(.closed(reason: -10)) == [], "reasserting+CLOSED again: no edge")
var c5 = established()
check(c5.handle(.closed(reason: -6)) == [.enterReasserting], "established+PROTOCOL reasserts")
for reason: Int32 in [-4, -5, -99] {
    var c = established()
    check(c.handle(.closed(reason: reason)) == [.cancelTunnel(.core(reason))],
          "established+\(reason) cancels")
    check(c.phase == .terminal, "established+\(reason) terminal")
}

// reasserting recovery: configReady + applied -> tunActive + exitReasserting
var c6 = established()
_ = c6.handle(.closed(reason: -10))
check(c6.handle(.configReady(2)) == [.applySettings(2)], "reasserting: configReady applies")
check(c6.handle(.settingsApplied(nil)) == [.tunActive, .exitReasserting], "recovery exits reasserting")
check(c6.phase == .established, "recovered to established")

// close during an in-flight apply marks it stale; its completion is inert
var c7 = established()
_ = c7.handle(.configReady(2))
check(c7.handle(.closed(reason: -10)) == [.enterReasserting], "close mid-apply reasserts")
check(c7.handle(.settingsApplied(nil)) == [], "stale apply completion is inert")
// same from reasserting (no enterReasserting edge)
var c8 = established()
_ = c8.handle(.closed(reason: -10))
_ = c8.handle(.configReady(2))
check(c8.handle(.closed(reason: -10)) == [], "reasserting close mid-apply: no edge")
check(c8.handle(.settingsApplied(nil)) == [], "stale apply completion inert (reasserting)")

// pending chain: B discarded by the second close, C applied from the stale completion
var c9 = established()
_ = c9.handle(.configReady(2))          // apply in flight
_ = c9.handle(.closed(reason: -10))     // stale
check(c9.handle(.configReady(3)) == [], "pending B queued silently")
_ = c9.handle(.closed(reason: -10))     // B discarded
check(c9.handle(.configReady(4)) == [], "pending C queued silently")
check(c9.handle(.settingsApplied(nil)) == [.applySettings(4)], "stale completion applies only C")
check(c9.handle(.settingsApplied(nil)) == [.tunActive, .exitReasserting], "C completion recovers")

// settingsApplied(error): fail start / cancel after; idle completions are inert
var c10 = TC()
_ = c10.handle(.configReady(1))
check(c10.handle(.settingsApplied(settingsErr)) == [.failStart(.settings(settingsErr))],
      "starting settings error fails start")
var c11 = established()
_ = c11.handle(.configReady(2))
check(c11.handle(.settingsApplied(settingsErr)) == [.cancelTunnel(.settings(settingsErr))],
      "established settings error cancels")
var c12 = established()
check(c12.handle(.settingsApplied(nil)) == [], "idle settingsApplied inert")
check(c12.handle(.settingsApplied(settingsErr)) == [], "idle settingsApplied(error) inert")

// startFailed
var c13 = TC()
check(c13.handle(.startFailed(code: -3)) == [.failStart(.local(-3))], "starting startFailed fails start")
var c14 = established()
check(c14.handle(.startFailed(code: -3)) == [.cancelTunnel(.local(-3))], "established startFailed cancels")

// stopRequested
var c15 = TC()
check(c15.handle(.stopRequested) == [.failStart(.cancelled)], "starting stop resolves the continuation")
check(c15.phase == .terminal, "stop is terminal")
var c16 = established()
check(c16.handle(.stopRequested) == [], "established stop: silent terminal")
check(c16.phase == .terminal, "established stop terminal")

// terminal absorbs everything
var c17 = TC()
_ = c17.handle(.stopRequested)
check(c17.handle(.configReady(9)) == [], "terminal: configReady inert")
check(c17.handle(.settingsApplied(nil)) == [], "terminal: settingsApplied inert")
check(c17.handle(.closed(reason: -10)) == [], "terminal: closed inert")
check(c17.handle(.startFailed(code: -3)) == [], "terminal: startFailed inert")
check(c17.handle(.stopRequested) == [], "terminal: stop inert")

// ── TeardownSequence (spec D8) ──────────────────────────────────────────
var tdOrder: [String] = []
var tdPathsDone: (() -> Void)?
TeardownSequence.run(
    detach: { tdOrder.append("detach") },
    disconnect: { tdOrder.append("disconnect") },
    resolveStart: { tdOrder.append("resolveStart") },
    stopPaths: { done in tdOrder.append("stopPaths"); tdPathsDone = done },
    destroy: { tdOrder.append("destroy") },
    complete: { tdOrder.append("complete") })
check(tdOrder == ["detach", "disconnect", "resolveStart", "stopPaths"],
      "teardown: destroy waits for the paths completion")
tdPathsDone?()
check(tdOrder == ["detach", "disconnect", "resolveStart", "stopPaths", "destroy", "complete"],
      "teardown: full order after paths completion")

// ── SystemTrust (spec D9): rejection paths only; acceptance of a real CA
// chain is the on-device gate G-t1 ──────────────────────────────────────
check(SystemTrust.evaluate(chain: [], hostname: "example.com") == false,
      "empty chain rejected")
check(SystemTrust.evaluate(chain: [Data([0x30, 0x00])], hostname: "example.com") == false,
      "broken DER rejected")
// Self-signed leaf: tests/certs/test.crt via #filePath (host-test cwd is the
// caller's, so relative paths are unusable).
let tdCertURL = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()                                   // ios/poc/Tests
    .appendingPathComponent("../../../tests/certs/test.crt").standardized
let tdPEM = try! String(contentsOf: tdCertURL, encoding: .utf8)
let tdB64 = tdPEM.split(separator: "\n").filter { !$0.hasPrefix("-----") }.joined()
let tdDER = Data(base64Encoded: tdB64)!
check(SystemTrust.evaluate(chain: [tdDER], hostname: "mqvpn-test") == false,
      "self-signed leaf rejected")

// ── Insecure defaults OFF (spec D10) ────────────────────────────────────
check(ServerSettings.emptyDraft.insecure == false, "emptyDraft defaults to Insecure OFF")

// ── EventLog: a transient stale CLOSED path must not fabricate churn ──────
// After a reconnect the core can briefly return two same-name paths (the live
// one + a stale CLOSED slot, since get_paths never shrinks n_paths). Keyed by
// interface name, that duplicate would fabricate en0 active<->closed churn.
func evSnap(_ paths: [(String, Int32)], state: Int32 = 4) -> TunnelSnapshot {
    TunnelSnapshot(timestamp: 0, clientState: state, connectedSince: nil, footprint: 0,
                   paths: paths.map { PathSnapshot(name: $0.0, status: $0.1, txBytes: 0, rxBytes: 0) })
}
func countStatus(_ log: EventLog) -> Int {
    log.events.filter { if case .pathStatus = $0.kind { return true } else { return false } }.count
}

let elReconnect = EventLog()
let t0 = Date()
elReconnect.ingest(evSnap([("en0", 1)]), now: t0)                 // baseline: active
elReconnect.ingest(evSnap([("en0", 1), ("en0", 4)]), now: t0)    // transient active + stale closed
elReconnect.ingest(evSnap([("en0", 1)]), now: t0)                // reaped back to single active
check(countStatus(elReconnect) == 0,
      "transient stale CLOSED duplicate must not fabricate path-status churn")

// A genuine live-status transition (active -> degraded) must still be logged.
let elReal = EventLog()
elReal.ingest(evSnap([("en0", 1)]), now: t0)
elReal.ingest(evSnap([("en0", 2)]), now: t0)
check(countStatus(elReal) == 1, "genuine active->degraded transition still logged")

// ── PathReadSource (the read-source chain) ─────────────────────────────────────────
// A loopback UDP socket, a fake hop that queues closures for the "tick
// thread" (this thread) and runs or refuses them on demand.
do {
    func udpSocket() -> (fd: Int32, addr: sockaddr_in) {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        check(fd >= 0, "socket()")
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK)
        var a = sockaddr_in()
        a.sin_family = sa_family_t(AF_INET)
        a.sin_addr.s_addr = CFSwapInt32HostToBig(INADDR_LOOPBACK)
        a.sin_port = 0
        var bound = a
        let rc = withUnsafePointer(to: &bound) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        check(rc == 0, "bind()")
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &bound) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        return (fd, bound)
    }
    func sendDatagrams(_ n: Int, from: Int32, to: sockaddr_in) {
        var dst = to
        var byte: UInt8 = 0x5a
        for _ in 0..<n {
            let rc = withUnsafePointer(to: &dst) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(from, &byte, 1, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
            }
            check(rc == 1, "sendto()")
        }
    }
    func drainAll(_ fd: Int32) -> Int {
        var n = 0
        var buf = [UInt8](repeating: 0, count: 64)
        while recv(fd, &buf, buf.count, 0) > 0 { n += 1 }
        return n
    }
    /// Wait until `cond` holds (polling; the sources run on their own queue).
    func waitFor(_ what: String, _ cond: () -> Bool) {
        for _ in 0..<200 { if cond() { return }; usleep(10_000) }
        check(false, "timeout waiting for \(what)")
    }
    let queue = DispatchQueue(label: "test.pathmon")
    let lock = NSLock()
    var pending: [() -> Void] = []          // hops not yet run ("tick thread" queue)
    var refuseNext = false
    var refused = 0
    let hop: (@escaping () -> Void) -> Bool = { c in
        lock.lock(); defer { lock.unlock() }
        if refuseNext { refuseNext = false; refused += 1; return false }
        pending.append(c); return true
    }
    func pendingCount() -> Int { lock.lock(); defer { lock.unlock() }; return pending.count }
    func runOneHop() {
        lock.lock()
        guard !pending.isEmpty else { lock.unlock(); check(false, "runOneHop: no pending hop"); return }
        let c = pending.removeFirst()
        lock.unlock()
        c()
    }

    // 1. One readable burst → ONE hop (the source is suspended meanwhile), the
    //    drain reads everything, and the resumed source does not re-fire.
    let (fd, addr) = udpSocket()
    let (peer, _) = udpSocket()
    var events: [String] = []
    var drained = 0
    let fence = DispatchGroup()
    var src: PathReadSource? = PathReadSource(
        fd: fd, queue: queue, fence: fence, hop: hop,
        drain: { drained += drainAll(fd); events.append("drain") },
        released: { events.append(fcntl(fd, F_GETFD) == -1 ? "released(fd closed)" : "released(fd open!)") })
    src!.resume()
    sendDatagrams(3, from: peer, to: addr)
    waitFor("first hop") { pendingCount() == 1 }
    usleep(100_000)
    check(pendingCount() == 1, "one readable burst = one hop (suspended source does not re-fire)")
    runOneHop()
    check(drained == 3, "the drain read the burst")
    usleep(100_000)
    check(pendingCount() == 0, "nothing left → no re-fire after the resume")

    // 2. Cancel while a drain hop is pending: the release hop queues behind
    //    it (the fake hop is FIFO), so the drain reads an open fd; then the
    //    release hop closes the fd → released (fd already closed) → fence.
    sendDatagrams(2, from: peer, to: addr)
    waitFor("second hop") { pendingCount() == 1 }
    src!.cancel()
    usleep(100_000)
    check(fcntl(fd, F_GETFD) != -1, "fd open while the drain hop is pending")
    check(!events.contains { $0.hasPrefix("released") }, "no release before the drain")
    runOneHop()                                  // drain → defer resume → cancel handler queues the release hop
    check(drained == 5, "the drain read the second burst through the open fd")
    waitFor("release hop") { pendingCount() == 1 }
    check(fcntl(fd, F_GETFD) != -1, "fd still open after the drain, before the release hop")
    runOneHop()                                  // close + released + fence.leave
    check(fcntl(fd, F_GETFD) == -1, "the release hop closed the fd")
    check(fence.wait(timeout: .now() + 2) == .success, "fence completes once the release was reported")
    check(events == ["drain", "drain", "released(fd closed)"], "order: drain, drain, released — got \(events)")
    src = nil                                    // released non-suspended: no crash

    // 3. A refused hop still resumes the source: the pending data makes it
    //    fire again, and that second hop is accepted; a later cancel completes.
    let (fd2, addr2) = udpSocket()
    var drained2 = 0
    var released2 = 0
    let fence2 = DispatchGroup()
    var src2: PathReadSource? = PathReadSource(
        fd: fd2, queue: queue, fence: fence2, hop: hop,
        drain: { drained2 += drainAll(fd2) },
        released: { released2 += 1 })
    lock.lock(); refuseNext = true; lock.unlock()
    src2!.resume()
    sendDatagrams(1, from: peer, to: addr2)
    waitFor("re-fire after the refused hop") { pendingCount() == 1 }
    check(refused == 1, "the first hop was refused")
    runOneHop()
    check(drained2 == 1, "the accepted second hop drained")
    src2!.cancel()
    waitFor("release hop 2") { pendingCount() == 1 }
    runOneHop()
    check(fence2.wait(timeout: .now() + 2) == .success && released2 == 1, "cancel completes after a refused hop")
    src2 = nil
    close(peer)
}

if failures == 0 { print("host tests: ALL PASS") } else { print("host tests: \(failures) FAILURES"); exit(1) }
