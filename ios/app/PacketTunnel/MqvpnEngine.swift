// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation
import os.log

let log = Logger(subsystem: "org.mqvpn.app", category: "engine")

/// Global library log sink (mqvpn_log_set_sink, declared in the bridging
/// header): every global libmqvpn line — the bind's socket-buffer and
/// send-error lines, the hybrid lwIP glue — reaches os_log instead of the
/// extension's stderr, which nobody sees (per-client lines, the path state
/// machine's included, arrive through cbs.log, which is this same function).
/// Installed once per process (the first start(), via
/// MqvpnEngine.logSinkInstalled); runs on whichever thread logged (os_log is
/// thread-safe).
private let mqvpnLogSink: mqvpn_log_fn = { level, msg, _ in
    // msg is not documented NULL-safe by the header; the JNI driver
    // substitutes "" too.
    let text = msg.map { String(cString: $0) } ?? ""
    switch level {
    case MQVPN_LOG_ERROR: log.error("[lib] \(text, privacy: .public)")
    case MQVPN_LOG_WARN: log.warning("[lib] \(text, privacy: .public)")
    default: log.notice("[lib] \(text, privacy: .public)")
    }
}

/// C trampoline for mqvpn_config_set_cert_verifier (spec D9). Rebuilds the
/// DER chain and asks SystemTrust; ctx is unused (SystemTrust is stateless).
/// Runs on the tick thread inside the handshake — SystemTrust never touches
/// the network, and nothing here re-enters libmqvpn.
private let mqvpnCertVerify: mqvpn_cert_verify_fn = { certs, certLen, nCerts, hostname, _ in
    guard let certs, let certLen, let hostname, nCerts > 0 else { return -1 }
    var chain: [Data] = []
    for i in 0..<nCerts {
        guard let p = certs[i] else { return -1 }
        chain.append(Data(bytes: p, count: certLen[i]))
    }
    return SystemTrust.evaluate(chain: chain, hostname: String(cString: hostname)) ? 0 : -1
}

/// Owns the libmqvpn client and the dedicated tick thread.
///
/// THREADING CONTRACT: every libmqvpn call happens on `tickThread`. The core
/// asserts pthread identity on entry (first call latches pthread_self, later
/// calls pthread_equal-check it), so a GCD serial queue is NOT sufficient —
/// it guarantees mutual exclusion, not thread affinity. All external events
/// hop in via `perform{}`.
final class MqvpnEngine: NSObject {
    private var client: OpaquePointer?          // mqvpn_client_t*
    private var serverAddr: ResolvedServerAddress!
    private var startFailed = false
    private var connected = false
    private var tickThread: Thread!
    private let runLoopReady = DispatchSemaphore(value: 0)
    private var runLoop: RunLoop!
    private var tickTimer: Timer?
    private(set) var reorderConfigured = false
    private(set) var hybridConfigured = false
    private var reorderStatsUnavailable = false
    /// Latched by tunnel_config_ready (tick thread); read by SnapshotCache
    /// on the same thread. Overwritten on every (re)connect.
    private(set) var tunnelInfo: TunnelInfoSnapshot?
    private var requestedScheduler: Int32?
    /// Once-token for the global log sink (src/log.h: set once per process,
    /// before any client exists). A static let is initialised lazily and
    /// thread-safely, exactly once: later sessions in the same extension
    /// process reuse the installed sink.
    private static let logSinkInstalled: Void = { mqvpn_log_set_sink(mqvpnLogSink, nil) }()
    /// Bind ctx per path handle (tick-thread confined). Library-owned once
    /// add_path succeeded; the pointer is read for stats and drains only.
    private var bindCtx: [mqvpn_path_handle_t: UnsafeMutableRawPointer] = [:]

    // Injected by PacketTunnelProvider:
    var onTunOutput: ((Data) -> Void)?          // -> packetFlow.writePackets
    var onTunnelConfig: ((mqvpn_tunnel_info_t) -> Void)?
    var onTunnelClosed: ((Int32) -> Void)?
    var onStartFailed: ((Int32) -> Void)?   // engine-local failures (client_new/connect)

    /// Blocks until the client exists on the tick thread — callers may start
    /// PathBinder immediately after return without ordering assumptions.
    func start(server: ServerSettings, reorder: ReorderSettings = .disabled,
               hybrid: HybridSettings = .disabled,
               split: SplitSettings = SplitSettings(providerConfiguration: nil),
               protection: ProtectionSettings = ProtectionSettings(),
               serverAddr: ResolvedServerAddress) {
        self.serverAddr = serverAddr
        // Provenance-independent ABI guard: the linked libmqvpn.a and this
        // extension must share the mqvpn_reorder_stats_t layout. On mismatch,
        // disable the monitor (never read the struct); a debug build asserts.
        if mqvpn_ext_reorder_layout_id() != mqvpn_reorder_stats_layout_id() {
            reorderStatsUnavailable = true
            log.error("[reorder] stats layout mismatch — monitor disabled")
            assert(false, "reorder stats ABI layout mismatch (stale libmqvpn.a?)")
        }
        _ = MqvpnEngine.logSinkInstalled
        tickThread = Thread { [weak self] in
            guard let self else { return }
            self.runLoop = RunLoop.current
            // A run loop with no sources exits immediately; NSMachPort keeps
            // it alive so perform{} hops and timers are serviced.
            self.runLoop.add(NSMachPort(), forMode: .default)
            self.runLoopReady.signal()
            while !self.tickThread.isCancelled {
                self.runLoop.run(mode: .default, before: .distantFuture)
            }
        }
        tickThread.name = "mqvpn.tick"
        tickThread.start()
        runLoopReady.wait()
        let ready = DispatchSemaphore(value: 0)
        perform {
            self.setupClient(server, reorder: reorder, hybrid: hybrid,
                             split: split, protection: protection)
            ready.signal()
        }
        ready.wait()
    }

    /// Hop an arbitrary closure onto the tick thread (the ONLY entry point).
    /// After destroy() the thread is gone — late hops (monitor updates) are
    /// dropped and the caller is told: PathReadSource must still balance a
    /// suspend when its hop is refused. Closures run one at a time on the
    /// tick thread via performSelector(onThread:), whose submission order is
    /// FIFO in practice but not documented by Apple. Path safety does not
    /// rely on it (`drain` is a no-op once the path's release ran, or the
    /// handle is poisoned). One residual does: destroy() ends the thread, so
    /// a drain hop still queued behind the teardown completion would never
    /// resume its suspended source. FIFO rules that out — each path's drain
    /// hop is submitted before its release hop, and the completion only
    /// after every release ran.
    @discardableResult
    func perform(_ body: @escaping () -> Void) -> Bool {
        guard let t = tickThread, !t.isFinished, !t.isCancelled else { return false }
        let wrapped = BlockOperation(block: body)
        wrapped.perform(#selector(Operation.start), on: t,
                        with: nil, waitUntilDone: false)
        return true
    }

    /// Stops the session (tick thread) but keeps `client` alive:
    /// binder.stop() runs after this, and its release hops must still reach
    /// the library (on_platform_path_released); disconnect's synchronous
    /// CONNECTION_CLOSE goes out through the paths' transports, still
    /// attached (sockets open) at this point. Reconnects are suppressed from
    /// here on.
    func disconnect() {
        tickTimer?.invalidate()
        if let c = client { mqvpn_client_disconnect(c) }
    }

    /// Final teardown (tick thread). client goes nil first so any
    /// already-queued hop on this run-loop pass sees the guard, not a freed
    /// pointer. Every path was released before this (binder.stop's fence);
    /// a ctx still in the dictionary is one whose release the library
    /// refused — its counters are read now (the pointer dangles after the
    /// destroy, which finalises it); a poisoned ctx is neither read nor
    /// ever freed (deliberately leaked: nobody can prove who owns it). The
    /// dictionary is then cleared without touching any ctx again.
    func destroy() {
        if let c = client {
            for (h, ctx) in bindCtx where !poisoned.contains(h) { logRxStats(h, ctx, tag: "at destroy") }
            client = nil
            mqvpn_client_destroy(c)
            bindCtx.removeAll()
            poisoned.removeAll()
        }
        tickThread.cancel()
    }

    /// Handles whose release the library did not recognise (path-ledger
    /// corruption): never dereferenced or reused again; cleared by destroy.
    private var poisoned: Set<mqvpn_path_handle_t> = []

    private func logRxStats(_ h: mqvpn_path_handle_t, _ ctx: UnsafeMutableRawPointer, tag: String) {
        var st = mqvpn_bind_posix_stats_t()
        st.struct_size = UInt32(MemoryLayout<mqvpn_bind_posix_stats_t>.size)
        mqvpn_bind_posix_path_get_stats(ctx, &st)
        log.notice("[path] handle=\(h) \(tag, privacy: .public): rx receives=\(st.rx_receives) datagrams=\(st.rx_datagrams)")
    }

    private func setupClient(_ server: ServerSettings, reorder: ReorderSettings, hybrid: HybridSettings,
                             split: SplitSettings, protection: ProtectionSettings) {
        let cfg = mqvpn_config_new()
        mqvpn_config_set_server(cfg, server.host, Int32(server.port))
        // "" = unset: the core then uses server.host for SNI / cert verify,
        // matching the desktop client.conf ServerName default.
        if !server.serverName.isEmpty {
            mqvpn_config_set_tls_server_name(cfg, server.serverName)
        }
        mqvpn_config_set_clock(cfg, mqvpn_ios_clock_us, nil)
        // Always installed; insecure precedence is the core's (D3): with
        // insecure=1 the core never consults the verifier and logs one WARN
        // at client creation — expected on self-signed test-server runs.
        mqvpn_config_set_cert_verifier(cfg, mqvpnCertVerify, nil)
        if !server.authKey.isEmpty { mqvpn_config_set_auth_key(cfg, server.authKey) }
        if server.insecure { mqvpn_config_set_insecure(cfg, 1) }
        // Add rules FIRST, enable ONLY if >=1 landed. Never hand the core
        // mode-ON-with-zero-rules (it reorders ALL UDP under a global default,
        // ignoring the profile).
        let plan = reorder.planReorder()
        var results: [Bool] = []
        for r in plan.rules {
            let prof: mqvpn_reorder_profile_t =
                (r.profile == ReorderSettings.profileFiberLTE) ? MQVPN_RPROF_FIBER_LTE
                                                               : MQVPN_RPROF_CELLULAR_BOND
            let rc = mqvpn_config_add_reorder_rule(cfg, UInt8(r.proto), UInt16(r.port), prof)
            results.append(rc == 0)
            if rc != 0 { log.error("[reorder] add rule port=\(r.port) rc=\(rc)") }
        }
        let decision = ReorderSettings.reorderEnableDecision(ruleResults: results)
        if decision.enable {
            _ = mqvpn_config_set_reorder_enabled(cfg, MQVPN_REORDER_ON)
            reorderConfigured = true
        }
        log.notice("[reorder] applied rules=\(decision.added)/\(plan.rules.count) configured=\(self.reorderConfigured)")
        // Hybrid: mode/limits/rate first, enable LAST only if all landed
        // (fail-closed — set_hybrid_enabled has no rollback for later
        // failures; mirrors the reorder rules-first pattern above).
        var hybridOK = false
        if hybrid.enabled {
            let iosTcpMaxFlows: UInt32 = 64      // couples with iOS-profile MEMP_NUM_TCP_PCB=128
            let iosIdleTimeoutSec: UInt32 = 300  // library default, stated explicitly
            let iosRecvRateLimit: UInt64 = 125_000_000  // 1 Gbps ceiling; QUIC window = rate x srtt
            let rcs = [
                mqvpn_config_set_hybrid_tcp_mode(cfg, Int32(hybrid.tcpMode)),
                mqvpn_config_set_hybrid_limits(cfg, iosTcpMaxFlows, iosIdleTimeoutSec),
                mqvpn_config_set_recv_rate_limit(cfg, iosRecvRateLimit),
            ]
            if rcs.allSatisfy({ $0 == 0 }) {
                hybridOK = (mqvpn_config_set_hybrid_enabled(cfg, 1) == 0)
            }
            if !hybridOK {
                // Array interpolation is os.Logger-private by default — force
                // public or the one log needed on failure reads "<private>".
                log.error("[hybrid] setter failed rcs=\(rcs.map(String.init).joined(separator: ","), privacy: .public) — starting with hybrid OFF")
            }
        }
        hybridConfigured = hybridOK
        log.notice("[hybrid] applied enabled=\(hybrid.enabled) mode=\(hybrid.tcpMode) configured=\(hybridOK)")
        // Split: a nil scheduler is the legacy config (no scheduler / cc call,
        // library defaults). Redundant fails closed on a malformed port list.
        requestedScheduler = split.scheduler?.rawValue
        var redundantActive = false
        if split.redundantEnabled {
            if split.redundantPortsMalformed {
                log.warning("[split] redundant ports invalid — redundant disabled")
            } else {
                let rc = split.redundantPorts.withUnsafeBufferPointer {
                    mqvpn_config_set_redundant(cfg, 1, $0.baseAddress, $0.count)
                }
                redundantActive = (rc == 0)
                if rc != 0 { log.error("[split] set_redundant rc=\(rc)") }
            }
        }
        if let sched = split.scheduler {
            mqvpn_config_set_scheduler(cfg, mqvpn_scheduler_t(rawValue: UInt32(sched.rawValue)))
            mqvpn_config_set_request_server_scheduler(cfg, 1)
        }
        if split.scheduler != nil || redundantActive {
            mqvpn_config_set_cc(cfg, redundantActive ? MQVPN_CC_BBR : MQVPN_CC_BBR2)
        }
        // Paired with the coordinator's reconnectEnabled: the core must never
        // arm a reconnect the coordinator would cancel.
        mqvpn_config_set_reconnect(cfg, protection.autoReconnect ? 1 : 0, 5)
        log.notice("[split] applied scheduler=\(split.scheduler.map { String($0.rawValue) } ?? "legacy", privacy: .public) redundant=\(redundantActive) reconnect=\(protection.autoReconnect)")
        var cbs = mqvpn_client_callbacks_t()
        cbs.abi_version = UInt32(MQVPN_CALLBACKS_ABI_VERSION)
        cbs.struct_size = UInt32(MemoryLayout<mqvpn_client_callbacks_t>.size)
        cbs.tun_output = { pkt, len, ctx in
            let engine = Unmanaged<MqvpnEngine>.fromOpaque(ctx!).takeUnretainedValue()
            engine.onTunOutput?(Data(bytes: pkt!, count: len))
        }
        cbs.tunnel_config_ready = { info, ctx in
            let engine = Unmanaged<MqvpnEngine>.fromOpaque(ctx!).takeUnretainedValue()
            engine.latchTunnelInfo(info!.pointee)
            engine.onTunnelConfig?(info!.pointee)
        }
        cbs.tunnel_closed = { reason, ctx in
            let engine = Unmanaged<MqvpnEngine>.fromOpaque(ctx!).takeUnretainedValue()
            engine.onTunnelClosed?(reason.rawValue)
        }
        // Per-client lines take the global sink's level mapping (error /
        // warning / notice) and its NULL-safe msg handling.
        cbs.log = mqvpnLogSink
        let ctx = Unmanaged.passUnretained(self).toOpaque()
        client = mqvpn_client_new(cfg, &cbs, ctx)
        mqvpn_config_free(cfg)
        guard client != nil else {
            log.error("[engine] mqvpn_client_new failed")
            startFailed = true
            onStartFailed?(Int32(MQVPN_ERR_ENGINE.rawValue))
            return
        }
        // NOTE: no connect here. The core sends handshake packets through
        // the first path's transport, and xquic needs the resolved peer
        // address set before connect — so connection start is deferred until
        // the first path is registered (connectIfNeeded, same ordering as
        // the Android runtime: addPath -> setServerAddr -> connect).
        scheduleTick(afterMs: 0)
    }

    /// v6 and server-scheduler fields were appended later: read them only when
    /// the library's struct_size covers them.
    private static func covers<T>(_ info: mqvpn_tunnel_info_t,
                                  _ kp: KeyPath<mqvpn_tunnel_info_t, T>) -> Bool {
        guard let off = MemoryLayout<mqvpn_tunnel_info_t>.offset(of: kp) else { return false }
        return Int(info.struct_size) >= off + MemoryLayout<T>.size
    }

    /// The assigned IPv6 address and TUN prefix; nil when none was assigned or
    /// the library's struct predates the fields. The one reader of the v6 fields.
    static func assignedV6(_ info: mqvpn_tunnel_info_t) -> (ip: String, prefix: UInt8)? {
        guard covers(info, \.has_v6), info.has_v6 != 0 else { return nil }
        let ip = ip6String(info.assigned_ip6)
        return ip.isEmpty ? nil : (ip, info.assigned_prefix6)
    }

    /// Tick thread (tunnel_config_ready).
    private func latchTunnelInfo(_ info: mqvpn_tunnel_info_t) {
        let v6 = Self.assignedV6(info)
        let hasSched = Self.covers(info, \.server_scheduler) && info.has_server_scheduler != 0
        tunnelInfo = TunnelInfoSnapshot(
            assignedIp: Self.ip4String(info.assigned_ip), assignedIp6: v6?.ip,
            mtu: Int32(info.mtu),
            serverScheduler: hasSched ? Int32(info.server_scheduler) : nil,
            requestedScheduler: requestedScheduler)
    }

    static func ip4String(_ b: (UInt8, UInt8, UInt8, UInt8)) -> String {
        "\(b.0).\(b.1).\(b.2).\(b.3)"
    }

    static func ip6String<T>(_ addr: T) -> String {
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        return withUnsafeBytes(of: addr) { raw in
            inet_ntop(AF_INET6, raw.baseAddress, &buf, socklen_t(buf.count)) == nil
                ? "" : String(cString: buf)
        }
    }

    /// Called by PathBinder after the FIRST successful addPath
    /// (tick thread). Sets the resolved server address and connects, once.
    func connectIfNeeded() {
        guard !connected, !startFailed, let c = client else { return }
        var sa = serverAddr.storage
        let rc = withUnsafePointer(to: &sa) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                mqvpn_client_set_server_addr(c, $0, serverAddr.len)
            }
        }
        func fail(_ what: String) {
            log.error("\(what)"); startFailed = true
            onStartFailed?(Int32(MQVPN_ERR_ENGINE.rawValue))
        }
        if rc != 0 { fail("set_server_addr rc=\(rc)"); return }
        if mqvpn_client_connect(c) != 0 { fail("connect failed"); return }
        connected = true
        scheduleTick(afterMs: 0)
    }

    /// Called by the provider after NE tunnel settings are applied (hop to
    /// tick thread first). The core gates TUN delivery on tun_active and
    /// this call also drives TUNNEL_READY -> ESTABLISHED; the fd argument
    /// is unused by the core (platform owns all I/O), so pass -1.
    func tunActive() {
        guard let c = client else { return }
        mqvpn_client_set_tun_active(c, 1, -1)
    }

    /// get_interest-driven tick loop, mirroring the Android JNI driver.
    private func scheduleTick(afterMs: Int32) {
        let delay = max(0, Int(afterMs))
        tickTimer?.invalidate()
        let t = Timer(timeInterval: Double(delay) / 1000.0, repeats: false) { [weak self] _ in
            guard let self, let c = self.client else { return }
            mqvpn_client_tick(c)
            var interest = mqvpn_interest_t()
            interest.struct_size = UInt32(MemoryLayout<mqvpn_interest_t>.size)
            mqvpn_client_get_interest(c, &interest)
            self.scheduleTick(afterMs: interest.next_timer_ms)
        }
        runLoop.add(t, forMode: .default)
        tickTimer = t
    }

    // All methods below assume the caller already hopped to the tick thread.
    func feedTunPacket(_ data: Data) {
        guard let c = client else { return }
        _ = data.withUnsafeBytes { buf in
            mqvpn_client_on_tun_packet(c, buf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                       data.count)
        }
        scheduleTick(afterMs: 0)   // input may arm new engine work; tick soon
    }
    /// Registers a path: wraps the (borrowed) fd in the bundled POSIX bind
    /// and hands ops + ctx to the library. Returns the handle and the
    /// synchronous activation outcome — a valid handle with a failed outcome
    /// is what the failover-flap gate observes; the path is kept either way
    /// (the ctx is library-owned from here). On a refused registration the
    /// ctx is freed here and the caller still owns the fd.
    func addPath(_ fd: Int32, desc: inout mqvpn_path_desc_t)
        -> (handle: mqvpn_path_handle_t, outcome: mqvpn_add_path_outcome_t) {
        var outcome = MQVPN_ADD_PATH_OK
        guard let c = client else { return (-1, outcome) }  // post-shutdown hop
        var opts = mqvpn_bind_posix_opts_t()
        opts.struct_size = UInt32(MemoryLayout<mqvpn_bind_posix_opts_t>.size)
        // 7 MiB request, as the core used to make (same as the macOS
        // platform); ENOBUFS keeps PathBinder's pre-set
        opts.socket_buf_bytes = 0
        withUnsafeMutableBytes(of: &opts.tag) { dst in
            withUnsafeBytes(of: &desc.iface) { src in dst.copyBytes(from: src.prefix(dst.count - 1)) }
        }
        var ctx: UnsafeMutableRawPointer?
        let brc = mqvpn_bind_posix_path_new(fd, &opts, &ctx)
        guard brc == 0, let bctx = ctx else {
            log.error("[path] bind_posix_path_new rc=\(brc)")
            return (-1, outcome)
        }
        let h = mqvpn_client_add_path(c, &desc, mqvpn_bind_posix_path_ops(), bctx, &outcome)
        if h < 0 {
            mqvpn_bind_posix_path_free(bctx)   // add failed: still ours
            return (h, outcome)
        }
        bindCtx[h] = bctx
        return (h, outcome)
    }
    func removePath(_ handle: mqvpn_path_handle_t) {
        guard let c = client else { return }
        mqvpn_client_remove_path(c, handle)
    }
    /// Reads the path's socket until it would block, delivering into the
    /// library (tick thread). A hard error is ignored: NWPathMonitor and
    /// reconcile own drop detection.
    func drain(_ handle: mqvpn_path_handle_t) {
        guard let c = client, let ctx = bindCtx[handle], !poisoned.contains(handle) else { return }
        _ = mqvpn_bind_posix_path_drain(ctx, c, handle, 64)
        scheduleTick(afterMs: 0)   // input may arm new engine work; tick soon
    }
    /// The platform closed the path's socket: report it. OK → the library
    /// finalised the ctx, forget it. INVALID_STATE (no remove preceded) → it
    /// stays library-owned until destroy. INVALID_ARG → the library does not
    /// know a handle we hold: ledger corruption; the entry is poisoned and
    /// the provider is asked to stop the tunnel.
    func pathReleased(_ handle: mqvpn_path_handle_t) {
        guard let c = client, let ctx = bindCtx[handle], !poisoned.contains(handle) else { return }
        logRxStats(handle, ctx, tag: "released")   // read BEFORE the call: the library finalises the ctx inside
        let rc = mqvpn_client_on_platform_path_released(c, handle)
        switch rc {
        case 0:
            bindCtx.removeValue(forKey: handle)
        case Int32(MQVPN_ERR_INVALID_ARG.rawValue):
            log.error("[path] handle=\(handle) unknown to the library: poisoned, stopping the tunnel")
            assertionFailure("path ledger corruption")
            poisoned.insert(handle)
            onLedgerCorruption?()
        default:
            // Unreachable: PathBinder removes before it cancels, so the slot
            // is CLOSED_DROPPED here. Were it reached, the ctx would stay
            // library-owned on an already-closed fd until destroy.
            log.warning("[path] handle=\(handle) path_released rc=\(rc); transport stays library-owned")
        }
    }
    /// Injected by PacketTunnelProvider: ends the session on ledger corruption.
    var onLedgerCorruption: (() -> Void)?

    // Snapshot accessors for GateMetrics (tick thread only).
    func state() -> mqvpn_client_state_t {
        guard let c = client else { return MQVPN_STATE_CLOSED }
        return mqvpn_client_get_state(c)
    }
    func paths() -> [mqvpn_path_info_t] {
        guard let c = client else { return [] }
        var out = [mqvpn_path_info_t](repeating: mqvpn_path_info_t(),
                                      count: Int(MQVPN_MAX_PATHS))
        var n: Int32 = 0
        // &out is Swift's inout-array-to-pointer bridging (valid for the
        // duration of the call) — matches the C signature exactly.
        mqvpn_client_get_paths(c, &out, Int32(out.count), &n)
        return Array(out.prefix(Int(n)))
    }

    /// Tick-thread only. nil when the client is gone or the call fails.
    func stats() -> StatsSnapshot? {
        guard let c = client else { return nil }
        var st = mqvpn_stats_t()
        st.struct_size = UInt32(MemoryLayout<mqvpn_stats_t>.size)
        guard mqvpn_client_get_stats(c, &st) == 0 else { return nil }
        return StatsSnapshot(bytesTx: st.bytes_tx, bytesRx: st.bytes_rx,
                             dgramSent: st.dgram_sent, dgramLost: st.dgram_lost,
                             srttMs: Double(st.srtt_ms))
    }

    /// Tick-thread only. nil when the ABI layout check failed (never misread)
    /// or the client is gone; else the current counters (get_reorder_stats
    /// always succeeds, zero-filled if RX absent).
    func reorderStats() -> ReorderStatsSnapshot? {
        guard !reorderStatsUnavailable, let c = client else { return nil }
        var st = mqvpn_reorder_stats_t()
        guard mqvpn_client_get_reorder_stats(c, &st) == 0 else { return nil }
        return ReorderStatsSnapshot(
            delivered: st.delivered_count, gapCount: st.gap_count,
            gapFilled: st.gap_filled_count, gapTimeout: st.gap_timeout_count,
            ackDemote: st.ack_demote_count,
            residenceBuckets: (0..<Int32(MQVPN_REORDER_LAT_BUCKETS)).map {
                mqvpn_shim_reorder_bucket(&st, $0)
            })
    }
}
