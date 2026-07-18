// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation
import os.log

let log = Logger(subsystem: "mqvpn.poc", category: "engine")

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

    // Injected by PacketTunnelProvider:
    var onTunOutput: ((Data) -> Void)?          // -> packetFlow.writePackets
    var onTunnelConfig: ((mqvpn_tunnel_info_t) -> Void)?
    var onTunnelClosed: ((Int32) -> Void)?

    /// Blocks until the client exists on the tick thread — callers may start
    /// PathBinder immediately after return without ordering assumptions.
    func start(server: ServerSettings, reorder: ReorderSettings = .disabled,
               hybrid: HybridSettings = .disabled, serverAddr: ResolvedServerAddress) {
        self.serverAddr = serverAddr
        // Provenance-independent ABI guard: the linked libmqvpn.a and this
        // extension must share the mqvpn_reorder_stats_t layout. On mismatch,
        // disable the monitor (never read the struct); a debug build asserts.
        if mqvpn_ext_reorder_layout_id() != mqvpn_reorder_stats_layout_id() {
            reorderStatsUnavailable = true
            log.error("[reorder] stats layout mismatch — monitor disabled")
            assert(false, "reorder stats ABI layout mismatch (stale libmqvpn.a?)")
        }
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
        perform { self.setupClient(server, reorder: reorder, hybrid: hybrid); ready.signal() }
        ready.wait()
    }

    /// Hop an arbitrary closure onto the tick thread (the ONLY entry point).
    /// After shutdown() the thread is gone — late hops (source cancel
    /// handlers, monitor updates) are silently dropped.
    func perform(_ body: @escaping () -> Void) {
        guard let t = tickThread, !t.isFinished, !t.isCancelled else { return }
        let wrapped = BlockOperation(block: body)
        wrapped.perform(#selector(Operation.start), on: t,
                        with: nil, waitUntilDone: false)
    }

    /// Tears the client down (tick thread). client goes nil first so any
    /// already-queued hop on this run-loop pass sees the guard, not a freed
    /// pointer.
    func shutdown() {
        tickTimer?.invalidate()
        if let c = client {
            client = nil
            mqvpn_client_disconnect(c)
            mqvpn_client_destroy(c)
        }
        tickThread.cancel()
    }

    private func setupClient(_ server: ServerSettings, reorder: ReorderSettings, hybrid: HybridSettings) {
        let cfg = mqvpn_config_new()
        mqvpn_config_set_server(cfg, server.host, Int32(server.port))
        mqvpn_config_set_clock(cfg, mqvpn_ios_clock_us, nil)
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
            let iosTcpMaxFlows: UInt32 = 64      // couples with mobile-profile MEMP_NUM_TCP_PCB=128
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
        var cbs = mqvpn_client_callbacks_t()
        cbs.abi_version = UInt32(MQVPN_CALLBACKS_ABI_VERSION)
        cbs.struct_size = UInt32(MemoryLayout<mqvpn_client_callbacks_t>.size)
        cbs.tun_output = { pkt, len, ctx in
            let engine = Unmanaged<MqvpnEngine>.fromOpaque(ctx!).takeUnretainedValue()
            engine.onTunOutput?(Data(bytes: pkt!, count: len))
        }
        cbs.tunnel_config_ready = { info, ctx in
            let engine = Unmanaged<MqvpnEngine>.fromOpaque(ctx!).takeUnretainedValue()
            engine.onTunnelConfig?(info!.pointee)
        }
        cbs.send_packet = nil                    // fd-path mode: core sends via sendto(fd)
        cbs.tunnel_closed = { reason, ctx in
            let engine = Unmanaged<MqvpnEngine>.fromOpaque(ctx!).takeUnretainedValue()
            engine.onTunnelClosed?(reason.rawValue)
        }
        cbs.log = { level, msg, _ in
            // msg is not documented NULL-safe by the header, but the JNI
            // reference driver defensively substitutes "" — mirror that here
            // rather than force-unwrapping into a crash.
            let text = msg.map { String(cString: $0) } ?? ""
            log.notice("[lib] \(text, privacy: .public)")
        }
        let ctx = Unmanaged.passUnretained(self).toOpaque()
        client = mqvpn_client_new(cfg, &cbs, ctx)
        mqvpn_config_free(cfg)
        guard client != nil else {
            log.error("[engine] mqvpn_client_new failed")
            startFailed = true
            onTunnelClosed?(Int32(MQVPN_ERR_ENGINE.rawValue))
            return
        }
        // NOTE: no connect here. The core sends handshake packets via
        // sendto() on path fds, and xquic needs the resolved peer address
        // set before connect — so connection start is deferred until the
        // first path fd is registered (connectIfNeeded, same ordering as
        // the Android runtime: addPathFd -> setServerAddr -> connect).
        scheduleTick(afterMs: 0)
    }

    /// Called by PathBinder after the FIRST successful add_path_fd
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
            onTunnelClosed?(Int32(MQVPN_ERR_ENGINE.rawValue))
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
    /// Registers a path fd. Uses the _with_outcome variant: the legacy
    /// add_path_fd can return a valid handle while a synchronous activation
    /// failure is swallowed — the outcome is what the failover-flap gate
    /// needs to observe.
    func addPathFd(_ fd: Int32, desc: inout mqvpn_path_desc_t)
        -> (handle: mqvpn_path_handle_t, outcome: mqvpn_add_path_outcome_t) {
        var outcome = MQVPN_ADD_PATH_OK
        guard let c = client else { return (-1, outcome) }  // post-shutdown hop
        let h = mqvpn_client_add_path_fd_with_outcome(c, fd, &desc, &outcome)
        return (h, outcome)
    }
    func removePath(_ handle: mqvpn_path_handle_t) {
        guard let c = client else { return }
        mqvpn_client_remove_path(c, handle)
    }
    func fdClosed(_ handle: mqvpn_path_handle_t) {
        guard let c = client else { return }
        mqvpn_client_on_platform_fd_closed(c, handle)
    }
    func socketRecv(_ handle: mqvpn_path_handle_t, _ data: Data,
                    _ peer: UnsafePointer<sockaddr>, _ peerLen: socklen_t) {
        guard let c = client else { return }
        _ = data.withUnsafeBytes { buf in
            mqvpn_client_on_socket_recv(c, handle, buf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                        data.count, peer, peerLen)
        }
        scheduleTick(afterMs: 0)
    }

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

    /// Tick-thread only. nil when the ABI layout check failed (never misread)
    /// or the client is gone; else the current counters (get_reorder_stats
    /// always succeeds, zero-filled if RX absent).
    func reorderStats() -> ReorderStatsSnapshot? {
        guard !reorderStatsUnavailable, let c = client else { return nil }
        var st = mqvpn_reorder_stats_t()
        guard mqvpn_client_get_reorder_stats(c, &st) == 0 else { return nil }
        let p50 = mqvpn_reorder_latency_buffered_percentile(&st, 0.50)
        let p99 = mqvpn_reorder_latency_buffered_percentile(&st, 0.99)
        return ReorderStatsSnapshot(
            delivered: st.delivered_count, gapCount: st.gap_count,
            gapFilled: st.gap_filled_count, gapTimeout: st.gap_timeout_count,
            ackDemote: st.ack_demote_count, bufferedP50Ms: p50, bufferedP99Ms: p99)
    }
}
