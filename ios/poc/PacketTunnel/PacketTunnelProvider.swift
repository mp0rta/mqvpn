// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import NetworkExtension

class PacketTunnelProvider: NEPacketTunnelProvider {
    private var engine: MqvpnEngine!
    private var binder: PathBinder!
    private var metrics: GateMetrics!

    override func startTunnel(options: [String: NSObject]?) async throws {
        let config = try PoCConfig.fromBundle()
        engine = MqvpnEngine()
        binder = PathBinder(engine: engine)
        metrics = GateMetrics(engine: engine, binder: binder)

        engine.onTunOutput = { [weak self] data in
            // NEPacketTunnelFlow requires a protocol family per packet; the
            // library hands us raw IP bytes, so derive it from the version
            // nibble.
            let proto: NSNumber = (data.first ?? 0) >> 4 == 6 ? NSNumber(value: AF_INET6)
                                                              : NSNumber(value: AF_INET)
            self?.packetFlow.writePackets([data], withProtocols: [proto])
        }
        return try await withCheckedThrowingContinuation { cont in
            // Two separate latches, both touched ONLY on the tick thread
            // (the settings completion hops back before touching them):
            //   configHandled — dedupes tunnel_config_ready refires so a
            //     second settings apply is never issued;
            //   startResolved — resume-once for the checked continuation.
            // Conflating them would let a tunnel_closed that arrives while
            // the settings apply is still in flight be treated as a
            // post-establishment close — reporting a successful start for a
            // dead session.
            var configHandled = false
            var startResolved = false
            engine.onTunnelConfig = { [weak self] info in
                // !startResolved: a late config-ready after a close must not
                // apply NE settings to a dead session.
                guard let self, !configHandled, !startResolved else { return }
                configHandled = true
                let settings = Self.makeSettings(from: info, server: config.serverHost)
                self.setTunnelNetworkSettings(settings) { err in
                    self.engine.perform {   // hop: latch access stays single-threaded
                        guard !startResolved else { return }
                        startResolved = true
                        if let err { cont.resume(throwing: err); return }
                        self.engine.tunActive()  // opens TUN + drives state 3->4
                        self.readLoop()          // one-shot API: re-armed per completion
                        self.metrics.start()     // 10s cadence os_log dumps
                        cont.resume()
                    }
                }
            }
            // Before startTunnel resolves, a close (handshake/auth failure,
            // or death during the settings apply) must fail startTunnel —
            // otherwise it hangs until the NE watchdog kills the extension.
            // After resolution, a close is a dead session: tear down.
            engine.onTunnelClosed = { [weak self] reason in
                guard let self else { return }
                let err = NSError(domain: "mqvpn.poc", code: Int(reason),
                                  userInfo: [NSLocalizedDescriptionKey: "tunnel closed"])
                if !startResolved {
                    startResolved = true
                    cont.resume(throwing: err)
                } else {
                    self.cancelTunnelWithError(err)
                }
            }
            engine.start(config: config)
            binder.start()
        }
    }

    private func readLoop() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            self.engine.perform {
                for p in packets { self.engine.feedTunPacket(p) }
            }
            self.readLoop()   // MUST re-arm: readPackets delivers once per call
        }
    }

    static func makeSettings(from info: mqvpn_tunnel_info_t,
                             server: String) -> NEPacketTunnelNetworkSettings {
        func ip4(_ b: (UInt8, UInt8, UInt8, UInt8)) -> String {
            "\(b.0).\(b.1).\(b.2).\(b.3)"
        }
        let s = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: server)
        let v4 = NEIPv4Settings(
            addresses: [ip4(info.assigned_ip)],
            subnetMasks: [Self.prefixToMask(info.assigned_prefix)])
        v4.includedRoutes = [NEIPv4Route.default()]
        s.ipv4Settings = v4
        s.mtu = NSNumber(value: info.mtu)
        // The tunnel protocol does not carry DNS servers; like the Android
        // client (which takes DNS from app-side config), the platform layer
        // must supply resolvers. Without dnsSettings the phone keeps sending
        // queries to its WiFi LAN resolver, which the full-tunnel default
        // route captures and the server NATs to an unroutable private
        // address — name resolution dies and every app looks offline.
        s.dnsSettings = NEDNSSettings(servers: ["1.1.1.1", "8.8.8.8"])
        // IPv6 (info.has_v6 / assigned_ip6 / assigned_prefix6) is out of PoC
        // scope: the PoC server config assigns IPv4 only.
        return s
    }

    static func prefixToMask(_ prefix: UInt8) -> String {
        let m: UInt32 = prefix == 0 ? 0 : ~UInt32(0) << (32 - UInt32(prefix))
        return "\((m >> 24) & 255).\((m >> 16) & 255).\((m >> 8) & 255).\(m & 255)"
    }

    override func stopTunnel(with reason: NEProviderStopReason) async {
        // The extension process dies right after this returns; the orderly
        // teardown is a BEST-EFFORT clean close for the server (the close
        // frame races the async fd close on monitorQueue — losing the race
        // just means the server falls back to its idle timeout) and gives
        // repeated gate runs a zero state start.
        await withCheckedContinuation { cont in
            // Safe to resume from inside perform{}: only this method cancels
            // the tick thread, so the hop cannot be dropped here.
            engine.perform { [binder, engine] in
                // Detach the closed-callback first: disconnect fires
                // tunnel_closed synchronously, and re-entering
                // cancelTunnelWithError during a system-initiated stop is
                // unwanted.
                engine?.onTunnelClosed = nil
                binder?.stop()       // removePath for every slot + cancel monitors
                engine?.shutdown()   // client=nil -> disconnect -> destroy -> thread cancel
                cont.resume()
            }
        }
    }
}
