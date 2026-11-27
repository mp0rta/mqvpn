// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation

/// One readPackets batch on its way into the core, and the read after it
/// (tick thread). A packet the core refuses with MQVPN_ERR_AGAIN is dropped
/// (the core's contract), and the core refuses every packet until
/// get_interest reports tun_readable again, so the rest of the batch and the
/// next read wait for that. Pure Foundation so the host test drives it with
/// a fake send; the extension passes mqvpn_client_on_tun_packet.
final class TunBacklog {
    private var rest: ArraySlice<Data> = []
    private var rearm: (() -> Void)?

    /// A refused packet is holding back the rest of its batch and the next read.
    var waiting: Bool { rearm != nil }

    /// Feeds `packets` through `send` (false = MQVPN_ERR_AGAIN) and calls
    /// `rearm` once every one of them is in.
    func feed(_ packets: [Data], send: (Data) -> Bool, then rearm: @escaping () -> Void) {
        rest = packets[...]
        self.rearm = rearm
        resume(send: send)
    }

    /// After tun_readable: feeds the rest, then calls the held `rearm`.
    func resume(send: (Data) -> Bool) {
        while let p = rest.popFirst() {
            if !send(p) { return }
        }
        let r = rearm
        rearm = nil
        r?()
    }
}
