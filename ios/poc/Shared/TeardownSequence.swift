// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation

/// The fixed stop order (spec D8), as a pure function so host tests can pin
/// it. Only `stopPaths` is asynchronous: it receives a completion the
/// callee invokes once every path fd is closed; `destroy` and `complete`
/// run only after that. The caller supplies real closures and runs the
/// whole thing on the tick thread.
enum TeardownSequence {
    static func run(detach: () -> Void,
                    disconnect: () -> Void,
                    resolveStart: () -> Void,
                    stopPaths: (@escaping () -> Void) -> Void,
                    destroy: @escaping () -> Void,
                    complete: @escaping () -> Void) {
        detach()
        disconnect()
        resolveStart()
        stopPaths {
            destroy()
            complete()
        }
    }
}
