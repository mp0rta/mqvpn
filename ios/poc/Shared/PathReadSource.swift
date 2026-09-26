// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

import Foundation

/// One path socket's read source and the whole chain around it:
/// readable → suspend → hop → drain → resume, and cancel → hop → close →
/// release → fence. Pure Foundation (no bridging header, no libmqvpn type)
/// so the host test drives it with a fake hop; the extension passes the
/// engine's perform / drain / pathReleased.
///
/// Event handler (monitor queue): the source is level-triggered and the read
/// happens on another thread, so it is SUSPENDED first, the drain is hopped
/// to the tick thread, and the resume runs in `defer` there — cancelled or
/// not. A refused hop resumes at once. Every suspend is balanced inside this
/// one closure: releasing a suspended source traps in libdispatch.
///
/// Cancel handler (monitor queue): hops close(fd), `released` and the fence
/// leave to the tick thread as one closure. The close runs there — never on
/// the monitor queue — so it can never overlap a drain: both run on the one
/// tick thread. Normally libdispatch defers a suspended source's cancel
/// handler until the resume, so the drain has already run when the release
/// hop is queued; when the cancel lands while the event handler is
/// executing, both hops can be queued and their relative order is the hop's
/// own (see `hop`) — hence `drain` must be a no-op once `released` has run.
/// The fd is still closed only after the cancel handler was invoked
/// (DispatchSource's rule). The fence therefore means "fd closed AND the
/// release reported". The hop is refused only after destroy, when the
/// library already finalised the transport; then close and leave directly.
///
/// The handlers capture `source`, not `self`: the chain completes even after
/// the owner dropped this object (PathBinder removes the slot before it
/// cancels). libdispatch releases that self-reference only after the cancel
/// handler ran, so `cancel()` is mandatory — a PathReadSource dropped
/// without it leaks the source (fd still polled, `hop`/`drain`/`released`
/// and what they capture retained) and never leaves the fence.
final class PathReadSource {
    private let source: DispatchSourceRead
    private var armed = false

    /// - Parameters:
    ///   - hop: runs the closure on the tick thread — one thread, so closures
    ///     never overlap. Submission order is not relied on (except at the
    ///     tick thread's exit — see MqvpnEngine.perform; the extension's
    ///     performSelector(onThread:) is FIFO in practice, but Apple documents
    ///     that only for the main thread). false if it cannot (thread gone).
    ///   - drain: tick thread; reads the socket until it would block. Must be a
    ///     no-op once `released` has run for this path (the two hops can be
    ///     queued in either order — see the cancel handler above).
    ///   - released: tick thread; reports the release to the library. Runs in
    ///     the same closure as the close, right after it.
    init(fd: Int32, queue: DispatchQueue, fence: DispatchGroup,
         hop: @escaping (@escaping () -> Void) -> Bool,
         drain: @escaping () -> Void,
         released: @escaping () -> Void) {
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        self.source = source
        source.setEventHandler {
            source.suspend()
            let accepted = hop {
                defer { source.resume() }
                drain()
            }
            if !accepted { source.resume() }
        }
        source.setCancelHandler {
            let accepted = hop {
                close(fd)
                released()
                fence.leave()
            }
            if !accepted {
                assertionFailure("release hop refused before destroy")
                close(fd)
                fence.leave()
            }
        }
        fence.enter()   // left in the cancel chain above
    }

    /// Arms the source. Exactly once, right after init: a source that is
    /// never resumed cannot be released. A second resume() while a drain hop
    /// holds the suspend would silently un-suspend the source mid-drain and
    /// only trap later, so the precondition catches it at the call.
    func resume() {
        precondition(!armed, "PathReadSource resumed twice")
        armed = true
        source.resume()
    }

    /// Cancels the source: its cancel handler queues the release hop, which
    /// closes the fd and reports the release on the tick thread. A drain hop
    /// still queued at that point either ran first or runs as a no-op after.
    func cancel() {
        source.cancel()
    }
}
