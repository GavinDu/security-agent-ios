import Foundation

/// Queue-confined generation for one authenticated NWConnection waiting
/// episode. A canceled or prior episode's timer must never tear down a
/// replacement Rust BoringTun tunnel. Socket readiness alone never proves
/// fresh authentication on a previously interrupted path.
struct WireGuardPathWaitGeneration {
    private(set) var current: UInt64 = 0
    private(set) var waiting = false

    /// Suspend all old-session crypto and packet forwarding during this wait.
    var permitsEngineIO: Bool { !waiting }

    /// A ready socket after a post-authentication wait requires a fresh
    /// OS-authorized tunnel start, not a resumed old Rust session.
    var requiresFreshStartOnReady: Bool { waiting }

    mutating func beginWait() -> UInt64? {
        guard !waiting else { return nil }
        waiting = true
        return advance()
    }

    mutating func invalidate() {
        waiting = false
        _ = advance()
    }

    func accepts(_ token: UInt64) -> Bool {
        waiting && token != 0 && token == current
    }

    @discardableResult
    private mutating func advance() -> UInt64 {
        current &+= 1
        if current == 0 { current = 1 }
        return current
    }
}
