import Foundation

/// Queue-confined generation for one authenticated NWConnection waiting
/// episode. A canceled or prior episode's timer must never tear down a
/// recovered or replacement Rust BoringTun tunnel.
struct WireGuardPathWaitGeneration {
    private(set) var current: UInt64 = 0
    private(set) var waiting = false

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
