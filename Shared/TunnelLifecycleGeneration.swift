import Foundation

/// Serial-queue-confined, monotonic token for a PacketTunnel instance.
/// Network callbacks can still arrive after a connection is cancelled;
/// a stale token must never operate on a replacement Rust BoringTun handle.
struct TunnelLifecycleGeneration {
    private(set) var current: UInt64 = 0

    @discardableResult
    mutating func advance() -> UInt64 {
        current &+= 1
        // Zero is reserved for "no session". Practically unreachable
        // after 2^64 starts, but preserve the invariant even on wrap.
        if current == 0 { current = 1 }
        return current
    }

    func matches(_ token: UInt64) -> Bool {
        token != 0 && token == current
    }
}
