import Foundation

/// Queue-confined provider lifecycle state; all transitions occur on the
/// PacketTunnelProvider private serial dispatch queue.
struct PacketTunnelProviderState {
    enum Phase: Equatable { case idle, starting, connected, stopping }

    private(set) var phase: Phase = .idle

    mutating func beginStart() -> Bool {
        guard phase == .idle else { return false }
        phase = .starting
        return true
    }

    /// Returns false for a late start callback after stop was requested.
    mutating func finishStart(success: Bool) -> Bool {
        guard phase == .starting else { return false }
        phase = success ? .connected : .idle
        return true
    }

    /// Only the first stop request may initiate transport teardown.
    mutating func beginStop() -> Bool {
        guard phase == .starting || phase == .connected else { return false }
        phase = .stopping
        return true
    }

    @discardableResult
    mutating func finishStop() -> Bool {
        guard phase == .stopping else { return false }
        phase = .idle
        return true
    }
}
