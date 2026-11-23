import Foundation

/// The entire native PacketTunnel startup (DNS, settings, UDP and handshake)
/// is bounded. Handshake-only deadlines do not cover a stuck NetworkExtension
/// setTunnelNetworkSettings completion. All decisions occur on the engine queue.
enum WireGuardStartupWatchdogPolicy {
    static let timeoutSeconds = 30

    /// A stale callback must never terminate a restarted Rust BoringTun tunnel.
    static func shouldExpire(
        active: Bool,
        pendingCompletion: Bool,
        expectedGeneration: UInt64,
        currentGeneration: UInt64
    ) -> Bool {
        active && pendingCompletion && expectedGeneration != 0 &&
            expectedGeneration == currentGeneration
    }
}
