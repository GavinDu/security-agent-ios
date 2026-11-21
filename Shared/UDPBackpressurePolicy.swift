import Foundation

/// Pure policy for bounding outstanding encrypted UDP writes from the
/// PacketTunnel. Temporary congestion must not terminate a live VPN session.
enum UDPBackpressurePolicy {
    enum Decision: Equatable {
        case enqueue
        case drop
        case invalid
    }

    static func decision(pendingSends: Int, maxPendingSends: Int) -> Decision {
        // Invalid local accounting is an invariant failure, not backpressure.
        guard pendingSends >= 0, maxPendingSends > 0,
              pendingSends <= maxPendingSends else {
            return .invalid
        }
        return pendingSends == maxPendingSends ? .drop : .enqueue
    }
}
