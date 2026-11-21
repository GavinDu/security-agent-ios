import Foundation

@main
struct UDPBackpressureSmoke {
    static func main() {
        let limit = 256
        for pending in [0, 1, 128, 255] {
            precondition(UDPBackpressurePolicy.decision(
                pendingSends: pending, maxPendingSends: limit
            ) == .enqueue)
        }
        precondition(UDPBackpressurePolicy.decision(
            pendingSends: limit, maxPendingSends: limit
        ) == .drop)
        for pending in [-1, 257, Int.max] {
            precondition(UDPBackpressurePolicy.decision(
                pendingSends: pending, maxPendingSends: limit
            ) == .invalid)
        }
        precondition(UDPBackpressurePolicy.decision(
            pendingSends: 0, maxPendingSends: 0
        ) == .invalid)
        precondition(UDPBackpressurePolicy.decision(
            pendingSends: 0, maxPendingSends: -1
        ) == .invalid)
        // Never turn a temporary full queue into an engine shutdown.
        precondition(UDPBackpressurePolicy.decision(
            pendingSends: 1, maxPendingSends: 1
        ) == .drop)
        print("UDP backpressure saturation policy: passed")
    }
}
