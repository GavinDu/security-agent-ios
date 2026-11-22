import Foundation

/// Pure queue-friendly rate policy for empty Network.framework UDP callbacks.
/// Positive encrypted datagrams are rearmed immediately; no-data callbacks
/// get a bounded delay to avoid an accidental CPU-spinning receive loop.
enum WireGuardReceiveRearmPolicy {
    static let emptyReceiveDelayMilliseconds = 25

    static func needsBackoff(receivedByteCount: Int?) -> Bool {
        guard let receivedByteCount else { return true }
        return receivedByteCount <= 0
    }
}
