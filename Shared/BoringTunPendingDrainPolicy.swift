import Foundation

/// BoringTun 0.7.1 MAX_QUEUE_DEPTH is 256. A local empty-input drain
/// may produce that many datagrams plus a final Done. Never spin forever
/// on a malformed engine; all calls are synchronous on the owner queue.
enum BoringTunPendingDrainPolicy {
    enum Failure: LocalizedError {
        case limitExceeded
        var errorDescription: String? {
            "Rust WireGuard queued-packet drain exceeded its safe limit."
        }
    }

    static let maxCalls = 257

    /// next returns true only for a network output, false only for Done.
    static func drain(next: () throws -> Bool) throws {
        for _ in 0..<maxCalls {
            if try !next() { return }
        }
        throw Failure.limitExceeded
    }
}
