import Foundation

/// Validate the local NEPacketTunnelFlow callback before ever entering the
/// serialized Rust BoringTun packet loop. A broken/huge local callback must
/// fail closed, not monopolize the queue or silently truncate via zip().
enum WireGuardPacketReadBatchPolicy {
    static let maxPacketsPerBatch = 256
    // Share the exact inner-envelope limit; do not let the pre-FFI gates drift.
    static let maxPacketBytes = IPPacketEnvelope.maxInnerBytes
    static let maxBatchBytes = 8 * 1_024 * 1_024

    static func accepts(packetCount: Int, protocolCount: Int) -> Bool {
        packetCount >= 0 && protocolCount >= 0 &&
            packetCount <= maxPacketsPerBatch &&
            packetCount == protocolCount
    }

    /// Called only AFTER count validation limits the length-array size.
    /// Subtract before comparing to avoid Int overflow on untrusted lengths.
    static func acceptsPayloadLengths(_ lengths: [Int]) -> Bool {
        guard lengths.count <= maxPacketsPerBatch else { return false }
        var total = 0
        for size in lengths {
            guard size > 0, size <= maxPacketBytes,
                  size <= maxBatchBytes - total else { return false }
            total += size
        }
        return true
    }
}
