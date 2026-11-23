import Foundation

/// Check the native packetFlow read callback contract before using Swift zip.
/// zip truncates a mismatched packet/protocol pair silently; a broken local
/// system-tunnel batch is not an unauthenticated peer packet to discard.
enum WireGuardPacketReadBatchPolicy {
    static func accepts(packetCount: Int, protocolCount: Int) -> Bool {
        packetCount >= 0 && protocolCount >= 0 && packetCount == protocolCount
    }
}
