import Foundation

/// Validate IP packet envelopes at the NetworkExtension / Rust BoringTun ABI.
/// This is deliberately only an outer-header check, not full IP validation.
enum IPPacketFamily { case ipv4, ipv6 }

enum IPPacketEnvelope {
    // BoringTunCodec limits inner traffic to 65,536 bytes.
    static let maxInnerBytes = 65_536

    static func isValid(_ packet: Data, family: IPPacketFamily) -> Bool {
        guard packet.count <= maxInnerBytes else { return false }
        return packet.withUnsafeBytes { raw -> Bool in
            let bytes = raw.bindMemory(to: UInt8.self)
            switch family {
            case .ipv4:
                guard bytes.count >= 20, bytes[0] >> 4 == 4 else { return false }
                let headerBytes = Int(bytes[0] & 0x0F) * 4
                guard headerBytes >= 20, headerBytes <= 60,
                      headerBytes <= bytes.count else { return false }
                let totalBytes = Int(bytes[2]) << 8 | Int(bytes[3])
                return totalBytes >= headerBytes && totalBytes == bytes.count

            case .ipv6:
                guard bytes.count >= 40, bytes[0] >> 4 == 6 else { return false }
                let payloadBytes = Int(bytes[4]) << 8 | Int(bytes[5])
                // Zero-length payload with extra bytes indicates a jumbogram
                // or a corrupt envelope; this bounded engine does not support it.
                return payloadBytes + 40 == bytes.count
            }
        }
    }
}
