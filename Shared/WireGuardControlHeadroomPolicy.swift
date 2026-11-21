import Foundation

/// Preserve a small bounded part of NWConnection's encrypted send backlog for
/// BoringTun-generated handshake/rekey control packets during data bursts.
/// These are WireGuard on-the-wire message types, not application payloads.
enum WireGuardControlHeadroomPolicy {
    enum Decision: Equatable {
        case enqueue
        case drop
        case invalid
    }

    static func decision(
        datagram: Data, pendingSends: Int, maxPendingSends: Int,
        reservedControlSlots: Int
    ) -> Decision {
        guard pendingSends >= 0, maxPendingSends > 0,
              pendingSends <= maxPendingSends,
              reservedControlSlots > 0,
              reservedControlSlots < maxPendingSends,
              datagram.count >= 4 else { return .invalid }

        // WireGuard type is little-endian UInt32; its upper three bytes
        // are reserved and must not smuggle unknown types into priority.
        guard datagram[1] == 0, datagram[2] == 0, datagram[3] == 0 else {
            return .invalid
        }

        // Handshake initiation / response / cookie are fixed wire lengths;
        // transport data has a 16-byte header and 16-byte AEAD tag.
        let control: Bool
        switch datagram[0] {
        case 1: guard datagram.count == 148 else { return .invalid }; control = true
        case 2: guard datagram.count == 92 else { return .invalid }; control = true
        case 3: guard datagram.count == 64 else { return .invalid }; control = true
        case 4: guard datagram.count >= 32 else { return .invalid }; control = false
        default: return .invalid
        }

        // The original global backlog limit is still enforced separately.
        guard pendingSends < maxPendingSends else { return .drop }
        if !control && pendingSends >= maxPendingSends - reservedControlSlots {
            return .drop
        }
        return .enqueue
    }
}
