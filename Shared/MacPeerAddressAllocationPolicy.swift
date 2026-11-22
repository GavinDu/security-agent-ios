import Foundation

/// Pure Mac-side reservation proposal. Never modifies WireGuard config,
/// persists keys, or asserts a physical client has been provisioned.
/// The current iOS PacketTunnel still uses a fixed .2 address; callers MUST
/// not activate second-peer reservations before implementing dynamic iOS
/// network settings and authenticated Mac roster transactions (#20).
struct MacPeerAddressReservation: Equatable {
    let publicKey: String
    let slot: UInt8

    /// The single integer is the source of truth, never user-entered CIDRs.
    var ipv4CIDR: String { "10.8.0.\(slot)/32" }
    var ipv6CIDR: String { "fd86:ea04:1111::\(String(slot, radix: 16))/128" }
    var allowedIPs: String { "\(ipv4CIDR), \(ipv6CIDR)" }
}

enum MacPeerAddressAllocationPolicy {
    // .1 is the Mac WireGuard server, .0 the network, .255 broadcast.
    private static let firstClient: UInt8 = 2
    private static let lastClient: UInt8 = 254
    static let maxClients = 253

    /// Deterministic, fail-closed, side-effect-free lowest-slot selection.
    /// An inconsistent or duplicated existing registry NEVER gets repaired
    /// silently. Real enrollment/revocation must be a separate transaction.
    static func nextReservation(
        publicKey: String, existing: [MacPeerAddressReservation]
    ) -> MacPeerAddressReservation? {
        guard IPhonePairingImportPolicy.validatedPublicKey(publicKey) != nil,
              existing.count < maxClients else { return nil }

        var keys = Set<String>()
        var slots = Set<UInt8>()
        for reservation in existing {
            guard IPhonePairingImportPolicy.validatedPublicKey(reservation.publicKey) != nil,
                  reservation.slot >= firstClient,
                  reservation.slot <= lastClient,
                  keys.insert(reservation.publicKey).inserted,
                  slots.insert(reservation.slot).inserted else {
                return nil
            }
        }
        guard !keys.contains(publicKey) else { return nil }
        for number in Int(firstClient)...Int(lastClient) {
            let slot = UInt8(number)
            if !slots.contains(slot) {
                return MacPeerAddressReservation(publicKey: publicKey, slot: slot)
            }
        }
        return nil
    }
}
