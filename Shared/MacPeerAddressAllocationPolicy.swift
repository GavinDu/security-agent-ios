import Foundation

/// Pure Mac-side reservation proposal. Never modifies WireGuard config,
/// persists keys, or asserts a physical client has been provisioned.
/// The current iOS PacketTunnel still uses a fixed .2 address; callers MUST
/// not activate second-peer reservations before implementing dynamic iOS
/// network settings and authenticated Mac roster transactions (#20).
struct MacPeerAddressReservation: Equatable, Sendable {
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


/// Public-only transaction state. No authorization, disk persistence or
/// privileged daemon calls occur here. The eventual daemon must supply
/// complete authoritative readback and a durable journal before use (#20).
struct MacPeerRosterSnapshot: Equatable, Sendable {
    let epoch: UUID
    let revision: UInt64
    let peers: [MacPeerAddressReservation]
}
enum MacPeerRosterMutation: Sendable {
    case enroll(publicKey: String)
    case revoke(MacPeerAddressReservation)
}
struct MacPeerRosterPlan: Sendable {
    let id: UUID
    let before: MacPeerRosterSnapshot
    let after: [MacPeerAddressReservation]
}
enum MacPeerRosterResolution: Equatable, Sendable {
    case committed, rolledBack, unverified, stale
}

/// Serializes callers within one process. An ambiguous readback leaves the
/// transaction pending and blocks subsequent changes. Not a durable store.
actor MacPeerRosterCoordinator {
    private var current: MacPeerRosterSnapshot
    private var pending: MacPeerRosterPlan?

    init?(peers: [MacPeerAddressReservation], revision: UInt64 = 0) {
        guard let canonical = Self.canonicalRoster(peers) else { return nil }
        current = MacPeerRosterSnapshot(epoch: UUID(), revision: revision, peers: canonical)
    }

    func snapshot() -> MacPeerRosterSnapshot { current }

    func prepare(_ mutation: MacPeerRosterMutation,
                 expected: MacPeerRosterSnapshot) -> MacPeerRosterPlan? {
        guard pending == nil, current == expected, current.revision < UInt64.max else {
            return nil
        }
        var proposed = current.peers
        switch mutation {
        case .enroll(let key):
            guard let reservation = MacPeerAddressAllocationPolicy.nextReservation(
                publicKey: key, existing: proposed
            ) else { return nil }
            proposed.append(reservation)
        case .revoke(let exactPeer):
            guard let index = proposed.firstIndex(of: exactPeer) else { return nil }
            proposed.remove(at: index)
        }
        guard let canonical = Self.canonicalRoster(proposed) else { return nil }
        let plan = MacPeerRosterPlan(id: UUID(), before: current, after: canonical)
        pending = plan
        return plan
    }

    /// Caller must establish provenance of a complete daemon observation
    /// AFTER fencing the operation against any further asynchronous writes.
    /// A pre-completion readback is not proof of rollback. A stale ID or
    /// divergent roster never releases a reservation.
    func resolve(id: UUID, observed: [MacPeerAddressReservation]) -> MacPeerRosterResolution {
        guard let plan = pending, plan.id == id else { return .stale }
        guard let canonical = Self.canonicalRoster(observed) else { return .unverified }
        let result: MacPeerRosterResolution
        if canonical == plan.after {
            result = .committed
        } else if canonical == plan.before.peers {
            result = .rolledBack
        } else {
            return .unverified
        }
        // Advance even on rollback to invalidate earlier snapshots (ABA).
        current = MacPeerRosterSnapshot(epoch: current.epoch,
                                        revision: current.revision + 1, peers: canonical)
        pending = nil
        return result
    }

    private static func canonicalRoster(_ peers: [MacPeerAddressReservation])
        -> [MacPeerAddressReservation]? {
        guard peers.count <= MacPeerAddressAllocationPolicy.maxClients else { return nil }
        var keys = Set<String>()
        var slots = Set<UInt8>()
        for peer in peers {
            guard (2...254).contains(Int(peer.slot)),
                  IPhonePairingImportPolicy.validatedPublicKey(peer.publicKey) != nil,
                  keys.insert(peer.publicKey).inserted,
                  slots.insert(peer.slot).inserted else { return nil }
        }
        return peers.sorted { $0.slot < $1.slot }
    }
}
