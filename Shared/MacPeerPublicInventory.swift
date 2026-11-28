import Foundation

/// Strict public-only parser of three separate successful, bounded
/// wireguard-tools queries on ONE previously verified Rust daemon interface:
/// public-key, peers, allowed-ips. Do not use dump/showconf or PSK output.
/// The privileged owner must guarantee complete capture, correct interface,
/// stable daemon generation and a terminal write fence across all queries.
/// This parser cannot establish any of those facts by itself.
enum MacPeerPublicInventory {
    static let maxBytes = 64 * 1024

    struct Snapshot: Equatable, Sendable {
        let serverPublicKey: String
        let peers: [MacPeerAddressReservation]

        // Only the bounded public parser may construct this shape. This is
        // structural validation, not a cryptographic attestation.
        fileprivate init(serverPublicKey: String, peers: [MacPeerAddressReservation]) {
            self.serverPublicKey = serverPublicKey
            self.peers = peers
        }
    }

    static func decode(expectedServerKey: String, publicKeyOutput: Data,
                       peersOutput: Data, allowedIPsOutput: Data) -> Snapshot? {
        guard IPhonePairingImportPolicy.validatedPublicKey(expectedServerKey) != nil,
              let server = lines(publicKeyOutput), server == [expectedServerKey],
              let peers = lines(peersOutput),
              let allowed = lines(allowedIPsOutput),
              peers.count <= MacPeerAddressAllocationPolicy.maxClients,
              peers.count == allowed.count else { return nil }
        var declared = Set<String>()
        for key in peers {
            guard key != expectedServerKey,
                  IPhonePairingImportPolicy.validatedPublicKey(key) != nil,
                  declared.insert(key).inserted else { return nil }
        }
        var parsed = Set<String>()
        var slots = Set<UInt8>()
        var reservations: [MacPeerAddressReservation] = []
        for row in allowed {
            let fields = row.split(separator: "\t", omittingEmptySubsequences: false)
            guard fields.count == 2 else { return nil }
            let key = String(fields[0])
            guard declared.contains(key), parsed.insert(key).inserted else { return nil }
            let addresses = fields[1].split(separator: " ", omittingEmptySubsequences: false)
            guard addresses.count == 2,
                  let ipv4 = addresses.first(where: { $0.hasPrefix("10.8.0.") }),
                  ipv4.hasSuffix("/32"),
                  let slot = UInt8(ipv4.dropFirst("10.8.0.".count).dropLast(3)),
                  (2...254).contains(Int(slot)),
                  slots.insert(slot).inserted else { return nil }
            let peer = MacPeerAddressReservation(publicKey: key, slot: slot)
            // Compare exact canonical host routes; reject overlapping,
            // extra, empty, noncanonical or inconsistent IPv4/IPv6 routes.
            guard Set(addresses.map(String.init)) == Set([peer.ipv4CIDR, peer.ipv6CIDR]) else {
                return nil
            }
            reservations.append(peer)
        }
        guard parsed == declared else { return nil }
        return Snapshot(serverPublicKey: expectedServerKey,
                        peers: reservations.sorted { $0.slot < $1.slot })
    }

    /// A nonempty command response must be newline terminated and ASCII.
    /// Empty data is permitted only for the two peer queries; the owner
    /// must separately verify process success and nontruncated capture.
    private static func lines(_ data: Data) -> [String]? {
        guard data.count <= maxBytes else { return nil }
        if data.isEmpty { return [] }
        guard data.count > 1, data.last == 10,
              data.allSatisfy({ $0 == 9 || $0 == 10 || (32...126).contains($0) }),
              let text = String(data: data, encoding: .utf8) else { return nil }
        let rows = text.dropLast().split(separator: "\n", omittingEmptySubsequences: false)
        guard rows.allSatisfy({ !$0.isEmpty }) else { return nil }
        return rows.map(String.init)
    }
}
