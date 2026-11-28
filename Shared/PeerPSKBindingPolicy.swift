import Foundation

/// Local selection boundary only. A bound secret is not evidence of remote
/// provisioning; the future authenticated transaction owner must create it.
/// No secret is exposed in public profile, QR or roster metadata.
enum PeerPSKBindingPolicy {
    enum SelectionError: Error, Equatable { case unboundLegacy, invalidBinding, invalidRecord }
    private struct Record: Codable {
        let version: Int
        let serverPublicKey: String
        let clientPublicKey: String
        let presharedKey: Data
    }

    static func select(serverPublicKey: String, clientPublicKey: String,
                       legacyPresent: Bool, boundRecord: Data?) throws -> Data? {
        // A legacy global key has no authenticated peer binding. Never
        // silently ignore it or fall back to a no-PSK handshake.
        guard !legacyPresent else { throw SelectionError.unboundLegacy }
        guard CanonicalWireGuardPublicKeyPolicy.accepts(serverPublicKey),
              CanonicalWireGuardPublicKeyPolicy.accepts(clientPublicKey),
              serverPublicKey != clientPublicKey else { throw SelectionError.invalidBinding }
        guard let boundRecord else { return nil }
        guard (1...2048).contains(boundRecord.count),
              let record = try? JSONDecoder().decode(Record.self, from: boundRecord),
              record.version == 1,
              record.serverPublicKey == serverPublicKey,
              record.clientPublicKey == clientPublicKey,
              record.presharedKey.count == 32,
              record.presharedKey.contains(where: { $0 != 0 }) else {
            throw SelectionError.invalidRecord
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        guard try encoder.encode(record) == boundRecord else { throw SelectionError.invalidRecord }
        return record.presharedKey
    }
}
