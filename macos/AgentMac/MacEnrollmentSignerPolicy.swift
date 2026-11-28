import Foundation
import CryptoKit

/// Mac-only signer custody policy. No signing endpoint, UI caller, or
/// WireGuard private key is accepted. The future authenticated owner must
/// supply verified server identity under its exclusive transaction lease.
enum MacEnrollmentSignerPolicy {
    enum Failure: Error, Equatable {
        case invalidServer, serverChanged, invalidRecord, missingSigner
        case conflictingSigner, missingReadback
    }
    struct PublicIdentity: Equatable {
        let serverPublicKey: String
        let signingPublicKey: Data
    }
    private struct Record: Codable {
        let version: Int
        let serverPublicKey: String
        let signingPublicKey: Data
        let seed: Data
    }
    private static func encode(_ record: Record) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let bytes = try encoder.encode(record)
        guard (1...1024).contains(bytes.count) else { throw Failure.invalidRecord }
        return bytes
    }
    private static func record(server: String, seed: Data) throws -> Record {
        guard seed.count == 32, seed.contains(where: { $0 != 0 }),
              let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: seed),
              let serverBytes = Data(base64Encoded: server),
              key.publicKey.rawRepresentation != serverBytes else { throw Failure.invalidRecord }
        return Record(version: 1, serverPublicKey: server,
                      signingPublicKey: key.publicKey.rawRepresentation, seed: seed)
    }
    private static func decode(_ bytes: Data, server: String) throws -> PublicIdentity {
        guard (1...1024).contains(bytes.count),
              let stored = try? JSONDecoder().decode(Record.self, from: bytes),
              stored.version == 1, stored.serverPublicKey == server,
              try encode(stored) == bytes,
              try record(server: server, seed: stored.seed).signingPublicKey == stored.signingPublicKey
              else { throw Failure.invalidRecord }
        return PublicIdentity(serverPublicKey: server, signingPublicKey: stored.signingPublicKey)
    }
    private static func checkServer(_ server: String, _ readVerifiedServer: () throws -> String) throws {
        guard CanonicalWireGuardPublicKeyPolicy.accepts(server) else { throw Failure.invalidServer }
        guard try readVerifiedServer() == server else { throw Failure.serverChanged }
    }

    /// Explicit first-time commissioning only. Never call as a fallback
    /// from normal lookup or a missing established signer. The trusted
    /// owner must distinguish first-ever commissioning from lost storage.
    /// On a race, adopt the valid immutable winner, never the losing seed.
    static func commission(server: String, readVerifiedServer: () throws -> String,
        readRecord: () throws -> Data?, insertIfAbsent: (Data) throws -> Void,
        generateSeed: () throws -> Data = { Curve25519.Signing.PrivateKey().rawRepresentation }
    ) throws -> PublicIdentity {
        try checkServer(server, readVerifiedServer)
        if let existing = try readRecord() {
            let identity = try decode(existing, server: server)
            try checkServer(server, readVerifiedServer)
            return identity
        }
        let candidate = try record(server: server, seed: generateSeed())
        try checkServer(server, readVerifiedServer)
        try insertIfAbsent(encode(candidate))
        guard let winner = try readRecord() else { throw Failure.missingReadback }
        let identity = try decode(winner, server: server)
        try checkServer(server, readVerifiedServer)
        return identity
    }

    /// Established lookup is read-only and requires the independently
    /// retained expected public signer. Missing or substituted records fail.
    static func existing(server: String, expectedSigner: Data,
        readVerifiedServer: () throws -> String, readRecord: () throws -> Data?
    ) throws -> PublicIdentity {
        try checkServer(server, readVerifiedServer)
        guard let bytes = try readRecord() else { throw Failure.missingSigner }
        let identity = try decode(bytes, server: server)
        guard identity.signingPublicKey == expectedSigner else { throw Failure.conflictingSigner }
        try checkServer(server, readVerifiedServer)
        return identity
    }
}
