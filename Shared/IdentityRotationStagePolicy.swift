import Foundation

/// Local staging only. A caller must authenticate the Mac and own the
/// rotation transaction before calling. No activation, dispatch, deletion,
/// handshake proof or revocation is implemented by this policy.
enum IdentityRotationStagePolicy {
    struct Binding: Codable, Equatable, Sendable {
        let transactionID: UUID
        let serverPublicKey: String
        let activePublicKey: String

        var isValid: Bool {
            transactionID.uuidString != "00000000-0000-0000-0000-000000000000" &&
            CanonicalWireGuardPublicKeyPolicy.accepts(serverPublicKey) &&
            CanonicalWireGuardPublicKeyPolicy.accepts(activePublicKey) &&
            serverPublicKey != activePublicKey
        }
    }

    struct Receipt: Equatable, Sendable {
        let binding: Binding
        let candidatePublicKey: String
    }

    private struct Record: Codable {
        let version: Int
        let binding: Binding
        let candidatePublicKey: String
        let candidatePrivateKey: Data
    }

    enum StageError: Error, Equatable { case invalidBinding, invalidRecord, conflict, missingWinner, activeChanged }
    private static let maxBytes = 2048

    /// A single insert-only staging slot prevents multiple orphan candidates.
    /// Duplicate retry adopts the stored candidate for the same binding only.
    /// Never replace the active identity or return private bytes to the caller.
    static func stage(
        binding: Binding,
        readActivePublicKey: () throws -> String,
        readStage: () throws -> Data?,
        generateCandidate: () throws -> Data,
        derivePublicKey: (Data) throws -> String,
        insertIfAbsent: (Data) throws -> ImmutableIdentityInstaller.InsertResult
    ) throws -> Receipt {
        guard binding.isValid else { throw StageError.invalidBinding }
        guard try readActivePublicKey() == binding.activePublicKey else { throw StageError.activeChanged }

        if let existing = try readStage() {
            return try verify(existing, binding: binding, readActivePublicKey: readActivePublicKey,
                              derivePublicKey: derivePublicKey)
        }
        let candidate = try generateCandidate()
        guard WireGuardPrivateIdentityPolicy.accepts(candidate) else { throw StageError.invalidRecord }
        let publicKey = try derivePublicKey(candidate)
        guard CanonicalWireGuardPublicKeyPolicy.accepts(publicKey),
              publicKey != binding.activePublicKey, publicKey != binding.serverPublicKey else {
            throw StageError.invalidRecord
        }
        let record = Record(version: 1, binding: binding,
                            candidatePublicKey: publicKey, candidatePrivateKey: candidate)
        let encoded = try encode(record)
        guard try readActivePublicKey() == binding.activePublicKey else { throw StageError.activeChanged }
        _ = try insertIfAbsent(encoded)
        // Read back on success AND duplicate. An absent or malformed winner
        // is not permission to overwrite or silently generate another key.
        guard let winner = try readStage() else { throw StageError.missingWinner }
        return try verify(winner, binding: binding, readActivePublicKey: readActivePublicKey,
                          derivePublicKey: derivePublicKey)
    }

    /// Read-only recovery for an exact authenticated transaction owner.
    /// Missing data is an error, never permission to create a candidate.
    static func recover(binding: Binding, readActivePublicKey: () throws -> String,
                        readStage: () throws -> Data?,
                        derivePublicKey: (Data) throws -> String) throws -> Receipt {
        guard binding.isValid else { throw StageError.invalidBinding }
        guard try readActivePublicKey() == binding.activePublicKey else { throw StageError.activeChanged }
        guard let existing = try readStage() else { throw StageError.missingWinner }
        return try verify(existing, binding: binding, readActivePublicKey: readActivePublicKey,
                          derivePublicKey: derivePublicKey)
    }

    private static func verify(_ data: Data, binding: Binding,
                               readActivePublicKey: () throws -> String,
                               derivePublicKey: (Data) throws -> String) throws -> Receipt {
        guard data.count > 0, data.count <= maxBytes,
              let record = try? JSONDecoder().decode(Record.self, from: data),
              record.version == 1, record.binding.isValid,
              try encode(record) == data,
              WireGuardPrivateIdentityPolicy.accepts(record.candidatePrivateKey),
              CanonicalWireGuardPublicKeyPolicy.accepts(record.candidatePublicKey),
              record.candidatePublicKey != record.binding.activePublicKey,
              record.candidatePublicKey != record.binding.serverPublicKey,
              try derivePublicKey(record.candidatePrivateKey) == record.candidatePublicKey else {
            throw StageError.invalidRecord
        }
        guard record.binding == binding else { throw StageError.conflict }
        guard try readActivePublicKey() == binding.activePublicKey else { throw StageError.activeChanged }
        return Receipt(binding: binding, candidatePublicKey: record.candidatePublicKey)
    }

    private static func encode(_ record: Record) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let bytes = try encoder.encode(record)
        guard bytes.count <= maxBytes else { throw StageError.invalidRecord }
        return bytes
    }
}
