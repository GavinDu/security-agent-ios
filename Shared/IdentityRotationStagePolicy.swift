import Foundation

/// Local staging only. A caller must authenticate the Mac and own the
/// rotation transaction before calling. No activation, dispatch, deletion,
/// handshake proof or revocation is implemented by this policy.
enum IdentityRotationStagePolicy {
    struct Binding: Codable, Equatable, Sendable {
        let transactionID: UUID
        let serverPublicKey: String
        let activePublicKey: String
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

    enum StageError: Error { case invalidBinding, invalidRecord, conflict, missingWinner, activeChanged }
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
        guard CanonicalWireGuardPublicKeyPolicy.accepts(binding.serverPublicKey),
              CanonicalWireGuardPublicKeyPolicy.accepts(binding.activePublicKey),
              binding.serverPublicKey != binding.activePublicKey else { throw StageError.invalidBinding }
        guard try readActivePublicKey() == binding.activePublicKey else { throw StageError.activeChanged }

        func verify(_ data: Data) throws -> Receipt {
            guard data.count > 0, data.count <= maxBytes,
                  let record = try? JSONDecoder().decode(Record.self, from: data),
                  record.version == 1,
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

        if let existing = try readStage() { return try verify(existing) }
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
        return try verify(winner)
    }

    private static func encode(_ record: Record) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let bytes = try encoder.encode(record)
        guard bytes.count <= maxBytes else { throw StageError.invalidRecord }
        return bytes
    }
}
