import Foundation

/// Public marker for a committed PSK transaction. No secret-derived data.
struct PeerPSKRequirement: Codable, Equatable, Sendable {
    let transactionID: UUID
    let clientPublicKey: String

    func isValid(serverPublicKey: String) -> Bool {
        CanonicalWireGuardPublicKeyPolicy.accepts(serverPublicKey) &&
        CanonicalWireGuardPublicKeyPolicy.accepts(clientPublicKey) &&
        clientPublicKey != serverPublicKey &&
        transactionID.uuidString != "00000000-0000-0000-0000-000000000000"
    }

    /// Ordinary QR pairing/settings cannot introduce, clear or replace a
    /// protected marker. Only a future authenticated provisioning owner can.
    static func permitsOrdinarySave(prior: PeerPSKRequirement?, priorServer: String?,
                                    candidate: PeerPSKRequirement?, candidateServer: String,
                                    nativeRequiresPSK: Bool, priorVerified: Bool) -> Bool {
        if prior == nil && candidate == nil && !nativeRequiresPSK { return true }
        guard let prior, priorVerified, nativeRequiresPSK else { return false }
        return prior == candidate && priorServer == candidateServer
    }
}

/// Local selection boundary only. A bound secret is not evidence of remote
/// provisioning; the future authenticated transaction owner must create it.
/// No secret is exposed in public profile, QR or roster metadata.
enum PeerPSKBindingPolicy {
    enum SelectionError: Error, Equatable { case unboundLegacy, invalidBinding, invalidRecord, missingRequired, unexpectedRecord }
    private struct Record: Codable {
        let version: Int
        let serverPublicKey: String
        let clientPublicKey: String
        let transactionID: UUID
        let presharedKey: Data
    }

    enum StageError: Error, Equatable { case invalidInput, conflict, missingWinner }
    struct StageReceipt: Equatable, Sendable {
        let serverPublicKey: String
        let requirement: PeerPSKRequirement
    }

    /// Local insert-only initial provisioning stage; caller must authenticate
    /// the exchange and serialize it with profile/identity/rotation changes.
    /// The staging account is never selected by transport. No secret receipt,
    /// committed key replacement, profile mutation, or remote proof.
    static func stageInitial(serverPublicKey: String, requirement: PeerPSKRequirement,
                             secret: Data, verifyLocalState: () throws -> Void,
                             readStage: () throws -> Data?,
                             insertIfAbsent: (Data) throws -> Void) throws -> StageReceipt {
        guard requirement.isValid(serverPublicKey: serverPublicKey),
              secret.count == 32, secret.contains(where: { $0 != 0 }) else {
            throw StageError.invalidInput
        }
        let record = Record(version: 2, serverPublicKey: serverPublicKey,
                            clientPublicKey: requirement.clientPublicKey,
                            transactionID: requirement.transactionID, presharedKey: secret)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let expected = try encoder.encode(record)
        guard (1...2048).contains(expected.count) else { throw StageError.invalidInput }
        try verifyLocalState()
        if let existing = try readStage() {
            guard existing == expected else { throw StageError.conflict }
        } else {
            try verifyLocalState()
            try insertIfAbsent(expected)
        }
        // Verify a persisted winner after both retry and atomic insert.
        // A conflicting/absent winner must not be replaced or activated.
        guard let winner = try readStage() else { throw StageError.missingWinner }
        guard winner == expected else { throw StageError.conflict }
        try verifyLocalState()
        return StageReceipt(serverPublicKey: serverPublicKey, requirement: requirement)
    }

    static func select(serverPublicKey: String, clientPublicKey: String,
                       legacyPresent: Bool, boundRecord: Data?,
                       requirement: PeerPSKRequirement?) throws -> Data? {
        // A legacy global key has no authenticated peer binding. Never
        // silently ignore it or fall back to a no-PSK handshake.
        guard !legacyPresent else { throw SelectionError.unboundLegacy }
        guard CanonicalWireGuardPublicKeyPolicy.accepts(serverPublicKey),
              CanonicalWireGuardPublicKeyPolicy.accepts(clientPublicKey),
              serverPublicKey != clientPublicKey else { throw SelectionError.invalidBinding }
        guard let requirement else {
            guard boundRecord == nil else { throw SelectionError.unexpectedRecord }
            return nil
        }
        guard requirement.isValid(serverPublicKey: serverPublicKey),
              requirement.clientPublicKey == clientPublicKey else { throw SelectionError.invalidBinding }
        guard let boundRecord else { throw SelectionError.missingRequired }
        guard (1...2048).contains(boundRecord.count),
              let record = try? JSONDecoder().decode(Record.self, from: boundRecord),
              record.version == 2,
              record.transactionID == requirement.transactionID,
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
