import Foundation

/// Resolves first-use private-key creation without ever overwriting the
/// winner of a concurrent Keychain insert by the app or PacketTunnel.
/// The Keychain SecItemAdd operation is the actual atomic insert boundary.
enum ImmutableIdentityInstaller {
    enum InsertResult {
        case inserted
        case alreadyExists
    }

    enum InstallationError: LocalizedError {
        case invalidCandidate
        case missingWinner
        case invalidWinner

        var errorDescription: String? {
            switch self {
            case .invalidCandidate:
                return "Generated WireGuard identity has the wrong length."
            case .missingWinner:
                return "A competing WireGuard identity could not be reloaded."
            case .invalidWinner:
                return "The stored WireGuard identity has the wrong length."
            }
        }
    }

    static func install(
        candidate: Data,
        insertIfAbsent: (Data) throws -> InsertResult,
        readExisting: () throws -> Data?
    ) throws -> Data {
        guard candidate.count == 32 else {
            throw InstallationError.invalidCandidate
        }
        switch try insertIfAbsent(candidate) {
        case .inserted:
            return candidate
        case .alreadyExists:
            // Never return the discarded candidate; pairing and PacketTunnel
            // must both use the immutable identity actually in Keychain.
            guard let winner = try readExisting() else {
                throw InstallationError.missingWinner
            }
            guard winner.count == 32 else {
                throw InstallationError.invalidWinner
            }
            return winner
        }
    }
}
