import CryptoKit
import Foundation

/// Public signer pin; not a signing private key or WireGuard secret.
/// The user must compare the FULL fingerprint displayed independently
/// by the trusted Mac, not a fingerprint included in the incoming message.
enum EnrollmentSigningPinPolicy {
    enum PinError: Error, Equatable { case invalidBinding, wrongFingerprint, conflict, missingReadback }

    struct Binding: Codable, Equatable {
        let serverPublicKey: String
        let clientPublicKey: String
        let signingPublicKey: Data

        fileprivate var valid: Bool {
            guard CanonicalWireGuardPublicKeyPolicy.accepts(serverPublicKey),
                  CanonicalWireGuardPublicKeyPolicy.accepts(clientPublicKey),
                  serverPublicKey != clientPublicKey,
                  let server = Data(base64Encoded: serverPublicKey),
                  let client = Data(base64Encoded: clientPublicKey),
                  signingPublicKey.count == 32,
                  signingPublicKey.contains(where: { $0 != 0 }),
                  signingPublicKey != server, signingPublicKey != client,
                  (try? Curve25519.Signing.PublicKey(rawRepresentation: signingPublicKey)) != nil
                  else { return false }
            return true
        }
    }

    private struct Record: Codable {
        let version: Int
        let binding: Binding
    }

    struct Confirmed {
        fileprivate let binding: Binding
        fileprivate let bytes: Data
        var serverPublicKey: String { binding.serverPublicKey }
        var clientPublicKey: String { binding.clientPublicKey }
    }

    /// A fixed-size, domain-separated SHA-256 digest over raw canonical
    /// keys in server/client/signer order. Display all 64 lowercase hex
    /// digits on both devices; no truncation or normalization accepted.
    static func fingerprint(_ binding: Binding) -> String? {
        guard binding.valid,
              let server = Data(base64Encoded: binding.serverPublicKey),
              let client = Data(base64Encoded: binding.clientPublicKey) else { return nil }
        var message = Data("security-agent.enrollment-signing-pin.v1\u{0}".utf8)
        message.append(server)
        message.append(client)
        message.append(binding.signingPublicKey)
        return SHA256.hash(data: message).map { String(format: "%02x", Int($0)) }.joined()
    }

    private static func canonicalBytes(_ binding: Binding) -> Data? {
        guard binding.valid else { return nil }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        guard let bytes = try? encoder.encode(Record(version: 1, binding: binding)),
              (1...1024).contains(bytes.count) else { return nil }
        return bytes
    }

    /// Enter the full fingerprint from a separately authenticated display.
    /// This is a local confirmation boundary, not proof of user presence.
    /// No actual QR, display or trusted UI is implemented here.
    static func confirm(_ binding: Binding, independentlyComparedFingerprint: String) throws -> Confirmed {
        guard let fingerprint = fingerprint(binding), let bytes = canonicalBytes(binding)
              else { throw PinError.invalidBinding }
        guard independentlyComparedFingerprint == fingerprint else { throw PinError.wrongFingerprint }
        return Confirmed(binding: binding, bytes: bytes)
    }

    /// Existing pin is immutable; never overwrite a mismatch. Retry with
    /// the exact already persisted winner is allowed, not pin rotation.
    static func install(_ confirmed: Confirmed, verifyLocalState: () throws -> Void,
                        readPin: () throws -> Data?, insertIfAbsent: (Data) throws -> Void) throws {
        try verifyLocalState()
        if let existing = try readPin() {
            guard existing == confirmed.bytes else { throw PinError.conflict }
        } else {
            try verifyLocalState()
            try insertIfAbsent(confirmed.bytes)
        }
        guard let winner = try readPin() else { throw PinError.missingReadback }
        guard winner == confirmed.bytes else { throw PinError.conflict }
        try verifyLocalState()
    }

    /// Canonical record only, scoped to the exact active server and client.
    /// No silent replacement or legacy fallback.
    static func load(_ bytes: Data?, serverPublicKey: String, clientPublicKey: String) -> Data? {
        guard let bytes, (1...1024).contains(bytes.count),
              let record = try? JSONDecoder().decode(Record.self, from: bytes),
              record.version == 1, canonicalBytes(record.binding) == bytes,
              record.binding.serverPublicKey == serverPublicKey,
              record.binding.clientPublicKey == clientPublicKey else { return nil }
        return record.binding.signingPublicKey
    }
}
