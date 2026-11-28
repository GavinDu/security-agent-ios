import CryptoKit
import Foundation

/// Client-only verification and one-shot claim for a public enrollment
/// receipt. No network transport, pin provisioning, native profile write,
/// or WireGuard identity/key mutation occurs here.
enum VerifiedEnrollmentReceiptPolicy {
    enum ClaimError: Error, Equatable {
        case invalidPin, invalidReceipt, invalidSignature, wrongContext
        case alreadyClaimed, conflictingClaim, missingReadback
    }

    /// Independently provisioned control-plane signing pin. It MUST come
    /// from an authenticated pairing ceremony, never the received envelope.
    /// A WireGuard X25519 key is not an Ed25519 signing identity.
    struct TrustContext {
        let signingPublicKey: Data
        let expected: MacEnrollmentAddressReceipt.Expected
    }

    /// Not Codable, no public initializer. Only verified signature + exact
    /// independent context can construct a value.
    struct Verified {
        fileprivate let receipt: MacEnrollmentAddressReceipt
        fileprivate let record: Data
        var requestID: UUID { receipt.requestID }
        var serverPublicKey: String { receipt.serverPublicKey }
        var clientPublicKey: String { receipt.clientPublicKey }
    }

    /// A successful insert is a claim, not proof of a native profile commit.
    /// The caller must hold the authenticated cross-store transaction lease.
    enum InsertResult: Equatable { case inserted, alreadyExists }

    struct Claim {
        let requestID: UUID
        let transactionID: UUID
        let reservation: MacPeerAddressReservation
        fileprivate init(_ receipt: MacEnrollmentAddressReceipt) {
            requestID = receipt.requestID
            transactionID = receipt.transactionID
            reservation = receipt.publicReservation
        }
    }

    private struct ClaimRecord: Codable {
        let version: Int
        let signingPublicKey: Data
        let receiptBytes: Data
        let signature: Data
    }

    /// Separate domain from any future signed control-plane message. Exact
    /// canonical receipt bytes (not decoded/re-encoded arbitrary JSON).
    static func signingMessage(receiptBytes: Data) -> Data {
        var message = Data("security-agent.enrollment-address-receipt.v1\u{0}".utf8)
        message.append(receiptBytes)
        return message
    }

    static func verify(receiptBytes: Data, signature: Data, trust: TrustContext) throws -> Verified {
        guard trust.signingPublicKey.count == 32,
              trust.signingPublicKey.contains(where: { $0 != 0 }),
              trust.signingPublicKey != Data(base64Encoded: trust.expected.serverPublicKey),
              trust.signingPublicKey != Data(base64Encoded: trust.expected.clientPublicKey),
              let signer = try? Curve25519.Signing.PublicKey(rawRepresentation: trust.signingPublicKey)
              else { throw ClaimError.invalidPin }
        guard let receipt = MacEnrollmentAddressReceipt.decodeUntrusted(receiptBytes)
              else { throw ClaimError.invalidReceipt }
        guard receipt.matchesUntrustedContext(trust.expected) else { throw ClaimError.wrongContext }
        guard signature.count == 64,
              signer.isValidSignature(signature, for: signingMessage(receiptBytes: receiptBytes))
              else { throw ClaimError.invalidSignature }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let record = try encoder.encode(ClaimRecord(version: 1,
            signingPublicKey: trust.signingPublicKey, receiptBytes: receiptBytes, signature: signature))
        guard (1...4096).contains(record.count) else { throw ClaimError.invalidReceipt }
        return Verified(receipt: receipt, record: record)
    }

    /// Insert-only, keyed by request ID across signer/peer/epoch changes.
    /// No retry can obtain another claim; ambiguous I/O is not authorization.
    /// A persisted claim survives restart but does NOT imply profile activation.
    /// There is no delete/reset/eviction API. Future transaction recovery
    /// must reconcile the claim with native preferences rather than reuse it.
    static func claim(_ verified: Verified, verifyLocalState: () throws -> Void,
                      readClaim: () throws -> Data?,
                      insertIfAbsent: (Data) throws -> InsertResult) throws -> Claim {
        try verifyLocalState()
        if let existing = try readClaim() {
            throw existing == verified.record ? ClaimError.alreadyClaimed : ClaimError.conflictingClaim
        }
        try verifyLocalState()
        let result = try insertIfAbsent(verified.record)
        guard let winner = try readClaim() else { throw ClaimError.missingReadback }
        guard winner == verified.record else { throw ClaimError.conflictingClaim }
        guard result == .inserted else { throw ClaimError.alreadyClaimed }
        // Failed postcondition consumes the claim conservatively. No retry
        // may treat a persisted record as permission to activate a profile.
        try verifyLocalState()
        return Claim(verified.receipt)
    }
}
