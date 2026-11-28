import CryptoKit
import Foundation
import XCTest
@testable import AgentApp

final class VerifiedEnrollmentReceiptPolicyTests: XCTestCase {
    private typealias Policy = VerifiedEnrollmentReceiptPolicy
    private struct Fixture {
        let signer: Curve25519.Signing.PrivateKey
        let bytes: Data
        let expected: MacEnrollmentAddressReceipt.Expected

        var trust: Policy.TrustContext {
            .init(signingPublicKey: signer.publicKey.rawRepresentation, expected: expected)
        }

        func verified() throws -> Policy.Verified {
            try Policy.verify(receiptBytes: bytes,
                signature: signer.signature(for: Policy.signingMessage(receiptBytes: bytes)), trust: trust)
        }
    }

    private func fixture(slot: UInt8 = 2, requestID: UUID = UUID()) throws -> Fixture {
        let server = Data(repeating: 42, count: 32).base64EncodedString()
        let client = Data(repeating: 7, count: 32).base64EncodedString()
        let expected = MacEnrollmentAddressReceipt.Expected(requestID: requestID,
            transactionID: UUID(), serverPublicKey: server, clientPublicKey: client,
            rosterEpoch: UUID(), revision: 1, slot: slot)
        let object: [String: Any] = ["version": 1, "kind": "enrollment-committed",
            "requestID": requestID.uuidString, "transactionID": expected.transactionID.uuidString,
            "serverPublicKey": server, "clientPublicKey": client,
            "rosterEpoch": expected.rosterEpoch.uuidString, "revision": 1, "slot": Int(slot)]
        // JSONEncoder canonical form also escapes slashes; keys here contain none.
        let bytes = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        XCTAssertNotNil(MacEnrollmentAddressReceipt.decodeUntrusted(bytes))
        return Fixture(signer: Curve25519.Signing.PrivateKey(), bytes: bytes, expected: expected)
    }

    func testSignatureRequiresIndependentPinExactContextAndDomain() throws {
        let f = try fixture()
        let signature = try f.signer.signature(for: Policy.signingMessage(receiptBytes: f.bytes))
        XCTAssertNoThrow(try f.verified())
        let wrong = Curve25519.Signing.PrivateKey()
        XCTAssertThrowsError(try Policy.verify(receiptBytes: f.bytes, signature: signature,
            trust: .init(signingPublicKey: wrong.publicKey.rawRepresentation, expected: f.expected)))
        let x25519Bytes = try XCTUnwrap(Data(base64Encoded: f.expected.serverPublicKey))
        XCTAssertThrowsError(try Policy.verify(receiptBytes: f.bytes, signature: signature,
            trust: .init(signingPublicKey: x25519Bytes, expected: f.expected))) {
            XCTAssertEqual($0 as? Policy.ClaimError, .invalidPin)
        }
        let clientKey = try XCTUnwrap(Data(base64Encoded: f.expected.clientPublicKey))
        XCTAssertThrowsError(try Policy.verify(receiptBytes: f.bytes, signature: signature,
            trust: .init(signingPublicKey: clientKey, expected: f.expected))) {
            XCTAssertEqual($0 as? Policy.ClaimError, .invalidPin)
        }
        let rawSignature = try f.signer.signature(for: f.bytes)
        XCTAssertThrowsError(try Policy.verify(receiptBytes: f.bytes, signature: rawSignature, trust: f.trust))
        XCTAssertThrowsError(try Policy.verify(receiptBytes: f.bytes,
            signature: Data(signature.dropLast()), trust: f.trust))
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: f.bytes) as? [String: Any])
        object["slot"] = 3
        let changed = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        let changedSignature = try f.signer.signature(for: Policy.signingMessage(receiptBytes: changed))
        XCTAssertThrowsError(try Policy.verify(receiptBytes: changed, signature: changedSignature,
            trust: f.trust)) { XCTAssertEqual($0 as? Policy.ClaimError, .wrongContext) }
        let changedExpected = MacEnrollmentAddressReceipt.Expected(requestID: f.expected.requestID,
            transactionID: f.expected.transactionID, serverPublicKey: f.expected.serverPublicKey,
            clientPublicKey: f.expected.clientPublicKey, rosterEpoch: f.expected.rosterEpoch,
            revision: f.expected.revision, slot: 3)
        XCTAssertThrowsError(try Policy.verify(receiptBytes: changed, signature: signature,
            trust: .init(signingPublicKey: f.trust.signingPublicKey, expected: changedExpected))) {
            XCTAssertEqual($0 as? Policy.ClaimError, .invalidSignature)
        }
        object["unknown"] = true
        let noncanonical = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        XCTAssertThrowsError(try Policy.verify(receiptBytes: noncanonical, signature: signature, trust: f.trust))
    }

    func testAtomicClaimAndDuplicateRaceNeverReturnSecondPermission() throws {
        let f = try fixture()
        let verified = try f.verified()
        var stored: Data?
        var writes = 0
        let insert: (Data) throws -> Policy.InsertResult = { bytes in
            writes += 1
            if stored != nil { return .alreadyExists }
            stored = bytes
            return .inserted
        }
        let claim = try Policy.claim(verified, verifyLocalState: {}, readClaim: { stored }, insertIfAbsent: insert)
        XCTAssertEqual(claim.requestID, f.expected.requestID)
        XCTAssertEqual(claim.reservation.slot, 2)
        XCTAssertThrowsError(try Policy.claim(verified, verifyLocalState: {},
            readClaim: { stored }, insertIfAbsent: insert)) {
            XCTAssertEqual($0 as? Policy.ClaimError, .alreadyClaimed)
        }
        XCTAssertEqual(writes, 1)
        let other = try fixture(slot: 3, requestID: f.expected.requestID).verified()
        XCTAssertThrowsError(try Policy.claim(other, verifyLocalState: {},
            readClaim: { stored }, insertIfAbsent: insert)) {
            XCTAssertEqual($0 as? Policy.ClaimError, .conflictingClaim)
        }
        XCTAssertEqual(writes, 1)
        // A competing insertion won between initial read and our SecItemAdd.
        stored = nil
        XCTAssertThrowsError(try Policy.claim(verified, verifyLocalState: {}, readClaim: { stored },
            insertIfAbsent: { stored = $0; return .alreadyExists })) {
            XCTAssertEqual($0 as? Policy.ClaimError, .alreadyClaimed)
        }
    }

    func testAmbiguousWriteAndFailedPostconditionStayConsumed() throws {
        enum Failure: Error { case io }
        let verified = try fixture().verified()
        var stored: Data?
        XCTAssertThrowsError(try Policy.claim(verified, verifyLocalState: {}, readClaim: { stored },
            insertIfAbsent: { stored = $0; throw Failure.io }))
        XCTAssertNotNil(stored)
        XCTAssertThrowsError(try Policy.claim(verified, verifyLocalState: {}, readClaim: { stored },
            insertIfAbsent: { _ in XCTFail("must not redispatch"); return .inserted })) {
            XCTAssertEqual($0 as? Policy.ClaimError, .alreadyClaimed)
        }
        stored = nil
        var checks = 0
        XCTAssertThrowsError(try Policy.claim(verified, verifyLocalState: {
            checks += 1
            if checks == 3 { throw Failure.io }
        }, readClaim: { stored }, insertIfAbsent: { stored = $0; return .inserted }))
        XCTAssertNotNil(stored)
        XCTAssertThrowsError(try Policy.claim(verified, verifyLocalState: {}, readClaim: { stored },
            insertIfAbsent: { _ in XCTFail("consumed"); return .inserted }))
        XCTAssertThrowsError(try Policy.claim(verified, verifyLocalState: {}, readClaim: { nil },
            insertIfAbsent: { _ in .inserted })) {
            XCTAssertEqual($0 as? Policy.ClaimError, .missingReadback)
        }
    }
}
