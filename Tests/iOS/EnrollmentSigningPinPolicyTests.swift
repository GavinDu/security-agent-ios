import CryptoKit
import Foundation
import XCTest
@testable import AgentApp

final class EnrollmentSigningPinPolicyTests: XCTestCase {
    private typealias Policy = EnrollmentSigningPinPolicy
    private func key(_ byte: UInt8) -> String { Data(repeating: byte, count: 32).base64EncodedString() }
    private func binding() -> Policy.Binding {
        .init(serverPublicKey: key(42), clientPublicKey: key(7),
              signingPublicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)
    }

    func testFullFingerprintBindsEachIdentityAndRefusesTruncation() throws {
        let b = binding()
        let fingerprint = try XCTUnwrap(Policy.fingerprint(b))
        XCTAssertEqual(fingerprint.count, 64)
        XCTAssertNoThrow(try Policy.confirm(b, independentlyComparedFingerprint: fingerprint))
        for bad in [String(fingerprint.prefix(16)), fingerprint.uppercased(), fingerprint + " "] {
            XCTAssertThrowsError(try Policy.confirm(b, independentlyComparedFingerprint: bad))
        }
        let changed: [Policy.Binding] = [
            .init(serverPublicKey: key(43), clientPublicKey: b.clientPublicKey, signingPublicKey: b.signingPublicKey),
            .init(serverPublicKey: b.serverPublicKey, clientPublicKey: key(8), signingPublicKey: b.signingPublicKey),
            .init(serverPublicKey: b.serverPublicKey, clientPublicKey: b.clientPublicKey,
                  signingPublicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)]
        for value in changed {
            XCTAssertNotEqual(Policy.fingerprint(value), fingerprint)
            XCTAssertThrowsError(try Policy.confirm(value, independentlyComparedFingerprint: fingerprint))
        }
        for invalid in [Data(repeating: 0, count: 32), Data(repeating: 42, count: 32), Data(repeating: 7, count: 32)] {
            XCTAssertNil(Policy.fingerprint(.init(serverPublicKey: b.serverPublicKey,
                clientPublicKey: b.clientPublicKey, signingPublicKey: invalid)))
        }
    }

    func testInsertOnlyPinAndExactReadback() throws {
        let b = binding()
        let confirmed = try Policy.confirm(b, independentlyComparedFingerprint: XCTUnwrap(Policy.fingerprint(b)))
        var stored: Data?
        var writes = 0
        let insert: (Data) throws -> Void = { bytes in writes += 1; stored = bytes }
        try Policy.install(confirmed, verifyLocalState: {}, readPin: { stored }, insertIfAbsent: insert)
        try Policy.install(confirmed, verifyLocalState: {}, readPin: { stored }, insertIfAbsent: insert)
        XCTAssertEqual(writes, 1)
        XCTAssertEqual(Policy.load(stored, serverPublicKey: b.serverPublicKey,
            clientPublicKey: b.clientPublicKey), b.signingPublicKey)
        XCTAssertNil(Policy.load(stored, serverPublicKey: key(43), clientPublicKey: b.clientPublicKey))
        XCTAssertNil(Policy.load(stored, serverPublicKey: b.serverPublicKey, clientPublicKey: key(8)))
        let other = binding()
        let conflicting = try Policy.confirm(other, independentlyComparedFingerprint: XCTUnwrap(Policy.fingerprint(other)))
        XCTAssertThrowsError(try Policy.install(conflicting, verifyLocalState: {}, readPin: { stored }, insertIfAbsent: insert)) {
            XCTAssertEqual($0 as? Policy.PinError, .conflict)
        }
        XCTAssertEqual(writes, 1)
        let original = try XCTUnwrap(stored)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: original) as? [String: Any])
        object["unexpected"] = true
        let corrupt = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        XCTAssertNil(Policy.load(corrupt, serverPublicKey: b.serverPublicKey, clientPublicKey: b.clientPublicKey))
        XCTAssertNil(Policy.load(Data(repeating: 0, count: 1025), serverPublicKey: b.serverPublicKey, clientPublicKey: b.clientPublicKey))
    }

    func testRaceAndMissingWinnerFailClosed() throws {
        let b = binding()
        let confirmed = try Policy.confirm(b, independentlyComparedFingerprint: XCTUnwrap(Policy.fingerprint(b)))
        var stored: Data?
        XCTAssertThrowsError(try Policy.install(confirmed, verifyLocalState: {}, readPin: { stored },
            insertIfAbsent: { _ in stored = Data([1]) })) {
            XCTAssertEqual($0 as? Policy.PinError, .conflict)
        }
        stored = nil
        XCTAssertThrowsError(try Policy.install(confirmed, verifyLocalState: {}, readPin: { stored },
            insertIfAbsent: { _ in })) {
            XCTAssertEqual($0 as? Policy.PinError, .missingReadback)
        }
    }
}
