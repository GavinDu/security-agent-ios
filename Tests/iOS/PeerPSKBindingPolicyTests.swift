import Foundation
import XCTest
@testable import AgentApp

final class PeerPSKBindingPolicyTests: XCTestCase {
    private func key(_ n: UInt8) -> String { Data(repeating: n, count: 32).base64EncodedString() }
    private let transaction = UUID(uuidString: "12345678-1234-1234-1234-123456789ABC")!
    private var requirement: PeerPSKRequirement { .init(transactionID: transaction, clientPublicKey: key(7)) }
    private func record(server: String, client: String, secret: Data, version: Int = 2,
                        extra: Bool = false) throws -> Data {
        var object: [String: Any] = ["version": version, "serverPublicKey": server,
            "clientPublicKey": client, "transactionID": transaction.uuidString, "presharedKey": secret.base64EncodedString()]
        if extra { object["unknown"] = true }
        // Match Foundation's canonical JSONEncoder sorted-key escaping.
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    func testCanonicalSecretContainingSlash() throws {
        struct Fixture: Encodable {
            let version = 2
            let transactionID: UUID
            let serverPublicKey: String
            let clientPublicKey: String
            let presharedKey: Data
        }
        let server = key(42), client = key(7), secret = Data(repeating: 255, count: 32)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let bound = try encoder.encode(Fixture(transactionID: transaction, serverPublicKey: server,
            clientPublicKey: client, presharedKey: secret))
        XCTAssertEqual(try PeerPSKBindingPolicy.select(serverPublicKey: server,
            clientPublicKey: client, legacyPresent: false, boundRecord: bound, requirement: requirement), secret)
        XCTAssertThrowsError(try PeerPSKBindingPolicy.select(serverPublicKey: server,
            clientPublicKey: client, legacyPresent: false, boundRecord: bound + Data([10]), requirement: requirement))
    }

    func testAbsentAndExactBoundPSK() throws {
        let server = key(42), client = key(7), secret = Data(repeating: 8, count: 32)
        XCTAssertNil(try PeerPSKBindingPolicy.select(serverPublicKey: server,
            clientPublicKey: client, legacyPresent: false, boundRecord: nil, requirement: nil))
        let bound = try record(server: server, client: client, secret: secret)
        XCTAssertEqual(try PeerPSKBindingPolicy.select(serverPublicKey: server,
            clientPublicKey: client, legacyPresent: false, boundRecord: bound, requirement: requirement), secret)
    }

    func testLegacyCannotDowngradeOrOverrideBoundKey() throws {
        let server = key(42), client = key(7)
        let bound = try record(server: server, client: client, secret: Data(repeating: 8, count: 32))
        for value in [nil, Optional(bound)] {
            XCTAssertThrowsError(try PeerPSKBindingPolicy.select(serverPublicKey: server,
                clientPublicKey: client, legacyPresent: true, boundRecord: value, requirement: requirement)) {
                XCTAssertEqual($0 as? PeerPSKBindingPolicy.SelectionError, .unboundLegacy)
            }
        }
    }

    func testWrongPeerMalformedZeroAndUnknownRecordsFailClosed() throws {
        let server = key(42), client = key(7), secret = Data(repeating: 8, count: 32)
        let bad = [try record(server: key(43), client: client, secret: secret),
                   try record(server: server, client: key(9), secret: secret),
                   try record(server: server, client: client, secret: Data(repeating: 0, count: 32)),
                   try record(server: server, client: client, secret: Data(repeating: 8, count: 31)),
                   try record(server: server, client: client, secret: secret, version: 1),
                   try record(server: server, client: client, secret: secret, extra: true),
                   Data("invalid".utf8), Data(repeating: 65, count: 2049)]
        for value in bad {
            XCTAssertThrowsError(try PeerPSKBindingPolicy.select(serverPublicKey: server,
                clientPublicKey: client, legacyPresent: false, boundRecord: value, requirement: requirement))
        }
        XCTAssertThrowsError(try PeerPSKBindingPolicy.select(serverPublicKey: server,
            clientPublicKey: server, legacyPresent: false, boundRecord: nil, requirement: nil))
    }
    func testRequiredMissingAndUnmarkedRecordAreRejected() throws {
        let server = key(42), client = key(7)
        let bound = try record(server: server, client: client, secret: Data(repeating: 8, count: 32))
        XCTAssertThrowsError(try PeerPSKBindingPolicy.select(serverPublicKey: server,
            clientPublicKey: client, legacyPresent: false, boundRecord: nil, requirement: requirement)) {
            XCTAssertEqual($0 as? PeerPSKBindingPolicy.SelectionError, .missingRequired)
        }
        XCTAssertThrowsError(try PeerPSKBindingPolicy.select(serverPublicKey: server,
            clientPublicKey: client, legacyPresent: false, boundRecord: bound, requirement: nil)) {
            XCTAssertEqual($0 as? PeerPSKBindingPolicy.SelectionError, .unexpectedRecord)
        }
        for wrong in [PeerPSKRequirement(transactionID: UUID(), clientPublicKey: client),
                      PeerPSKRequirement(transactionID: transaction, clientPublicKey: key(9))] {
            XCTAssertThrowsError(try PeerPSKBindingPolicy.select(serverPublicKey: server,
                clientPublicKey: client, legacyPresent: false, boundRecord: bound, requirement: wrong))
        }
    }
}
