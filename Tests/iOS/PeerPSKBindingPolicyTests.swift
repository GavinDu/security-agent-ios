import Foundation
import XCTest
@testable import AgentApp

final class PeerPSKBindingPolicyTests: XCTestCase {
    private func key(_ n: UInt8) -> String { Data(repeating: n, count: 32).base64EncodedString() }
    private func record(server: String, client: String, secret: Data, version: Int = 1,
                        extra: Bool = false) throws -> Data {
        var object: [String: Any] = ["version": version, "serverPublicKey": server,
            "clientPublicKey": client, "presharedKey": secret.base64EncodedString()]
        if extra { object["unknown"] = true }
        // Match Foundation's canonical JSONEncoder sorted-key escaping.
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    func testAbsentAndExactBoundPSK() throws {
        let server = key(42), client = key(7), secret = Data(repeating: 8, count: 32)
        XCTAssertNil(try PeerPSKBindingPolicy.select(serverPublicKey: server,
            clientPublicKey: client, legacyPresent: false, boundRecord: nil))
        let bound = try record(server: server, client: client, secret: secret)
        XCTAssertEqual(try PeerPSKBindingPolicy.select(serverPublicKey: server,
            clientPublicKey: client, legacyPresent: false, boundRecord: bound), secret)
    }

    func testLegacyCannotDowngradeOrOverrideBoundKey() throws {
        let server = key(42), client = key(7)
        let bound = try record(server: server, client: client, secret: Data(repeating: 8, count: 32))
        for value in [nil, Optional(bound)] {
            XCTAssertThrowsError(try PeerPSKBindingPolicy.select(serverPublicKey: server,
                clientPublicKey: client, legacyPresent: true, boundRecord: value)) {
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
                   try record(server: server, client: client, secret: secret, version: 2),
                   try record(server: server, client: client, secret: secret, extra: true),
                   Data("invalid".utf8), Data(repeating: 65, count: 2049)]
        for value in bad {
            XCTAssertThrowsError(try PeerPSKBindingPolicy.select(serverPublicKey: server,
                clientPublicKey: client, legacyPresent: false, boundRecord: value))
        }
        XCTAssertThrowsError(try PeerPSKBindingPolicy.select(serverPublicKey: server,
            clientPublicKey: server, legacyPresent: false, boundRecord: nil))
    }
}
