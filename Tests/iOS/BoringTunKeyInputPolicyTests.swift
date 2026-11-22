import Foundation
import XCTest
@testable import AgentApp

final class BoringTunKeyInputPolicyTests: XCTestCase {
    private let privateKey = Data(repeating: 0x2A, count: 32)
    private let serverKey = Data(repeating: 0x19, count: 32).base64EncodedString()

    func testWellFormedInputAndOptionalPSK() {
        XCTAssertTrue(BoringTunKeyInputPolicy.accepts(
            privateKey: privateKey, serverPublicKey: serverKey, presharedKey: nil
        ))
        XCTAssertTrue(BoringTunKeyInputPolicy.accepts(
            privateKey: privateKey, serverPublicKey: serverKey,
            presharedKey: Data(repeating: 0, count: 32)
        ))
    }

    func testRejectsZeroNoncanonicalAndWrongSizeInputs() {
        for secret in [
            Data(), Data(repeating: 0, count: 32),
            Data(repeating: 3, count: 31), Data(repeating: 3, count: 33)
        ] {
            XCTAssertFalse(BoringTunKeyInputPolicy.accepts(
                privateKey: secret, serverPublicKey: serverKey, presharedKey: nil
            ))
        }
        for invalidPeer in [
            "", "not base64", serverKey + "\n", " " + serverKey,
            Data(repeating: 0, count: 32).base64EncodedString(),
            Data(repeating: 1, count: 31).base64EncodedString()
        ] {
            XCTAssertFalse(BoringTunKeyInputPolicy.accepts(
                privateKey: privateKey, serverPublicKey: invalidPeer, presharedKey: nil
            ))
        }
        XCTAssertFalse(BoringTunKeyInputPolicy.accepts(
            privateKey: privateKey, serverPublicKey: serverKey,
            presharedKey: Data(repeating: 1, count: 31)
        ))
    }
}
