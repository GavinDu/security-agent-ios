import Foundation
import XCTest
@testable import AgentApp

final class MacPairingQRInputPolicyTests: XCTestCase {
    private let key = Data(repeating: 0x2a, count: 32).base64EncodedString()

    func testRealMacPairingQRRoundTripIsAccepted() throws {
        let encoded = try PairingQRCode(
            kind: .mac, publicKey: key, endpoint: "home.example.test:51820"
        ).encodedText()
        XCTAssertEqual(try MacPairingQRInputPolicy.decode(encoded).publicKey, key)
        XCTAssertEqual(try PairingQRCode.decodeMac(encoded).endpoint, "home.example.test:51820")
    }

    func testOversizedWrongKindNoncanonicalAndZeroMacKeyReject() throws {
        let encoded = try PairingQRCode(
            kind: .mac, publicKey: key, endpoint: "home.example.test:51820"
        ).encodedText()
        for value in [
            String(repeating: "x", count: 4_097),
            encoded.replacingOccurrences(of: #""mac""#, with: #""iphone""#),
            encoded.replacingOccurrences(of: key, with: Data(repeating: 0, count: 32).base64EncodedString()),
            encoded.replacingOccurrences(of: key, with: key + "\\n"),
            "{}", "[]"
        ] {
            XCTAssertThrowsError(try MacPairingQRInputPolicy.decode(value))
            XCTAssertThrowsError(try PairingQRCode.decodeMac(value))
        }
    }
}
